import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Callable
import requests

logger = logging.getLogger(__name__)

class TokenManager:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Token data
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._access_expires_at: Optional[datetime] = None
        self._refresh_expires_at: Optional[datetime] = None
        
        # Refresh settings
        self._refresh_margin = 300  # Refresh 5 minutes before expiry
        self._refresh_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        
        # Failure tracking
        self._consecutive_refresh_failures = 0
        self._max_refresh_failures = 3  # Trigger re-registration after this many failures
        self._needs_reregistration = False
        
        # Callbacks
        self._on_token_refreshed: Optional[Callable] = None
        self._on_token_expired: Optional[Callable] = None
        self._on_reregistration_needed: Optional[Callable] = None
        
        # Load tokens from config if available
        self._load_tokens_from_config()
        
        self.logger.info("TokenManager initialized")
    
    def _load_tokens_from_config(self):
        """Load tokens from config if available"""
        jwt_config = self.config.get('jwt', {})
        
        if jwt_config:
            self._access_token = jwt_config.get('access_token')
            self._refresh_token = jwt_config.get('refresh_token')
            
            # Parse expiry times. Malformed timestamps from a stale config
            # file shouldn't break startup, but they must be logged or
            # `has_valid_token` will silently report False and the agent
            # will spin trying to refresh a token it can't introspect.
            access_exp = jwt_config.get('access_expires_at')
            if access_exp:
                try:
                    self._access_expires_at = datetime.fromisoformat(access_exp.replace('Z', '+00:00'))
                except (ValueError, AttributeError, TypeError) as e:
                    self.logger.warning(
                        f"Could not parse jwt.access_expires_at={access_exp!r}: {e}"
                    )

            refresh_exp = jwt_config.get('refresh_expires_at')
            if refresh_exp:
                try:
                    self._refresh_expires_at = datetime.fromisoformat(refresh_exp.replace('Z', '+00:00'))
                except (ValueError, AttributeError, TypeError) as e:
                    self.logger.warning(
                        f"Could not parse jwt.refresh_expires_at={refresh_exp!r}: {e}"
                    )
            
            if self._access_token:
                self.logger.info("Loaded existing JWT tokens from config")
    
    def set_tokens(self, access_token: str, refresh_token: str,
                   access_expires_at: str = None, refresh_expires_at: str = None):
        """
        Set new tokens.
        
        Args:
            access_token: JWT access token
            refresh_token: JWT refresh token
            access_expires_at: ISO format expiry time for access token
            refresh_expires_at: ISO format expiry time for refresh token
        """
        with self._lock:
            self._access_token = access_token
            self._refresh_token = refresh_token
            
            # Parse expiry times
            if access_expires_at:
                try:
                    self._access_expires_at = datetime.fromisoformat(
                        access_expires_at.replace('Z', '+00:00')
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to parse access_expires_at: {e}")
            
            if refresh_expires_at:
                try:
                    self._refresh_expires_at = datetime.fromisoformat(
                        refresh_expires_at.replace('Z', '+00:00')
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to parse refresh_expires_at: {e}")
            
            # Update config
            self.config['jwt'] = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'access_expires_at': access_expires_at,
                'refresh_expires_at': refresh_expires_at,
            }
        
        self.logger.info("JWT tokens updated")
    
    @property
    def access_token(self) -> Optional[str]:
        """Get current access token, refreshing if needed"""
        with self._lock:
            # Check if token needs refresh
            if self._should_refresh():
                self._do_refresh()
            
            return self._access_token
    
    @property
    def refresh_token(self) -> Optional[str]:
        """Get refresh token"""
        with self._lock:
            return self._refresh_token
    
    @property
    def has_valid_token(self) -> bool:
        """Check if we have a valid access token"""
        with self._lock:
            if not self._access_token:
                return False
            
            if self._access_expires_at:
                return datetime.now(self._access_expires_at.tzinfo) < self._access_expires_at
            
            return True  # Assume valid if no expiry info
    
    @property
    def is_expired(self) -> bool:
        """Check if access token is expired"""
        with self._lock:
            if not self._access_expires_at:
                return False
            
            return datetime.now(self._access_expires_at.tzinfo) >= self._access_expires_at
    
    def get_auth_header(self) -> Dict[str, str]:
        #Get Authorization header for requests.
        token = self.access_token
        if token:
            return {'Authorization': f'Bearer {token}'}
        return {}
    
    def _should_refresh(self) -> bool:
        """Check if token should be refreshed"""
        if not self._access_token or not self._access_expires_at:
            return False
        
        # Calculate refresh threshold (refresh X seconds before expiry).
        # Only timezone arithmetic can blow up here; bare-except hides cases
        # where _access_expires_at is the wrong type (e.g. a string slipped
        # past _load_tokens_from_config) which we want surfaced once.
        try:
            now = datetime.now(self._access_expires_at.tzinfo)
            refresh_at = self._access_expires_at - timedelta(seconds=self._refresh_margin)
            return now >= refresh_at
        except (TypeError, AttributeError, OverflowError) as e:
            self.logger.warning(
                f"_should_refresh comparison failed (expires_at={self._access_expires_at!r}): {e}"
            )
            return False
    
    def _do_refresh(self, with_rotation: bool = True) -> bool:
        """
        Perform token refresh.
        
        Args:
            with_rotation: If True, request new refresh token too (more secure)
        """
        if not self._refresh_token:
            self.logger.warning("No refresh token available")
            self._trigger_reregistration("No refresh token")
            return False
        
        server_url = self.config.get('server_url', '')
        if not server_url:
            server_urls = self.config.get('server', {}).get('urls', [])
            server_url = server_urls[0] if server_urls else ''
        
        if not server_url:
            self.logger.error("No server URL for token refresh")
            return False
        
        try:
            refresh_url = f"{server_url.rstrip('/')}/api/auth/refresh"
            self.logger.info(f"Refreshing tokens (rotation={with_rotation})...")
            
            response = requests.post(
                refresh_url,
                json={
                    'refresh_token': self._refresh_token,
                    'rotate': with_rotation
                },
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    token_data = data.get('data', {})
                    
                    # Update access token
                    self._access_token = token_data.get('access_token')
                    
                    # Update refresh token if rotated
                    if token_data.get('refresh_token'):
                        self._refresh_token = token_data.get('refresh_token')
                        refresh_exp = token_data.get('refresh_expires_at')
                        if refresh_exp:
                            try:
                                self._refresh_expires_at = datetime.fromisoformat(
                                    refresh_exp.replace('Z', '+00:00')
                                )
                            except (ValueError, AttributeError, TypeError) as e:
                                # Server sent a malformed timestamp; keep the
                                # previous expiry so _should_refresh keeps
                                # working, but surface the bug.
                                self.logger.warning(
                                    f"Server returned unparseable refresh_expires_at={refresh_exp!r}: {e}"
                                )

                    # Update access expiry
                    expires_at = token_data.get('expires_at') or token_data.get('access_expires_at')
                    if expires_at:
                        try:
                            self._access_expires_at = datetime.fromisoformat(
                                expires_at.replace('Z', '+00:00')
                            )
                        except (ValueError, AttributeError, TypeError) as e:
                            self.logger.warning(
                                f"Server returned unparseable access expires_at={expires_at!r}: {e}"
                            )
                    
                    # Update config
                    self._update_config_tokens(token_data)
                    
                    self.logger.info("Tokens refreshed successfully")
                    
                    # Reset failure counter
                    self._consecutive_refresh_failures = 0
                    
                    # Callback
                    if self._on_token_refreshed:
                        try:
                            self._on_token_refreshed()
                        except Exception as e:
                            self.logger.warning(f"on_token_refreshed callback error: {e}")
                    
                    return True
                else:
                    return self._handle_refresh_error(data)
            elif response.status_code == 401:
                # Auth error - token invalid or expired. The server *should*
                # return a JSON body with an error code; if the response is
                # garbled or not JSON we fall back to a generic
                # re-registration. Bare-except previously swallowed the
                # failure type, which made it impossible to tell "server
                # returned HTML 401" from "server JSON had unexpected
                # shape".
                try:
                    data = response.json()
                    return self._handle_refresh_error(data)
                except ValueError as e:
                    self.logger.warning(
                        f"401 response body was not JSON ({e}); falling back to re-registration"
                    )
                    self._trigger_reregistration("Server returned 401 with non-JSON body")
                    return False
            else:
                self.logger.error(f"Token refresh HTTP error: {response.status_code}")
                self._consecutive_refresh_failures += 1
                return False
                
        except requests.exceptions.Timeout:
            self.logger.error("Token refresh timeout")
            self._consecutive_refresh_failures += 1
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error("Token refresh connection error")
            self._consecutive_refresh_failures += 1
            return False
        except Exception as e:
            self.logger.error(f"Token refresh error: {e}")
            self._consecutive_refresh_failures += 1
            return False
    
    def _handle_refresh_error(self, data: Dict) -> bool:
        """Handle refresh error response"""
        error = data.get('error', 'Unknown error')
        code = data.get('code', '')
        
        self.logger.error(f"Token refresh failed: {error} (code={code})")
        
        # Handle specific error codes
        if code in ('REFRESH_TOKEN_EXPIRED', 'TOKEN_REVOKED', 'INVALID_TOKEN'):
            self._trigger_reregistration(f"Refresh token invalid: {code}")
            return False
        
        # Generic error - increment failure counter
        self._consecutive_refresh_failures += 1
        
        # After too many failures, trigger re-registration
        if self._consecutive_refresh_failures >= self._max_refresh_failures:
            self._trigger_reregistration(f"Too many refresh failures ({self._consecutive_refresh_failures})")
        
        return False
    
    def _trigger_reregistration(self, reason: str):
        """Trigger agent re-registration"""
        self.logger.warning(f"Triggering re-registration: {reason}")
        self._clear_tokens()
        self._needs_reregistration = True
        
        if self._on_token_expired:
            try:
                self._on_token_expired()
            except Exception as e:
                self.logger.warning(f"on_token_expired callback error: {e}")
    
    def _update_config_tokens(self, token_data: Dict):
        """Update config with new tokens"""
        jwt_config = self.config.get('jwt', {})
        
        jwt_config['access_token'] = token_data.get('access_token')
        jwt_config['access_expires_at'] = token_data.get('expires_at') or token_data.get('access_expires_at')
        
        if token_data.get('refresh_token'):
            jwt_config['refresh_token'] = token_data.get('refresh_token')
            jwt_config['refresh_expires_at'] = token_data.get('refresh_expires_at')
        
        self.config['jwt'] = jwt_config
    
    def _clear_tokens(self):
        """Clear all tokens"""
        self._access_token = None
        self._refresh_token = None
        self._access_expires_at = None
        self._refresh_expires_at = None
        
        if 'jwt' in self.config:
            del self.config['jwt']
        
        self.logger.warning("Tokens cleared")
    
    def refresh_now(self) -> bool:
        """Force token refresh"""
        with self._lock:
            return self._do_refresh()
    
    def start_auto_refresh(self, on_refreshed: Callable = None, on_expired: Callable = None):
        """
        Start background thread for auto token refresh.
        
        Args:
            on_refreshed: Callback when token is refreshed
            on_expired: Callback when refresh token expires
        """
        self._on_token_refreshed = on_refreshed
        self._on_token_expired = on_expired
        self._running = True
        
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            name="TokenRefresh",
            daemon=True
        )
        self._refresh_thread.start()
        self.logger.info("Auto token refresh started")
    
    def stop_auto_refresh(self):
        """Stop background refresh thread"""
        self._running = False
        if self._refresh_thread:
            self._refresh_thread.join(timeout=5)
        self.logger.info("Auto token refresh stopped")
    
    def _refresh_loop(self):
        """Background loop for token refresh"""
        while self._running:
            try:
                # Check every 60 seconds
                time.sleep(60)
                
                if not self._running:
                    break
                
                # Check if refresh needed
                with self._lock:
                    if self._should_refresh():
                        self._do_refresh()
                        
            except Exception as e:
                self.logger.error(f"Error in refresh loop: {e}")
    
    def on_token_refreshed(self, callback: Callable):
        """Set callback for token refresh"""
        self._on_token_refreshed = callback
    
    def on_token_expired(self, callback: Callable):
        """Set callback for token expiry"""
        self._on_token_expired = callback
    
    def on_reregistration_needed(self, callback: Callable):
        """Set callback for when re-registration is required"""
        self._on_reregistration_needed = callback
    
    @property
    def needs_reregistration(self) -> bool:
        """Check if agent needs to re-register"""
        return self._needs_reregistration
    
    def reset_reregistration_flag(self):
        """Reset the re-registration flag after successful registration"""
        self._needs_reregistration = False
        self._consecutive_refresh_failures = 0
        self.logger.info("Re-registration flag reset")
    
    def get_token_status(self) -> Dict:
        """
        Get current token status for monitoring.
        
        Returns:
            Dict with token status information
        """
        with self._lock:
            access_expires_in = None
            if self._access_expires_at:
                try:
                    access_now = datetime.now(self._access_expires_at.tzinfo) if self._access_expires_at.tzinfo else datetime.now()
                    access_expires_in = (self._access_expires_at - access_now).total_seconds()
                except (TypeError, AttributeError, OverflowError) as e:
                    self.logger.debug(
                        f"access_expires_in calc failed (expires_at={self._access_expires_at!r}): {e}"
                    )

            refresh_expires_in = None
            if self._refresh_expires_at:
                try:
                    refresh_now = datetime.now(self._refresh_expires_at.tzinfo) if self._refresh_expires_at.tzinfo else datetime.now()
                    refresh_expires_in = (self._refresh_expires_at - refresh_now).total_seconds()
                except (TypeError, AttributeError, OverflowError) as e:
                    self.logger.debug(
                        f"refresh_expires_in calc failed (expires_at={self._refresh_expires_at!r}): {e}"
                    )
            
            return {
                'has_access_token': bool(self._access_token),
                'has_refresh_token': bool(self._refresh_token),
                'access_expires_in': access_expires_in,
                'refresh_expires_in': refresh_expires_in,
                'needs_refresh': self._should_refresh(),
                'needs_reregistration': self._needs_reregistration,
                'consecutive_failures': self._consecutive_refresh_failures,
                'auto_refresh_running': self._running
            }


# Global token manager instance
_token_manager: Optional[TokenManager] = None


def init_token_manager(config: Dict) -> TokenManager:
    """Initialize global token manager"""
    global _token_manager
    _token_manager = TokenManager(config)
    return _token_manager


def get_token_manager() -> Optional[TokenManager]:
    """Get global token manager"""
    return _token_manager


def get_auth_headers(config: Dict) -> Dict[str, str]:
    """
    Get authentication headers for requests.
    
    Returns JWT Bearer token if available, otherwise falls back to legacy token.
    
    Args:
        config: Agent configuration
        
    Returns:
        Dict with appropriate auth headers
    """
    headers = {}
    
    # Try JWT first
    if _token_manager:
        jwt_headers = _token_manager.get_auth_header()
        if jwt_headers:
            return jwt_headers
    
    # Check config for JWT
    jwt_config = config.get('jwt', {})
    access_token = jwt_config.get('access_token')
    if access_token:
        return {'Authorization': f'Bearer {access_token}'}
    
    # Fall back to legacy token
    legacy_token = config.get('agent_token')
    if legacy_token:
        return {'X-Agent-Token': legacy_token}
    
    return headers
