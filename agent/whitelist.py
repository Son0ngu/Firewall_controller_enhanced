import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Union

import requests

# Configure logging
logger = logging.getLogger("whitelist")

class WhitelistManager:
    """
    Manages the whitelist of allowed domains.
    Provides functionality to load whitelist from local file or server,
    check if domains are allowed, and update the whitelist periodically.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the whitelist manager.
        
        Args:
            config: Configuration dictionary with keys:
                - server_url: URL of the server API
                - api_key: API key for authentication
                - whitelist_source: "file" or "server" or "both"
                - whitelist_file: Path to local whitelist file
                - update_interval: Seconds between whitelist updates (if server used)
        """
        self.config = config
        
        # Default configuration values
        self.server_url = config.get("server_url", "")
        self.api_key = config.get("api_key", "")
        self.whitelist_source = config.get("whitelist_source", "both")
        self.whitelist_file = config.get("whitelist_file", "whitelist.json")
        self.update_interval = config.get("update_interval", 3600)  # Default: 1 hour
        
        # Initialize whitelist data structures
        self.domains: Set[str] = set()  # Set for O(1) lookups
        self.last_updated: Optional[datetime] = None
        self.update_lock = threading.Lock()
        self.update_thread = None
        self.running = False
        
        # Load initial whitelist
        self.load_whitelist()
    
    def start_periodic_updates(self):
        """Start periodic updates of the whitelist from server."""
        if self.running:
            logger.warning("Whitelist updater is already running")
            return
            
        if self.whitelist_source in ["server", "both"]:
            self.running = True
            self.update_thread = threading.Thread(target=self._update_loop)
            self.update_thread.daemon = True
            self.update_thread.start()
            logger.info("Started periodic whitelist updates every %d seconds", self.update_interval)
        else:
            logger.info("Whitelist source is set to 'file', periodic updates disabled")
    
    def stop_periodic_updates(self):
        """Stop periodic updates of the whitelist."""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=3)
            if self.update_thread.is_alive():
                logger.warning("Whitelist update thread did not terminate gracefully")
    
    def _update_loop(self):
        """Background thread for periodic whitelist updates."""
        while self.running:
            try:
                # Update whitelist from server
                self.update_whitelist_from_server()
                
                # Sleep for the configured interval
                for _ in range(self.update_interval):
                    if not self.running:
                        break
                    time.sleep(1)  # Sleep in small chunks to allow quicker shutdown
                    
            except Exception as e:
                logger.error("Error in whitelist update loop: %s", str(e))
                # Sleep a bit before retrying to avoid hammering the server on errors
                time.sleep(60)
    
    def load_whitelist(self):
        """
        Load the whitelist from the configured source(s).
        """
        with self.update_lock:
            # Reset domains
            self.domains = set()
            
            # Load from file if specified
            if self.whitelist_source in ["file", "both"]:
                self._load_from_file()
                
            # Load from server if specified
            if self.whitelist_source in ["server", "both"]:
                self.update_whitelist_from_server()
            
            logger.info("Loaded whitelist with %d domains", len(self.domains))
    
    def _load_from_file(self):
        """Load whitelist from the local file."""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    
                if isinstance(data, dict) and "domains" in data:
                    # New format: {"domains": [...], "last_updated": "..."}
                    domains = data.get("domains", [])
                    last_updated_str = data.get("last_updated")
                    if last_updated_str:
                        try:
                            self.last_updated = datetime.fromisoformat(last_updated_str)
                        except ValueError:
                            self.last_updated = datetime.now()
                elif isinstance(data, list):
                    # Simple format: just a list of domains
                    domains = data
                    self.last_updated = datetime.now()
                else:
                    domains = []
                    logger.warning("Invalid format in whitelist file %s", self.whitelist_file)
                
                # Add all valid domains to the set
                for domain in domains:
                    if isinstance(domain, str) and self._is_valid_domain(domain):
                        self.domains.add(domain)
                
                logger.info("Loaded %d domains from file %s", len(self.domains), self.whitelist_file)
            else:
                logger.warning("Whitelist file not found: %s", self.whitelist_file)
                # Create a default whitelist with common domains
                self._create_default_whitelist()
                
        except Exception as e:
            logger.error("Error loading whitelist from file: %s", str(e))
            # Create a default whitelist if we couldn't load one
            self._create_default_whitelist()
    
    def _create_default_whitelist(self):
        """Create a default whitelist with common safe domains."""
        default_domains = [
            "google.com", "www.google.com", "microsoft.com", "www.microsoft.com",
            "github.com", "www.github.com", "stackoverflow.com", "www.stackoverflow.com",
            "wikipedia.org", "www.wikipedia.org"
        ]
        
        for domain in default_domains:
            self.domains.add(domain)
            
        self.last_updated = datetime.now()
        
        # Save the default whitelist to file
        self._save_to_file()
        
        logger.info("Created default whitelist with %d domains", len(self.domains))
    
    def update_whitelist_from_server(self) -> bool:
        """
        Fetch the latest whitelist from the server.
        
        Returns:
            bool: True if update successful, False otherwise
        """
        if not self.server_url:
            logger.warning("Server URL not configured, cannot update whitelist from server")
            return False
            
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
                
            # If we have a last_updated timestamp, send it to get only newer entries
            params = {}
            if self.last_updated:
                params["since"] = self.last_updated.isoformat()
                
            # Make the API request
            url = f"{self.server_url.rstrip('/')}/api/whitelist"
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                with self.update_lock:
                    if "domains" in data:
                        # Full replacement
                        new_domains = set()
                        for domain in data["domains"]:
                            if isinstance(domain, str) and self._is_valid_domain(domain):
                                new_domains.add(domain)
                                
                        self.domains = new_domains
                    elif isinstance(data, list):
                        # Just a list of domains - differential update
                        for domain in data:
                            if isinstance(domain, str) and self._is_valid_domain(domain):
                                self.domains.add(domain)
                    
                    # Update timestamp
                    self.last_updated = datetime.now()
                    
                    # Save updated whitelist to file if using "both" source
                    if self.whitelist_source == "both":
                        self._save_to_file()
                        
                    logger.info("Updated whitelist from server, now contains %d domains", len(self.domains))
                return True
                
            elif response.status_code == 304:
                # Not modified, our whitelist is already up-to-date
                logger.debug("Whitelist is already up-to-date")
                return True
                
            else:
                logger.error("Failed to update whitelist from server: HTTP %d %s", 
                             response.status_code, response.text)
                return False
                
        except requests.RequestException as e:
            logger.error("Error connecting to server for whitelist update: %s", str(e))
            return False
        except json.JSONDecodeError:
            logger.error("Invalid JSON response from server")
            return False
        except Exception as e:
            logger.error("Unexpected error updating whitelist from server: %s", str(e))
            return False
    
    def _save_to_file(self):
        """Save the current whitelist to the local file."""
        try:
            data = {
                "domains": list(self.domains),
                "last_updated": self.last_updated.isoformat() if self.last_updated else None
            }
            
            with open(self.whitelist_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug("Saved whitelist to file %s", self.whitelist_file)
        except Exception as e:
            logger.error("Error saving whitelist to file: %s", str(e))
    
    def is_allowed(self, domain: str) -> bool:
        """
        Check if a domain is in the whitelist.
        
        Args:
            domain: The domain name to check
            
        Returns:
            bool: True if domain is allowed, False otherwise
        """
        if not domain:
            return False
            
        # Clean up the domain (remove whitespace, lowercase)
        domain = domain.strip().lower()
        
        # Direct match
        if domain in self.domains:
            return True
            
        # Check parent domains
        parts = domain.split('.')
        for i in range(1, len(parts) - 1):
            parent_domain = '.'.join(parts[i:])
            if f"*.{parent_domain}" in self.domains:
                return True
        
        return False
    
    def add_domain(self, domain: str) -> bool:
        """
        Add a domain to the whitelist.
        
        Args:
            domain: The domain to add
            
        Returns:
            bool: True if domain was added, False if invalid or already exists
        """
        if not domain or not self._is_valid_domain(domain):
            logger.warning("Invalid domain format: %s", domain)
            return False
            
        domain = domain.strip().lower()
        
        with self.update_lock:
            if domain in self.domains:
                logger.debug("Domain already in whitelist: %s", domain)
                return False
                
            self.domains.add(domain)
            self.last_updated = datetime.now()
            
            # Save to file if using file or both as source
            if self.whitelist_source in ["file", "both"]:
                self._save_to_file()
                
            logger.info("Added domain to whitelist: %s", domain)
            return True
    
    def remove_domain(self, domain: str) -> bool:
        """
        Remove a domain from the whitelist.
        
        Args:
            domain: The domain to remove
            
        Returns:
            bool: True if domain was removed, False if not in whitelist
        """
        if not domain:
            return False
            
        domain = domain.strip().lower()
        
        with self.update_lock:
            if domain not in self.domains:
                logger.debug("Domain not in whitelist: %s", domain)
                return False
                
            self.domains.remove(domain)
            self.last_updated = datetime.now()
            
            # Save to file if using file or both as source
            if self.whitelist_source in ["file", "both"]:
                self._save_to_file()
                
            logger.info("Removed domain from whitelist: %s", domain)
            return True
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Check if a string is a valid domain name.
        
        Args:
            domain: Domain to validate
            
        Returns:
            bool: True if domain format is valid
        """
        if not domain or len(domain) > 253:
            return False
            
        # Allow wildcard domains (e.g., *.example.com)
        if domain.startswith("*."):
            domain = domain[2:]
            
        # Use regex for domain validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))


# Example usage (for testing)
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration for testing
    test_config = {
        "whitelist_source": "file",
        "whitelist_file": "test_whitelist.json",
        "server_url": "http://localhost:5000",
        "api_key": "test_key",
        "update_interval": 60
    }
    
    # Create whitelist manager
    whitelist = WhitelistManager(test_config)
    
    # Test if some domains are allowed
    test_domains = [
        "google.com",
        "malware.bad-domain.com",
        "www.github.com",
        "subdomain.wikipedia.org"
    ]
    
    print("\nTesting domain checks:")
    for domain in test_domains:
        allowed = whitelist.is_allowed(domain)
        print(f"Domain {domain}: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Add a domain and check again
    print("\nAdding malware.bad-domain.com to whitelist...")
    whitelist.add_domain("malware.bad-domain.com")
    
    print("\nTesting again after adding domain:")
    for domain in test_domains:
        allowed = whitelist.is_allowed(domain)
        print(f"Domain {domain}: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Start periodic updates (for demonstration)
    print("\nStarting periodic updates...")
    whitelist.start_periodic_updates()
    
    try:
        # Let it run for a bit, then stop
        time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        whitelist.stop_periodic_updates()
        print("\nWhitelist manager stopped.")