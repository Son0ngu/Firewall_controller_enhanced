"""
Whitelist Service - Business logic for whitelist operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from models.whitelist_model import WhitelistModel
import pytz  # ✅ ADD TIMEZONE SUPPORT

class WhitelistService:
    """Service class for whitelist business logic"""
    
    def __init__(self, whitelist_model: WhitelistModel, socketio=None):
        self.model = whitelist_model
        self.socketio = socketio
        # ✅ ADD TIMEZONE
        self.timezone = pytz.timezone('Asia/Ho_Chi_Minh')  # Vietnam timezone
    
    def _get_current_time(self):
        """Get current time in configured timezone"""
        return datetime.now(self.timezone)
    
    def get_all_entries(self, filters: Dict = None) -> Dict:
        """Get all whitelist entries with optional filtering"""
        # Build query from filters
        query = {}
        if filters:
            query = self.model.build_query_from_filters(filters)
        
        # Get entries from model
        entries = self.model.find_all_entries(query)
        
        # Format entries for response
        formatted_entries = []
        for entry in entries:
            formatted_entry = {
                "id": entry.get("_id"),
                "type": entry.get("type", "domain"),
                "value": entry.get("value"),
                "domain": entry.get("value"),  # Backwards compatibility
                "category": entry.get("category"),
                "notes": entry.get("notes"),
                "priority": entry.get("priority", "normal"),
                "added_by": entry.get("added_by"),
                "added_date": entry.get("added_date").isoformat() if entry.get("added_date") else None,
                "expiry_date": entry.get("expiry_date").isoformat() if entry.get("expiry_date") else None,
                "max_requests_per_hour": entry.get("max_requests_per_hour"),
                "enable_logging": entry.get("enable_logging", False),
                "is_temporary": entry.get("is_temporary", False),
                "dns_config": entry.get("dns_config"),
                "usage_count": entry.get("usage_count", 0),
                "last_used": entry.get("last_used").isoformat() if entry.get("last_used") else None
            }
            formatted_entries.append(formatted_entry)
        
        return {
            "domains": formatted_entries,  # Keep "domains" for backwards compatibility
            "success": True
        }
    
    def add_entry(self, entry_data: Dict, client_ip: str) -> Dict:
        """Add new entry to whitelist"""
        entry_type = entry_data.get("type", "domain")
        value = entry_data.get("value", "").strip().lower()
        
        if not value:
            raise ValueError("Value is required")
        
        # Validate entry using model
        validation_result = self.model.validate_entry_value(entry_type, value)
        if not validation_result["valid"]:
            raise ValueError(validation_result["message"])
        
        # Check for duplicates
        existing = self.model.find_entry_by_value(value)
        if existing:
            raise ValueError("Entry already exists")
        
        # ✅ USE TIMEZONE-AWARE TIME
        current_time = self._get_current_time()
        processed_entry = {
            "type": entry_type,
            "value": value,
            "category": entry_data.get("category", "uncategorized"),
            "notes": entry_data.get("notes"),
            "priority": entry_data.get("priority", "normal"),
            "added_by": client_ip,
            "enable_logging": entry_data.get("enable_logging", False),
            "is_temporary": entry_data.get("is_temporary", False)
        }
        
        # Add expiry date
        if entry_data.get("expiry_date"):
            try:
                # ✅ HANDLE TIMEZONE-AWARE EXPIRY
                expiry_str = entry_data["expiry_date"]
                if expiry_str.endswith('Z'):
                    expiry_dt = datetime.fromisoformat(expiry_str[:-1]).replace(tzinfo=pytz.UTC)
                else:
                    expiry_dt = datetime.fromisoformat(expiry_str)
                    if expiry_dt.tzinfo is None:
                        expiry_dt = self.timezone.localize(expiry_dt)
                processed_entry["expiry_date"] = expiry_dt
            except ValueError:
                raise ValueError("Invalid expiry date format")
        elif entry_data.get("is_temporary"):
            processed_entry["expiry_date"] = current_time + timedelta(hours=24)
        
        # Add rate limiting
        if entry_data.get("max_requests_per_hour"):
            processed_entry["max_requests_per_hour"] = int(entry_data["max_requests_per_hour"])
        
        # Add DNS config for domains
        if entry_type == "domain" and entry_data.get("dns_config"):
            dns_config = entry_data["dns_config"]
            if dns_config.get("verify"):
                dns_result = self.model.verify_dns(value)
                if not dns_result["valid"]:
                    raise ValueError(f"DNS verification failed: {dns_result['message']}")
                processed_entry["dns_info"] = dns_result["info"]
            processed_entry["dns_config"] = dns_config
        
        # Insert entry using model
        entry_id = self.model.insert_entry(processed_entry)
        
        # Broadcast notification via SocketIO
        if self.socketio:
            self.socketio.emit("whitelist_added", {
                "type": entry_type,
                "value": value,
                "category": processed_entry["category"],
                "added_by": client_ip,
                "timestamp": current_time.isoformat()  # ✅ TIMEZONE-AWARE
            })
        
        return {
            "id": entry_id,
            "message": f"{entry_type.capitalize()} added to whitelist"
        }
    
    def test_entry(self, entry_data: Dict) -> Dict:
        """Test an entry before adding it"""
        entry_type = entry_data.get("type")
        value = entry_data.get("value", "").strip()
        
        if not entry_type or not value:
            raise ValueError("Type and value are required")
        
        # Validate entry using model
        validation_result = self.model.validate_entry_value(entry_type, value)
        if not validation_result["valid"]:
            raise ValueError(validation_result["message"])
        
        result = {"valid": True, "type": entry_type, "value": value}
        
        # DNS verification for domains
        if entry_type == "domain" and entry_data.get("dns_verify"):
            dns_result = self.model.verify_dns(value)
            result["dns_info"] = dns_result.get("info", [])
            result["dns_valid"] = dns_result["valid"]
        
        # Reachability test for IPs and URLs
        if entry_type in ["ip", "url"]:
            reachable = self._test_reachability(entry_type, value)
            result["reachable"] = reachable
        
        return result
    
    def test_dns(self, domain: str) -> Dict:
        """Test DNS resolution for a domain"""
        if not domain:
            raise ValueError("Domain is required")
        
        return self.model.verify_dns(domain)
    
    def get_agent_sync_data(self, since: str = None, agent_id: str = None) -> Dict:
        """Get whitelist data for agent synchronization"""
        since_date = None
        if since:
            try:
                # ✅ PARSE TIMEZONE-AWARE DATETIME
                if since.endswith('Z'):
                    since_date = datetime.fromisoformat(since[:-1]).replace(tzinfo=pytz.UTC)
                else:
                    since_date = datetime.fromisoformat(since)
                    if since_date.tzinfo is None:
                        since_date = self.timezone.localize(since_date)
                # Convert to local timezone for comparison
                since_date = since_date.astimezone(self.timezone)
            except ValueError:
                pass  # Invalid date format, ignore
        
        # Get domains from model
        domains = self.model.get_entries_for_sync(since_date)
        
        # ✅ USE TIMEZONE-AWARE TIMESTAMP
        current_time = self._get_current_time()
        
        return {
            "domains": domains,
            "timestamp": current_time.isoformat(),
            "count": len(domains),
            "type": "incremental" if since else "full"
        }
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry"""
        # Check if entry exists
        entry = self.model.find_entry_by_id(entry_id)
        if not entry:
            raise ValueError("Entry not found")
        
        # Delete using model
        success = self.model.delete_entry(entry_id)
        
        # Broadcast notification via SocketIO
        if success and self.socketio:
            self.socketio.emit("whitelist_deleted", {
                "id": entry_id,
                "value": entry.get("value"),
                "type": entry.get("type", "domain"),
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return success
    
    def bulk_add_entries(self, entries_data: List[Dict], client_ip: str) -> Dict:
        """Bulk add entries to whitelist"""
        if not entries_data:
            raise ValueError("No entries provided")
        
        if len(entries_data) > 1000:
            raise ValueError("Maximum 1000 entries allowed per bulk operation")
        
        # Process and validate entries
        processed_entries = []
        errors = []
        
        for i, entry_data in enumerate(entries_data):
            try:
                entry_type = entry_data.get("type", "domain")
                value = entry_data.get("value", "").strip().lower()
                
                if not value:
                    errors.append(f"Entry {i+1}: Value is required")
                    continue
                
                # Validate entry
                validation_result = self.model.validate_entry_value(entry_type, value)
                if not validation_result["valid"]:
                    errors.append(f"Entry {i+1}: {validation_result['message']}")
                    continue
                
                # Check for duplicates within the batch
                if any(e.get("value") == value for e in processed_entries):
                    errors.append(f"Entry {i+1}: Duplicate value in batch")
                    continue
                
                # Check for existing entries
                existing = self.model.find_entry_by_value(value)
                if existing:
                    errors.append(f"Entry {i+1}: Entry already exists")
                    continue
                
                # Prepare entry
                processed_entry = {
                    "type": entry_type,
                    "value": value,
                    "category": entry_data.get("category", "uncategorized"),
                    "notes": entry_data.get("notes", "Bulk import"),
                    "priority": entry_data.get("priority", "normal"),
                    "added_by": client_ip
                }
                
                processed_entries.append(processed_entry)
                
            except Exception as e:
                errors.append(f"Entry {i+1}: {str(e)}")
        
        # ✅ USE TIMEZONE-AWARE TIME FOR BULK OPERATIONS
        current_time = self._get_current_time()
        
        # Insert valid entries using model
        inserted_ids = []
        if processed_entries:
            inserted_ids = self.model.bulk_insert_entries(processed_entries)
        
        # Broadcast notification for successful entries
        if inserted_ids and self.socketio:
            self.socketio.emit("whitelist_bulk_added", {
                "count": len(inserted_ids),
                "added_by": client_ip,
                "timestamp": current_time.isoformat()  # ✅ TIMEZONE-AWARE
            })
        
        return {
            "inserted_count": len(inserted_ids),
            "error_count": len(errors),
            "errors": errors[:10],  # Return first 10 errors only
            "success": len(inserted_ids) > 0
        }
    
    def get_statistics(self) -> Dict:
        """Get whitelist statistics"""
        return self.model.get_statistics()
    
    def _test_reachability(self, entry_type: str, value: str) -> bool:
        """Test if an IP or URL is reachable"""
        try:
            if entry_type == "ip":
                # Extract IP from value
                import socket
                import ipaddress
                ip_part = value.split(':')[0]
                host = ipaddress.ip_address(ip_part)
                # Simple ping-like test
                socket.create_connection((str(host), 80), timeout=5)
                return True
            elif entry_type == "url":
                # For URLs, could use requests library for HTTP testing
                # For now, just return True
                return True
        except Exception:
            return False
        
        return False