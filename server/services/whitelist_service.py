"""
Whitelist Service - Business logic for whitelist operations
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from models.whitelist_model import WhitelistModel

logger = logging.getLogger(__name__)

class WhitelistService:
    """Service class for whitelist business logic"""
    
    def __init__(self, whitelist_model: WhitelistModel, socketio=None):
        """Initialize WhitelistService with model and socketio"""
        self.model = whitelist_model
        self.socketio = socketio
        
        # ✅ FIX: Use correct attribute name from model
        self.server_timezone = self.model.server_timezone  # Changed from .timezone to .server_timezone
        
        # Set up logger for this service
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # ✅ ADD: Debug timezone info
        self.logger.info(f"WhitelistService initialized with timezone: {self.server_timezone}")
    
    def _now_local(self) -> datetime:
        """Get current time in Vietnam timezone"""
        # ✅ FIX: Use model's method directly - no need to duplicate
        return self.model._now_local()
    
    def _ensure_timezone_aware(self, dt: datetime) -> datetime:
        """Ensure datetime is timezone-aware"""
        # ✅ FIX: Use model's method directly - no need to duplicate
        return self.model._ensure_timezone_aware(dt)
    
    def get_all_entries(self, filters: Dict = None) -> Dict:
        """Get all whitelist entries with optional filtering"""
        query = {}
        if filters:
            query = self.model.build_query_from_filters(filters)
        
        entries = self.model.find_all_entries(query)
        
        # ✅ FIX: Proper timezone handling - entries are already converted by model
        formatted_entries = []
        for entry in entries:
            formatted_entry = {
                "id": entry.get("_id"),
                "type": entry.get("type", "domain"),
                "value": entry.get("value"),
                "domain": entry.get("value"),  # Backwards compatibility
                "category": entry.get("category"),
                "priority": entry.get("priority", "normal"),
                "added_by": entry.get("added_by"),
                # ✅ FIX: Entries from model are already in UTC+7, just format them
                "added_date": entry.get("added_date").isoformat() if entry.get("added_date") else None
            }
            
            # ✅ CONDITIONAL: Only add optional fields if they exist
            if entry.get("notes"):
                formatted_entry["notes"] = entry.get("notes")
            if entry.get("expiry_date"):
                formatted_entry["expiry_date"] = entry.get("expiry_date").isoformat()
            if entry.get("max_requests_per_hour"):
                formatted_entry["max_requests_per_hour"] = entry.get("max_requests_per_hour")
            if entry.get("is_temporary"):
                formatted_entry["is_temporary"] = entry.get("is_temporary")
            if entry.get("dns_config"):
                formatted_entry["dns_config"] = entry.get("dns_config")
            
            # ✅ ADD: Include timezone info for debugging
            if entry.get("timezone"):
                formatted_entry["timezone"] = entry.get("timezone")
            if entry.get("local_added_date"):
                formatted_entry["local_added_date"] = entry.get("local_added_date")
            
            formatted_entries.append(formatted_entry)
        
        return {
            "domains": formatted_entries,
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
        
        # ✅ FIX: Get current time
        current_time = self._now_local()
        logger.info(f"Adding entry with timestamp: {current_time}")
        
        # ✅ FIX: Minimal entry data
        processed_entry = {
            "type": entry_type,
            "value": value,
            "category": entry_data.get("category", "uncategorized"),
            "priority": entry_data.get("priority", "normal"),
            "added_by": client_ip,
            "added_date": current_time,
            "is_active": True
        }
        
        # ✅ CONDITIONAL: Only add optional fields if specified
        if entry_data.get("notes"):
            processed_entry["notes"] = entry_data.get("notes")
        
        if entry_data.get("expiry_date"):
            try:
                expiry_str = entry_data["expiry_date"]
                if expiry_str.endswith('Z'):
                    expiry_str = expiry_str[:-1] + '+00:00'
                
                parsed_date = datetime.fromisoformat(expiry_str)
                processed_entry["expiry_date"] = self._ensure_timezone_aware(parsed_date)
                
            except (ValueError, AttributeError) as e:
                logger.warning(f"Invalid expiry date format: {e}")
                raise ValueError("Invalid expiry date format")
                
        elif entry_data.get("is_temporary"):
            processed_entry["is_temporary"] = True
            processed_entry["expiry_date"] = current_time + timedelta(hours=24)
        
        if entry_data.get("max_requests_per_hour"):
            try:
                processed_entry["max_requests_per_hour"] = int(entry_data["max_requests_per_hour"])
            except (ValueError, TypeError):
                pass
        
        if entry_type == "domain" and entry_data.get("dns_config"):
            dns_config = entry_data["dns_config"]
            if dns_config.get("verify"):
                dns_result = self.model.verify_dns(value)
                if not dns_result["valid"]:
                    raise ValueError(f"DNS verification failed: {dns_result['message']}")
                processed_entry["dns_info"] = dns_result["info"]
            processed_entry["dns_config"] = dns_config
        
        # Insert entry using model
        try:
            entry_id = self.model.insert_entry(processed_entry)
            logger.info(f"Successfully inserted entry with ID: {entry_id}")
        except Exception as e:
            logger.error(f"Failed to insert entry: {e}")
            raise
        
        # Broadcast notification via SocketIO
        if self.socketio:
            self.socketio.emit("whitelist_added", {
                "type": entry_type,
                "value": value,
                "category": processed_entry["category"],
                "added_by": client_ip,
                "timestamp": current_time.isoformat()
            })
        
        return {
            "id": entry_id,
            "message": f"{entry_type.capitalize()} added to whitelist",
            "timestamp": current_time.isoformat()
        }
    
    def test_entry(self, entry_data: Dict) -> Dict:
        """Test an entry before adding it"""
        try:
            entry_type = entry_data.get("type", "domain")
            value = entry_data.get("value", "").strip().lower()
            
            if not value:
                return {"valid": False, "message": "Value is required"}
            
            # Validate entry using model
            validation_result = self.model.validate_entry_value(entry_type, value)
            
            if not validation_result["valid"]:
                return validation_result
            
            # Check for duplicates
            existing = self.model.find_entry_by_value(value)
            if existing:
                return {"valid": False, "message": "Entry already exists"}
            
            # Additional tests based on type
            if entry_type == "domain":
                try:
                    # Test DNS resolution
                    import socket
                    socket.getaddrinfo(value, None, socket.AF_INET)
                    dns_info = f"DNS resolution successful"
                except Exception as e:
                    dns_info = f"DNS resolution failed: {str(e)}"
                
                return {
                    "valid": True,
                    "message": "Entry is valid",
                    "dns_info": dns_info
                }
            
            return {"valid": True, "message": "Entry is valid"}
            
        except Exception as e:
            # ✅ FIX: Use self.logger instead of self.logger.error
            self.logger.error(f"Error testing entry: {e}")
            return {"valid": False, "message": f"Test failed: {str(e)}"}
    
    def test_dns(self, domain: str) -> Dict:
        """Test DNS resolution for a domain"""
        try:
            if not domain:
                return {"valid": False, "message": "Domain is required"}
            
            domain = domain.strip().lower()
            
            # Validate domain format first
            validation_result = self.model.validate_entry_value("domain", domain)
            if not validation_result["valid"]:
                return validation_result
            
            # Test DNS resolution
            import socket
            try:
                results = socket.getaddrinfo(domain, None, socket.AF_INET)
                ips = []
                for result in results:
                    ip = result[4][0]
                    if ip not in ips:
                        ips.append(ip)
                
                return {
                    "valid": True,
                    "message": f"DNS resolution successful",
                    "domain": domain,
                    "ips": ips,
                    "count": len(ips)
                }
                
            except Exception as e:
                return {
                    "valid": False,
                    "message": f"DNS resolution failed: {str(e)}",
                    "domain": domain
                }
                
        except Exception as e:
            # ✅ FIX: Use self.logger instead of self.logger.error  
            self.logger.error(f"Error testing DNS: {e}")
            return {"valid": False, "message": f"DNS test failed: {str(e)}"}
    
    def get_agent_sync_data(self, since: str = None, agent_id: str = None) -> Dict:
        """Get whitelist data for agent synchronization"""
        try:
            since_date = None
            if since:
                try:
                    if isinstance(since, str):
                        since_str = since
                        if since_str.endswith('Z'):
                            since_str = since_str[:-1] + '+00:00'
                        since_date = datetime.fromisoformat(since_str)
                    else:
                        since_date = since
                        
                    since_date = self._ensure_timezone_aware(since_date)
                        
                except (ValueError, AttributeError) as e:
                    # ✅ FIX: Use self.logger instead of self.logger.warning
                    self.logger.warning(f"Invalid since date format '{since}': {e}")
                    since_date = None
        
            # Get entries from model for sync
            query = {"is_active": True}
            if since_date:
                query["added_date"] = {"$gte": since_date}
            
            entries = self.model.find_all_entries(query)
            current_time = self._now_local()
            
            # Format entries for agent sync
            domains = []
            for entry in entries:
                domain_entry = {
                    "value": entry.get("value"),
                    "type": entry.get("type", "domain"),
                    "added_date": entry.get("added_date").isoformat() if entry.get("added_date") else None,
                    "priority": entry.get("priority", "normal"),
                    "category": entry.get("category", "uncategorized")
                }
                domains.append(domain_entry)
            
            response = {
                "domains": domains,
                "timestamp": current_time.isoformat(),
                "count": len(domains),
                "type": "incremental" if since_date else "full",
                "success": True
            }
            
            # ✅ FIX: Use self.logger instead of self.logger.info
            self.logger.info(f"Agent sync response: {response['type']} sync with {len(domains)} domains")
            return response
            
        except Exception as e:
            # ✅ FIX: Use self.logger instead of self.logger.error
            self.logger.error(f"Error in agent sync: {e}")
            return {
                "domains": [],
                "timestamp": self._now_local().isoformat(),
                "count": 0,
                "type": "error",
                "success": False,
                "error": str(e)
            }
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry"""
        entry = self.model.find_entry_by_id(entry_id)
        if not entry:
            raise ValueError("Entry not found")
        
        success = self.model.delete_entry(entry_id)
        
        if success and self.socketio:
            self.socketio.emit("whitelist_deleted", {
                "id": entry_id,
                "value": entry.get("value"),
                "type": entry.get("type", "domain"),
                "timestamp": self._now_local().isoformat()
            })
        
        return success
    
    def bulk_add_entries(self, entries_data: List[Dict], client_ip: str) -> Dict:
        """Bulk add entries to whitelist"""
        if not entries_data:
            raise ValueError("No entries provided")
        
        if len(entries_data) > 1000:
            raise ValueError("Maximum 1000 entries allowed per bulk operation")
        
        current_time = self._now_local()
        processed_entries = []
        errors = []
        
        for i, entry_data in enumerate(entries_data):
            try:
                entry_type = entry_data.get("type", "domain")
                value = entry_data.get("value", "").strip().lower()
                
                if not value:
                    errors.append(f"Entry {i+1}: Value is required")
                    continue
                
                validation_result = self.model.validate_entry_value(entry_type, value)
                if not validation_result["valid"]:
                    errors.append(f"Entry {i+1}: {validation_result['message']}")
                    continue
                
                if any(e.get("value") == value for e in processed_entries):
                    errors.append(f"Entry {i+1}: Duplicate value in batch")
                    continue
                
                existing = self.model.find_entry_by_value(value)
                if existing:
                    errors.append(f"Entry {i+1}: Entry already exists")
                    continue
                
                processed_entry = {
                    "type": entry_type,
                    "value": value,
                    "category": entry_data.get("category", "uncategorized"),
                    "priority": entry_data.get("priority", "normal"),
                    "added_by": client_ip,
                    "added_date": current_time,
                    "is_active": True,
                    "notes": entry_data.get("notes", "Bulk import")
                }
                
                processed_entries.append(processed_entry)
                
            except Exception as e:
                errors.append(f"Entry {i+1}: {str(e)}")
        
        inserted_ids = []
        if processed_entries:
            inserted_ids = self.model.bulk_insert_entries(processed_entries)
        
        if inserted_ids and self.socketio:
            self.socketio.emit("whitelist_bulk_added", {
                "count": len(inserted_ids),
                "added_by": client_ip,
                "timestamp": current_time.isoformat()
            })
        
        return {
            "inserted_count": len(inserted_ids),
            "error_count": len(errors),
            "errors": errors[:10],
            "success": len(inserted_ids) > 0
        }
    
    def get_statistics(self) -> Dict:
        """Get whitelist statistics"""
        return self.model.get_statistics()