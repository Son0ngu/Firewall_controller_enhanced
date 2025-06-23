"""
Whitelist Service - Business logic for whitelist operations
"""

import logging
from typing import Dict, List, Optional
from models.whitelist_model import WhitelistModel

# Import time utilities
from time_utils import (
    now_vietnam, now_vietnam_naive, now_vietnam_iso,
    to_vietnam_timezone, parse_agent_timestamp_direct
)

logger = logging.getLogger(__name__)

class WhitelistService:
    """Service class for whitelist business logic"""
    
    def __init__(self, whitelist_model: WhitelistModel, socketio=None):
        """Initialize WhitelistService with model and socketio"""
        self.model = whitelist_model
        self.socketio = socketio
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.logger.info("WhitelistService initialized with time_utils")
    
    def get_all_entries(self, filters: Dict = None) -> Dict:
        """Get all whitelist entries with optional filtering"""
        query = {}
        if filters:
            query = self.model.build_query_from_filters(filters)
        
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
                "priority": entry.get("priority", "normal"),
                "added_by": entry.get("added_by"),
                "added_date": entry.get("added_date").isoformat() if entry.get("added_date") else None
            }
            
            # Add optional fields if they exist
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
        
        # Use Vietnam time for timestamps
        current_time = now_vietnam_naive()
        logger.info(f"Adding entry with timestamp: {current_time}")
        
        # Create processed entry
        processed_entry = {
            "type": entry_type,
            "value": value,
            "category": entry_data.get("category", "uncategorized"),
            "priority": entry_data.get("priority", "normal"),
            "added_by": client_ip,
            "added_date": current_time,
            "is_active": True
        }
        
        # Add optional fields if specified
        if entry_data.get("notes"):
            processed_entry["notes"] = entry_data.get("notes")
        
        if entry_data.get("expiry_date"):
            try:
                # Parse expiry date using time_utils
                expiry_vietnam = parse_agent_timestamp_direct(entry_data["expiry_date"])
                processed_entry["expiry_date"] = expiry_vietnam.replace(tzinfo=None)
                
            except Exception as e:
                logger.warning(f"Invalid expiry date format: {e}")
                raise ValueError("Invalid expiry date format")
                
        elif entry_data.get("is_temporary"):
            from datetime import timedelta
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
                "timestamp": now_vietnam_iso()
            })
        
        return {
            "id": entry_id,
            "message": f"{entry_type.capitalize()} added to whitelist",
            "timestamp": now_vietnam_iso()
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
            self.logger.error(f"Error testing DNS: {e}")
            return {"valid": False, "message": f"DNS test failed: {str(e)}"}
    
    def get_agent_sync_data(self, since_datetime: Optional[object] = None, agent_id: str = None) -> Dict:
        """Get whitelist data for agent synchronization"""
        try:
            sync_type = "full"  # Default to full sync
            
            # Handle since parameter
            if since_datetime:
                try:
                    sync_type = "incremental"
                    current_time = now_vietnam_naive()
                    
                    # Convert since to Vietnam naive
                    if isinstance(since_datetime, str):
                        since_vn = parse_agent_timestamp_direct(since_datetime)
                        since_naive = since_vn.replace(tzinfo=None)
                    else:
                        since_vn = to_vietnam_timezone(since_datetime)
                        since_naive = since_vn.replace(tzinfo=None)
                    
                    # Check if since is too old (more than 24 hours)
                    from datetime import timedelta
                    hours_ago = (current_time - since_naive).total_seconds() / 3600
                    
                    if hours_ago > 24:  # More than 24 hours ago
                        sync_type = "full"
                        self.logger.info(f"Since date too old ({hours_ago:.1f}h), switching to full sync")
                        since_datetime = None
                        
                except Exception as e:
                    self.logger.warning(f"Error processing since parameter: {e}")
                    since_datetime = None
                    sync_type = "full"
            
            # Get entries from model
            entries = self.model.get_entries_for_sync(since_datetime)
            current_time = now_vietnam_naive()
            
            # Format entries for agent sync
            domains = []
            for entry in entries:
                domain_entry = {
                    "value": entry.get("value"),
                    "type": entry.get("type", "domain"),
                    "added_date": entry.get("added_date"),
                    "priority": entry.get("priority", "normal"),
                    "category": entry.get("category", "uncategorized"),
                    "is_active": entry.get("is_active", True)
                }
                domains.append(domain_entry)
            
            response = {
                "domains": domains,
                "timestamp": current_time.isoformat(),
                "count": len(domains),
                "type": sync_type,
                "success": True,
                "server_time": now_vietnam_iso()
            }
            
            # Include agent_id if provided
            if agent_id:
                response["agent_id"] = agent_id
            
            self.logger.info(f"Agent sync response: {sync_type} sync with {len(domains)} domains for agent {agent_id or 'unknown'}")
            return response
            
        except Exception as e:
            self.logger.error(f"Error in agent sync: {e}")
            return {
                "domains": [],
                "timestamp": now_vietnam_iso(),
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
                "timestamp": now_vietnam_iso()
            })
        
        return success
    
    def bulk_add_entries(self, entries_data: List[Dict], client_ip: str) -> Dict:
        """Bulk add entries to whitelist"""
        if not entries_data:
            raise ValueError("No entries provided")
        
        if len(entries_data) > 1000:
            raise ValueError("Maximum 1000 entries allowed per bulk operation")
        
        current_time = now_vietnam_naive()
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
                "timestamp": now_vietnam_iso()
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
    
    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update an entry"""
        entry = self.model.find_entry_by_id(entry_id)
        if not entry:
            raise ValueError("Entry not found")
        
        # Validate update data
        if 'value' in update_data:
            value = update_data['value'].strip().lower()
            entry_type = update_data.get('type', entry.get('type', 'domain'))
            
            validation_result = self.model.validate_entry_value(entry_type, value)
            if not validation_result["valid"]:
                raise ValueError(validation_result["message"])
            
            update_data['value'] = value
        
        # Update timestamp
        update_data['updated_at'] = now_vietnam_naive()
        
        success = self.model.update_entry(entry_id, update_data)
        
        if success and self.socketio:
            self.socketio.emit("whitelist_updated", {
                "id": entry_id,
                "value": update_data.get('value', entry.get('value')),
                "type": update_data.get('type', entry.get('type', 'domain')),
                "timestamp": now_vietnam_iso()
            })
        
        return success