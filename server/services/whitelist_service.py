"""
Whitelist Service - Business logic for whitelist operations
UTC ONLY - Clean and simple
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
from models.whitelist_model import WhitelistModel

# Import time utilities - UTC ONLY
from time_utils import now_utc, to_utc_naive, now_iso, parse_agent_timestamp

logger = logging.getLogger(__name__)

class WhitelistService:
    """Service class for whitelist business logic - UTC ONLY"""
    
    def __init__(self, whitelist_model: WhitelistModel, socketio=None):
        """Initialize WhitelistService with model and socketio"""
        self.model = whitelist_model
        self.socketio = socketio
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.logger.info("WhitelistService initialized with UTC timezone support")
    
    def get_all_entries(self, filters: Dict = None) -> Dict:
        """Get all whitelist entries with optional filtering - UTC ONLY"""
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
            "success": True,
            "server_time": now_iso()  # UTC ISO
        }
    
    def add_entry(self, entry_data: Dict, client_ip: str) -> Dict:
        """Add new entry to whitelist - UTC ONLY"""
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
        
        # Use UTC time for timestamps - UTC naive for MongoDB
        current_time = to_utc_naive(now_utc())
        logger.info(f"Adding entry with UTC timestamp: {current_time}")
        
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
                # Parse expiry date using UTC parsing
                expiry_utc = parse_agent_timestamp(entry_data["expiry_date"])
                processed_entry["expiry_date"] = expiry_utc.replace(tzinfo=None)  # UTC naive for MongoDB
                
            except Exception as e:
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
        
        # Broadcast notification via SocketIO - UTC only
        if self.socketio:
            self.socketio.emit("whitelist_added", {
                "type": entry_type,
                "value": value,
                "category": processed_entry["category"],
                "added_by": client_ip,
                "timestamp": now_iso()  # UTC ISO
            })
        
        return {
            "id": entry_id,
            "message": f"{entry_type.capitalize()} added to whitelist",
            "timestamp": now_iso(),  # UTC ISO
            "server_time": now_iso()  # UTC ISO
        }
    
    def test_entry(self, entry_data: Dict) -> Dict:
        """Test an entry before adding it - UTC ONLY"""
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
                    "dns_info": dns_info,
                    "server_time": now_iso()  # UTC ISO
                }
            
            return {
                "valid": True, 
                "message": "Entry is valid",
                "server_time": now_iso()  # UTC ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error testing entry: {e}")
            return {
                "valid": False, 
                "message": f"Test failed: {str(e)}",
                "server_time": now_iso()  # UTC ISO
            }
    
    def test_dns(self, domain: str) -> Dict:
        """Test DNS resolution for a domain - UTC ONLY"""
        try:
            if not domain:
                return {
                    "valid": False, 
                    "message": "Domain is required",
                    "server_time": now_iso()  # UTC ISO
                }
            
            domain = domain.strip().lower()
            
            # Validate domain format first
            validation_result = self.model.validate_entry_value("domain", domain)
            if not validation_result["valid"]:
                return {
                    **validation_result,
                    "server_time": now_iso()  # UTC ISO
                }
            
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
                    "count": len(ips),
                    "server_time": now_iso()  # UTC ISO
                }
                
            except Exception as e:
                return {
                    "valid": False,
                    "message": f"DNS resolution failed: {str(e)}",
                    "domain": domain,
                    "server_time": now_iso()  # UTC ISO
                }
                
        except Exception as e:
            self.logger.error(f"Error testing DNS: {e}")
            return {
                "valid": False, 
                "message": f"DNS test failed: {str(e)}",
                "server_time": now_iso()  # UTC ISO
            }
    
    def get_agent_sync_data(self, since_datetime: Optional[object] = None, agent_id: str = None) -> Dict:
        """Get whitelist data for agent synchronization - UTC ONLY"""
        try:
            sync_type = "full"  # Default to full sync
            
            # Handle since parameter
            if since_datetime:
                try:
                    sync_type = "incremental"
                    current_time = to_utc_naive(now_utc())  # UTC naive for comparison
                    
                    # Convert since to UTC naive
                    if isinstance(since_datetime, str):
                        since_utc = parse_agent_timestamp(since_datetime)  # UTC parsing
                        since_naive = since_utc.replace(tzinfo=None)
                    else:
                        # Convert datetime to UTC naive
                        if isinstance(since_datetime, datetime):
                            if since_datetime.tzinfo is None:
                                since_utc = since_datetime.replace(tzinfo=timezone.utc)
                            else:
                                since_utc = since_datetime.astimezone(timezone.utc)
                            since_naive = since_utc.replace(tzinfo=None)
                        else:
                            since_naive = to_utc_naive(now_utc())
                    
                    # Check if since is too old (more than 24 hours)
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
            current_time = to_utc_naive(now_utc())
            
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
                "server_time": now_iso()  # UTC ISO
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
                "timestamp": now_iso(),  # UTC ISO
                "count": 0,
                "type": "error",
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry - UTC ONLY"""
        entry = self.model.find_entry_by_id(entry_id)
        if not entry:
            raise ValueError("Entry not found")
        
        success = self.model.delete_entry(entry_id)
        
        if success and self.socketio:
            self.socketio.emit("whitelist_deleted", {
                "id": entry_id,
                "value": entry.get("value"),
                "type": entry.get("type", "domain"),
                "timestamp": now_iso()  # UTC ISO
            })
        
        return success
    
    def bulk_add_entries(self, entries_data: List[Dict], client_ip: str) -> Dict:
        """Bulk add entries to whitelist - UTC ONLY"""
        if not entries_data:
            raise ValueError("No entries provided")
        
        if len(entries_data) > 1000:
            raise ValueError("Maximum 1000 entries allowed per bulk operation")
        
        current_time = to_utc_naive(now_utc())  # UTC naive for MongoDB
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
                "timestamp": now_iso()  # UTC ISO
            })
        
        return {
            "inserted_count": len(inserted_ids),
            "error_count": len(errors),
            "errors": errors[:10],
            "success": len(inserted_ids) > 0,
            "server_time": now_iso()  # UTC ISO
        }
    
    def get_statistics(self) -> Dict:
        """Get whitelist statistics - UTC ONLY"""
        try:
            stats = self.model.get_statistics()
            stats["server_time"] = now_iso()  # UTC ISO
            return stats
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {
                "total": 0,
                "active": 0,
                "inactive": 0,
                "by_type": {},
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update an entry - UTC ONLY"""
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
        
        # Update timestamp - UTC naive for MongoDB
        update_data['updated_at'] = to_utc_naive(now_utc())
        
        success = self.model.update_entry(entry_id, update_data)
        
        if success and self.socketio:
            self.socketio.emit("whitelist_updated", {
                "id": entry_id,
                "value": update_data.get('value', entry.get('value')),
                "type": update_data.get('type', entry.get('type', 'domain')),
                "timestamp": now_iso()  # UTC ISO
            })
        
        return success
    
    def sync_for_agent(self, agent_id: str, token: str, since_datetime: datetime = None) -> Dict:
        """Sync whitelist for agent - UTC ONLY"""
        try:
            # Get entries for sync
            domains = self.model.get_entries_for_sync(since_datetime)
            
            self.logger.info(f"Syncing {len(domains)} domains for agent {agent_id}")
            
            return {
                "success": True,
                "domains": domains,
                "count": len(domains),
                "agent_id": agent_id,
                "server_time": now_iso(),  # UTC ISO
                "since": since_datetime.isoformat() if since_datetime else None
            }
            
        except Exception as e:
            self.logger.error(f"Error syncing for agent {agent_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "domains": [],
                "count": 0,
                "server_time": now_iso()  # UTC ISO
            }
    
    def get_all_domains(self, limit: int = 100, offset: int = 0, search: str = None) -> Dict:
        """Get all domains with pagination - UTC ONLY"""
        try:
            # Build query
            query = {}
            if search:
                query["$or"] = [
                    {"value": {"$regex": search, "$options": "i"}},
                    {"category": {"$regex": search, "$options": "i"}}
                ]
            
            # Get domains
            domains = self.model.find_all_entries(query)
            
            # Apply pagination
            total_count = len(domains)
            paginated_domains = domains[offset:offset + limit]
            
            return {
                "success": True,
                "domains": paginated_domains,
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "server_time": now_iso()  # UTC ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error getting all domains: {e}")
            return {
                "success": False,
                "error": str(e),
                "domains": [],
                "total": 0,
                "server_time": now_iso()  # UTC ISO
            }
    
    def add_domain(self, domain_value: str, category: str = "general") -> Dict:
        """Add new domain to whitelist - UTC ONLY"""
        try:
            # Check if domain already exists
            existing = self.model.find_entry_by_value(domain_value)
            if existing:
                return {
                    "success": False,
                    "error": "Domain already exists in whitelist",
                    "existing_entry": existing,
                    "server_time": now_iso()  # UTC ISO
                }
            
            # Validate domain
            validation = self.model.validate_entry_value("domain", domain_value)
            if not validation.get("valid"):
                return {
                    "success": False,
                    "error": validation.get("message", "Invalid domain"),
                    "server_time": now_iso()  # UTC ISO
                }
            
            # Create entry data
            entry_data = {
                "value": domain_value.strip().lower(),
                "type": "domain",
                "category": category,
                "is_active": True,
                "priority": "normal",
                "added_by": "admin"
            }
            
            # Insert domain
            entry_id = self.model.insert_entry(entry_data)
            
            return {
                "success": True,
                "entry_id": entry_id,
                "domain": domain_value,
                "category": category,
                "server_time": now_iso()  # UTC ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error adding domain {domain_value}: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def delete_domain(self, domain_id: str) -> Dict:
        """Delete domain from whitelist - UTC ONLY"""
        try:
            # Check if domain exists
            existing = self.model.find_entry_by_id(domain_id)
            if not existing:
                return {
                    "success": False,
                    "error": "Domain not found",
                    "server_time": now_iso()  # UTC ISO
                }
            
            # Delete domain
            success = self.model.delete_entry(domain_id)
            
            if success:
                return {
                    "success": True,
                    "domain_id": domain_id,
                    "domain_value": existing.get("value"),
                    "server_time": now_iso()  # UTC ISO
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to delete domain",
                    "server_time": now_iso()  # UTC ISO
                }
                
        except Exception as e:
            self.logger.error(f"Error deleting domain {domain_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def import_domains(self, domains: List[str], category: str = "imported") -> Dict:
        """Import multiple domains - UTC ONLY"""
        try:
            added_count = 0
            duplicate_count = 0
            error_count = 0
            errors = []
            
            for domain in domains:
                try:
                    domain = domain.strip().lower()
                    if not domain:
                        continue
                    
                    # Check if already exists
                    if self.model.find_entry_by_value(domain):
                        duplicate_count += 1
                        continue
                    
                    # Validate domain
                    validation = self.model.validate_entry_value("domain", domain)
                    if not validation.get("valid"):
                        error_count += 1
                        errors.append(f"{domain}: {validation.get('message')}")
                        continue
                    
                    # Create entry
                    entry_data = {
                        "value": domain,
                        "type": "domain",
                        "category": category,
                        "is_active": True,
                        "priority": "normal",
                        "added_by": "import"
                    }
                    
                    self.model.insert_entry(entry_data)
                    added_count += 1
                    
                except Exception as e:
                    error_count += 1
                    errors.append(f"{domain}: {str(e)}")
            
            return {
                "success": True,
                "added_count": added_count,
                "duplicate_count": duplicate_count,
                "error_count": error_count,
                "errors": errors[:10],  # Limit error list
                "total_processed": len(domains),
                "server_time": now_iso()  # UTC ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error importing domains: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def export_domains(self, format: str = "json", category: str = None) -> Dict:
        """Export domains in specified format - UTC ONLY"""
        try:
            # Build query
            query = {}
            if category:
                query["category"] = category
            
            # Get domains
            domains = self.model.find_all_entries(query)
            
            if format == "txt":
                # Text format - one domain per line
                domain_list = [domain["value"] for domain in domains]
                text_data = "\n".join(domain_list)
                
                return {
                    "success": True,
                    "data": text_data,
                    "count": len(domain_list),
                    "format": format,
                    "server_time": now_iso()  # UTC ISO
                }
            else:
                # JSON format
                return {
                    "success": True,
                    "data": domains,
                    "count": len(domains),
                    "format": format,
                    "server_time": now_iso()  # UTC ISO
                }
                
        except Exception as e:
            self.logger.error(f"Error exporting domains: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }