"""
Whitelist Model - handles whitelist data operations
UTC ONLY - Clean and simple
"""
import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import logging
import re

# Import time utilities - UTC ONLY
from time_utils import now_utc, to_utc_naive, parse_agent_timestamp

class WhitelistModel:
    """Model for whitelist data operations - UTC ONLY"""
    
    def __init__(self, db: Database):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.db = db
        self.collection: Collection = db.whitelist
        
        # Create indexes for better performance
        self._create_indexes()
    
    def _create_indexes(self):
        """Create necessary indexes with enhanced conflict handling"""
        try:
            #  FIX: Get detailed existing indexes information
            existing_indexes = list(self.collection.list_indexes())
            
            #  FIX: Create mapping of field -> existing index info
            existing_fields = {}
            for idx in existing_indexes:
                if 'key' in idx:
                    for field, direction in idx['key'].items():
                        if field != '_id':  # Skip default _id index
                            existing_fields[field] = {
                                'name': idx['name'],
                                'direction': direction,
                                'sparse': idx.get('sparse', False)
                            }
            
            self.logger.debug(f"Existing field indexes: {existing_fields}")
            
            #  FIX: Define desired indexes with all properties
            desired_indexes = [
                {"field": "value", "direction": 1, "sparse": False},
                {"field": "type", "direction": 1, "sparse": False},
                {"field": "added_date", "direction": -1, "sparse": False},
                {"field": "is_active", "direction": 1, "sparse": False},
                {"field": "expiry_date", "direction": 1, "sparse": True}
            ]
            
            #  FIX: Check and create indexes only if needed
            for idx_spec in desired_indexes:
                field = idx_spec["field"]
                direction = idx_spec["direction"]
                sparse = idx_spec["sparse"]
                
                if field in existing_fields:
                    existing = existing_fields[field]
                    
                    #  FIX: Check if existing index matches our requirements
                    if (existing['direction'] == direction and 
                        existing.get('sparse', False) == sparse):
                        self.logger.debug(f" Index '{field}' already exists with correct properties (name: {existing['name']})")
                        continue
                    else:
                        self.logger.info(f" Index '{field}' exists but with different properties - keeping existing")
                        continue
                
                #  FIX: Create index only if it doesn't exist
                try:
                    if sparse:
                        self.collection.create_index([(field, direction)], sparse=True)
                        self.logger.debug(f" Created sparse index: {field}")
                    else:
                        self.collection.create_index([(field, direction)])
                        self.logger.debug(f" Created index: {field}")
                        
                except Exception as e:
                    #  FIX: More detailed error handling
                    if "already exists" in str(e).lower():
                        self.logger.debug(f" Index '{field}' already exists (concurrent creation)")
                    else:
                        self.logger.warning(f"Failed to create index '{field}': {e}")
            
            #  FIX: Handle compound index separately
            try:
                compound_index_name = "whitelist_compound_idx"
                compound_exists = False
                
                # Check if compound index exists by examining all indexes
                for idx in existing_indexes:
                    if len(idx.get('key', {})) > 1:  # Multi-field index
                        # Check if it matches our compound pattern
                        key = idx['key']
                        if ('value' in key and 'type' in key and 'is_active' in key):
                            compound_exists = True
                            self.logger.debug(f" Compound index already exists as '{idx['name']}'")
                            break
                
                if not compound_exists:
                    self.collection.create_index([
                        ("value", 1), 
                        ("type", 1), 
                        ("is_active", 1)
                    ], name=compound_index_name)
                    self.logger.debug(f" Created compound index: {compound_index_name}")
                else:
                    self.logger.debug(f" Compound index already exists")
                    
            except Exception as e:
                if "already exists" in str(e).lower():
                    self.logger.debug(" Compound index already exists (concurrent creation)")
                else:
                    self.logger.warning(f"Failed to create compound index: {e}")
            
            self.logger.info(" Index setup completed (with enhanced conflict handling)")
            
        except Exception as e:
            self.logger.warning(f"Index creation process failed: {e}")
            # Continue anyway - indexes are not critical for basic functionality
    
    def insert_entry(self, entry_data: Dict) -> str:
        """Insert a new whitelist entry - UTC ONLY"""
        try:
            # Use UTC time for all timestamps - UTC naive for MongoDB storage
            current_time = to_utc_naive(now_utc())
            
            # Store all timestamps as naive datetime in MongoDB
            entry_data["added_date"] = current_time
            entry_data["created_at"] = current_time
            entry_data["updated_at"] = current_time
            
            #  FIX: Set essential defaults BEFORE validation
            entry_data.setdefault("is_active", True)
            entry_data.setdefault("type", "domain")
            
            #  FIX: Validate value field early
            if not entry_data.get("value"):
                raise ValueError("Value field is required")
            
            #  FIX: Ensure value is lowercase and trimmed
            entry_data["value"] = entry_data["value"].strip().lower()
            
            self.logger.info(f"Inserting entry: {entry_data['value']} at {current_time.isoformat()}")
            
            result = self.collection.insert_one(entry_data)
            
            if result.inserted_id:
                self.logger.info(f" Successfully inserted: {entry_data['value']} with ID: {result.inserted_id}")
                return str(result.inserted_id)
            else:
                raise Exception("Insert operation returned no ID")
                
        except Exception as e:
            self.logger.error(f" Error inserting entry: {e}")
            raise
    
    def find_all_entries(self, query: Dict = None, sort_field: str = "added_date", 
                        sort_order: int = DESCENDING) -> List[Dict]:
        """Find all whitelist entries with proper sorting - UTC ONLY"""
        query = query or {}
        
        #  FIX: Add active filter by default
        if "is_active" not in query:
            query["is_active"] = True
        
        # Clean up expired entries first
        self.cleanup_expired_entries()
        
        self.logger.debug(f"Query: {query}")
        
        cursor = self.collection.find(query).sort(sort_field, sort_order)
        
        entries = []
        for entry in cursor:
            entry["_id"] = str(entry["_id"])
            
            # Convert entry timezones for display - UTC ONLY
            entry = self._convert_entry_timezones(entry)
            
            #  FIX: Ensure all required fields exist
            entry.setdefault("type", "domain")
            entry.setdefault("category", "uncategorized")
            entry.setdefault("is_active", True)
            entry.setdefault("priority", "normal")
            
            entries.append(entry)
        
        self.logger.debug(f"Retrieved {len(entries)} entries from database")
        return entries
    
    def _convert_entry_timezones(self, entry: Dict) -> Dict:
        """Convert entry datetime fields for display - UTC ONLY"""
        if not entry:
            return entry
            
        for date_field in ["added_date", "created_at", "updated_at", "expiry_date", "last_used"]:
            if date_field in entry and entry[date_field]:
                try:
                    # Since we store as UTC naive datetime, convert to UTC timezone for display
                    if hasattr(entry[date_field], 'strftime'):
                        # Convert naive datetime to UTC timezone
                        from datetime import timezone
                        utc_dt = entry[date_field].replace(tzinfo=timezone.utc)
                        
                        entry[f"{date_field}_formatted"] = utc_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                        entry[f"{date_field}_iso"] = utc_dt.isoformat()
                        
                except Exception as e:
                    self.logger.warning(f"Timezone conversion error for {date_field}: {e}")
                    
        return entry
    
    def find_entry_by_value(self, value: str) -> Optional[Dict]:
        """Find entry by value (case-insensitive)"""
        try:
            entry = self.collection.find_one({
                "value": value.lower().strip(),
                "is_active": True
            })
            
            if entry:
                entry["_id"] = str(entry["_id"])
                entry = self._convert_entry_timezones(entry)
                
            return entry
            
        except Exception as e:
            self.logger.error(f"Error finding entry by value: {e}")
            return None
    
    def cleanup_expired_entries(self) -> int:
        """Remove expired entries - UTC ONLY"""
        try:
            current_time = to_utc_naive(now_utc())  # UTC naive for MongoDB comparison
            
            #  ADD: Debug log before cleanup
            expired_query = {"expiry_date": {"$lt": current_time}}
            expired_count = self.collection.count_documents(expired_query)
            
            if expired_count > 0:
                self.logger.info(f"Found {expired_count} expired entries to clean up")
                result = self.collection.delete_many(expired_query)
                self.logger.info(f"Cleaned up {result.deleted_count} expired entries")
                return result.deleted_count
            else:
                self.logger.debug("No expired entries found")
                return 0
                
        except Exception as e:
            self.logger.error(f"Error cleaning up expired entries: {e}")
            return 0
    
    def validate_entry_value(self, entry_type: str, value: str) -> Dict:
        """Validate entry value based on type"""
        try:
            value = value.strip().lower()
            
            if not value:
                return {"valid": False, "message": "Value cannot be empty"}
            
            if entry_type == "domain":
                return self._validate_domain(value)
            elif entry_type == "ip":
                return self._validate_ip(value)
            elif entry_type == "url":
                return self._validate_url(value)
            else:
                return {"valid": False, "message": f"Unknown entry type: {entry_type}"}
                
        except Exception as e:
            return {"valid": False, "message": f"Validation error: {str(e)}"}
    
    def _validate_domain(self, domain: str) -> Dict:
        """Validate domain format"""
        # Basic domain validation regex
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$'
        
        if re.match(domain_pattern, domain):
            return {"valid": True, "message": "Valid domain"}
        else:
            return {"valid": False, "message": "Invalid domain format"}
    
    def _validate_ip(self, ip: str) -> Dict:
        """Validate IP address format"""
        import socket
        try:
            socket.inet_aton(ip)
            return {"valid": True, "message": "Valid IP address"}
        except socket.error:
            return {"valid": False, "message": "Invalid IP address format"}
    
    def _validate_url(self, url: str) -> Dict:
        """Validate URL format"""
        try:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return {"valid": True, "message": "Valid URL"}
            else:
                return {"valid": False, "message": "Invalid URL format"}
        except Exception:
            return {"valid": False, "message": "Invalid URL format"}
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete entry by ID"""
        try:
            result = self.collection.delete_one({"_id": ObjectId(entry_id)})
            if result.deleted_count > 0:
                self.logger.info(f"Deleted entry: {entry_id}")
                return True
            else:
                self.logger.warning(f"Entry not found for deletion: {entry_id}")
                return False
        except Exception as e:
            self.logger.error(f"Error deleting entry: {e}")
            return False
    
    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update entry by ID - UTC ONLY"""
        try:
            # Add updated timestamp - UTC naive for MongoDB
            update_data["updated_at"] = to_utc_naive(now_utc())
            
            result = self.collection.update_one(
                {"_id": ObjectId(entry_id)},
                {"$set": update_data}
            )
            
            if result.modified_count > 0:
                self.logger.info(f"Updated entry: {entry_id}")
                return True
            else:
                self.logger.warning(f"No changes made to entry: {entry_id}")
                return False
        except Exception as e:
            self.logger.error(f"Error updating entry: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get whitelist statistics"""
        try:
            total = self.collection.count_documents({})
            active = self.collection.count_documents({"is_active": True})
            
            # Count by type
            pipeline = [
                {"$match": {"is_active": True}},
                {"$group": {"_id": "$type", "count": {"$sum": 1}}}
            ]
            
            type_counts = {}
            for result in self.collection.aggregate(pipeline):
                type_counts[result["_id"]] = result["count"]
            
            return {
                "total": total,
                "active": active,
                "inactive": total - active,
                "by_type": type_counts
            }
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {"total": 0, "active": 0, "inactive": 0, "by_type": {}}
    
    def find_entry_by_id(self, entry_id: str) -> Optional[Dict]:
        """Find entry by ID"""
        try:
            entry = self.collection.find_one({"_id": ObjectId(entry_id)})
            
            if entry:
                entry["_id"] = str(entry["_id"])
                entry = self._convert_entry_timezones(entry)
                
            return entry
            
        except Exception as e:
            self.logger.error(f"Error finding entry by ID: {e}")
            return None

    def get_entries_for_sync(self, since_date=None) -> List[Dict]:
        """Get entries for agent synchronization - UTC ONLY"""
        try:
            query = {"is_active": True}
            
            if since_date:
                # Parse and convert to UTC naive for database query
                if isinstance(since_date, str):
                    since_utc = parse_agent_timestamp(since_date)  # UTC parsing
                    since_naive = since_utc.replace(tzinfo=None)  # UTC naive for MongoDB
                else:
                    # Convert datetime to UTC naive
                    from datetime import timezone
                    if isinstance(since_date, datetime):
                        if since_date.tzinfo is None:
                            since_utc = since_date.replace(tzinfo=timezone.utc)
                        else:
                            since_utc = since_date.astimezone(timezone.utc)
                        since_naive = since_utc.replace(tzinfo=None)
                    else:
                        since_naive = to_utc_naive(now_utc())
                
                query["added_date"] = {"$gte": since_naive}
            
            entries = list(self.collection.find(query).sort("added_date", ASCENDING))
            
            # Format entries for sync
            sync_entries = []
            for entry in entries:
                sync_entry = {
                    "value": entry.get("value"),
                    "type": entry.get("type", "domain"),
                    "priority": entry.get("priority", "normal"),
                    "category": entry.get("category", "uncategorized")
                }
                
                # Add timestamp for sync - UTC ISO format
                if entry.get("added_date"):
                    # Convert naive datetime to UTC timezone for ISO format
                    from datetime import timezone
                    utc_dt = entry["added_date"].replace(tzinfo=timezone.utc)
                    sync_entry["added_date"] = utc_dt.isoformat()
                
                sync_entries.append(sync_entry)
            
            return sync_entries
            
        except Exception as e:
            self.logger.error(f"Error getting entries for sync: {e}")
            return []

    def bulk_insert_entries(self, entries: List[Dict]) -> List[str]:
        """Bulk insert multiple entries - UTC ONLY"""
        if not entries:
            return []
        
        try:
            # Set timestamps for all entries - UTC naive for MongoDB
            current_time = to_utc_naive(now_utc())
            
            for entry in entries:
                entry["added_date"] = current_time
                entry["created_at"] = current_time
                entry["updated_at"] = current_time
                entry.setdefault("is_active", True)
                entry.setdefault("type", "domain")
            
            result = self.collection.insert_many(entries)
            
            self.logger.info(f"Bulk inserted {len(result.inserted_ids)} entries")
            return [str(id) for id in result.inserted_ids]
            
        except Exception as e:
            self.logger.error(f"Error bulk inserting entries: {e}")
            return []

    def build_query_from_filters(self, filters: Dict) -> Dict:
        """Build MongoDB query from filters"""
        query = {}
        
        if filters.get("type"):
            query["type"] = filters["type"]
        
        if filters.get("category"):
            query["category"] = filters["category"]
        
        if filters.get("added_by"):
            query["added_by"] = filters["added_by"]
        
        if filters.get("search"):
            search_term = filters["search"]
            query["$or"] = [
                {"value": {"$regex": search_term, "$options": "i"}},
                {"notes": {"$regex": search_term, "$options": "i"}}
            ]
        
        # Default to active entries only
        if "is_active" not in query:
            query["is_active"] = True
        
        return query

    def verify_dns(self, domain: str) -> Dict:
        """Verify DNS resolution for a domain"""
        try:
            import socket
            results = socket.getaddrinfo(domain, None, socket.AF_INET)
            
            ips = []
            for result in results:
                ip = result[4][0]
                if ip not in ips:
                    ips.append(ip)
            
            return {
                "valid": True,
                "message": "DNS resolution successful",
                "info": {
                    "domain": domain,
                    "ips": ips,
                    "count": len(ips)
                }
            }
            
        except Exception as e:
            return {
                "valid": False,
                "message": f"DNS resolution failed: {str(e)}",
                "info": {"domain": domain, "error": str(e)}
            }