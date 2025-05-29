"""
Whitelist Model - handles whitelist data operations
"""

import re
import socket
import ipaddress
from datetime import datetime, timedelta, timezone  # ✅ ADD: Import timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import logging

class WhitelistModel:
    """Model for whitelist data operations"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = self.db.whitelist
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # ✅ FIXED: Better timezone setup
        self.timezone = self._get_timezone()
        self._setup_indexes()
    
    def _get_timezone(self):
        """Get Vietnam timezone consistently"""
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo("Asia/Ho_Chi_Minh")
        except ImportError:
            # ✅ FIX: Fallback should be more accurate
            from datetime import timezone, timedelta
            # Vietnam is UTC+7 (no DST since 1979)
            return timezone(timedelta(hours=7), name="Asia/Ho_Chi_Minh")
    
    def _now_local(self) -> datetime:
        """Get current time in Vietnam timezone"""
        utc_now = datetime.now(timezone.utc)
        local_now = utc_now.astimezone(self.timezone)
        self.logger.debug(f"Current time: UTC {utc_now.strftime('%H:%M:%S')} -> VN {local_now.strftime('%H:%M:%S')}")
        return local_now
    
    def _ensure_timezone_aware(self, dt: datetime) -> datetime:
        """Ensure datetime is timezone-aware with Vietnam timezone"""
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=self.timezone)
        return dt.astimezone(self.timezone)
    
    def _setup_indexes(self):
        """Setup indexes for whitelist collection"""
        try:
            # ✅ FIX: Better index management
            existing_indexes = self.collection.list_indexes()
            index_names = [idx['name'] for idx in existing_indexes]
            
            # Clean up invalid documents first
            cleanup_result = self.collection.delete_many({
                "$or": [
                    {"value": None},
                    {"value": ""},
                    {"value": {"$exists": False}},
                    {"value": {"$type": "null"}}
                ]
            })
            
            if cleanup_result.deleted_count > 0:
                self.logger.info(f"Cleaned up {cleanup_result.deleted_count} invalid whitelist entries")
            
            # Drop problematic unique index if exists
            if "value_1" in index_names:
                try:
                    self.collection.drop_index("value_1")
                    self.logger.info("Dropped existing value_1 index")
                except Exception as e:
                    self.logger.warning(f"Could not drop value_1 index: {e}")
            
            # Create new indexes
            indexes_to_create = [
                ([("value", 1)], {"unique": True, "sparse": True, "name": "value_unique_sparse"}),
                ([("type", 1)], {"name": "type_index"}),
                ([("category", 1)], {"name": "category_index"}),
                ([("added_date", -1)], {"name": "added_date_desc"}),
                ([("is_active", 1)], {"name": "is_active_index"})
            ]
            
            for index_spec, options in indexes_to_create:
                try:
                    if options["name"] not in index_names:
                        self.collection.create_index(index_spec, **options)
                        self.logger.debug(f"Created index: {options['name']}")
                except Exception as e:
                    self.logger.warning(f"Could not create index {options['name']}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error setting up indexes: {e}")
            # Continue without indexes if creation fails

    def insert_entry(self, entry_data: Dict) -> str:
        """Insert a new whitelist entry"""
        try:
            # ✅ FIX: Get current time in UTC+7
            current_time = self._now_local()
            self.logger.info(f"Inserting entry at: {current_time} (timezone: {current_time.tzinfo})")
            
            # ✅ FIX: Convert to UTC before storing in MongoDB
            current_time_utc = current_time.astimezone(timezone.utc)
            
            # Store timestamps as UTC (MongoDB standard)
            entry_data["added_date"] = current_time_utc
            entry_data["created_at"] = current_time_utc
            entry_data["updated_at"] = current_time_utc
            
            # Store original timezone for reference
            entry_data["timezone"] = "UTC+7"
            entry_data["local_added_date"] = current_time.isoformat()  # Store as string for reference
            
            # Set essential defaults
            entry_data.setdefault("is_active", True)
            
            # Validate value field
            if not entry_data.get("value"):
                raise ValueError("Value field is required")
            
            # Log the data being inserted
            self.logger.debug(f"Entry data to insert (UTC): {entry_data}")
            
            result = self.collection.insert_one(entry_data)
            self.logger.info(f"Successfully inserted whitelist entry: {entry_data.get('value')} with ID: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            self.logger.error(f"Error inserting entry: {e}")
            raise

    def find_all_entries(self, query: Dict = None, sort_field: str = "added_date", 
                        sort_order: int = DESCENDING) -> List[Dict]:
        """Find all whitelist entries"""
        query = query or {}
        
        # Clean up expired entries first
        self.cleanup_expired_entries()
        
        cursor = self.collection.find(query).sort(sort_field, sort_order)
        
        entries = []
        for entry in cursor:
            entry["_id"] = str(entry["_id"])
            
            # ✅ FIX: Use helper method
            entry = self._convert_entry_timezones(entry)
            entries.append(entry)
        
        return entries
    
    def find_entry_by_value(self, value: str) -> Optional[Dict]:
        """Find entry by value"""
        entry = self.collection.find_one({"value": value})
        if entry:
            entry["_id"] = str(entry["_id"])
            # ✅ FIX: Use helper method
            entry = self._convert_entry_timezones(entry)
        return entry
    
    def find_entry_by_id(self, entry_id: str) -> Optional[Dict]:
        """Find entry by ID"""
        try:
            object_id = ObjectId(entry_id)
            entry = self.collection.find_one({"_id": object_id})
            if entry:
                entry["_id"] = str(entry["_id"])
                # ✅ FIX: Use helper method
                entry = self._convert_entry_timezones(entry)
            return entry
        except:
            return None
    
    # ✅ ADD: Helper method to avoid code duplication
    def _convert_entry_timezones(self, entry: Dict) -> Dict:
        """Convert entry datetime fields from UTC to local timezone"""
        if not entry:
            return entry
            
        for date_field in ["added_date", "created_at", "updated_at", "expiry_date", "last_used"]:
            if date_field in entry and entry[date_field]:
                utc_time = entry[date_field]
                
                # Ensure it's timezone-aware UTC
                if utc_time.tzinfo is None:
                    utc_time = utc_time.replace(tzinfo=timezone.utc)
                
                # Convert to Vietnam timezone for display
                local_time = utc_time.astimezone(self.timezone)
                entry[date_field] = local_time
                
        return entry
    
    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update an entry"""
        try:
            object_id = ObjectId(entry_id)
            
            # ✅ FIX: Convert updated_at to UTC
            local_time = self._now_local()
            update_data["updated_at"] = local_time.astimezone(timezone.utc)
            update_data["timezone"] = "UTC+7"
            
            result = self.collection.update_one(
                {"_id": object_id},
                {"$set": update_data}
            )
            return result.modified_count > 0
        except:
            return False
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry"""
        try:
            object_id = ObjectId(entry_id)
            result = self.collection.delete_one({"_id": object_id})
            return result.deleted_count > 0
        except:
            return False
    
    def delete_entry_by_value(self, value: str) -> bool:
        """Delete entry by value"""
        result = self.collection.delete_one({"value": value})
        return result.deleted_count > 0
    
    def bulk_insert_entries(self, entries: List[Dict]) -> List[str]:
        """Bulk insert entries"""
        if not entries:
            return []
        
        # ✅ FIX: Convert timestamps to UTC before bulk insert
        current_time = self._now_local()
        current_time_utc = current_time.astimezone(timezone.utc)
        
        for entry in entries:
            entry["added_date"] = current_time_utc
            entry["created_at"] = current_time_utc
            entry["updated_at"] = current_time_utc
            entry["timezone"] = "UTC+7"
            entry["local_added_date"] = current_time.isoformat()
            entry.setdefault("is_active", True)
        
        try:
            result = self.collection.insert_many(entries, ordered=False)
            return [str(id) for id in result.inserted_ids]
        except Exception as e:
            self.logger.error(f"Error bulk inserting entries: {e}")
            return []
    
    def count_entries(self, query: Dict = None) -> int:
        """Count entries matching query"""
        query = query or {}
        return self.collection.count_documents(query)
    
    def cleanup_expired_entries(self) -> int:
        """Remove expired entries"""
        try:
            # ✅ FIX: Compare with UTC time
            current_time = self._now_local()
            current_time_utc = current_time.astimezone(timezone.utc)
            
            result = self.collection.delete_many({
                "expiry_date": {"$lt": current_time_utc}
            })
            
            if result.deleted_count > 0:
                self.logger.info(f"Cleaned up {result.deleted_count} expired entries")
            
            return result.deleted_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up expired entries: {e}")
            return 0
    
    def get_entries_for_sync(self, since: datetime = None) -> List[str]:
        """Get entries for agent sync (values only)"""
        try:
            query = {"is_active": True}
            
            if since:
                # ✅ FIX: Convert since to UTC for comparison
                if since.tzinfo is None:
                    since = since.replace(tzinfo=self.timezone)
                
                # Convert to UTC for database comparison
                since_utc = since.astimezone(timezone.utc)
                
                query["$or"] = [
                    {"added_date": {"$gte": since_utc}},
                    {"updated_at": {"$gte": since_utc}},
                    {"created_at": {"$gte": since_utc}}
                ]
                
                self.logger.debug(f"Sync query with since UTC: {since_utc.isoformat()}")
            else:
                self.logger.debug("Full sync - no since parameter")
            
            # Clean up expired entries first
            expired_count = self.cleanup_expired_entries()
            if expired_count > 0:
                self.logger.info(f"Cleaned up {expired_count} expired entries before sync")
            
            cursor = self.collection.find(
                query, 
                {"value": 1, "_id": 0, "added_date": 1, "updated_at": 1}
            ).sort("added_date", -1)
            
            values = []
            processed_count = 0
            
            for entry in cursor:
                processed_count += 1
                value = entry.get("value")
                if value and isinstance(value, str) and value.strip():
                    clean_value = value.strip().lower()
                    if clean_value not in values:  # Prevent duplicates
                        values.append(clean_value)
            
            self.logger.info(f"Sync query processed {processed_count} entries, returning {len(values)} unique values")
            
            if since:
                self.logger.debug(f"Incremental sync since {since.isoformat()}: found {len(values)} entries")
            else:
                self.logger.debug(f"Full sync: returning {len(values)} total entries")
            
            return values
            
        except Exception as e:
            self.logger.error(f"Error getting entries for sync: {e}", exc_info=True)
            return []

    def get_statistics(self) -> Dict:
        """Get whitelist statistics"""
        total = self.collection.count_documents({})
        active = self.collection.count_documents({"is_active": True})
        
        # Count by type
        type_stats = {}
        type_pipeline = [
            {"$group": {"_id": "$type", "count": {"$sum": 1}}}
        ]
        for result in self.collection.aggregate(type_pipeline):
            type_stats[result["_id"]] = result["count"]
        
        # Count by category
        category_stats = {}
        category_pipeline = [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}}
        ]
        for result in self.collection.aggregate(category_pipeline):
            category_stats[result["_id"]] = result["count"]
        
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "by_type": type_stats,
            "by_category": category_stats
        }
    
    def build_query_from_filters(self, filters: Dict) -> Dict:
        """Build MongoDB query from filter parameters"""
        query = {}
        
        if filters.get("type"):
            query["type"] = filters["type"]
        
        if filters.get("category"):
            query["category"] = filters["category"]
        
        if filters.get("search"):
            search_term = filters["search"]
            query["$or"] = [
                {"value": {"$regex": search_term, "$options": "i"}},
                {"notes": {"$regex": search_term, "$options": "i"}}
            ]
        
        if filters.get("added_by"):
            query["added_by"] = filters["added_by"]
        
        if filters.get("is_active") is not None:
            query["is_active"] = filters["is_active"]
        
        return query
    
    def validate_entry_value(self, entry_type: str, value: str) -> Dict:
        """Validate entry value based on type"""
        try:
            if entry_type == "domain":
                # Remove wildcard for validation
                domain_to_check = value.replace("*.", "")
                # Enhanced domain validation - allow hyphens and longer domains
                domain_regex = re.compile(
                    r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$',
                    re.IGNORECASE
                )
                
                # Additional checks
                if len(domain_to_check) > 253:
                    return {"valid": False, "message": "Domain name too long (max 253 characters)"}
                if not domain_regex.match(domain_to_check):
                    return {"valid": False, "message": "Invalid domain format"}
                if '..' in domain_to_check:
                    return {"valid": False, "message": "Domain cannot contain consecutive dots"}
                    
            elif entry_type == "ip":
                # Extract IP and port
                if ':' in value and not value.startswith('['):
                    # IPv4 with port
                    parts = value.rsplit(':', 1)
                    ip_part = parts[0]
                    try:
                        port = int(parts[1])
                        if not (1 <= port <= 65535):
                            return {"valid": False, "message": "Port must be between 1 and 65535"}
                    except ValueError:
                        return {"valid": False, "message": "Invalid port number"}
                else:
                    ip_part = value
                    
                # Validate IP address (supports CIDR)
                try:
                    if '/' in ip_part:
                        ipaddress.ip_network(ip_part, strict=False)
                    else:
                        ipaddress.ip_address(ip_part)
                except ValueError:
                    return {"valid": False, "message": "Invalid IP address format"}
                
            elif entry_type == "url":
                try:
                    # More flexible URL validation
                    if not (value.startswith('http://') or value.startswith('https://')):
                        return {"valid": False, "message": "URL must start with http:// or https://"}
                    
                    # Handle wildcards by replacing them temporarily
                    test_value = value.replace('*', 'test')
                    parsed = urlparse(test_value)
                    
                    if not parsed.scheme or not parsed.netloc:
                        return {"valid": False, "message": "Invalid URL format"}
                        
                    # Additional URL validation
                    if len(value) > 2048:
                        return {"valid": False, "message": "URL too long (max 2048 characters)"}
                        
                except Exception:
                    return {"valid": False, "message": "Invalid URL format"}
                
            elif entry_type == "pattern":
                if len(value.strip()) < 1:
                    return {"valid": False, "message": "Pattern cannot be empty"}
                if len(value) > 255:
                    return {"valid": False, "message": "Pattern too long (max 255 characters)"}
                
            return {"valid": True, "message": "Valid"}
            
        except Exception as e:
            return {"valid": False, "message": f"Validation error: {str(e)}"}
    
    def verify_dns(self, domain: str) -> Dict:
        """Verify DNS resolution for a domain"""
        try:
            # Remove wildcard prefix
            domain_to_check = domain.replace("*.", "")
            
            result = {"valid": True, "info": []}
            
            # IPv4 resolution
            try:
                ipv4_addresses = socket.getaddrinfo(domain_to_check, None, socket.AF_INET)
                ipv4_list = list(set([addr[4][0] for addr in ipv4_addresses]))
                if ipv4_list:
                    result["ipv4"] = ipv4_list
                    result["info"].extend([f"IPv4: {ip}" for ip in ipv4_list])
            except socket.gaierror:
                pass
                
            # IPv6 resolution
            try:
                ipv6_addresses = socket.getaddrinfo(domain_to_check, None, socket.AF_INET6)
                ipv6_list = list(set([addr[4][0] for addr in ipv6_addresses]))
                if ipv6_list:
                    result["ipv6"] = ipv6_list
                    result["info"].extend([f"IPv6: {ip}" for ip in ipv6_list])
            except socket.gaierror:
                pass
                
            if not result["info"]:
                result["valid"] = False
                result["message"] = "No DNS records found"
                
            return result
            
        except Exception as e:
            return {"valid": False, "message": f"DNS verification failed: {str(e)}"}