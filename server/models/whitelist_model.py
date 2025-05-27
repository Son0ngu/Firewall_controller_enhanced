"""
Whitelist Model - handles whitelist data operations
"""

import re
import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlparse
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import pytz  # ✅ ADD TIMEZONE SUPPORT

class WhitelistModel:
    """Model for whitelist data operations"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = self.db.whitelist
        # ✅ ADD TIMEZONE
        self.timezone = pytz.timezone('Asia/Ho_Chi_Minh')  # Vietnam timezone
        self._setup_indexes()
    
    def _setup_indexes(self):
        """Setup indexes for whitelist collection"""
        try:
            # Clean up invalid documents before creating indexes
            cleanup_result = self.collection.delete_many({
                "$or": [
                    {"value": None},
                    {"value": ""},
                    {"value": {"$exists": False}}
                ]
            })
            
            # Drop existing problematic index if it exists
            try:
                self.collection.drop_index("value_1")
            except Exception:
                pass  # Index might not exist
            
            # Create unique sparse index on value field
            self.collection.create_index(
                [("value", 1)], 
                unique=True,
                sparse=True  # Sparse index automatically excludes null/missing values
            )
            
            # Create other indexes
            self.collection.create_index([("type", 1)])
            self.collection.create_index([("category", 1)])
            self.collection.create_index([("priority", DESCENDING)])
            self.collection.create_index([("added_date", DESCENDING)])
            self.collection.create_index([("expiry_date", 1)], sparse=True)
            
        except Exception as e:
            # Continue without indexes if creation fails
            pass
    
    def _get_current_time(self):
        """Get current time in configured timezone"""
        return datetime.now(self.timezone)
    
    def insert_entry(self, entry_data: Dict) -> str:
        """Insert a new whitelist entry"""
        # ✅ USE TIMEZONE-AWARE TIMESTAMPS
        current_time = self._get_current_time()
        entry_data["added_date"] = current_time
        entry_data["created_at"] = current_time
        entry_data["updated_at"] = current_time
        
        # Set defaults
        entry_data.setdefault("usage_count", 0)
        entry_data.setdefault("is_active", True)
        entry_data.setdefault("enable_logging", False)
        entry_data.setdefault("is_temporary", False)
        
        result = self.collection.insert_one(entry_data)
        return str(result.inserted_id)
    
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
            entries.append(entry)
        
        return entries
    
    def find_entry_by_value(self, value: str) -> Optional[Dict]:
        """Find entry by value"""
        entry = self.collection.find_one({"value": value})
        if entry:
            entry["_id"] = str(entry["_id"])
        return entry
    
    def find_entry_by_id(self, entry_id: str) -> Optional[Dict]:
        """Find entry by ID"""
        try:
            object_id = ObjectId(entry_id)
            entry = self.collection.find_one({"_id": object_id})
            if entry:
                entry["_id"] = str(entry["_id"])
            return entry
        except:
            return None
    
    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update an entry"""
        try:
            object_id = ObjectId(entry_id)
            # ✅ USE TIMEZONE-AWARE TIME
            update_data["updated_at"] = self._get_current_time()
            
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
        
        # ✅ USE TIMEZONE-AWARE TIMESTAMPS
        current_time = self._get_current_time()
        for entry in entries:
            entry["added_date"] = current_time
            entry["created_at"] = current_time
            entry["updated_at"] = current_time
            entry.setdefault("usage_count", 0)
            entry.setdefault("is_active", True)
            entry.setdefault("enable_logging", False)
            entry.setdefault("is_temporary", False)
        
        try:
            result = self.collection.insert_many(entries, ordered=False)
            return [str(id) for id in result.inserted_ids]
        except Exception as e:
            # Handle duplicate key errors and return partial success
            return []
    
    def count_entries(self, query: Dict = None) -> int:
        """Count entries matching query"""
        query = query or {}
        return self.collection.count_documents(query)
    
    def cleanup_expired_entries(self) -> int:
        """Remove expired entries"""
        # ✅ USE TIMEZONE-AWARE TIME
        current_time = self._get_current_time()
        result = self.collection.delete_many({
            "expiry_date": {"$lt": current_time}
        })
        return result.deleted_count
    
    def get_entries_for_sync(self, since: datetime = None) -> List[str]:
        """Get entries for agent sync (values only)"""
        query = {"is_active": True}
        
        if since:
            # ✅ ENSURE TIMEZONE CONSISTENCY
            if since.tzinfo is None:
                since = self.timezone.localize(since)
            elif since.tzinfo != self.timezone:
                since = since.astimezone(self.timezone)
                
            query["$or"] = [
                {"added_date": {"$gte": since}},
                {"updated_at": {"$gte": since}}
            ]
        
        # Clean up expired entries first
        self.cleanup_expired_entries()
        
        cursor = self.collection.find(query, {"value": 1})
        
        values = []
        for entry in cursor:
            value = entry.get("value")
            if value:
                values.append(value)
        
        return values
    
    def update_usage(self, value: str) -> bool:
        """Update usage count and last used time"""
        # ✅ USE TIMEZONE-AWARE TIME
        current_time = self._get_current_time()
        result = self.collection.update_one(
            {"value": value},
            {
                "$inc": {"usage_count": 1},
                "$set": {"last_used": current_time}
            }
        )
        return result.modified_count > 0
    
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
                # Basic domain validation
                domain_regex = re.compile(
                    r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$',
                    re.IGNORECASE
                )
                if not domain_regex.match(domain_to_check):
                    return {"valid": False, "message": "Invalid domain format"}
                    
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
                    parsed = urlparse(value)
                    if not parsed.scheme or not parsed.netloc:
                        return {"valid": False, "message": "Invalid URL format"}
                except Exception:
                    return {"valid": False, "message": "Invalid URL format"}
                    
            elif entry_type == "pattern":
                if len(value) < 1:
                    return {"valid": False, "message": "Pattern cannot be empty"}
                    
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