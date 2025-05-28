"""
Agent Model - handles agent data operations
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

class AgentModel:
    """Model for agent data operations"""
    
    def __init__(self, db: Database):
        self.logger = logging.getLogger(self.__class__.__name__)  # ✅ Add logger
        self.db = db
        self.collection: Collection = self.db.agents
        
        # ✅ FIXED: Use timezone offset instead of ZoneInfo
        self.vietnam_offset = timezone(timedelta(hours=7))  # UTC+7 for Vietnam
        self._setup_indexes()
    
    def _now_local(self) -> datetime:
        """Lấy thời gian hiện tại theo múi giờ của server"""
        return datetime.now()
    
    def _setup_indexes(self):
        """Setup indexes for agents collection"""
        try:
            # Unique index on agent_id
            self.collection.create_index([("agent_id", ASCENDING)], unique=True)
            # Indexes for queries (removed MAC index)
            self.collection.create_index([("hostname", ASCENDING)])
            self.collection.create_index([("ip_address", ASCENDING)])
            self.collection.create_index([("last_heartbeat", DESCENDING)])
            self.collection.create_index([("status", ASCENDING)])
            # Compound index for hostname + IP combination
            self.collection.create_index([("hostname", ASCENDING), ("ip_address", ASCENDING)])
            self.logger.info("Agent indexes created successfully")
        except Exception as e:
            self.logger.warning(f"Error creating indexes: {e}")

    def register_agent(self, agent_data: Dict) -> Dict:
        """Register a new agent (CREATE only, not update)"""
        try:
            # ✅ SỬA: Dùng server local time thay vì UTC
            current_time = self._now_local()
            agent_data.update({
                "registered_date": current_time,
                "updated_date": current_time,
                "last_heartbeat": current_time,
                "status": "active"
            })
            
            result = self.collection.insert_one(agent_data)
            agent_data["_id"] = result.inserted_id
            
            self.logger.info(f"Agent registered: {agent_data.get('agent_id')}")
            return agent_data
            
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            raise

    def update_agent(self, agent_id: str, update_data: Dict) -> bool:
        """Update existing agent"""
        try:
            update_data["updated_date"] = self._now_local()  # ✅ SỬA: Dùng local time
            result = self.collection.update_one(
                {"agent_id": agent_id},
                {"$set": update_data}
            )
            self.logger.debug(f"Agent {agent_id} updated: {result.modified_count} records")
            return result.modified_count > 0
        except Exception as e:
            self.logger.error(f"Error updating agent {agent_id}: {e}")
            return False
    
    def update_heartbeat(self, agent_id: str, update_data: Dict) -> bool:
        """Update agent heartbeat with PROPER TIMEZONE"""
        try:
            # ✅ CRITICAL FIX: Add proper Vietnam timezone to heartbeat
            from datetime import datetime, timezone, timedelta
            vietnam_offset = timezone(timedelta(hours=7))
            
            # Set proper heartbeat timestamp
            current_vietnam_time = datetime.now(vietnam_offset)
            
            update_data_with_heartbeat = {
                **update_data,
                "last_heartbeat": current_vietnam_time,  # ✅ FIX: Proper timezone
                "updated_date": current_vietnam_time
            }
            
            result = self.collection.update_one(
                {"agent_id": agent_id},
                {"$set": update_data_with_heartbeat}
            )
            
            self.logger.info(f"✅ Updated heartbeat for {agent_id}: {current_vietnam_time}")
            return result.modified_count > 0
            
        except Exception as e:
            self.logger.error(f"Error updating heartbeat for {agent_id}: {e}")
            return False
    
    def find_by_agent_id(self, agent_id: str) -> Optional[Dict]:
        """Find agent by agent_id"""
        try:
            return self.collection.find_one({"agent_id": agent_id})
        except Exception as e:
            self.logger.error(f"Error finding agent {agent_id}: {e}")
            return None
    
    def find_by_hostname(self, hostname: str) -> List[Dict]:
        """Find agents by hostname"""
        try:
            return list(self.collection.find({"hostname": {"$regex": hostname, "$options": "i"}}))
        except Exception as e:
            self.logger.error(f"Error finding agents by hostname {hostname}: {e}")
            return []
    
    def get_all_agents(self, query: Dict = None, limit: int = 100, skip: int = 0) -> List[Dict]:
        """Get all agents with optional filtering"""
        try:
            if query is None:
                query = {}
            return list(self.collection.find(query).sort("last_heartbeat", -1).skip(skip).limit(limit))
        except Exception as e:
            self.logger.error(f"Error getting agents: {e}")
            return []
    
    def count_agents(self, query: Dict = None) -> int:
        """Count agents with optional filtering"""
        try:
            if query is None:
                query = {}
            return self.collection.count_documents(query)
        except Exception as e:
            self.logger.error(f"Error counting agents: {e}")
            return 0
    
    def get_active_agents(self, inactive_threshold_minutes: int = 5) -> List[Dict]:
        """Get list of active agents"""
        try:
            # ✅ SỬA: Dùng server local time thay vì UTC
            threshold = self._now_local() - timedelta(minutes=inactive_threshold_minutes)
            return list(self.collection.find({
                "last_heartbeat": {"$gte": threshold}
            }))
        except Exception as e:
            self.logger.error(f"Error getting active agents: {e}")
            return []
    
    def get_inactive_agents(self, inactive_threshold_minutes: int = 5) -> List[Dict]:
        """Get list of inactive agents"""
        try:
            # ✅ SỬA: Dùng server local time thay vì UTC
            threshold = self._now_local() - timedelta(minutes=inactive_threshold_minutes)
            return list(self.collection.find({
                "last_heartbeat": {"$lt": threshold}
            }))
        except Exception as e:
            self.logger.error(f"Error getting inactive agents: {e}")
            return []
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent"""
        try:
            result = self.collection.delete_one({"agent_id": agent_id})
            self.logger.info(f"Agent {agent_id} deleted: {result.deleted_count} records")
            return result.deleted_count > 0
        except Exception as e:
            self.logger.error(f"Error deleting agent {agent_id}: {e}")
            return False
    
    def get_agent_statistics(self, inactive_threshold_minutes: int = 5) -> Dict:
        """Get agent statistics"""
        try:
            # ✅ SỬA: Dùng server local time để tính threshold
            inactive_threshold = self._now_local() - timedelta(minutes=inactive_threshold_minutes)
            
            pipeline = [
                {
                    "$addFields": {
                        "actual_status": {
                            "$cond": {
                                "if": {"$gte": ["$last_heartbeat", inactive_threshold]},
                                "then": "active",
                                "else": {
                                    "$cond": {
                                        "if": {"$eq": ["$last_heartbeat", None]},
                                        "then": "offline",
                                        "else": "inactive"
                                    }
                                }
                            }
                        }
                    }
                },
                {
                    "$group": {
                        "_id": "$actual_status",
                        "count": {"$sum": 1}
                    }
                }
            ]
            
            results = list(self.collection.aggregate(pipeline))
            
            stats = {"total": 0, "active": 0, "inactive": 0, "offline": 0}
            
            for result in results:
                status = result["_id"]
                count = result["count"]
                stats[status] = count
                stats["total"] += count
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting agent statistics: {e}")
            return {"total": 0, "active": 0, "inactive": 0, "offline": 0}