"""
Agent Model - handles agent data operations
"""

import logging
from datetime import datetime, timedelta
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
        self._setup_indexes()
    
    def _setup_indexes(self):
        """Setup indexes for agents collection"""
        try:
            # Unique index on agent_id
            self.collection.create_index([("agent_id", ASCENDING)], unique=True)
            # ✅ Unique index on MAC address
            self.collection.create_index([("mac_address", ASCENDING)], unique=True, sparse=True)
            # Indexes for queries
            self.collection.create_index([("hostname", ASCENDING)])
            self.collection.create_index([("ip_address", ASCENDING)])
            self.collection.create_index([("last_heartbeat", DESCENDING)])
            self.collection.create_index([("status", ASCENDING)])
            self.logger.info("Agent indexes created successfully")
        except Exception as e:
            self.logger.warning(f"Error creating indexes: {e}")

    def find_by_mac_address(self, mac_address: str) -> Optional[Dict]:
        """Find agent by MAC address"""
        if not mac_address or mac_address == "unknown":
            return None
        
        try:
            result = self.collection.find_one({"mac_address": mac_address})
            if result:
                self.logger.debug(f"Found agent by MAC {mac_address}: {result.get('agent_id')}")
            return result
        except Exception as e:
            self.logger.error(f"Error finding agent by MAC {mac_address}: {e}")
            return None

    def register_agent(self, agent_data: Dict) -> Dict:
        """Register a new agent (CREATE only, not update)"""
        try:
            agent_data.update({
                "registered_date": datetime.utcnow(),
                "updated_date": datetime.utcnow(),
                "last_heartbeat": datetime.utcnow(),
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
            update_data["updated_date"] = datetime.utcnow()
            result = self.collection.update_one(
                {"agent_id": agent_id},
                {"$set": update_data}
            )
            self.logger.debug(f"Agent {agent_id} updated: {result.modified_count} records")
            return result.modified_count > 0
        except Exception as e:
            self.logger.error(f"Error updating agent {agent_id}: {e}")
            return False
    
    def update_heartbeat(self, agent_id: str, heartbeat_data: Dict = None) -> bool:
        """Update agent heartbeat"""
        try:
            update_data = {
                "last_heartbeat": datetime.utcnow(),
                "status": "active",
                "updated_date": datetime.utcnow()
            }
            
            if heartbeat_data:
                if heartbeat_data.get("client_ip"):
                    update_data["last_heartbeat_ip"] = heartbeat_data["client_ip"]
                if heartbeat_data.get("metrics"):
                    update_data["metrics"] = heartbeat_data["metrics"]
                if heartbeat_data.get("status"):
                    update_data["status"] = heartbeat_data["status"]
                if heartbeat_data.get("hostname"):
                    update_data["hostname"] = heartbeat_data["hostname"]
                if heartbeat_data.get("platform"):
                    update_data["platform"] = heartbeat_data["platform"]
            
            result = self.collection.update_one({"agent_id": agent_id}, {"$set": update_data})
            return result.modified_count > 0
            
        except Exception as e:
            self.logger.error(f"Error updating heartbeat for agent {agent_id}: {e}")
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
            threshold = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)
            return list(self.collection.find({
                "last_heartbeat": {"$gte": threshold}
            }))
        except Exception as e:
            self.logger.error(f"Error getting active agents: {e}")
            return []
    
    def get_inactive_agents(self, inactive_threshold_minutes: int = 5) -> List[Dict]:
        """Get list of inactive agents"""
        try:
            threshold = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)
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
            inactive_threshold = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)
            
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