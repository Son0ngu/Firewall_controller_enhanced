"""
Agent Model - handles agent data operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

class AgentModel:
    """Model for agent data operations"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = self.db.agents
        self._setup_indexes()
    
    def _setup_indexes(self):
        """Setup indexes for agents collection"""
        # Unique index on agent_id
        self.collection.create_index([("agent_id", ASCENDING)], unique=True)
        # Indexes for queries
        self.collection.create_index([("hostname", ASCENDING)])
        self.collection.create_index([("last_heartbeat", DESCENDING)])
        self.collection.create_index([("status", ASCENDING)])
        self.collection.create_index([("user_id", ASCENDING)])
    
    def register_agent(self, agent_data: Dict) -> Dict:
        """Register a new agent or update existing one"""
        agent_id = agent_data.get('agent_id')
        
        # Check if agent exists
        existing = self.collection.find_one({"agent_id": agent_id})
        
        if existing:
            # Update existing agent
            update_data = {
                "hostname": agent_data.get("hostname"),
                "ip_address": agent_data.get("ip_address"),
                "platform": agent_data.get("platform"),
                "os_info": agent_data.get("os_info"),
                "agent_version": agent_data.get("agent_version"),
                "last_heartbeat": datetime.utcnow(),
                "status": "active",
                "updated_date": datetime.utcnow()
            }
            self.collection.update_one({"agent_id": agent_id}, {"$set": update_data})
            return existing
        else:
            # Create new agent
            agent_data.update({
                "registered_date": datetime.utcnow(),
                "last_heartbeat": datetime.utcnow(),
                "status": "active",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            })
            result = self.collection.insert_one(agent_data)
            return self.collection.find_one({"_id": result.inserted_id})
    
    def update_heartbeat(self, agent_id: str, heartbeat_data: Dict = None) -> bool:
        """Update agent heartbeat"""
        update_data = {
            "last_heartbeat": datetime.utcnow(),
            "status": "active",
            "updated_at": datetime.utcnow(),
            "last_heartbeat_ip": heartbeat_data.get("client_ip") if heartbeat_data else None
        }
        
        if heartbeat_data:
            if "metrics" in heartbeat_data:
                update_data["metrics"] = heartbeat_data["metrics"]
            if "status" in heartbeat_data:
                update_data["status"] = heartbeat_data["status"]
            if "hostname" in heartbeat_data:
                update_data["hostname"] = heartbeat_data["hostname"]
            if "platform" in heartbeat_data:
                update_data["platform"] = heartbeat_data["platform"]
        
        result = self.collection.update_one({"agent_id": agent_id}, {"$set": update_data})
        return result.modified_count > 0
    
    def find_by_agent_id(self, agent_id: str) -> Optional[Dict]:
        """Find agent by agent_id"""
        return self.collection.find_one({"agent_id": agent_id})
    
    def find_by_hostname(self, hostname: str) -> List[Dict]:
        """Find agents by hostname"""
        return list(self.collection.find({"hostname": {"$regex": hostname, "$options": "i"}}))
    
    def get_all_agents(self, query: Dict = None, limit: int = 100, skip: int = 0) -> List[Dict]:
        """Get all agents with optional filtering"""
        query = query or {}
        return list(self.collection.find(query).sort("last_heartbeat", -1).skip(skip).limit(limit))
    
    def count_agents(self, query: Dict = None) -> int:
        """Count agents with optional filtering"""
        query = query or {}
        return self.collection.count_documents(query)
    
    def get_active_agents(self, inactive_threshold_minutes: int = 5) -> List[Dict]:
        """Get list of active agents"""
        threshold = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)
        return list(self.collection.find({
            "last_heartbeat": {"$gte": threshold}
        }))
    
    def get_inactive_agents(self, inactive_threshold_minutes: int = 5) -> List[Dict]:
        """Get list of inactive agents"""
        threshold = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)
        return list(self.collection.find({
            "last_heartbeat": {"$lt": threshold}
        }))
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent"""
        result = self.collection.delete_one({"agent_id": agent_id})
        return result.deleted_count > 0
    
    def get_agent_statistics(self, inactive_threshold_minutes: int = 5) -> Dict:
        """Get agent statistics"""
        inactive_threshold = datetime.utcnow() - timedelta(minutes=inactive_threshold_minutes)
        
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "active": {
                        "$sum": {
                            "$cond": [
                                {"$gte": ["$last_heartbeat", inactive_threshold]},
                                1, 0
                            ]
                        }
                    },
                    "inactive": {
                        "$sum": {
                            "$cond": [
                                {"$lt": ["$last_heartbeat", inactive_threshold]},
                                1, 0
                            ]
                        }
                    }
                }
            }
        ]
        
        result = list(self.collection.aggregate(pipeline))
        if result:
            stats = result[0]
            return {
                "total": stats["total"],
                "active": stats["active"],
                "inactive": stats["inactive"],
                "offline": 0  # Can be calculated based on longer threshold
            }
        
        return {"total": 0, "active": 0, "inactive": 0, "offline": 0}