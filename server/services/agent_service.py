"""
Agent Service - Business logic for agent operations
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from bson import ObjectId
import pytz
import logging

class AgentService:
    def __init__(self, model, socketio=None):  # ✅ CORRECT: Only model and optional socketio
        """Initialize AgentService"""
        self.model = model
        self.socketio = socketio
        self.logger = logging.getLogger(self.__class__.__name__)
        # ✅ SET TIMEZONE
        self.timezone = pytz.timezone('Asia/Ho_Chi_Minh')  # Vietnam timezone
        self.inactive_threshold = 2    # 2 minutes
        self.offline_threshold = 10    # 10 minutes

    def _get_current_time(self):
        """Get current time in configured timezone"""
        return datetime.now(self.timezone)

    def register_agent(self, agent_data: Dict, client_ip: str) -> Dict:
        """Register a new agent"""
        try:
            # Generate unique agent ID
            import uuid
            agent_id = str(uuid.uuid4())
            agent_token = str(uuid.uuid4())
            
            # ✅ USE TIMEZONE-AWARE TIME
            current_time = self._get_current_time()
            
            # Prepare agent data for database
            processed_data = {
                "agent_id": agent_id,
                "agent_token": agent_token,
                "hostname": agent_data.get("hostname", "Unknown"),
                "ip_address": agent_data.get("ip_address", client_ip),
                "platform": agent_data.get("platform", "Unknown"),
                "os_info": agent_data.get("os_info", "Unknown"),
                "agent_version": agent_data.get("agent_version", "1.0.0"),
                "client_ip": client_ip,
                "user_id": client_ip,  # Simple user identification
                "status": "active",
                "registered_date": current_time,
                "last_heartbeat": current_time,
                "updated_date": current_time
            }
            
            # Register agent using model
            registered_agent = self.model.register_agent(processed_data)
            
            self.logger.info(f"Agent registered successfully: {agent_id}")
            
            return {
                "agent_id": agent_id,
                "token": agent_token,
                "user_id": client_ip,
                "hostname": agent_data.get("hostname"),
                "ip_address": agent_data.get("ip_address", client_ip),
                "status": "active"
            }
            
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            raise ValueError(f"Failed to register agent: {str(e)}")

    def get_agents(self, filters: Dict = None, limit: int = 100, skip: int = 0) -> Dict:
        """Get agents with filtering and status calculation"""
        try:
            # Build query for model
            query = {}
            if filters:
                if filters.get("status"):
                    status = filters["status"]
                    if status == "inactive":
                        inactive_threshold = self._get_current_time() - timedelta(minutes=self.inactive_threshold)
                        query["last_heartbeat"] = {"$lt": inactive_threshold}
                    elif status == "active":
                        inactive_threshold = self._get_current_time() - timedelta(minutes=self.inactive_threshold)
                        query["last_heartbeat"] = {"$gte": inactive_threshold}
                    else:
                        query["status"] = status
                
                if filters.get("hostname"):
                    query["hostname"] = {"$regex": filters["hostname"], "$options": "i"}
            
            # Get agents from model
            agents = self.model.get_all_agents(query, limit, skip)
            total_count = self.model.count_agents(query)
            
            # ✅ CALCULATE REAL-TIME STATUS FOR EACH AGENT
            current_time = self._get_current_time()
            agents_list = []
            
            for agent in agents:
                # ✅ Calculate actual status based on last_heartbeat
                actual_status = self._calculate_agent_status(agent, current_time)
                
                # Calculate time since last heartbeat
                time_since_heartbeat = None
                last_heartbeat = agent.get("last_heartbeat")
                if last_heartbeat:
                    # Handle timezone conversion
                    if hasattr(last_heartbeat, 'tzinfo') and last_heartbeat.tzinfo is None:
                        last_heartbeat = self.timezone.localize(last_heartbeat)
                    elif isinstance(last_heartbeat, datetime) and last_heartbeat.tzinfo != current_time.tzinfo:
                        last_heartbeat = last_heartbeat.astimezone(current_time.tzinfo)
                    
                    time_since_heartbeat = (current_time - last_heartbeat).total_seconds() / 60
                
                # Format agent data
                agent_data = {
                    "agent_id": agent.get("agent_id"),
                    "hostname": agent.get("hostname", "Unknown"),
                    "ip_address": agent.get("ip_address", "Unknown"),
                    "platform": agent.get("platform", "Unknown"),
                    "os_info": agent.get("os_info", "Unknown"),
                    "agent_version": agent.get("agent_version", "Unknown"),
                    "status": actual_status,  # ✅ Use calculated status
                    "registered_date": agent.get("registered_date").isoformat() if agent.get("registered_date") else None,
                    "last_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
                    "time_since_heartbeat": time_since_heartbeat,  # ✅ Add time since heartbeat
                    "metrics": agent.get("metrics"),
                    "user_id": agent.get("ip_address")
                }
                
                agents_list.append(agent_data)
            
            return {
                "agents": agents_list,
                "total": total_count,
                "success": True
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agents: {e}")
            return {
                "agents": [],
                "total": 0,
                "success": False,
                "error": str(e)
            }

    def _calculate_agent_status(self, agent: Dict, current_time: datetime) -> str:
        """
        ✅ Calculate real-time agent status based on last heartbeat
        
        Status Logic:
        - active: Last heartbeat within 2 minutes (up to 4 missed 30s heartbeats)
        - inactive: Last heartbeat 2-10 minutes ago  
        - offline: Last heartbeat > 10 minutes ago or never
        """
        last_heartbeat = agent.get("last_heartbeat")
        
        if not last_heartbeat:
            self.logger.debug(f"Agent {agent.get('hostname', 'unknown')}: No heartbeat → offline")
            return "offline"
        
        # Handle timezone conversion
        if hasattr(last_heartbeat, 'tzinfo') and last_heartbeat.tzinfo is None:
            # If stored as naive datetime, assume it's in our timezone
            last_heartbeat = self.timezone.localize(last_heartbeat)
        elif isinstance(last_heartbeat, datetime) and last_heartbeat.tzinfo != current_time.tzinfo:
            # Convert to same timezone for comparison
            last_heartbeat = last_heartbeat.astimezone(current_time.tzinfo)
        
        # Calculate time difference in minutes
        time_diff = (current_time - last_heartbeat).total_seconds() / 60
        
        # ✅ UPDATED THRESHOLDS FOR 30s HEARTBEAT
        if time_diff <= self.inactive_threshold:      # ≤ 2 minutes = active
            status = "active"
        elif time_diff <= self.offline_threshold:     # 2-10 minutes = inactive  
            status = "inactive"
        else:                                         # > 10 minutes = offline
            status = "offline"
        
        self.logger.debug(f"Agent {agent.get('hostname', 'unknown')}: {time_diff:.1f}m ago → {status}")
        return status

    def process_heartbeat(self, agent_id: str, token: str, heartbeat_data: Dict, client_ip: str) -> Dict:
        """Process agent heartbeat with enhanced validation"""
        try:
            # Validate agent and token
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # ✅ Update heartbeat timestamp immediately
            current_time = self._get_current_time()
            update_data = {
                "last_heartbeat": current_time,  # ✅ Ensure this is set to NOW
                "client_ip": client_ip,
                "metrics": heartbeat_data.get("metrics", {}),
                "status": "active",  # ✅ Force status to active when heartbeat received
                "agent_version": heartbeat_data.get("agent_version"),
                "last_heartbeat_data": heartbeat_data,
                "platform": heartbeat_data.get("platform"),
                "os_info": heartbeat_data.get("os_info")
            }
            
            success = self.model.update_heartbeat(agent_id, update_data)
            
            if not success:
                raise ValueError("Failed to update heartbeat")
            
            # ✅ Debug log to verify heartbeat processing
            self.logger.info(f"✅ Heartbeat processed: {agent.get('hostname')} at {current_time.isoformat()}")
            
            # Emit real-time status update
            if self.socketio:
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": "active",
                    "last_heartbeat": current_time.isoformat(),
                    "metrics": heartbeat_data.get("metrics", {}),
                    "client_ip": client_ip
                })
            
            return {
                "agent_id": agent_id,
                "status": "active",
                "next_heartbeat": int((current_time.timestamp() + 30) * 1000),  # ✅ Next in 30s
                "server_commands": [],
                "server_time": current_time.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Heartbeat processing failed: {e}")
            raise

    def get_active_count(self) -> int:
        """Get count of active agents"""
        try:
            current_time = self._get_current_time()
            inactive_threshold = current_time - timedelta(minutes=self.inactive_threshold)
            return self.model.count_agents({"last_heartbeat": {"$gte": inactive_threshold}})
        except Exception as e:
            self.logger.error(f"Error getting active agent count: {e}")
            return 0