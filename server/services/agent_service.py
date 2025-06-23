"""
Agent Service - Business logic for agent operations
"""
from datetime import datetime, timedelta, timezone  # 🔄 FIX: Add datetime import
import logging
import time
import secrets
import uuid
import traceback
from typing import Dict, List, Optional
from bson import ObjectId
from models.agent_model import AgentModel

# Import time utilities
from time_utils import (
    now_vietnam, now_vietnam_naive, now_vietnam_iso,
    to_vietnam_timezone, parse_agent_timestamp_direct, VIETNAM_TIMEZONE
)

class AgentService:
    """Service class for agent business logic"""
    
    def __init__(self, agent_model: AgentModel, socketio=None):
        """Initialize AgentService with proper parameters"""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = agent_model
        self.socketio = socketio
        
        #  FIX: Get database from model, not from parameter
        self.db = self.model.db
        self.commands_collection = self.db.agent_commands
        
        #  SYNC với client thresholds - FIXED values
        self.active_threshold = 2      # minutes - Agent is ACTIVE if heartbeat within 2 minutes
        self.inactive_threshold = 5    # minutes - Agent is INACTIVE if heartbeat 2-5 minutes ago
        # Agent is OFFLINE if heartbeat > 5 minutes ago or never
        
        self.logger.info(f" AgentService initialized")
        self.logger.info(f"Status thresholds: active≤{self.active_threshold}m, inactive≤{self.inactive_threshold}m")

    def register_agent(self, agent_data: Dict, client_ip: str) -> Dict:
        """Register a new agent using hostname+IP as identifier"""
        try:
            hostname = agent_data.get("hostname")
            
            self.logger.info(f"🔍 Agent registration: {hostname} from {client_ip}")
            
            if not hostname:
                raise ValueError("Hostname is required")
            
            # Use agent's reported IP if available
            agent_ip = agent_data.get("ip_address") or client_ip
            if agent_ip == "127.0.0.1" and client_ip != "127.0.0.1":
                agent_ip = client_ip
        
            # Check for existing agent by hostname + IP
            query = {"$or": [
                {"ip_address": agent_ip}, 
                {"hostname": hostname},
                {"$and": [{"hostname": hostname}, {"ip_address": agent_ip}]}
            ]}
            
            agents = self.model.get_all_agents(query, limit=1)
            existing_agent = agents[0] if agents else None
            
            # Use Vietnam time for all timestamps
            current_time = now_vietnam_naive()
            
            if existing_agent:
                # Update existing agent
                agent_id = existing_agent.get("agent_id")
                update_data = {
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "platform": agent_data.get("platform"),
                    "os_info": agent_data.get("os_info"),
                    "agent_version": agent_data.get("agent_version"),
                    "last_heartbeat": current_time,
                    "updated_date": current_time,
                    "status": "active"
                }
                
                self.model.update_agent(agent_id, update_data)
                agent_token = existing_agent.get("agent_token")
                if not agent_token:
                    agent_token = secrets.token_hex(32)
                    self.model.update_agent(agent_id, {"agent_token": agent_token})
                
                self.logger.info(f" Updated existing agent: {agent_id}")
            else:
                # Create new agent
                agent_id = str(uuid.uuid4())
                agent_token = secrets.token_hex(32)
                
                agent_registration_data = {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "platform": agent_data.get("platform"),
                    "os_info": agent_data.get("os_info"),
                    "agent_version": agent_data.get("agent_version"),
                    "agent_token": agent_token,
                    "registered_date": current_time,
                    "last_heartbeat": current_time,
                    "status": "active"
                }
                
                self.model.register_agent(agent_registration_data)
                self.logger.info(f" Created new agent: {agent_id}")

            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("agent_registered", {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "status": "active",
                    "timestamp": now_vietnam_iso()
                })
        
            return {
                "agent_id": agent_id,
                "user_id": agent_ip,
                "token": agent_token,
                "status": "active",
                "message": f"Agent {'updated' if existing_agent else 'registered'} successfully",
                "server_time": now_vietnam_iso()
            }
        
        except Exception as e:
            self.logger.error(f"Agent registration failed: {e}")
            raise

    def get_agents_with_status(self) -> List[Dict]:
        """Get all agents with status calculation - FIXED timezone handling"""
        try:
            self.logger.info("🔧 get_agents_with_status() called - FIXED VERSION")
            
            agents = self.model.get_all_agents()
            self.logger.info(f"🔧 Found {len(agents)} agents from database")
            
            # Use Vietnam time for status calculation
            now_vn = now_vietnam()
            
            self.logger.info(f"🔧 Current Vietnam time: {now_vn}")
            
            for agent in agents:
                hostname = agent.get('hostname', 'Unknown')
                heartbeat = agent.get('last_heartbeat')
                
                if heartbeat:
                    self.logger.info(f"🔧 {hostname}: Processing heartbeat {heartbeat} (type: {type(heartbeat)})")
                    
                    try:
                        # 🔄 FIX: Handle different heartbeat formats
                        if isinstance(heartbeat, str):
                            # Parse string heartbeat using parse_agent_timestamp_direct
                            try:
                                heartbeat_vietnam = parse_agent_timestamp_direct(heartbeat)
                                # Convert to timezone-aware for comparison
                                heartbeat_vietnam = heartbeat_vietnam.replace(tzinfo=VIETNAM_TIMEZONE)
                            except Exception as parse_error:
                                self.logger.error(f"🔧 {hostname}: String parse error: {parse_error}")
                                agent['status'] = 'offline'
                                agent['time_since_heartbeat'] = 999
                                continue
                                
                        elif isinstance(heartbeat, datetime):
                            if heartbeat.tzinfo is None:
                                # 🔄 CRITICAL FIX: Naive datetime from MongoDB is UTC, not Vietnam!
                                # Old data was stored as UTC naive, convert to Vietnam
                                heartbeat_utc = heartbeat.replace(tzinfo=timezone.utc)
                                heartbeat_vietnam = heartbeat_utc.astimezone(VIETNAM_TIMEZONE)
                                self.logger.info(f"🔧 {hostname}: Naive datetime converted UTC→Vietnam: {heartbeat} → {heartbeat_vietnam}")
                            else:
                                # Has timezone - convert to Vietnam
                                heartbeat_vietnam = to_vietnam_timezone(heartbeat)
                                self.logger.info(f"🔧 {hostname}: Timezone-aware datetime converted: {heartbeat_vietnam}")
                        else:
                            self.logger.warning(f"🔧 {hostname}: Unknown heartbeat type: {type(heartbeat)}")
                            agent['status'] = 'offline'
                            agent['time_since_heartbeat'] = 999
                            continue
                        
                        # Calculate difference
                        time_diff = now_vn - heartbeat_vietnam
                        minutes_diff = time_diff.total_seconds() / 60
                        
                        self.logger.info(f"🔧 {hostname}: Time calculation:")
                        self.logger.info(f"🔧   Now Vietnam: {now_vn}")
                        self.logger.info(f"🔧   Heartbeat Vietnam: {heartbeat_vietnam}")
                        self.logger.info(f"🔧   Difference: {time_diff}")
                        self.logger.info(f"🔧   Minutes: {minutes_diff:.2f}")
                        
                        # Status calculation
                        if minutes_diff <= self.active_threshold:      # 2 minutes = active
                            status = 'active'
                            self.logger.info(f"🔧 {hostname}: {minutes_diff:.2f} ≤ {self.active_threshold} → ACTIVE")
                        elif minutes_diff <= self.inactive_threshold:  # 5 minutes = inactive
                            status = 'inactive'
                            self.logger.info(f"🔧 {hostname}: {minutes_diff:.2f} ≤ {self.inactive_threshold} → INACTIVE")
                        else:                                          # > 5 minutes = offline
                            status = 'offline'
                            self.logger.info(f"🔧 {hostname}: {minutes_diff:.2f} > {self.inactive_threshold} → OFFLINE")
                        
                        agent['status'] = status
                        agent['time_since_heartbeat'] = minutes_diff
                        
                        self.logger.info(f"🔧 {hostname}: FINAL → {minutes_diff:.2f}m = {status}")
                        
                    except Exception as e:
                        self.logger.error(f"🔧 {hostname}: Error processing heartbeat: {e}")
                        self.logger.error(f"🔧 {hostname}: Traceback: {traceback.format_exc()}")
                        agent['status'] = 'offline'
                        agent['time_since_heartbeat'] = 999
                else:
                    self.logger.info(f"🔧 {hostname}: No heartbeat found")
                    agent['status'] = 'offline'
                    agent['time_since_heartbeat'] = None

            self.logger.info(f"🔧 Returning {len(agents)} agents with status")
            return agents
            
        except Exception as e:
            self.logger.error(f"🔧 get_agents_with_status error: {e}")
            self.logger.error(traceback.format_exc())
            return []

    def calculate_statistics(self) -> Dict:
        """Calculate agent statistics"""
        try:
            agents = self.get_agents_with_status()
            
            total = len(agents)
            active = len([a for a in agents if a.get('status') == 'active'])
            inactive = len([a for a in agents if a.get('status') == 'inactive'])
            offline = len([a for a in agents if a.get('status') == 'offline'])
            
            stats = {
                'total': total,
                'active': active,
                'inactive': inactive,
                'offline': offline
            }
            
            self.logger.info(f"📊 Statistics: {stats}")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {e}")
            return {'total': 0, 'active': 0, 'inactive': 0, 'offline': 0}

    def process_heartbeat(self, agent_id: str, token: str, heartbeat_data: Dict, client_ip: str) -> Dict:
        """Process agent heartbeat - FIXED to use parse_agent_timestamp_direct"""
        try:
            # Validate agent and token
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # 🔄 FIX: Parse agent timestamp using NEW method
            agent_timestamp = heartbeat_data.get("timestamp")
            if agent_timestamp:
                try:
                    # Use parse_agent_timestamp_direct instead of parse_iso_to_vietnam
                    current_time = parse_agent_timestamp_direct(agent_timestamp)
                    self.logger.info(f"🔧 Agent {agent_id} sent: '{agent_timestamp}' → parsed: {current_time}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to parse agent timestamp '{agent_timestamp}': {e}")
                    current_time = now_vietnam_naive()
            else:
                current_time = now_vietnam_naive()
        
            # Update heartbeat with parsed timestamp
            update_data = {
                "client_ip": client_ip,
                "metrics": heartbeat_data.get("metrics", {}),
                "status": heartbeat_data.get("status", "active"),
                "agent_version": heartbeat_data.get("agent_version"),
                "last_heartbeat_data": heartbeat_data,
                "platform": heartbeat_data.get("platform"),
                "os_info": heartbeat_data.get("os_info"),
                "last_heartbeat": current_time  # Use parsed timestamp
            }
            
            self.logger.info(f"🔧 Setting heartbeat for {agent_id}: {current_time}")
            
            success = self.model.update_heartbeat(agent_id, update_data)
            
            if not success:
                raise ValueError("Failed to update heartbeat")
            
            # Emit real-time status update
            if self.socketio:
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": "active",
                    "last_heartbeat": now_vietnam_iso(),
                    "metrics": heartbeat_data.get("metrics", {}),
                    "client_ip": client_ip
                })
            
            self.logger.info(f" Heartbeat processed for agent: {agent_id}")
            
            # Calculate next heartbeat time
            from datetime import timedelta
            next_heartbeat_time = now_vietnam() + timedelta(seconds=60)
            
            return {
                "agent_id": agent_id,
                "status": "active",
                "next_heartbeat": int(next_heartbeat_time.timestamp() * 1000),
                "server_commands": [],
                "server_time": now_vietnam_iso()
            }
            
        except Exception as e:
            self.logger.error(f"Heartbeat processing failed: {e}")
            raise

    def get_total_agents(self) -> int:
        """Get total number of agents"""
        try:
            return self.model.count_agents({})
        except Exception as e:
            self.logger.error(f"Error getting total agents: {e}")
            return 0
    
    def get_active_agents_count(self) -> int:
        """Get count of active agents"""
        try:
            agents = self.get_agents_with_status()
            return len([a for a in agents if a.get('status') == 'active'])
        except Exception as e:
            self.logger.error(f"Error getting active agents count: {e}")
            return 0

    def get_all_agents(self, filters: Dict = None) -> List[Dict]:
        """Get all agents with optional filtering"""
        try:
            agents = self.get_agents_with_status()
            
            # Apply filters if provided
            if filters:
                if filters.get("status"):
                    status_filter = filters["status"]
                    agents = [a for a in agents if a.get('status') == status_filter]
                
                if filters.get("hostname"):
                    hostname_filter = filters["hostname"].lower()
                    agents = [a for a in agents if hostname_filter in a.get('hostname', '').lower()]
            
            # Format for response
            formatted_agents = []
            for agent in agents:
                formatted_agent = {
                    "id": str(agent.get("_id", "")),
                    "agent_id": agent.get("agent_id", "unknown"),
                    "hostname": agent.get("hostname", "unknown"),
                    "ip_address": agent.get("ip_address", "unknown"),
                    "status": agent.get("status", "unknown"),
                    "last_seen": agent.get("last_heartbeat"),
                    "version": agent.get("agent_version", "unknown"),
                    "os_info": agent.get("os_info", {}),
                    "platform": agent.get("platform", "unknown"),
                    "created_at": agent.get("registered_date"),
                    "updated_at": agent.get("last_heartbeat"),
                    "time_since_heartbeat": agent.get("time_since_heartbeat")
                }
                
                # Format timestamps
                for time_field in ["last_seen", "created_at", "updated_at"]:
                    if agent.get(time_field):
                        try:
                            timestamp = agent[time_field]
                            if hasattr(timestamp, 'isoformat'):
                                formatted_agent[time_field] = timestamp.isoformat()
                            else:
                                formatted_agent[time_field] = str(timestamp)
                        except Exception as e:
                            self.logger.warning(f"Error formatting {time_field}: {e}")
                            formatted_agent[time_field] = None
                
                formatted_agents.append(formatted_agent)
            
            return formatted_agents
            
        except Exception as e:
            self.logger.error(f"Error getting all agents: {e}")
            return []

    def get_agent_details(self, agent_id: str) -> Dict:
        """Get detailed agent information"""
        try:
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Calculate status using get_agents_with_status for consistency
            agents_with_status = self.get_agents_with_status()
            agent_with_status = next((a for a in agents_with_status if a.get('agent_id') == agent_id), None)
            
            if agent_with_status:
                actual_status = agent_with_status.get('status', 'offline')
                time_since_heartbeat = agent_with_status.get('time_since_heartbeat')
            else:
                actual_status = 'offline'
                time_since_heartbeat = None
            
            # Get recent commands
            recent_commands = list(self.commands_collection.find(
                {"agent_id": agent_id}
            ).sort("created_at", -1).limit(5))
            
            commands = []
            for cmd in recent_commands:
                commands.append({
                    "command_id": str(cmd["_id"]),
                    "command_type": cmd.get("command_type"),
                    "status": cmd.get("status"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None
                })
            
            return {
                "agent_id": agent.get("agent_id"),
                "hostname": agent.get("hostname"),
                "ip_address": agent.get("ip_address"),
                "mac_address": agent.get("mac_address"),
                "platform": agent.get("platform"),
                "os_info": agent.get("os_info"),
                "agent_version": agent.get("agent_version"),
                "status": actual_status,
                "registered_date": agent.get("registered_date").isoformat() if agent.get("registered_date") else None,
                "last_heartbeat": agent.get("last_heartbeat").isoformat() if agent.get("last_heartbeat") else None,
                "time_since_heartbeat": time_since_heartbeat,
                "recent_commands": commands
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent details: {e}")
            raise

    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent and related data"""
        try:
            # Check if agent exists
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Delete related commands
            deleted_commands = self.commands_collection.delete_many({"agent_id": agent_id})
            self.logger.info(f"Deleted {deleted_commands.deleted_count} commands for agent {agent_id}")
            
            # Delete agent
            success = self.model.delete_agent(agent_id)
            
            if success and self.socketio:
                self.socketio.emit("agent_deleted", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "timestamp": now_vietnam_iso()
                })
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting agent {agent_id}: {e}")
            raise

    def ping_agent(self, agent_id: str) -> Dict:
        """Ping an agent to check connectivity"""
        try:
            import time
            import requests
            
            self.logger.info(f"📡 Pinging agent: {agent_id}")
            
            # Check if agent exists
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Get agent info
            hostname = agent.get("hostname", "Unknown")
            ip_address = agent.get("ip_address", "unknown")
            
            # Try to ping agent's IP address
            ping_result = self._ping_ip_address(ip_address)
            
            if ping_result["success"]:
                # Success - update agent status to active
                current_time = now_vietnam_naive()
                
                self.model.update_agent(agent_id, {
                    "status": "active",
                    "last_ping": current_time,
                    "ping_response_time": ping_result["response_time"]
                })
                
                return {
                    "success": True,
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "response_time": ping_result["response_time"],
                    "method": "ip_ping",
                    "message": f"Agent {hostname} is reachable"
                }
            else:
                # Failed - mark as inactive but don't fail completely
                self.model.update_agent(agent_id, {
                    "status": "inactive",
                    "last_ping_attempt": now_vietnam_naive(),
                    "last_ping_error": ping_result["error"]
                })
                
                return {
                    "success": False,
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "response_time": None,
                    "method": "ip_ping",
                    "error": ping_result["error"],
                    "message": f"Agent {hostname} is not reachable"
                }
                
        except ValueError as ve:
            self.logger.error(f"Ping validation error: {ve}")
            raise
        except Exception as e:
            self.logger.error(f"Error pinging agent {agent_id}: {e}")
            raise

    def _ping_ip_address(self, ip_address: str) -> Dict:
        """Ping an IP address using system ping command"""
        try:
            import subprocess
            import platform
            import time
            
            if not ip_address or ip_address == "unknown":
                return {
                    "success": False,
                    "response_time": None,
                    "error": "Invalid IP address"
                }
            
            # Cross-platform ping command
            system = platform.system().lower()
            
            if system == "windows":
                # Windows ping command
                cmd = ["ping", "-n", "1", "-w", "3000", ip_address]  # 1 packet, 3 second timeout
            else:
                # Linux/macOS ping command
                cmd = ["ping", "-c", "1", "-W", "3", ip_address]     # 1 packet, 3 second timeout
            
            self.logger.debug(f"Executing ping command: {' '.join(cmd)}")
            
            start_time = time.time()
            
            # Execute ping command
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=5  # Total timeout 5 seconds
            )
            
            end_time = time.time()
            response_time = round((end_time - start_time), 3)
            
            if result.returncode == 0:
                # Ping successful
                self.logger.debug(f"Ping successful to {ip_address}: {response_time}s")
                return {
                    "success": True,
                    "response_time": response_time,
                    "output": result.stdout.strip()
                }
            else:
                # Ping failed
                error_msg = result.stderr.strip() or result.stdout.strip() or "Ping failed"
                self.logger.debug(f"Ping failed to {ip_address}: {error_msg}")
                return {
                    "success": False,
                    "response_time": response_time,
                    "error": error_msg
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "response_time": 5.0,
                "error": "Ping timeout (5 seconds)"
            }
        except FileNotFoundError:
            return {
                "success": False,
                "response_time": None,
                "error": "Ping command not found on system"
            }
        except Exception as e:
            self.logger.error(f"Error executing ping: {e}")
            return {
                "success": False,
                "response_time": None,
                "error": f"Ping execution error: {str(e)}"
            }

    def send_command(self, agent_id: str, command_data: Dict, created_by: str) -> str:
        """Send command to agent"""
        try:
            # Check if agent exists
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Generate command ID
            command_id = str(uuid.uuid4())
            
            # Create command document
            current_time = now_vietnam_naive()
            
            command_doc = {
                "_id": ObjectId(),
                "command_id": command_id,
                "agent_id": agent_id,
                "command_type": command_data.get("command_type"),
                "parameters": command_data.get("parameters", {}),
                "status": "pending",
                "created_by": created_by,
                "created_at": current_time,
                "updated_at": current_time,
                "expires_at": current_time + timedelta(hours=1)  # Commands expire after 1 hour
            }
            
            # Insert command
            result = self.commands_collection.insert_one(command_doc)
            
            if result.inserted_id:
                self.logger.info(f"Command {command_id} created for agent {agent_id}")
                return command_id
            else:
                raise Exception("Failed to create command")
                
        except Exception as e:
            self.logger.error(f"Error sending command to agent {agent_id}: {e}")
            raise

    def get_pending_commands(self, agent_id: str, token: str) -> List[Dict]:
        """Get pending commands for agent"""
        try:
            # Validate agent and token
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Get pending commands
            current_time = now_vietnam_naive()
            
            commands = list(self.commands_collection.find({
                "agent_id": agent_id,
                "status": "pending",
                "expires_at": {"$gte": current_time}
            }).sort("created_at", 1))
            
            # Format commands for agent
            formatted_commands = []
            for cmd in commands:
                formatted_cmd = {
                    "command_id": cmd.get("command_id"),
                    "command_type": cmd.get("command_type"),
                    "parameters": cmd.get("parameters", {}),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None
                }
                formatted_commands.append(formatted_cmd)
            
            return formatted_commands
            
        except Exception as e:
            self.logger.error(f"Error getting pending commands for agent {agent_id}: {e}")
            raise

    def update_command_result(self, agent_id: str, token: str, command_id: str, 
                         status: str, result: str = None, execution_time: float = None):
        """Update command execution result"""
        try:
            # Validate agent and token
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Update command
            current_time = now_vietnam_naive()
            
            update_data = {
                "status": status,
                "updated_at": current_time,
                "completed_at": current_time,
                "execution_time": execution_time
            }
            
            if result:
                update_data["result"] = result
            
            result = self.commands_collection.update_one(
                {"command_id": command_id, "agent_id": agent_id},
                {"$set": update_data}
            )
            
            if result.modified_count > 0:
                self.logger.info(f"Command {command_id} updated with status: {status}")
            else:
                self.logger.warning(f"Command {command_id} not found or not updated")
                
        except Exception as e:
            self.logger.error(f"Error updating command result: {e}")
            raise

    def list_commands(self, filters: Dict = None, limit: int = 50, skip: int = 0) -> Dict:
        """List commands with filtering"""
        try:
            query = {}
            
            if filters:
                if filters.get("agent_id"):
                    query["agent_id"] = filters["agent_id"]
                if filters.get("status"):
                    query["status"] = filters["status"]
                if filters.get("command_type"):
                    query["command_type"] = filters["command_type"]
            
            # Get total count
            total = self.commands_collection.count_documents(query)
            
            # Get commands
            commands = list(self.commands_collection.find(query)
                           .sort("created_at", -1)
                           .skip(skip)
                           .limit(limit))
            
            # Format commands
            formatted_commands = []
            for cmd in commands:
                # Get agent info
                agent = self.model.find_by_agent_id(cmd.get("agent_id"))
                
                formatted_cmd = {
                    "command_id": cmd.get("command_id"),
                    "agent_id": cmd.get("agent_id"),
                    "hostname": agent.get("hostname") if agent else "Unknown",
                    "command_type": cmd.get("command_type"),
                    "status": cmd.get("status"),
                    "created_by": cmd.get("created_by"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None,
                    "completed_at": cmd.get("completed_at").isoformat() if cmd.get("completed_at") else None,
                    "execution_time": cmd.get("execution_time"),
                    "result": cmd.get("result")
                }
                formatted_commands.append(formatted_cmd)
            
            return {
                "commands": formatted_commands,
                "total": total
            }
            
        except Exception as e:
            self.logger.error(f"Error listing commands: {e}")
            raise