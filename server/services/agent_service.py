"""
Agent Service - Business logic for agent operations
"""

import uuid
import secrets
import logging
from datetime import datetime, timedelta, timezone
# ✅ REMOVED: ZoneInfo import (Windows compatibility issue)
from typing import Dict, List, Optional
from bson import ObjectId
from models.agent_model import AgentModel

class AgentService:
    """Service class for agent business logic"""
    
    def __init__(self, agent_model: AgentModel, db, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = agent_model
        self.db = db
        self.socketio = socketio
        
        self.commands_collection = db.agent_commands
        
        # ✅ SYNC với client thresholds - FIXED values
        self.active_threshold = 2      # minutes - Agent is ACTIVE if heartbeat within 2 minutes
        self.inactive_threshold = 5    # minutes - Agent is INACTIVE if heartbeat 2-5 minutes ago
        # Agent is OFFLINE if heartbeat > 5 minutes ago or never
        
        # ✅ FIXED: Use timezone offset instead of ZoneInfo (Windows compatible)
        self.vietnam_offset = timezone(timedelta(hours=7))  # UTC+7 for Vietnam
        self.server_timezone = self._get_server_timezone()
        
        self.logger.info(f"Server timezone: {self.server_timezone}")
        self.logger.info(f"Status thresholds: active≤{self.active_threshold}m, inactive≤{self.inactive_threshold}m")
    
    def _get_server_timezone(self) -> timezone:
        """Get server timezone - Windows compatible"""
        try:
            # Get local timezone offset
            local_offset = datetime.now().astimezone().utcoffset()
            return timezone(local_offset)
        except Exception:
            # Fallback to UTC
            self.logger.warning("Could not detect server timezone, using UTC")
            return timezone.utc
    
    def _now_local(self) -> datetime:
        """Get current local server time"""
        return datetime.now(self.server_timezone)
    
    def _now_vietnam(self) -> datetime:
        """Get current Vietnam time (UTC+7)"""
        vietnam_tz = timezone(timedelta(hours=7))
        return datetime.now(vietnam_tz)

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
            
            # ✅ FORCE UTC+7 for all timestamps
            vietnam_tz = timezone(timedelta(hours=7))
            current_time = datetime.now(vietnam_tz)
            
            if existing_agent:
                # Update existing agent
                agent_id = existing_agent.get("agent_id")
                update_data = {
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "platform": agent_data.get("platform"),
                    "os_info": agent_data.get("os_info"),
                    "agent_version": agent_data.get("agent_version"),
                    "last_heartbeat": current_time,  # ✅ UTC+7
                    "updated_date": current_time,    # ✅ UTC+7
                    "status": "active"
                }
                
                self.model.update_agent(agent_id, update_data)
                agent_token = existing_agent.get("agent_token")
                if not agent_token:
                    agent_token = secrets.token_hex(32)
                    self.model.update_agent(agent_id, {"agent_token": agent_token})
                
                self.logger.info(f"✅ Updated existing agent: {agent_id}")
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
                    "registered_date": current_time,   # ✅ UTC+7
                    "last_heartbeat": current_time,    # ✅ UTC+7
                    "status": "active"
                }
                
                self.model.register_agent(agent_registration_data)
                self.logger.info(f"✅ Created new agent: {agent_id}")

            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("agent_registered", {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "status": "active",
                    "timestamp": current_time.isoformat()
                })
        
            return {
                "agent_id": agent_id,
                "user_id": agent_ip,
                "token": agent_token,
                "status": "active",
                "message": f"Agent {'updated' if existing_agent else 'registered'} successfully",
                "server_time": current_time.isoformat()
            }
        
        except Exception as e:
            self.logger.error(f"Agent registration failed: {e}")
            raise

    def get_agents_with_status(self) -> List[Dict]:
        """Get all agents with FIXED status calculation - UTC+7 for ALL"""
        try:
            self.logger.info("🔧 get_agents_with_status() called - UTC+7 ONLY VERSION")
            
            agents = self.model.get_all_agents()
            self.logger.info(f"🔧 Found {len(agents)} agents from database")
            
            # ✅ SIMPLE: Use UTC+7 for everything
            vietnam_tz = timezone(timedelta(hours=7))
            now_vietnam = datetime.now(vietnam_tz)
            
            self.logger.info(f"🔧 Current Vietnam time (UTC+7): {now_vietnam}")
            
            for agent in agents:
                hostname = agent.get('hostname', 'Unknown')
                heartbeat = agent.get('last_heartbeat')
                
                if heartbeat:
                    self.logger.info(f"🔧 {hostname}: Processing heartbeat {heartbeat} (type: {type(heartbeat)})")
                    
                    try:
                        # ✅ CRITICAL FIX: Proper timezone handling
                        if isinstance(heartbeat, str):
                            # Parse string heartbeat
                            try:
                                if '+07:00' in heartbeat or '+00:00' in heartbeat or 'Z' in heartbeat:
                                    # Has timezone info - parse and convert to Vietnam time
                                    heartbeat_dt = datetime.fromisoformat(heartbeat.replace('Z', '+00:00'))
                                    heartbeat_vietnam = heartbeat_dt.astimezone(vietnam_tz)
                                    self.logger.info(f"🔧 {hostname}: Parsed with timezone, converted: {heartbeat_vietnam}")
                                else:
                                    # No timezone - assume it's UTC and convert to Vietnam
                                    heartbeat_utc = datetime.fromisoformat(heartbeat).replace(tzinfo=timezone.utc)
                                    heartbeat_vietnam = heartbeat_utc.astimezone(vietnam_tz)
                                    self.logger.info(f"🔧 {hostname}: Assumed UTC, converted to Vietnam: {heartbeat_vietnam}")
                            except Exception as parse_error:
                                self.logger.error(f"🔧 {hostname}: String parse error: {parse_error}")
                                agent['status'] = 'offline'
                                agent['time_since_heartbeat'] = 999
                                continue
                                
                        elif isinstance(heartbeat, datetime):
                            # Handle datetime object
                            if heartbeat.tzinfo is None:
                                # No timezone - assume it's UTC and convert to Vietnam
                                heartbeat_utc = heartbeat.replace(tzinfo=timezone.utc)
                                heartbeat_vietnam = heartbeat_utc.astimezone(vietnam_tz)
                                self.logger.info(f"🔧 {hostname}: Naive datetime assumed UTC, converted: {heartbeat_vietnam}")
                            else:
                                # Has timezone - convert to Vietnam
                                heartbeat_vietnam = heartbeat.astimezone(vietnam_tz)
                                self.logger.info(f"🔧 {hostname}: Datetime with timezone, converted: {heartbeat_vietnam}")
                        else:
                            self.logger.warning(f"🔧 {hostname}: Unknown heartbeat type: {type(heartbeat)}")
                            agent['status'] = 'offline'
                            agent['time_since_heartbeat'] = 999
                            continue
                        
                        # ✅ SIMPLE: Calculate difference (both in UTC+7 now)
                        time_diff = now_vietnam - heartbeat_vietnam
                        minutes_diff = time_diff.total_seconds() / 60
                        
                        self.logger.info(f"🔧 {hostname}: Time calculation (UTC+7 only):")
                        self.logger.info(f"🔧   Now Vietnam: {now_vietnam}")
                        self.logger.info(f"🔧   Heartbeat Vietnam: {heartbeat_vietnam}")
                        self.logger.info(f"🔧   Difference: {time_diff}")
                        self.logger.info(f"🔧   Minutes: {minutes_diff:.2f}")
                        
                        # ✅ Status calculation
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
                        import traceback
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
            import traceback
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
        """Process agent heartbeat - FORCE UTC+7 for all timestamps"""
        try:
            # Validate agent and token
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # ✅ CRITICAL FIX: Force UTC+7 timezone for heartbeat
            vietnam_tz = timezone(timedelta(hours=7))
            current_vietnam_time = datetime.now(vietnam_tz)
            
            # Update heartbeat with comprehensive data
            update_data = {
                "client_ip": client_ip,
                "metrics": heartbeat_data.get("metrics", {}),
                "status": heartbeat_data.get("status", "active"),
                "agent_version": heartbeat_data.get("agent_version"),
                "last_heartbeat_data": heartbeat_data,
                "platform": heartbeat_data.get("platform"),
                "os_info": heartbeat_data.get("os_info"),
                # ✅ FORCE: Set proper timestamp with UTC+7 timezone
                "last_heartbeat": current_vietnam_time
            }
            
            self.logger.info(f"🔧 Setting heartbeat for {agent_id}: {current_vietnam_time}")
            
            success = self.model.update_heartbeat(agent_id, update_data)
            
            if not success:
                raise ValueError("Failed to update heartbeat")
            
            # Emit real-time status update
            if self.socketio:
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": "active",
                    "last_heartbeat": current_vietnam_time.isoformat(),
                    "metrics": heartbeat_data.get("metrics", {}),
                    "client_ip": client_ip
                })
            
            self.logger.info(f"✅ Heartbeat processed for agent: {agent_id}")
            
            # Calculate next heartbeat time
            next_heartbeat_time = current_vietnam_time + timedelta(seconds=60)
            
            return {
                "agent_id": agent_id,
                "status": "active",
                "next_heartbeat": int(next_heartbeat_time.timestamp() * 1000),
                "server_commands": [],
                "server_time": current_vietnam_time.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Heartbeat processing failed: {e}")
            raise

    def force_agent_active(self, agent_id: str) -> bool:
        """TEMPORARY: Force agent to active status with current timestamp"""
        try:
            vietnam_tz = timezone(timedelta(hours=7))
            current_vietnam_time = datetime.now(vietnam_tz)
            
            update_data = {
                "last_heartbeat": current_vietnam_time,
                "status": "active",
                "updated_date": current_vietnam_time
            }
            
            result = self.model.collection.update_one(
                {"agent_id": agent_id},
                {"$set": update_data}
            )
            
            self.logger.info(f"✅ FORCED agent {agent_id} to active with heartbeat: {current_vietnam_time}")
            return result.modified_count > 0
            
        except Exception as e:
            self.logger.error(f"Error forcing agent active: {e}")
            return False

    def debug_status_calculation(self) -> Dict:
        """Debug method - UTC+7 ONLY"""
        try:
            agents = self.model.get_all_agents()
            vietnam_tz = timezone(timedelta(hours=7))
            now_vietnam = datetime.now(vietnam_tz)
            
            debug_info = {
                'current_time_vietnam': now_vietnam.isoformat(),
                'timezone': 'UTC+7 (Vietnam)',
                'thresholds': {
                    'active': self.active_threshold,
                    'inactive': self.inactive_threshold
                },
                'agents': []
            }
            
            for agent in agents:
                hostname = agent.get('hostname', 'Unknown')
                heartbeat = agent.get('last_heartbeat')
                
                agent_debug = {
                    'hostname': hostname,
                    'heartbeat_raw': str(heartbeat),
                    'heartbeat_type': str(type(heartbeat)),
                    'calculation_steps': []
                }
                
                if heartbeat:
                    try:
                        # Step 1: Parse heartbeat
                        if isinstance(heartbeat, str):
                            if '+07:00' in heartbeat or '+00:00' in heartbeat or 'Z' in heartbeat:
                                heartbeat_dt = datetime.fromisoformat(heartbeat.replace('Z', '+00:00'))
                                heartbeat_vietnam = heartbeat_dt.astimezone(vietnam_tz)
                            else:
                                heartbeat_utc = datetime.fromisoformat(heartbeat).replace(tzinfo=timezone.utc)
                                heartbeat_vietnam = heartbeat_utc.astimezone(vietnam_tz)
                        elif isinstance(heartbeat, datetime):
                            if heartbeat.tzinfo is None:
                                heartbeat_utc = heartbeat.replace(tzinfo=timezone.utc)
                                heartbeat_vietnam = heartbeat_utc.astimezone(vietnam_tz)
                            else:
                                heartbeat_vietnam = heartbeat.astimezone(vietnam_tz)
                        else:
                            agent_debug['error'] = f"Unknown heartbeat type: {type(heartbeat)}"
                            debug_info['agents'].append(agent_debug)
                            continue
                        
                        agent_debug['calculation_steps'].append(f"Parsed heartbeat: {heartbeat}")
                        agent_debug['calculation_steps'].append(f"Converted to Vietnam: {heartbeat_vietnam}")
                        
                        # Step 2: Calculate difference
                        time_diff = now_vietnam - heartbeat_vietnam
                        minutes_diff = time_diff.total_seconds() / 60
                        agent_debug['calculation_steps'].append(f"Time difference: {time_diff}")
                        agent_debug['calculation_steps'].append(f"Minutes: {minutes_diff:.2f}")
                        
                        # Step 3: Determine status
                        if minutes_diff <= self.active_threshold:
                            status = 'active'
                        elif minutes_diff <= self.inactive_threshold:
                            status = 'inactive'
                        else:
                            status = 'offline'
                        
                        agent_debug['final_status'] = status
                        agent_debug['minutes_since_heartbeat'] = minutes_diff
                        
                    except Exception as e:
                        agent_debug['error'] = str(e)
                        agent_debug['final_status'] = 'offline'
                else:
                    agent_debug['final_status'] = 'offline'
                    agent_debug['reason'] = 'No heartbeat found'
            
            return debug_info
        
        except Exception as e:
            return {'error': str(e)}

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
                    "timestamp": self._now_vietnam().isoformat()
                })
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting agent {agent_id}: {e}")
            raise

    def send_command(self, agent_id: str, command_data: Dict, created_by: str = "admin") -> str:
        """Send command to agent"""
        try:
            # Validate agent
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Check if agent is active
            agents_with_status = self.get_agents_with_status()
            agent_with_status = next((a for a in agents_with_status if a.get('agent_id') == agent_id), None)
            
            if agent_with_status:
                time_since_heartbeat = agent_with_status.get('time_since_heartbeat', float('inf'))
                if time_since_heartbeat > self.active_threshold:
                    agent_status = agent_with_status.get('status', 'offline')
                    raise ValueError(f"Agent is {agent_status} (last seen {time_since_heartbeat:.1f} minutes ago)")
            
            # Create command
            command = {
                "agent_id": agent_id,
                "command_type": command_data["command_type"],
                "parameters": command_data.get("parameters", {}),
                "priority": command_data.get("priority", 1),
                "description": command_data.get("description", ""),
                "status": "pending",
                "created_by": created_by,
                "created_at": self._now_vietnam()
            }
            
            result = self.commands_collection.insert_one(command)
            command_id = str(result.inserted_id)
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("command_created", {
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "command_type": command_data["command_type"],
                    "created_by": created_by,
                    "timestamp": self._now_vietnam().isoformat()
                })
            
            self.logger.info(f"Command {command_id} sent to agent {agent_id}")
            return command_id
            
        except Exception as e:
            self.logger.error(f"Error sending command to agent {agent_id}: {e}")
            raise

    def get_pending_commands(self, agent_id: str, token: str) -> Dict:
        """Get pending commands for agent"""
        try:
            # Validate agent
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Update heartbeat when agent checks for commands
            current_vietnam_time = self._now_vietnam()
            self.model.update_heartbeat(agent_id, {
                "client_ip": "heartbeat_via_commands",
                "last_heartbeat": current_vietnam_time
            })
            
            # Get pending commands
            commands = list(self.commands_collection.find({
                "agent_id": agent_id,
                "status": "pending"
            }).sort("priority", -1).sort("created_at", 1))
            
            # Format commands
            command_list = []
            for cmd in commands:
                cmd_data = {
                    "command_id": str(cmd["_id"]),
                    "command_type": cmd.get("command_type"),
                    "parameters": cmd.get("parameters"),
                    "priority": cmd.get("priority"),
                    "description": cmd.get("description"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None
                }
                command_list.append(cmd_data)
            
            return {
                "commands": command_list,
                "count": len(command_list),
                "server_time": current_vietnam_time.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting pending commands for agent {agent_id}: {e}")
            raise

    def update_command_result(self, agent_id: str, token: str, command_id: str, 
                            status: str, result: str = None, execution_time: float = None):
        """Update command execution result"""
        try:
            # Validate agent
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Validate command
            try:
                command_object_id = ObjectId(command_id)
            except:
                raise ValueError("Invalid command ID format")
            
            command = self.commands_collection.find_one({"_id": command_object_id})
            if not command:
                raise ValueError("Command not found")
            
            if command.get("agent_id") != agent_id:
                raise ValueError("Command does not belong to this agent")
            
            # Update command status
            update_data = {
                "status": status,
                "completed_at": self._now_vietnam(),
                "result": result,
                "execution_time": execution_time
            }
            
            self.commands_collection.update_one(
                {"_id": command_object_id},
                {"$set": update_data}
            )
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("command_status_update", {
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": status,
                    "timestamp": self._now_vietnam().isoformat()
                })
            
            self.logger.info(f"Command {command_id} status updated to {status}")
            
        except Exception as e:
            self.logger.error(f"Error updating command result: {e}")
            raise

    def ping_agent(self, agent_id: str) -> Dict:
        """Ping agent to check connectivity and response time"""
        try:
            # Validate agent exists
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Check if agent is active (optional - you can ping offline agents too)
            agents_with_status = self.get_agents_with_status()
            agent_with_status = next((a for a in agents_with_status if a.get('agent_id') == agent_id), None)
            
            current_status = 'offline'
            time_since_heartbeat = None
            
            if agent_with_status:
                current_status = agent_with_status.get('status', 'offline')
                time_since_heartbeat = agent_with_status.get('time_since_heartbeat')
            
            # Create ping command
            ping_command = {
                "command_type": "ping",
                "parameters": {
                    "timeout": 30,  # 30 seconds timeout
                    "expect_response": True
                },
                "priority": 5,  # High priority
                "description": f"Ping connectivity test from admin"
            }
            
            # Send ping command
            command_id = self.send_command(agent_id, ping_command, "system_ping")
            
            # Wait for response (for immediate feedback)
            import time
            max_wait_time = 30  # seconds
            wait_interval = 0.5  # seconds
            elapsed_time = 0
            
            ping_start_time = time.time()
            
            while elapsed_time < max_wait_time:
                # Check if command was completed
                try:
                    from bson import ObjectId
                    command = self.commands_collection.find_one({"_id": ObjectId(command_id)})
                    
                    if command and command.get("status") in ["completed", "success", "failed", "error"]:
                        response_time = time.time() - ping_start_time
                        
                        if command.get("status") in ["completed", "success"]:
                            self.logger.info(f"✅ Ping successful for agent {agent_id} in {response_time:.2f}s")
                            return {
                                "success": True,
                                "agent_id": agent_id,
                                "command_id": command_id,
                                "response_time": round(response_time, 2),
                                "agent_status": current_status,
                                "time_since_heartbeat": time_since_heartbeat,
                                "result": command.get("result", "Ping successful"),
                                "timestamp": self._now_vietnam().isoformat()
                            }
                        else:
                            self.logger.warning(f"❌ Ping failed for agent {agent_id}: {command.get('result', 'Unknown error')}")
                            return {
                                "success": False,
                                "agent_id": agent_id,
                                "command_id": command_id,
                                "response_time": round(response_time, 2),
                                "agent_status": current_status,
                                "time_since_heartbeat": time_since_heartbeat,
                                "error": command.get("result", "Ping command failed"),
                                "timestamp": self._now_vietnam().isoformat()
                            }
                
                except Exception as e:
                    self.logger.error(f"Error checking ping command status: {e}")
                
                time.sleep(wait_interval)
                elapsed_time += wait_interval
            
            # Timeout - command didn't complete in time
            self.logger.warning(f"⏰ Ping timeout for agent {agent_id} after {max_wait_time}s")
            return {
                "success": False,
                "agent_id": agent_id,
                "command_id": command_id,
                "response_time": max_wait_time,
                "agent_status": current_status,
                "time_since_heartbeat": time_since_heartbeat,
                "error": f"Ping timeout after {max_wait_time} seconds",
                "timeout": True,
                "timestamp": self._now_vietnam().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error pinging agent {agent_id}: {e}")
            raise

    def get_agent_ping_history(self, agent_id: str, limit: int = 10) -> List[Dict]:
        """Get ping command history for an agent"""
        try:
            # Validate agent
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Get ping commands
            ping_commands = list(self.commands_collection.find({
                "agent_id": agent_id,
                "command_type": "ping"
            }).sort("created_at", -1).limit(limit))
            
            history = []
            for cmd in ping_commands:
                history.append({
                    "command_id": str(cmd["_id"]),
                    "status": cmd.get("status"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None,
                    "completed_at": cmd.get("completed_at").isoformat() if cmd.get("completed_at") else None,
                    "execution_time": cmd.get("execution_time"),
                    "result": cmd.get("result"),
                    "created_by": cmd.get("created_by")
                })
            
            return history
            
        except Exception as e:
            self.logger.error(f"Error getting ping history for agent {agent_id}: {e}")
            raise