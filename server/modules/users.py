"""
User Management Module - Simplified for IP-based agent users and admin.
"""

import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from bson import ObjectId
from flask import Blueprint, jsonify, request
from flask_socketio import SocketIO
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

logger = logging.getLogger("users_module")
users_bp = Blueprint('users', __name__)

# Global variables
socketio: Optional[SocketIO] = None
_db: Optional[Database] = None
_users_collection: Optional[Collection] = None

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO = None):
    """Initialize users module."""
    global _db, _users_collection, socketio
    
    socketio = socket_io
    db_name = app.config.get('MONGO_DBNAME', 'Monitoring')
    _db = mongo_client[db_name]
    _users_collection = _db.users
    
    # Create indexes
    _users_collection.create_index([("user_id", 1), ("role", 1)], unique=True)
    _users_collection.create_index([("role", 1)])
    _users_collection.create_index([("status", 1)])
    _users_collection.create_index([("last_heartbeat", DESCENDING)])
    
    app.register_blueprint(users_bp, url_prefix='/api/users')
    
    # Create default admin if not exists
    _create_default_admin()
    
    logger.info("Users module initialized")

def _create_default_admin():
    """Create default admin user if not exists."""
    try:
        admin_exists = _users_collection.find_one({"role": "admin"})
        if not admin_exists:
            # Create default admin
            admin_data = {
                "user_id": "admin",
                "username": "admin",
                "password_hash": _hash_password("admin123"),  # Default password
                "email": "admin@firewall-controller.local",
                "role": "admin",
                "status": "active",
                "created_at": datetime.utcnow()
            }
            
            _users_collection.insert_one(admin_data)
            logger.info("Created default admin user (username: admin, password: admin123)")
    except Exception as e:
        logger.error(f"Error creating default admin: {str(e)}")

def _hash_password(password: str) -> str:
    """Simple password hashing."""
    return hashlib.sha256(password.encode()).hexdigest()

# ======== PUBLIC APIs ========

@users_bp.route('', methods=['GET'])
def list_users():
    """List all users - public access."""
    try:
        role = request.args.get('role')  # admin, agent
        status = request.args.get('status')  # active, inactive
        limit = min(int(request.args.get('limit', 100)), 500)
        skip = int(request.args.get('skip', 0))
        
        # Build query
        query = {}
        if role:
            query["role"] = role
        if status:
            query["status"] = status
            
        # Execute query
        cursor = _users_collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
        total_count = _users_collection.count_documents(query)
        
        # Format results
        users = []
        for user in cursor:
            user_data = {
                "user_id": user.get("user_id"),
                "role": user.get("role"),
                "status": user.get("status"),
                "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
                "last_heartbeat": user.get("last_heartbeat").isoformat() if user.get("last_heartbeat") else None
            }
            
            # Add role-specific fields
            if user.get("role") == "admin":
                user_data.update({
                    "username": user.get("username"),
                    "email": user.get("email"),
                    "last_login": user.get("last_login").isoformat() if user.get("last_login") else None
                })
            elif user.get("role") == "agent":
                user_data.update({
                    "hostname": user.get("hostname"),
                    "ip_address": user.get("ip_address"),
                    "platform": user.get("platform"),
                    "agent_version": user.get("agent_version")
                })
            
            users.append(user_data)
            
        return jsonify({
            "users": users,
            "total": total_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return jsonify({"error": "Failed to list users"}), 500

@users_bp.route('/agents', methods=['GET'])
def list_agent_users():
    """List all agent users (by IP) - public access."""
    try:
        # Get all agent users
        cursor = _users_collection.find({"role": "agent"}).sort("last_heartbeat", -1)
        
        agents = []
        current_time = datetime.utcnow()
        
        for user in cursor:
            # Calculate status based on heartbeat
            actual_status = user.get("status", "unknown")
            if user.get("last_heartbeat"):
                time_since_heartbeat = (current_time - user["last_heartbeat"]).total_seconds() / 60
                if time_since_heartbeat > 5:  # 5 minutes threshold
                    actual_status = "inactive"
            
            agent_data = {
                "user_id": user.get("user_id"),  # IP address
                "hostname": user.get("hostname"),
                "ip_address": user.get("ip_address"),
                "platform": user.get("platform"),
                "os_info": user.get("os_info"),
                "agent_version": user.get("agent_version"),
                "status": actual_status,
                "last_heartbeat": user.get("last_heartbeat").isoformat() if user.get("last_heartbeat") else None,
                "created_at": user.get("created_at").isoformat() if user.get("created_at") else None
            }
            agents.append(agent_data)
            
        return jsonify({
            "agents": agents,
            "total": len(agents)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing agent users: {str(e)}")
        return jsonify({"error": "Failed to list agent users"}), 500

@users_bp.route('/admin/login', methods=['POST'])
def admin_login():
    """Admin login - public access."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    try:
        # Find admin user
        admin = _users_collection.find_one({
            "username": username,
            "role": "admin",
            "status": "active"
        })
        
        if not admin:
            return jsonify({"error": "Invalid credentials"}), 401
            
        # Check password
        password_hash = _hash_password(password)
        if admin.get("password_hash") != password_hash:
            return jsonify({"error": "Invalid credentials"}), 401
            
        # Update last login
        _users_collection.update_one(
            {"_id": admin["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": {
                "user_id": admin.get("user_id"),
                "username": admin.get("username"),
                "role": admin.get("role")
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error during admin login: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@users_bp.route('/stats', methods=['GET'])
def get_user_stats():
    """Get user statistics - public access."""
    try:
        # Count by role
        admin_count = _users_collection.count_documents({"role": "admin"})
        agent_count = _users_collection.count_documents({"role": "agent"})
        
        # Count active agents (heartbeat within 5 minutes)
        active_threshold = datetime.utcnow() - timedelta(minutes=5)
        active_agent_count = _users_collection.count_documents({
            "role": "agent",
            "last_heartbeat": {"$gte": active_threshold}
        })
        
        # Platform distribution for agents
        platform_pipeline = [
            {"$match": {"role": "agent"}},
            {"$group": {"_id": "$platform", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        platform_stats = list(_users_collection.aggregate(platform_pipeline))
        
        return jsonify({
            "users": {
                "admin_count": admin_count,
                "agent_count": agent_count,
                "active_agent_count": active_agent_count,
                "inactive_agent_count": agent_count - active_agent_count
            },
            "platforms": platform_stats,
            "generated_at": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting user stats: {str(e)}")
        return jsonify({"error": "Failed to get user statistics"}), 500

# ======== Helper functions ========

def get_user_by_ip(ip_address: str) -> Optional[Dict]:
    """Get agent user by IP address."""
    try:
        return _users_collection.find_one({"user_id": ip_address, "role": "agent"})
    except Exception as e:
        logger.error(f"Error getting user by IP: {str(e)}")
        return None

def get_admin_user() -> Optional[Dict]:
    """Get admin user."""
    try:
        return _users_collection.find_one({"role": "admin", "status": "active"})
    except Exception as e:
        logger.error(f"Error getting admin user: {str(e)}")
        return None

def update_agent_heartbeat(ip_address: str, data: Dict) -> bool:
    """Update agent user heartbeat."""
    try:
        update_data = {
            "last_heartbeat": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            **data
        }
        
        result = _users_collection.update_one(
            {"user_id": ip_address, "role": "agent"},
            {"$set": update_data},
            upsert=True
        )
        
        return result.modified_count > 0 or result.upserted_id is not None
        
    except Exception as e:
        logger.error(f"Error updating agent heartbeat: {str(e)}")
        return False