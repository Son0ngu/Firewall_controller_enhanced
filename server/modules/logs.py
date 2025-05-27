"""
Simplified Logs Module - No Authentication Required.
All endpoints are now public access for small project.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union

from bson import ObjectId
from flask import Blueprint, jsonify, request, current_app
from flask_socketio import SocketIO
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

# ❌ REMOVED: All authentication imports and decorators

logger = logging.getLogger("logs_module")
logs_bp = Blueprint('logs', __name__)

# Global variables
socketio: Optional[SocketIO] = None
_db: Optional[Database] = None
_logs_collection: Optional[Collection] = None

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO = None):
    """Initialize logs module."""
    global _db, _logs_collection, socketio
    
    socketio = socket_io
    db_name = app.config.get('MONGO_DBNAME', 'Monitoring')
    _db = mongo_client[db_name]
    _logs_collection = _db.logs
    
    # Create indexes for better performance
    _logs_collection.create_index([("timestamp", DESCENDING)])
    _logs_collection.create_index([("agent_id", 1)])
    _logs_collection.create_index([("domain", 1)])
    _logs_collection.create_index([("action", 1)])
    
    app.register_blueprint(logs_bp, url_prefix='/api')
    logger.info("Logs module initialized")

# ======== PUBLIC APIs - No Authentication Required ========

@logs_bp.route('/logs', methods=['POST'])
def receive_logs():
    """Receive logs from agents - public access."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    if not data or not isinstance(data, dict) or "logs" not in data:
        return jsonify({"error": "Invalid request format, 'logs' field required"}), 400
    
    logs = data["logs"]
    if not isinstance(logs, list):
        return jsonify({"error": "'logs' must be an array"}), 400
    
    # Validate and process each log
    valid_logs = []
    for log in logs:
        if not isinstance(log, dict):
            continue
            
        # Ensure required fields exist
        if "domain" not in log or "agent_id" not in log:
            continue
            
        # Add timestamp if not present
        if "timestamp" not in log:
            log["timestamp"] = datetime.utcnow().isoformat()
            
        # Convert timestamp from string to datetime
        if isinstance(log["timestamp"], str):
            try:
                log["timestamp"] = datetime.fromisoformat(log["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                log["timestamp"] = datetime.utcnow()
                
        valid_logs.append(log)
    
    if not valid_logs:
        return jsonify({"status": "warning", "message": "No valid logs provided"}), 200
        
    try:
        # Store logs in database
        result = _logs_collection.insert_many(valid_logs)
        
        # Broadcast new logs via SocketIO
        if socketio:
            for log in valid_logs:
                log_copy = log.copy()
                if "_id" in log_copy and isinstance(log_copy["_id"], ObjectId):
                    log_copy["_id"] = str(log_copy["_id"])
                if "timestamp" in log_copy and isinstance(log_copy["timestamp"], datetime):
                    log_copy["timestamp"] = log_copy["timestamp"].isoformat()
                socketio.emit('new_log', log_copy)
        
        return jsonify({
            "status": "success",
            "count": len(result.inserted_ids)
        }), 201
        
    except Exception as e:
        logger.error(f"Error storing logs: {str(e)}")
        return jsonify({"error": f"Failed to store logs: {str(e)}"}), 500

@logs_bp.route('/logs', methods=['GET'])
def get_logs():
    """Retrieve logs with filtering - public access."""
    try:
        # Parse query parameters
        agent_id = request.args.get('agent_id')
        domain = request.args.get('domain')
        action = request.args.get('action')
        since_str = request.args.get('since')
        until_str = request.args.get('until')
        limit = min(int(request.args.get('limit', 100)), 1000)
        skip = int(request.args.get('skip', 0))
        sort_field = request.args.get('sort', 'timestamp')
        sort_order = DESCENDING if request.args.get('order', 'desc').lower() == 'desc' else 1
        
        # Build query
        query = {}
        if agent_id:
            query["agent_id"] = agent_id
        if domain:
            query["domain"] = {"$regex": domain, "$options": "i"}
        if action:
            query["action"] = action
            
        # Build time query
        time_query = {}
        if since_str:
            try:
                since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
                time_query["$gte"] = since
            except ValueError:
                pass
        if until_str:
            try:
                until = datetime.fromisoformat(until_str.replace('Z', '+00:00'))
                time_query["$lte"] = until
            except ValueError:
                pass
        if time_query:
            query["timestamp"] = time_query
            
        # Execute query
        cursor = _logs_collection.find(query)
        total_count = _logs_collection.count_documents(query)
        cursor = cursor.sort(sort_field, sort_order).skip(skip).limit(limit)
        
        # Format results
        logs = []
        for log in cursor:
            log["_id"] = str(log["_id"])
            if "timestamp" in log and isinstance(log["timestamp"], datetime):
                log["timestamp"] = log["timestamp"].isoformat()
            logs.append(log)
            
        return jsonify({
            "logs": logs,
            "total": total_count,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pages": (total_count + limit - 1) // limit if limit > 0 else 1
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving logs: {str(e)}")
        return jsonify({"error": "Failed to retrieve logs"}), 500

@logs_bp.route('/logs/summary', methods=['GET'])
def get_logs_summary():
    """Get logs summary statistics - public access."""
    try:
        period = request.args.get('period', 'day').lower()
        
        # Determine time range
        now = datetime.utcnow()
        if period == 'week':
            since = now - timedelta(days=7)
        elif period == 'month':
            since = now - timedelta(days=30)
        else:
            since = now - timedelta(days=1)
            
        # Action statistics
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {"$group": {"_id": "$action", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        action_counts = list(_logs_collection.aggregate(pipeline))
        
        # Top blocked domains
        domains_pipeline = [
            {"$match": {"timestamp": {"$gte": since}, "action": "block"}},
            {"$group": {"_id": "$domain", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_blocked_domains = list(_logs_collection.aggregate(domains_pipeline))
        
        # Agent statistics
        agents_pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {"$group": {
                "_id": "$agent_id",
                "count": {"$sum": 1},
                "blocked": {"$sum": {"$cond": [{"$eq": ["$action", "block"]}, 1, 0]}},
                "allowed": {"$sum": {"$cond": [{"$eq": ["$action", "allow"]}, 1, 0]}}
            }},
            {"$sort": {"count": -1}}
        ]
        agent_stats = list(_logs_collection.aggregate(agents_pipeline))
        
        summary = {
            "period": period,
            "since": since.isoformat(),
            "until": now.isoformat(),
            "actions": {item["_id"]: item["count"] for item in action_counts},
            "top_blocked_domains": [{"domain": item["_id"], "count": item["count"]} for item in top_blocked_domains],
            "agents": [
                {
                    "agent_id": item["_id"],
                    "total": item["count"],
                    "blocked": item["blocked"],
                    "allowed": item["allowed"]
                } 
                for item in agent_stats
            ],
            "total_logs": sum(item["count"] for item in action_counts)
        }
        
        return jsonify(summary), 200
        
    except Exception as e:
        logger.error(f"Error generating logs summary: {str(e)}")
        return jsonify({"error": "Failed to generate logs summary"}), 500

@logs_bp.route('/logs/<log_id>', methods=['DELETE'])
def delete_log(log_id):
    """Delete specific log - public access."""
    try:
        try:
            object_id = ObjectId(log_id)
        except:
            return jsonify({"error": "Invalid log ID format"}), 400
            
        result = _logs_collection.delete_one({"_id": object_id})
        
        if result.deleted_count:
            return jsonify({"status": "success", "message": "Log deleted"}), 200
        else:
            return jsonify({"status": "error", "message": "Log not found"}), 404
            
    except Exception as e:
        logger.error(f"Error deleting log {log_id}: {str(e)}")
        return jsonify({"error": "Failed to delete log"}), 500

@logs_bp.route('/logs/clear', methods=['POST'])
def clear_logs():
    """Clear logs by criteria - public access."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    # Build delete query
    query = {}
    
    if "older_than" in data:
        try:
            older_than = datetime.fromisoformat(data["older_than"].replace('Z', '+00:00'))
            query["timestamp"] = {"$lt": older_than}
        except ValueError:
            return jsonify({"error": "Invalid datetime format"}), 400
            
    if "agent_id" in data:
        query["agent_id"] = data["agent_id"]
    if "action" in data:
        query["action"] = data["action"]
        
    if not query:
        return jsonify({"error": "At least one filter must be specified"}), 400
        
    try:
        result = _logs_collection.delete_many(query)
        return jsonify({
            "status": "success",
            "count": result.deleted_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({"error": "Failed to clear logs"}), 500

# ======== Helper functions remain the same ========
def add_log(log_data: Dict) -> Optional[str]:
    """Add log programmatically."""
    # Same implementation as before
    pass

def get_recent_logs(limit: int = 100) -> List[Dict]:
    """Get recent logs."""
    # Same implementation as before
    pass