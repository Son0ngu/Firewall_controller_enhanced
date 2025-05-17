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

# Configure logging
logger = logging.getLogger("logs_module")

# Initialize Blueprint for API routes
logs_bp = Blueprint('logs', __name__)

# Will be initialized externally with the Flask-SocketIO instance
socketio: Optional[SocketIO] = None

# MongoDB connection (initialized in init_app)
_db: Optional[Database] = None
_logs_collection: Optional[Collection] = None

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO):
    """
    Initialize the logs module with the Flask app and MongoDB connection.
    
    Args:
        app: The Flask application instance
        mongo_client: PyMongo MongoClient instance
        socket_io: Flask-SocketIO instance
    """
    global _db, _logs_collection, socketio
    
    # Store the SocketIO instance
    socketio = socket_io
    
    # Get the database
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Get the logs collection
    _logs_collection = _db.logs
    
    # Create indexes
    _logs_collection.create_index([("timestamp", DESCENDING)])
    _logs_collection.create_index([("agent_id", 1)])
    _logs_collection.create_index([("domain", 1)])
    _logs_collection.create_index([("action", 1)])
    
    # Register the blueprint with the app
    app.register_blueprint(logs_bp, url_prefix='/api')
    
    logger.info("Logs module initialized")


# API Routes

@logs_bp.route('/logs', methods=['POST'])
def receive_logs():
    """
    Receive logs from agents and store them in the database.
    Broadcasts new logs to dashboard clients via Socket.IO.
    
    Request format:
    {
        "logs": [
            {
                "agent_id": "agent123",
                "timestamp": "2023-01-01T12:00:00Z",
                "domain": "example.com",
                "dest_ip": "93.184.216.34",
                "dest_port": 443,
                "protocol": "HTTPS",
                "action": "block"
            },
            ...
        ]
    }
    
    Returns:
        JSON response with status and count of logs stored
    """
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
        # Skip invalid logs
        if not isinstance(log, dict):
            continue
            
        # Ensure required fields
        if "domain" not in log or "agent_id" not in log:
            continue
            
        # Add timestamp if not present
        if "timestamp" not in log:
            log["timestamp"] = datetime.utcnow().isoformat()
            
        # Parse timestamp if it's a string
        if isinstance(log["timestamp"], str):
            try:
                log["timestamp"] = datetime.fromisoformat(log["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                # If parsing fails, use current time
                log["timestamp"] = datetime.utcnow()
                
        # Add to valid logs
        valid_logs.append(log)
    
    if not valid_logs:
        return jsonify({"status": "warning", "message": "No valid logs provided"}), 200
        
    try:
        # Insert logs into database
        result = _logs_collection.insert_many(valid_logs)
        
        # Broadcast new logs to connected clients
        for log in valid_logs:
            # Convert ObjectId to string for JSON serialization
            log_with_id = log.copy()
            if "_id" in log_with_id and isinstance(log_with_id["_id"], ObjectId):
                log_with_id["_id"] = str(log_with_id["_id"])
                
            # Convert datetime to ISO string
            if "timestamp" in log_with_id and isinstance(log_with_id["timestamp"], datetime):
                log_with_id["timestamp"] = log_with_id["timestamp"].isoformat()
                
            # Emit the log event
            if socketio:
                socketio.emit('new_log', log_with_id)
        
        return jsonify({
            "status": "success",
            "count": len(result.inserted_ids)
        }), 201
        
    except Exception as e:
        logger.error(f"Error storing logs: {str(e)}")
        return jsonify({"error": "Failed to store logs"}), 500


@logs_bp.route('/logs', methods=['GET'])
def get_logs():
    """
    Retrieve logs with optional filtering and pagination.
    
    Query parameters:
    - agent_id: Filter by agent ID
    - domain: Filter by domain (supports partial match)
    - action: Filter by action (e.g., block, allow)
    - since: ISO datetime string to filter logs after a certain time
    - until: ISO datetime string to filter logs before a certain time
    - limit: Maximum number of logs to return (default: 100)
    - skip: Number of logs to skip (for pagination, default: 0)
    - sort: Field to sort by (default: timestamp)
    - order: Sort order, 'asc' or 'desc' (default: desc)
    
    Returns:
        JSON with logs array and metadata
    """
    try:
        # Parse query parameters
        agent_id = request.args.get('agent_id')
        domain = request.args.get('domain')
        action = request.args.get('action')
        since_str = request.args.get('since')
        until_str = request.args.get('until')
        limit = min(int(request.args.get('limit', 100)), 1000)  # Cap at 1000
        skip = int(request.args.get('skip', 0))
        sort_field = request.args.get('sort', 'timestamp')
        sort_order = DESCENDING if request.args.get('order', 'desc').lower() == 'desc' else 1
        
        # Build query
        query = {}
        
        if agent_id:
            query["agent_id"] = agent_id
            
        if domain:
            query["domain"] = {"$regex": domain, "$options": "i"}  # Case-insensitive partial match
            
        if action:
            query["action"] = action
            
        # Parse time filters
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
        
        # Get total count (before pagination)
        total_count = _logs_collection.count_documents(query)
        
        # Apply sorting and pagination
        cursor = cursor.sort(sort_field, sort_order).skip(skip).limit(limit)
        
        # Convert to list and prepare for JSON serialization
        logs = []
        for log in cursor:
            # Convert ObjectId to string
            log["_id"] = str(log["_id"])
            
            # Convert datetime to ISO string
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
    """
    Get summary statistics for logs.
    
    Query parameters:
    - period: Time period for the summary - 'day', 'week', 'month' (default: day)
    
    Returns:
        JSON with summary statistics
    """
    try:
        # Parse period parameter
        period = request.args.get('period', 'day').lower()
        
        # Determine the time range based on period
        now = datetime.utcnow()
        if period == 'week':
            since = now - timedelta(days=7)
        elif period == 'month':
            since = now - timedelta(days=30)
        else:  # default to day
            since = now - timedelta(days=1)
            
        # Build the aggregation pipeline
        pipeline = [
            # Match logs in the time range
            {"$match": {"timestamp": {"$gte": since}}},
            
            # Group by action and count
            {"$group": {
                "_id": "$action",
                "count": {"$sum": 1}
            }},
            
            # Sort by count (descending)
            {"$sort": {"count": -1}}
        ]
        
        action_counts = list(_logs_collection.aggregate(pipeline))
        
        # Top blocked domains
        domains_pipeline = [
            {"$match": {"timestamp": {"$gte": since}, "action": "block"}},
            {"$group": {
                "_id": "$domain",
                "count": {"$sum": 1}
            }},
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
        
        # Format the results
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
    """
    Delete a specific log by ID.
    
    Args:
        log_id: The ID of the log to delete
    
    Returns:
        JSON response with status
    """
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(log_id)
        except:
            return jsonify({"error": "Invalid log ID format"}), 400
            
        # Try to delete the log
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
    """
    Clear logs matching certain criteria.
    
    Request body:
    {
        "older_than": "2023-01-01T00:00:00Z",  # Optional, clear logs older than this
        "agent_id": "agent123",                # Optional, clear logs for this agent
        "action": "block"                      # Optional, clear logs with this action
    }
    
    Returns:
        JSON response with count of logs deleted
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    # Build query
    query = {}
    
    # Older than filter
    if "older_than" in data:
        try:
            older_than = datetime.fromisoformat(data["older_than"].replace('Z', '+00:00'))
            query["timestamp"] = {"$lt": older_than}
        except ValueError:
            return jsonify({"error": "Invalid datetime format"}), 400
            
    # Agent filter
    if "agent_id" in data:
        query["agent_id"] = data["agent_id"]
        
    # Action filter
    if "action" in data:
        query["action"] = data["action"]
        
    if not query:
        return jsonify({"error": "At least one filter must be specified"}), 400
        
    try:
        # Delete matching logs
        result = _logs_collection.delete_many(query)
        
        return jsonify({
            "status": "success",
            "count": result.deleted_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({"error": "Failed to clear logs"}), 500


# Helper functions

def add_log(log_data: Dict) -> Optional[str]:
    """
    Add a single log entry programmatically (for internal use).
    
    Args:
        log_data: Dictionary with log data
        
    Returns:
        str: ID of the inserted log, or None if insertion failed
    """
    try:
        # Ensure required fields
        if "domain" not in log_data:
            logger.error("Log data missing required 'domain' field")
            return None
            
        # Add timestamp if not present
        if "timestamp" not in log_data:
            log_data["timestamp"] = datetime.utcnow()
            
        # Insert the log
        result = _logs_collection.insert_one(log_data)
        
        # Broadcast the new log
        if socketio:
            log_for_emit = log_data.copy()
            log_for_emit["_id"] = str(result.inserted_id)
            
            # Convert datetime to ISO string
            if "timestamp" in log_for_emit and isinstance(log_for_emit["timestamp"], datetime):
                log_for_emit["timestamp"] = log_for_emit["timestamp"].isoformat()
                
            socketio.emit('new_log', log_for_emit)
            
        return str(result.inserted_id)
        
    except Exception as e:
        logger.error(f"Error adding log: {str(e)}")
        return None


def get_recent_logs(limit: int = 100) -> List[Dict]:
    """
    Get the most recent logs (for internal use).
    
    Args:
        limit: Maximum number of logs to return
        
    Returns:
        List[Dict]: List of recent logs
    """
    try:
        logs = []
        cursor = _logs_collection.find().sort("timestamp", DESCENDING).limit(limit)
        
        for log in cursor:
            # Convert ObjectId to string
            log["_id"] = str(log["_id"])
            
            # Convert datetime to ISO string
            if "timestamp" in log and isinstance(log["timestamp"], datetime):
                log["timestamp"] = log["timestamp"].isoformat()
                
            logs.append(log)
            
        return logs
        
    except Exception as e:
        logger.error(f"Error getting recent logs: {str(e)}")
        return []