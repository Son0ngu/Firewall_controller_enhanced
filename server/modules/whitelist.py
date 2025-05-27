"""
Whitelist Management module with support for domains, IPs, URLs, and patterns.
"""

import logging
import re
import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlparse

from bson import ObjectId
from flask import Blueprint, jsonify, request
from flask_socketio import SocketIO
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

logger = logging.getLogger("whitelist_module")
whitelist_bp = Blueprint('whitelist', __name__)

# Global variables
socketio: Optional[SocketIO] = None
_db: Optional[Database] = None
_whitelist_collection: Optional[Collection] = None

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO = None):
    """Initialize whitelist module."""
    global _db, _whitelist_collection, socketio
    
    socketio = socket_io
    db_name = app.config.get('MONGO_DBNAME', 'Monitoring')
    _db = mongo_client[db_name]
    _whitelist_collection = _db.whitelist
    
    # Clean up invalid documents before creating indexes
    try:
        # Remove documents with null or empty values
        cleanup_result = _whitelist_collection.delete_many({
            "$or": [
                {"value": None},
                {"value": ""},
                {"value": {"$exists": False}}
            ]
        })
        if cleanup_result.deleted_count > 0:
            logger.info(f"Cleaned up {cleanup_result.deleted_count} invalid whitelist documents")
    except Exception as e:
        logger.warning(f"Error cleaning up invalid documents: {e}")
    
    # Create indexes with error handling
    try:
        # Drop existing problematic index if it exists
        try:
            _whitelist_collection.drop_index("value_1")
            logger.info("Dropped existing value index")
        except Exception:
            pass  # Index might not exist
        
        # ✅ SỬA: Sử dụng sparse index thay vì partial filter
        _whitelist_collection.create_index(
            [("value", 1)], 
            unique=True,
            sparse=True  # Sparse index tự động loại trừ null/missing values
        )
        logger.info("Created unique sparse index on value field")
        
        # Create other indexes
        _whitelist_collection.create_index([("type", 1)])
        _whitelist_collection.create_index([("category", 1)])
        _whitelist_collection.create_index([("priority", DESCENDING)])
        _whitelist_collection.create_index([("added_date", DESCENDING)])
        _whitelist_collection.create_index([("expiry_date", 1)], sparse=True)
        
        logger.info("All whitelist indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")
        # Continue without indexes if creation fails
        logger.warning("Continuing without indexes - performance may be affected")
    
    app.register_blueprint(whitelist_bp, url_prefix='/api/whitelist')
    logger.info("Whitelist module initialized")

@whitelist_bp.route('', methods=['GET'])
def list_whitelist():
    """Get all whitelist entries."""
    try:
        query = {}
        
        # Filter by type
        entry_type = request.args.get('type')
        if entry_type:
            query["type"] = entry_type
            
        # Filter by category
        category = request.args.get('category')
        if category:
            query["category"] = category
            
        # Search
        search = request.args.get('search')
        if search:
            query["$or"] = [
                {"value": {"$regex": search, "$options": "i"}},
                {"notes": {"$regex": search, "$options": "i"}}
            ]
        
        # Clean up expired entries
        cleanup_expired_entries()
        
        cursor = _whitelist_collection.find(query).sort([
            ("priority", DESCENDING),
            ("added_date", DESCENDING)
        ])
        
        entries = []
        for entry in cursor:
            entry_data = {
                "id": str(entry["_id"]),
                "type": entry.get("type", "domain"),
                "value": entry.get("value"),
                "domain": entry.get("value"),  # Backwards compatibility
                "category": entry.get("category"),
                "notes": entry.get("notes"),
                "priority": entry.get("priority", "normal"),
                "added_by": entry.get("added_by"),
                "added_date": entry.get("added_date").isoformat() if entry.get("added_date") else None,
                "expiry_date": entry.get("expiry_date").isoformat() if entry.get("expiry_date") else None,
                "max_requests_per_hour": entry.get("max_requests_per_hour"),
                "enable_logging": entry.get("enable_logging", False),
                "is_temporary": entry.get("is_temporary", False),
                "dns_config": entry.get("dns_config"),
                "usage_count": entry.get("usage_count", 0),
                "last_used": entry.get("last_used").isoformat() if entry.get("last_used") else None
            }
            entries.append(entry_data)
            
        return jsonify({"domains": entries}), 200  # Keep "domains" for backwards compatibility
        
    except Exception as e:
        logger.error(f"Error listing whitelist: {str(e)}")
        return jsonify({"error": "Failed to list whitelist"}), 500

@whitelist_bp.route('', methods=['POST'])
def add_entry():
    """Add new entry to whitelist."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    entry_type = data.get("type", "domain")
    value = data.get("value", "").strip().lower()
    
    if not value:
        return jsonify({"error": "Value is required"}), 400
    
    # Validate based on type
    validation_result = validate_entry(entry_type, value)
    if not validation_result["valid"]:
        return jsonify({"error": validation_result["message"]}), 400
    
    try:
        current_time = datetime.utcnow()
        client_ip = request.remote_addr
        
        # Check for duplicates before inserting
        existing = _whitelist_collection.find_one({"value": value})
        if existing:
            return jsonify({"error": "Entry already exists"}), 409
        
        # Prepare entry data
        entry_data = {
            "type": entry_type,
            "value": value,
            "category": data.get("category", "uncategorized"),
            "notes": data.get("notes"),
            "priority": data.get("priority", "normal"),
            "added_by": client_ip,
            "added_date": current_time,
            "enable_logging": data.get("enable_logging", False),
            "is_temporary": data.get("is_temporary", False),
            "usage_count": 0
        }
        
        # Add expiry date
        if data.get("expiry_date"):
            try:
                entry_data["expiry_date"] = datetime.fromisoformat(data["expiry_date"])
            except ValueError:
                return jsonify({"error": "Invalid expiry date format"}), 400
        elif data.get("is_temporary"):
            entry_data["expiry_date"] = current_time + timedelta(hours=24)
            
        # Add rate limiting
        if data.get("max_requests_per_hour"):
            entry_data["max_requests_per_hour"] = int(data["max_requests_per_hour"])
            
        # Add DNS config for domains
        if entry_type == "domain" and data.get("dns_config"):
            dns_config = data["dns_config"]
            if dns_config.get("verify"):
                dns_result = verify_dns(value, dns_config.get("server"))
                if not dns_result["valid"]:
                    return jsonify({"error": f"DNS verification failed: {dns_result['message']}"}), 400
                entry_data["dns_info"] = dns_result["info"]
            entry_data["dns_config"] = dns_config
            
        # Insert entry with duplicate key handling
        try:
            result = _whitelist_collection.insert_one(entry_data)
        except Exception as insert_error:
            if "duplicate key" in str(insert_error).lower():
                return jsonify({"error": "Entry already exists"}), 409
            raise
        
        # Broadcast notification
        if socketio:
            socketio.emit("whitelist_added", {
                "type": entry_type,
                "value": value,
                "category": entry_data["category"],
                "added_by": client_ip,
                "timestamp": current_time.isoformat()
            })
            
        logger.info(f"Added {entry_type} entry: {value} by {client_ip}")
        
        return jsonify({
            "id": str(result.inserted_id),
            "message": f"{entry_type.capitalize()} added to whitelist"
        }), 201
        
    except Exception as e:
        logger.error(f"Error adding entry: {str(e)}")
        return jsonify({"error": "Failed to add entry"}), 500

@whitelist_bp.route('/test', methods=['POST'])
def test_entry():
    """Test an entry before adding it."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    entry_type = data.get("type")
    value = data.get("value", "").strip()
    
    if not entry_type or not value:
        return jsonify({"error": "Type and value are required"}), 400
    
    try:
        # Validate entry
        validation_result = validate_entry(entry_type, value)
        if not validation_result["valid"]:
            return jsonify({"error": validation_result["message"]}), 400
        
        result = {"valid": True, "type": entry_type, "value": value}
        
        # DNS verification for domains
        if entry_type == "domain" and data.get("dns_verify"):
            dns_result = verify_dns(value)
            result["dns_info"] = dns_result.get("info", [])
            result["dns_valid"] = dns_result["valid"]
            
        # Reachability test for IPs and URLs
        if entry_type in ["ip", "url"]:
            reachable = test_reachability(entry_type, value)
            result["reachable"] = reachable
            
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error testing entry: {str(e)}")
        return jsonify({"error": "Test failed"}), 500

@whitelist_bp.route('/dns-test', methods=['POST'])
def dns_test():
    """Test DNS resolution for a domain."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    domain = data.get("domain", "").strip()
    
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    try:
        result = verify_dns(domain)
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error testing DNS: {str(e)}")
        return jsonify({"error": "DNS test failed"}), 500

@whitelist_bp.route('/agent-sync', methods=['GET'])
def agent_sync():
    """Sync whitelist for agents - returns only active domains."""
    try:
        # Get query parameters
        since = request.args.get('since')  # ISO datetime string
        agent_id = request.args.get('agent_id')  # Optional agent identification
        
        query = {}  # No restriction to is_active since we don't have that field yet
        
        # If 'since' parameter provided, return incremental update
        if since:
            try:
                since_date = datetime.fromisoformat(since)
                query["$or"] = [
                    {"added_date": {"$gte": since_date}},
                    {"last_updated": {"$gte": since_date}}
                ]
            except ValueError:
                logger.warning(f"Invalid 'since' parameter: {since}")
        
        # Clean up expired entries first
        cleanup_expired_entries()
        
        cursor = _whitelist_collection.find(query)
        
        # Extract domain values only (for agent efficiency)
        domains = []
        for entry in cursor:
            value = entry.get("value") or entry.get("domain")  # Support both fields
            if value:
                domains.append(value)
        
        # Log the sync request
        logger.info(f"Agent sync request - returned {len(domains)} domains"
                   f"{' (incremental)' if since else ' (full)'}"
                   f"{' for agent: ' + agent_id if agent_id else ''}")
        
        return jsonify({
            "domains": domains,
            "timestamp": datetime.utcnow().isoformat(),
            "count": len(domains),
            "type": "incremental" if since else "full"
        }), 200
        
    except Exception as e:
        logger.error(f"Error in agent sync: {str(e)}")
        return jsonify({"error": "Sync failed", "domains": []}), 500

# Helper Functions

def validate_entry(entry_type: str, value: str) -> Dict:
    """Validate entry based on type."""
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
            # Additional pattern validation could be added here
            
        return {"valid": True, "message": "Valid"}
        
    except Exception as e:
        return {"valid": False, "message": f"Validation error: {str(e)}"}

def verify_dns(domain: str, dns_server: str = None) -> Dict:
    """Verify DNS resolution for a domain."""
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

def test_reachability(entry_type: str, value: str) -> bool:
    """Test if an IP or URL is reachable."""
    try:
        if entry_type == "ip":
            # Extract IP from value
            ip_part = value.split(':')[0]
            host = ipaddress.ip_address(ip_part)
            # Simple ping-like test (you might want to implement actual ping)
            socket.create_connection((str(host), 80), timeout=5)
            return True
        elif entry_type == "url":
            # You could use requests library here for HTTP testing
            # For now, just return True
            return True
    except Exception:
        return False
    
    return False

def cleanup_expired_entries():
    """Remove expired entries from whitelist."""
    try:
        current_time = datetime.utcnow()
        result = _whitelist_collection.delete_many({
            "expiry_date": {"$lt": current_time}
        })
        
        if result.deleted_count > 0:
            logger.info(f"Cleaned up {result.deleted_count} expired entries")
            
    except Exception as e:
        logger.error(f"Error cleaning up expired entries: {str(e)}")