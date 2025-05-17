import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Union

from bson import ObjectId
from flask import Blueprint, jsonify, request, current_app, g
from flask_socketio import SocketIO
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

from server.modules.auth import token_required, admin_required, operator_required

# Configure logging
logger = logging.getLogger("whitelist_module")

# Initialize Blueprint for API routes
whitelist_bp = Blueprint('whitelist', __name__)

# Will be initialized externally with the Flask-SocketIO instance
socketio: Optional[SocketIO] = None

# MongoDB connection (initialized in init_app)
_db: Optional[Database] = None
_whitelist_collection: Optional[Collection] = None

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO):
    """
    Initialize the whitelist module with the Flask app and MongoDB connection.
    
    Args:
        app: The Flask application instance
        mongo_client: PyMongo MongoClient instance
        socket_io: Flask-SocketIO instance
    """
    global _db, _whitelist_collection, socketio
    
    # Store the SocketIO instance
    socketio = socket_io
    
    # Get the database
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Get the whitelist collection
    _whitelist_collection = _db.whitelist
    
    # Create indexes
    _whitelist_collection.create_index([("domain", 1)], unique=True)
    _whitelist_collection.create_index([("added_date", DESCENDING)])
    _whitelist_collection.create_index([("added_by", 1)])
    
    # Register the blueprint with the app
    app.register_blueprint(whitelist_bp, url_prefix='/api')
    
    # Create default whitelist entries if none exist
    if _whitelist_collection.count_documents({}) == 0:
        _create_default_whitelist()
    
    logger.info("Whitelist module initialized")


# API Routes

@whitelist_bp.route('/whitelist', methods=['GET'])
@token_required
def get_whitelist():
    """
    Retrieve the whitelist with optional filtering.
    
    Query parameters:
    - search: Filter by domain (partial match)
    - since: ISO datetime string to filter entries added after a certain time
    - limit: Maximum number of entries to return (default: 1000)
    - skip: Number of entries to skip (for pagination, default: 0)
    
    Returns:
        JSON with domains array and metadata
    """
    try:
        # Parse query parameters
        search = request.args.get('search', '')
        since_str = request.args.get('since')
        limit = min(int(request.args.get('limit', 1000)), 2000)  # Cap at 2000
        skip = int(request.args.get('skip', 0))
        
        # Build query
        query = {}
        
        if search:
            query["domain"] = {"$regex": search, "$options": "i"}  # Case-insensitive partial match
            
        # Parse time filter
        if since_str:
            try:
                since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
                query["added_date"] = {"$gte": since}
            except ValueError:
                pass
                
        # Execute query
        cursor = _whitelist_collection.find(query)
        
        # Get total count (before pagination)
        total_count = _whitelist_collection.count_documents(query)
        
        # Apply sorting and pagination
        cursor = cursor.sort("domain", 1).skip(skip).limit(limit)
        
        # Convert to list and prepare for JSON serialization
        domains = []
        for entry in cursor:
            # Convert ObjectId to string
            entry["_id"] = str(entry["_id"])
            
            # Convert datetime to ISO string
            if "added_date" in entry and isinstance(entry["added_date"], datetime):
                entry["added_date"] = entry["added_date"].isoformat()
                
            domains.append(entry)
            
        # For simple clients, also provide a flat list of just domains
        simple_domains = [entry["domain"] for entry in domains]
            
        return jsonify({
            "domains": domains,
            "simple_domains": simple_domains,
            "total": total_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving whitelist: {str(e)}")
        return jsonify({"error": "Failed to retrieve whitelist"}), 500


@whitelist_bp.route('/whitelist', methods=['POST'])
@token_required
@operator_required
def add_domain():
    """
    Add a domain to the whitelist.
    
    Request body:
    {
        "domain": "example.com",   # Required
        "notes": "Example domain", # Optional
    }
    
    Returns:
        JSON response with status and domain data
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict) or "domain" not in data:
        return jsonify({"error": "Invalid request format, 'domain' field required"}), 400
        
    # Get domain and clean it
    domain = data.get("domain", "").strip().lower()
    
    # Validate domain
    if not is_valid_domain(domain):
        return jsonify({"error": "Invalid domain format"}), 400
        
    # Check if domain already exists
    if _whitelist_collection.find_one({"domain": domain}):
        return jsonify({"error": "Domain already exists in whitelist"}), 409
        
    # Get user info from auth token
    username = g.user.get('username', 'unknown')
    
    # Prepare entry
    entry = {
        "domain": domain,
        "notes": data.get("notes", ""),
        "added_by": username,
        "added_date": datetime.utcnow()
    }
    
    try:
        # Insert the entry
        result = _whitelist_collection.insert_one(entry)
        
        # Prepare response
        entry["_id"] = str(result.inserted_id)
        entry["added_date"] = entry["added_date"].isoformat()
        
        # Broadcast the update
        if socketio:
            socketio.emit('whitelist_updated', {
                "action": "add",
                "domain": entry["domain"],
                "entry": entry
            })
        
        logger.info(f"Domain {domain} added to whitelist by {username}")
        
        return jsonify({
            "status": "success",
            "message": "Domain added to whitelist",
            "domain": entry
        }), 201
        
    except Exception as e:
        logger.error(f"Error adding domain to whitelist: {str(e)}")
        return jsonify({"error": "Failed to add domain to whitelist"}), 500


@whitelist_bp.route('/whitelist/<domain_id>', methods=['PUT'])
@token_required
@operator_required
def update_domain(domain_id):
    """
    Update a domain entry in the whitelist.
    
    Args:
        domain_id: The ID of the domain entry to update
    
    Request body:
    {
        "notes": "Updated notes",  # Optional
        "domain": "example.com"    # Optional, but must be valid if provided
    }
    
    Returns:
        JSON response with status
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(domain_id)
        except:
            return jsonify({"error": "Invalid domain ID format"}), 400
            
        # Get the current entry
        current = _whitelist_collection.find_one({"_id": object_id})
        if not current:
            return jsonify({"error": "Domain entry not found"}), 404
            
        # Get user info
        username = g.user.get('username', 'unknown')
        
        # Build update query
        update = {}
        
        # Update notes if provided
        if "notes" in data:
            update["notes"] = data["notes"]
            
        # Update domain if provided
        if "domain" in data:
            domain = data["domain"].strip().lower()
            
            # Validate domain
            if not is_valid_domain(domain):
                return jsonify({"error": "Invalid domain format"}), 400
                
            # Check for duplicates (only if actually changing the domain)
            if domain != current["domain"] and _whitelist_collection.find_one({"domain": domain}):
                return jsonify({"error": "Domain already exists in whitelist"}), 409
                
            update["domain"] = domain
            
        # If nothing to update, return success
        if not update:
            return jsonify({"status": "success", "message": "No changes made"}), 200
            
        # Add last update information
        update["last_updated"] = datetime.utcnow()
        update["last_updated_by"] = username
        
        # Update the entry
        result = _whitelist_collection.update_one(
            {"_id": object_id},
            {"$set": update}
        )
        
        if result.modified_count:
            # Get the updated document
            updated = _whitelist_collection.find_one({"_id": object_id})
            
            # Prepare for response
            updated["_id"] = str(updated["_id"])
            if "added_date" in updated and isinstance(updated["added_date"], datetime):
                updated["added_date"] = updated["added_date"].isoformat()
            if "last_updated" in updated and isinstance(updated["last_updated"], datetime):
                updated["last_updated"] = updated["last_updated"].isoformat()
            
            # Broadcast the update
            if socketio:
                socketio.emit('whitelist_updated', {
                    "action": "update",
                    "domain": updated["domain"],
                    "entry": updated
                })
            
            logger.info(f"Domain entry {domain_id} updated by {username}")
            
            return jsonify({
                "status": "success", 
                "message": "Domain entry updated",
                "domain": updated
            }), 200
        else:
            return jsonify({"status": "warning", "message": "No changes made"}), 200
            
    except Exception as e:
        logger.error(f"Error updating domain entry: {str(e)}")
        return jsonify({"error": "Failed to update domain entry"}), 500


@whitelist_bp.route('/whitelist/<domain_id>', methods=['DELETE'])
@token_required
@operator_required
def delete_domain(domain_id):
    """
    Delete a domain from the whitelist.
    
    Args:
        domain_id: The ID of the domain to delete
    
    Returns:
        JSON response with status
    """
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(domain_id)
        except:
            return jsonify({"error": "Invalid domain ID format"}), 400
            
        # Get user info
        username = g.user.get('username', 'unknown')
        
        # Get the domain first (for broadcasting)
        domain_entry = _whitelist_collection.find_one({"_id": object_id})
        if not domain_entry:
            return jsonify({"error": "Domain not found"}), 404
            
        # Delete the domain
        result = _whitelist_collection.delete_one({"_id": object_id})
        
        if result.deleted_count:
            # Broadcast the update
            if socketio:
                socketio.emit('whitelist_updated', {
                    "action": "delete",
                    "domain": domain_entry["domain"],
                    "entry_id": str(object_id)
                })
            
            logger.info(f"Domain {domain_entry['domain']} removed from whitelist by {username}")
            
            return jsonify({
                "status": "success", 
                "message": "Domain removed from whitelist"
            }), 200
        else:
            return jsonify({"status": "error", "message": "Domain not found"}), 404
            
    except Exception as e:
        logger.error(f"Error deleting domain: {str(e)}")
        return jsonify({"error": "Failed to delete domain"}), 500


@whitelist_bp.route('/whitelist/domain/<domain>', methods=['DELETE'])
@token_required
@operator_required
def delete_domain_by_name(domain):
    """
    Delete a domain from the whitelist by its name.
    
    Args:
        domain: The domain name to delete
    
    Returns:
        JSON response with status
    """
    try:
        # Clean and validate domain
        domain = domain.strip().lower()
        
        # Get user info
        username = g.user.get('username', 'unknown')
        
        # Find the domain
        domain_entry = _whitelist_collection.find_one({"domain": domain})
        if not domain_entry:
            return jsonify({"error": "Domain not found in whitelist"}), 404
            
        # Delete the domain
        result = _whitelist_collection.delete_one({"domain": domain})
        
        if result.deleted_count:
            # Broadcast the update
            if socketio:
                socketio.emit('whitelist_updated', {
                    "action": "delete",
                    "domain": domain,
                    "entry_id": str(domain_entry["_id"])
                })
            
            logger.info(f"Domain {domain} removed from whitelist by {username}")
            
            return jsonify({
                "status": "success", 
                "message": "Domain removed from whitelist"
            }), 200
        else:
            return jsonify({"status": "error", "message": "Domain not found"}), 404
            
    except Exception as e:
        logger.error(f"Error deleting domain: {str(e)}")
        return jsonify({"error": "Failed to delete domain"}), 500


@whitelist_bp.route('/whitelist/check/<domain>', methods=['GET'])
def check_domain(domain):
    """
    Check if a domain is in the whitelist.
    This endpoint is public to allow agent verification without authentication.
    
    Args:
        domain: The domain to check
    
    Returns:
        JSON response with result
    """
    try:
        # Clean domain
        domain = domain.strip().lower()
        
        # Direct match
        if _whitelist_collection.find_one({"domain": domain}):
            return jsonify({
                "domain": domain,
                "allowed": True,
                "match_type": "exact"
            }), 200
            
        # Wildcard match (check if *.example.com matches a.example.com)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            wildcard = f"*.{'.'.join(parts[i:])}"
            if _whitelist_collection.find_one({"domain": wildcard}):
                return jsonify({
                    "domain": domain,
                    "allowed": True,
                    "match_type": "wildcard",
                    "wildcard": wildcard
                }), 200
        
        # Not in whitelist
        return jsonify({
            "domain": domain,
            "allowed": False
        }), 200
            
    except Exception as e:
        logger.error(f"Error checking domain: {str(e)}")
        return jsonify({"error": "Failed to check domain"}), 500


@whitelist_bp.route('/whitelist/bulk', methods=['POST'])
@token_required
@operator_required
def bulk_add_domains():
    """
    Add multiple domains to the whitelist in bulk.
    
    Request body:
    {
        "domains": [
            "example.com", 
            "example.org"
        ],
        "notes": "Bulk import"      # Optional, applied to all
    }
    
    Returns:
        JSON response with counts of added and skipped domains
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict) or "domains" not in data or not isinstance(data["domains"], list):
        return jsonify({"error": "Invalid request format, 'domains' array required"}), 400
        
    # Get user info
    username = g.user.get('username', 'unknown')
    
    # Common fields
    notes = data.get("notes", "Bulk import")
    
    try:
        # Process domains
        added = []
        skipped = []
        
        for domain in data["domains"]:
            # Skip if not a string
            if not isinstance(domain, str):
                continue
                
            # Clean and validate
            domain = domain.strip().lower()
            if not is_valid_domain(domain):
                skipped.append({"domain": domain, "reason": "invalid_format"})
                continue
                
            # Check if already exists
            if _whitelist_collection.find_one({"domain": domain}):
                skipped.append({"domain": domain, "reason": "already_exists"})
                continue
                
            # Prepare entry
            entry = {
                "domain": domain,
                "notes": notes,
                "added_by": username,
                "added_date": datetime.utcnow()
            }
            
            # Add to whitelist
            result = _whitelist_collection.insert_one(entry)
            added.append({
                "domain": domain,
                "id": str(result.inserted_id)
            })
        
        # Broadcast the update if we added any domains
        if added and socketio:
            socketio.emit('whitelist_bulk_updated', {
                "action": "bulk_add",
                "count": len(added)
            })
        
        logger.info(f"Bulk import: {len(added)} domains added by {username}")
        
        return jsonify({
            "status": "success",
            "added": len(added),
            "skipped": len(skipped),
            "added_domains": added,
            "skipped_domains": skipped
        }), 201
            
    except Exception as e:
        logger.error(f"Error in bulk domain add: {str(e)}")
        return jsonify({"error": "Failed to process bulk domain addition"}), 500


@whitelist_bp.route('/whitelist/agent-sync', methods=['GET'])
def agent_whitelist_sync():
    """
    Endpoint for agents to sync their whitelist.
    This endpoint is accessible without user authentication but requires a valid agent token.
    
    Query parameters:
    - since: ISO datetime string to filter entries added after a certain time
    - agent_id: Required agent ID for tracking
    - agent_token: Required agent authentication token
    
    Returns:
        JSON with domains array and metadata
    """
    try:
        # Parse query parameters
        since_str = request.args.get('since')
        agent_id = request.args.get('agent_id')
        agent_token = request.args.get('agent_token')
        
        # Validate agent_id and token (basic validation for now, should be enhanced)
        if not agent_id:
            return jsonify({"error": "Agent ID is required"}), 400
        
        # TODO: Implement proper agent authentication
        # For now we'll keep it simple for compatibility
        
        # Build query
        query = {}
        
        # Parse time filter
        if since_str:
            try:
                since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
                query["added_date"] = {"$gte": since}
            except ValueError:
                pass
        
        # Find all domains
        cursor = _whitelist_collection.find(query)
        
        # Get last update time for the entire whitelist
        last_update = _whitelist_collection.find_one(
            {}, 
            sort=[("added_date", DESCENDING)]
        )
        
        last_update_time = None
        if last_update and "added_date" in last_update:
            last_update_time = last_update["added_date"].isoformat()
        
        # Convert to list of domain strings for lightweight response
        domains = []
        for entry in cursor:
            domains.append(entry["domain"])
            
        # Log the sync event
        logger.info(f"Agent {agent_id} synced whitelist. Returned {len(domains)} domains.")
        
        return jsonify({
            "domains": domains,
            "count": len(domains),
            "last_updated": last_update_time
        }), 200
        
    except Exception as e:
        logger.error(f"Error in agent whitelist sync: {str(e)}")
        return jsonify({"error": "Failed to sync whitelist"}), 500


# Helper functions

def is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a properly formatted domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        bool: True if domain format is valid
    """
    if not domain or len(domain) > 253:
        return False
        
    # Allow wildcard domains (e.g., *.example.com)
    if domain.startswith("*."):
        domain = domain[2:]
        
    # Basic domain format validation
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def add_domain_programmatically(domain: str, notes: str = "", added_by: str = "system") -> Optional[str]:
    """
    Add a domain to the whitelist programmatically (for internal use).
    
    Args:
        domain: The domain to add
        notes: Optional notes about this domain
        added_by: Who/what added this domain
        
    Returns:
        str: ID of the inserted domain, or None if insertion failed
    """
    try:
        # Clean and validate domain
        domain = domain.strip().lower()
        if not is_valid_domain(domain):
            logger.error(f"Invalid domain format: {domain}")
            return None
            
        # Check if domain already exists
        if _whitelist_collection.find_one({"domain": domain}):
            logger.debug(f"Domain already exists in whitelist: {domain}")
            return None
            
        # Prepare entry
        entry = {
            "domain": domain,
            "notes": notes,
            "added_by": added_by,
            "added_date": datetime.utcnow()
        }
        
        # Insert the entry
        result = _whitelist_collection.insert_one(entry)
        
        # Broadcast the update
        if socketio:
            entry["_id"] = str(result.inserted_id)
            entry["added_date"] = entry["added_date"].isoformat()
            
            socketio.emit('whitelist_updated', {
                "action": "add",
                "domain": domain,
                "entry": entry
            })
            
        return str(result.inserted_id)
            
    except Exception as e:
        logger.error(f"Error adding domain programmatically: {str(e)}")
        return None


def check_domain_allowed(domain: str) -> bool:
    """
    Check if a domain is allowed according to the whitelist.
    
    Args:
        domain: Domain to check
        
    Returns:
        bool: True if the domain is allowed
    """
    try:
        # Clean domain
        domain = domain.strip().lower()
        
        # Check direct match
        if _whitelist_collection.find_one({"domain": domain}):
            return True
            
        # Check wildcard match
        parts = domain.split('.')
        for i in range(1, len(parts)):
            wildcard = f"*.{'.'.join(parts[i:])}"
            if _whitelist_collection.find_one({"domain": wildcard}):
                return True
                
        # Not in whitelist
        return False
        
    except Exception as e:
        logger.error(f"Error checking if domain is allowed: {str(e)}")
        return False


def get_domain_list() -> List[str]:
    """
    Get a list of all domains in the whitelist (for internal use).
    
    Returns:
        List[str]: List of domain names
    """
    try:
        domains = []
        cursor = _whitelist_collection.find({}, {"domain": 1})
        
        for doc in cursor:
            domains.append(doc["domain"])
            
        return domains
        
    except Exception as e:
        logger.error(f"Error getting domain list: {str(e)}")
        return []


def _create_default_whitelist():
    """Create a default whitelist with common safe domains."""
    default_domains = [
        "google.com", "www.google.com",
        "microsoft.com", "www.microsoft.com",
        "github.com", "www.github.com", 
        "wikipedia.org", "www.wikipedia.org",
        "stackoverflow.com", "www.stackoverflow.com",
        "cloudflare.com", "www.cloudflare.com",
        "apple.com", "www.apple.com",
        "amazon.com", "www.amazon.com",
        "office.com", "www.office.com",
        "live.com", "login.live.com",
        "windows.com", "update.microsoft.com",
        "mozilla.org", "www.mozilla.org",
        "firefox.com", "www.firefox.com",
        "ubuntu.com", "www.ubuntu.com",
        "python.org", "www.python.org",
        "npmjs.com", "www.npmjs.com"
    ]
    
    added_count = 0
    for domain in default_domains:
        entry = {
            "domain": domain,
            "notes": "Default whitelist entry",
            "added_by": "system",
            "added_date": datetime.utcnow()
        }
        
        try:
            _whitelist_collection.insert_one(entry)
            added_count += 1
        except Exception as e:
            logger.error(f"Error adding default domain {domain}: {str(e)}")
    
    logger.info(f"Created default whitelist with {added_count} domains")