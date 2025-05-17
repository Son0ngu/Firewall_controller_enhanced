"""
Authentication module for the Firewall Controller Server.

This module handles user authentication, authorization, and user management.
It provides endpoints for login, logout, token refresh, and user CRUD operations.
"""

import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Union

import bcrypt
import jwt
from bson import ObjectId
from flask import Blueprint, jsonify, request, current_app, g
from flask_socketio import SocketIO
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

from server.models.user_model import User, UserCreate, UserUpdate, UserResponse, UserRole, UserStatus

# Configure logging
logger = logging.getLogger("auth_module")

# Initialize Blueprint for API routes
auth_bp = Blueprint('auth', __name__)
users_bp = Blueprint('users', __name__)

# Will be initialized externally with the Flask-SocketIO instance
socketio: Optional[SocketIO] = None

# MongoDB connection (initialized in init_app)
_db: Optional[Database] = None
_users_collection: Optional[Collection] = None

# JWT settings
_jwt_secret_key: str = ""
_jwt_access_token_expires: int = 3600  # 1 hour
_jwt_refresh_token_expires: int = 2592000  # 30 days

def init_app(app, mongo_client: MongoClient, socket_io: Optional[SocketIO] = None):
    """
    Initialize the authentication module with the Flask app and MongoDB connection.
    
    Args:
        app: The Flask application instance
        mongo_client: PyMongo MongoClient instance
        socket_io: Optional Flask-SocketIO instance
    """
    global _db, _users_collection, socketio, _jwt_secret_key, _jwt_access_token_expires, _jwt_refresh_token_expires
    
    # Store the SocketIO instance if provided
    socketio = socket_io
    
    # Get the database
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Get the users collection
    _users_collection = _db.users
    
    # Create indexes
    _users_collection.create_index([("username", 1)], unique=True)
    _users_collection.create_index([("email", 1)], unique=True)
    _users_collection.create_index([("password_reset_token", 1)])
    
    # Get JWT settings from app config
    _jwt_secret_key = app.config.get('JWT_SECRET_KEY', app.config.get('SECRET_KEY'))
    _jwt_access_token_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
    _jwt_refresh_token_expires = app.config.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000)
    
    # Register the blueprints with the app
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    
    # Create default admin user if none exists
    if _users_collection.count_documents({"role": UserRole.ADMIN}) == 0:
        _create_default_admin(app)
    
    logger.info("Authentication module initialized")


# ======== JWT Token Functions ========

def generate_access_token(user_id: str, role: str) -> str:
    """
    Generate an access token for a user.
    
    Args:
        user_id: The user's ID
        role: The user's role
    
    Returns:
        str: JWT access token
    """
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(seconds=_jwt_access_token_expires)
    }
    return jwt.encode(payload, _jwt_secret_key, algorithm="HS256")


def generate_refresh_token(user_id: str) -> str:
    """
    Generate a refresh token for a user.
    
    Args:
        user_id: The user's ID
    
    Returns:
        str: JWT refresh token
    """
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(seconds=_jwt_refresh_token_expires)
    }
    return jwt.encode(payload, _jwt_secret_key, algorithm="HS256")


def validate_token(token: str) -> Dict:
    """
    Validate a JWT token.
    
    Args:
        token: The JWT token to validate
    
    Returns:
        Dict: Token payload if valid
    
    Raises:
        jwt.InvalidTokenError: If the token is invalid
    """
    return jwt.decode(token, _jwt_secret_key, algorithms=["HS256"])


# ======== Authentication Decorators ========

def token_required(f):
    """
    Decorator to require a valid JWT token for API access.
    Places the authenticated user in g.user
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({"error": "Authentication token is missing"}), 401
        
        try:
            # Validate token
            payload = validate_token(token)
            
            # Check if it's an access token
            if payload.get('type') != 'access':
                return jsonify({"error": "Invalid token type"}), 401
            
            # Get user from database
            user = _users_collection.find_one({"_id": ObjectId(payload['sub'])})
            
            if not user:
                return jsonify({"error": "User not found"}), 401
            
            # Check if user is active
            if user.get("status") != UserStatus.ACTIVE:
                return jsonify({"error": "User account is inactive"}), 403
            
            # Store user in Flask's g object
            g.user = user
            g.user_id = str(user["_id"])
            g.user_role = user.get("role", UserRole.VIEWER)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired", "code": "token_expired"}), 401
        except (jwt.InvalidTokenError, Exception) as e:
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({"error": "Invalid authentication token"}), 401
        
        return f(*args, **kwargs)
    
    return decorated


def admin_required(f):
    """
    Decorator to require admin role.
    Must be used after token_required.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, 'user_role'):
            return jsonify({"error": "Authentication required"}), 401
        
        if g.user_role != UserRole.ADMIN:
            return jsonify({"error": "Admin privileges required"}), 403
        
        return f(*args, **kwargs)
    
    return decorated


def operator_required(f):
    """
    Decorator to require at least operator role.
    Must be used after token_required.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, 'user_role'):
            return jsonify({"error": "Authentication required"}), 401
        
        if g.user_role not in [UserRole.ADMIN, UserRole.OPERATOR]:
            return jsonify({"error": "Operator privileges required"}), 403
        
        return f(*args, **kwargs)
    
    return decorated


# ======== Authentication Routes ========

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login endpoint.
    
    Request body:
    {
        "username": "admin",
        "password": "password"
    }
    
    Returns:
        JSON with access token, refresh token, and user data
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Find user by username
    user = _users_collection.find_one({"username": username})
    
    if not user:
        logger.warning(f"Login attempt with non-existent username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user.get('password_hash', '').encode('utf-8')):
        logger.warning(f"Failed login attempt for user: {username}")
        
        # Increment failed login attempts
        _users_collection.update_one(
            {"_id": user["_id"]},
            {"$inc": {"login_attempts": 1}}
        )
        
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Check if user is active
    if user.get("status") != UserStatus.ACTIVE:
        return jsonify({"error": "Your account is inactive. Please contact an administrator."}), 403
    
    # Generate tokens
    access_token = generate_access_token(str(user["_id"]), user.get("role", UserRole.VIEWER))
    refresh_token = generate_refresh_token(str(user["_id"]))
    
    # Update user's last login time and reset login attempts
    _users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "last_login": datetime.utcnow(),
                "login_attempts": 0
            }
        }
    )
    
    # Prepare user data for response
    user_data = {
        "_id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user.get("role", UserRole.VIEWER)
    }
    
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": _jwt_access_token_expires,
        "user": user_data
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """
    Refresh access token using a refresh token.
    
    Request body:
    {
        "refresh_token": "eyJhbGciOiJIUzI1..."
    }
    
    Returns:
        JSON with new access token
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    refresh_token = request.json.get('refresh_token')
    
    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400
    
    try:
        # Validate refresh token
        payload = validate_token(refresh_token)
        
        # Check if it's a refresh token
        if payload.get('type') != 'refresh':
            return jsonify({"error": "Invalid token type"}), 401
        
        user_id = payload.get('sub')
        
        # Find user
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 401
        
        # Check if user is active
        if user.get("status") != UserStatus.ACTIVE:
            return jsonify({"error": "Your account is inactive"}), 403
        
        # Generate new access token
        access_token = generate_access_token(user_id, user.get("role", UserRole.VIEWER))
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": _jwt_access_token_expires
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token has expired", "code": "token_expired"}), 401
    except (jwt.InvalidTokenError, Exception) as e:
        logger.error(f"Refresh token validation error: {str(e)}")
        return jsonify({"error": "Invalid refresh token"}), 401


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout():
    """
    User logout endpoint.
    
    Note: With JWT, server-side logout is limited. The client should discard tokens.
    This endpoint is mainly for future extensions or stateful tracking.
    
    Returns:
        JSON confirming logout
    """
    # In a stateless JWT system, there's no server-side logout beyond token expiry
    # Future enhancement: could implement a token blocklist/revocation mechanism
    
    return jsonify({"message": "Successfully logged out"}), 200


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """
    Get current user profile.
    
    Returns:
        JSON with user profile data
    """
    user = g.user
    
    # Prepare user profile data
    profile = {
        "_id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user.get("role", UserRole.VIEWER),
        "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
        "preferences": user.get("preferences", {})
    }
    
    return jsonify(profile), 200


@auth_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile():
    """
    Update current user profile.
    
    Request body:
    {
        "full_name": "New Name",
        "email": "new.email@example.com",
        "preferences": { "theme": "dark" }
    }
    
    Returns:
        JSON with updated profile
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    user_id = ObjectId(g.user_id)
    updates = {}
    
    # Fields that can be updated by the user
    if 'full_name' in data:
        updates['full_name'] = data['full_name']
    
    if 'email' in data:
        # Check if email is already taken
        if _users_collection.find_one({"email": data['email'], "_id": {"$ne": user_id}}):
            return jsonify({"error": "Email is already in use"}), 409
        updates['email'] = data['email']
    
    if 'preferences' in data and isinstance(data['preferences'], dict):
        # Merge with existing preferences
        current_prefs = g.user.get('preferences', {})
        current_prefs.update(data['preferences'])
        updates['preferences'] = current_prefs
    
    if updates:
        updates['updated_at'] = datetime.utcnow()
        
        # Update the user
        result = _users_collection.update_one(
            {"_id": user_id},
            {"$set": updates}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Profile update failed"}), 500
        
        # Get updated user data
        user = _users_collection.find_one({"_id": user_id})
        
        # Prepare response
        profile = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "role": user.get("role", UserRole.VIEWER),
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
            "preferences": user.get("preferences", {})
        }
        
        return jsonify(profile), 200
    else:
        return jsonify({"message": "No changes to update"}), 200


@auth_bp.route('/change-password', methods=['POST'])
@token_required
def change_password():
    """
    Change user password.
    
    Request body:
    {
        "current_password": "current-password",
        "new_password": "new-secure-password"
    }
    
    Returns:
        JSON confirming password change
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords required"}), 400
    
    user = g.user
    
    # Verify current password
    if not bcrypt.checkpw(current_password.encode('utf-8'), user.get('password_hash', '').encode('utf-8')):
        return jsonify({"error": "Current password is incorrect"}), 401
    
    # Validate new password strength
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    # Hash new password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Update password in database
    result = _users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password_hash": hashed_password,
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    if result.modified_count == 0:
        return jsonify({"error": "Password update failed"}), 500
    
    return jsonify({"message": "Password changed successfully"}), 200


# ======== User Management Routes (Admin only) ========

@users_bp.route('', methods=['GET'])
@token_required
@admin_required
def list_users():
    """
    List all users. Admin only.
    
    Query parameters:
    - limit: Maximum number of users to return (default: 100)
    - skip: Number of users to skip (default: 0)
    - status: Filter by account status
    - role: Filter by role
    
    Returns:
        JSON with list of users
    """
    # Parse query parameters
    limit = min(int(request.args.get('limit', 100)), 100)
    skip = int(request.args.get('skip', 0))
    status = request.args.get('status')
    role = request.args.get('role')
    
    # Build query
    query = {}
    if status:
        query['status'] = status
    if role:
        query['role'] = role
    
    # Execute query
    users = _users_collection.find(query).sort([("username", 1)]).skip(skip).limit(limit)
    total = _users_collection.count_documents(query)
    
    # Format user data
    result = []
    for user in users:
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "role": user.get("role", UserRole.VIEWER),
            "status": user.get("status", UserStatus.ACTIVE),
            "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None
        }
        result.append(user_data)
    
    return jsonify({
        "total": total,
        "users": result
    }), 200


@users_bp.route('', methods=['POST'])
@token_required
@admin_required
def create_user():
    """
    Create a new user. Admin only.
    
    Request body:
    {
        "username": "newuser",
        "email": "user@example.com",
        "password": "securepassword",
        "full_name": "New User",
        "role": "viewer"
    }
    
    Returns:
        JSON with created user data
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    
    # Validate required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate username
    username = data['username']
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400
    
    # Check if username is taken
    if _users_collection.find_one({"username": username}):
        return jsonify({"error": "Username is already taken"}), 409
    
    # Validate email
    email = data['email']
    
    # Check if email is already registered
    if _users_collection.find_one({"email": email}):
        return jsonify({"error": "Email is already registered"}), 409
    
    # Validate role
    role = data.get('role', UserRole.VIEWER)
    if role not in [r.value for r in UserRole]:
        return jsonify({"error": f"Invalid role: {role}"}), 400
    
    # Validate password
    password = data['password']
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Prepare user document
    new_user = {
        "username": username,
        "email": email,
        "password_hash": hashed_password,
        "full_name": data.get('full_name', ""),
        "role": role,
        "status": UserStatus.ACTIVE,
        "created_at": datetime.utcnow(),
        "login_attempts": 0,
        "preferences": {}
    }
    
    try:
        # Insert user
        result = _users_collection.insert_one(new_user)
        new_user_id = result.inserted_id
        
        # Get created user
        created_user = _users_collection.find_one({"_id": new_user_id})
        
        # Format user data for response
        user_data = {
            "_id": str(created_user["_id"]),
            "username": created_user["username"],
            "email": created_user["email"],
            "full_name": created_user.get("full_name", ""),
            "role": created_user.get("role", UserRole.VIEWER),
            "status": created_user.get("status", UserStatus.ACTIVE),
            "created_at": created_user.get("created_at").isoformat()
        }
        
        return jsonify({
            "message": "User created successfully",
            "user": user_data
        }), 201
    
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500


@users_bp.route('/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    """
    Get user details.
    
    Regular users can only get their own details.
    Admins can get details for any user.
    
    Args:
        user_id: User ID
    
    Returns:
        JSON with user details
    """
    try:
        # Check if user is requesting their own info or is admin
        is_admin = g.user_role == UserRole.ADMIN
        is_self = g.user_id == user_id
        
        if not is_admin and not is_self:
            return jsonify({"error": "Permission denied"}), 403
        
        # Find user
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Format user data
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "role": user.get("role", UserRole.VIEWER),
            "status": user.get("status", UserStatus.ACTIVE),
            "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None
        }
        
        # Additional information for admins
        if is_admin:
            user_data["login_attempts"] = user.get("login_attempts", 0)
        
        return jsonify(user_data), 200
    
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {str(e)}")
        return jsonify({"error": "Failed to retrieve user details"}), 500


@users_bp.route('/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    """
    Update user details.
    
    Regular users can only update their own details and only certain fields.
    Admins can update any user and all fields.
    
    Args:
        user_id: User ID
    
    Request body:
    {
        "email": "new.email@example.com",
        "full_name": "Updated Name",
        "role": "operator",
        "status": "active"
    }
    
    Returns:
        JSON with updated user details
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    
    try:
        # Check if user is updating their own info or is admin
        is_admin = g.user_role == UserRole.ADMIN
        is_self = g.user_id == user_id
        
        if not is_admin and not is_self:
            return jsonify({"error": "Permission denied"}), 403
        
        # Find user
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Prepare updates
        updates = {}
        
        # Fields that regular users can update for themselves
        if 'email' in data:
            # Check if email is already taken
            if _users_collection.find_one({"email": data['email'], "_id": {"$ne": ObjectId(user_id)}}):
                return jsonify({"error": "Email is already in use"}), 409
            updates['email'] = data['email']
        
        if 'full_name' in data:
            updates['full_name'] = data['full_name']
        
        # Admin-only fields
        if is_admin:
            if 'role' in data:
                # Prevent removing the last admin
                if user.get('role') == UserRole.ADMIN and data['role'] != UserRole.ADMIN:
                    admin_count = _users_collection.count_documents({"role": UserRole.ADMIN})
                    if admin_count <= 1:
                        return jsonify({"error": "Cannot remove last administrator"}), 400
                updates['role'] = data['role']
            
            if 'status' in data:
                # Prevent deactivating the last admin
                if user.get('role') == UserRole.ADMIN and data['status'] != UserStatus.ACTIVE:
                    active_admin_count = _users_collection.count_documents({
                        "role": UserRole.ADMIN, 
                        "status": UserStatus.ACTIVE
                    })
                    if active_admin_count <= 1:
                        return jsonify({"error": "Cannot deactivate last administrator"}), 400
                updates['status'] = data['status']
        
        # Apply updates if any
        if updates:
            updates['updated_at'] = datetime.utcnow()
            
            result = _users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": updates}
            )
            
            if result.modified_count == 0:
                return jsonify({"error": "Failed to update user"}), 500
            
            # Get updated user
            updated_user = _users_collection.find_one({"_id": ObjectId(user_id)})
            
            # Format user data for response
            user_data = {
                "_id": str(updated_user["_id"]),
                "username": updated_user["username"],
                "email": updated_user["email"],
                "full_name": updated_user.get("full_name", ""),
                "role": updated_user.get("role", UserRole.VIEWER),
                "status": updated_user.get("status", UserStatus.ACTIVE),
                "updated_at": updates['updated_at'].isoformat()
            }
            
            return jsonify({
                "message": "User updated successfully",
                "user": user_data
            }), 200
        
        else:
            return jsonify({"message": "No changes to update"}), 200
    
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {str(e)}")
        return jsonify({"error": "Failed to update user"}), 500


@users_bp.route('/<user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    """
    Delete a user. Admin only.
    
    Args:
        user_id: User ID to delete
    
    Returns:
        JSON confirming deletion
    """
    try:
        # Check if trying to delete self
        if g.user_id == user_id:
            return jsonify({"error": "Cannot delete your own account"}), 400
        
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Prevent deleting the last admin
        if user.get('role') == UserRole.ADMIN:
            admin_count = _users_collection.count_documents({"role": UserRole.ADMIN})
            if admin_count <= 1:
                return jsonify({"error": "Cannot delete the last administrator"}), 400
        
        # Delete user
        result = _users_collection.delete_one({"_id": ObjectId(user_id)})
        
        if result.deleted_count == 0:
            return jsonify({"error": "Failed to delete user"}), 500
        
        return jsonify({"message": "User deleted successfully"}), 200
    
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({"error": "Failed to delete user"}), 500


@users_bp.route('/<user_id>/reset-password', methods=['POST'])
@token_required
@admin_required
def reset_user_password(user_id):
    """
    Reset a user's password. Admin only.
    
    Args:
        user_id: User ID
    
    Request body:
    {
        "new_password": "new-secure-password"  # Optional, auto-generated if not provided
    }
    
    Returns:
        JSON with new password (if auto-generated) or confirmation
    """
    try:
        # Find user
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        data = request.json or {}
        new_password = data.get('new_password')
        
        # Generate a random password if none provided
        if not new_password:
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits
            new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
            password_was_generated = True
        else:
            # Validate provided password
            if len(new_password) < 8:
                return jsonify({"error": "Password must be at least 8 characters long"}), 400
            password_was_generated = False
        
        # Hash new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password in database
        result = _users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "password_hash": hashed_password,
                    "updated_at": datetime.utcnow(),
                    "login_attempts": 0
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to reset password"}), 500
        
        if password_was_generated:
            return jsonify({
                "message": "Password reset successfully",
                "generated_password": new_password
            }), 200
        else:
            return jsonify({"message": "Password reset successfully"}), 200
    
    except Exception as e:
        logger.error(f"Error resetting password for user {user_id}: {str(e)}")
        return jsonify({"error": "Failed to reset password"}), 500


# ======== Helper Functions ========

def _create_default_admin(app):
    """
    Create a default admin user if none exists.
    
    Args:
        app: Flask application with config
    """
    default_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
    default_password = app.config.get('DEFAULT_ADMIN_PASSWORD')
    default_email = app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    
    # Generate a random password if none is provided
    if not default_password:
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        default_password = ''.join(secrets.choice(alphabet) for _ in range(12))
    
    # Hash the password
    hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Create admin user
    admin_user = {
        "username": default_username,
        "email": default_email,
        "password_hash": hashed_password,
        "full_name": "System Administrator",
        "role": UserRole.ADMIN,
        "status": UserStatus.ACTIVE,
        "created_at": datetime.utcnow(),
        "login_attempts": 0
    }
    
    try:
        _users_collection.insert_one(admin_user)
        logger.info(f"Created default admin user: {default_username}")
        logger.info(f"Default admin password: {default_password}")
    except Exception as e:
        logger.error(f"Error creating default admin: {str(e)}")