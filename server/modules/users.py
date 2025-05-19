"""
User management module for the Firewall Controller Server.

This module provides API endpoints for user authentication and management,
including user registration, login, profile management, and role-based access control.
"""

import logging
import secrets
import string
import re
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
logger = logging.getLogger("users_module")

# Initialize Blueprint for API routes
users_bp = Blueprint('users', __name__)
auth_bp = Blueprint('auth', __name__)

# Will be initialized externally with the Flask-SocketIO instance
socketio: Optional[SocketIO] = None

# MongoDB connection (initialized in init_app)
_db: Optional[Database] = None
_users_collection: Optional[Collection] = None

# JWT settings
_jwt_secret_key: str = ""
_jwt_access_token_expires: int = 3600  # 1 hour
_jwt_refresh_token_expires: int = 2592000  # 30 days


def init_app(app, mongo_client: MongoClient, socket_io: SocketIO):
    """
    Initialize the users module with the Flask app and MongoDB connection.
    
    Args:
        app: The Flask application instance
        mongo_client: PyMongo MongoClient instance
        socket_io: Flask-SocketIO instance
    """
    global _db, _users_collection, socketio, _jwt_secret_key, _jwt_access_token_expires, _jwt_refresh_token_expires
    
    # Store the SocketIO instance
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
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
    # Create default admin user if none exists
    if _users_collection.count_documents({"role": "admin"}) == 0:
        _create_default_admin(app)
    
    logger.info("Users module initialized")


# ======== Authentication Decorators ========

def login_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        
        try:
            # Decode the token
            payload = jwt.decode(token, _jwt_secret_key, algorithms=["HS256"])
            
            # Get user from database
            user = _users_collection.find_one({"_id": ObjectId(payload["sub"])})
            
            if not user:
                return jsonify({"error": "User not found"}), 401
                
            if user.get("status") != "active":
                return jsonify({"error": "Account is not active"}), 403
            
            # Store user in flask g object
            g.user = user
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except (jwt.InvalidTokenError, Exception) as e:
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({"error": "Invalid token"}), 401
            
        return f(*args, **kwargs)
    
    return decorated_function


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is authenticated
        if not hasattr(g, 'user'):
            return jsonify({"error": "Authentication required"}), 401
            
        # Check if user is admin
        if g.user.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
            
        return f(*args, **kwargs)
    
    return decorated_function


# ======== Authentication Routes ========

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login endpoint.
    
    Request body:
    {
        "username": "admin",
        "password": "securepassword"
    }
    
    Returns:
        JSON with access token and user data
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    try:
        # Find user by username
        user = _users_collection.find_one({"username": username})
        
        if not user:
            # Use same response to prevent username enumeration
            return jsonify({"error": "Invalid username or password"}), 401
            
        # Check if account is active
        if user.get("status") != "active":
            return jsonify({"error": "Account is not active"}), 403
            
        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), user.get("password_hash").encode('utf-8')):
            # Increment login attempts
            _users_collection.update_one(
                {"_id": user["_id"]},
                {"$inc": {"login_attempts": 1}}
            )
            return jsonify({"error": "Invalid username or password"}), 401
            
        # Reset login attempts and update last login
        _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "last_login": datetime.utcnow(),
                    "login_attempts": 0
                }
            }
        )
        
        # Generate tokens
        access_token = _generate_token(
            str(user["_id"]), 
            user.get("role", "viewer"),
            _jwt_access_token_expires
        )
        
        refresh_token = _generate_token(
            str(user["_id"]), 
            user.get("role", "viewer"),
            _jwt_refresh_token_expires,
            is_refresh=True
        )
        
        # Prepare user data for response (exclude sensitive fields)
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name"),
            "role": user.get("role", "viewer"),
            "preferences": user.get("preferences", {})
        }
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": _jwt_access_token_expires,
            "user": user_data
        }), 200
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "An error occurred during login"}), 500


@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    Refresh access token using refresh token.
    
    Request body:
    {
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    
    Returns:
        JSON with new access token
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    refresh_token = data.get("refresh_token")
    
    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400
        
    try:
        # Decode and validate refresh token
        payload = jwt.decode(refresh_token, _jwt_secret_key, algorithms=["HS256"])
        
        # Check if it's actually a refresh token
        if not payload.get("refresh"):
            return jsonify({"error": "Invalid refresh token"}), 401
            
        # Get user from database
        user = _users_collection.find_one({"_id": ObjectId(payload["sub"])})
        
        if not user:
            return jsonify({"error": "User not found"}), 401
            
        if user.get("status") != "active":
            return jsonify({"error": "Account is not active"}), 403
            
        # Generate new access token
        access_token = _generate_token(
            str(user["_id"]), 
            user.get("role", "viewer"),
            _jwt_access_token_expires
        )
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": _jwt_access_token_expires
        }), 200
            
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token has expired"}), 401
    except (jwt.InvalidTokenError, Exception) as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({"error": "Invalid refresh token"}), 401


@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """
    Get current user profile.
    
    Returns:
        JSON with user data
    """
    try:
        user = g.user
        
        # Prepare user data for response (exclude sensitive fields)
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name"),
            "role": user.get("role", "viewer"),
            "status": user.get("status", "active"),
            "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
            "preferences": user.get("preferences", {})
        }
        
        return jsonify(user_data), 200
            
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """
    Update current user profile.
    
    Request body:
    {
        "email": "new.email@example.com",  # Optional
        "full_name": "New Name",           # Optional
        "preferences": {                   # Optional
            "theme": "dark"
        }
    }
    
    Returns:
        JSON with updated user data
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        user = g.user
        user_id = user["_id"]
        
        # Build update dictionary
        update = {}
        
        # Email update
        if "email" in data and data["email"] != user.get("email"):
            # Check if email is already taken
            if _users_collection.find_one({"email": data["email"], "_id": {"$ne": user_id}}):
                return jsonify({"error": "Email is already in use"}), 409
                
            update["email"] = data["email"]
            
        # Full name update
        if "full_name" in data:
            update["full_name"] = data["full_name"]
            
        # Preferences update
        if "preferences" in data and isinstance(data["preferences"], dict):
            # Merge with existing preferences
            preferences = user.get("preferences", {})
            preferences.update(data["preferences"])
            update["preferences"] = preferences
            
        # If nothing to update
        if not update:
            return jsonify({"message": "No changes to update"}), 200
            
        # Add updated_at timestamp
        update["updated_at"] = datetime.utcnow()
        
        # Update the user
        result = _users_collection.update_one(
            {"_id": user_id},
            {"$set": update}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update profile"}), 500
            
        # Get updated user
        updated_user = _users_collection.find_one({"_id": user_id})
        
        # Prepare user data for response
        user_data = {
            "_id": str(updated_user["_id"]),
            "username": updated_user["username"],
            "email": updated_user["email"],
            "full_name": updated_user.get("full_name"),
            "role": updated_user.get("role", "viewer"),
            "preferences": updated_user.get("preferences", {})
        }
        
        return jsonify({
            "message": "Profile updated successfully",
            "user": user_data
        }), 200
            
    except Exception as e:
        logger.error(f"Update profile error: {str(e)}")
        return jsonify({"error": "Failed to update profile"}), 500


@auth_bp.route('/change-password', methods=['PUT'])
@login_required
def change_password():
    """
    Change user password.
    
    Request body:
    {
        "current_password": "oldpassword",
        "new_password": "newStrongPwd123"
    }
    
    Returns:
        JSON with status message
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({"error": "Both current and new password are required"}), 400
        
    # Validate password strength
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not any(c.isupper() for c in new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not any(c.islower() for c in new_password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    
    try:
        user = g.user
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user.get("password_hash").encode('utf-8')):
            return jsonify({"error": "Current password is incorrect"}), 401
            
        # Hash new password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        result = _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_hash": password_hash,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update password"}), 500
            
        return jsonify({"message": "Password changed successfully"}), 200
            
    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        return jsonify({"error": "Failed to change password"}), 500


@auth_bp.route('/reset-password', methods=['POST'])
def request_password_reset():
    """
    Request password reset link.
    
    Request body:
    {
        "email": "user@example.com"
    }
    
    Returns:
        JSON with status message
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    email = data.get("email")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
        
    try:
        # Find user by email
        user = _users_collection.find_one({"email": email})
        
        # Always return success even if user not found (to prevent email enumeration)
        if not user:
            logger.info(f"Password reset requested for non-existent email: {email}")
            return jsonify({"message": "If the email exists, a reset link will be sent"}), 200
            
        # Generate reset token
        token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        expiration = datetime.utcnow() + timedelta(hours=1)
        
        # Store token and expiration in user document
        _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_reset_token": token,
                    "password_reset_expires": expiration
                }
            }
        )
        
        # In a real application, you would send an email with the reset link
        # For this example, we'll just log it
        reset_url = f"{request.host_url.rstrip('/')}/reset-password/{token}"
        logger.info(f"Password reset link for {email}: {reset_url}")
        
        return jsonify({
            "message": "If the email exists, a reset link will be sent", 
            "debug_token": token  # Remove in production
        }), 200
            
    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}")
        return jsonify({"error": "Failed to process password reset request"}), 500


@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    """
    Reset password with token.
    
    Args:
        token: The password reset token
    
    Request body:
    {
        "password": "newStrongPwd123"
    }
    
    Returns:
        JSON with status message
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    new_password = data.get("password")
    
    if not new_password:
        return jsonify({"error": "New password is required"}), 400
        
    # Validate password strength
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not any(c.isupper() for c in new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not any(c.islower() for c in new_password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    
    try:
        # Find user with the token
        user = _users_collection.find_one({
            "password_reset_token": token,
            "password_reset_expires": {"$gt": datetime.utcnow()}
        })
        
        if not user:
            return jsonify({"error": "Invalid or expired reset token"}), 400
            
        # Hash new password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password and clear reset token
        result = _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_hash": password_hash,
                    "updated_at": datetime.utcnow(),
                    "status": "active"  # Activate account if it was pending
                },
                "$unset": {
                    "password_reset_token": "",
                    "password_reset_expires": ""
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to reset password"}), 500
            
        return jsonify({"message": "Password has been reset successfully"}), 200
            
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({"error": "Failed to reset password"}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    User logout endpoint.
    
    Note: Since JWT is stateless, this endpoint is mostly for client-side purposes.
    The client should discard the token on logout.
    
    Returns:
        JSON with status message
    """
    # In a stateful auth system, we would invalidate the token here
    # For JWT, the client just needs to remove the token
    
    return jsonify({"message": "Successfully logged out"}), 200


# ======== API Key Routes ========

@auth_bp.route('/api-keys', methods=['GET'])
@login_required
def list_api_keys():
    """
    List API keys for the current user.
    
    Returns:
        JSON with list of API keys
    """
    try:
        user = g.user
        
        # Extract API keys (don't include the actual keys for security)
        api_keys = []
        for key in user.get("api_keys", []):
            api_keys.append({
                "id": key.get("id"),
                "name": key.get("name"),
                "created_at": key.get("created_at").isoformat() if key.get("created_at") else None,
                "last_used": key.get("last_used").isoformat() if key.get("last_used") else None
            })
            
        return jsonify({"api_keys": api_keys}), 200
            
    except Exception as e:
        logger.error(f"List API keys error: {str(e)}")
        return jsonify({"error": "Failed to list API keys"}), 500


@auth_bp.route('/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """
    Create a new API key for the current user.
    
    Request body:
    {
        "name": "My API Key"  # Optional
    }
    
    Returns:
        JSON with the new API key
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    key_name = data.get("name", "API Key")
    
    try:
        user = g.user
        
        # Generate API key
        api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        key_id = str(ObjectId())
        
        # Add API key to user
        new_key = {
            "id": key_id,
            "name": key_name,
            "key_hash": bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            "created_at": datetime.utcnow(),
            "last_used": None
        }
        
        result = _users_collection.update_one(
            {"_id": user["_id"]},
            {"$push": {"api_keys": new_key}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to create API key"}), 500
            
        # Return the key (only shown once)
        return jsonify({
            "message": "API key created successfully",
            "api_key": {
                "id": key_id,
                "name": key_name,
                "key": api_key,  # Only returned once
                "created_at": new_key["created_at"].isoformat()
            }
        }), 201
            
    except Exception as e:
        logger.error(f"Create API key error: {str(e)}")
        return jsonify({"error": "Failed to create API key"}), 500


@auth_bp.route('/api-keys/<key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """
    Delete an API key.
    
    Args:
        key_id: The ID of the API key to delete
        
    Returns:
        JSON with status message
    """
    try:
        user = g.user
        
        # Remove API key from user
        result = _users_collection.update_one(
            {"_id": user["_id"]},
            {"$pull": {"api_keys": {"id": key_id}}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "API key not found"}), 404
            
        return jsonify({"message": "API key deleted successfully"}), 200
            
    except Exception as e:
        logger.error(f"Delete API key error: {str(e)}")
        return jsonify({"error": "Failed to delete API key"}), 500


# ======== User Management Routes (Admin Only) ========

@users_bp.route('', methods=['GET'])
@login_required
@admin_required
def get_users():
    """
    Get all users (admin only).
    
    Query parameters:
    - limit: Maximum number of users to return
    - skip: Number of users to skip
    - role: Filter by role
    - status: Filter by status
    
    Returns:
        JSON with list of users
    """
    try:
        # Parse query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)
        skip = int(request.args.get('skip', 0))
        role = request.args.get('role')
        status = request.args.get('status')
        
        # Build query
        query = {}
        if role:
            query["role"] = role
        if status:
            query["status"] = status
            
        # Execute query
        cursor = _users_collection.find(query)
        
        # Get total count
        total_count = _users_collection.count_documents(query)
        
        # Apply pagination
        cursor = cursor.skip(skip).limit(limit)
        
        # Convert to list and prepare for JSON response
        users = []
        for user in cursor:
            # Exclude sensitive fields
            user_data = {
                "_id": str(user["_id"]),
                "username": user["username"],
                "email": user["email"],
                "full_name": user.get("full_name"),
                "role": user.get("role", "viewer"),
                "status": user.get("status", "active"),
                "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
                "last_login": user.get("last_login").isoformat() if user.get("last_login") else None
            }
            users.append(user_data)
            
        return jsonify({
            "users": users,
            "total": total_count
        }), 200
            
    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        return jsonify({"error": "Failed to retrieve users"}), 500


@users_bp.route('', methods=['POST'])
@login_required
@admin_required
def create_user():
    """
    Create a new user (admin only).
    
    Request body:
    {
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "StrongPwd123",
        "full_name": "New User",
        "role": "viewer",
        "status": "active"
    }
    
    Returns:
        JSON with the created user
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Validate required fields
        required_fields = ["username", "email", "password"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
                
        # Validate username
        username = data["username"]
        if not username or len(username) < 3 or len(username) > 50:
            return jsonify({"error": "Username must be between 3 and 50 characters"}), 400
            
        if not _is_valid_username(username):
            return jsonify({"error": "Username must contain only alphanumeric characters, underscores, or hyphens"}), 400
            
        # Check if username is taken
        if _users_collection.find_one({"username": username}):
            return jsonify({"error": "Username is already taken"}), 409
            
        # Validate email
        email = data["email"]
        if not email or "@" not in email:
            return jsonify({"error": "Invalid email address"}), 400
            
        # Check if email is taken
        if _users_collection.find_one({"email": email}):
            return jsonify({"error": "Email is already registered"}), 409
            
        # Validate password
        password = data["password"]
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if not any(c.isupper() for c in password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.islower() for c in password):
            return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
        if not any(c.isdigit() for c in password):
            return jsonify({"error": "Password must contain at least one digit"}), 400
            
        # Validate role
        role = data.get("role", "viewer")
        if role not in ["admin", "operator", "viewer"]:
            return jsonify({"error": "Invalid role"}), 400
            
        # Validate status
        status = data.get("status", "active")
        if status not in ["active", "inactive", "pending"]:
            return jsonify({"error": "Invalid status"}), 400
            
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Prepare user document
        new_user = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "full_name": data.get("full_name"),
            "role": role,
            "status": status,
            "created_at": datetime.utcnow(),
            "api_keys": [],
            "preferences": data.get("preferences", {})
        }
        
        # Insert user
        result = _users_collection.insert_one(new_user)
        
        # Get the inserted user
        user = _users_collection.find_one({"_id": result.inserted_id})
        
        # Prepare response
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name"),
            "role": user.get("role"),
            "status": user.get("status"),
            "created_at": user.get("created_at").isoformat()
        }
        
        return jsonify({
            "message": "User created successfully",
            "user": user_data
        }), 201
            
    except Exception as e:
        logger.error(f"Create user error: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500


@users_bp.route('/<user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """
    Get a specific user.
    
    Args:
        user_id: The ID of the user to retrieve
        
    Returns:
        JSON with user data
    """
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Get user
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Check permissions - admins can see all users, others only themselves
        current_user = g.user
        if str(current_user["_id"]) != user_id and current_user.get("role") != "admin":
            return jsonify({"error": "Permission denied"}), 403
            
        # Prepare response
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name"),
            "role": user.get("role", "viewer"),
            "status": user.get("status", "active"),
            "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
            "api_key_count": len(user.get("api_keys", [])),
            "preferences": user.get("preferences", {})
        }
        
        # Add sensitive data for admins
        if current_user.get("role") == "admin":
            user_data["login_attempts"] = user.get("login_attempts", 0)
            
        return jsonify(user_data), 200
            
    except Exception as e:
        logger.error(f"Get user error: {str(e)}")
        return jsonify({"error": "Failed to retrieve user"}), 500


@users_bp.route('/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """
    Update a user.
    
    Args:
        user_id: The ID of the user to update
        
    Request body:
    {
        "email": "updated@example.com",
        "full_name": "Updated Name",
        "role": "operator",
        "status": "active",
        "preferences": { ... }
    }
    
    Returns:
        JSON with updated user data
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Get user to update
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Check permissions - admins can update all users, others only themselves
        current_user = g.user
        is_admin = current_user.get("role") == "admin"
        is_self = str(current_user["_id"]) == user_id
        
        if not is_admin and not is_self:
            return jsonify({"error": "Permission denied"}), 403
            
        # Role changes are admin-only
        if "role" in data and not is_admin:
            return jsonify({"error": "Only administrators can change roles"}), 403
            
        # Status changes are admin-only
        if "status" in data and not is_admin:
            return jsonify({"error": "Only administrators can change account status"}), 403
            
        # Admins cannot downgrade their own role to prevent lockout
        if is_self and is_admin and data.get("role") != "admin":
            return jsonify({"error": "Administrators cannot downgrade their own role"}), 403
            
        # Build update dictionary
        update = {}
        
        # Email update
        if "email" in data and data["email"] != user.get("email"):
            # Check if email is already taken
            if _users_collection.find_one({"email": data["email"], "_id": {"$ne": object_id}}):
                return jsonify({"error": "Email is already in use"}), 409
                
            update["email"] = data["email"]
            
        # Full name update
        if "full_name" in data:
            update["full_name"] = data["full_name"]
            
        # Role update (admin only)
        if "role" in data and is_admin:
            if data["role"] not in ["admin", "operator", "viewer"]:
                return jsonify({"error": "Invalid role"}), 400
                
            update["role"] = data["role"]
            
        # Status update (admin only)
        if "status" in data and is_admin:
            if data["status"] not in ["active", "inactive", "pending"]:
                return jsonify({"error": "Invalid status"}), 400
                
            update["status"] = data["status"]
            
        # Preferences update
        if "preferences" in data and isinstance(data["preferences"], dict):
            # For admins or self, update preferences
            if is_admin or is_self:
                # Merge with existing preferences
                preferences = user.get("preferences", {})
                preferences.update(data["preferences"])
                update["preferences"] = preferences
            
        # If nothing to update
        if not update:
            return jsonify({"message": "No changes to update"}), 200
            
        # Add updated_at timestamp
        update["updated_at"] = datetime.utcnow()
        
        # Update the user
        result = _users_collection.update_one(
            {"_id": object_id},
            {"$set": update}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update user"}), 500
            
        # Get updated user
        updated_user = _users_collection.find_one({"_id": object_id})
        
        # Prepare response
        user_data = {
            "_id": str(updated_user["_id"]),
            "username": updated_user["username"],
            "email": updated_user["email"],
            "full_name": updated_user.get("full_name"),
            "role": updated_user.get("role"),
            "status": updated_user.get("status"),
            "updated_at": update["updated_at"].isoformat()
        }
        
        return jsonify({
            "message": "User updated successfully",
            "user": user_data
        }), 200
            
    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify({"error": "Failed to update user"}), 500


@users_bp.route('/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """
    Delete a user (admin only).
    
    Args:
        user_id: The ID of the user to delete
        
    Returns:
        JSON with status message
    """
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Get user
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Prevent deleting self
        current_user = g.user
        if str(current_user["_id"]) == user_id:
            return jsonify({"error": "Cannot delete your own account"}), 403
            
        # Check if this is the last admin
        if user.get("role") == "admin" and _users_collection.count_documents({"role": "admin"}) <= 1:
            return jsonify({"error": "Cannot delete the last administrator account"}), 403
            
        # Delete user
        result = _users_collection.delete_one({"_id": object_id})
        
        if result.deleted_count == 0:
            return jsonify({"error": "Failed to delete user"}), 500
            
        return jsonify({"message": "User deleted successfully"}), 200
            
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({"error": "Failed to delete user"}), 500


@users_bp.route('/<user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    """
    Reset a user's password (admin only).
    
    Args:
        user_id: The ID of the user whose password to reset
        
    Request body:
    {
        "password": "NewStrongPwd123"  # Optional, will generate random password if not provided
    }
    
    Returns:
        JSON with new password (if generated) or status message
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    # Check if password is provided or should be generated
    new_password = data.get("password")
    generate_password = new_password is None
    
    if not generate_password:
        # Validate password strength
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if not any(c.isupper() for c in new_password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.islower() for c in new_password):
            return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
        if not any(c.isdigit() for c in new_password):
            return jsonify({"error": "Password must contain at least one digit"}), 400
    
    try:
        # Convert string ID to ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Get user
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Generate random password if needed
        if generate_password:
            new_password = ''.join(
                secrets.choice(string.ascii_lowercase) +
                secrets.choice(string.ascii_uppercase) +
                secrets.choice(string.digits)
                for _ in range(4)
            ) + secrets.token_urlsafe(6)
            
        # Hash new password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password and clear any reset token
        result = _users_collection.update_one(
            {"_id": object_id},
            {
                "$set": {
                    "password_hash": password_hash,
                    "updated_at": datetime.utcnow(),
                    "login_attempts": 0
                },
                "$unset": {
                    "password_reset_token": "",
                    "password_reset_expires": ""
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to reset password"}), 500
            
        # Return different responses based on whether password was generated
        if generate_password:
            return jsonify({
                "message": "Password has been reset",
                "generated_password": new_password  # Only for admin reset
            }), 200
        else:
            return jsonify({"message": "Password has been reset"}), 200
            
    except Exception as e:
        logger.error(f"Admin reset password error: {str(e)}")
        return jsonify({"error": "Failed to reset password"}), 500


# ======== Helper Functions ========

def _generate_token(user_id: str, role: str, expires_in: int, is_refresh: bool = False) -> str:
    """
    Generate a JWT token.
    
    Args:
        user_id: User ID to include in the token
        role: User role for authorization
        expires_in: Expiration time in seconds
        is_refresh: Whether this is a refresh token
        
    Returns:
        str: Generated JWT token
    """
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "refresh": is_refresh
    }
    return jwt.encode(payload, _jwt_secret_key, algorithm="HS256")


def _is_valid_username(username: str) -> bool:
    """
    Check if username contains only allowed characters.
    
    Args:
        username: Username to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))


def _create_default_admin(app):
    """
    Create a default admin user if none exists.
    
    Args:
        app: Flask application instance with config
    """
    # Get default admin credentials from app config
    default_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
    default_password = app.config.get('DEFAULT_ADMIN_PASSWORD')
    default_email = app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    
    # If no default password is set, generate a random one
    if not default_password:
        default_password = ''.join(
            secrets.choice(string.ascii_lowercase) +
            secrets.choice(string.ascii_uppercase) +
            secrets.choice(string.digits)
            for _ in range(4)
        ) + secrets.token_urlsafe(6)
        
    # Hash password
    password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Create admin user
    admin_user = {
        "username": default_username,
        "email": default_email,
        "password_hash": password_hash,
        "full_name": "System Administrator",
        "role": "admin",
        "status": "active",
        "created_at": datetime.utcnow(),
        "api_keys": [],
        "preferences": {}
    }
    
    try:
        # Insert the admin user
        result = _users_collection.insert_one(admin_user)
        
        logger.info(f"Default admin user created with username: {default_username}")
        logger.info(f"Default admin password: {default_password}")
        
        # In production, you would want to encourage changing this password
        
    except Exception as e:
        logger.error(f"Error creating default admin user: {str(e)}")