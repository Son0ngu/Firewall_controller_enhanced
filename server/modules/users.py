"""
User management module for the Firewall Controller Server.

This module provides API endpoints for user authentication and management,
including user registration, login, profile management, and role-based access control.
"""

# Import các thư viện cần thiết
import logging  # Thư viện ghi log, dùng để theo dõi hoạt động của module
import secrets  # Thư viện tạo token và chuỗi ngẫu nhiên an toàn, dùng cho API key và reset token
import string  # Thư viện xử lý chuỗi, dùng để tạo mật khẩu ngẫu nhiên
import re  # Thư viện xử lý biểu thức chính quy, dùng để kiểm tra định dạng username
from datetime import datetime, timedelta  # Thư viện xử lý thời gian, dùng cho token và timestamp
from functools import wraps  # Thư viện hỗ trợ tạo decorator, dùng cho xác thực và phân quyền
from typing import Dict, List, Optional, Union  # Thư viện kiểu dữ liệu, giúp code rõ ràng hơn

import bcrypt  # Thư viện mã hóa mật khẩu, dùng để băm và xác thực mật khẩu
import jwt  # Thư viện JSON Web Token, dùng để tạo và xác thực token xác thực
from bson import ObjectId  # Thư viện xử lý ObjectId của MongoDB
from flask import Blueprint, jsonify, request, current_app, g  # Framework Flask để tạo API
from flask_socketio import SocketIO  # Thư viện xử lý kết nối WebSocket realtime
from pymongo import MongoClient, DESCENDING  # Thư viện kết nối MongoDB và hằng số sắp xếp
from pymongo.collection import Collection  # Kiểu dữ liệu Collection của MongoDB
from pymongo.database import Database  # Kiểu dữ liệu Database của MongoDB

# Import các model từ module khác
from server.models.user_model import User, UserCreate, UserUpdate, UserResponse, UserRole, UserStatus

# Cấu hình logging cho module
# Sử dụng logger riêng giúp dễ dàng lọc log từ module này
logger = logging.getLogger("users_module")

# Khởi tạo Blueprint cho các route API
# Blueprint giúp tổ chức các route theo nhóm chức năng
users_bp = Blueprint('users', __name__)  # Blueprint cho quản lý người dùng
auth_bp = Blueprint('auth', __name__)  # Blueprint cho xác thực

# Biến socketio sẽ được khởi tạo từ bên ngoài với instance Flask-SocketIO
# Dùng để thông báo realtime khi có thay đổi về người dùng
socketio: Optional[SocketIO] = None

# Các biến kết nối MongoDB (được khởi tạo trong hàm init_app)
_db: Optional[Database] = None  # Database MongoDB
_users_collection: Optional[Collection] = None  # Collection lưu thông tin người dùng

# Cài đặt JWT
_jwt_secret_key: str = ""  # Khóa bí mật để ký và xác thực token
_jwt_access_token_expires: int = 3600  # Thời gian hết hạn của access token (1 giờ)
_jwt_refresh_token_expires: int = 2592000  # Thời gian hết hạn của refresh token (30 ngày)


def init_app(app, mongo_client: MongoClient, socket_io: SocketIO):
    """
    Khởi tạo module users với ứng dụng Flask và kết nối MongoDB.
    
    Args:
        app: Instance ứng dụng Flask
        mongo_client: Instance MongoClient của PyMongo để kết nối đến MongoDB
        socket_io: Instance Flask-SocketIO để thông báo realtime
    """
    global _db, _users_collection, socketio, _jwt_secret_key, _jwt_access_token_expires, _jwt_refresh_token_expires
    
    # Lưu trữ instance SocketIO
    # Dùng để gửi thông báo realtime khi có thay đổi về người dùng
    socketio = socket_io
    
    # Lấy database từ client MongoDB
    # Sử dụng tên database từ cấu hình hoặc mặc định là 'firewall_controller'
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Lấy collection users từ database
    # Collection này lưu trữ thông tin người dùng
    _users_collection = _db.users
    
    # Tạo các index trong MongoDB để tối ưu hiệu suất truy vấn
    _users_collection.create_index([("username", 1)], unique=True)  # Index username, đảm bảo duy nhất
    _users_collection.create_index([("email", 1)], unique=True)  # Index email, đảm bảo duy nhất
    _users_collection.create_index([("password_reset_token", 1)])  # Index token reset password
    
    # Lấy cài đặt JWT từ cấu hình ứng dụng
    # Dùng để cấu hình việc tạo và xác thực token
    _jwt_secret_key = app.config.get('JWT_SECRET_KEY', app.config.get('SECRET_KEY'))
    _jwt_access_token_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
    _jwt_refresh_token_expires = app.config.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000)
    
    # Đăng ký các blueprint với ứng dụng
    # Cài đặt đường dẫn prefix cho các API
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
    # Tạo tài khoản admin mặc định nếu chưa có admin nào
    # Đảm bảo luôn có ít nhất một tài khoản admin để quản lý hệ thống
    if _users_collection.count_documents({"role": "admin"}) == 0:
        _create_default_admin(app)
    
    logger.info("Users module initialized")


# ======== Các Decorator Xác thực ========

def login_required(f):
    """
    Decorator để yêu cầu đăng nhập.
    Kiểm tra và xác thực JWT token trong header Authorization.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Lấy token từ header Authorization
        # Format: "Bearer [token]"
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Kiểm tra xem có token không
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        
        try:
            # Giải mã và xác thực token
            payload = jwt.decode(token, _jwt_secret_key, algorithms=["HS256"])
            
            # Lấy thông tin người dùng từ database
            user = _users_collection.find_one({"_id": ObjectId(payload["sub"])})
            
            # Kiểm tra xem người dùng có tồn tại không
            if not user:
                return jsonify({"error": "User not found"}), 401
                
            # Kiểm tra trạng thái tài khoản
            if user.get("status") != "active":
                return jsonify({"error": "Account is not active"}), 403
            
            # Lưu thông tin người dùng vào đối tượng g của Flask
            # g là global object của Flask, sống trong một request
            g.user = user
            
        except jwt.ExpiredSignatureError:
            # Token đã hết hạn
            return jsonify({"error": "Token has expired"}), 401
        except (jwt.InvalidTokenError, Exception) as e:
            # Token không hợp lệ hoặc lỗi khác
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({"error": "Invalid token"}), 401
            
        # Nếu token hợp lệ, tiếp tục thực hiện hàm gốc
        return f(*args, **kwargs)
    
    return decorated_function


def admin_required(f):
    """
    Decorator để yêu cầu quyền admin.
    Phải sử dụng sau login_required.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Kiểm tra xem đã xác thực chưa
        if not hasattr(g, 'user'):
            return jsonify({"error": "Authentication required"}), 401
            
        # Kiểm tra xem có phải admin không
        if g.user.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
            
        # Nếu là admin, tiếp tục thực hiện hàm gốc
        return f(*args, **kwargs)
    
    return decorated_function


# ======== Các Route Xác thực ========

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Endpoint đăng nhập người dùng.
    
    Request body:
    {
        "username": "admin",
        "password": "securepassword"
    }
    
    Returns:
        JSON với access token và thông tin người dùng
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    username = data.get("username")
    password = data.get("password")
    
    # Kiểm tra các trường bắt buộc
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    try:
        # Tìm người dùng theo username
        user = _users_collection.find_one({"username": username})
        
        if not user:
            # Sử dụng cùng một thông báo lỗi để ngăn liệt kê username
            # Tránh attacker biết username nào tồn tại
            return jsonify({"error": "Invalid username or password"}), 401
            
        # Kiểm tra trạng thái tài khoản
        if user.get("status") != "active":
            return jsonify({"error": "Account is not active"}), 403
            
        # Kiểm tra mật khẩu
        # bcrypt.checkpw so sánh mật khẩu nhập vào với mật khẩu đã mã hóa
        if not bcrypt.checkpw(password.encode('utf-8'), user.get("password_hash").encode('utf-8')):
            # Tăng số lần đăng nhập thất bại
            # Dùng để phát hiện brute force
            _users_collection.update_one(
                {"_id": user["_id"]},
                {"$inc": {"login_attempts": 1}}
            )
            return jsonify({"error": "Invalid username or password"}), 401
            
        # Reset số lần đăng nhập thất bại và cập nhật thời gian đăng nhập
        _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "last_login": datetime.utcnow(),
                    "login_attempts": 0
                }
            }
        )
        
        # Tạo token
        # Access token dùng để xác thực API, có thời hạn ngắn
        access_token = _generate_token(
            str(user["_id"]), 
            user.get("role", "viewer"),
            _jwt_access_token_expires
        )
        
        # Refresh token dùng để tạo lại access token, có thời hạn dài
        refresh_token = _generate_token(
            str(user["_id"]), 
            user.get("role", "viewer"),
            _jwt_refresh_token_expires,
            is_refresh=True
        )
        
        # Chuẩn bị dữ liệu người dùng cho response
        # Loại bỏ các trường nhạy cảm như password_hash
        user_data = {
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name"),
            "role": user.get("role", "viewer"),
            "preferences": user.get("preferences", {})
        }
        
        # Trả về token và thông tin người dùng
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": _jwt_access_token_expires,
            "user": user_data
        }), 200
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi chung
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "An error occurred during login"}), 500


@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    Làm mới access token bằng refresh token.
    Khi access token hết hạn, client dùng refresh token để lấy access token mới.
    
    Request body:
    {
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    
    Returns:
        JSON với access token mới
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    refresh_token = data.get("refresh_token")
    
    # Kiểm tra xem có refresh token không
    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400
        
    try:
        # Giải mã và xác thực refresh token
        payload = jwt.decode(refresh_token, _jwt_secret_key, algorithms=["HS256"])
        
        # Kiểm tra xem có phải refresh token không
        if not payload.get("refresh"):
            return jsonify({"error": "Invalid refresh token"}), 401
            
        # Lấy thông tin người dùng từ database
        user = _users_collection.find_one({"_id": ObjectId(payload["sub"])})
        
        if not user:
            return jsonify({"error": "User not found"}), 401
            
        # Kiểm tra trạng thái tài khoản
        if user.get("status") != "active":
            return jsonify({"error": "Account is not active"}), 403
            
        # Tạo access token mới
        access_token = _generate_token(
            str(user["_id"]), 
            user.get("role", "viewer"),
            _jwt_access_token_expires
        )
        
        # Trả về access token mới
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": _jwt_access_token_expires
        }), 200
            
    except jwt.ExpiredSignatureError:
        # Refresh token đã hết hạn
        return jsonify({"error": "Refresh token has expired"}), 401
    except (jwt.InvalidTokenError, Exception) as e:
        # Refresh token không hợp lệ hoặc lỗi khác
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({"error": "Invalid refresh token"}), 401


@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """
    Lấy thông tin hồ sơ người dùng hiện tại.
    
    Returns:
        JSON với thông tin người dùng
    """
    try:
        # Lấy thông tin người dùng từ g object
        # g.user được thiết lập bởi decorator login_required
        user = g.user
        
        # Chuẩn bị dữ liệu người dùng cho response
        # Loại bỏ các trường nhạy cảm
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """
    Cập nhật hồ sơ người dùng hiện tại.
    
    Request body:
    {
        "email": "new.email@example.com",  # Tùy chọn
        "full_name": "New Name",           # Tùy chọn
        "preferences": {                   # Tùy chọn
            "theme": "dark"
        }
    }
    
    Returns:
        JSON với thông tin người dùng đã cập nhật
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Lấy thông tin người dùng từ g object
        user = g.user
        user_id = user["_id"]
        
        # Xây dựng dict chứa các cập nhật
        update = {}
        
        # Cập nhật email
        if "email" in data and data["email"] != user.get("email"):
            # Kiểm tra xem email đã được sử dụng chưa
            if _users_collection.find_one({"email": data["email"], "_id": {"$ne": user_id}}):
                return jsonify({"error": "Email is already in use"}), 409
                
            update["email"] = data["email"]
            
        # Cập nhật tên đầy đủ
        if "full_name" in data:
            update["full_name"] = data["full_name"]
            
        # Cập nhật tùy chọn người dùng
        if "preferences" in data and isinstance(data["preferences"], dict):
            # Kết hợp với tùy chọn hiện tại
            preferences = user.get("preferences", {})
            preferences.update(data["preferences"])
            update["preferences"] = preferences
            
        # Nếu không có gì để cập nhật
        if not update:
            return jsonify({"message": "No changes to update"}), 200
            
        # Thêm timestamp cập nhật
        update["updated_at"] = datetime.utcnow()
        
        # Cập nhật người dùng trong database
        result = _users_collection.update_one(
            {"_id": user_id},
            {"$set": update}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update profile"}), 500
            
        # Lấy thông tin người dùng đã cập nhật
        updated_user = _users_collection.find_one({"_id": user_id})
        
        # Chuẩn bị dữ liệu người dùng cho response
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Update profile error: {str(e)}")
        return jsonify({"error": "Failed to update profile"}), 500


@auth_bp.route('/change-password', methods=['PUT'])
@login_required
def change_password():
    """
    Thay đổi mật khẩu người dùng.
    
    Request body:
    {
        "current_password": "oldpassword",
        "new_password": "newStrongPwd123"
    }
    
    Returns:
        JSON với thông báo trạng thái
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    # Kiểm tra các trường bắt buộc
    if not current_password or not new_password:
        return jsonify({"error": "Both current and new password are required"}), 400
        
    # Kiểm tra độ mạnh của mật khẩu mới
    # Yêu cầu ít nhất 8 ký tự, có chữ hoa, chữ thường và số
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not any(c.isupper() for c in new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not any(c.islower() for c in new_password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    
    try:
        # Lấy thông tin người dùng từ g object
        user = g.user
        
        # Xác thực mật khẩu hiện tại
        if not bcrypt.checkpw(current_password.encode('utf-8'), user.get("password_hash").encode('utf-8')):
            return jsonify({"error": "Current password is incorrect"}), 401
            
        # Mã hóa mật khẩu mới
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Cập nhật mật khẩu trong database
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Change password error: {str(e)}")
        return jsonify({"error": "Failed to change password"}), 500


@auth_bp.route('/reset-password', methods=['POST'])
def request_password_reset():
    """
    Yêu cầu link đặt lại mật khẩu.
    
    Request body:
    {
        "email": "user@example.com"
    }
    
    Returns:
        JSON với thông báo trạng thái
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    email = data.get("email")
    
    # Kiểm tra xem có email không
    if not email:
        return jsonify({"error": "Email is required"}), 400
        
    try:
        # Tìm người dùng theo email
        user = _users_collection.find_one({"email": email})
        
        # Luôn trả về thành công dù người dùng không tồn tại
        # Ngăn chặn việc liệt kê email đã đăng ký
        if not user:
            logger.info(f"Password reset requested for non-existent email: {email}")
            return jsonify({"message": "If the email exists, a reset link will be sent"}), 200
            
        # Tạo token đặt lại mật khẩu
        # Token ngẫu nhiên 64 ký tự
        token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        # Token có hiệu lực trong 1 giờ
        expiration = datetime.utcnow() + timedelta(hours=1)
        
        # Lưu token và thời hạn vào document người dùng
        _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_reset_token": token,
                    "password_reset_expires": expiration
                }
            }
        )
        
        # Trong ứng dụng thực tế, bạn sẽ gửi email với link đặt lại mật khẩu
        # Ở đây, chúng ta chỉ ghi log
        reset_url = f"{request.host_url.rstrip('/')}/reset-password/{token}"
        logger.info(f"Password reset link for {email}: {reset_url}")
        
        return jsonify({
            "message": "If the email exists, a reset link will be sent", 
            "debug_token": token  # Xóa trong môi trường sản xuất
        }), 200
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Password reset request error: {str(e)}")
        return jsonify({"error": "Failed to process password reset request"}), 500


@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    """
    Đặt lại mật khẩu bằng token.
    
    Args:
        token: Token đặt lại mật khẩu
    
    Request body:
    {
        "password": "newStrongPwd123"
    }
    
    Returns:
        JSON với thông báo trạng thái
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    new_password = data.get("password")
    
    # Kiểm tra xem có mật khẩu mới không
    if not new_password:
        return jsonify({"error": "New password is required"}), 400
        
    # Kiểm tra độ mạnh của mật khẩu
    # Yêu cầu ít nhất 8 ký tự, có chữ hoa, chữ thường và số
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not any(c.isupper() for c in new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not any(c.islower() for c in new_password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must contain at least one digit"}), 400
    
    try:
        # Tìm người dùng với token và token chưa hết hạn
        user = _users_collection.find_one({
            "password_reset_token": token,
            "password_reset_expires": {"$gt": datetime.utcnow()}
        })
        
        if not user:
            return jsonify({"error": "Invalid or expired reset token"}), 400
            
        # Mã hóa mật khẩu mới
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Cập nhật mật khẩu và xóa token đặt lại
        result = _users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_hash": password_hash,
                    "updated_at": datetime.utcnow(),
                    "status": "active"  # Kích hoạt tài khoản nếu đang ở trạng thái chờ
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({"error": "Failed to reset password"}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Endpoint đăng xuất người dùng.
    
    Lưu ý: Vì JWT là stateless, endpoint này chủ yếu phục vụ client.
    Client nên hủy token khi đăng xuất.
    
    Returns:
        JSON với thông báo trạng thái
    """
    # Trong hệ thống auth stateful, ta sẽ vô hiệu hóa token tại đây
    # Đối với JWT, client chỉ cần xóa token
    
    return jsonify({"message": "Successfully logged out"}), 200


# ======== Các Route Quản lý API Key ========

@auth_bp.route('/api-keys', methods=['GET'])
@login_required
def list_api_keys():
    """
    Liệt kê các API key của người dùng hiện tại.
    
    Returns:
        JSON với danh sách API key
    """
    try:
        # Lấy thông tin người dùng từ g object
        user = g.user
        
        # Trích xuất thông tin API key (không bao gồm key thật vì lý do bảo mật)
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"List API keys error: {str(e)}")
        return jsonify({"error": "Failed to list API keys"}), 500


@auth_bp.route('/api-keys', methods=['POST'])
@login_required
def create_api_key():
    """
    Tạo API key mới cho người dùng hiện tại.
    
    Request body:
    {
        "name": "My API Key"  # Tùy chọn
    }
    
    Returns:
        JSON với API key mới
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    key_name = data.get("name", "API Key")
    
    try:
        # Lấy thông tin người dùng từ g object
        user = g.user
        
        # Tạo API key
        # Tạo chuỗi ngẫu nhiên 32 ký tự
        api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        key_id = str(ObjectId())
        
        # Thêm API key vào người dùng
        # Lưu hash của key thay vì key gốc để tăng bảo mật
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
            
        # Trả về key (chỉ hiển thị một lần)
        # Client phải lưu key này vì sau này không thể xem lại
        return jsonify({
            "message": "API key created successfully",
            "api_key": {
                "id": key_id,
                "name": key_name,
                "key": api_key,  # Chỉ trả về một lần
                "created_at": new_key["created_at"].isoformat()
            }
        }), 201
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Create API key error: {str(e)}")
        return jsonify({"error": "Failed to create API key"}), 500


@auth_bp.route('/api-keys/<key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """
    Xóa API key.
    
    Args:
        key_id: ID của API key cần xóa
        
    Returns:
        JSON với thông báo trạng thái
    """
    try:
        # Lấy thông tin người dùng từ g object
        user = g.user
        
        # Xóa API key khỏi người dùng
        result = _users_collection.update_one(
            {"_id": user["_id"]},
            {"$pull": {"api_keys": {"id": key_id}}}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "API key not found"}), 404
            
        return jsonify({"message": "API key deleted successfully"}), 200
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Delete API key error: {str(e)}")
        return jsonify({"error": "Failed to delete API key"}), 500


# ======== Các Route Quản lý Người dùng (Chỉ Admin) ========

@users_bp.route('', methods=['GET'])
@login_required
@admin_required
def get_users():
    """
    Lấy tất cả người dùng (chỉ dành cho admin).
    
    Query parameters:
    - limit: Số lượng người dùng tối đa trả về
    - skip: Số lượng người dùng bỏ qua
    - role: Lọc theo vai trò
    - status: Lọc theo trạng thái
    
    Returns:
        JSON với danh sách người dùng
    """
    try:
        # Phân tích các tham số truy vấn
        limit = min(int(request.args.get('limit', 100)), 1000)  # Giới hạn tối đa 1000 người dùng
        skip = int(request.args.get('skip', 0))
        role = request.args.get('role')
        status = request.args.get('status')
        
        # Xây dựng truy vấn
        query = {}
        if role:
            query["role"] = role
        if status:
            query["status"] = status
            
        # Thực hiện truy vấn
        cursor = _users_collection.find(query)
        
        # Lấy tổng số người dùng
        total_count = _users_collection.count_documents(query)
        
        # Áp dụng phân trang
        cursor = cursor.skip(skip).limit(limit)
        
        # Chuyển thành danh sách và chuẩn bị cho response JSON
        users = []
        for user in cursor:
            # Loại bỏ các trường nhạy cảm
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Get users error: {str(e)}")
        return jsonify({"error": "Failed to retrieve users"}), 500


@users_bp.route('', methods=['POST'])
@login_required
@admin_required
def create_user():
    """
    Tạo người dùng mới (chỉ dành cho admin).
    
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
        JSON với thông tin người dùng đã tạo
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Xác thực các trường bắt buộc
        required_fields = ["username", "email", "password"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
                
        # Xác thực username
        username = data["username"]
        if not username or len(username) < 3 or len(username) > 50:
            return jsonify({"error": "Username must be between 3 and 50 characters"}), 400
            
        if not _is_valid_username(username):
            return jsonify({"error": "Username must contain only alphanumeric characters, underscores, or hyphens"}), 400
            
        # Kiểm tra xem username đã được sử dụng chưa
        if _users_collection.find_one({"username": username}):
            return jsonify({"error": "Username is already taken"}), 409
            
        # Xác thực email
        email = data["email"]
        if not email or "@" not in email:
            return jsonify({"error": "Invalid email address"}), 400
            
        # Kiểm tra xem email đã đăng ký chưa
        if _users_collection.find_one({"email": email}):
            return jsonify({"error": "Email is already registered"}), 409
            
        # Xác thực mật khẩu
        password = data["password"]
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if not any(c.isupper() for c in password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.islower() for c in password):
            return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
        if not any(c.isdigit() for c in password):
            return jsonify({"error": "Password must contain at least one digit"}), 400
            
        # Xác thực vai trò
        role = data.get("role", "viewer")
        if role not in ["admin", "operator", "viewer"]:
            return jsonify({"error": "Invalid role"}), 400
            
        # Xác thực trạng thái
        status = data.get("status", "active")
        if status not in ["active", "inactive", "pending"]:
            return jsonify({"error": "Invalid status"}), 400
            
        # Mã hóa mật khẩu
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Chuẩn bị document người dùng
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
        
        # Thêm người dùng vào database
        result = _users_collection.insert_one(new_user)
        
        # Lấy người dùng đã thêm
        user = _users_collection.find_one({"_id": result.inserted_id})
        
        # Chuẩn bị response
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Create user error: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500


@users_bp.route('/<user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """
    Lấy thông tin của một người dùng cụ thể.
    
    Args:
        user_id: ID của người dùng cần lấy thông tin
        
    Returns:
        JSON với thông tin người dùng
    """
    try:
        # Chuyển chuỗi ID thành ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Lấy thông tin người dùng
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Kiểm tra quyền - admin có thể xem tất cả người dùng, những người khác chỉ xem chính họ
        current_user = g.user
        if str(current_user["_id"]) != user_id and current_user.get("role") != "admin":
            return jsonify({"error": "Permission denied"}), 403
            
        # Chuẩn bị response
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
        
        # Thêm dữ liệu nhạy cảm cho admin
        if current_user.get("role") == "admin":
            user_data["login_attempts"] = user.get("login_attempts", 0)
            
        return jsonify(user_data), 200
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Get user error: {str(e)}")
        return jsonify({"error": "Failed to retrieve user"}), 500


@users_bp.route('/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """
    Cập nhật thông tin người dùng.
    
    Args:
        user_id: ID của người dùng cần cập nhật
        
    Request body:
    {
        "email": "updated@example.com",
        "full_name": "Updated Name",
        "role": "operator",
        "status": "active",
        "preferences": { ... }
    }
    
    Returns:
        JSON với thông tin người dùng đã cập nhật
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Chuyển chuỗi ID thành ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Lấy thông tin người dùng cần cập nhật
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Kiểm tra quyền - admin có thể cập nhật tất cả người dùng, những người khác chỉ cập nhật chính họ
        current_user = g.user
        is_admin = current_user.get("role") == "admin"
        is_self = str(current_user["_id"]) == user_id
        
        if not is_admin and not is_self:
            return jsonify({"error": "Permission denied"}), 403
            
        # Thay đổi vai trò chỉ dành cho admin
        if "role" in data and not is_admin:
            return jsonify({"error": "Only administrators can change roles"}), 403
            
        # Thay đổi trạng thái chỉ dành cho admin
        if "status" in data and not is_admin:
            return jsonify({"error": "Only administrators can change account status"}), 403
            
        # Admin không thể hạ cấp vai trò của chính mình để tránh tình trạng khóa
        if is_self and is_admin and data.get("role") != "admin":
            return jsonify({"error": "Administrators cannot downgrade their own role"}), 403
            
        # Xây dựng dict chứa các cập nhật
        update = {}
        
        # Cập nhật email
        if "email" in data and data["email"] != user.get("email"):
            # Kiểm tra xem email đã được sử dụng chưa
            if _users_collection.find_one({"email": data["email"], "_id": {"$ne": object_id}}):
                return jsonify({"error": "Email is already in use"}), 409
                
            update["email"] = data["email"]
            
        # Cập nhật tên đầy đủ
        if "full_name" in data:
            update["full_name"] = data["full_name"]
            
        # Cập nhật vai trò (chỉ admin)
        if "role" in data and is_admin:
            if data["role"] not in ["admin", "operator", "viewer"]:
                return jsonify({"error": "Invalid role"}), 400
                
            update["role"] = data["role"]
            
        # Cập nhật trạng thái (chỉ admin)
        if "status" in data and is_admin:
            if data["status"] not in ["active", "inactive", "pending"]:
                return jsonify({"error": "Invalid status"}), 400
                
            update["status"] = data["status"]
            
        # Cập nhật tùy chọn
        if "preferences" in data and isinstance(data["preferences"], dict):
            # Đối với admin hoặc bản thân, cập nhật tùy chọn
            if is_admin or is_self:
                # Kết hợp với tùy chọn hiện tại
                preferences = user.get("preferences", {})
                preferences.update(data["preferences"])
                update["preferences"] = preferences
            
        # Nếu không có gì để cập nhật
        if not update:
            return jsonify({"message": "No changes to update"}), 200
            
        # Thêm timestamp cập nhật
        update["updated_at"] = datetime.utcnow()
        
        # Cập nhật người dùng trong database
        result = _users_collection.update_one(
            {"_id": object_id},
            {"$set": update}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update user"}), 500
            
        # Lấy thông tin người dùng đã cập nhật
        updated_user = _users_collection.find_one({"_id": object_id})
        
        # Chuẩn bị response
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
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Update user error: {str(e)}")
        return jsonify({"error": "Failed to update user"}), 500


@users_bp.route('/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """
    Xóa người dùng (chỉ dành cho admin).
    
    Args:
        user_id: ID của người dùng cần xóa
        
    Returns:
        JSON với thông báo trạng thái
    """
    try:
        # Chuyển chuỗi ID thành ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Lấy thông tin người dùng
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Ngăn chặn việc xóa chính mình
        current_user = g.user
        if str(current_user["_id"]) == user_id:
            return jsonify({"error": "Cannot delete your own account"}), 403
            
        # Kiểm tra xem đây có phải là admin cuối cùng không
        if user.get("role") == "admin" and _users_collection.count_documents({"role": "admin"}) <= 1:
            return jsonify({"error": "Cannot delete the last administrator account"}), 403
            
        # Xóa người dùng
        result = _users_collection.delete_one({"_id": object_id})
        
        if result.deleted_count == 0:
            return jsonify({"error": "Failed to delete user"}), 500
            
        return jsonify({"message": "User deleted successfully"}), 200
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({"error": "Failed to delete user"}), 500


@users_bp.route('/<user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    """
    Đặt lại mật khẩu người dùng (chỉ dành cho admin).
    
    Args:
        user_id: ID của người dùng cần đặt lại mật khẩu
        
    Request body:
    {
        "password": "NewStrongPwd123"  # Tùy chọn, sẽ tạo mật khẩu ngẫu nhiên nếu không cung cấp
    }
    
    Returns:
        JSON với mật khẩu mới (nếu được tạo tự động) hoặc thông báo trạng thái
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    # Kiểm tra xem dữ liệu có phải dict không
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    # Kiểm tra xem mật khẩu được cung cấp hay cần tạo tự động
    new_password = data.get("password")
    generate_password = new_password is None
    
    if not generate_password:
        # Kiểm tra độ mạnh của mật khẩu
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if not any(c.isupper() for c in new_password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.islower() for c in new_password):
            return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
        if not any(c.isdigit() for c in new_password):
            return jsonify({"error": "Password must contain at least one digit"}), 400
    
    try:
        # Chuyển chuỗi ID thành ObjectId
        try:
            object_id = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID format"}), 400
            
        # Lấy thông tin người dùng
        user = _users_collection.find_one({"_id": object_id})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Tạo mật khẩu ngẫu nhiên nếu cần
        if generate_password:
            # Tạo mật khẩu với chữ thường, chữ hoa, số và một số ký tự đặc biệt
            new_password = ''.join(
                secrets.choice(string.ascii_lowercase) +
                secrets.choice(string.ascii_uppercase) +
                secrets.choice(string.digits)
                for _ in range(4)
            ) + secrets.token_urlsafe(6)
            
        # Mã hóa mật khẩu mới
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Cập nhật mật khẩu và xóa token đặt lại
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
            
        # Trả về response khác nhau tùy thuộc vào việc mật khẩu được tạo tự động hay không
        if generate_password:
            return jsonify({
                "message": "Password has been reset",
                "generated_password": new_password  # Chỉ cho admin reset
            }), 200
        else:
            return jsonify({"message": "Password has been reset"}), 200
            
    except Exception as e:
        # Ghi log lỗi và trả về thông báo lỗi
        logger.error(f"Admin reset password error: {str(e)}")
        return jsonify({"error": "Failed to reset password"}), 500


# ======== Các Hàm Trợ Giúp ========

def _generate_token(user_id: str, role: str, expires_in: int, is_refresh: bool = False) -> str:
    """
    Tạo một JWT token.
    
    Args:
        user_id: User ID để đưa vào token
        role: Vai trò người dùng để phân quyền
        expires_in: Thời gian hết hạn tính bằng giây
        is_refresh: Liệu đây có phải là refresh token không
        
    Returns:
        str: JWT token đã tạo
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
    Kiểm tra xem username có chỉ chứa các ký tự được phép không.
    
    Args:
        username: Username để xác thực
        
    Returns:
        bool: True nếu hợp lệ, False nếu không
    """
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))


def _create_default_admin(app):
    """
    Tạo một tài khoản admin mặc định nếu chưa có.
    
    Args:
        app: Instance ứng dụng Flask với cấu hình
    """
    # Lấy thông tin đăng nhập admin mặc định từ cấu hình ứng dụng
    default_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
    default_password = app.config.get('DEFAULT_ADMIN_PASSWORD')
    default_email = app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    
    # Nếu không có mật khẩu mặc định, tạo một mật khẩu ngẫu nhiên
    if not default_password:
        default_password = ''.join(
            secrets.choice(string.ascii_lowercase) +
            secrets.choice(string.ascii_uppercase) +
            secrets.choice(string.digits)
            for _ in range(4)
        ) + secrets.token_urlsafe(6)
        
    # Mã hóa mật khẩu
    password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Tạo tài khoản admin
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
        # Thêm tài khoản admin vào database
        result = _users_collection.insert_one(admin_user)
        
        logger.info(f"Default admin user created with username: {default_username}")
        logger.info(f"Default admin password: {default_password}")
        
        # Trong production, bạn nên khuyến khích việc đổi mật khẩu này
        
    except Exception as e:
        # Ghi log lỗi nếu có
        logger.error(f"Error creating default admin user: {str(e)}")