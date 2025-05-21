"""
Authentication module for the Firewall Controller Server.

This module handles user authentication, authorization, and user management.
It provides endpoints for login, logout, token refresh, and user CRUD operations.
"""

# Import các thư viện cần thiết
import logging  # Thư viện hỗ trợ ghi log, dùng để theo dõi hoạt động của module
from datetime import datetime, timedelta  # Thư viện xử lý thời gian, dùng cho token và timestamp
from functools import wraps  # Thư viện hỗ trợ tạo decorator, dùng cho xác thực và phân quyền
from typing import Dict, List, Optional, Union  # Thư viện kiểu dữ liệu, giúp viết code rõ ràng hơn

import bcrypt  # Thư viện mã hóa mật khẩu, dùng để băm và xác thực mật khẩu người dùng
import jwt  # Thư viện JWT (JSON Web Token), dùng để tạo và xác thực token xác thực
from bson import ObjectId  # Thư viện làm việc với ObjectID của MongoDB
from flask import Blueprint, jsonify, request, current_app, g  # Framework Flask để tạo API web
from flask_socketio import SocketIO  # Thư viện hỗ trợ WebSocket, dùng cho giao tiếp thời gian thực
from pymongo import MongoClient, DESCENDING  # Thư viện kết nối đến MongoDB
from pymongo.collection import Collection  # Kiểu Collection trong MongoDB
from pymongo.database import Database  # Kiểu Database trong MongoDB

# Import model từ các module khác của dự án
from server.models.user_model import User, UserCreate, UserUpdate, UserResponse, UserRole, UserStatus

# Cấu hình logging cho module này
# Sử dụng logger riêng để dễ dàng lọc log từ module này
logger = logging.getLogger("auth_module")

# Khởi tạo Blueprint cho các route API
# Blueprint giúp tổ chức các route theo nhóm chức năng
auth_bp = Blueprint('auth', __name__)  # Blueprint cho các API xác thực (login, logout)
users_bp = Blueprint('users', __name__)  # Blueprint cho các API quản lý người dùng

# Biến socketio sẽ được khởi tạo từ bên ngoài với instance Flask-SocketIO
# Dùng để thông báo realtime khi có thay đổi (như tạo user mới, đăng nhập, v.v.)
socketio: Optional[SocketIO] = None

# Các biến kết nối MongoDB (được khởi tạo trong hàm init_app)
_db: Optional[Database] = None  # Database MongoDB
_users_collection: Optional[Collection] = None  # Collection lưu thông tin người dùng

# Cài đặt JWT
_jwt_secret_key: str = ""  # Khóa bí mật để ký và xác thực token
_jwt_access_token_expires: int = 3600  # Thời gian hết hạn của access token (1 giờ)
_jwt_refresh_token_expires: int = 2592000  # Thời gian hết hạn của refresh token (30 ngày)

def init_app(app, mongo_client: MongoClient, socket_io: Optional[SocketIO] = None):
    """
    Khởi tạo module xác thực với ứng dụng Flask và kết nối MongoDB.
    
    Args:
        app: Instance ứng dụng Flask
        mongo_client: Instance MongoClient của PyMongo để kết nối đến MongoDB
        socket_io: Instance Flask-SocketIO tùy chọn (cho thông báo realtime)
    """
    global _db, _users_collection, socketio, _jwt_secret_key, _jwt_access_token_expires, _jwt_refresh_token_expires
    
    # Lưu trữ instance SocketIO nếu được cung cấp
    # Giúp gửi thông báo realtime khi có thay đổi
    socketio = socket_io
    
    # Lấy database từ MongoDB client
    # Sử dụng tên database từ cấu hình hoặc mặc định là 'firewall_controller'
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Lấy collection users từ database
    # Collection này lưu trữ thông tin người dùng và xác thực
    _users_collection = _db.users
    
    # Tạo các index trong MongoDB để tối ưu truy vấn và đảm bảo tính duy nhất
    _users_collection.create_index([("username", 1)], unique=True)  # Index theo username, đảm bảo duy nhất
    _users_collection.create_index([("email", 1)], unique=True)  # Index theo email, đảm bảo duy nhất
    _users_collection.create_index([("password_reset_token", 1)])  # Index theo token reset password
    
    # Lấy cài đặt JWT từ cấu hình ứng dụng
    _jwt_secret_key = app.config.get('JWT_SECRET_KEY', app.config.get('SECRET_KEY'))
    _jwt_access_token_expires = app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
    _jwt_refresh_token_expires = app.config.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000)
    
    # Đăng ký các blueprint với ứng dụng
    # Cài đặt đường dẫn prefix cho các API
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    
    # Tạo tài khoản admin mặc định nếu chưa có admin nào trong hệ thống
    # Đảm bảo luôn có ít nhất một tài khoản admin để quản lý hệ thống
    if _users_collection.count_documents({"role": UserRole.ADMIN}) == 0:
        _create_default_admin(app)
    
    logger.info("Authentication module initialized")


# ======== Các hàm xử lý JWT Token ========

def generate_access_token(user_id: str, role: str) -> str:
    """
    Tạo access token cho người dùng.
    Access token có thời hạn ngắn và dùng để xác thực người dùng khi truy cập API.
    
    Args:
        user_id: ID của người dùng
        role: Vai trò của người dùng
    
    Returns:
        str: JWT access token
    """
    now = datetime.utcnow()
    payload = {
        "sub": user_id,  # subject - ID của user
        "role": role,  # vai trò người dùng để phân quyền
        "type": "access",  # loại token là access
        "iat": now,  # issued at - thời điểm tạo token
        "exp": now + timedelta(seconds=_jwt_access_token_expires)  # expiration - thời điểm hết hạn
    }
    return jwt.encode(payload, _jwt_secret_key, algorithm="HS256")


def generate_refresh_token(user_id: str) -> str:
    """
    Tạo refresh token cho người dùng.
    Refresh token có thời hạn dài và dùng để tạo access token mới khi access token cũ hết hạn.
    
    Args:
        user_id: ID của người dùng
    
    Returns:
        str: JWT refresh token
    """
    now = datetime.utcnow()
    payload = {
        "sub": user_id,  # subject - ID của user
        "type": "refresh",  # loại token là refresh
        "iat": now,  # issued at - thời điểm tạo token
        "exp": now + timedelta(seconds=_jwt_refresh_token_expires)  # expiration - thời điểm hết hạn
    }
    return jwt.encode(payload, _jwt_secret_key, algorithm="HS256")


def validate_token(token: str) -> Dict:
    """
    Xác thực một JWT token.
    Kiểm tra tính hợp lệ và thời hạn của token.
    
    Args:
        token: JWT token cần xác thực
    
    Returns:
        Dict: Payload của token nếu hợp lệ
    
    Raises:
        jwt.InvalidTokenError: Nếu token không hợp lệ
    """
    return jwt.decode(token, _jwt_secret_key, algorithms=["HS256"])


# ======== Các Decorator Xác thực ========

def token_required(f):
    """
    Decorator để yêu cầu JWT token hợp lệ khi truy cập API.
    Đặt thông tin người dùng đã xác thực vào g.user để sử dụng trong hàm xử lý.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Lấy token từ header Authorization
        # Format: "Bearer [token]"
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Kiểm tra xem có token không
        if not token:
            return jsonify({"error": "Authentication token is missing"}), 401
        
        try:
            # Xác thực token
            payload = validate_token(token)
            
            # Kiểm tra xem có phải access token không
            if payload.get('type') != 'access':
                return jsonify({"error": "Invalid token type"}), 401
            
            # Lấy thông tin người dùng từ database
            user = _users_collection.find_one({"_id": ObjectId(payload['sub'])})
            
            if not user:
                return jsonify({"error": "User not found"}), 401
            
            # Kiểm tra trạng thái tài khoản
            if user.get("status") != UserStatus.ACTIVE:
                return jsonify({"error": "User account is inactive"}), 403
            
            # Lưu thông tin người dùng vào đối tượng g của Flask
            # g là context global cho mỗi request
            g.user = user
            g.user_id = str(user["_id"])
            g.user_role = user.get("role", UserRole.VIEWER)
            
        except jwt.ExpiredSignatureError:
            # Token đã hết hạn
            return jsonify({"error": "Token has expired", "code": "token_expired"}), 401
        except (jwt.InvalidTokenError, Exception) as e:
            # Token không hợp lệ hoặc lỗi khác
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({"error": "Invalid authentication token"}), 401
        
        # Nếu token hợp lệ, tiếp tục thực hiện hàm xử lý API
        return f(*args, **kwargs)
    
    return decorated


def admin_required(f):
    """
    Decorator để yêu cầu quyền admin.
    Phải sử dụng sau token_required.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Kiểm tra xem đã xác thực chưa
        if not hasattr(g, 'user_role'):
            return jsonify({"error": "Authentication required"}), 401
        
        # Kiểm tra xem có phải admin không
        if g.user_role != UserRole.ADMIN:
            return jsonify({"error": "Admin privileges required"}), 403
        
        # Nếu là admin, tiếp tục thực hiện hàm xử lý API
        return f(*args, **kwargs)
    
    return decorated


def operator_required(f):
    """
    Decorator để yêu cầu ít nhất quyền operator.
    Cả admin và operator đều có thể truy cập.
    Phải sử dụng sau token_required.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Kiểm tra xem đã xác thực chưa
        if not hasattr(g, 'user_role'):
            return jsonify({"error": "Authentication required"}), 401
        
        # Kiểm tra xem có quyền admin hoặc operator không
        if g.user_role not in [UserRole.ADMIN, UserRole.OPERATOR]:
            return jsonify({"error": "Operator privileges required"}), 403
        
        # Nếu có đủ quyền, tiếp tục thực hiện hàm xử lý API
        return f(*args, **kwargs)
    
    return decorated


# ======== Các Route Xác thực ========

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    API đăng nhập người dùng.
    
    Request body:
    {
        "username": "admin",
        "password": "password"
    }
    
    Returns:
        JSON với access token, refresh token và thông tin người dùng
    """
    # Kiểm tra xem request có phải là JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Kiểm tra các trường bắt buộc
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Tìm người dùng theo username
    user = _users_collection.find_one({"username": username})
    
    if not user:
        # Ghi log cảnh báo nếu có người thử đăng nhập với username không tồn tại
        logger.warning(f"Login attempt with non-existent username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Xác thực mật khẩu bằng bcrypt
    # bcrypt.checkpw so sánh mật khẩu nhập vào (đã mã hóa) với mật khẩu đã lưu
    if not bcrypt.checkpw(password.encode('utf-8'), user.get('password_hash', '').encode('utf-8')):
        # Ghi log cảnh báo nếu mật khẩu sai
        logger.warning(f"Failed login attempt for user: {username}")
        
        # Tăng số lần đăng nhập thất bại
        # Giúp phát hiện các cuộc tấn công brute force
        _users_collection.update_one(
            {"_id": user["_id"]},
            {"$inc": {"login_attempts": 1}}
        )
        
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Kiểm tra trạng thái tài khoản
    if user.get("status") != UserStatus.ACTIVE:
        return jsonify({"error": "Your account is inactive. Please contact an administrator."}), 403
    
    # Tạo token
    access_token = generate_access_token(str(user["_id"]), user.get("role", UserRole.VIEWER))
    refresh_token = generate_refresh_token(str(user["_id"]))
    
    # Cập nhật thời gian đăng nhập cuối và reset số lần đăng nhập thất bại
    _users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "last_login": datetime.utcnow(),
                "login_attempts": 0
            }
        }
    )
    
    # Chuẩn bị dữ liệu người dùng cho response
    # Loại bỏ thông tin nhạy cảm như password_hash
    user_data = {
        "_id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user.get("role", UserRole.VIEWER)
    }
    
    # Trả về token và thông tin người dùng
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
    Làm mới access token bằng refresh token.
    Khi access token hết hạn, client gửi refresh token để lấy access token mới.
    
    Request body:
    {
        "refresh_token": "eyJhbGciOiJIUzI1..."
    }
    
    Returns:
        JSON với access token mới
    """
    # Kiểm tra xem request có phải là JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    refresh_token = request.json.get('refresh_token')
    
    # Kiểm tra các trường bắt buộc
    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400
    
    try:
        # Xác thực refresh token
        payload = validate_token(refresh_token)
        
        # Kiểm tra xem có phải refresh token không
        if payload.get('type') != 'refresh':
            return jsonify({"error": "Invalid token type"}), 401
        
        user_id = payload.get('sub')
        
        # Tìm người dùng
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 401
        
        # Kiểm tra trạng thái tài khoản
        if user.get("status") != UserStatus.ACTIVE:
            return jsonify({"error": "Your account is inactive"}), 403
        
        # Tạo access token mới
        access_token = generate_access_token(user_id, user.get("role", UserRole.VIEWER))
        
        # Trả về access token mới
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": _jwt_access_token_expires
        }), 200
        
    except jwt.ExpiredSignatureError:
        # Refresh token đã hết hạn
        return jsonify({"error": "Refresh token has expired", "code": "token_expired"}), 401
    except (jwt.InvalidTokenError, Exception) as e:
        # Refresh token không hợp lệ hoặc lỗi khác
        logger.error(f"Refresh token validation error: {str(e)}")
        return jsonify({"error": "Invalid refresh token"}), 401


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout():
    """
    API đăng xuất người dùng.
    
    Lưu ý: Với JWT, việc đăng xuất ở phía server có hạn chế. Client nên hủy token.
    Endpoint này chủ yếu để mở rộng trong tương lai hoặc theo dõi trạng thái.
    
    Returns:
        JSON xác nhận đăng xuất
    """
    # Trong hệ thống JWT không trạng thái, không có đăng xuất phía server ngoài việc token hết hạn
    # Cải tiến trong tương lai: có thể triển khai cơ chế chặn/thu hồi token
    
    return jsonify({"message": "Successfully logged out"}), 200


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """
    Lấy thông tin hồ sơ người dùng hiện tại.
    
    Returns:
        JSON với dữ liệu hồ sơ người dùng
    """
    user = g.user
    
    # Chuẩn bị dữ liệu hồ sơ người dùng
    # Loại bỏ thông tin nhạy cảm như password_hash
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
    Cập nhật hồ sơ người dùng hiện tại.
    
    Request body:
    {
        "full_name": "Tên Mới",
        "email": "email.moi@example.com",
        "preferences": { "theme": "dark" }
    }
    
    Returns:
        JSON với hồ sơ đã cập nhật
    """
    # Kiểm tra xem request có phải là JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    user_id = ObjectId(g.user_id)
    updates = {}
    
    # Các trường người dùng có thể cập nhật
    if 'full_name' in data:
        updates['full_name'] = data['full_name']
    
    if 'email' in data:
        # Kiểm tra xem email đã được sử dụng chưa
        if _users_collection.find_one({"email": data['email'], "_id": {"$ne": user_id}}):
            return jsonify({"error": "Email is already in use"}), 409
        updates['email'] = data['email']
    
    if 'preferences' in data and isinstance(data['preferences'], dict):
        # Kết hợp với preferences hiện tại
        current_prefs = g.user.get('preferences', {})
        current_prefs.update(data['preferences'])
        updates['preferences'] = current_prefs
    
    if updates:
        updates['updated_at'] = datetime.utcnow()
        
        # Cập nhật người dùng trong database
        result = _users_collection.update_one(
            {"_id": user_id},
            {"$set": updates}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Profile update failed"}), 500
        
        # Lấy dữ liệu người dùng đã cập nhật
        user = _users_collection.find_one({"_id": user_id})
        
        # Chuẩn bị response
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
    Thay đổi mật khẩu người dùng.
    
    Request body:
    {
        "current_password": "mat-khau-hien-tai",
        "new_password": "mat-khau-moi-an-toan"
    }
    
    Returns:
        JSON xác nhận thay đổi mật khẩu
    """
    # Kiểm tra xem request có phải là JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    # Kiểm tra các trường bắt buộc
    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords required"}), 400
    
    user = g.user
    
    # Xác thực mật khẩu hiện tại
    if not bcrypt.checkpw(current_password.encode('utf-8'), user.get('password_hash', '').encode('utf-8')):
        return jsonify({"error": "Current password is incorrect"}), 401
    
    # Xác thực độ mạnh của mật khẩu mới
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    # Mã hóa mật khẩu mới
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Cập nhật mật khẩu trong database
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


# ======== Các Route Quản lý Người dùng (Chỉ Admin) ========

@users_bp.route('', methods=['GET'])
@token_required
@admin_required
def list_users():
    """
    Liệt kê tất cả người dùng. Chỉ dành cho Admin.
    
    Query parameters:
    - limit: Số lượng người dùng tối đa trả về (mặc định: 100)
    - skip: Số lượng người dùng bỏ qua (mặc định: 0)
    - status: Lọc theo trạng thái tài khoản
    - role: Lọc theo vai trò
    
    Returns:
        JSON với danh sách người dùng
    """
    # Phân tích tham số truy vấn
    limit = min(int(request.args.get('limit', 100)), 100)  # Giới hạn tối đa 100 người dùng
    skip = int(request.args.get('skip', 0))
    status = request.args.get('status')
    role = request.args.get('role')
    
    # Xây dựng truy vấn
    query = {}
    if status:
        query['status'] = status
    if role:
        query['role'] = role
    
    # Thực hiện truy vấn
    users = _users_collection.find(query).sort([("username", 1)]).skip(skip).limit(limit)
    total = _users_collection.count_documents(query)
    
    # Định dạng dữ liệu người dùng
    # Loại bỏ thông tin nhạy cảm và chuyển ObjectId thành chuỗi
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
    Tạo người dùng mới. Chỉ dành cho Admin.
    
    Request body:
    {
        "username": "taikhoanmoi",
        "email": "user@example.com",
        "password": "matkhauantoan",
        "full_name": "Người Dùng Mới",
        "role": "viewer"
    }
    
    Returns:
        JSON với dữ liệu người dùng đã tạo
    """
    # Kiểm tra xem request có phải là JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    
    # Xác thực các trường bắt buộc
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Xác thực username
    username = data['username']
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400
    
    # Kiểm tra xem username đã được sử dụng chưa
    if _users_collection.find_one({"username": username}):
        return jsonify({"error": "Username is already taken"}), 409
    
    # Xác thực email
    email = data['email']
    
    # Kiểm tra xem email đã đăng ký chưa
    if _users_collection.find_one({"email": email}):
        return jsonify({"error": "Email is already registered"}), 409
    
    # Xác thực vai trò
    role = data.get('role', UserRole.VIEWER)
    if role not in [r.value for r in UserRole]:
        return jsonify({"error": f"Invalid role: {role}"}), 400
    
    # Xác thực mật khẩu
    password = data['password']
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    # Mã hóa mật khẩu
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Chuẩn bị document người dùng
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
        # Thêm người dùng vào database
        result = _users_collection.insert_one(new_user)
        new_user_id = result.inserted_id
        
        # Lấy người dùng đã tạo
        created_user = _users_collection.find_one({"_id": new_user_id})
        
        # Định dạng dữ liệu người dùng cho response
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
    Lấy thông tin chi tiết người dùng.
    
    Người dùng thông thường chỉ có thể xem thông tin của chính họ.
    Admin có thể xem thông tin của bất kỳ người dùng nào.
    
    Args:
        user_id: ID người dùng
    
    Returns:
        JSON với thông tin chi tiết người dùng
    """
    try:
        # Kiểm tra xem người dùng có đang yêu cầu thông tin của chính họ hoặc là admin
        is_admin = g.user_role == UserRole.ADMIN
        is_self = g.user_id == user_id
        
        if not is_admin and not is_self:
            return jsonify({"error": "Permission denied"}), 403
        
        # Tìm người dùng
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Định dạng dữ liệu người dùng
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
        
        # Thông tin bổ sung cho admin
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
    Cập nhật thông tin người dùng.
    
    Người dùng thông thường chỉ có thể cập nhật thông tin của chính họ và chỉ một số trường nhất định.
    Admin có thể cập nhật bất kỳ người dùng nào và tất cả các trường.
    
    Args:
        user_id: ID người dùng
    
    Request body:
    {
        "email": "email.moi@example.com",
        "full_name": "Tên Đã Cập Nhật",
        "role": "operator",
        "status": "active"
    }
    
    Returns:
        JSON với thông tin người dùng đã cập nhật
    """
    # Kiểm tra xem request có phải là JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    
    try:
        # Kiểm tra xem người dùng có đang cập nhật thông tin của chính họ hoặc là admin
        is_admin = g.user_role == UserRole.ADMIN
        is_self = g.user_id == user_id
        
        if not is_admin and not is_self:
            return jsonify({"error": "Permission denied"}), 403
        
        # Tìm người dùng
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Chuẩn bị các cập nhật
        updates = {}
        
        # Các trường mà người dùng thông thường có thể cập nhật cho chính họ
        if 'email' in data:
            # Kiểm tra xem email đã được sử dụng chưa
            if _users_collection.find_one({"email": data['email'], "_id": {"$ne": ObjectId(user_id)}}):
                return jsonify({"error": "Email is already in use"}), 409
            updates['email'] = data['email']
        
        if 'full_name' in data:
            updates['full_name'] = data['full_name']
        
        # Các trường chỉ dành cho admin
        if is_admin:
            if 'role' in data:
                # Ngăn chặn việc xóa admin cuối cùng
                if user.get('role') == UserRole.ADMIN and data['role'] != UserRole.ADMIN:
                    admin_count = _users_collection.count_documents({"role": UserRole.ADMIN})
                    if admin_count <= 1:
                        return jsonify({"error": "Cannot remove last administrator"}), 400
                updates['role'] = data['role']
            
            if 'status' in data:
                # Ngăn chặn việc vô hiệu hóa admin cuối cùng
                if user.get('role') == UserRole.ADMIN and data['status'] != UserStatus.ACTIVE:
                    active_admin_count = _users_collection.count_documents({
                        "role": UserRole.ADMIN, 
                        "status": UserStatus.ACTIVE
                    })
                    if active_admin_count <= 1:
                        return jsonify({"error": "Cannot deactivate last administrator"}), 400
                updates['status'] = data['status']
        
        # Áp dụng các cập nhật nếu có
        if updates:
            updates['updated_at'] = datetime.utcnow()
            
            result = _users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": updates}
            )
            
            if result.modified_count == 0:
                return jsonify({"error": "Failed to update user"}), 500
            
            # Lấy người dùng đã cập nhật
            updated_user = _users_collection.find_one({"_id": ObjectId(user_id)})
            
            # Định dạng dữ liệu người dùng cho response
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
    Xóa người dùng. Chỉ dành cho Admin.
    
    Args:
        user_id: ID người dùng cần xóa
    
    Returns:
        JSON xác nhận xóa
    """
    try:
        # Kiểm tra xem có đang cố gắng xóa chính mình không
        if g.user_id == user_id:
            return jsonify({"error": "Cannot delete your own account"}), 400
        
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Ngăn chặn xóa admin cuối cùng
        if user.get('role') == UserRole.ADMIN:
            admin_count = _users_collection.count_documents({"role": UserRole.ADMIN})
            if admin_count <= 1:
                return jsonify({"error": "Cannot delete the last administrator"}), 400
        
        # Xóa người dùng
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
    Đặt lại mật khẩu người dùng. Chỉ dành cho Admin.
    
    Args:
        user_id: ID người dùng
    
    Request body:
    {
        "new_password": "mat-khau-moi-an-toan"  # Tùy chọn, tự động tạo nếu không cung cấp
    }
    
    Returns:
        JSON với mật khẩu mới (nếu tự động tạo) hoặc xác nhận
    """
    try:
        # Tìm người dùng
        user = _users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        data = request.json or {}
        new_password = data.get('new_password')
        
        # Tạo mật khẩu ngẫu nhiên nếu không được cung cấp
        if not new_password:
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits
            new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
            password_was_generated = True
        else:
            # Xác thực mật khẩu được cung cấp
            if len(new_password) < 8:
                return jsonify({"error": "Password must be at least 8 characters long"}), 400
            password_was_generated = False
        
        # Mã hóa mật khẩu mới
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Cập nhật mật khẩu trong database
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


# ======== Các Hàm Hỗ Trợ ========

def _create_default_admin(app):
    """
    Tạo người dùng admin mặc định nếu chưa tồn tại.
    
    Args:
        app: Ứng dụng Flask với cấu hình
    """
    default_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
    default_password = app.config.get('DEFAULT_ADMIN_PASSWORD')
    default_email = app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    
    # Tạo mật khẩu ngẫu nhiên nếu không được cung cấp
    if not default_password:
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        default_password = ''.join(secrets.choice(alphabet) for _ in range(12))
    
    # Mã hóa mật khẩu
    hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Tạo người dùng admin
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