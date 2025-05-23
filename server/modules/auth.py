"""
Authentication module for Firewall Controller Server.
Simplified to only support admin login and user monitoring.
"""

# Import các thư viện cần thiết
import logging  # Thư viện hỗ trợ ghi log, dùng để theo dõi hoạt động của module
import bcrypt  # Thư viện mã hóa mật khẩu, dùng để băm và xác thực mật khẩu người dùng
from datetime import datetime, timezone  # Thư viện xử lý thời gian, dùng cho token và timestamp
from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for  # Framework Flask để tạo API web

# Import model từ các module khác của dự án
from server.models.user_model import UserRole, UserStatus

# Cấu hình logging cho module này
# Sử dụng logger riêng để dễ dàng lọc log từ module này
logger = logging.getLogger("auth_module")

# Khởi tạo Blueprint cho các route API
# Blueprint giúp tổ chức các route theo nhóm chức năng
auth_bp = Blueprint('auth', __name__)  # Blueprint cho các API xác thực (login, logout)

# Khai báo biến toàn cục
_users_collection = None

def init_app(app, mongo_client, socket_io=None):
    """
    Khởi tạo module auth với ứng dụng Flask và kết nối MongoDB.
    """
    global _users_collection
    
    # Sử dụng database từ cấu hình
    db_name = app.config.get('MONGO_DBNAME', 'Monitoring')
    _db = mongo_client[db_name]
    
    # Collection users
    _users_collection = _db.users
    
    # Tạo index
    _users_collection.create_index([("username", 1)], unique=True)
    
    # Đăng ký blueprint
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    # Tạo tài khoản admin mặc định nếu chưa có
    if _users_collection.count_documents({"role": UserRole.ADMIN}) == 0:
        _create_default_admin(app)
    
    logger.info("Authentication module initialized")


# Route trang đăng nhập
@auth_bp.route('/login', methods=['GET'])
def login_page():
    """Hiển thị trang đăng nhập"""
    return render_template('auth/login.html')


# API đăng nhập
@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Xử lý đăng nhập cho admin.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Tìm người dùng
    user = _users_collection.find_one({"username": username})
    
    if not user:
        logger.warning(f"Login attempt with non-existent username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Kiểm tra có phải admin không
    if user.get("role") != UserRole.ADMIN:
        logger.warning(f"Non-admin user attempted to login: {username}")
        return jsonify({"error": "Only administrators can login"}), 403
    
    # Xác thực mật khẩu
    if not bcrypt.checkpw(password.encode('utf-8'), user.get('password_hash', '').encode('utf-8')):
        logger.warning(f"Failed login attempt for admin: {username}")
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Kiểm tra trạng thái tài khoản
    if user.get("status") != UserStatus.ACTIVE:
        return jsonify({"error": "Your account is inactive"}), 403
    
    # Tạo session
    session['user_id'] = str(user["_id"])
    session['username'] = username
    session['role'] = user.get("role")
    
    # Cập nhật thời gian đăng nhập
    _users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
    
    # Chuẩn bị dữ liệu người dùng
    user_data = {
        "_id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user.get("role")
    }
    
    # Trả về dữ liệu người dùng
    return jsonify({"success": True, "user": user_data}), 200


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    Đăng xuất người dùng.
    """
    session.clear()
    return redirect(url_for('auth.login_page'))


def _create_default_admin(app):
    """
    Tạo người dùng admin mặc định.
    """
    default_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
    default_password = app.config.get('DEFAULT_ADMIN_PASSWORD')
    default_email = app.config.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    
    # Sử dụng mật khẩu mặc định nếu không có trong cấu hình
    if not default_password:
        default_password = "admin123"
        logger.warning(
            "DEFAULT_ADMIN_PASSWORD not found in configuration. "
            "Using insecure default password. "
            "Please set a strong password in your .env file!"
        )
    
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
        "created_at": datetime.now(timezone.utc)
    }
    
    try:
        _users_collection.insert_one(admin_user)
        logger.info(f"Created default admin user: {default_username}")
        if default_password == "admin123":
            logger.warning("Default admin password is being used. Please change it immediately!")
        else:
            logger.info("Admin user created with configured password")
    except Exception as e:
        logger.error(f"Error creating default admin: {str(e)}")