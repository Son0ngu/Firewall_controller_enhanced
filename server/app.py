"""
Main application entry point for the Firewall Controller Server.

This module initializes and configures the Flask application, sets up database connections,
registers blueprints, initializes components like SocketIO, and provides the application runner.
"""

# Import các thư viện cần thiết
import logging  # Thư viện ghi log, dùng để theo dõi hoạt động của ứng dụng
import os  # Thư viện tương tác với hệ điều hành, dùng để truy cập biến môi trường và thao tác với đường dẫn
from logging.handlers import RotatingFileHandler  # Handler ghi log vào file có khả năng tự động xoay vòng khi đạt kích thước giới hạn

import eventlet  # Thư viện xử lý IO không đồng bộ, tối ưu cho WebSocket và các hoạt động mạng
# Patch standard library for eventlet compatibility (must be first)
# Monkey patching: Sửa đổi các hàm thư viện chuẩn để tương thích với eventlet
# Điều này cần phải được thực hiện trước khi import các module khác để tránh xung đột
eventlet.monkey_patch()

# Import các thành phần của Flask và các extension
from flask import Flask, jsonify, request  # Framework web Flask cơ bản và các tiện ích
from flask_cors import CORS  # Extension để hỗ trợ Cross-Origin Resource Sharing, cho phép truy cập API từ domain khác
from flask_socketio import SocketIO  # Extension hỗ trợ WebSocket cho giao tiếp realtime
from pymongo import MongoClient  # Thư viện kết nối đến MongoDB

# Import các module tự định nghĩa từ dự án
from server.config import get_config  # Hàm lấy cấu hình ứng dụng
from server.modules import auth, logs, whitelist, agents  # Các module chức năng của hệ thống

# Cấu hình logging cơ bản
# Thiết lập định dạng log để dễ dàng theo dõi và gỡ lỗi
logging.basicConfig(level=logging.INFO,  # Mức độ log: INFO trở lên sẽ được ghi lại
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')  # Định dạng log gồm thời gian, tên logger, mức độ và nội dung
logger = logging.getLogger(__name__)  # Tạo logger cho module hiện tại

# Tạo đối tượng Flask application
# static_folder: thư mục chứa các file tĩnh như CSS, JavaScript, hình ảnh
# template_folder: thư mục chứa các template HTML
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')

def create_app(config_object=None):
    """
    Factory function to create and configure the Flask application.
    Hàm tạo và cấu hình ứng dụng Flask theo mẫu Factory Pattern.
    
    Args:
        config_object: Đối tượng cấu hình (mặc định lấy từ hàm get_config())
    
    Returns:
        Đối tượng ứng dụng Flask đã được cấu hình
    """
    global app  # Sử dụng biến app toàn cục đã được khai báo ở trên
    
    # Load cấu hình cho ứng dụng
    # Nếu không có config_object được cung cấp, sử dụng cấu hình mặc định từ get_config()
    if config_object is None:
        config_object = get_config()
    app.config.from_object(config_object)  # Áp dụng cấu hình vào app
    
    # Cấu hình logging chi tiết
    # Chỉ thiết lập khi không ở chế độ debug hoặc testing
    # Điều này giúp tránh log trùng lặp trong quá trình phát triển
    if not app.debug and not app.testing:
        # Tạo thư mục logs nếu chưa tồn tại
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Tạo RotatingFileHandler để ghi log vào file
        # Tự động tạo file log mới khi file hiện tại đạt kích thước giới hạn
        file_handler = RotatingFileHandler(
            os.path.join('logs', app.config['LOG_FILE']),  # Đường dẫn file log
            maxBytes=app.config['LOG_MAX_BYTES'],  # Kích thước tối đa cho mỗi file log
            backupCount=app.config['LOG_BACKUP_COUNT']  # Số lượng file log cũ được giữ lại
        )
        # Thiết lập định dạng và mức độ log
        file_handler.setFormatter(logging.Formatter(app.config['LOG_FORMAT']))
        file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.addHandler(file_handler)  # Thêm handler vào logger của Flask
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))  # Thiết lập mức độ log cho Flask logger
    
    # Thiết lập CORS (Cross-Origin Resource Sharing)
    # Cho phép frontend từ các domain khác truy cập API
    CORS(app, resources={
        r"/api/*": {  # Áp dụng CORS cho tất cả các endpoint bắt đầu bằng /api/
            "origins": app.config['CORS_ORIGINS'],  # Các domain được phép truy cập API
            "methods": app.config['CORS_METHODS'],  # Các phương thức HTTP được phép
            "allow_headers": app.config['CORS_ALLOW_HEADERS'],  # Các header được phép gửi lên
            "expose_headers": app.config['CORS_EXPOSE_HEADERS'],  # Các header được phép trả về client
            "supports_credentials": app.config['CORS_SUPPORTS_CREDENTIALS']  # Cho phép gửi cookie trong request
        }
    })
    
    # Thiết lập Socket.IO với CORS được cấu hình
    # Socket.IO được sử dụng cho giao tiếp realtime giữa client và server
    socketio = SocketIO(
        app, 
        cors_allowed_origins=app.config['SOCKETIO_CORS_ALLOWED_ORIGINS'],  # Các domain được phép kết nối WebSocket
        async_mode=app.config['SOCKETIO_ASYNC_MODE'],  # Chế độ không đồng bộ (eventlet)
        logger=True,  # Bật logging cho SocketIO
        engineio_logger=app.debug  # Chỉ bật engineio logger trong chế độ debug
    )
    
    # Kết nối đến MongoDB
    # Đây là cơ sở dữ liệu chính của ứng dụng
    mongo_uri = app.config.get('MONGO_URI')
    if not mongo_uri:
        if app.config['TESTING']:
            # Sử dụng MongoDB giả lập trong bộ nhớ cho unit test
            mongo_uri = "mongomock://localhost/firewall_controller_test"
        else:
            # Sử dụng MongoDB local nếu không có URI được cấu hình
            mongo_uri = "mongodb://localhost:27017/firewall_controller"
    
    # Tạo kết nối đến MongoDB
    mongo_client = MongoClient(mongo_uri)
    
    # Khởi tạo các module với Flask app, MongoDB client và SocketIO
    # Mỗi module này đảm nhận một phần chức năng của hệ thống
    auth.init_app(app, mongo_client, socketio)  # Module xác thực và quản lý người dùng
    logs.init_app(app, mongo_client, socketio)  # Module quản lý logs từ các agent và hệ thống
    whitelist.init_app(app, mongo_client, socketio)  # Module quản lý danh sách các domain được phép
    agents.init_app(app, mongo_client, socketio)  # Module quản lý các agent được cài đặt trên máy client
    
    # Đăng ký các handler xử lý lỗi cho ứng dụng
    register_error_handlers(app)
    
    # Đăng ký các route chính của ứng dụng
    register_main_routes(app)
    
    # Ghi log xác nhận ứng dụng đã được khởi tạo thành công
    app.logger.info("Application initialized successfully")
    
    # Trả về đối tượng app đã được cấu hình và socketio để sử dụng sau này
    return app, socketio


def register_error_handlers(app):
    """
    Đăng ký các handler xử lý lỗi tùy chỉnh cho ứng dụng.
    Các handler này sẽ định dạng lỗi HTTP thành JSON để client dễ dàng xử lý.
    """
    
    @app.errorhandler(400)
    def bad_request(e):
        """Handler cho lỗi Bad Request (400) - Request không hợp lệ"""
        return jsonify({"error": "Bad request", "message": str(e)}), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        """Handler cho lỗi Unauthorized (401) - Chưa xác thực"""
        return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        """Handler cho lỗi Forbidden (403) - Không có quyền truy cập"""
        return jsonify({"error": "Forbidden", "message": "You don't have permission to access this resource"}), 403
    
    @app.errorhandler(404)
    def not_found(e):
        """Handler cho lỗi Not Found (404) - Không tìm thấy tài nguyên"""
        return jsonify({"error": "Not found", "message": "Resource not found"}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(e):
        """Handler cho lỗi Method Not Allowed (405) - Phương thức HTTP không được phép"""
        return jsonify({"error": "Method not allowed", "message": "The method is not allowed for this resource"}), 405
    
    @app.errorhandler(429)
    def too_many_requests(e):
        """Handler cho lỗi Too Many Requests (429) - Quá nhiều request trong một khoảng thời gian"""
        return jsonify({"error": "Too many requests", "message": "Rate limit exceeded"}), 429
    
    @app.errorhandler(500)
    def server_error(e):
        """Handler cho lỗi Internal Server Error (500) - Lỗi nội bộ server"""
        # Ghi log lỗi để theo dõi và gỡ lỗi sau này
        app.logger.error(f"Server error: {str(e)}")
        return jsonify({"error": "Internal server error", "message": "An internal error occurred"}), 500


def register_main_routes(app):
    """
    Đăng ký các route chính của ứng dụng.
    Bao gồm các endpoint cơ bản như trang chủ, kiểm tra sức khỏe và cấu hình client.
    """
    
    @app.route('/', methods=['GET'])
    def index():
        """
        Route trang chủ của ứng dụng.
        Trả về file index.html từ thư mục static.
        """
        return app.send_static_file('index.html')
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """
        Endpoint kiểm tra sức khỏe của API.
        Được sử dụng bởi các hệ thống giám sát hoặc cân bằng tải để kiểm tra trạng thái hoạt động.
        """
        return jsonify({"status": "ok", "version": "1.0.0"}), 200
    
    @app.route('/api/config', methods=['GET'])
    def get_client_config():
        """
        Endpoint cung cấp cấu hình cho client.
        Chỉ trả về các cài đặt công khai, an toàn cho client biết.
        """
        return jsonify({
            "socketio_enabled": True,  # Cho client biết WebSocket được bật
            "version": "1.0.0",  # Phiên bản của ứng dụng
            "environment": os.environ.get('FLASK_ENV', 'development')  # Môi trường hiện tại (development, production...)
        }), 200


if __name__ == "__main__":
    """
    Điểm khởi chạy chính của ứng dụng khi được chạy trực tiếp (python app.py).
    Không được thực thi khi ứng dụng được import từ module khác.
    """
    # Tạo đối tượng ứng dụng
    app, socketio = create_app()
    
    # Lấy host và port từ biến môi trường hoặc sử dụng giá trị mặc định
    host = os.environ.get('HOST', '0.0.0.0')  # Mặc định lắng nghe trên tất cả các interface
    port = int(os.environ.get('PORT', 5000))  # Cổng mặc định 5000
    
    # Chạy ứng dụng với hỗ trợ Socket.IO
    logger.info(f"Starting server on {host}:{port}")  # Ghi log thông báo khởi động
    socketio.run(app, host=host, port=port, debug=app.debug)  # Khởi chạy server với SocketIO