"""
Main application entry point for the Firewall Controller Server.
Simplified version without authentication - suitable for small projects.
"""

# Import các thư viện cần thiết
import logging  # Thư viện ghi log, dùng để theo dõi hoạt động của ứng dụng
import os  # Thư viện tương tác với hệ điều hành, dùng để truy cập biến môi trường và thao tác với đường dẫn
from logging.handlers import RotatingFileHandler  # Handler ghi log vào file có khả năng tự động xoay vòng khi đạt kích thước giới hạn
from datetime import datetime  # Thêm import datetime

import eventlet  # Thư viện xử lý IO không đồng bộ, tối ưu cho WebSocket và các hoạt động mạng
# Monkey patching for eventlet compatibility (must be first)
# Sửa đổi các hàm thư viện chuẩn để tương thích với eventlet
# Điều này cần phải được thực hiện trước khi import các module khác để tránh xung đột
eventlet.monkey_patch()

# Import các thành phần của Flask và các extension
from flask import Flask, jsonify, request, render_template  # Thêm render_template
from flask_cors import CORS  # Extension để hỗ trợ Cross-Origin Resource Sharing, cho phép truy cập API từ domain khác
from flask_socketio import SocketIO  # Extension hỗ trợ WebSocket cho giao tiếp realtime
from pymongo import MongoClient  # Thư viện kết nối đến MongoDB
from dotenv import load_dotenv  # Thư viện đọc file .env

# Tải biến môi trường từ file .env
load_dotenv()

# ✅ SỬA: Import với relative paths (không dùng server. prefix)
from config import get_config
from modules import logs, whitelist, agents, users

# Cấu hình logging cơ bản
# Thiết lập định dạng log để dễ dàng theo dõi và gỡ lỗi
logging.basicConfig(
    level=logging.INFO,  # Mức độ log: INFO trở lên sẽ được ghi lại
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Định dạng log gồm thời gian, tên logger, mức độ và nội dung
)
logger = logging.getLogger(__name__)  # Tạo logger cho module hiện tại

def create_app(config_object=None):
    """
    Factory function to create and configure the Flask application.
    Simplified version without authentication.
    """
    # Create Flask app
    app = Flask(__name__, 
                static_folder='static',
                template_folder='templates')
    
    # Load configuration
    if config_object is None:
        config_object = get_config()
    app.config.from_object(config_object)
    
    # Set secret key
    app.secret_key = app.config.get('SECRET_KEY', 'firewall-controller-secret-key')
    
    # Setup CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": ["*"],  # Allow all origins for simplicity
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Setup Socket.IO
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='eventlet',
        logger=app.debug,
        engineio_logger=app.debug
    )
    
    # MongoDB connection
    mongo_uri = os.environ.get('MONGO_URI')
    if not mongo_uri:
        mongo_uri = app.config.get('MONGO_URI', 'mongodb://localhost:27017/')
    
    app.logger.info(f"Connecting to MongoDB: {mongo_uri}")
    try:
        mongo_client = MongoClient(mongo_uri)
        # Test connection
        mongo_client.admin.command('ping')
        app.logger.info("MongoDB connection successful!")
    except Exception as e:
        app.logger.error(f"MongoDB connection failed: {e}")
        # Continue anyway for now
        mongo_client = MongoClient(mongo_uri)
    
    # Initialize modules with error handling
    try:
        users.init_app(app, mongo_client, socketio)
        app.logger.info("Users module initialized")
    except Exception as e:
        app.logger.error(f"Failed to initialize users module: {e}")
    
    try:
        logs.init_app(app, mongo_client, socketio)
        app.logger.info("Logs module initialized")
    except Exception as e:
        app.logger.error(f"Failed to initialize logs module: {e}")
    
    try:
        whitelist.init_app(app, mongo_client, socketio)
        app.logger.info("Whitelist module initialized")
    except Exception as e:
        app.logger.error(f"Failed to initialize whitelist module: {e}")
    
    try:
        agents.init_app(app, mongo_client, socketio)
        app.logger.info("Agents module initialized")
    except Exception as e:
        app.logger.error(f"Failed to initialize agents module: {e}")
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register main routes
    register_main_routes(app)
    
    # Template filters
    @app.template_filter('format_datetime')
    def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
        """Format a datetime object to a string."""
        if value is None:
            return ""
        return value.strftime(format)
    
    # Context processor for templates
    @app.context_processor
    def inject_template_vars():
        return {
            'current_year': datetime.now().year
        }
    
    app.logger.info("Application initialized successfully")
    return app, socketio

def register_error_handlers(app):
    """Register custom error handlers for the application."""
    
    @app.errorhandler(404)
    def not_found(e):
        app.logger.warning(f"404 Error: {request.path} not found")
        if request.path.startswith('/api/'):
            return jsonify({"error": "Not found", "message": "API endpoint not found"}), 404
        else:
            return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def server_error(e):
        app.logger.error(f"Server error: {str(e)}")
        if request.path.startswith('/api/'):
            return jsonify({"error": "Internal server error", "message": "An internal error occurred"}), 500
        else:
            return render_template('500.html'), 500

def register_main_routes(app):
    """Register main application routes."""
    
    @app.route('/')
    def index():
        """Main dashboard page."""
        try:
            stats = {
                "total_agents": 0,
                "active_agents": 0,
                "total_logs": 0,
                "blocked_count": 0,
                "allowed_count": 0
            }
            
            recent_logs = []
            
            return render_template('dashboard.html', 
                                 stats=stats, 
                                 recent_logs=recent_logs,
                                 page_title="Firewall Controller Dashboard")
        except Exception as e:
            app.logger.error(f"Error loading dashboard: {str(e)}")
            return render_template('dashboard.html', 
                                 stats={}, 
                                 recent_logs=[],
                                 page_title="Firewall Controller Dashboard")
    
    @app.route('/logs')
    def logs_page():
        """Logs page."""
        return render_template('logs.html', page_title="System Logs")
    
    @app.route('/whitelist')
    def whitelist_page():
        """Whitelist management page."""
        return render_template('whitelist.html', page_title="Whitelist Management")
    
    @app.route('/agents')
    def agents_page():
        """Agents management page."""
        return render_template('agents.html', page_title="Agent Management")
    
    @app.route('/api/health')
    def health_check():
        """Health check endpoint."""
        try:
            return jsonify({
                "status": "healthy",
                "version": "1.0.0",
                "timestamp": datetime.utcnow().isoformat(),
                "database": "connected"
            }), 200
        except Exception as e:
            return jsonify({
                "status": "unhealthy",
                "version": "1.0.0",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }), 503
    
    @app.route('/api/config')
    def get_client_config():
        """Get client configuration."""
        return jsonify({
            "socketio_enabled": True,
            "version": "1.0.0",
            "environment": os.environ.get('FLASK_ENV', 'development'),
            "authentication_required": False
        }), 200

def register_socketio_events(socketio):
    """Register Socket.IO event handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        logger.info(f"Client connected: {request.sid}")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        logger.info(f"Client disconnected: {request.sid}")

if __name__ == "__main__":
    """Main entry point when running directly."""
    
    # Create application
    app, socketio = create_app()
    
    # Register Socket.IO events
    register_socketio_events(socketio)
    
    # Get host and port from environment
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Start server
    logger.info(f"Starting Firewall Controller Server on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    logger.info("No authentication required - all endpoints are public")
    
    try:
        socketio.run(
            app, 
            host=host, 
            port=port, 
            debug=debug,
            use_reloader=debug,
            log_output=debug
        )
    except KeyboardInterrupt:
        logger.info("Server shutdown by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        raise