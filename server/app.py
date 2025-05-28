"""
Main Flask application with MVC architecture
"""

# ✅ QUAN TRỌNG: Monkey patch PHẢI ở đầu tiên, trước tất cả imports khác
import eventlet
eventlet.monkey_patch()

import os
import sys
import logging
from datetime import datetime

# ✅ Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS

# ✅ Import từ config.py (không phải database/config.py)
from database.config import get_config, get_mongo_client, get_database, validate_config, close_mongo_client

# ✅ Import MVC components với absolute imports
from models.whitelist_model import WhitelistModel
from models.agent_model import AgentModel
from models.log_model import LogModel

from services.whitelist_service import WhitelistService
from services.agent_service import AgentService
from services.log_service import LogService

from controllers.whitelist_controller import WhitelistController
from controllers.agent_controller import AgentController
from controllers.log_controller import LogController

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Create Flask application with MVC architecture"""
    
    # Create Flask app
    app = Flask(__name__, 
                static_folder='views/static',
                template_folder='views/templates')
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # ✅ Add template filters
    @app.template_filter('format_datetime')
    def format_datetime_filter(dt, format='%Y-%m-%d %H:%M:%S'):
        """Format datetime for template"""
        if dt is None:
            return 'N/A'
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except:
                return dt
        return dt.strftime(format)
    
    # Validate configuration
    if not validate_config(config):
        raise RuntimeError("Invalid configuration")
    
    # Setup CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": ["*"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Initialize SocketIO
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='eventlet',
        logger=False,
        engineio_logger=False
    )
    
    # Initialize database
    try:
        db = get_database(config)
        app.logger.info(f"✅ MongoDB connected: {config.MONGO_DBNAME}")
        
    except Exception as e:
        app.logger.error(f"❌ MongoDB connection failed: {e}")
        raise
    
    # Initialize MVC components
    # Models
    whitelist_model = WhitelistModel(db)
    agent_model = AgentModel(db)
    log_model = LogModel(db)
    
    # Services
    whitelist_service = WhitelistService(whitelist_model, socketio)
    agent_service = AgentService(agent_model, db, socketio)
    log_service = LogService(log_model, socketio)
    
    # Controllers
    whitelist_controller = WhitelistController(whitelist_model, whitelist_service, socketio)
    agent_controller = AgentController(agent_model, agent_service, socketio)
    log_controller = LogController(log_model, log_service, socketio)
    
    # ✅ Register MVC blueprints với correct prefixes
    app.register_blueprint(whitelist_controller.blueprint, url_prefix='/api/whitelist')
    app.register_blueprint(agent_controller.blueprint, url_prefix='/api/agents')
    app.register_blueprint(log_controller.blueprint, url_prefix='/api')  # Chỉ /api, không /api/logs
    
    # Register application routes
    register_main_routes(app, log_service, agent_service)
    register_error_handlers(app)
    register_socketio_events(socketio)
    
    # Store instances
    app.config_instance = config
    app.socketio = socketio
    app.log_service = log_service
    app.agent_service = agent_service
    
    app.logger.info("🚀 MVC Application initialized successfully")
    return app, socketio

def register_main_routes(app, log_service, agent_service):
    """Register main web routes"""
    
    @app.route('/')
    def index():
        """Dashboard route with statistics"""
        try:
            # Get dashboard statistics
            stats = {
                'total_logs': 0,
                'allowed_count': 0,
                'blocked_count': 0,
                'active_agents': 0
            }
            
            recent_logs = []
            
            # Try to get real statistics
            try:
                # Get log statistics
                stats['total_logs'] = log_service.get_total_count()
                stats['allowed_count'] = log_service.get_count_by_action('allow')
                stats['blocked_count'] = log_service.get_count_by_action('block')
                
                # ✅ FIX: Get active agents count properly
                agent_stats = agent_service.calculate_statistics()
                stats['active_agents'] = agent_stats.get('active', 0)
                
                # Get recent logs (last 10)
                recent_logs = log_service.get_recent_logs(limit=10)
                
            except Exception as e:
                app.logger.warning(f"Could not fetch dashboard stats: {e}")
                # Use default values (zeros)
            
            return render_template('dashboard.html', 
                                 page_title="Dashboard", 
                                 stats=stats,
                                 recent_logs=recent_logs)
                                 
        except Exception as e:
            app.logger.error(f"Dashboard error: {e}")
            return render_template('dashboard.html', 
                                 page_title="Dashboard", 
                                 stats={'total_logs': 0, 'allowed_count': 0, 'blocked_count': 0, 'active_agents': 0},
                                 recent_logs=[])
    
    @app.route('/agents')
    def agents_page():
        return render_template('agents.html', page_title="Agent Management")
    
    @app.route('/whitelist')
    def whitelist_page():
        return render_template('whitelist.html', page_title="Whitelist Management")
    
    @app.route('/logs')
    def logs_page():
        return render_template('logs.html', page_title="System Logs")
    
    @app.route('/api/health')
    def health_check():
        return jsonify({
            "status": "healthy",
            "version": "1.0.0",
            "architecture": "MVC",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    @app.route('/api/config')
    def get_client_config():
        return jsonify({
            "socketio_enabled": True,
            "version": "1.0.0",
            "architecture": "MVC",
            "environment": os.environ.get('FLASK_ENV', 'production')
        }), 200

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({"error": "Not found"}), 404
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def server_error(e):
        app.logger.error(f"Server error: {str(e)}")
        if request.path.startswith('/api/'):
            return jsonify({"error": "Internal server error"}), 500
        return render_template('500.html'), 500

def register_socketio_events(socketio):
    """Register Socket.IO events"""
    
    @socketio.on('connect')
    def handle_connect():
        logger.info(f"Client connected: {request.sid}")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        logger.info(f"Client disconnected: {request.sid}")

if __name__ == "__main__":
    # Create MVC application
    app, socketio = create_app()
    
    # Get configuration
    config = app.config_instance
    
    logger.info(f"🚀 Starting MVC Firewall Controller")
    logger.info(f"🌐 Server: {config.HOST}:{config.PORT}")
    logger.info(f"🏗️  Architecture: Model-View-Controller")
    logger.info(f"🗄️  Database: {config.MONGO_DBNAME}")
    
    try:
        socketio.run(
            app, 
            host=config.HOST, 
            port=config.PORT, 
            debug=config.DEBUG,
            use_reloader=config.DEBUG
        )
    except KeyboardInterrupt:
        logger.info("⏹️  Server stopped by user")
        close_mongo_client()
    except Exception as e:
        logger.error(f"❌ Server error: {str(e)}")
        raise