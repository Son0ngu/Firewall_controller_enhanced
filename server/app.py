"""
Main application entry point for the Firewall Controller Server.

This module initializes and configures the Flask application, sets up database connections,
registers blueprints, initializes components like SocketIO, and provides the application runner.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

import eventlet
# Patch standard library for eventlet compatibility (must be first)
eventlet.monkey_patch()

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from pymongo import MongoClient

from server.config import get_config
from server.modules import auth, logs, whitelist, agents

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')

def create_app(config_object=None):
    """
    Factory function to create and configure the Flask application.
    
    Args:
        config_object: Configuration object (defaults to config from get_config())
    
    Returns:
        Flask application instance
    """
    global app
    
    # Load configuration
    if config_object is None:
        config_object = get_config()
    app.config.from_object(config_object)
    
    # Configure logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler(
            os.path.join('logs', app.config['LOG_FILE']),
            maxBytes=app.config['LOG_MAX_BYTES'],
            backupCount=app.config['LOG_BACKUP_COUNT']
        )
        file_handler.setFormatter(logging.Formatter(app.config['LOG_FORMAT']))
        file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
    
    # Set up CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": app.config['CORS_METHODS'],
            "allow_headers": app.config['CORS_ALLOW_HEADERS'],
            "expose_headers": app.config['CORS_EXPOSE_HEADERS'],
            "supports_credentials": app.config['CORS_SUPPORTS_CREDENTIALS']
        }
    })
    
    # Set up Socket.IO with CORS configured
    socketio = SocketIO(
        app, 
        cors_allowed_origins=app.config['SOCKETIO_CORS_ALLOWED_ORIGINS'],
        async_mode=app.config['SOCKETIO_ASYNC_MODE'],
        logger=True,
        engineio_logger=app.debug
    )
    
    # Connect to MongoDB
    mongo_uri = app.config.get('MONGO_URI')
    if not mongo_uri:
        if app.config['TESTING']:
            # Use in-memory MongoDB mock for tests
            mongo_uri = "mongomock://localhost/firewall_controller_test"
        else:
            mongo_uri = "mongodb://localhost:27017/firewall_controller"
    
    mongo_client = MongoClient(mongo_uri)
    
    # Initialize modules with Flask app
    auth.init_app(app, mongo_client, socketio)
    logs.init_app(app, mongo_client, socketio)
    whitelist.init_app(app, mongo_client, socketio)
    agents.init_app(app, mongo_client, socketio)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register main routes
    register_main_routes(app)
    
    app.logger.info("Application initialized successfully")
    
    return app, socketio


def register_error_handlers(app):
    """Register custom error handlers for the application."""
    
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request", "message": str(e)}), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Forbidden", "message": "You don't have permission to access this resource"}), 403
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found", "message": "Resource not found"}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed", "message": "The method is not allowed for this resource"}), 405
    
    @app.errorhandler(429)
    def too_many_requests(e):
        return jsonify({"error": "Too many requests", "message": "Rate limit exceeded"}), 429
    
    @app.errorhandler(500)
    def server_error(e):
        app.logger.error(f"Server error: {str(e)}")
        return jsonify({"error": "Internal server error", "message": "An internal error occurred"}), 500


def register_main_routes(app):
    """Register main application routes."""
    
    @app.route('/', methods=['GET'])
    def index():
        """Main application page."""
        return app.send_static_file('index.html')
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """API health check endpoint."""
        return jsonify({"status": "ok", "version": "1.0.0"}), 200
    
    @app.route('/api/config', methods=['GET'])
    def get_client_config():
        """Get client-side configuration (public settings only)."""
        return jsonify({
            "socketio_enabled": True,
            "version": "1.0.0",
            "environment": os.environ.get('FLASK_ENV', 'development')
        }), 200


if __name__ == "__main__":
    # Create the application
    app, socketio = create_app()
    
    # Get the host and port from environment or use defaults
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application with Socket.IO support
    logger.info(f"Starting server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=app.debug)