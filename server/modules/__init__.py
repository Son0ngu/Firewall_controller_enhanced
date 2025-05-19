"""
Modules package for the Firewall Controller Server.

This package contains the core functional modules of the application:
- auth: Authentication and authorization
- logs: Log collection and management
- whitelist: Domain whitelist management
- users: User account management
- agents: Agent registration and communication
"""

# Re-export key components from modules to provide a cleaner API
from server.modules.auth import (
    init_app as init_auth, 
    token_required, 
    admin_required, 
    operator_required
)
from server.modules.logs import init_app as init_logs
from server.modules.whitelist import init_app as init_whitelist
from server.modules.users import init_app as init_users
from server.modules.agents import init_app as init_agents

# Define a simple function to initialize all modules
def init_all_modules(app, mongo_client, socketio):
    """
    Initialize all application modules.
    
    Args:
        app: Flask application instance
        mongo_client: MongoDB client connection
        socketio: Flask-SocketIO instance
    """
    init_auth(app, mongo_client, socketio)
    init_logs(app, mongo_client, socketio)
    init_whitelist(app, mongo_client, socketio)
    init_users(app, mongo_client, socketio)
    init_agents(app, mongo_client, socketio)

# Define what should be exported with "from server.modules import *"
__all__ = [
    'init_all_modules',
    'init_auth', 'token_required', 'admin_required', 'operator_required',
    'init_logs', 'init_whitelist', 'init_users', 'init_agents'
]