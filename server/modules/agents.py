"""
Agent Management module for the Firewall Controller Server.
"""

# Import các thư viện cần thiết
import logging  # Thư viện ghi log, giúp theo dõi hoạt động của module
import secrets  # Thư viện tạo token bảo mật
import uuid  # Thư viện tạo ID độc nhất
from datetime import datetime, timedelta  # Thư viện xử lý thời gian, cho timestamps và tính toán thời gian
from typing import Dict, List, Optional  # Thư viện kiểu dữ liệu tĩnh

from bson import ObjectId  # Thư viện làm việc với MongoDB ObjectId
from flask import Blueprint, jsonify, request  # Framework Flask để tạo API
from flask_socketio import SocketIO  # Thư viện hỗ trợ WebSocket cho giao tiếp realtime
from pymongo import MongoClient, DESCENDING  # Thư viện kết nối MongoDB và hằng số sắp xếp
from pymongo.collection import Collection  # Kiểu Collection trong MongoDB
from pymongo.database import Database  # Kiểu Database trong MongoDB

# Cấu hình logging cho module
logger = logging.getLogger("agents_module")

# Khởi tạo Blueprint cho các route API
agents_bp = Blueprint('agents', __name__)

# Biến socketio sẽ được khởi tạo từ bên ngoài với instance Flask-SocketIO
# Dùng để thông báo realtime về trạng thái agent, kết nối, v.v.
socketio: Optional[SocketIO] = None

# Các biến kết nối MongoDB (được khởi tạo trong hàm init_app)
_db: Optional[Database] = None  # Database MongoDB
_agents_collection: Optional[Collection] = None  # Collection lưu thông tin agent

# Khoảng thời gian để xác định một agent không hoạt động (phút)
AGENT_INACTIVE_THRESHOLD = 5

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO = None):
    """
    Khởi tạo module agents với ứng dụng Flask và kết nối MongoDB.
    """
    global _db, _agents_collection, socketio
    
    # Lưu trữ instance SocketIO
    socketio = socket_io
    
    # Sử dụng tên database từ cấu hình
    db_name = app.config.get('MONGO_DBNAME', 'Monitoring')
    _db = mongo_client[db_name]
    
    # Lấy collection agents từ database
    _agents_collection = _db.agents
    
    # Tạo các chỉ mục (index) để tối ưu hiệu suất truy vấn
    _agents_collection.create_index([("agent_id", 1)], unique=True)  # Index theo agent_id, đảm bảo duy nhất
    _agents_collection.create_index([("hostname", 1)])  # Index theo hostname để tìm kiếm nhanh
    _agents_collection.create_index([("last_heartbeat", DESCENDING)])  # Index theo thời gian heartbeat cuối
    _agents_collection.create_index([("status", 1)])  # Index theo trạng thái agent
    
    # Đăng ký blueprint với ứng dụng Flask
    app.register_blueprint(agents_bp, url_prefix='/api/agents')
    
    logger.info("Agents module initialized")


# ======== Các route API ========

@agents_bp.route('/register', methods=['POST'])
def register_agent():
    """
    API đăng ký agent mới hoặc cập nhật thông tin agent đã tồn tại.
    
    Request body:
    {
        "hostname": "laptop-user1",  # Tên máy chủ
        "agent_id": "550e8400-e29b-41d4-a716-446655440000",  # Tùy chọn, tự tạo nếu không có
        "ip_address": "192.168.1.5",  # Địa chỉ IP
        "platform": "Windows",  # Nền tảng hệ điều hành 
        "os_info": "Windows 10 Pro 21H2",  # Thông tin chi tiết hệ điều hành
        "agent_version": "1.0.0",  # Phiên bản agent
        "mac_address": "00:1B:44:11:3A:B7"  # Địa chỉ MAC
    }
    
    Returns:
        JSON với thông tin agent và token xác thực
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not data.get("hostname"):
        return jsonify({"error": "Hostname is required"}), 400

    # ✅ SỬA: Sử dụng IP address làm user_id
    client_ip = request.remote_addr or data.get("ip_address", "unknown")
    agent_id = data.get("agent_id", str(uuid.uuid4()))
    
    try:
        # ✅ THÊM: Tự động tạo/cập nhật user trong users collection
        users_collection = _db.users
        
        # Tìm user hiện có theo IP
        existing_user = users_collection.find_one({"user_id": client_ip, "role": "agent"})
        
        # Tạo user data
        user_data = {
            "user_id": client_ip,  # IP làm user ID
            "hostname": data.get("hostname"),
            "ip_address": client_ip,
            "platform": data.get("platform"),
            "os_info": data.get("os_info"),
            "agent_version": data.get("agent_version"),
            "role": "agent",
            "status": "active",
            "last_heartbeat": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "created_at": datetime.utcnow() if not existing_user else existing_user.get("created_at"),
            "agent_token": secrets.token_hex(32)
        }
        
        if existing_user:
            # Giữ lại token cũ nếu có
            if "agent_token" in existing_user:
                user_data["agent_token"] = existing_user["agent_token"]
            
            # Cập nhật user
            users_collection.update_one(
                {"user_id": client_ip, "role": "agent"},
                {"$set": user_data}
            )
            logger.info(f"Updated agent user: {client_ip} ({data.get('hostname')})")
        else:
            # Tạo user mới
            users_collection.insert_one(user_data)
            logger.info(f"Created new agent user: {client_ip} ({data.get('hostname')})")
        
        # ✅ SỬA: Cập nhật agents collection với user_id
        existing_agent = _agents_collection.find_one({"agent_id": agent_id})
        
        agent_data = {
            "agent_id": agent_id,
            "user_id": client_ip,  # ← Link to user
            "hostname": data.get("hostname"),
            "ip_address": client_ip,
            "mac_address": data.get("mac_address"),
            "platform": data.get("platform"),
            "os_info": data.get("os_info"),
            "agent_version": data.get("agent_version"),
            "status": "active",
            "last_heartbeat": datetime.utcnow(),
            "last_heartbeat_ip": client_ip,
            "agent_token": user_data["agent_token"],
            "registered_date": datetime.utcnow() if not existing_agent else existing_agent.get("registered_date"),
            "updated_date": datetime.utcnow()
        }
        
        if existing_agent:
            _agents_collection.update_one({"agent_id": agent_id}, {"$set": agent_data})
        else:
            _agents_collection.insert_one(agent_data)
            
        # Broadcast notification
        if socketio:
            socketio.emit("agent_registered", {
                "agent_id": agent_id,
                "user_id": client_ip,
                "hostname": data.get("hostname"),
                "status": "active",
                "timestamp": datetime.utcnow().isoformat()
            })
            
        return jsonify({
            "agent_id": agent_id,
            "user_id": client_ip,
            "token": user_data["agent_token"],
            "status": "active",
            "message": "Agent registered successfully",
            "server_time": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error registering agent: {str(e)}")
        return jsonify({"error": "Failed to register agent"}), 500


@agents_bp.route('/heartbeat', methods=['POST'])
def heartbeat():
    """Agent heartbeat - updates both agents and users collections."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not data.get("agent_id") or not data.get("token"):
        return jsonify({"error": "Agent ID and token are required"}), 400
        
    agent_id = data.get("agent_id")
    token = data.get("token")
    client_ip = request.remote_addr
    
    try:
        # Validate agent
        agent = _agents_collection.find_one({"agent_id": agent_id})
        if not agent:
            return jsonify({"error": "Unknown agent"}), 404
            
        if agent.get("agent_token") != token:
            return jsonify({"error": "Invalid token"}), 401
            
        current_time = datetime.utcnow()
        
        # ✅ THÊM: Update user record
        users_collection = _db.users
        user_update = {
            "last_heartbeat": current_time,
            "last_seen": current_time,
            "status": data.get("status", "active"),
            "hostname": data.get("hostname", agent.get("hostname")),
            "platform": data.get("platform", agent.get("platform"))
        }
        
        users_collection.update_one(
            {"user_id": client_ip, "role": "agent"},
            {"$set": user_update},
            upsert=True  # Create if not exists
        )
        
        # Update agent record
        agent_update = {
            "last_heartbeat": current_time,
            "last_heartbeat_ip": client_ip,
            "status": data.get("status", "active"),
            "updated_date": current_time
        }
        
        if "metrics" in data:
            agent_update["metrics"] = data["metrics"]
            
        _agents_collection.update_one(
            {"agent_id": agent_id},
            {"$set": agent_update}
        )
        
        # Broadcast updates
        if socketio:
            socketio.emit("agent_heartbeat", {
                "agent_id": agent_id,
                "user_id": client_ip,
                "hostname": agent.get("hostname"),
                "status": data.get("status", "active"),
                "timestamp": current_time.isoformat()
            })
        
        return jsonify({
            "status": "success",
            "message": "Heartbeat received",
            "server_time": current_time.isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing heartbeat: {str(e)}")
        return jsonify({"error": "Failed to process heartbeat"}), 500


@agents_bp.route('/commands', methods=['GET'])
def get_commands():
    """
    API để agent lấy các lệnh đang chờ xử lý.
    
    Tham số truy vấn:
    - agent_id: ID của agent (bắt buộc)
    - token: Token xác thực của agent (bắt buộc)
    - last_command_id: ID của lệnh cuối cùng đã xử lý (tùy chọn)
    
    Returns:
        JSON với danh sách lệnh cần thực thi
    """
    # Lấy tham số truy vấn
    agent_id = request.args.get('agent_id')
    token = request.args.get('token')
    last_command_id = request.args.get('last_command_id')
    
    # Kiểm tra các tham số bắt buộc
    if not agent_id or not token:
        return jsonify({"error": "Agent ID and token are required"}), 400
        
    try:
        # Tìm agent theo ID
        agent = _agents_collection.find_one({"agent_id": agent_id})
        
        # Kiểm tra xem agent có tồn tại không
        if not agent:
            logger.warning(f"Command request from unknown agent: {agent_id}")
            return jsonify({"error": "Unknown agent"}), 404
            
        # Xác thực token
        if agent.get("agent_token") != token:
            logger.warning(f"Invalid token for agent: {agent_id}")
            return jsonify({"error": "Invalid token"}), 401
            
        # Cập nhật thời gian last_heartbeat
        _agents_collection.update_one(
            {"agent_id": agent_id},
            {"$set": {
                "last_heartbeat": datetime.utcnow(),
                "last_heartbeat_ip": request.remote_addr
            }}
        )
        
        # Tìm các lệnh đang chờ xử lý cho agent này
        # Giả sử có collection "agent_commands" để lưu các lệnh
        command_collection = _db.agent_commands
        query = {
            "agent_id": agent_id,
            "status": "pending"
        }
        
        # Chỉ lấy các lệnh mới hơn last_command_id nếu được cung cấp
        if last_command_id:
            try:
                last_command = command_collection.find_one({"_id": ObjectId(last_command_id)})
                if last_command:
                    query["created_at"] = {"$gt": last_command["created_at"]}
            except:
                pass
                
        # Lấy các lệnh
        commands = list(command_collection.find(query).sort("priority", -1).sort("created_at", 1))
        
        # Chuẩn bị dữ liệu cho response
        command_list = []
        for cmd in commands:
            cmd["_id"] = str(cmd["_id"])
            if "created_at" in cmd:
                cmd["created_at"] = cmd["created_at"].isoformat()
            command_list.append(cmd)
            
        return jsonify({
            "commands": command_list,
            "count": len(command_list),
            "server_time": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving commands: {str(e)}")
        return jsonify({"error": "Failed to retrieve commands"}), 500


@agents_bp.route('/command/result', methods=['POST'])
def update_command_result():
    """
    API để agent báo cáo kết quả thực thi lệnh.
    
    Request body:
    {
        "agent_id": "550e8400-e29b-41d4-a716-446655440000",
        "token": "abc123...",
        "command_id": "5f8d0d55b54764b213d85236",
        "status": "completed",  # completed, failed, processing
        "result": {
            "success": true,
            "message": "Command executed successfully",
            "details": { ... }  # Thông tin chi tiết về kết quả
        },
        "execution_time": 1.5  # Thời gian thực thi (giây)
    }
    
    Returns:
        JSON xác nhận cập nhật thành công
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    
    # Kiểm tra các trường bắt buộc
    required_fields = ["agent_id", "token", "command_id", "status"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
            
    agent_id = data["agent_id"]
    token = data["token"]
    command_id = data["command_id"]
    
    try:
        # Tìm agent theo ID
        agent = _agents_collection.find_one({"agent_id": agent_id})
        
        # Kiểm tra xem agent có tồn tại không
        if not agent:
            logger.warning(f"Command result from unknown agent: {agent_id}")
            return jsonify({"error": "Unknown agent"}), 404
            
        # Xác thực token
        if agent.get("agent_token") != token:
            logger.warning(f"Invalid token for agent: {agent_id}")
            return jsonify({"error": "Invalid token"}), 401
        
        # Chuyển đổi command_id thành ObjectId
        try:
            command_object_id = ObjectId(command_id)
        except:
            return jsonify({"error": "Invalid command ID format"}), 400
            
        # Cập nhật lệnh với kết quả
        command_collection = _db.agent_commands
        command = command_collection.find_one({"_id": command_object_id})
        
        if not command:
            return jsonify({"error": "Command not found"}), 404
            
        # Kiểm tra xem lệnh có thuộc về agent này không
        if command.get("agent_id") != agent_id:
            logger.warning(f"Agent {agent_id} tried to update command for another agent")
            return jsonify({"error": "Command does not belong to this agent"}), 403
            
        # Cập nhật trạng thái và kết quả lệnh
        update_data = {
            "status": data["status"],
            "completed_at": datetime.utcnow(),
            "result": data.get("result"),
            "execution_time": data.get("execution_time")
        }
        
        command_collection.update_one(
            {"_id": command_object_id},
            {"$set": update_data}
        )
        
        # Phát sóng cập nhật lệnh qua SocketIO
        if socketio:
            update_data["command_id"] = command_id
            update_data["agent_id"] = agent_id
            update_data["hostname"] = agent.get("hostname")
            update_data["command_type"] = command.get("command_type")
            update_data["completed_at"] = update_data["completed_at"].isoformat()
            socketio.emit("command_status_update", update_data)
            
        return jsonify({
            "status": "success",
            "message": "Command result updated"
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating command result: {str(e)}")
        return jsonify({"error": "Failed to update command result"}), 500


@agents_bp.route('', methods=['GET'])
def list_agents():
    """
    API để lấy danh sách các agent và trạng thái của chúng.
    Yêu cầu xác thực người dùng.
    
    Tham số truy vấn:
    - status: Lọc theo trạng thái (active, inactive, error)
    - hostname: Lọc theo tên máy chủ (hỗ trợ khớp một phần)
    - limit: Số lượng kết quả tối đa
    - skip: Số lượng kết quả để bỏ qua (phân trang)
    
    Returns:
        JSON với danh sách agent
    """
    try:
        # Phân tích tham số truy vấn
        status = request.args.get('status')
        hostname = request.args.get('hostname')
        limit = min(int(request.args.get('limit', 100)), 1000)  # Tối đa 1000 kết quả
        skip = int(request.args.get('skip', 0))
        
        # Xây dựng truy vấn
        query = {}
        
        # Lọc theo trạng thái
        if status:
            if status == "inactive":
                # Tìm các agent không hoạt động (không có heartbeat trong khoảng thời gian nhất định)
                inactive_threshold = datetime.utcnow() - timedelta(minutes=AGENT_INACTIVE_THRESHOLD)
                query["last_heartbeat"] = {"$lt": inactive_threshold}
            elif status in ["active", "error", "busy"]:
                # Nếu là active, cần kiểm tra thời gian heartbeat gần đây
                if status == "active":
                    inactive_threshold = datetime.utcnow() - timedelta(minutes=AGENT_INACTIVE_THRESHOLD)
                    query["last_heartbeat"] = {"$gte": inactive_threshold}
                # Trạng thái cụ thể khác
                query["status"] = status
        
        # Lọc theo hostname
        if hostname:
            query["hostname"] = {"$regex": hostname, "$options": "i"}
            
        # Thực hiện truy vấn
        cursor = _agents_collection.find(query).sort("hostname").skip(skip).limit(limit)
        
        # Đếm tổng số kết quả
        total_count = _agents_collection.count_documents(query)
        
        # Chuẩn bị dữ liệu cho response
        agents_list = []
        current_time = datetime.utcnow()
        
        for agent in cursor:
            # Tính trạng thái thực tế dựa trên last_heartbeat
            reported_status = agent.get("status", "unknown")
            actual_status = reported_status
            
            # Nếu không có heartbeat gần đây, đánh dấu là inactive bất kể trạng thái reported
            if agent.get("last_heartbeat"):
                time_since_heartbeat = (current_time - agent["last_heartbeat"]).total_seconds() / 60
                if time_since_heartbeat > AGENT_INACTIVE_THRESHOLD:
                    actual_status = "inactive"
            
            # Chuẩn bị dữ liệu agent
            agent_data = {
                "agent_id": agent.get("agent_id"),
                "hostname": agent.get("hostname"),
                "ip_address": agent.get("ip_address"),
                "platform": agent.get("platform"),
                "os_info": agent.get("os_info"),
                "agent_version": agent.get("agent_version"),
                "reported_status": reported_status,
                "status": actual_status,
                "registered_date": agent.get("registered_date").isoformat() if agent.get("registered_date") else None,
                "last_heartbeat": agent.get("last_heartbeat").isoformat() if agent.get("last_heartbeat") else None,
                "metrics": agent.get("metrics")
            }
            
            agents_list.append(agent_data)
            
        return jsonify({
            "agents": agents_list,
            "total": total_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing agents: {str(e)}")
        return jsonify({"error": "Failed to list agents"}), 500


@agents_bp.route('/<agent_id>', methods=['GET'])
def get_agent(agent_id):
    """
    API để lấy thông tin chi tiết về một agent cụ thể.
    Yêu cầu xác thực người dùng.
    
    Args:
        agent_id: ID của agent
    
    Returns:
        JSON với thông tin chi tiết về agent
    """
    try:
        # Tìm agent theo ID
        agent = _agents_collection.find_one({"agent_id": agent_id})
        
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
            
        # Chuẩn bị dữ liệu cho response
        current_time = datetime.utcnow()
        
        # Tính trạng thái thực tế dựa trên last_heartbeat
        reported_status = agent.get("status", "unknown")
        actual_status = reported_status
        
        # Nếu không có heartbeat gần đây, đánh dấu là inactive
        time_since_heartbeat = None
        if agent.get("last_heartbeat"):
            time_since_heartbeat = (current_time - agent["last_heartbeat"]).total_seconds() / 60
            if time_since_heartbeat > AGENT_INACTIVE_THRESHOLD:
                actual_status = "inactive"
        
        # Chuyển đổi các trường thời gian
        registered_date = agent.get("registered_date").isoformat() if agent.get("registered_date") else None
        last_heartbeat = agent.get("last_heartbeat").isoformat() if agent.get("last_heartbeat") else None
        updated_date = agent.get("updated_date").isoformat() if agent.get("updated_date") else None
        
        # Lấy lịch sử metrics
        metrics_history = []
        if agent.get("metrics_history"):
            for entry in agent["metrics_history"]:
                if "timestamp" in entry:
                    entry["timestamp"] = entry["timestamp"].isoformat()
                metrics_history.append(entry)
        
        # Chuẩn bị dữ liệu agent
        agent_data = {
            "agent_id": agent.get("agent_id"),
            "hostname": agent.get("hostname"),
            "ip_address": agent.get("ip_address"),
            "mac_address": agent.get("mac_address"),
            "platform": agent.get("platform"),
            "os_info": agent.get("os_info"),
            "agent_version": agent.get("agent_version"),
            "reported_status": reported_status,
            "status": actual_status,
            "registered_date": registered_date,
            "last_heartbeat": last_heartbeat,
            "updated_date": updated_date,
            "last_heartbeat_ip": agent.get("last_heartbeat_ip"),
            "time_since_heartbeat": time_since_heartbeat,
            "metrics": agent.get("metrics"),
            "metrics_history": metrics_history
        }
        
        # Lấy lệnh gần đây nhất của agent
        command_collection = _db.agent_commands
        recent_commands = list(command_collection.find(
            {"agent_id": agent_id}
        ).sort("created_at", -1).limit(10))
        
        # Định dạng lệnh
        commands = []
        for cmd in recent_commands:
            cmd_data = {
                "command_id": str(cmd["_id"]),
                "command_type": cmd.get("command_type"),
                "status": cmd.get("status"),
                "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None,
                "completed_at": cmd.get("completed_at").isoformat() if cmd.get("completed_at") else None
            }
            commands.append(cmd_data)
            
        agent_data["recent_commands"] = commands
        
        return jsonify(agent_data), 200
        
    except Exception as e:
        logger.error(f"Error retrieving agent details: {str(e)}")
        return jsonify({"error": "Failed to retrieve agent details"}), 500


@agents_bp.route('/<agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    """
    API để xóa một agent khỏi hệ thống.
    Yêu cầu quyền admin.
    
    Args:
        agent_id: ID của agent cần xóa
    
    Returns:
        JSON xác nhận xóa thành công
    """
    try:
        # Tìm agent theo ID
        agent = _agents_collection.find_one({"agent_id": agent_id})
        
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
            
        # Xóa các lệnh liên quan đến agent
        command_collection = _db.agent_commands
        command_collection.delete_many({"agent_id": agent_id})
        
        # Xóa agent
        result = _agents_collection.delete_one({"agent_id": agent_id})
        
        if result.deleted_count:
            # Phát sóng thông báo xóa agent
            if socketio:
                socketio.emit("agent_deleted", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
            return jsonify({
                "status": "success",
                "message": f"Agent {agent_id} deleted successfully"
            }), 200
        else:
            return jsonify({"error": "Failed to delete agent"}), 500
            
    except Exception as e:
        logger.error(f"Error deleting agent: {str(e)}")
        return jsonify({"error": "Failed to delete agent"}), 500


@agents_bp.route('/<agent_id>/command', methods=['POST'])
def send_command(agent_id):
    """
    API để gửi lệnh đến một agent cụ thể.
    Yêu cầu ít nhất quyền operator.
    
    Args:
        agent_id: ID của agent
    
    Request body:
    {
        "command_type": "block_ip",  # Loại lệnh
        "parameters": {  # Các tham số cho lệnh
            "ip": "192.168.1.1"
        },
        "priority": 1,  # Độ ưu tiên (1-5, 5 cao nhất)
        "description": "Block suspicious IP"  # Mô tả lệnh
    }
    
    Returns:
        JSON xác nhận lệnh đã được gửi
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    
    # Kiểm tra các trường bắt buộc
    if not data.get("command_type"):
        return jsonify({"error": "Command type is required"}), 400
        
    try:
        # Tìm agent theo ID
        agent = _agents_collection.find_one({"agent_id": agent_id})
        
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
            
        # Kiểm tra trạng thái agent
        current_time = datetime.utcnow()
        if agent.get("last_heartbeat"):
            time_since_heartbeat = (current_time - agent["last_heartbeat"]).total_seconds() / 60
            if time_since_heartbeat > AGENT_INACTIVE_THRESHOLD:
                return jsonify({
                    "error": "Agent is inactive",
                    "last_heartbeat": agent["last_heartbeat"].isoformat()
                }), 400
        
        # Lấy thông tin người dùng từ token
        username = "admin"  # Fixed username for simplicity
        
        # Chuẩn bị lệnh
        command = {
            "agent_id": agent_id,
            "command_type": data["command_type"],
            "parameters": data.get("parameters", {}),
            "priority": data.get("priority", 1),
            "description": data.get("description", ""),
            "status": "pending",
            "created_by": username,
            "created_at": current_time
        }
        
        # Lưu lệnh vào database
        command_collection = _db.agent_commands
        result = command_collection.insert_one(command)
        
        command_id = str(result.inserted_id)
        
        # Phát sóng thông báo lệnh mới
        if socketio:
            socketio.emit("command_created", {
                "command_id": command_id,
                "agent_id": agent_id,
                "hostname": agent.get("hostname"),
                "command_type": data["command_type"],
                "created_by": username,
                "created_at": current_time.isoformat()
            })
            
        return jsonify({
            "status": "success",
            "message": "Command sent to agent",
            "command_id": command_id
        }, 201)
        
    except Exception as e:
        logger.error(f"Error sending command to agent: {str(e)}")
        return jsonify({"error": "Failed to send command to agent"}), 500


@agents_bp.route('/broadcast', methods=['POST'])
def broadcast_command():
    """Gửi lệnh đến tất cả agent hoặc nhóm agent."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.json
    if not data.get("command_type"):
        return jsonify({"error": "Command type is required"}), 400
        
    try:
        # Xây dựng query lọc agent
        query = {}
        if "filter" in data and isinstance(data["filter"], dict):
            for key, value in data["filter"].items():
                if key == "status" and value == "active":
                    inactive_threshold = datetime.utcnow() - timedelta(minutes=AGENT_INACTIVE_THRESHOLD)
                    query["last_heartbeat"] = {"$gte": inactive_threshold}
                else:
                    query[key] = value
        
        # Tìm agent phù hợp
        agents = list(_agents_collection.find(query))
        if not agents:
            return jsonify({"error": "No agents found"}), 404
            
        # Gửi lệnh đến từng agent
        username = "admin"  # Fixed username
        current_time = datetime.utcnow()
        command_ids = []
        command_collection = _db.agent_commands
        
        for agent in agents:
            command = {
                "agent_id": agent["agent_id"],
                "command_type": data["command_type"],
                "parameters": data.get("parameters", {}),
                "priority": data.get("priority", 1),
                "description": data.get("description", ""),
                "status": "pending",
                "created_by": username,
                "created_at": current_time
            }
            
            result = command_collection.insert_one(command)
            command_ids.append(str(result.inserted_id))
        
        # Broadcast notification
        if socketio:
            socketio.emit("commands_broadcast", {
                "command_type": data["command_type"],
                "agent_count": len(agents),
                "created_by": username,
                "created_at": current_time.isoformat()
            })
            
        return jsonify({
            "status": "success",
            "message": f"Command sent to {len(agents)} agents",
            "command_ids": command_ids
        }), 201
        
    except Exception as e:
        logger.error(f"Error broadcasting command: {str(e)}")
        return jsonify({"error": "Failed to broadcast command"}), 500


@agents_bp.route('/commands/<command_id>', methods=['DELETE'])
def cancel_command(command_id):
    """Hủy lệnh đang chờ xử lý."""
    try:
        try:
            command_object_id = ObjectId(command_id)
        except:
            return jsonify({"error": "Invalid command ID format"}), 400
            
        # Tìm command
        command_collection = _db.agent_commands
        command = command_collection.find_one({"_id": command_object_id})
        
        if not command:
            return jsonify({"error": "Command not found"}), 404
            
        # Chỉ có thể hủy lệnh pending
        if command["status"] != "pending":
            return jsonify({"error": "Can only cancel pending commands"}), 400
            
        # Cập nhật status
        username = "admin"  # Fixed username
        result = command_collection.update_one(
            {"_id": command_object_id},
            {"$set": {
                "status": "cancelled",
                "cancelled_by": username,
                "cancelled_at": datetime.utcnow()
            }}
        )
        
        if result.modified_count:
            return jsonify({
                "status": "success",
                "message": "Command cancelled"
            }), 200
        else:
            return jsonify({"error": "Failed to cancel command"}), 500
            
    except Exception as e:
        logger.error(f"Error cancelling command: {str(e)}")
        return jsonify({"error": "Failed to cancel command"}), 500


@agents_bp.route('/commands', methods=['GET'])  # ✅ Changed from /admin/commands
def list_commands():
    """Liệt kê lệnh của các agent."""
    try:
        # Parse query params
        agent_id = request.args.get('agent_id')
        status = request.args.get('status')
        command_type = request.args.get('command_type')
        limit = min(int(request.args.get('limit', 50)), 200)
        skip = int(request.args.get('skip', 0))
        
        # Build query
        query = {}
        if agent_id:
            query["agent_id"] = agent_id
        if status:
            query["status"] = status
        if command_type:
            query["command_type"] = command_type
            
        # Execute query
        command_collection = _db.agent_commands
        cursor = command_collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
        total_count = command_collection.count_documents(query)
        
        # Format results
        commands = []
        for cmd in cursor:
            cmd_data = {
                "command_id": str(cmd["_id"]),
                "agent_id": cmd.get("agent_id"),
                "command_type": cmd.get("command_type"),
                "status": cmd.get("status"),
                "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None,
                "created_by": cmd.get("created_by"),
                "parameters": cmd.get("parameters"),
                "priority": cmd.get("priority")
            }
            commands.append(cmd_data)
            
        return jsonify({
            "commands": commands,
            "total": total_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing commands: {str(e)}")
        return jsonify({"error": "Failed to list commands"}), 500


# ======== Hàm hỗ trợ cho các module khác ========

def send_command_to_agent(agent_id, command_type, parameters=None, description=None, priority=1):
    """
    Gửi lệnh đến agent từ module khác trong server.
    
    Args:
        agent_id: ID của agent để gửi lệnh
        command_type: Loại lệnh
        parameters: Các tham số cho lệnh (tùy chọn)
        description: Mô tả lệnh (tùy chọn)
        priority: Độ ưu tiên lệnh (mặc định: 1)
    
    Returns:
        str: ID của lệnh đã tạo, hoặc None nếu thất bại
    """
    try:
        # Tìm agent theo ID
        agent = _agents_collection.find_one({"agent_id": agent_id})
        
        if not agent:
            logger.error(f"Cannot send command: Agent {agent_id} not found")
            return None
            
        # Chuẩn bị lệnh
        current_time = datetime.utcnow()
        command = {
            "agent_id": agent_id,
            "command_type": command_type,
            "parameters": parameters or {},
            "priority": priority,
            "description": description or command_type,
            "status": "pending",
            "created_by": "system",
            "created_at": current_time
        }
        
        # Lưu lệnh vào database
        command_collection = _db.agent_commands
        result = command_collection.insert_one(command)
        
        command_id = str(result.inserted_id)
        
        # Phát sóng thông báo lệnh mới
        if socketio:
            socketio.emit("command_created", {
                "command_id": command_id,
                "agent_id": agent_id,
                "hostname": agent.get("hostname"),
                "command_type": command_type,
                "created_by": "system",
                "created_at": current_time.isoformat(),
                "priority": priority
            })
            
        logger.info(f"Sent command {command_type} to agent {agent_id}")
        return command_id
        
    except Exception as e:
        logger.error(f"Error sending command to agent: {str(e)}")
        return None


def get_active_agents():
    """
    Lấy danh sách tất cả các agent đang hoạt động.
    
    Returns:
        List[Dict]: Danh sách thông tin cơ bản về các agent đang hoạt động
    """
    try:
        # Tính ngưỡng thời gian cho agent hoạt động
        inactive_threshold = datetime.utcnow() - timedelta(minutes=AGENT_INACTIVE_THRESHOLD)
        
        # Tìm các agent có heartbeat gần đây
        cursor = _agents_collection.find({
            "last_heartbeat": {"$gte": inactive_threshold}
        })
        
        # Chuẩn bị dữ liệu
        agents = []
        for agent in cursor:
            agents.append({
                "agent_id": agent["agent_id"],
                "hostname": agent.get("hostname"),
                "ip_address": agent.get("ip_address"),
                "status": agent.get("status"),
                "platform": agent.get("platform")
            })
            
        return agents
        
    except Exception as e:
        logger.error(f"Error getting active agents: {str(e)}")
        return []