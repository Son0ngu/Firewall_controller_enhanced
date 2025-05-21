import json  # Thư viện xử lý định dạng JSON, dùng cho việc serialize/deserialize dữ liệu
import logging  # Thư viện ghi log, giúp theo dõi hoạt động của module
from datetime import datetime, timedelta  # Xử lý thời gian, dùng cho timestamps và tính toán khoảng thời gian
from typing import Dict, List, Optional, Union  # Thư viện kiểu dữ liệu tĩnh, giúp code rõ ràng hơn

from bson import ObjectId  # Thư viện làm việc với MongoDB ObjectId
from flask import Blueprint, jsonify, request, current_app  # Framework Flask để tạo API
from flask_socketio import SocketIO  # Thư viện để triển khai giao tiếp real-time thông qua WebSocket
from pymongo import MongoClient, DESCENDING  # Thư viện kết nối MongoDB và hằng số sắp xếp
from pymongo.collection import Collection  # Kiểu dữ liệu Collection của MongoDB
from pymongo.database import Database  # Kiểu dữ liệu Database của MongoDB

# Cấu hình logging cho module
# Sử dụng logger riêng giúp lọc log theo module cụ thể
logger = logging.getLogger("logs_module")

# Khởi tạo Blueprint cho các route API logs
# Blueprint giúp tổ chức các route theo nhóm chức năng
logs_bp = Blueprint('logs', __name__)

# Biến socketio sẽ được khởi tạo từ bên ngoài với instance Flask-SocketIO
# Dùng để gửi thông báo realtime khi có log mới
socketio: Optional[SocketIO] = None

# Các biến kết nối MongoDB (được khởi tạo trong hàm init_app)
_db: Optional[Database] = None  # Database MongoDB
_logs_collection: Optional[Collection] = None  # Collection lưu trữ logs

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO):
    """
    Khởi tạo module logs với ứng dụng Flask và kết nối MongoDB.
    
    Args:
        app: Instance ứng dụng Flask
        mongo_client: Instance MongoClient của PyMongo để kết nối đến MongoDB
        socket_io: Instance Flask-SocketIO để gửi thông báo realtime
    """
    global _db, _logs_collection, socketio
    
    # Lưu trữ instance SocketIO để sử dụng sau này
    # SocketIO giúp gửi thông báo realtime khi có log mới đến các client
    socketio = socket_io
    
    # Lấy tên database từ cấu hình hoặc sử dụng tên mặc định
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Lấy collection logs từ database
    # Collection này lưu trữ tất cả log từ các agent
    _logs_collection = _db.logs
    
    # Tạo các chỉ mục (index) để tối ưu hiệu suất truy vấn
    # Index timestamp giúp truy vấn nhanh theo thời gian (thường xuyên dùng)
    _logs_collection.create_index([("timestamp", DESCENDING)])
    # Index agent_id để lọc nhanh theo agent
    _logs_collection.create_index([("agent_id", 1)])
    # Index domain để tìm kiếm nhanh theo tên miền
    _logs_collection.create_index([("domain", 1)])
    # Index action để lọc nhanh theo hành động (block/allow)
    _logs_collection.create_index([("action", 1)])
    
    # Đăng ký blueprint với ứng dụng Flask
    # URL prefix '/api' sẽ được thêm vào tất cả các route trong blueprint
    app.register_blueprint(logs_bp, url_prefix='/api')
    
    logger.info("Logs module initialized")


# ======== Các route API ========

@logs_bp.route('/logs', methods=['POST'])
def receive_logs():
    """
    Nhận logs từ các agent và lưu trữ vào database.
    Phát sóng (broadcast) logs mới đến các client qua Socket.IO.
    
    Format yêu cầu:
    {
        "logs": [
            {
                "agent_id": "agent123",
                "timestamp": "2023-01-01T12:00:00Z",
                "domain": "example.com",
                "dest_ip": "93.184.216.34",
                "dest_port": 443,
                "protocol": "HTTPS",
                "action": "block"
            },
            ...
        ]
    }
    
    Returns:
        JSON response với trạng thái và số lượng logs đã lưu
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    # Lấy dữ liệu từ request
    data = request.json
    # Kiểm tra cấu trúc dữ liệu và sự tồn tại của trường 'logs'
    if not data or not isinstance(data, dict) or "logs" not in data:
        return jsonify({"error": "Invalid request format, 'logs' field required"}), 400
    
    # Lấy danh sách logs và kiểm tra kiểu dữ liệu
    logs = data["logs"]
    if not isinstance(logs, list):
        return jsonify({"error": "'logs' must be an array"}), 400
    
    # Xác thực và xử lý từng log một
    valid_logs = []
    for log in logs:
        # Bỏ qua logs không hợp lệ
        if not isinstance(log, dict):
            continue
            
        # Đảm bảo các trường bắt buộc
        # domain và agent_id là bắt buộc để một log có ý nghĩa
        if "domain" not in log or "agent_id" not in log:
            continue
            
        # Thêm timestamp nếu không có
        # Timestamp là quan trọng để theo dõi thời gian xảy ra sự kiện
        if "timestamp" not in log:
            log["timestamp"] = datetime.utcnow().isoformat()
            
        # Phân tích timestamp nếu nó là chuỗi
        # Chuyển đổi từ chuỗi ISO thành đối tượng datetime
        if isinstance(log["timestamp"], str):
            try:
                # Thay 'Z' bằng '+00:00' để tuân thủ định dạng ISO 8601
                log["timestamp"] = datetime.fromisoformat(log["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                # Nếu phân tích thất bại, sử dụng thời gian hiện tại
                log["timestamp"] = datetime.utcnow()
                
        # Thêm vào danh sách logs hợp lệ
        valid_logs.append(log)
    
    # Kiểm tra xem có logs hợp lệ nào không
    if not valid_logs:
        return jsonify({"status": "warning", "message": "No valid logs provided"}), 200
        
    try:
        # Chèn logs vào database với thao tác hàng loạt
        # Sử dụng insert_many để tối ưu hiệu suất khi thêm nhiều bản ghi
        result = _logs_collection.insert_many(valid_logs)
        
        # Phát sóng logs mới đến các client đang kết nối
        # Điều này cho phép cập nhật giao diện người dùng theo thời gian thực
        for log in valid_logs:
            # Copy log để không thay đổi dữ liệu gốc
            log_with_id = log.copy()
            
            # Chuyển đổi ObjectId thành chuỗi để serialization JSON
            if "_id" in log_with_id and isinstance(log_with_id["_id"], ObjectId):
                log_with_id["_id"] = str(log_with_id["_id"])
                
            # Chuyển đổi datetime thành chuỗi ISO
            if "timestamp" in log_with_id and isinstance(log_with_id["timestamp"], datetime):
                log_with_id["timestamp"] = log_with_id["timestamp"].isoformat()
                
            # Phát sóng sự kiện 'new_log' với dữ liệu log
            if socketio:
                socketio.emit('new_log', log_with_id)
        
        # Trả về thông tin thành công
        return jsonify({
            "status": "success",
            "count": len(result.inserted_ids)
        }), 201
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi lưu trữ
        logger.error(f"Error storing logs: {str(e)}")
        return jsonify({"error": "Failed to store logs"}), 500


@logs_bp.route('/logs', methods=['GET'])
def get_logs():
    """
    Truy xuất logs với tùy chọn lọc và phân trang.
    
    Tham số truy vấn:
    - agent_id: Lọc theo ID của agent
    - domain: Lọc theo tên miền (hỗ trợ khớp một phần)
    - action: Lọc theo hành động (ví dụ: block, allow)
    - since: Chuỗi datetime ISO để lọc logs sau một thời điểm nhất định
    - until: Chuỗi datetime ISO để lọc logs trước một thời điểm nhất định
    - limit: Số lượng logs tối đa để trả về (mặc định: 100)
    - skip: Số lượng logs để bỏ qua (cho phân trang, mặc định: 0)
    - sort: Trường để sắp xếp theo (mặc định: timestamp)
    - order: Thứ tự sắp xếp, 'asc' hoặc 'desc' (mặc định: desc)
    
    Returns:
        JSON với mảng logs và metadata
    """
    try:
        # Phân tích các tham số truy vấn từ URL
        # Các tham số này sẽ được dùng để lọc và định dạng kết quả
        agent_id = request.args.get('agent_id')
        domain = request.args.get('domain')
        action = request.args.get('action')
        since_str = request.args.get('since')
        until_str = request.args.get('until')
        # Giới hạn limit tối đa là 1000 để tránh tải quá mức
        limit = min(int(request.args.get('limit', 100)), 1000)
        skip = int(request.args.get('skip', 0))
        sort_field = request.args.get('sort', 'timestamp')
        # Xác định thứ tự sắp xếp (tăng dần hoặc giảm dần)
        sort_order = DESCENDING if request.args.get('order', 'desc').lower() == 'desc' else 1
        
        # Xây dựng truy vấn MongoDB dựa trên các tham số
        query = {}
        
        # Thêm điều kiện lọc theo agent_id nếu được cung cấp
        if agent_id:
            query["agent_id"] = agent_id
            
        # Thêm điều kiện lọc theo domain, hỗ trợ khớp một phần và không phân biệt hoa thường
        if domain:
            query["domain"] = {"$regex": domain, "$options": "i"}
            
        # Thêm điều kiện lọc theo action
        if action:
            query["action"] = action
            
        # Xây dựng điều kiện lọc theo thời gian
        time_query = {}
        
        # Lọc các logs sau một thời điểm nhất định
        if since_str:
            try:
                since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
                time_query["$gte"] = since
            except ValueError:
                # Bỏ qua lỗi định dạng thời gian
                pass
                
        # Lọc các logs trước một thời điểm nhất định
        if until_str:
            try:
                until = datetime.fromisoformat(until_str.replace('Z', '+00:00'))
                time_query["$lte"] = until
            except ValueError:
                # Bỏ qua lỗi định dạng thời gian
                pass
                
        # Thêm điều kiện thời gian vào truy vấn nếu có
        if time_query:
            query["timestamp"] = time_query
            
        # Thực hiện truy vấn từ database
        cursor = _logs_collection.find(query)
        
        # Lấy tổng số logs phù hợp với điều kiện (trước khi phân trang)
        # Dùng cho việc tính toán số trang
        total_count = _logs_collection.count_documents(query)
        
        # Áp dụng sắp xếp và phân trang
        cursor = cursor.sort(sort_field, sort_order).skip(skip).limit(limit)
        
        # Chuyển đổi kết quả thành danh sách và chuẩn bị cho serialization JSON
        logs = []
        for log in cursor:
            # Chuyển đổi ObjectId thành chuỗi
            log["_id"] = str(log["_id"])
            
            # Chuyển đổi datetime thành chuỗi ISO
            if "timestamp" in log and isinstance(log["timestamp"], datetime):
                log["timestamp"] = log["timestamp"].isoformat()
                
            logs.append(log)
            
        # Trả về kết quả kèm metadata hỗ trợ phân trang
        return jsonify({
            "logs": logs,
            "total": total_count,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pages": (total_count + limit - 1) // limit if limit > 0 else 1
        }), 200
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi truy xuất
        logger.error(f"Error retrieving logs: {str(e)}")
        return jsonify({"error": "Failed to retrieve logs"}), 500


@logs_bp.route('/logs/summary', methods=['GET'])
def get_logs_summary():
    """
    Lấy thống kê tóm tắt cho logs.
    
    Tham số truy vấn:
    - period: Khoảng thời gian cho bản tóm tắt - 'day', 'week', 'month' (mặc định: day)
    
    Returns:
        JSON với các thống kê tóm tắt
    """
    try:
        # Phân tích tham số period từ URL
        period = request.args.get('period', 'day').lower()
        
        # Xác định khoảng thời gian dựa trên period
        now = datetime.utcnow()
        # Tính toán thời điểm bắt đầu dựa trên period
        if period == 'week':
            since = now - timedelta(days=7)
        elif period == 'month':
            since = now - timedelta(days=30)
        else:  # mặc định là day
            since = now - timedelta(days=1)
            
        # Xây dựng pipeline tổng hợp (aggregation) cho MongoDB
        # Pipeline sẽ thực hiện các bước xử lý dữ liệu theo thứ tự
        
        # Pipeline 1: Thống kê theo action
        pipeline = [
            # Bước 1: Lọc logs trong khoảng thời gian
            {"$match": {"timestamp": {"$gte": since}}},
            
            # Bước 2: Nhóm theo action và đếm số lượng mỗi nhóm
            {"$group": {
                "_id": "$action",  # Trường để nhóm theo
                "count": {"$sum": 1}  # Đếm số lượng bản ghi trong mỗi nhóm
            }},
            
            # Bước 3: Sắp xếp theo số lượng (giảm dần)
            {"$sort": {"count": -1}}
        ]
        
        # Thực hiện tổng hợp để đếm logs theo action
        action_counts = list(_logs_collection.aggregate(pipeline))
        
        # Pipeline 2: Thống kê các tên miền bị chặn nhiều nhất
        domains_pipeline = [
            # Bước 1: Lọc logs trong khoảng thời gian và có action là "block"
            {"$match": {"timestamp": {"$gte": since}, "action": "block"}},
            
            # Bước 2: Nhóm theo domain và đếm số lượng
            {"$group": {
                "_id": "$domain",
                "count": {"$sum": 1}
            }},
            
            # Bước 3: Sắp xếp theo số lượng (giảm dần)
            {"$sort": {"count": -1}},
            
            # Bước 4: Giới hạn chỉ lấy top 10
            {"$limit": 10}
        ]
        
        # Thực hiện tổng hợp để lấy top 10 tên miền bị chặn
        top_blocked_domains = list(_logs_collection.aggregate(domains_pipeline))
        
        # Pipeline 3: Thống kê theo agent
        agents_pipeline = [
            # Bước 1: Lọc logs trong khoảng thời gian
            {"$match": {"timestamp": {"$gte": since}}},
            
            # Bước 2: Nhóm theo agent_id và tính các thống kê
            {"$group": {
                "_id": "$agent_id",
                "count": {"$sum": 1},  # Tổng số logs
                # Đếm số logs bị chặn bằng cách sử dụng điều kiện
                "blocked": {"$sum": {"$cond": [{"$eq": ["$action", "block"]}, 1, 0]}},
                # Đếm số logs được cho phép
                "allowed": {"$sum": {"$cond": [{"$eq": ["$action", "allow"]}, 1, 0]}}
            }},
            
            # Bước 3: Sắp xếp theo tổng số logs (giảm dần)
            {"$sort": {"count": -1}}
        ]
        
        # Thực hiện tổng hợp để lấy thống kê theo agent
        agent_stats = list(_logs_collection.aggregate(agents_pipeline))
        
        # Định dạng kết quả thành cấu trúc JSON phù hợp
        summary = {
            "period": period,
            "since": since.isoformat(),
            "until": now.isoformat(),
            # Chuyển đổi danh sách action_counts thành dictionary
            "actions": {item["_id"]: item["count"] for item in action_counts},
            # Định dạng lại top_blocked_domains thành danh sách các dict
            "top_blocked_domains": [{"domain": item["_id"], "count": item["count"]} for item in top_blocked_domains],
            # Định dạng lại agent_stats thành danh sách các dict với các trường cụ thể
            "agents": [
                {
                    "agent_id": item["_id"],
                    "total": item["count"],
                    "blocked": item["blocked"],
                    "allowed": item["allowed"]
                } 
                for item in agent_stats
            ],
            # Tính tổng số logs bằng cách cộng tất cả action_counts
            "total_logs": sum(item["count"] for item in action_counts)
        }
        
        # Trả về bản tóm tắt dưới dạng JSON
        return jsonify(summary), 200
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi tạo bản tóm tắt
        logger.error(f"Error generating logs summary: {str(e)}")
        return jsonify({"error": "Failed to generate logs summary"}), 500


@logs_bp.route('/logs/<log_id>', methods=['DELETE'])
def delete_log(log_id):
    """
    Xóa một log cụ thể theo ID.
    
    Args:
        log_id: ID của log cần xóa
    
    Returns:
        JSON response với trạng thái
    """
    try:
        # Chuyển đổi chuỗi ID thành ObjectId
        # MongoDB sử dụng ObjectId cho trường _id
        try:
            object_id = ObjectId(log_id)
        except:
            # Trả về lỗi nếu ID không hợp lệ
            return jsonify({"error": "Invalid log ID format"}), 400
            
        # Thực hiện xóa log
        result = _logs_collection.delete_one({"_id": object_id})
        
        # Kiểm tra kết quả xóa
        if result.deleted_count:
            # Log đã được xóa thành công
            return jsonify({"status": "success", "message": "Log deleted"}), 200
        else:
            # Không tìm thấy log với ID đã cho
            return jsonify({"status": "error", "message": "Log not found"}), 404
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi xóa
        logger.error(f"Error deleting log {log_id}: {str(e)}")
        return jsonify({"error": "Failed to delete log"}), 500


@logs_bp.route('/logs/clear', methods=['POST'])
def clear_logs():
    """
    Xóa logs theo các tiêu chí nhất định.
    
    Request body:
    {
        "older_than": "2023-01-01T00:00:00Z",  # Tùy chọn, xóa logs cũ hơn thời điểm này
        "agent_id": "agent123",                # Tùy chọn, xóa logs của agent này
        "action": "block"                      # Tùy chọn, xóa logs có action này
    }
    
    Returns:
        JSON response với số lượng logs đã xóa
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    # Lấy dữ liệu từ request
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    # Xây dựng truy vấn xóa dựa trên các tham số
    query = {}
    
    # Xử lý lọc theo thời gian (older_than)
    if "older_than" in data:
        try:
            # Chuyển đổi chuỗi thời gian thành đối tượng datetime
            older_than = datetime.fromisoformat(data["older_than"].replace('Z', '+00:00'))
            # Thêm điều kiện timestamp < older_than
            query["timestamp"] = {"$lt": older_than}
        except ValueError:
            # Trả về lỗi nếu định dạng thời gian không hợp lệ
            return jsonify({"error": "Invalid datetime format"}), 400
            
    # Xử lý lọc theo agent_id
    if "agent_id" in data:
        query["agent_id"] = data["agent_id"]
        
    # Xử lý lọc theo action
    if "action" in data:
        query["action"] = data["action"]
        
    # Kiểm tra xem có ít nhất một điều kiện lọc không
    if not query:
        return jsonify({"error": "At least one filter must be specified"}), 400
        
    try:
        # Xóa logs khớp với truy vấn
        result = _logs_collection.delete_many(query)
        
        # Trả về kết quả với số lượng bản ghi đã xóa
        return jsonify({
            "status": "success",
            "count": result.deleted_count
        }), 200
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi xóa
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({"error": "Failed to clear logs"}), 500


# ======== Các hàm hỗ trợ ========

def add_log(log_data: Dict) -> Optional[str]:
    """
    Thêm một bản ghi log từ bên trong hệ thống (sử dụng nội bộ).
    
    Args:
        log_data: Dictionary chứa dữ liệu log
        
    Returns:
        str: ID của log đã chèn, hoặc None nếu chèn thất bại
    """
    try:
        # Kiểm tra các trường bắt buộc
        if "domain" not in log_data:
            logger.error("Log data missing required 'domain' field")
            return None
            
        # Thêm timestamp nếu không có
        if "timestamp" not in log_data:
            log_data["timestamp"] = datetime.utcnow()
            
        # Chèn log vào database
        result = _logs_collection.insert_one(log_data)
        
        # Phát sóng log mới đến các client qua SocketIO
        # Cho phép cập nhật realtime trên dashboard
        if socketio:
            # Tạo bản sao log để tránh thay đổi dữ liệu gốc
            log_for_emit = log_data.copy()
            log_for_emit["_id"] = str(result.inserted_id)
            
            # Chuyển đổi datetime thành chuỗi ISO
            if "timestamp" in log_for_emit and isinstance(log_for_emit["timestamp"], datetime):
                log_for_emit["timestamp"] = log_for_emit["timestamp"].isoformat()
                
            # Gửi sự kiện 'new_log' với dữ liệu log
            socketio.emit('new_log', log_for_emit)
            
        # Trả về ID của log đã chèn
        return str(result.inserted_id)
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi thêm log
        logger.error(f"Error adding log: {str(e)}")
        return None


def get_recent_logs(limit: int = 100) -> List[Dict]:
    """
    Lấy các logs gần đây nhất (sử dụng nội bộ).
    
    Args:
        limit: Số lượng logs tối đa để trả về
        
    Returns:
        List[Dict]: Danh sách các logs gần đây
    """
    try:
        # Danh sách để lưu kết quả
        logs = []
        # Truy vấn các logs, sắp xếp theo timestamp giảm dần
        cursor = _logs_collection.find().sort("timestamp", DESCENDING).limit(limit)
        
        # Định dạng từng log cho serialization JSON
        for log in cursor:
            # Chuyển đổi ObjectId thành chuỗi
            log["_id"] = str(log["_id"])
            
            # Chuyển đổi datetime thành chuỗi ISO
            if "timestamp" in log and isinstance(log["timestamp"], datetime):
                log["timestamp"] = log["timestamp"].isoformat()
                
            logs.append(log)
            
        return logs
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi lấy logs
        logger.error(f"Error getting recent logs: {str(e)}")
        return []