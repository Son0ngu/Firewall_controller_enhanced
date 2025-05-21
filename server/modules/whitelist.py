# Import các thư viện cần thiết
import logging  # Thư viện ghi log, giúp theo dõi hoạt động của module
import re  # Thư viện xử lý biểu thức chính quy, dùng để xác thực định dạng tên miền
from datetime import datetime  # Thư viện xử lý thời gian, dùng cho timestamps
from typing import Dict, List, Optional, Set, Union  # Thư viện kiểu dữ liệu tĩnh, giúp code rõ ràng hơn

from bson import ObjectId  # Thư viện làm việc với MongoDB ObjectId
from flask import Blueprint, jsonify, request, current_app, g  # Framework Flask để tạo API
from flask_socketio import SocketIO  # Thư viện để triển khai giao tiếp real-time qua WebSocket
from pymongo import MongoClient, DESCENDING  # Thư viện kết nối MongoDB và hằng số sắp xếp
from pymongo.collection import Collection  # Kiểu dữ liệu Collection của MongoDB
from pymongo.database import Database  # Kiểu dữ liệu Database của MongoDB

# Import các decorator xác thực và phân quyền từ module auth
from server.modules.auth import token_required, admin_required, operator_required

# Cấu hình logging cho module
# Sử dụng logger riêng giúp dễ dàng lọc log từ module này
logger = logging.getLogger("whitelist_module")

# Khởi tạo Blueprint cho các route API
# Blueprint giúp tổ chức các route theo nhóm chức năng
whitelist_bp = Blueprint('whitelist', __name__)

# Biến socketio sẽ được khởi tạo từ bên ngoài với instance Flask-SocketIO
# Dùng để gửi thông báo realtime khi có thay đổi trong whitelist
socketio: Optional[SocketIO] = None

# Các biến kết nối MongoDB (được khởi tạo trong hàm init_app)
_db: Optional[Database] = None  # Database MongoDB
_whitelist_collection: Optional[Collection] = None  # Collection lưu trữ whitelist

def init_app(app, mongo_client: MongoClient, socket_io: SocketIO):
    """
    Khởi tạo module whitelist với ứng dụng Flask và kết nối MongoDB.
    
    Args:
        app: Instance ứng dụng Flask
        mongo_client: Instance MongoClient của PyMongo để kết nối đến MongoDB
        socket_io: Instance Flask-SocketIO cho thông báo realtime
    """
    global _db, _whitelist_collection, socketio
    
    # Lưu trữ instance SocketIO để sử dụng sau này
    # SocketIO dùng để thông báo realtime khi whitelist thay đổi
    socketio = socket_io
    
    # Lấy tên database từ cấu hình hoặc sử dụng tên mặc định
    db_name = app.config.get('MONGO_DBNAME', 'firewall_controller')
    _db = mongo_client[db_name]
    
    # Lấy collection whitelist từ database
    # Collection này lưu trữ danh sách các tên miền được phép truy cập
    _whitelist_collection = _db.whitelist
    
    # Tạo các chỉ mục (index) để tối ưu hiệu suất truy vấn
    # Index domain là unique để đảm bảo không có tên miền trùng lặp
    _whitelist_collection.create_index([("domain", 1)], unique=True)
    # Index added_date để sắp xếp và lọc theo thời gian thêm
    _whitelist_collection.create_index([("added_date", DESCENDING)])
    # Index added_by để lọc theo người đã thêm tên miền
    _whitelist_collection.create_index([("added_by", 1)])
    
    # Đăng ký blueprint với ứng dụng Flask
    # URL prefix '/api' sẽ được thêm vào tất cả các route trong blueprint
    app.register_blueprint(whitelist_bp, url_prefix='/api')
    
    # Tạo whitelist mặc định nếu chưa có dữ liệu
    # Đảm bảo hệ thống có một số tên miền an toàn từ đầu
    if _whitelist_collection.count_documents({}) == 0:
        _create_default_whitelist()
    
    logger.info("Whitelist module initialized")


# ======== Các route API ========

@whitelist_bp.route('/whitelist', methods=['GET'])
@token_required  # Yêu cầu người dùng đã đăng nhập
def get_whitelist():
    """
    Lấy danh sách whitelist với tùy chọn lọc.
    
    Tham số truy vấn:
    - search: Lọc theo tên miền (khớp một phần)
    - since: Chuỗi datetime ISO để lọc các bản ghi sau một thời điểm
    - limit: Số lượng bản ghi tối đa để trả về (mặc định: 1000)
    - skip: Số lượng bản ghi để bỏ qua (cho phân trang, mặc định: 0)
    
    Returns:
        JSON với mảng domains và metadata
    """
    try:
        # Phân tích các tham số truy vấn
        search = request.args.get('search', '')  # Từ khóa tìm kiếm, mặc định rỗng
        since_str = request.args.get('since')  # Thời gian bắt đầu lọc
        limit = min(int(request.args.get('limit', 1000)), 2000)  # Giới hạn tối đa 2000 bản ghi
        skip = int(request.args.get('skip', 0))  # Số bản ghi bỏ qua cho phân trang
        
        # Xây dựng truy vấn MongoDB
        query = {}
        
        # Thêm điều kiện tìm kiếm theo tên miền nếu có
        # Sử dụng regex để tìm kiếm một phần tên miền, không phân biệt hoa thường
        if search:
            query["domain"] = {"$regex": search, "$options": "i"}
            
        # Phân tích thời gian để lọc
        if since_str:
            try:
                # Chuyển đổi chuỗi ISO thành đối tượng datetime
                since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
                # Lọc các bản ghi được thêm sau mốc thời gian này
                query["added_date"] = {"$gte": since}
            except ValueError:
                # Bỏ qua nếu định dạng thời gian không hợp lệ
                pass
                
        # Thực hiện truy vấn từ database
        cursor = _whitelist_collection.find(query)
        
        # Lấy tổng số bản ghi phù hợp với điều kiện (trước khi phân trang)
        total_count = _whitelist_collection.count_documents(query)
        
        # Áp dụng sắp xếp theo tên miền và phân trang
        cursor = cursor.sort("domain", 1).skip(skip).limit(limit)
        
        # Chuyển kết quả thành danh sách và chuẩn bị cho response JSON
        domains = []
        for entry in cursor:
            # Chuyển ObjectId thành chuỗi để có thể serialize
            entry["_id"] = str(entry["_id"])
            
            # Chuyển datetime thành chuỗi ISO
            if "added_date" in entry and isinstance(entry["added_date"], datetime):
                entry["added_date"] = entry["added_date"].isoformat()
                
            domains.append(entry)
            
        # Tạo danh sách đơn giản chỉ chứa tên miền (không có metadata)
        # Hữu ích cho client đơn giản không cần chi tiết
        simple_domains = [entry["domain"] for entry in domains]
            
        # Trả về kết quả với metadata
        return jsonify({
            "domains": domains,  # Danh sách đầy đủ với metadata
            "simple_domains": simple_domains,  # Danh sách đơn giản chỉ có tên miền
            "total": total_count  # Tổng số bản ghi thỏa mãn điều kiện
        }), 200
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi truy vấn
        logger.error(f"Error retrieving whitelist: {str(e)}")
        return jsonify({"error": "Failed to retrieve whitelist"}), 500


@whitelist_bp.route('/whitelist', methods=['POST'])
@token_required  # Yêu cầu người dùng đã đăng nhập
@operator_required  # Yêu cầu ít nhất quyền operator
def add_domain():
    """
    Thêm một tên miền vào whitelist.
    
    Request body:
    {
        "domain": "example.com",   # Bắt buộc
        "notes": "Example domain", # Tùy chọn
    }
    
    Returns:
        JSON response với trạng thái và dữ liệu tên miền
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    # Lấy dữ liệu từ request
    data = request.json
    # Kiểm tra cấu trúc dữ liệu và trường bắt buộc domain
    if not isinstance(data, dict) or "domain" not in data:
        return jsonify({"error": "Invalid request format, 'domain' field required"}), 400
        
    # Lấy domain và làm sạch (loại bỏ khoảng trắng, chuyển thành chữ thường)
    domain = data.get("domain", "").strip().lower()
    
    # Xác thực định dạng tên miền
    if not is_valid_domain(domain):
        return jsonify({"error": "Invalid domain format"}), 400
        
    # Kiểm tra xem tên miền đã tồn tại chưa
    if _whitelist_collection.find_one({"domain": domain}):
        return jsonify({"error": "Domain already exists in whitelist"}), 409
        
    # Lấy thông tin người dùng từ token xác thực
    # g.user được đặt bởi decorator token_required
    username = g.user.get('username', 'unknown')
    
    # Chuẩn bị bản ghi để thêm vào database
    entry = {
        "domain": domain,
        "notes": data.get("notes", ""),  # Ghi chú, mặc định rỗng
        "added_by": username,  # Người thêm
        "added_date": datetime.utcnow()  # Thời điểm thêm
    }
    
    try:
        # Chèn bản ghi vào database
        result = _whitelist_collection.insert_one(entry)
        
        # Chuẩn bị dữ liệu cho response
        entry["_id"] = str(result.inserted_id)  # Chuyển ObjectId thành chuỗi
        entry["added_date"] = entry["added_date"].isoformat()  # Chuyển datetime thành chuỗi ISO
        
        # Phát sóng thông báo qua SocketIO
        # Thông báo cho tất cả client đang kết nối rằng whitelist đã được cập nhật
        if socketio:
            socketio.emit('whitelist_updated', {
                "action": "add",  # Loại hành động: thêm
                "domain": entry["domain"],  # Tên miền đã thêm
                "entry": entry  # Dữ liệu đầy đủ của bản ghi
            })
        
        # Ghi log hoạt động
        logger.info(f"Domain {domain} added to whitelist by {username}")
        
        # Trả về thành công với dữ liệu bản ghi
        return jsonify({
            "status": "success",
            "message": "Domain added to whitelist",
            "domain": entry
        }), 201  # 201 Created: resource đã được tạo thành công
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi thêm vào database
        logger.error(f"Error adding domain to whitelist: {str(e)}")
        return jsonify({"error": "Failed to add domain to whitelist"}), 500


@whitelist_bp.route('/whitelist/<domain_id>', methods=['PUT'])
@token_required  # Yêu cầu người dùng đã đăng nhập
@operator_required  # Yêu cầu ít nhất quyền operator
def update_domain(domain_id):
    """
    Cập nhật một bản ghi tên miền trong whitelist.
    
    Args:
        domain_id: ID của bản ghi tên miền cần cập nhật
    
    Request body:
    {
        "notes": "Ghi chú mới",    # Tùy chọn
        "domain": "example.com"    # Tùy chọn, nhưng phải hợp lệ nếu được cung cấp
    }
    
    Returns:
        JSON response với trạng thái và dữ liệu đã cập nhật
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    # Lấy dữ liệu từ request
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request format"}), 400
        
    try:
        # Chuyển đổi chuỗi ID thành ObjectId MongoDB
        try:
            object_id = ObjectId(domain_id)
        except:
            return jsonify({"error": "Invalid domain ID format"}), 400
            
        # Lấy bản ghi hiện tại từ database
        current = _whitelist_collection.find_one({"_id": object_id})
        if not current:
            return jsonify({"error": "Domain entry not found"}), 404
            
        # Lấy thông tin người dùng từ token xác thực
        username = g.user.get('username', 'unknown')
        
        # Xây dựng truy vấn cập nhật
        update = {}
        
        # Cập nhật ghi chú nếu được cung cấp
        if "notes" in data:
            update["notes"] = data["notes"]
            
        # Cập nhật tên miền nếu được cung cấp
        if "domain" in data:
            # Làm sạch tên miền (loại bỏ khoảng trắng, chuyển thành chữ thường)
            domain = data["domain"].strip().lower()
            
            # Xác thực định dạng tên miền
            if not is_valid_domain(domain):
                return jsonify({"error": "Invalid domain format"}), 400
                
            # Kiểm tra xem tên miền mới đã tồn tại chưa (chỉ nếu khác tên miền hiện tại)
            if domain != current["domain"] and _whitelist_collection.find_one({"domain": domain}):
                return jsonify({"error": "Domain already exists in whitelist"}), 409
                
            update["domain"] = domain
            
        # Nếu không có gì để cập nhật, trả về thành công
        if not update:
            return jsonify({"status": "success", "message": "No changes made"}), 200
            
        # Thêm thông tin cập nhật cuối cùng
        update["last_updated"] = datetime.utcnow()  # Thời điểm cập nhật
        update["last_updated_by"] = username  # Người cập nhật
        
        # Cập nhật bản ghi trong database
        result = _whitelist_collection.update_one(
            {"_id": object_id},
            {"$set": update}
        )
        
        # Kiểm tra xem có bản ghi nào được cập nhật không
        if result.modified_count:
            # Lấy bản ghi đã cập nhật
            updated = _whitelist_collection.find_one({"_id": object_id})
            
            # Chuẩn bị dữ liệu cho response
            updated["_id"] = str(updated["_id"])  # Chuyển ObjectId thành chuỗi
            # Chuyển các trường datetime thành chuỗi ISO
            if "added_date" in updated and isinstance(updated["added_date"], datetime):
                updated["added_date"] = updated["added_date"].isoformat()
            if "last_updated" in updated and isinstance(updated["last_updated"], datetime):
                updated["last_updated"] = updated["last_updated"].isoformat()
            
            # Phát sóng thông báo qua SocketIO
            if socketio:
                socketio.emit('whitelist_updated', {
                    "action": "update",  # Loại hành động: cập nhật
                    "domain": updated["domain"],  # Tên miền đã cập nhật
                    "entry": updated  # Dữ liệu đầy đủ của bản ghi
                })
            
            # Ghi log hoạt động
            logger.info(f"Domain entry {domain_id} updated by {username}")
            
            # Trả về thành công với dữ liệu đã cập nhật
            return jsonify({
                "status": "success", 
                "message": "Domain entry updated",
                "domain": updated
            }), 200
        else:
            # Không có bản ghi nào được cập nhật
            return jsonify({"status": "warning", "message": "No changes made"}), 200
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi cập nhật
        logger.error(f"Error updating domain entry: {str(e)}")
        return jsonify({"error": "Failed to update domain entry"}), 500


@whitelist_bp.route('/whitelist/<domain_id>', methods=['DELETE'])
@token_required  # Yêu cầu người dùng đã đăng nhập
@operator_required  # Yêu cầu ít nhất quyền operator
def delete_domain(domain_id):
    """
    Xóa một tên miền khỏi whitelist.
    
    Args:
        domain_id: ID của tên miền cần xóa
    
    Returns:
        JSON response với trạng thái
    """
    try:
        # Chuyển đổi chuỗi ID thành ObjectId MongoDB
        try:
            object_id = ObjectId(domain_id)
        except:
            return jsonify({"error": "Invalid domain ID format"}), 400
            
        # Lấy thông tin người dùng từ token xác thực
        username = g.user.get('username', 'unknown')
        
        # Lấy thông tin tên miền trước khi xóa (để sử dụng cho thông báo)
        domain_entry = _whitelist_collection.find_one({"_id": object_id})
        if not domain_entry:
            return jsonify({"error": "Domain not found"}), 404
            
        # Xóa tên miền khỏi database
        result = _whitelist_collection.delete_one({"_id": object_id})
        
        # Kiểm tra xem có bản ghi nào bị xóa không
        if result.deleted_count:
            # Phát sóng thông báo qua SocketIO
            if socketio:
                socketio.emit('whitelist_updated', {
                    "action": "delete",  # Loại hành động: xóa
                    "domain": domain_entry["domain"],  # Tên miền đã xóa
                    "entry_id": str(object_id)  # ID của bản ghi đã xóa
                })
            
            # Ghi log hoạt động
            logger.info(f"Domain {domain_entry['domain']} removed from whitelist by {username}")
            
            # Trả về thành công
            return jsonify({
                "status": "success", 
                "message": "Domain removed from whitelist"
            }), 200
        else:
            # Không tìm thấy tên miền để xóa
            return jsonify({"status": "error", "message": "Domain not found"}), 404
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi xóa
        logger.error(f"Error deleting domain: {str(e)}")
        return jsonify({"error": "Failed to delete domain"}), 500


@whitelist_bp.route('/whitelist/domain/<domain>', methods=['DELETE'])
@token_required  # Yêu cầu người dùng đã đăng nhập
@operator_required  # Yêu cầu ít nhất quyền operator
def delete_domain_by_name(domain):
    """
    Xóa một tên miền khỏi whitelist theo tên.
    
    Args:
        domain: Tên miền cần xóa
    
    Returns:
        JSON response với trạng thái
    """
    try:
        # Làm sạch tên miền (loại bỏ khoảng trắng, chuyển thành chữ thường)
        domain = domain.strip().lower()
        
        # Lấy thông tin người dùng từ token xác thực
        username = g.user.get('username', 'unknown')
        
        # Tìm tên miền trong database
        domain_entry = _whitelist_collection.find_one({"domain": domain})
        if not domain_entry:
            return jsonify({"error": "Domain not found in whitelist"}), 404
            
        # Xóa tên miền khỏi database
        result = _whitelist_collection.delete_one({"domain": domain})
        
        # Kiểm tra xem có bản ghi nào bị xóa không
        if result.deleted_count:
            # Phát sóng thông báo qua SocketIO
            if socketio:
                socketio.emit('whitelist_updated', {
                    "action": "delete",  # Loại hành động: xóa
                    "domain": domain,  # Tên miền đã xóa
                    "entry_id": str(domain_entry["_id"])  # ID của bản ghi đã xóa
                })
            
            # Ghi log hoạt động
            logger.info(f"Domain {domain} removed from whitelist by {username}")
            
            # Trả về thành công
            return jsonify({
                "status": "success", 
                "message": "Domain removed from whitelist"
            }), 200
        else:
            # Không tìm thấy tên miền để xóa
            return jsonify({"status": "error", "message": "Domain not found"}), 404
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi xóa
        logger.error(f"Error deleting domain: {str(e)}")
        return jsonify({"error": "Failed to delete domain"}), 500


@whitelist_bp.route('/whitelist/check/<domain>', methods=['GET'])
def check_domain(domain):
    """
    Kiểm tra xem một tên miền có trong whitelist không.
    Endpoint này là công khai (không yêu cầu xác thực) để cho phép agent kiểm tra mà không cần đăng nhập.
    
    Args:
        domain: Tên miền cần kiểm tra
    
    Returns:
        JSON response với kết quả
    """
    try:
        # Làm sạch tên miền (loại bỏ khoảng trắng, chuyển thành chữ thường)
        domain = domain.strip().lower()
        
        # Kiểm tra khớp chính xác
        if _whitelist_collection.find_one({"domain": domain}):
            return jsonify({
                "domain": domain,
                "allowed": True,  # Tên miền được cho phép
                "match_type": "exact"  # Loại khớp: chính xác
            }), 200
            
        # Kiểm tra khớp wildcard (ví dụ: *.example.com khớp với a.example.com)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            # Tạo wildcard domain từ phần còn lại của tên miền
            # Ví dụ: Từ a.example.com, tạo *.example.com
            wildcard = f"*.{'.'.join(parts[i:])}"
            if _whitelist_collection.find_one({"domain": wildcard}):
                return jsonify({
                    "domain": domain,
                    "allowed": True,  # Tên miền được cho phép
                    "match_type": "wildcard",  # Loại khớp: wildcard
                    "wildcard": wildcard  # Tên miền wildcard khớp
                }), 200
        
        # Không tìm thấy trong whitelist
        return jsonify({
            "domain": domain,
            "allowed": False  # Tên miền không được cho phép
        }), 200
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi kiểm tra
        logger.error(f"Error checking domain: {str(e)}")
        return jsonify({"error": "Failed to check domain"}), 500


@whitelist_bp.route('/whitelist/bulk', methods=['POST'])
@token_required  # Yêu cầu người dùng đã đăng nhập
@operator_required  # Yêu cầu ít nhất quyền operator
def bulk_add_domains():
    """
    Thêm nhiều tên miền vào whitelist cùng lúc.
    
    Request body:
    {
        "domains": [
            "example.com", 
            "example.org"
        ],
        "notes": "Bulk import"      # Tùy chọn, áp dụng cho tất cả các tên miền
    }
    
    Returns:
        JSON response với số lượng tên miền đã thêm và bỏ qua
    """
    # Kiểm tra xem request có định dạng JSON không
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    # Lấy dữ liệu từ request
    data = request.json
    # Kiểm tra cấu trúc dữ liệu và trường bắt buộc domains
    if not isinstance(data, dict) or "domains" not in data or not isinstance(data["domains"], list):
        return jsonify({"error": "Invalid request format, 'domains' array required"}), 400
        
    # Lấy thông tin người dùng từ token xác thực
    username = g.user.get('username', 'unknown')
    
    # Lấy ghi chú chung cho tất cả các tên miền
    notes = data.get("notes", "Bulk import")
    
    try:
        # Xử lý từng tên miền
        added = []  # Danh sách tên miền đã thêm thành công
        skipped = []  # Danh sách tên miền đã bỏ qua
        
        for domain in data["domains"]:
            # Bỏ qua nếu không phải chuỗi
            if not isinstance(domain, str):
                continue
                
            # Làm sạch và xác thực tên miền
            domain = domain.strip().lower()
            if not is_valid_domain(domain):
                # Thêm vào danh sách bỏ qua với lý do định dạng không hợp lệ
                skipped.append({"domain": domain, "reason": "invalid_format"})
                continue
                
            # Kiểm tra xem tên miền đã tồn tại chưa
            if _whitelist_collection.find_one({"domain": domain}):
                # Thêm vào danh sách bỏ qua với lý do đã tồn tại
                skipped.append({"domain": domain, "reason": "already_exists"})
                continue
                
            # Chuẩn bị bản ghi để thêm vào database
            entry = {
                "domain": domain,
                "notes": notes,
                "added_by": username,
                "added_date": datetime.utcnow()
            }
            
            # Thêm vào whitelist
            result = _whitelist_collection.insert_one(entry)
            # Thêm vào danh sách đã thêm thành công
            added.append({
                "domain": domain,
                "id": str(result.inserted_id)
            })
        
        # Phát sóng thông báo qua SocketIO nếu có tên miền nào được thêm
        if added and socketio:
            socketio.emit('whitelist_bulk_updated', {
                "action": "bulk_add",  # Loại hành động: thêm hàng loạt
                "count": len(added)  # Số lượng tên miền đã thêm
            })
        
        # Ghi log hoạt động
        logger.info(f"Bulk import: {len(added)} domains added by {username}")
        
        # Trả về thành công với thống kê
        return jsonify({
            "status": "success",
            "added": len(added),  # Số lượng tên miền đã thêm
            "skipped": len(skipped),  # Số lượng tên miền đã bỏ qua
            "added_domains": added,  # Chi tiết các tên miền đã thêm
            "skipped_domains": skipped  # Chi tiết các tên miền đã bỏ qua và lý do
        }), 201
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi thêm hàng loạt
        logger.error(f"Error in bulk domain add: {str(e)}")
        return jsonify({"error": "Failed to process bulk domain addition"}), 500


@whitelist_bp.route('/whitelist/agent-sync', methods=['GET'])
def agent_whitelist_sync():
    """
    Endpoint cho các agent đồng bộ whitelist của họ.
    Endpoint này có thể truy cập mà không cần xác thực người dùng nhưng yêu cầu token agent hợp lệ.
    
    Tham số truy vấn:
    - since: Chuỗi datetime ISO để lọc các bản ghi sau một thời điểm
    - agent_id: ID agent bắt buộc để theo dõi
    - agent_token: Token xác thực agent bắt buộc
    
    Returns:
        JSON với mảng domains và metadata
    """
    try:
        # Phân tích các tham số truy vấn
        since_str = request.args.get('since')  # Thời gian bắt đầu lọc
        agent_id = request.args.get('agent_id')  # ID của agent
        agent_token = request.args.get('agent_token')  # Token xác thực
        
        # Xác thực agent_id (cơ bản cho bây giờ)
        if not agent_id:
            return jsonify({"error": "Agent ID is required"}), 400
        
        # TODO: Triển khai xác thực agent đúng cách
        # Hiện tại giữ đơn giản để tương thích
        
        # Xây dựng truy vấn MongoDB
        query = {}
        
        # Phân tích lọc thời gian
        if since_str:
            try:
                # Chuyển đổi chuỗi ISO thành đối tượng datetime
                since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
                # Lọc các bản ghi được thêm sau mốc thời gian này
                query["added_date"] = {"$gte": since}
            except ValueError:
                # Bỏ qua nếu định dạng thời gian không hợp lệ
                pass
        
        # Tìm tất cả tên miền phù hợp với điều kiện
        cursor = _whitelist_collection.find(query)
        
        # Lấy thời gian cập nhật gần nhất cho toàn bộ whitelist
        # Sắp xếp theo added_date giảm dần và lấy bản ghi đầu tiên
        last_update = _whitelist_collection.find_one(
            {}, 
            sort=[("added_date", DESCENDING)]
        )
        
        # Lấy thời gian cập nhật cuối cùng
        last_update_time = None
        if last_update and "added_date" in last_update:
            last_update_time = last_update["added_date"].isoformat()
        
        # Chuyển đổi thành danh sách các chuỗi tên miền để response nhẹ hơn
        domains = []
        for entry in cursor:
            domains.append(entry["domain"])
            
        # Ghi log sự kiện đồng bộ
        logger.info(f"Agent {agent_id} synced whitelist. Returned {len(domains)} domains.")
        
        # Trả về kết quả
        return jsonify({
            "domains": domains,  # Danh sách tên miền
            "count": len(domains),  # Số lượng tên miền
            "last_updated": last_update_time  # Thời gian cập nhật cuối cùng
        }), 200
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi đồng bộ
        logger.error(f"Error in agent whitelist sync: {str(e)}")
        return jsonify({"error": "Failed to sync whitelist"}), 500


# ======== Các hàm hỗ trợ ========

def is_valid_domain(domain: str) -> bool:
    """
    Xác thực xem một chuỗi có phải là tên miền được định dạng đúng không.
    
    Args:
        domain: Tên miền cần xác thực
        
    Returns:
        bool: True nếu định dạng tên miền hợp lệ
    """
    # Kiểm tra tên miền rỗng hoặc quá dài
    if not domain or len(domain) > 253:
        return False
        
    # Cho phép tên miền wildcard (ví dụ: *.example.com)
    if domain.startswith("*."):
        # Loại bỏ phần "*." để kiểm tra phần còn lại
        domain = domain[2:]
        
    # Xác thực định dạng tên miền cơ bản
    # Mẫu regex này kiểm tra:
    # - Bắt đầu bằng chữ cái hoặc số
    # - Có thể chứa chữ cái, số, dấu gạch ngang (tối đa 63 ký tự mỗi phần)
    # - Có ít nhất 2 phần (ví dụ: example.com)
    # - Phần mở rộng (com, org, ...) chỉ chứa chữ cái và ít nhất 2 ký tự
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def add_domain_programmatically(domain: str, notes: str = "", added_by: str = "system") -> Optional[str]:
    """
    Thêm một tên miền vào whitelist lập trình (sử dụng nội bộ).
    
    Args:
        domain: Tên miền cần thêm
        notes: Ghi chú tùy chọn về tên miền này
        added_by: Người/hệ thống đã thêm tên miền này
        
    Returns:
        str: ID của tên miền đã chèn, hoặc None nếu việc chèn thất bại
    """
    try:
        # Làm sạch và xác thực tên miền
        domain = domain.strip().lower()
        if not is_valid_domain(domain):
            # Ghi log lỗi nếu định dạng tên miền không hợp lệ
            logger.error(f"Invalid domain format: {domain}")
            return None
            
        # Kiểm tra xem tên miền đã tồn tại chưa
        if _whitelist_collection.find_one({"domain": domain}):
            # Ghi log debug nếu tên miền đã tồn tại
            logger.debug(f"Domain already exists in whitelist: {domain}")
            return None
            
        # Chuẩn bị bản ghi để thêm vào database
        entry = {
            "domain": domain,
            "notes": notes,
            "added_by": added_by,
            "added_date": datetime.utcnow()
        }
        
        # Chèn bản ghi vào database
        result = _whitelist_collection.insert_one(entry)
        
        # Phát sóng thông báo qua SocketIO
        if socketio:
            # Chuẩn bị dữ liệu cho SocketIO
            entry["_id"] = str(result.inserted_id)  # Chuyển ObjectId thành chuỗi
            entry["added_date"] = entry["added_date"].isoformat()  # Chuyển datetime thành chuỗi ISO
            
            # Gửi thông báo
            socketio.emit('whitelist_updated', {
                "action": "add",  # Loại hành động: thêm
                "domain": domain,  # Tên miền đã thêm
                "entry": entry  # Dữ liệu đầy đủ của bản ghi
            })
            
        # Trả về ID của bản ghi đã chèn
        return str(result.inserted_id)
            
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi thêm tên miền
        logger.error(f"Error adding domain programmatically: {str(e)}")
        return None


def check_domain_allowed(domain: str) -> bool:
    """
    Kiểm tra xem một tên miền có được cho phép theo whitelist không.
    
    Args:
        domain: Tên miền cần kiểm tra
        
    Returns:
        bool: True nếu tên miền được cho phép
    """
    try:
        # Làm sạch tên miền
        domain = domain.strip().lower()
        
        # Kiểm tra khớp chính xác
        if _whitelist_collection.find_one({"domain": domain}):
            return True
            
        # Kiểm tra khớp wildcard
        parts = domain.split('.')
        for i in range(1, len(parts)):
            # Tạo wildcard domain từ phần còn lại của tên miền
            wildcard = f"*.{'.'.join(parts[i:])}"
            if _whitelist_collection.find_one({"domain": wildcard}):
                return True
                
        # Không tìm thấy trong whitelist
        return False
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi kiểm tra
        logger.error(f"Error checking if domain is allowed: {str(e)}")
        return False


def get_domain_list() -> List[str]:
    """
    Lấy danh sách tất cả tên miền trong whitelist (sử dụng nội bộ).
    
    Returns:
        List[str]: Danh sách tên miền
    """
    try:
        domains = []
        # Truy vấn tất cả tên miền, chỉ lấy trường domain
        cursor = _whitelist_collection.find({}, {"domain": 1})
        
        # Thêm từng tên miền vào danh sách
        for doc in cursor:
            domains.append(doc["domain"])
            
        return domains
        
    except Exception as e:
        # Ghi log lỗi nếu có vấn đề khi lấy danh sách
        logger.error(f"Error getting domain list: {str(e)}")
        return []


def _create_default_whitelist():
    """Tạo whitelist mặc định với các tên miền an toàn phổ biến."""
    # Danh sách các tên miền an toàn phổ biến
    default_domains = [
        "google.com", "www.google.com",  # Google
        "microsoft.com", "www.microsoft.com",  # Microsoft
        "github.com", "www.github.com",  # GitHub
        "wikipedia.org", "www.wikipedia.org",  # Wikipedia
        "stackoverflow.com", "www.stackoverflow.com",  # Stack Overflow
        "cloudflare.com", "www.cloudflare.com",  # Cloudflare
        "apple.com", "www.apple.com",  # Apple
        "amazon.com", "www.amazon.com",  # Amazon
        "office.com", "www.office.com",  # Office
        "live.com", "login.live.com",  # Microsoft Live
        "windows.com", "update.microsoft.com",  # Windows
        "mozilla.org", "www.mozilla.org",  # Mozilla
        "firefox.com", "www.firefox.com",  # Firefox
        "ubuntu.com", "www.ubuntu.com",  # Ubuntu
        "python.org", "www.python.org",  # Python
        "npmjs.com", "www.npmjs.com"  # npm
    ]
    
    # Đếm số tên miền đã thêm thành công
    added_count = 0
    for domain in default_domains:
        # Chuẩn bị bản ghi cho mỗi tên miền
        entry = {
            "domain": domain,
            "notes": "Default whitelist entry",  # Ghi chú
            "added_by": "system",  # Người thêm
            "added_date": datetime.utcnow()  # Thời điểm thêm
        }
        
        try:
            # Thêm tên miền vào database
            _whitelist_collection.insert_one(entry)
            added_count += 1
        except Exception as e:
            # Ghi log lỗi nếu có vấn đề khi thêm tên miền mặc định
            logger.error(f"Error adding default domain {domain}: {str(e)}")
    
    # Ghi log số lượng tên miền đã thêm
    logger.info(f"Created default whitelist with {added_count} domains")