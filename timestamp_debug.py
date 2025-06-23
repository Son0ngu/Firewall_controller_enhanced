"""
Timestamp Debug Tool - Phát hiện và sửa lỗi múi giờ trong log

Tool này sẽ:
1. Kiểm tra cách timestamp được tạo ở agent
2. Kiểm tra cách timestamp được lưu trong MongoDB
3. Kiểm tra cách timestamp được xử lý ở server
4. Kiểm tra cách timestamp được hiển thị ở frontend
5. Đề xuất giải pháp fix
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta
import pymongo
from bson import ObjectId
import requests
import logging

# Thêm đường dẫn để import module từ server/agent
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'server'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'agent'))

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("timestamp_debug")

# Constants
VIETNAM_TIMEZONE = timezone(timedelta(hours=7))
MONGODB_URI = "mongodb+srv://sonbx:1234@cluster0.dkzkq.mongodb.net/Monitoring?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "Monitoring"

def check_agent_timestamp_format():
    """Kiểm tra cách agent định dạng timestamp"""
    logger.info("⏱️  1. Kiểm tra timestamp format từ Agent")
    
    try:
        from agent.time_utils import (
            now, now_iso, now_utc_iso, now_vietnam_iso, now_server_compatible
        )
        
        # Lấy mẫu các định dạng thời gian
        current_timestamp = now()
        iso_format = now_iso()
        utc_iso = now_utc_iso()
        vietnam_iso = now_vietnam_iso()
        server_compatible = now_server_compatible()
        
        # Log kết quả
        logger.info(f"Unix timestamp: {current_timestamp}")
        logger.info(f"ISO format: {iso_format}")
        logger.info(f"UTC ISO: {utc_iso}")
        logger.info(f"Vietnam ISO: {vietnam_iso}")
        logger.info(f"Server compatible: {server_compatible}")
        
        # Kiểm tra múi giờ trong Vietnam ISO
        if "+07:00" in vietnam_iso:
            logger.info("✅ Vietnam ISO format có chứa timezone +07:00")
        else:
            logger.error("❌ Vietnam ISO format KHÔNG chứa timezone +07:00")
        
        # Kiểm tra multiple agent functions có cùng kết quả không
        now_dt = datetime.fromtimestamp(current_timestamp, VIETNAM_TIMEZONE)
        now_str = now_dt.isoformat()
        
        if now_str.startswith(vietnam_iso[:16]):  # So sánh đến phút
            logger.info("✅ Vietnam timestamp khớp với mong đợi")
        else:
            logger.error(f"❌ Vietnam timestamp không khớp. Expected: {now_str}, Got: {vietnam_iso}")
        
        # Kiểm tra now_server_compatible
        if "+07:00" in server_compatible:
            logger.info("✅ server_compatible format có chứa timezone +07:00")
        else:
            logger.error("❌ server_compatible format KHÔNG chứa timezone +07:00")

        return {
            "unix_timestamp": current_timestamp,
            "iso_format": iso_format,
            "utc_iso": utc_iso, 
            "vietnam_iso": vietnam_iso,
            "server_compatible": server_compatible
        }
    
    except ImportError:
        logger.error("❌ Không thể import agent.time_utils")
        return None
    except Exception as e:
        logger.error(f"❌ Lỗi khi kiểm tra agent timestamp: {e}")
        return None

def check_mongodb_timestamps():
    """Kiểm tra timestamp trong MongoDB"""
    logger.info("⏱️  2. Kiểm tra timestamp trong MongoDB")
    
    try:
        # Kết nối MongoDB
        client = pymongo.MongoClient(MONGODB_URI)
        db = client[DB_NAME]
        logs_collection = db.logs
        
        # Lấy 5 log gần nhất
        logs = list(logs_collection.find().sort("timestamp", -1).limit(5))
        
        if not logs:
            logger.warning("Không tìm thấy log nào trong MongoDB")
            return None
        
        results = []
        for i, log in enumerate(logs):
            # Lấy timestamp
            timestamp = log.get("timestamp")
            log_id = str(log.get("_id", ""))
            agent_id = log.get("agent_id", "unknown")
            
            # Xác định loại và giá trị
            timestamp_type = type(timestamp).__name__
            timestamp_value = str(timestamp)
            has_tzinfo = hasattr(timestamp, "tzinfo") and timestamp.tzinfo is not None
            
            # Thử chuyển đổi sang Vietnam time
            vietnam_time = None
            if isinstance(timestamp, datetime):
                if timestamp.tzinfo is None:
                    # Naive datetime - có thể là UTC hoặc đã là Vietnam time
                    utc_guess = timestamp.replace(tzinfo=timezone.utc)
                    vietnam_guess_from_utc = utc_guess.astimezone(VIETNAM_TIMEZONE)
                    logger.info(f"Log {i+1} ({log_id[:8]}): Naive datetime - nếu là UTC thì Vietnam time sẽ là {vietnam_guess_from_utc}")
                    vietnam_time = vietnam_guess_from_utc
                else:
                    # Timezone-aware datetime
                    vietnam_time = timestamp.astimezone(VIETNAM_TIMEZONE)
                    logger.info(f"Log {i+1} ({log_id[:8]}): Timezone-aware datetime - Vietnam time là {vietnam_time}")
            else:
                logger.warning(f"Log {i+1} ({log_id[:8]}): Không phải datetime, nên không thể chuyển đổi")
            
            # So sánh với thời gian hiện tại
            time_diff = ""
            if vietnam_time:
                now_vn = datetime.now(VIETNAM_TIMEZONE)
                diff_seconds = (now_vn - vietnam_time).total_seconds()
                time_diff = f"{diff_seconds/60:.1f} phút trước"
            
            # Kiểm tra nếu timestamp là 00:00-07:00 sáng VN hoặc 17:00-23:59 UTC
            is_suspicious = False
            if isinstance(timestamp, datetime):
                hour = timestamp.hour
                if timestamp.tzinfo is None:
                    # Nếu naive và là 17-23h, có thể là UTC
                    if 17 <= hour <= 23:
                        is_suspicious = True
                        logger.warning(f"⚠️ Log {i+1} ({log_id[:8]}): Timestamp giờ {hour} có thể là UTC, không phải VN")
                    # Nếu naive và là 0-7h, có thể là VN không được chuyển đổi từ UTC
                    elif 0 <= hour <= 7:
                        is_suspicious = True
                        logger.warning(f"⚠️ Log {i+1} ({log_id[:8]}): Timestamp giờ {hour} có thể là VN sai múi giờ")
            
            results.append({
                "log_id": log_id,
                "agent_id": agent_id,
                "timestamp": timestamp_value,
                "timestamp_type": timestamp_type,
                "has_tzinfo": has_tzinfo,
                "vietnam_time": str(vietnam_time) if vietnam_time else None,
                "time_diff": time_diff,
                "is_suspicious": is_suspicious
            })
            
            logger.info(f"Log {i+1}: {timestamp_type} - {timestamp_value} - tzinfo: {has_tzinfo}")
        
        return results
                
    except Exception as e:
        logger.error(f"❌ Lỗi khi kiểm tra MongoDB timestamps: {e}")
        return None

def check_server_timestamp_processing():
    """Kiểm tra xử lý timestamp ở Server"""
    logger.info("⏱️  3. Kiểm tra xử lý timestamp ở Server")
    
    try:
        from server.time_utils import (
            now_vietnam, now_vietnam_naive, parse_agent_timestamp_direct,
            to_vietnam_timezone
        )
        
        # Tạo một số test cases
        test_cases = [
            "2025-06-23T17:47:27.793+07:00",  # Vietnam time with timezone
            "2025-06-23T10:47:27.793Z",        # UTC with Z
            "2025-06-23T10:47:27.793+00:00",   # UTC with +00:00
            "2025-06-23T10:47:27.793",         # No timezone (assume UTC)
            "2025-06-23 10:47:27",             # Simple format (assume UTC)
            "2025-06-23 10:47:27.793000",      # Simple format with microseconds
            "2025-06-24T00:54:49",             # Suspicious early morning time (00:54)
        ]
        
        results = []
        for i, test in enumerate(test_cases):
            # Parse với hàm server
            try:
                parsed = parse_agent_timestamp_direct(test)
                parsed_str = str(parsed)
                parsed_type = type(parsed).__name__
                has_tzinfo = hasattr(parsed, "tzinfo") and parsed.tzinfo is not None
                
                # Kiểm tra chuyển đổi múi giờ
                vietnam_time = None
                if isinstance(parsed, datetime):
                    if not has_tzinfo:
                        vietnam_time = f"{parsed} (naive - assumed VN already)"
                    else:
                        vietnam_time = str(parsed.astimezone(VIETNAM_TIMEZONE))
                
                results.append({
                    "input": test,
                    "parsed": parsed_str,
                    "parsed_type": parsed_type,
                    "has_tzinfo": has_tzinfo,
                    "vietnam_time": vietnam_time
                })
                
                logger.info(f"Test {i+1}: '{test}' -> {parsed_str} ({parsed_type}, tzinfo: {has_tzinfo})")
                if vietnam_time:
                    logger.info(f"   Vietnam time: {vietnam_time}")
                    
                # Nếu kết quả có giờ từ 0-7, cảnh báo
                if isinstance(parsed, datetime) and 0 <= parsed.hour <= 7 and not has_tzinfo:
                    logger.warning(f"⚠️ Test {i+1}: Suspicious early morning time (hour={parsed.hour})")
            
            except Exception as e:
                logger.error(f"❌ Test {i+1} '{test}' failed: {e}")
                results.append({
                    "input": test,
                    "error": str(e)
                })
        
        return results
        
    except ImportError:
        logger.error("❌ Không thể import server.time_utils")
        return None
    except Exception as e:
        logger.error(f"❌ Lỗi khi kiểm tra server timestamp processing: {e}")
        return None

def check_frontend_timestamp_rendering():
    """Kiểm tra cách frontend render timestamp"""
    logger.info("⏱️  4. Kiểm tra cách frontend render timestamp")
    
    try:
        # Đọc file template logs.html để kiểm tra code
        with open(os.path.join('server', 'views', 'templates', 'logs.html'), 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # Tìm đoạn code xử lý timestamp
        timestamp_code_lines = []
        in_timestamp_section = False
        
        for line in template_content.splitlines():
            if "const timestamp" in line and "log.timestamp" in line:
                in_timestamp_section = True
            
            if in_timestamp_section:
                timestamp_code_lines.append(line.strip())
                if line.strip().endswith(";"):
                    in_timestamp_section = False
        
        timestamp_code = "\n".join(timestamp_code_lines)
        logger.info(f"Frontend timestamp rendering code:\n{timestamp_code}")
        
        # Thử các test case với JavaScript equivalent
        test_cases = [
            "2025-06-23T17:47:27.793+07:00",  # Vietnam time with timezone
            "2025-06-23T10:47:27.793Z",        # UTC with Z 
            "2025-06-23T10:47:27.793+00:00",   # UTC with +00:00
            "2025-06-23T10:47:27.793",         # No timezone (assume local)
            "2025-06-24T00:54:49",             # Suspicious early morning time (00:54)
        ]
        
        logger.info("JavaScript new Date() với các test cases:")
        for test in test_cases:
            logger.info(f"'{test}' nếu parse bằng new Date() sẽ thành giờ local của browser")
        
        # Phân tích mã frontend
        if "toLocaleString('vi-VN')" in timestamp_code:
            logger.info("✅ Frontend dùng toLocaleString('vi-VN') - OK")
        else:
            logger.warning("⚠️ Frontend không dùng toLocaleString('vi-VN')")
        
        return {
            "timestamp_code": timestamp_code,
            "test_cases": test_cases
        }
        
    except Exception as e:
        logger.error(f"❌ Lỗi khi kiểm tra frontend timestamp rendering: {e}")
        return None

def perform_end_to_end_test():
    """Thực hiện kiểm tra end-to-end"""
    logger.info("⏱️  5. Thực hiện kiểm tra end-to-end")
    
    try:
        # Tạo sample log
        from agent.time_utils import now, now_server_compatible
        
        current_time = now()
        sample_log = {
            "timestamp": now_server_compatible(),
            "level": "INFO",
            "action": "TEST",
            "domain": "timestamp.test",
            "source_ip": "127.0.0.1",
            "dest_ip": "8.8.8.8",
            "message": f"Timestamp test at unix time {current_time}"
        }
        
        logger.info(f"Sample log timestamp: {sample_log['timestamp']}")
        
        # Lưu log vào MongoDB
        client = pymongo.MongoClient(MONGODB_URI)
        db = client[DB_NAME]
        logs_collection = db.logs
        
        result = logs_collection.insert_one(sample_log)
        log_id = result.inserted_id
        
        logger.info(f"Inserted log with ID: {log_id}")
        
        # Lấy lại từ MongoDB
        saved_log = logs_collection.find_one({"_id": log_id})
        saved_timestamp = saved_log.get("timestamp")
        
        logger.info(f"Saved log timestamp: {saved_timestamp} (type: {type(saved_timestamp).__name__})")
        
        # Xem timestamp nó hiểu là gì
        from server.time_utils import to_vietnam_timezone
        
        if isinstance(saved_timestamp, datetime):
            if saved_timestamp.tzinfo is None:
                logger.info(f"MongoDB stored naive datetime: {saved_timestamp}")
                # Giả sử đây là UTC
                utc_dt = saved_timestamp.replace(tzinfo=timezone.utc)
                vietnam_time = utc_dt.astimezone(VIETNAM_TIMEZONE)
                logger.info(f"If UTC, Vietnam time would be: {vietnam_time}")
                # Giả sử đây đã là Vietnam time
                vn_dt = saved_timestamp.replace(tzinfo=VIETNAM_TIMEZONE)
                logger.info(f"If already Vietnam, time would be: {vn_dt}")
            else:
                logger.info(f"MongoDB stored timezone-aware datetime: {saved_timestamp}")
                vietnam_time = saved_timestamp.astimezone(VIETNAM_TIMEZONE)
                logger.info(f"Vietnam time: {vietnam_time}")
        else:
            logger.info(f"MongoDB did not store as datetime: {saved_timestamp}")
        
        return {
            "original": sample_log['timestamp'],
            "saved": str(saved_timestamp),
            "saved_type": type(saved_timestamp).__name__
        }
        
    except ImportError:
        logger.error("❌ Không thể import required modules")
        return None
    except Exception as e:
        logger.error(f"❌ Lỗi khi thực hiện end-to-end test: {e}")
        return None

def check_display_in_browser():
    """Kiểm tra cách timestamp hiển thị trong trình duyệt"""
    logger.info("⏱️  6. Kiểm tra timestamp trong trình duyệt")
    
    # Các test cases để thử trong browser console
    js_tests = """
// Các test cases để chạy trong Console của DevTools trình duyệt
const testCases = [
    "2025-06-23T17:47:27.793+07:00",  // Vietnam time
    "2025-06-23T10:47:27.793Z",        // UTC
    "2025-06-23T10:47:27.793",         // No timezone
    "2025-06-24T00:54:49+07:00",       // Early morning Vietnam
    new Date()                          // Current time
];

console.log("=== BROWSER TIMESTAMP TESTS ===");

// Test 1: Default Date display
console.log("Default Date display:");
testCases.forEach(ts => {
    const date = new Date(ts);
    console.log(`${ts} → ${date}`);
});

// Test 2: toLocaleString with vi-VN locale
console.log("\\ntoLocaleString('vi-VN'):");
testCases.forEach(ts => {
    const date = new Date(ts);
    console.log(`${ts} → ${date.toLocaleString('vi-VN')}`);
});

// Test 3: Convert using timezone offset
console.log("\\nTimezone conversion:");
testCases.forEach(ts => {
    const date = new Date(ts);
    // Adjusted for Vietnam +7
    const vietnamTime = new Date(date.getTime() + (7*60*60*1000 - date.getTimezoneOffset()*60*1000));
    console.log(`${ts} → ${vietnamTime.toLocaleString('vi-VN')}`);
});
    """
    
    logger.info("Để kiểm tra trong trình duyệt, copy đoạn code sau và paste vào Console:")
    logger.info("\n" + js_tests)
    
    return js_tests

def diagnose_and_recommend():
    """Phân tích và đưa ra khuyến nghị"""
    logger.info("⏱️  7. Phân tích và khuyến nghị")
    
    # Dựa trên kết quả kiểm tra, đưa ra khuyến nghị
    logger.info("\n=== PHÂN TÍCH VÀ KHUYẾN NGHỊ ===\n")
    
    logger.info("Kết luận có khả năng cao:")
    logger.info("1. Agent gửi timestamp với đúng định dạng ISO và timezone +07:00")
    logger.info("2. MongoDB lưu timestamp dưới dạng naive datetime (không có timezone)")
    logger.info("3. Khi server đọc timestamp từ MongoDB, nó đã coi đó là giờ VN")
    logger.info("4. Server gửi timestamp dạng string (có thể là ISO) đến frontend")
    logger.info("5. Frontend tạo đối tượng Date từ string, browser tự convert sang local (UTC/GMT)")
    
    logger.info("\n🔴 Khuyến nghị khắc phục:")
    
    recommendation = """
    1. Sửa trong file server/log_model.py - Hàm find_all_logs:
    ```python
    # Thay vì gửi naive datetime string hoặc timezone-aware datetime
    # Cần convert rõ ràng sang ISO string với timezone +07:00
    if "timestamp" in log and log["timestamp"]:
        # Đảm bảo timestamp là ISO string với timezone +07:00
        if hasattr(log["timestamp"], 'isoformat'):  
            log["timestamp"] = log["timestamp"].replace(tzinfo=VIETNAM_TIMEZONE).isoformat()
        elif isinstance(log["timestamp"], str):
            # Đã là string, check và ensure có +07:00
            if "+07:00" not in log["timestamp"] and "Z" not in log["timestamp"]:
                # Parse và convert
                dt = parse_agent_timestamp_direct(log["timestamp"])
                log["timestamp"] = dt.replace(tzinfo=VIETNAM_TIMEZONE).isoformat()
    ```

    2. Sửa trong file server/views/templates/logs.html:
    ```javascript
    // Thay vì
    const timestamp = log.timestamp ? 
        (typeof log.timestamp === 'string' ? 
            new Date(log.timestamp).toLocaleString('vi-VN') : log.timestamp)
        : 'Unknown';
        
    // Sửa thành
    const timestamp = log.timestamp ? 
        (typeof log.timestamp === 'string' ? 
            // Đảm bảo parse chuỗi ISO đúng timezone
            (log.timestamp.includes('+07:00') ?
                new Date(log.timestamp).toLocaleString('vi-VN') : 
                // Không có timezone, coi là UTC và + thêm 7h
                new Date(new Date(log.timestamp).getTime() + 7*60*60*1000).toLocaleString('vi-VN')
            ) : log.timestamp)
        : 'Unknown';
    ```
    
    3. Fix the formatTimestamp function in logs.html:
    ```javascript
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'Unknown';
        try {
            // Handle timezone explicitly for Vietnam (+7)
            const date = new Date(timestamp);
            if (timestamp.includes('+07:00')) {
                // Already Vietnam time
                return date.toLocaleString('vi-VN');
            } else {
                // Assume UTC, convert to Vietnam time (+7)
                const vietnamTime = new Date(date.getTime() + 7*60*60*1000);
                return vietnamTime.toLocaleString('vi-VN');
            }
        } catch (e) {
            console.error('Error formatting timestamp:', timestamp, e);
            return String(timestamp);
        }
    }
    ```
    """
    
    logger.info(recommendation)
    
    return recommendation

def full_debug():
    """Thực hiện toàn bộ quy trình debug"""
    try:
        results = {
            "agent_timestamp": check_agent_timestamp_format(),
            "mongodb_timestamps": check_mongodb_timestamps(),
            "server_processing": check_server_timestamp_processing(),
            "frontend_rendering": check_frontend_timestamp_rendering(),
            "end_to_end_test": perform_end_to_end_test(),
            "browser_test": check_display_in_browser()
        }
        
        # Lưu kết quả kiểm tra
        with open('timestamp_debug_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Kết quả đã được lưu vào timestamp_debug_results.json")
        
        # Đưa ra khuyến nghị
        recommendation = diagnose_and_recommend()
        
        return results, recommendation
    
    except Exception as e:
        logger.error(f"❌ Lỗi trong quá trình debug: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == "__main__":
    logger.info("🕒 Bắt đầu chẩn đoán lỗi timestamp")
    full_debug()
    logger.info("✅ Hoàn thành chẩn đoán")