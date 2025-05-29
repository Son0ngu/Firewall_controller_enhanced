"""
Firewall Controller Agent - Module Chính

Đây là điểm khởi đầu cho ứng dụng agent. Nó khởi tạo và quản lý tất cả các thành phần:
- Bắt và kiểm tra gói tin mạng
- Quản lý danh sách trắng (whitelist) các tên miền
- Điều khiển tường lửa
- Thu thập và gửi nhật ký (log)

Agent có thể chạy như một tiến trình thông thường hoặc đăng ký như một dịch vụ Windows.
"""

# Import các thư viện cần thiết
import logging  # Thư viện để ghi log
import signal  # Xử lý tín hiệu hệ thống (để bắt sự kiện khi người dùng dừng chương trình)
import sys  # Để làm việc với môi trường hệ thống
import time  # Để xử lý thời gian, tạm dừng
from typing import Dict  # Hỗ trợ gợi ý kiểu dữ liệu cho dictionary
import socket
import platform
import requests

# Import các module tự định nghĩa từ package agent
from config import get_config  # Đọc cấu hình từ file
from firewall_manager import FirewallManager  # Quản lý tường lửa
from log_sender import LogSender  # Gửi log tới server
from packet_sniffer import PacketSniffer  # Bắt gói tin mạng
from whitelist import WhitelistManager  # Quản lý danh sách tên miền cho phép
from heartbeat_sender import HeartbeatSender  # THÊM import
from command_processor import CommandProcessor  # ADD import

# Cấu hình hệ thống ghi log
# - level=logging.INFO: Chỉ ghi những thông báo từ mức INFO trở lên
# - format: Định dạng log gồm thời gian, tên module, mức log và nội dung
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("agent_main")  # Tạo logger cho module này

# Khai báo biến toàn cục để lưu trữ các thành phần của agent
# Các biến này sẽ được khởi tạo trong hàm initialize_components()
config = None  # Cấu hình của agent
firewall = None  # Quản lý tường lửa
whitelist = None  # Quản lý danh sách tên miền được phép
log_sender = None  # Gửi log đến server
packet_sniffer = None  # Bắt gói tin mạng
heartbeat_sender = None  # THÊM global variable
command_processor = None  # ADD global variable
running = True  # Điều khiển vòng lặp chính, khi False thì agent sẽ dừng

def handle_domain_detection(record: Dict):
    """
    Hàm callback khi phát hiện kết nối đến một tên miền trong lưu lượng mạng.
    Kiểm tra tên miền với whitelist và thực hiện hành động phù hợp.
    
    Tham số:
        record: Dictionary chứa chi tiết kết nối mạng (tên miền, IP, v.v.)
    """
    try:
        # Lấy thông tin tên miền và IP đích từ bản ghi
        domain = record.get("domain")
        dest_ip = record.get("dest_ip")
        
        # Kiểm tra tính hợp lệ của dữ liệu
        if not domain or not dest_ip:
            logger.warning("Nhận được bản ghi kết nối không đầy đủ")
            return
        
        # Kiểm tra xem tên miền có trong danh sách cho phép không
        allowed = whitelist.is_allowed(domain)
        
        # Thêm thông tin hành động vào bản ghi
        record["action"] = "allow" if allowed else "block"
        
        # Đưa log vào hàng đợi để gửi đến server
        log_sender.queue_log(record)
        
        # Thực hiện hành động dựa trên cấu hình và kết quả kiểm tra whitelist
        if not allowed:
            # Nếu tên miền không được phép và cấu hình cho phép chặn
            if firewall and config["firewall"]["enabled"] and config["firewall"]["mode"] == "block":
                # Chặn IP đích tương ứng với tên miền không được phép
                firewall.block_ip(dest_ip, domain)
                logger.info(f"Đã chặn kết nối đến {domain} ({dest_ip})")
            else:
                # Chỉ ghi log cảnh báo nếu đang ở chế độ giám sát (không chặn)
                logger.warning(f"Phát hiện kết nối đến tên miền không nằm trong whitelist: {domain} ({dest_ip})")
    
    except Exception as e:
        # Ghi log nếu xảy ra lỗi trong quá trình xử lý
        logger.error(f"Lỗi trong hàm xử lý phát hiện tên miền: {str(e)}", exc_info=True)

def initialize_components():
    """Khởi tạo tất cả các thành phần của agent."""
    global config, firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender, command_processor
    
    try:
        logger.info("Đang khởi tạo các thành phần của agent...")
        
        # FIX: Check if global config is available
        if not config:
            logger.error("Global config chưa được khởi tạo! Attempting to load...")
            config = get_config()  # Load config nếu chưa có
            if not config:
                raise ValueError("Cannot load configuration")
        
        # IMPROVED: Better local IP detection
        def get_local_ip():
            try:
                # Try multiple methods to get local IP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    return s.getsockname()[0]
            except:
                try:
                    # Fallback: get hostname IP
                    return socket.gethostbyname(socket.gethostname())
                except:
                    return "127.0.0.1"
        
        local_ip = get_local_ip()
        
        # IMPROVED: Better agent info collection
        agent_info = {
            "hostname": socket.gethostname(),
            "ip_address": local_ip,
            "platform": platform.system(),
            "os_info": f"{platform.system()} {platform.release()} {platform.version()}",
            "agent_version": "1.0.0",
            "python_version": f"{platform.python_version()}",
            "architecture": platform.architecture()[0]
        }
    
        # IMPROVED: Better registration logic với multiple URLs
        registration_success = False
        server_urls = config['server'].get('urls', [config['server']['url']])
        
        for server_url in server_urls:
            try:
                register_url = f"{server_url.rstrip('/')}/api/agents/register"
                logger.info(f"Attempting registration with: {register_url}")
                
                response = requests.post(
                    register_url, 
                    json=agent_info, 
                    timeout=config['server'].get('connect_timeout', 10),
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        agent_data = data.get('data', {})
                        logger.info(f"✅ Agent registered successfully with ID: {agent_data.get('agent_id')}")
                        
                        # Lưu agent_id và token vào config để sử dụng sau
                        config['agent_id'] = agent_data.get('agent_id')
                        config['agent_token'] = agent_data.get('token')
                        config['user_id'] = agent_data.get('user_id')
                        config['server_url'] = server_url  # Save working server URL
                        
                        logger.info(f"Agent token: {config['agent_token'][:8]}...")
                        registration_success = True
                        break
                    else:
                        logger.warning(f"Registration failed with {server_url}: {data.get('error', 'Unknown error')}")
                else:
                    logger.warning(f"Registration failed with {server_url}: HTTP {response.status_code}")
                    
            except requests.exceptions.ConnectionError:
                logger.warning(f"Could not connect to {server_url}")
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout connecting to {server_url}")
            except Exception as e:
                logger.warning(f"Error registering with {server_url}: {e}")
        
        if not registration_success:
            logger.error("Failed to register with any server - agent functionality will be limited")
        
        # Initialize các components...
        # Initialize whitelist với updated config
        whitelist = WhitelistManager(config)
        logger.info(f"Whitelist initialized for agent: {local_ip}")
        
        # Khởi tạo quản lý tường lửa nếu được bật trong cấu hình
        if config["firewall"]["enabled"]:
            firewall = FirewallManager(config["firewall"]["rule_prefix"])
            logger.info(f"Firewall manager đã khởi tạo với {len(firewall.blocked_ips)} quy tắc chặn hiện có")
            
            # Link firewall với whitelist để auto-sync
            whitelist.set_firewall_manager(firewall)
            logger.info("Linked firewall manager with whitelist for auto-sync")
        else:
            logger.info("Chức năng tường lửa bị vô hiệu hóa trong cấu hình")
        
        # IMPROVED: Log sender với better config
        log_sender_config = {
            "server_url": config.get('server_url', config["server"]["url"]),  # Use working URL
            "batch_size": config["logging"]["sender"]["batch_size"],
            "max_queue_size": config["logging"]["sender"]["max_queue_size"],
            "send_interval": config["logging"]["sender"]["send_interval"],
            "timeout": config["server"].get("connect_timeout", 10)
        }
        
        # Thêm agent credentials vào log sender config
        if config.get('agent_id') and config.get('agent_token'):
            log_sender_config["agent_id"] = config['agent_id']
            log_sender_config["agent_token"] = config['agent_token']
        
        log_sender = LogSender(log_sender_config)
        log_sender.start()
        logger.info("Log sender đã khởi tạo và bắt đầu")
        
        # Khởi tạo module bắt gói tin
        packet_sniffer = PacketSniffer(callback=handle_domain_detection)
        packet_sniffer.start()
        logger.info("Packet sniffer đã khởi tạo và bắt đầu")
        
        # Heartbeat sender với better error handling
        if registration_success:
            heartbeat_sender = HeartbeatSender(config)
            heartbeat_sender.set_agent_credentials(config['agent_id'], config['agent_token'])
            heartbeat_sender.start()
            logger.info("Heartbeat sender started")
        else:
            logger.warning("Skipping heartbeat sender - agent not registered")
        
        # Initialize command processor
        command_processor = CommandProcessor()
        logger.info(" Command processor initialized")
        
        # Start command polling (check for commands periodically)
        if registration_success:
            start_command_polling()
        
        logger.info("Tất cả các thành phần của agent đã khởi tạo thành công")
        
    except Exception as e:
        logger.error(f"Lỗi khi khởi tạo các thành phần: {str(e)}", exc_info=True)
        raise

def start_command_polling():
    """Start polling for commands from server"""
    import threading
    import requests
    import time
    
    def poll_commands():
        while running:
            try:
                if not config.get('agent_id') or not config.get('agent_token'):
                    time.sleep(30)  # Wait if not registered
                    continue
                
                # Check for pending commands
                server_url = config.get('server_url', config["server"]["url"])
                commands_url = f"{server_url.rstrip('/')}/api/agents/commands"
                
                params = {
                    'agent_id': config['agent_id'],
                    'token': config['agent_token']
                }
                
                response = requests.get(commands_url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    commands = data.get('data', {}).get('commands', [])
                    
                    for command in commands:
                        process_command(command)
                
                time.sleep(5)  # Poll every 5 seconds
                
            except Exception as e:
                logger.error(f"Error polling commands: {e}")
                time.sleep(10)  # Wait longer on error
    
    # Start polling in background thread
    polling_thread = threading.Thread(target=poll_commands)
    polling_thread.daemon = True
    polling_thread.start()
    logger.info("Command polling started")

def process_command(command: Dict):
    """Process a command from server"""
    try:
        command_id = command.get('command_id')
        logger.info(f"Processing command {command_id}: {command.get('command_type')}")
        
        # Process command
        result = command_processor.process_command(command)
        
        # Send result back to server
        server_url = config.get('server_url', config["server"]["url"])
        result_url = f"{server_url.rstrip('/')}/api/agents/command/result"
        
        result_data = {
            'agent_id': config['agent_id'],
            'token': config['agent_token'],
            'command_id': command_id,
            'status': 'completed' if result.get('success') else 'failed',
            'result': result.get('message') or result.get('error', 'No result'),
            'execution_time': result.get('execution_time', 0)
        }
        
        response = requests.post(result_url, json=result_data, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"Command {command_id} result sent successfully")
        else:
            logger.error(f"Failed to send command result: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error processing command {command.get('command_id')}: {e}")

def cleanup():
    """
    Dừng tất cả các thành phần một cách an toàn khi agent kết thúc.
    Bao gồm: packet_sniffer, whitelist updater, log_sender và có thể xóa các quy tắc tường lửa.
    """
    global firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender, command_processor  # THÊM heartbeat_sender
    
    logger.info("Đang dừng các thành phần của agent...")
    
    # Dừng packet sniffer - module bắt gói tin
    if packet_sniffer:
        try:
            packet_sniffer.stop()
            logger.info("Packet sniffer đã dừng")
        except Exception as e:
            logger.error(f"Lỗi khi dừng packet sniffer: {str(e)}")
    
    # Dừng cập nhật whitelist
    if whitelist:
        try:
            whitelist.stop_periodic_updates()
            logger.info("Whitelist updater đã dừng")
        except Exception as e:
            logger.error(f"Lỗi khi dừng whitelist updater: {str(e)}")
    
    # Dừng log sender và đẩy các log còn trong hàng đợi
    if log_sender:
        try:
            log_sender.stop()  # Hàm này sẽ cố gắng gửi các log còn lại trước khi thoát
            logger.info("Log sender đã dừng")
        except Exception as e:
            logger.error(f"Lỗi khi dừng log sender: {str(e)}")
    
    # Stop heartbeat sender
    if heartbeat_sender:
        try:
            heartbeat_sender.stop()
            logger.info("Heartbeat sender đã dừng")
        except Exception as e:
            logger.error(f"Lỗi khi dừng heartbeat sender: {str(e)}")
    
    # Xóa các quy tắc tường lửa nếu được cấu hình
    if firewall and config and config["firewall"]["cleanup_on_exit"]:
        try:
            logger.info("Đang xóa các quy tắc tường lửa...")
            firewall.clear_all_rules()  # Xóa tất cả các quy tắc do agent tạo ra
            logger.info("Các quy tắc tường lửa đã được xóa")
        except Exception as e:
            logger.error(f"Lỗi khi xóa các quy tắc tường lửa: {str(e)}")
    
    # Command processor cleanup if needed
    if command_processor:
        logger.info("Command processor stopped")
    
    logger.info("Agent đã đóng hoàn toàn")

def signal_handler(sig, frame):
    """
    Xử lý tín hiệu kết thúc từ hệ điều hành (Ctrl+C, kill, v.v).
    
    Tham số:
        sig: Mã tín hiệu nhận được
        frame: Frame stack hiện tại
    """
    global running
    logger.info(f"Nhận được tín hiệu {sig}, đang dừng agent...")
    running = False  # Đặt biến running thành False để thoát vòng lặp chính

def main():
    """Hàm chính của agent"""
    global config, firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender, command_processor
    
    try:
        # Load config vào global variable
        logger.info("Loading agent configuration...")
        config = get_config()  # Load vào global variable
        logger.info("Configuration loaded successfully")
        
        # Debug config để kiểm tra
        logger.info(f"Server URLs: {config['server'].get('urls', [])}")
        logger.info(f"Primary URL: {config['server']['url']}")
        logger.info(f"Whitelist auto-sync: {config['whitelist']['auto_sync']}")
        logger.info(f"Firewall enabled: {config['firewall']['enabled']}")
        
        # Áp dụng độ trễ khởi động nếu được cấu hình
        startup_delay = config["general"]["startup_delay"]
        if startup_delay > 0:
            logger.info(f"Áp dụng độ trễ khởi động {startup_delay} giây...")
            time.sleep(startup_delay)  # Tạm dừng trước khi khởi động
        
        # Kiểm tra quyền admin nếu yêu cầu (cần thiết cho thao tác tường lửa)
        if config["general"]["check_admin"] and config["firewall"]["enabled"]:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.error("Các thao tác với tường lửa yêu cầu quyền admin. Vui lòng chạy với quyền admin.")
                if config["firewall"]["enabled"]:
                    logger.warning("Tiếp tục mà không có khả năng điều khiển tường lửa...")
                    config["firewall"]["enabled"] = False  # Vô hiệu hóa chức năng tường lửa
        
        # Khởi tạo tất cả các thành phần
        initialize_components()
        
        # Gửi log thông báo khởi động
        if log_sender and config.get('agent_id'):
            startup_log = {
                "agent_id": config['agent_id'],  # Thêm agent_id
                "event_type": "agent_startup",  # Loại sự kiện: khởi động agent
                "hostname": socket.gethostname(),  # Tên máy
                "os": f"{platform.system()} {platform.version()}",  # Thông tin hệ điều hành
                "firewall_enabled": config["firewall"]["enabled"],  # Trạng thái tường lửa
                "firewall_mode": config["firewall"]["mode"]  # Chế độ tường lửa (block/monitor)
            }
            log_sender.queue_log(startup_log)  # Đưa log khởi động vào hàng đợi
        
        logger.info("Khởi tạo agent hoàn tất, bắt đầu vòng lặp chính")
        
        # Vòng lặp chính - giữ cho tiến trình hoạt động
        # Công việc chính được thực hiện trong các luồng nền
        while running:
            time.sleep(1)  # Ngủ 1 giây để giảm tải CPU
        
    except KeyboardInterrupt:
        # Bắt sự kiện khi người dùng nhấn Ctrl+C
        logger.info("Nhận được tín hiệu ngắt từ bàn phím")
    except Exception as e:
        # Bắt các lỗi không xử lý được
        logger.error(f"Lỗi không xử lý được trong agent main: {str(e)}", exc_info=True)
    finally:
        # Luôn thực hiện đoạn cleanup khi kết thúc, dù có lỗi hay không
        cleanup()

def run_as_service():
    """
    Chạy agent như một dịch vụ Windows, cho phép:
    - Cài đặt/gỡ bỏ dịch vụ
    - Khởi động/dừng dịch vụ từ trình quản lý dịch vụ Windows
    """
    try:
        # Import các module cần thiết cho dịch vụ Windows
        import servicemanager  # Tương tác với trình quản lý dịch vụ Windows
        import win32event  # Xử lý sự kiện Windows
        import win32service  # Giao diện với hệ thống dịch vụ Windows
        import win32serviceutil  # Tiện ích làm việc với dịch vụ Windows
        
        class AgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "FirewallControllerAgent"  # Tên dịch vụ trong hệ thống
            _svc_display_name_ = "Firewall Controller Agent"  # Tên hiển thị
            _svc_description_ = "Giám sát lưu lượng mạng và thực thi chính sách whitelist tên miền"  # Mô tả

            def __init__(self, args):
                # Khởi tạo framework dịch vụ
                win32serviceutil.ServiceFramework.__init__(self, args)
                # Tạo event để báo hiệu dừng dịch vụ
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                # Được gọi khi dịch vụ nhận lệnh dừng
                # Báo cáo trạng thái "đang chuẩn bị dừng"
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                # Đặt event dừng để báo hiệu dừng dịch vụ
                win32event.SetEvent(self.stop_event)
                # Đặt biến running thành False để dừng vòng lặp chính
                global running
                running = False

            def SvcDoRun(self):
                # Được gọi khi dịch vụ bắt đầu chạy
                # Báo cáo trạng thái "đang chạy"
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                # Ghi log khởi động dịch vụ vào event log Windows
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                
                # Gọi hàm main để chạy logic chính của agent
                main()

        # Xử lý các đối số dòng lệnh
        if len(sys.argv) == 1:
            # Không có đối số = chạy dịch vụ
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            # Có đối số = xử lý lệnh dịch vụ (install, remove, start, stop)
            win32serviceutil.HandleCommandLine(AgentService)
            
    except ImportError:
        # Xử lý trường hợp không cài đặt thư viện pywin32
        logger.error("Các module dịch vụ Windows cần thiết chưa được cài đặt. Vui lòng cài đặt pywin32.")
        sys.exit(1)

if __name__ == "__main__":
    # Đăng ký handler xử lý tín hiệu
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # kill command
    
    # Kiểm tra xem có đang chạy như một dịch vụ không
    if len(sys.argv) > 1 and sys.argv[1] in ['--service', 'install', 'remove', 'start', 'stop', 'update']:
        # Chạy như dịch vụ Windows
        run_as_service()
    else:
        # Chạy như tiến trình thông thường
        main()