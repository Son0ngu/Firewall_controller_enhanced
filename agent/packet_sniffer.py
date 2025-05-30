# Import các thư viện cần thiết
import logging  # Thư viện ghi log để theo dõi hoạt động của module
import threading  # Thư viện hỗ trợ đa luồng để chạy bắt gói tin trong luồng riêng
import time  # Thư viện xử lý thời gian, dùng cho việc tạm dừng
import re  # ✅ ADD: Missing import for regex validation
from datetime import datetime  # Thư viện xử lý ngày giờ để gắn thời gian cho các sự kiện
from typing import Callable, Dict, Optional  # Thư viện hỗ trợ kiểu dữ liệu tĩnh

# Import các module từ thư viện Scapy để bắt và phân tích gói tin mạng
from scapy.all import sniff  # Hàm sniff để bắt gói tin mạng
from scapy.layers.http import HTTPRequest  # Lớp xử lý gói tin HTTP Request
from scapy.layers.inet import IP, TCP, UDP  # ✅ ADD: Missing UDP import
from scapy.layers.dns import DNS  # ✅ ADD: Missing DNS import
from scapy.packet import Raw  # ✅ ADD: Missing Raw import
from scapy.layers.tls.extensions import ServerName  # Lớp xử lý phần mở rộng ServerName trong TLS
from scapy.layers.tls.handshake import TLSClientHello  # Lớp xử lý bản tin ClientHello trong TLS
from scapy.packet import Packet  # Lớp cơ sở cho các gói tin trong Scapy

# Cấu hình logger cho module này
# Sử dụng tên riêng để dễ dàng lọc log từ module này
logger = logging.getLogger("packet_sniffer")

class PacketSniffer:
    """
    Captures and analyzes network packets to extract domain information from HTTP and HTTPS traffic.
    Uses Scapy to capture network traffic.
    """
    
    def __init__(self, callback: Callable[[Dict], None]):
        """
        Initialize the packet sniffer.
        
        Args:
            callback: Function to call when a domain is detected in traffic.
                      Will receive a dictionary with domain info.
        """
        # Hàm callback sẽ được gọi khi phát hiện tên miền trong lưu lượng mạng
        # Callback nhận một dict chứa thông tin về tên miền, IP, cổng, v.v.
        self.callback = callback
        
        # Cờ báo hiệu trạng thái hoạt động của bộ bắt gói tin
        # Dùng để điều khiển vòng lặp bắt gói tin
        self.running = False
        
        # Biến lưu trữ tham chiếu đến luồng bắt gói tin
        # Sẽ được khởi tạo khi gọi phương thức start()
        self.capture_thread = None
    
    def start(self):
        """Start capturing packets in a background thread."""
        # Kiểm tra nếu đã đang chạy thì không khởi động lại
        # Tránh tạo nhiều luồng bắt gói tin dẫn đến xung đột
        if self.running:
            logger.warning("Packet sniffer is already running")
            return
        
        # Đánh dấu là đang chạy
        self.running = True
        
        # Tạo luồng mới để bắt gói tin
        # - target=self._capture_packets: Hàm sẽ được thực thi trong luồng
        # - daemon=True: Khi chương trình chính kết thúc, luồng này sẽ tự động kết thúc
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Ghi log thông báo đã khởi động
        logger.info("Packet sniffer started")
    
    def stop(self):
        """Stop capturing packets."""
        # Kiểm tra nếu không đang chạy thì không cần dừng
        if not self.running:
            logger.warning("Packet sniffer is not running")
            return
        
        # Đánh dấu yêu cầu dừng luồng bắt gói tin
        # Cờ này được kiểm tra trong hàm stop_filter của sniff()
        self.running = False
        
        # Nếu có luồng bắt gói tin, chờ cho nó kết thúc
        if self.capture_thread:
            # Chờ luồng kết thúc với timeout 3 giây
            # Tránh treo chương trình nếu luồng không kết thúc
            self.capture_thread.join(timeout=3)
            
            # Kiểm tra xem luồng có thực sự dừng hay không
            if self.capture_thread.is_alive():
                # Ghi log cảnh báo nếu luồng không dừng được
                logger.warning("Packet capture thread did not terminate gracefully")
        
        # Ghi log thông báo đã dừng
        logger.info("Packet sniffer stopped")
    
    def _capture_packets(self):
        """Main packet capture loop với error recovery"""
        max_retries = 3
        retry_count = 0
        
        while self.running and retry_count < max_retries:
            try:
                # Xây dựng bộ lọc BPF (Berkeley Packet Filter) cho gói tin
                # ✅ FIX: Enhanced filter để bắt nhiều traffic hơn
                filter_str = "tcp and (dst port 80 or dst port 443 or dst port 53) or udp and dst port 53"
                
                # Ghi log thông tin về bộ lọc đang sử dụng
                logger.info("Started packet capture with filter: %s", filter_str)
                
                # Bắt đầu bắt gói tin với Scapy
                # Các tham số:
                # - filter: Chuỗi bộ lọc BPF, xác định gói tin nào sẽ được bắt
                # - prn: Hàm xử lý cho mỗi gói tin được bắt
                # - store=0: Không lưu gói tin trong bộ nhớ (tiết kiệm bộ nhớ)
                # - stop_filter: Hàm kiểm tra khi nào dừng bắt gói tin
                sniff(
                    filter=filter_str,
                    prn=self._process_packet,  # Gọi _process_packet cho mỗi gói tin
                    store=0,  # Không lưu gói tin vào bộ nhớ để tránh tràn bộ nhớ
                    stop_filter=lambda _: not self.running  # Dừng khi self.running = False
                )
                break  # Thành công, thoát loop
                
            except Exception as e:
                retry_count += 1
                logger.error(f"Error in packet capture (attempt {retry_count}/{max_retries}): {str(e)}")
                
                if retry_count < max_retries and self.running:
                    logger.info(f"Retrying packet capture in 5 seconds...")
                    time.sleep(5)
                else:
                    logger.error("Failed to start packet capture after all retries")
                    break
    
    def _process_packet(self, packet: Packet):
        """
        Process a captured packet to extract domain information.
        
        Args:
            packet: The Scapy packet object
        """
        try:
            # ✅ FIX: Enhanced packet processing với better logic
            if not packet.haslayer(IP):
                return
            
            # Trích xuất thông tin cơ bản từ gói tin
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # ✅ FIX: Handle both TCP and UDP
            domain = None
            protocol = "unknown"
            dst_port = None
            src_port = None
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                
                # Xác định giao thức dựa vào cổng đích
                if dst_port == 80:
                    protocol = "HTTP"
                    domain = self._extract_http_host(packet)
                elif dst_port == 443:
                    protocol = "HTTPS"
                    domain = self._extract_https_sni(packet)
                else:
                    protocol = f"TCP/{dst_port}"
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                
                if dst_port == 53:
                    protocol = "DNS"
                    domain = self._extract_dns_query(packet)
                else:
                    protocol = f"UDP/{dst_port}"
            
            # ✅ FIX: Nếu tìm thấy tên miền hoặc có kết nối đáng chú ý, tạo record
            if domain or dst_port in [80, 443, 53]:
                # ✅ FIX: Create complete record with all required fields
                record = {
                    "timestamp": datetime.now().isoformat(),
                    "domain": domain,
                    "src_ip": src_ip,
                    "dest_ip": dst_ip,
                    "src_port": src_port,
                    "port": dst_port,  # ✅ FIX: Use dest_port as main port
                    "dest_port": dst_port,
                    "protocol": protocol,
                    "packet_size": len(packet),
                    "connection_direction": "outbound"
                }
                
                # ✅ FIX: Call callback with complete record
                self.callback(record)
    
        except Exception as e:
            logger.error("Error processing packet: %s", str(e))
    
    def _extract_http_host(self, packet) -> Optional[str]:
        """
        Extract the Host header from an HTTP packet.
        
        Args:
            packet: The Scapy packet
            
        Returns:
            str: The domain name from the Host header, or None if not found
        """
        try:
            # Cách 1: Sử dụng lớp HTTPRequest có sẵn của Scapy
            if packet.haslayer(HTTPRequest):
                if hasattr(packet[HTTPRequest], 'Host'):
                    # Giải mã giá trị Host từ bytes sang chuỗi UTF-8
                    return packet[HTTPRequest].Host.decode('utf-8', errors='ignore')
            
            # Cách 2 (backup): Nếu cách 1 không thành công, thử trích xuất thủ công
            if packet.haslayer(TCP) and packet[TCP].payload:
                # Lấy nội dung payload của gói TCP
                payload = bytes(packet[TCP].payload)
                
                # Tìm trường "Host: " trong payload
                if b"Host: " in payload:
                    # Tìm vị trí bắt đầu của giá trị Host
                    host_idx = payload.find(b"Host: ") + 6  # Bỏ qua "Host: "
                    
                    # Tìm vị trí kết thúc của giá trị Host (CRLF - \r\n)
                    end_idx = payload.find(b"\r\n", host_idx)
                    
                    # Nếu tìm thấy cả điểm bắt đầu và kết thúc
                    if end_idx > host_idx:
                        # Trích xuất và giải mã giá trị host
                        host = payload[host_idx:end_idx].decode('utf-8', errors='ignore')
                        return host.strip()  # Loại bỏ khoảng trắng thừa
            
            # Nếu không tìm thấy bằng cả hai cách
            return None
            
        except Exception as e:
            # Bắt và xử lý các ngoại lệ có thể xảy ra trong quá trình trích xuất
            logger.error("Error extracting HTTP host: %s", str(e))
            return None
    
    def _extract_https_sni(self, packet) -> Optional[str]:
        """
        Extract the Server Name Indication (SNI) from TLS ClientHello.
        
        Args:
            packet: The Scapy packet
            
        Returns:
            str: The domain from SNI, or None if not found/not a ClientHello
        """
        try:
            # Cách 1: Sử dụng lớp TLS của Scapy để trích xuất SNI
            if packet.haslayer(TLSClientHello):
                client_hello = packet[TLSClientHello]
                
                # Duyệt qua các phần mở rộng (extensions) trong ClientHello
                if hasattr(client_hello, 'ext') and client_hello.ext:
                    for extension in client_hello.ext:
                        # Kiểm tra nếu là phần mở rộng ServerName
                        if isinstance(extension, ServerName):
                            # Kiểm tra nếu có tên server trong extension
                            if hasattr(extension, 'servernames') and extension.servernames:
                                # Giải mã tên server từ bytes sang chuỗi UTF-8
                                servername = extension.servernames[0].servername.decode('utf-8', errors='ignore')
                                # Xác thực tên miền trước khi trả về
                                if self._is_valid_hostname(servername):
                                    return servername
            
            # Cách 2: Phân tích thủ công nếu lớp TLS của Scapy không hoạt động đúng
            if packet.haslayer(TCP) and packet[TCP].payload:
                # Lấy nội dung payload của gói TCP
                payload = bytes(packet[TCP].payload)
                
                # Kiểm tra độ dài tối thiểu cho TLS handshake
                if len(payload) < 43:
                    return None
                    
                # Kiểm tra loại bản ghi TLS (0x16 = handshake) và phiên bản
                if payload[0] != 0x16:  # Không phải handshake
                    return None
                
                # Kiểm tra nếu đây là bản tin ClientHello (loại handshake = 1)
                if len(payload) <= 5 or payload[5] != 0x01:
                    return None

                # ✅ FIX: Enhanced SNI extraction với better error handling
                try:
                    # Bỏ qua header bản ghi (5 bytes) và header handshake (4 bytes)
                    pos = 9
                    
                    # Bỏ qua phiên bản client (2 bytes)
                    pos += 2
                    
                    # Bỏ qua random client (32 bytes)
                    pos += 32
                    
                    # Bỏ qua session ID
                    if pos >= len(payload):
                        return None
                        
                    # Độ dài session ID + bỏ qua nó
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length
                    
                    # Bỏ qua danh sách cipher suites
                    if pos + 2 > len(payload):
                        return None
                        
                    # Độ dài cipher suites (2 bytes) + bỏ qua nó
                    cipher_suites_length = (payload[pos] << 8) | payload[pos + 1]
                    pos += 2 + cipher_suites_length
                    
                    # Bỏ qua phương thức nén
                    if pos >= len(payload):
                        return None
                        
                    # Độ dài phương thức nén + bỏ qua nó
                    compression_methods_length = payload[pos]
                    pos += 1 + compression_methods_length
                    
                    # Kiểm tra xem có phần mở rộng không
                    if pos + 2 > len(payload):
                        return None
                        
                    # Độ dài tổng các phần mở rộng (2 bytes)
                    extensions_length = (payload[pos] << 8) | payload[pos + 1]
                    pos += 2
                    extensions_end = pos + extensions_length
                    
                    # Đảm bảo không đọc quá độ dài payload
                    if extensions_end > len(payload):
                        return None
                        
                    # Phân tích từng phần mở rộng
                    while pos + 4 <= extensions_end:
                        # Lấy loại phần mở rộng và độ dài
                        ext_type = (payload[pos] << 8) | payload[pos + 1]
                        pos += 2
                        
                        ext_length = (payload[pos] << 8) | payload[pos + 1]
                        pos += 2
                        
                        # Kiểm tra có đủ bytes cho phần mở rộng không
                        if pos + ext_length > extensions_end:
                            break
                        
                        # Kiểm tra nếu là phần mở rộng SNI (loại 0)
                        if ext_type == 0 and ext_length > 2:
                            # Bỏ qua độ dài danh sách tên server
                            if pos + 2 > extensions_end:
                                break
                            sni_list_length = (payload[pos] << 8) | payload[pos + 1]
                            pos += 2
                            
                            # Đảm bảo đủ bytes và loại tên đúng
                            if pos < extensions_end and payload[pos] == 0:  # Loại tên: host_name (0)
                                pos += 1
                                
                                # Lấy độ dài hostname
                                if pos + 2 > extensions_end:
                                    break
                                    
                                name_length = (payload[pos] << 8) | payload[pos + 1]
                                pos += 2
                                
                                # Đảm bảo có đủ bytes cho hostname
                                if pos + name_length <= extensions_end:
                                    try:
                                        # Giải mã hostname từ bytes sang chuỗi UTF-8
                                        hostname = payload[pos:pos + name_length].decode('utf-8', errors='ignore')
                                        
                                        # Xác thực hostname trước khi trả về
                                        if self._is_valid_hostname(hostname):
                                            return hostname
                                    except:
                                        pass  # Bỏ qua nếu giải mã thất bại, tiếp tục tìm
                        
                        # Di chuyển đến phần mở rộng tiếp theo
                        pos += ext_length
                
                except IndexError:
                    # Xử lý lỗi chỉ số trong quá trình phân tích
                    pass
                    
            # Nếu không tìm thấy bằng cả hai cách
            return None
            
        except Exception as e:
            # Bắt và xử lý các ngoại lệ có thể xảy ra
            logger.error("Error extracting HTTPS SNI: %s", str(e))
            return None

    def _extract_dns_query(self, packet) -> Optional[str]:
        """
        Extract domain from DNS query packet.
        
        Args:
            packet: The Scapy packet
            
        Returns:
            str: The queried domain, or None if not found
        """
        try:
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                # Kiểm tra nếu có DNS query
                if hasattr(dns_layer, 'qd') and dns_layer.qd:
                    # Lấy tên miền từ query
                    domain = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if self._is_valid_hostname(domain):
                        return domain
            return None
        except Exception as e:
            logger.error("Error extracting DNS query: %s", str(e))
            return None

    def _is_valid_hostname(self, hostname: str) -> bool:
        """
        Validates if a string is a plausible hostname.
        
        Args:
            hostname: The hostname to validate
            
        Returns:
            bool: True if the hostname appears valid
        """
        # Kiểm tra độ dài hostname
        if not hostname or len(hostname) > 253:
            return False
            
        # Kiểm tra ký tự hợp lệ (chữ cái, số, dấu chấm, dấu gạch ngang)
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            return False
            
        # Kiểm tra ít nhất có một dấu chấm (tên miền phải có ít nhất một cấp)
        if '.' not in hostname:
            return False
            
        # Kiểm tra từng phần của tên miền
        parts = hostname.split('.')
        for part in parts:
            if not part or part.startswith('-') or part.endswith('-'):
                return False
                
        return True

    def _is_ip_address(self, address: str) -> bool:
        """Check if string is an IP address (IPv4 or IPv6)"""
        try:
            # Try IPv4
            parts = address.split('.')
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts)
        except:
            pass
        
        try:
            # Try IPv6
            import ipaddress
            ipaddress.ip_address(address)
            return True
        except:
            pass
        
        return False

