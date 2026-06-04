import logging
import threading
from typing import Callable, Dict, Optional

from shared.time_utils import now_iso, sleep

from .scapy_config import configure_scapy, apply_scapy_config

configure_scapy()

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

# Apply configuration after import
apply_scapy_config()

from .extractors import DomainExtractor

logger = logging.getLogger("capture.sniffer")


class PacketSniffer:
    def __init__(self, callback: Callable[[Dict], None]):
   
        self.callback = callback
        self.running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._extractor = DomainExtractor()
        
       
        self.packet_count = 0
        self.domain_count = 0
        self._stats_lock = threading.Lock()
    
    def start(self) -> None:
       
        if self.running:
            logger.warning("Packet sniffer is already running")
            return
        
        self.running = True
        self._stop_event.clear()
        
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketSniffer"
        )
        self._capture_thread.start()
        
        logger.info("Packet sniffer started")
    
    def stop(self) -> None:
        if not self.running:
            logger.warning("Packet sniffer is not running")
            return
        
        logger.info("Stopping packet sniffer...")
        self.running = False
        self._stop_event.set()
        
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
            
            if self._capture_thread.is_alive():
                logger.warning("Packet capture thread did not terminate gracefully")
            else:
                logger.info("Packet capture thread terminated")
        
        logger.info("Packet sniffer stopped")
    
    def _capture_loop(self) -> None:
        max_retries = 3
        retry_count = 0
        
        filter_str = (
            "tcp and (dst port 80 or dst port 443 or dst port 53) "
            "or udp and dst port 53"
        )
        
        while self.running and retry_count < max_retries:
            try:
                logger.info(f"Starting packet capture with filter: {filter_str}")
                
                while self.running and not self._stop_event.is_set():
                    try:
                        sniff(
                            filter=filter_str,
                            prn=self._process_packet,
                            store=0,
                            timeout=2,
                            stop_filter=lambda _: self._stop_event.is_set()
                        )
                    except Exception as e:
                        if self.running:
                            logger.debug(f"Sniff iteration error: {e}")
                        break
                    
                    if self._stop_event.is_set():
                        break
                
                break  # Normal exit
                
            except PermissionError as e:
                logger.error(f"Permission error - need admin/root: {e}")
                break
                
            except OSError as e:
                if "No suitable" in str(e) or "wpcap" in str(e).lower():
                    logger.error(f"Network driver issue: {e}")
                    logger.error("Ensure WinPcap or Npcap is installed")
                    break
                else:
                    retry_count += 1
                    logger.error(f"OS error (attempt {retry_count}/{max_retries}): {e}")
                    
            except Exception as e:
                retry_count += 1
                logger.error(f"Capture error (attempt {retry_count}/{max_retries}): {e}")
                
                if retry_count < max_retries and self.running:
                    logger.info("Retrying capture in 5 seconds...")
                    if self._stop_event.wait(timeout=5):
                        break
        
        logger.debug("Packet capture thread exiting")
    
    def _process_packet(self, packet: Packet) -> None:
        """Process captured packet and extract domain info."""
        try:
            if not packet.haslayer(IP):
                return
            
            # Increment packet counter
            with self._stats_lock:
                self.packet_count += 1
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            domain: Optional[str] = None
            protocol = "unknown"
            dst_port: Optional[int] = None
            src_port: Optional[int] = None
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                
                if dst_port == 80:
                    protocol = "HTTP"
                    domain = self._extractor.extract_http_host(packet)
                elif dst_port == 443:
                    protocol = "HTTPS"
                    domain = self._extractor.extract_https_sni(packet)
                else:
                    protocol = f"TCP/{dst_port}"
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                
                if dst_port == 53:
                    protocol = "DNS"
                    domain = self._extractor.extract_dns_query(packet)
                else:
                    protocol = f"UDP/{dst_port}"
            
            if domain or dst_port in [80, 443, 53]:
                # Increment domain counter
                if domain:
                    with self._stats_lock:
                        self.domain_count += 1
                
                record = {
                    "timestamp": now_iso(),
                    "domain": domain,
                    "src_ip": src_ip,
                    "dest_ip": dst_ip,
                    "src_port": src_port,
                    "port": dst_port,
                    "dest_port": dst_port,
                    "protocol": protocol,
                    "packet_size": len(packet),
                    "connection_direction": "outbound"
                }
                
                self.callback(record)
    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
