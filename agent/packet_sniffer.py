import logging
import threading
import time
from datetime import datetime
from typing import Callable, Dict, Optional

from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.extensions import ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Packet

# Configure logging
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
        self.callback = callback
        self.running = False
        self.capture_thread = None
    
    def start(self):
        """Start capturing packets in a background thread."""
        if self.running:
            logger.warning("Packet sniffer is already running")
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logger.info("Packet sniffer started")
    
    def stop(self):
        """Stop capturing packets."""
        if not self.running:
            logger.warning("Packet sniffer is not running")
            return
        
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=3)
            if self.capture_thread.is_alive():
                logger.warning("Packet capture thread did not terminate gracefully")
        
        logger.info("Packet sniffer stopped")
    
    def _capture_packets(self):
        """Main packet capture loop using Scapy's sniff function."""
        try:
            # Filter for outbound TCP traffic on ports 80 (HTTP) and 443 (HTTPS)
            # BPF syntax for outbound connections can vary by platform
            filter_str = "tcp and (dst port 80 or dst port 443)"
            
            logger.info("Started packet capture with filter: %s", filter_str)
            
            # Start sniffing
            sniff(
                filter=filter_str,
                prn=self._process_packet,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: not self.running  # Stop when self.running is False
            )
        
        except Exception as e:
            logger.error("Error in packet capture: %s", str(e))
    
    def _process_packet(self, packet: Packet):
        """
        Process a captured packet to extract domain information.
        
        Args:
            packet: The Scapy packet object
        """
        try:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return
            
            # Get basic packet information
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            
            dst_ip = ip_layer.dst
            dst_port = tcp_layer.dport
            protocol = "HTTP" if dst_port == 80 else "HTTPS" if dst_port == 443 else "Unknown"
            
            # Extract domain based on protocol
            domain = None
            
            if dst_port == 80 and packet.haslayer(HTTPRequest):
                # Extract from HTTP Host header
                domain = self._extract_http_host(packet)
            elif dst_port == 443:
                # Extract from TLS ClientHello (SNI)
                domain = self._extract_https_sni(packet)
            
            if domain:
                # Create record with domain info
                record = {
                    "timestamp": datetime.now().isoformat(),
                    "domain": domain,
                    "dest_ip": dst_ip,
                    "dest_port": dst_port,
                    "protocol": protocol
                }
                
                # Send the record to the callback
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
            if packet.haslayer(HTTPRequest):
                if hasattr(packet[HTTPRequest], 'Host'):
                    return packet[HTTPRequest].Host.decode('utf-8', errors='ignore')
            
            # Fallback: Try to extract manually from raw data
            if packet.haslayer(TCP) and packet[TCP].payload:
                payload = bytes(packet[TCP].payload)
                if b"Host: " in payload:
                    # Find the Host header
                    host_idx = payload.find(b"Host: ") + 6  # Skip "Host: "
                    
                    # Find the end of the header (CR LF)
                    end_idx = payload.find(b"\r\n", host_idx)
                    
                    if end_idx > host_idx:
                        # Extract and decode the host
                        host = payload[host_idx:end_idx].decode('utf-8', errors='ignore')
                        return host.strip()
            
            return None
        except Exception as e:
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
            # First attempt: Use Scapy's TLS layer if available
            if packet.haslayer(TLSClientHello):
                client_hello = packet[TLSClientHello]
                
                # Find ServerName extension
                for extension in client_hello.ext:
                    if isinstance(extension, ServerName):
                        # Extract the server name
                        if extension.servernames:
                            servername = extension.servernames[0].servername.decode('utf-8', errors='ignore')
                            # Validate the hostname (basic check)
                            if self._is_valid_hostname(servername):
                                return servername
            
            # Second attempt: Try manual parsing if Scapy's TLS layer doesn't work
            if packet.haslayer(TCP) and packet[TCP].payload:
                payload = bytes(packet[TCP].payload)
                
                # Verify this is a TLS handshake with minimum viable length
                if len(payload) < 43:
                    return None
                    
                # Check for TLS handshake record type (0x16) and version
                if payload[0] != 0x16:  # Not a handshake
                    return None
                    
                # Verify this is a ClientHello message (handshake type 1)
                if len(payload) <= 5 or payload[5] != 0x01:
                    return None

                # More reliable parsing approach for TLS extensions
                try:
                    # Skip record header (5 bytes) and handshake header (4 bytes)
                    pos = 9
                    
                    # Skip client version (2 bytes)
                    pos += 2
                    
                    # Skip client random (32 bytes)
                    pos += 32
                    
                    # Skip session ID
                    if pos >= len(payload):
                        return None
                        
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length
                    
                    # Skip cipher suites
                    if pos + 2 > len(payload):
                        return None
                        
                    cipher_suites_length = (payload[pos] << 8) | payload[pos + 1]
                    pos += 2 + cipher_suites_length
                    
                    # Skip compression methods
                    if pos >= len(payload):
                        return None
                        
                    compression_methods_length = payload[pos]
                    pos += 1 + compression_methods_length
                    
                    # Check if we have extensions
                    if pos + 2 > len(payload):
                        return None
                        
                    extensions_length = (payload[pos] << 8) | payload[pos + 1]
                    pos += 2
                    extensions_end = pos + extensions_length
                    
                    # Ensure we don't read past the payload
                    if extensions_end > len(payload):
                        return None
                        
                    # Parse extensions
                    while pos + 4 <= extensions_end:
                        # Get extension type and length
                        ext_type = (payload[pos] << 8) | payload[pos + 1]
                        pos += 2
                        
                        ext_length = (payload[pos] << 8) | payload[pos + 1]
                        pos += 2
                        
                        # Check if we have enough bytes for the extension
                        if pos + ext_length > extensions_end:
                            break
                        
                        # Check for SNI extension (type 0)
                        if ext_type == 0 and ext_length > 2:
                            # Skip server name list length
                            sni_list_length = (payload[pos] << 8) | payload[pos + 1]
                            pos += 2
                            
                            # Ensure we have enough bytes and the correct name type
                            if pos < extensions_end and payload[pos] == 0:  # Name type: host_name (0)
                                pos += 1
                                
                                # Get hostname length
                                if pos + 2 > extensions_end:
                                    break
                                    
                                name_length = (payload[pos] << 8) | payload[pos + 1]
                                pos += 2
                                
                                # Ensure we have enough bytes for the hostname
                                if pos + name_length <= extensions_end:
                                    try:
                                        hostname = payload[pos:pos + name_length].decode('utf-8', errors='ignore')
                                        
                                        # Validate hostname before returning
                                        if self._is_valid_hostname(hostname):
                                            return hostname
                                    except:
                                        pass  # Decoding failed, continue looking
                        
                        # Move to next extension
                        pos += ext_length
                
                except IndexError:
                    # Handle potential index errors during parsing
                    pass
                    
            return None
        except Exception as e:
            logger.error("Error extracting HTTPS SNI: %s", str(e))
            return None

    def _is_valid_hostname(self, hostname: str) -> bool:
        """
        Validates if a string is a plausible hostname.
        
        Args:
            hostname: The hostname to validate
            
        Returns:
            bool: True if the hostname appears valid
        """
        if not hostname or len(hostname) > 253:
            return False
            
        # Check for valid characters (alphanumeric, dots, hyphens)
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            return False
            
        # Check for at least one dot (domain should have at least one level)
        if '.' not in hostname:
            return False
            
        # Check that parts are valid (not starting/ending with hyphen, not all numeric)
        parts = hostname.split('.')
        for part in parts:
            if not part or part.startswith('-') or part.endswith('-'):
                return False
                
        return True


# Example usage (for testing)
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Define a simple callback
    def domain_callback(record):
        print(f"Detected domain: {record['domain']} (IP: {record['dest_ip']}:{record['dest_port']})")
    
    # Create and start the sniffer
    sniffer = PacketSniffer(callback=domain_callback)
    
    try:
        sniffer.start()
        
        # Keep the script running
        print("Sniffer running. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping sniffer...")
    finally:
        sniffer.stop()