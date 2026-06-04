import ipaddress
import logging
import socket
import subprocess
from typing import Set

from utils.ip_detector import check_admin_privileges, get_local_ip

logger = logging.getLogger("firewall.utils")


class FirewallUtils:

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return isinstance(addr, ipaddress.IPv4Address)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        # IPv4-only: SAINT firewall enforcement is IPv4 (netsh advfirewall with
        # IPv6 has quirks like empty stderr on failure, and our DNS resolver
        # only queries A records).
        return FirewallUtils.is_valid_ipv4(ip)

    @staticmethod
    def get_essential_ips() -> Set[str]:
        essential: Set[str] = set()

        # Localhost (IPv4 only)
        essential.add("127.0.0.1")

        # Auto-detect system DNS servers (IPv4 only). Do not inject public DNS
        # fallbacks here; SAINT should honor the machine's DNS configuration.
        try:
            import dns.resolver
            sys_resolver = dns.resolver.Resolver()
            if sys_resolver.nameservers:
                ipv4_dns = [
                    ns for ns in sys_resolver.nameservers
                    if FirewallUtils.is_valid_ipv4(ns)
                ]
                essential.update(ipv4_dns)
                logger.debug(f"Detected IPv4 system DNS servers: {ipv4_dns}")
        except Exception as e:
            logger.warning(
                "Could not detect system DNS configuration; no public DNS "
                "fallback will be added: %s",
                e,
            )
        
        # Try to detect local IPv4 via shared IPDetector
        try:
            local_ip = get_local_ip()
            if local_ip:
                essential.add(local_ip)
                if '.' in local_ip:
                    gateway_ip = '.'.join(local_ip.split('.')[:-1]) + '.1'
                    essential.add(gateway_ip)
                    logger.debug(f"Detected local IPv4 network: {local_ip}, gateway: {gateway_ip}")
        except Exception as e:
            logger.debug(f"Could not detect local IPv4 network: {e}")
        
        return essential
    
    @staticmethod
    def has_admin_privileges() -> bool:
        """Check if the application is running with administrator privileges."""
        try:
            return check_admin_privileges()
        except Exception as e:
            logger.error(f"Error checking admin privileges: {e}")
            return False
    
    @staticmethod
    def run_netsh_command(args: list, timeout: int = 30) -> subprocess.CompletedProcess:
        command = ["netsh"] + args
        
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    
    @staticmethod
    def test_ip_connectivity(ip: str, ports: list = None, timeout: int = 3) -> bool:
        if ports is None:
            ports = [80, 443, 53]
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.debug(f"Connectivity test skipped - invalid IP: {ip}")
            return False

        try:
            for port in ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(timeout)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            return True
                except Exception:
                    continue
            return False
        except Exception as e:
            logger.debug(f"Connectivity test failed for {ip}: {e}")
            return False
