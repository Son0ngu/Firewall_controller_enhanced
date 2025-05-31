"""
SERVER-ONLY whitelist test script
"""
import sys
import os
sys.path.append('.')

from config import get_config
from whitelist import WhitelistManager
import logging
import requests

logging.basicConfig(level=logging.INFO)

def test_server_only_sync():
    """Test strict server-only sync"""
    
    print("🧪 TESTING SERVER-ONLY WHITELIST SYNC")
    print("="*60)
    
    # 1. Test server response
    server_url = "https://firewall-controller.onrender.com"
    sync_url = f"{server_url}/api/whitelist/agent-sync"
    
    print("1️⃣ Testing server response...")
    response = requests.get(sync_url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        server_domains = len(data.get('domains', []))
        print(f"   ✅ Server has {server_domains} domains")
        
        if server_domains == 0:
            print("   ⚠️ WARNING: Server has no domains!")
            print("   Add domains via: https://firewall-controller.onrender.com/whitelist")
            return False
    else:
        print(f"   ❌ Server error: {response.status_code}")
        return False
    
    # 2. Test agent with strict server-only mode
    print(f"\n2️⃣ Testing agent SERVER-ONLY mode...")
    config = get_config()
    config["whitelist"]["sync_on_startup"] = True
    config["whitelist"]["auto_sync"] = False
    
    # Initialize with strict server-only mode
    whitelist = WhitelistManager(config)
    
    print(f"   Domains from server: {len(whitelist.domains)}")
    print(f"   Startup sync completed: {whitelist.startup_sync_completed}")
    
    if len(whitelist.domains) > 0:
        print(f"   ✅ SUCCESS! Domains loaded from server:")
        for i, domain in enumerate(sorted(whitelist.domains), 1):
            print(f"     {i:2d}. {domain}")
        
        # Test IP resolution
        print(f"\n3️⃣ Testing IP resolution...")
        ip_success = whitelist._resolve_all_domain_ips(force_refresh=True)
        print(f"   IP resolution success: {ip_success}")
        print(f"   Total IPs resolved: {len(whitelist.current_resolved_ips)}")
        
        # Test essential IPs only
        print(f"\n4️⃣ Testing essential IP checking...")
        essential_ips = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]
        
        for ip in essential_ips:
            allowed = whitelist.is_ip_allowed(ip)
            status = "✅ ALLOWED" if allowed else "❌ NOT ALLOWED"
            print(f"   - {ip:<15} {status}")
    else:
        print(f"   ❌ NO DOMAINS FROM SERVER!")
        print(f"   This is expected behavior if server has no configured domains")
    
    # Cleanup
    whitelist.stop_periodic_updates()
    
    return len(whitelist.domains) > 0

if __name__ == "__main__":
    success = test_server_only_sync()
    print(f"\n🏁 Server-only test {'PASSED' if success else 'FAILED'}")
    
    if not success:
        print("\n💡 TO ADD DOMAINS TO SERVER:")
        print("1. Visit: https://firewall-controller.onrender.com/whitelist")
        print("2. Add domains like: google.com, youtube.com, github.com")
        print("3. Re-run this test")