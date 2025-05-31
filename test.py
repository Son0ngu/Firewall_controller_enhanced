"""
Test script để verify whitelist sync hoạt động đúng
"""
import sys
import os
sys.path.append('.')

from agent.config import get_config
from agent.whitelist import WhitelistManager
import logging
import requests

logging.basicConfig(level=logging.INFO)

def test_sync_process():
    """Test complete sync process"""
    
    print("🧪 TESTING COMPLETE SYNC PROCESS")
    print("="*60)
    
    # 1. Test server response directly
    server_url = "https://firewall-controller.onrender.com"
    
    print("1️⃣ Testing server without since parameter...")
    full_sync_url = f"{server_url}/api/whitelist/agent-sync"
    
    response = requests.get(full_sync_url, timeout=30)
    if response.status_code == 200:
        data = response.json()
        print(f"   ✅ Full sync: {data.get('success')} - {len(data.get('domains', []))} domains")
        if len(data.get('domains', [])) > 0:
            sample = data.get('domains', [])[:2]
            for i, domain in enumerate(sample):
                domain_value = domain.get('value') if isinstance(domain, dict) else domain
                print(f"     {i+1}. {domain_value}")
    else:
        print(f"   ❌ Server error: {response.status_code}")
        return False
    
    # 2. Test agent full sync
    print(f"\n2️⃣ Testing agent force full sync...")
    config = get_config()
    config["whitelist"]["sync_on_startup"] = False
    config["whitelist"]["auto_sync"] = False
    
    whitelist = WhitelistManager(config)
    
    print(f"   Before sync: {len(whitelist.domains)} domains")
    
    # Force full sync
    success = whitelist.force_refresh()
    
    print(f"   After sync: {len(whitelist.domains)} domains")
    print(f"   Force refresh success: {success}")
    
    if len(whitelist.domains) > 0:
        print(f"   ✅ SUCCESS! Sample domains:")
        for i, domain in enumerate(sorted(whitelist.domains)[:5], 1):
            print(f"     {i:2d}. {domain}")
        
        # Test IP resolution
        print(f"\n3️⃣ Testing IP resolution...")
        ip_success = whitelist._resolve_all_domain_ips(force_refresh=True)
        print(f"   IP resolution success: {ip_success}")
        print(f"   Total IPs resolved: {len(whitelist.current_resolved_ips)}")
        
        if whitelist.current_resolved_ips:
            sample_ips = list(whitelist.current_resolved_ips)[:5]
            print(f"   Sample IPs: {sample_ips}")
        
        # Test domain checking
        print(f"\n4️⃣ Testing domain checking...")
        test_domains = ["google.com", "www.google.com", "youtube.com", "github.com"]
        
        for domain in test_domains:
            allowed = whitelist.is_allowed(domain)
            status = "✅ ALLOWED" if allowed else "❌ NOT ALLOWED"
            print(f"   - {domain:<20} {status}")
        
        # Test IP checking
        print(f"\n5️⃣ Testing IP checking...")
        test_ips = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]
        
        for ip in test_ips:
            allowed = whitelist.is_ip_allowed(ip)
            status = "✅ ALLOWED" if allowed else "❌ NOT ALLOWED"
            print(f"   - {ip:<15} {status}")
        
    else:
        print(f"   ❌ NO DOMAINS AFTER SYNC!")
        print(f"   Check server and agent sync logic")
    
    # Cleanup
    whitelist.stop_periodic_updates()
    
    return len(whitelist.domains) > 0

if __name__ == "__main__":
    success = test_sync_process()
    print(f"\n🏁 Sync test {'PASSED' if success else 'FAILED'}")