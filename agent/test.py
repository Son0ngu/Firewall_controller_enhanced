"""
Test script để kiểm tra agent sync process cụ thể
"""
import sys
import os
sys.path.append('.')

from config import get_config
from whitelist import WhitelistManager
import logging

logging.basicConfig(level=logging.DEBUG)

def test_agent_sync():
    """Test agent sync process chi tiết"""
    
    print("🧪 TESTING AGENT SYNC PROCESS")
    print("="*50)
    
    try:
        # Load config
        config = get_config()
        server_url = config.get("server", {}).get("url", "Unknown")
        print(f"Server URL: {server_url}")
        
        # Create whitelist manager (no auto-sync)
        config["whitelist"]["sync_on_startup"] = False
        config["whitelist"]["auto_sync"] = False
        
        whitelist = WhitelistManager(config)
        
        print(f"\n📊 BEFORE SYNC:")
        print(f"   Domains: {len(whitelist.domains)}")
        print(f"   IPs: {len(whitelist.current_resolved_ips)}")
        
        # Manual sync
        print(f"\n🔄 PERFORMING MANUAL SYNC...")
        sync_success = whitelist.update_whitelist_from_server()
        
        print(f"\n📊 AFTER SYNC:")
        print(f"   Sync success: {sync_success}")
        print(f"   Domains: {len(whitelist.domains)}")
        print(f"   IPs: {len(whitelist.current_resolved_ips)}")
        
        if len(whitelist.domains) > 0:
            print(f"\n✅ SYNC SUCCESSFUL! Found domains:")
            for i, domain in enumerate(sorted(whitelist.domains), 1):
                print(f"   {i:2d}. {domain}")
            
            # Test IP resolution
            print(f"\n🔍 Testing IP resolution...")
            ip_success = whitelist._resolve_all_domain_ips(force_refresh=True)
            print(f"   IP resolution success: {ip_success}")
            print(f"   Total IPs resolved: {len(whitelist.current_resolved_ips)}")
            
            # Sample IPs
            if whitelist.current_resolved_ips:
                sample_ips = list(whitelist.current_resolved_ips)[:5]
                print(f"   Sample IPs: {sample_ips}")
            
        else:
            print(f"\n❌ SYNC FAILED OR SERVER HAS NO DOMAINS")
            
        # Cleanup
        whitelist.stop_periodic_updates()
        
        return len(whitelist.domains) > 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_agent_sync()
    print(f"\n🏁 Test {'PASSED' if success else 'FAILED'}")