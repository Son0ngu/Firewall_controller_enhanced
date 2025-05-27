"""
Test script với URL đã fix
"""

import requests
import time

RENDER_URL = "https://firewall-controller-vu7f.onrender.com"

def test_all_endpoints():
    print(f"🚀 Testing Render deployment: {RENDER_URL}")
    print("=" * 60)
    
    # 1. Test health
    print("1️⃣ Testing health...")
    try:
        response = requests.get(f"{RENDER_URL}/api/health", timeout=30)
        if response.status_code == 200:
            print("   ✅ Health check passed")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
    
    # 2. Setup sample data
    print("\n2️⃣ Setting up sample data...")
    try:
        response = requests.post(f"{RENDER_URL}/setup-sample-data", timeout=60)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Sample data: {data.get('created', 0)} created, {data.get('existing', 0)} existing")
        else:
            print(f"   ❌ Sample data failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Sample data error: {e}")
    
    # 3. Test whitelist API
    print("\n3️⃣ Testing whitelist API...")
    try:
        response = requests.get(f"{RENDER_URL}/api/whitelist", timeout=30)
        if response.status_code == 200:
            data = response.json()
            entries = data.get("domains", [])
            print(f"   ✅ Whitelist API: {len(entries)} entries")
            
            # Count by type
            types = {}
            for entry in entries:
                entry_type = entry.get("type", "domain")
                types[entry_type] = types.get(entry_type, 0) + 1
            
            for entry_type, count in types.items():
                print(f"      • {entry_type}: {count}")
        else:
            print(f"   ❌ Whitelist API failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Whitelist API error: {e}")
    
    # 4. Test agent sync (MOST IMPORTANT)
    print("\n4️⃣ Testing agent sync...")
    try:
        response = requests.get(f"{RENDER_URL}/api/whitelist/agent-sync", timeout=30)
        if response.status_code == 200:
            data = response.json()
            domains = data.get("domains", [])
            print(f"   ✅ Agent sync working: {len(domains)} domains")
            print(f"      Timestamp: {data.get('timestamp')}")
            print(f"      Type: {data.get('type')}")
            
            if domains:
                print(f"      Sample domains:")
                for domain in domains[:3]:
                    print(f"        • {domain}")
        else:
            print(f"   ❌ Agent sync failed: {response.status_code}")
            print(f"      Response: {response.text}")
    except Exception as e:
        print(f"   ❌ Agent sync error: {e}")
    
    # 5. Test add entry
    print("\n5️⃣ Testing add entry...")
    try:
        test_entry = {
            "type": "domain",
            "value": f"test-{int(time.time())}.example.com",
            "category": "test",
            "notes": "Test entry from script"
        }
        
        response = requests.post(
            f"{RENDER_URL}/api/whitelist",
            json=test_entry,
            timeout=30
        )
        
        if response.status_code == 201:
            print(f"   ✅ Add entry working: {test_entry['value']}")
        elif response.status_code == 409:
            print(f"   ⚠️ Entry already exists")
        else:
            print(f"   ❌ Add entry failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Add entry error: {e}")
    
    print(f"\n🎉 Test completed!")
    print(f"📝 Agent should connect to: {RENDER_URL}")

if __name__ == "__main__":
    test_all_endpoints()