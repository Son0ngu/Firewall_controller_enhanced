"""
Script để tạo sample whitelist cho testing
"""

import requests
import json
from datetime import datetime

# Server URL
SERVER_URL = "http://localhost:5000"  # Thay đổi nếu server chạy ở port khác

# Sample domains để thêm vào whitelist
SAMPLE_DOMAINS = [
    # Essential services
    {"value": "google.com", "category": "search", "notes": "Google search engine"},
    {"value": "*.google.com", "category": "search", "notes": "All Google services"},
    {"value": "github.com", "category": "development", "notes": "Code repository"},
    {"value": "stackoverflow.com", "category": "development", "notes": "Developer Q&A"},
    {"value": "microsoft.com", "category": "business", "notes": "Microsoft services"},
    {"value": "*.microsoft.com", "category": "business", "notes": "All Microsoft services"},
    
    # Windows Updates
    {"value": "windowsupdate.microsoft.com", "category": "system", "notes": "Windows Update"},
    {"value": "update.microsoft.com", "category": "system", "notes": "Microsoft Update"},
    {"value": "download.microsoft.com", "category": "system", "notes": "Microsoft Downloads"},
    
    # Popular sites
    {"value": "wikipedia.org", "category": "education", "notes": "Wikipedia encyclopedia"},
    {"value": "*.wikipedia.org", "category": "education", "notes": "All Wikipedia sites"},
    {"value": "youtube.com", "category": "media", "notes": "Video platform"},
    {"value": "*.youtube.com", "category": "media", "notes": "All YouTube services"},
    
    # CDN and services
    {"value": "cloudflare.com", "category": "cdn", "notes": "Cloudflare CDN"},
    {"value": "amazonaws.com", "category": "cloud", "notes": "AWS services"},
    {"value": "*.amazonaws.com", "category": "cloud", "notes": "All AWS services"},
    
    # Social Media (optional)
    {"value": "facebook.com", "category": "social", "notes": "Facebook platform"},
    {"value": "twitter.com", "category": "social", "notes": "Twitter platform"},
    {"value": "linkedin.com", "category": "social", "notes": "LinkedIn platform"},
    
    # Development tools
    {"value": "npmjs.com", "category": "development", "notes": "NPM package manager"},
    {"value": "pypi.org", "category": "development", "notes": "Python package index"},
    {"value": "docker.com", "category": "development", "notes": "Docker platform"},
    {"value": "*.docker.com", "category": "development", "notes": "All Docker services"},
    
    # Security and certificates
    {"value": "letsencrypt.org", "category": "security", "notes": "Let's Encrypt certificates"},
    {"value": "digicert.com", "category": "security", "notes": "DigiCert certificates"},
    
    # News sites
    {"value": "bbc.com", "category": "news", "notes": "BBC News"},
    {"value": "cnn.com", "category": "news", "notes": "CNN News"},
    {"value": "reuters.com", "category": "news", "notes": "Reuters News"},
]

def create_sample_whitelist():
    """Tạo sample whitelist entries"""
    
    print(f"Creating sample whitelist on server: {SERVER_URL}")
    print(f"Total entries to create: {len(SAMPLE_DOMAINS)}")
    
    success_count = 0
    error_count = 0
    
    for entry in SAMPLE_DOMAINS:
        try:
            response = requests.post(
                f"{SERVER_URL}/api/whitelist",
                json={
                    "type": "domain",
                    "value": entry["value"],
                    "category": entry["category"],
                    "notes": entry["notes"],
                    "priority": "normal"
                },
                timeout=10
            )
            
            if response.status_code == 201:
                success_count += 1
                print(f"✅ Added: {entry['value']}")
            elif response.status_code == 409:
                print(f"⚠️  Already exists: {entry['value']}")
            else:
                error_count += 1
                print(f"❌ Failed to add {entry['value']}: {response.status_code} - {response.text}")
                
        except Exception as e:
            error_count += 1
            print(f"❌ Error adding {entry['value']}: {e}")
    
    print(f"\n📊 Summary:")
    print(f"✅ Successfully added: {success_count}")
    print(f"❌ Errors: {error_count}")
    print(f"📝 Total processed: {len(SAMPLE_DOMAINS)}")

def check_whitelist():
    """Kiểm tra whitelist hiện tại"""
    try:
        response = requests.get(f"{SERVER_URL}/api/whitelist", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            domains = data.get("domains", [])
            
            print(f"\n📋 Current whitelist ({len(domains)} entries):")
            
            # Group by category
            categories = {}
            for domain in domains:
                category = domain.get("category", "uncategorized")
                if category not in categories:
                    categories[category] = []
                categories[category].append(domain.get("value") or domain.get("domain"))
            
            for category, domain_list in categories.items():
                print(f"\n📁 {category.upper()} ({len(domain_list)} entries):")
                for domain in sorted(domain_list):
                    print(f"   • {domain}")
                    
        else:
            print(f"❌ Failed to fetch whitelist: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error checking whitelist: {e}")

def test_agent_sync():
    """Test agent sync endpoint"""
    try:
        print(f"\n🔄 Testing agent sync endpoint...")
        
        response = requests.get(f"{SERVER_URL}/api/whitelist/agent-sync", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            domains = data.get("domains", [])
            print(f"✅ Agent sync working! Retrieved {len(domains)} domains")
            print(f"   Timestamp: {data.get('timestamp')}")
            print(f"   Type: {data.get('type')}")
            
            # Show first 5 domains
            if domains:
                print(f"   Sample domains:")
                for domain in domains[:5]:
                    print(f"     • {domain}")
                if len(domains) > 5:
                    print(f"     ... and {len(domains) - 5} more")
        else:
            print(f"❌ Agent sync failed: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing agent sync: {e}")

if __name__ == "__main__":
    print("🚀 Firewall Controller - Sample Whitelist Creator")
    print("=" * 50)
    
    # Check current whitelist first
    print("1. Checking current whitelist...")
    check_whitelist()
    
    # Create sample whitelist
    print("\n2. Creating sample whitelist...")
    create_sample_whitelist()
    
    # Check again after creation
    print("\n3. Checking whitelist after creation...")
    check_whitelist()
    
    # Test agent sync
    print("\n4. Testing agent sync endpoint...")
    test_agent_sync()
    
    print("\n✅ Done! Your whitelist is ready for testing.")