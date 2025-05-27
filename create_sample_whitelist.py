"""
Script để tạo sample whitelist đầy đủ cho testing - bao gồm Domain, IP, URL và Pattern
"""

import requests
import json
from datetime import datetime, timedelta

# Server URL
SERVER_URL = "http://localhost:5000"  # Thay đổi nếu server chạy ở port khác

# Sample DOMAINS
SAMPLE_DOMAINS = [
    # Essential services
    {"value": "google.com", "category": "search", "notes": "Google search engine", "priority": "high"},
    {"value": "*.google.com", "category": "search", "notes": "All Google services", "priority": "high"},
    {"value": "github.com", "category": "development", "notes": "Code repository", "priority": "normal"},
    {"value": "stackoverflow.com", "category": "development", "notes": "Developer Q&A", "priority": "normal"},
    {"value": "microsoft.com", "category": "business", "notes": "Microsoft services", "priority": "high"},
    {"value": "*.microsoft.com", "category": "business", "notes": "All Microsoft services", "priority": "high"},
    
    # Windows Updates
    {"value": "windowsupdate.microsoft.com", "category": "system", "notes": "Windows Update", "priority": "critical"},
    {"value": "update.microsoft.com", "category": "system", "notes": "Microsoft Update", "priority": "critical"},
    {"value": "download.microsoft.com", "category": "system", "notes": "Microsoft Downloads", "priority": "critical"},
    
    # Popular sites
    {"value": "wikipedia.org", "category": "education", "notes": "Wikipedia encyclopedia", "priority": "normal"},
    {"value": "*.wikipedia.org", "category": "education", "notes": "All Wikipedia sites", "priority": "normal"},
    {"value": "youtube.com", "category": "media", "notes": "Video platform", "priority": "normal"},
    
    # CDN and services
    {"value": "cloudflare.com", "category": "cdn", "notes": "Cloudflare CDN", "priority": "normal"},
    {"value": "amazonaws.com", "category": "cloud", "notes": "AWS services", "priority": "normal"},
    {"value": "*.amazonaws.com", "category": "cloud", "notes": "All AWS services", "priority": "normal"},
]

# Sample IP ADDRESSES
SAMPLE_IPS = [
    # Google DNS
    {"value": "8.8.8.8", "category": "dns", "notes": "Google DNS Primary", "priority": "high"},
    {"value": "8.8.4.4", "category": "dns", "notes": "Google DNS Secondary", "priority": "high"},
    
    # Cloudflare DNS
    {"value": "1.1.1.1", "category": "dns", "notes": "Cloudflare DNS Primary", "priority": "high"},
    {"value": "1.0.0.1", "category": "dns", "notes": "Cloudflare DNS Secondary", "priority": "high"},
    
    # Common web servers with ports
    {"value": "192.168.1.1:80", "category": "local", "notes": "Local router web interface", "priority": "normal"},
    {"value": "127.0.0.1:8080", "category": "local", "notes": "Local development server", "priority": "normal"},
    
    # IPv6 examples
    {"value": "2001:4860:4860::8888", "category": "dns", "notes": "Google IPv6 DNS", "priority": "high"},
    {"value": "2606:4700:4700::1111", "category": "dns", "notes": "Cloudflare IPv6 DNS", "priority": "high"},
    
    # Subnet examples
    {"value": "192.168.0.0/24", "category": "local", "notes": "Local network subnet", "priority": "normal"},
    {"value": "10.0.0.0/8", "category": "local", "notes": "Private network range", "priority": "normal"},
    
    # Corporate IPs
    {"value": "172.16.0.1", "category": "corporate", "notes": "Corporate gateway", "priority": "normal"},
    {"value": "203.0.113.0/24", "category": "business", "notes": "Business network", "priority": "normal"},
]

# Sample URLs
SAMPLE_URLS = [
    # API endpoints
    {"value": "https://api.github.com/user", "category": "api", "notes": "GitHub User API", "priority": "normal"},
    {"value": "https://api.github.com/*", "category": "api", "notes": "All GitHub API endpoints", "priority": "normal"},
    {"value": "https://graph.microsoft.com/*", "category": "api", "notes": "Microsoft Graph API", "priority": "high"},
    
    # CDN resources
    {"value": "https://cdn.jsdelivr.net/*", "category": "cdn", "notes": "JSDelivr CDN", "priority": "normal"},
    {"value": "https://cdnjs.cloudflare.com/*", "category": "cdn", "notes": "Cloudflare CDN", "priority": "normal"},
    {"value": "https://fonts.googleapis.com/*", "category": "cdn", "notes": "Google Fonts", "priority": "normal"},
    
    # Secure endpoints
    {"value": "https://login.microsoftonline.com/*", "category": "security", "notes": "Microsoft OAuth", "priority": "critical"},
    {"value": "https://accounts.google.com/*", "category": "security", "notes": "Google Accounts", "priority": "critical"},
    {"value": "https://auth.github.com/*", "category": "security", "notes": "GitHub Authentication", "priority": "high"},
    
    # Package managers
    {"value": "https://registry.npmjs.org/*", "category": "development", "notes": "NPM Registry", "priority": "normal"},
    {"value": "https://pypi.org/simple/*", "category": "development", "notes": "Python Package Index", "priority": "normal"},
    {"value": "https://repo1.maven.org/*", "category": "development", "notes": "Maven Repository", "priority": "normal"},
    
    # Update services
    {"value": "https://update.code.visualstudio.com/*", "category": "system", "notes": "VS Code Updates", "priority": "normal"},
    {"value": "https://vortex.data.microsoft.com/*", "category": "system", "notes": "Microsoft Telemetry", "priority": "normal"},
]

# Sample PATTERNS
SAMPLE_PATTERNS = [
    # Wildcard patterns
    {"value": "*.githubusercontent.com", "category": "development", "notes": "GitHub raw content", "priority": "normal", "pattern_type": "wildcard"},
    {"value": "*update*.microsoft.com", "category": "system", "notes": "Microsoft update services", "priority": "high", "pattern_type": "wildcard"},
    {"value": "*.office365.com", "category": "business", "notes": "Office 365 services", "priority": "high", "pattern_type": "wildcard"},
    
    # Regex patterns (advanced)
    {"value": "regex:.*\\.edu$", "category": "education", "notes": "Educational domains", "priority": "normal", "pattern_type": "regex"},
    {"value": "regex:^api\\.[a-z]+\\.(com|org|net)$", "category": "api", "notes": "API subdomains", "priority": "normal", "pattern_type": "regex"},
    {"value": "regex:^[a-z0-9-]+\\.azurewebsites\\.net$", "category": "cloud", "notes": "Azure websites", "priority": "normal", "pattern_type": "regex"},
    
    # Glob patterns
    {"value": "*.docker.io", "category": "development", "notes": "Docker registry", "priority": "normal", "pattern_type": "glob"},
    {"value": "hub.docker.com/*", "category": "development", "notes": "Docker Hub paths", "priority": "normal", "pattern_type": "glob"},
    {"value": "registry-*.docker.io", "category": "development", "notes": "Docker registries", "priority": "normal", "pattern_type": "glob"},
    
    # Security patterns
    {"value": "*.letsencrypt.org", "category": "security", "notes": "Let's Encrypt services", "priority": "high", "pattern_type": "wildcard"},
    {"value": "regex:^.*\\.(crt|pem|key)$", "category": "security", "notes": "Certificate files", "priority": "high", "pattern_type": "regex"},
]

def create_entries_by_type(entries, entry_type):
    """Tạo entries theo loại"""
    print(f"\n📝 Creating {entry_type.upper()} entries ({len(entries)} items)...")
    
    success_count = 0
    error_count = 0
    
    for entry in entries:
        try:
            # Chuẩn bị data cho API
            entry_data = {
                "type": entry_type,
                "value": entry["value"],
                "category": entry["category"],
                "notes": entry["notes"],
                "priority": entry.get("priority", "normal")
            }
            
            # Thêm config đặc biệt cho pattern
            if entry_type == "pattern" and "pattern_type" in entry:
                entry_data["pattern_type"] = entry["pattern_type"]
            
            # Thêm expiry date cho một số entries (test)
            if entry.get("priority") == "normal" and success_count % 3 == 0:
                # Thêm expiry date cho 1/3 số entries normal
                expiry_date = (datetime.now() + timedelta(days=30)).date().isoformat()
                entry_data["expiry_date"] = expiry_date
            
            # Thêm rate limiting cho API endpoints
            if entry.get("category") == "api":
                entry_data["max_requests_per_hour"] = 1000
            
            response = requests.post(
                f"{SERVER_URL}/api/whitelist",
                json=entry_data,
                timeout=10
            )
            
            if response.status_code == 201:
                success_count += 1
                priority_indicator = "🔴" if entry.get("priority") == "critical" else "🟡" if entry.get("priority") == "high" else "🟢"
                print(f"  ✅ {priority_indicator} Added: {entry['value']}")
            elif response.status_code == 409:
                print(f"  ⚠️  Already exists: {entry['value']}")
            else:
                error_count += 1
                print(f"  ❌ Failed to add {entry['value']}: {response.status_code} - {response.text}")
                
        except Exception as e:
            error_count += 1
            print(f"  ❌ Error adding {entry['value']}: {e}")
    
    print(f"  📊 {entry_type.upper()} Summary: ✅ {success_count} added, ❌ {error_count} errors")
    return success_count, error_count

def create_comprehensive_whitelist():
    """Tạo comprehensive whitelist với tất cả các loại entries"""
    
    print(f"🚀 Creating comprehensive whitelist on server: {SERVER_URL}")
    print("=" * 60)
    
    total_success = 0
    total_errors = 0
    
    # Tạo domains
    success, errors = create_entries_by_type(SAMPLE_DOMAINS, "domain")
    total_success += success
    total_errors += errors
    
    # Tạo IP addresses
    success, errors = create_entries_by_type(SAMPLE_IPS, "ip")
    total_success += success
    total_errors += errors
    
    # Tạo URLs
    success, errors = create_entries_by_type(SAMPLE_URLS, "url")
    total_success += success
    total_errors += errors
    
    # Tạo Patterns
    success, errors = create_entries_by_type(SAMPLE_PATTERNS, "pattern")
    total_success += success
    total_errors += errors
    
    print(f"\n🎉 FINAL SUMMARY:")
    print(f"✅ Total successfully added: {total_success}")
    print(f"❌ Total errors: {total_errors}")
    print(f"📝 Total processed: {total_success + total_errors}")

def check_whitelist_by_type():
    """Kiểm tra whitelist theo từng loại"""
    try:
        response = requests.get(f"{SERVER_URL}/api/whitelist", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            entries = data.get("domains", [])  # API vẫn dùng "domains" key
            
            print(f"\n📋 Current whitelist analysis ({len(entries)} total entries):")
            print("=" * 50)
            
            # Group by type and category
            types = {}
            categories = {}
            priorities = {"critical": 0, "high": 0, "normal": 0}
            
            for entry in entries:
                entry_type = entry.get("type", "domain")
                category = entry.get("category", "uncategorized")
                priority = entry.get("priority", "normal")
                
                # Count by type
                if entry_type not in types:
                    types[entry_type] = []
                types[entry_type].append(entry.get("value"))
                
                # Count by category
                if category not in categories:
                    categories[category] = 0
                categories[category] += 1
                
                # Count by priority
                if priority in priorities:
                    priorities[priority] += 1
            
            # Show by type
            print("\n📊 BY TYPE:")
            type_icons = {
                "domain": "🌐",
                "ip": "🔌", 
                "url": "🔗",
                "pattern": "📝"
            }
            
            for entry_type, values in types.items():
                icon = type_icons.get(entry_type, "📄")
                print(f"  {icon} {entry_type.upper()}: {len(values)} entries")
                # Show first few examples
                for value in values[:3]:
                    print(f"    • {value}")
                if len(values) > 3:
                    print(f"    ... and {len(values) - 3} more")
            
            # Show by category
            print(f"\n🏷️  BY CATEGORY:")
            category_icons = {
                "search": "🔍", "development": "💻", "business": "🏢",
                "system": "⚙️", "education": "📚", "media": "🎬",
                "cdn": "📡", "cloud": "☁️", "social": "👥",
                "security": "🔒", "api": "🔌", "dns": "🌐",
                "local": "🏠", "corporate": "🏢"
            }
            
            for category, count in sorted(categories.items()):
                icon = category_icons.get(category, "📂")
                print(f"  {icon} {category.title()}: {count} entries")
            
            # Show by priority
            print(f"\n⭐ BY PRIORITY:")
            priority_icons = {"critical": "🔴", "high": "🟡", "normal": "🟢"}
            for priority, count in priorities.items():
                if count > 0:
                    icon = priority_icons.get(priority, "⚪")
                    print(f"  {icon} {priority.title()}: {count} entries")
                    
        else:
            print(f"❌ Failed to fetch whitelist: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error checking whitelist: {e}")

def test_agent_sync_comprehensive():
    """Test agent sync endpoint với các filter"""
    try:
        print(f"\n🔄 Testing agent sync endpoint comprehensively...")
        
        # Test full sync
        response = requests.get(f"{SERVER_URL}/api/whitelist/agent-sync", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            domains = data.get("domains", [])
            print(f"✅ Full sync working! Retrieved {len(domains)} total entries")
            print(f"   Timestamp: {data.get('timestamp')}")
            print(f"   Type: {data.get('type')}")
            
            # Analyze types in sync response
            domain_types = {"domains": 0, "ips": 0, "urls": 0, "patterns": 0}
            
            for domain in domains:
                if domain.startswith(('http://', 'https://')):
                    domain_types["urls"] += 1
                elif domain.startswith('regex:') or '*' in domain:
                    domain_types["patterns"] += 1
                elif any(c.isdigit() for c in domain.replace('.', '').replace(':', '')):
                    # Simple heuristic for IPs
                    domain_types["ips"] += 1
                else:
                    domain_types["domains"] += 1
            
            print(f"   📊 Sync breakdown:")
            for dtype, count in domain_types.items():
                if count > 0:
                    print(f"     • {dtype.title()}: {count}")
            
            # Show sample entries
            print(f"   📝 Sample entries:")
            for domain in domains[:5]:
                print(f"     • {domain}")
            if len(domains) > 5:
                print(f"     ... and {len(domains) - 5} more")
                
        else:
            print(f"❌ Agent sync failed: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing agent sync: {e}")

def test_entry_validation():
    """Test validation cho các loại entries"""
    print(f"\n🧪 Testing entry validation...")
    
    test_cases = [
        # Valid cases
        {"type": "domain", "value": "example.com", "should_pass": True},
        {"type": "domain", "value": "*.example.com", "should_pass": True},
        {"type": "ip", "value": "192.168.1.1", "should_pass": True},
        {"type": "ip", "value": "192.168.1.0/24", "should_pass": True},
        {"type": "url", "value": "https://example.com/api/v1", "should_pass": True},
        {"type": "pattern", "value": "*.example.*", "should_pass": True},
        
        # Invalid cases
        {"type": "domain", "value": "invalid..domain", "should_pass": False},
        {"type": "ip", "value": "256.256.256.256", "should_pass": False},
        {"type": "url", "value": "not-a-url", "should_pass": False},
        {"type": "pattern", "value": "", "should_pass": False},
    ]
    
    for test_case in test_cases:
        try:
            response = requests.post(
                f"{SERVER_URL}/api/whitelist/test",
                json={
                    "type": test_case["type"],
                    "value": test_case["value"]
                },
                timeout=5
            )
            
            success = response.status_code == 200
            expected = test_case["should_pass"]
            
            if success == expected:
                status = "✅ PASS"
            else:
                status = "❌ FAIL"
            
            print(f"  {status} {test_case['type']}: '{test_case['value']}' (expected: {'VALID' if expected else 'INVALID'})")
            
        except Exception as e:
            print(f"  ❌ ERROR testing {test_case['type']}: {test_case['value']} - {e}")

if __name__ == "__main__":
    print("🚀 Firewall Controller - Comprehensive Whitelist Creator")
    print("=" * 60)
    
    # Check current whitelist first
    print("1️⃣  Checking current whitelist...")
    check_whitelist_by_type()
    
    # Create comprehensive whitelist
    print("\n2️⃣  Creating comprehensive sample whitelist...")
    create_comprehensive_whitelist()
    
    # Check again after creation
    print("\n3️⃣  Analyzing whitelist after creation...")
    check_whitelist_by_type()
    
    # Test agent sync
    print("\n4️⃣  Testing agent sync endpoint...")
    test_agent_sync_comprehensive()
    
    # Test validation
    print("\n5️⃣  Testing entry validation...")
    test_entry_validation()
    
    print("\n🎉 Comprehensive whitelist testing completed!")
    print("✅ Your whitelist now contains examples of all entry types:")
    print("   🌐 Domains (with wildcards)")
    print("   🔌 IP Addresses (IPv4/IPv6, with ports/subnets)")
    print("   🔗 URLs (API endpoints, CDN resources)")
    print("   📝 Patterns (wildcard, regex, glob)")
    print("\nReady for comprehensive agent testing! 🚀")