"""
Script to setup sample whitelist data for Firewall Controller.
Run this script to populate the database with sample entries.
"""

import os
import sys
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_mongo_client():
    """Get MongoDB client connection"""
    mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    db_name = os.environ.get('MONGO_DBNAME', 'Monitoring')
    
    print(f"Connecting to MongoDB: {mongo_uri}")
    print(f"Database name: {db_name}")
    
    try:
        client = MongoClient(mongo_uri)
        # Test connection
        client.admin.command('ping')
        print("✅ MongoDB connection successful!")
        return client, db_name
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return None, None

def get_sample_data():
    """Get sample whitelist entries"""
    return [
        # System domains for localhost
        {"type": "domain", "value": "localhost", "category": "system", "notes": "Local development server", "priority": "critical"},
        {"type": "ip", "value": "127.0.0.1", "category": "system", "notes": "Localhost IP", "priority": "critical"},
        {"type": "ip", "value": "::1", "category": "system", "notes": "IPv6 localhost", "priority": "critical"},
        
        # Essential domains
        {"type": "domain", "value": "google.com", "category": "search", "notes": "Google search engine", "priority": "high"},
        {"type": "domain", "value": "*.google.com", "category": "search", "notes": "All Google services", "priority": "high"},
        {"type": "domain", "value": "github.com", "category": "development", "notes": "Code repository", "priority": "normal"},
        {"type": "domain", "value": "*.github.com", "category": "development", "notes": "GitHub services", "priority": "normal"},
        {"type": "domain", "value": "microsoft.com", "category": "business", "notes": "Microsoft services", "priority": "high"},
        {"type": "domain", "value": "*.microsoft.com", "category": "business", "notes": "Microsoft services pattern", "priority": "normal"},
        {"type": "domain", "value": "stackoverflow.com", "category": "development", "notes": "Developer Q&A", "priority": "normal"},
        
        # System domains
        {"type": "domain", "value": "windowsupdate.microsoft.com", "category": "system", "notes": "Windows Update", "priority": "critical"},
        {"type": "domain", "value": "update.microsoft.com", "category": "system", "notes": "Microsoft Update", "priority": "critical"},
        {"type": "domain", "value": "download.windowsupdate.com", "category": "system", "notes": "Windows Update downloads", "priority": "critical"},
        
        # DNS servers
        {"type": "ip", "value": "8.8.8.8", "category": "dns", "notes": "Google DNS Primary", "priority": "high"},
        {"type": "ip", "value": "8.8.4.4", "category": "dns", "notes": "Google DNS Secondary", "priority": "high"},
        {"type": "ip", "value": "1.1.1.1", "category": "dns", "notes": "Cloudflare DNS Primary", "priority": "high"},
        {"type": "ip", "value": "1.0.0.1", "category": "dns", "notes": "Cloudflare DNS Secondary", "priority": "high"},
        
        # CDN and API endpoints
        {"type": "url", "value": "https://api.github.com/*", "category": "api", "notes": "GitHub API endpoints", "priority": "normal"},
        {"type": "url", "value": "https://fonts.googleapis.com/*", "category": "cdn", "notes": "Google Fonts CDN", "priority": "normal"},
        {"type": "url", "value": "https://cdnjs.cloudflare.com/*", "category": "cdn", "notes": "Cloudflare CDN", "priority": "normal"},
        {"type": "url", "value": "https://ajax.googleapis.com/*", "category": "cdn", "notes": "Google AJAX CDN", "priority": "normal"},
        
        # Cloud services patterns
        {"type": "pattern", "value": "*.amazonaws.com", "category": "cloud", "notes": "AWS services pattern", "priority": "normal"},
        {"type": "pattern", "value": "*.azurewebsites.net", "category": "cloud", "notes": "Azure websites pattern", "priority": "normal"},
        {"type": "pattern", "value": "*.herokuapp.com", "category": "cloud", "notes": "Heroku apps pattern", "priority": "normal"},
        
        # Development tools
        {"type": "domain", "value": "npmjs.com", "category": "development", "notes": "NPM package registry", "priority": "normal"},
        {"type": "domain", "value": "*.npmjs.com", "category": "development", "notes": "NPM services", "priority": "normal"},
        {"type": "domain", "value": "pypi.org", "category": "development", "notes": "Python package index", "priority": "normal"},
        {"type": "domain", "value": "*.pypi.org", "category": "development", "notes": "PyPI services", "priority": "normal"},
        
        # Common safe domains
        {"type": "domain", "value": "wikipedia.org", "category": "education", "notes": "Wikipedia encyclopedia", "priority": "normal"},
        {"type": "domain", "value": "*.wikipedia.org", "category": "education", "notes": "Wikipedia services", "priority": "normal"},
    ]

def setup_sample_data():
    """Setup sample whitelist data in MongoDB"""
    print("🚀 Starting sample data setup...")
    
    # Get MongoDB connection
    mongo_client, db_name = get_mongo_client()
    if not mongo_client:
        print("❌ Cannot connect to MongoDB. Exiting.")
        return False
    
    try:
        # Get database and collection - sử dụng db_name từ .env
        db = mongo_client[db_name]
        whitelist_collection = db.whitelist
        
        # Debug: In thông tin database
        print(f"📋 Using database: {db_name}")
        print(f"📋 Collection: whitelist")
        
        # Get sample data
        sample_entries = get_sample_data()
        
        created_count = 0
        existing_count = 0
        error_count = 0
        
        print(f"📝 Processing {len(sample_entries)} sample entries...")
        
        for entry in sample_entries:
            try:
                entry_data = {
                    "type": entry["type"],
                    "value": entry["value"], 
                    "category": entry["category"],
                    "notes": entry["notes"],
                    "priority": entry.get("priority", "normal"),
                    "added_by": "system",
                    "added_date": datetime.utcnow(),
                    "last_updated": datetime.utcnow(),
                    "usage_count": 0,
                    "enable_logging": False,
                    "is_temporary": False,
                    "is_active": True
                }
                
                # Check if exists
                existing = whitelist_collection.find_one({"value": entry["value"]})
                if not existing:
                    result = whitelist_collection.insert_one(entry_data)
                    created_count += 1
                    print(f"✅ Created: {entry['value']} (ID: {result.inserted_id})")
                else:
                    existing_count += 1
                    print(f"⚠️  Already exists: {entry['value']}")
                    
            except Exception as e:
                error_count += 1
                print(f"❌ Error creating {entry['value']}: {e}")
        
        # Kiểm tra số lượng documents trong collection
        total_in_db = whitelist_collection.count_documents({})
        print(f"📊 Total documents in database: {total_in_db}")
        
        print("\n" + "="*50)
        print("📊 SUMMARY:")
        print(f"✅ Created: {created_count} entries")
        print(f"⚠️  Already existed: {existing_count} entries")
        print(f"❌ Errors: {error_count} entries")
        print(f"📝 Total processed: {len(sample_entries)} entries")
        print(f"🗃️  Total in database: {total_in_db} entries")
        print("="*50)
        
        return True
        
    except Exception as e:
        print(f"❌ Error during setup: {e}")
        return False
    finally:
        mongo_client.close()

def clear_whitelist():
    """Clear all whitelist entries (use with caution!)"""
    print("⚠️  WARNING: This will delete ALL whitelist entries!")
    confirm = input("Type 'YES' to confirm deletion: ")
    
    if confirm != 'YES':
        print("❌ Operation cancelled.")
        return False
    
    mongo_client, db_name = get_mongo_client()
    if not mongo_client:
        return False
    
    try:
        db = mongo_client[db_name]
        whitelist_collection = db.whitelist
        
        result = whitelist_collection.delete_many({})
        print(f"🗑️  Deleted {result.deleted_count} whitelist entries")
        return True
        
    except Exception as e:
        print(f"❌ Error clearing whitelist: {e}")
        return False
    finally:
        mongo_client.close()

if __name__ == "__main__":
    print("🔥 Firewall Controller - Sample Data Setup")
    print("="*50)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "clear":
            clear_whitelist()
        elif sys.argv[1] == "setup":
            setup_sample_data()
        else:
            print("Usage:")
            print("  python setup_sample_data.py setup  - Setup sample data")
            print("  python setup_sample_data.py clear  - Clear all whitelist data")
    else:
        # Default action is setup
        setup_sample_data()
    
    print("\n✨ Done!")