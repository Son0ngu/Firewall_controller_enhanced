"""
Clean corrupted JSON state files
"""

import os
import json
import time
import shutil

def cleanup_corrupted_files():
    """Clean up corrupted state files"""
    files_to_check = [
        "whitelist_state.json",
        "ip_cache.json"
    ]
    
    for filename in files_to_check:
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    content = f.read().strip()
                    if content:
                        json.loads(content)  # Test parsing
                        print(f"✅ {filename} is valid")
                    else:
                        print(f"⚠️ {filename} is empty, removing...")
                        os.remove(filename)
            except json.JSONDecodeError as e:
                print(f"❌ {filename} is corrupted: {e}")
                backup_name = f"{filename}.corrupted.{int(time.time())}"
                shutil.move(filename, backup_name)
                print(f"📁 Moved to {backup_name}")
            except Exception as e:
                print(f"❌ Error checking {filename}: {e}")

if __name__ == "__main__":
    print("🧹 Cleaning corrupted JSON files...")
    cleanup_corrupted_files()
    print("✅ Cleanup completed!")