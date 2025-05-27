import time
import random
from log_sender import LogSender

# Cấu hình LogSender
config = {
    "server_url": "http://localhost:5000",
    "batch_size": 10,
    "send_interval": 5
}

# Khởi tạo LogSender
log_sender = LogSender(config)
log_sender.start()

# Danh sách tên miền ví dụ
domains = [
    "google.com", "facebook.com", "youtube.com", "twitter.com",
    "malware-site.com", "suspicious-domain.net", "phishing-example.org"
]

# Gửi log ví dụ
try:
    print("Sending sample logs. Press Ctrl+C to stop.")
    i = 0
    while True:
        domain = random.choice(domains)
        ip = f"192.168.1.{random.randint(1, 255)}"
        action = "block" if "malware" in domain or "suspicious" in domain or "phishing" in domain else "allow"
        
        log = {
            "domain": domain,
            "dest_ip": ip,
            "dest_port": random.choice([80, 443]),
            "protocol": random.choice(["HTTP", "HTTPS"]),
            "action": action,
            "process": random.choice(["chrome.exe", "firefox.exe", "edge.exe"])
        }
        
        log_sender.queue_log(log)
        
        i += 1
        if i % 10 == 0:
            print(f"Queued {i} logs...")
        
        time.sleep(random.uniform(0.5, 2.0))
        
except KeyboardInterrupt:
    print("\nStopping...")
finally:
    log_sender.stop()
    print("Done.")