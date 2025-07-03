# Firewall Controller - Network Security Management System

## Tổng quan

Firewall Controller là một hệ thống quản lý bảo mật mạng phân tán, bao gồm:
- **Agent**: Chạy trên các máy client, giám sát traffic và thực thi firewall rules
- **Server**: Central management server với web interface và API
- **Whitelist Management**: Quản lý danh sách domain được phép truy cập tập trung

## Kiến trúc hệ thống

```
┌─────────────────┐    HTTPS/REST API    ┌─────────────────┐
│   Agent (Client) │ ←─────────────────→ │   Server        │
│                 │                      │                 │
│ • Packet Capture│                      │ • Web Dashboard │
│ • Firewall Mgmt │                      │ • API Endpoints │
│ • Whitelist Sync│                      │ • MongoDB       │
│ • Log Reporting │                      │ • Agent Mgmt    │
└─────────────────┘                      └─────────────────┘
```

## Yêu cầu hệ thống

### Agent (Windows Client)
- **OS**: Windows 10/11, Windows Server 2016+
- **Python**: 3.8+ (khuyến nghị 3.12)
- **Privileges**: Administrator (cho firewall management)
- **Network**: HTTPS access đến server
- **RAM**: 512MB+
- **Disk**: 100MB+