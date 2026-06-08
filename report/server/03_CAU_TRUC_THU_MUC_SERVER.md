# Cấu trúc thư mục Server

```text
server/
├── bootstrap/
│   ├── __init__.py
│   ├── app_factory.py        # tạo Flask app, CORS, SocketIO, DB, register route modules
│   ├── container.py          # tạo model/service/controller, middleware, register API blueprint
│   └── startup_tasks.py      # optional admin bootstrap; API key bootstrap skipped
├── config/
│   ├── __init__.py
│   └── rbac_config.py
├── controllers/
│   ├── admin_auth_controller.py    # shim: re-export WebAuthController + alias AdminAuthController
│   ├── agent_controller.py
│   ├── api_key_controller.py
│   ├── audit_controller.py
│   ├── auth_controller.py          # AgentAuthController (alias AuthController giữ cho backwards-compat)
│   ├── group_controller.py
│   ├── log_controller.py
│   ├── user_controller.py
│   ├── web_auth_controller.py      # WebAuthController — canonical, /api/admin/auth/*
│   ├── whitelist_controller.py
│   └── whitelist_profile_controller.py
├── database/
│   └── config.py
├── middleware/
│   ├── __init__.py
│   ├── auth.py
│   └── rbac.py
├── models/
│   ├── agent_model.py
│   ├── agent_policy_model.py
│   ├── api_key_model.py
│   ├── audit_model.py
│   ├── group_model.py
│   ├── log_model.py
│   ├── session_model.py
│   ├── user_model.py
│   ├── whitelist_model.py
│   └── whitelist_profile_model.py
├── scripts/
│   ├── migrations/
│   │   └── 2026_remove_default_profiles.py
│   └── seed_rbac.py
├── routes/
│   ├── __init__.py
│   ├── errors.py             # error handlers HTML/JSON
│   ├── pages.py              # dashboard/page routes + /api/health, /api/config
│   └── socketio_events.py    # connect/disconnect/ping inbound handlers
├── services/
│   ├── admin_auth_service.py
│   ├── agent_policy_service.py
│   ├── agent_service.py
│   ├── api_key_service.py
│   ├── audit_service.py
│   ├── group_service.py
│   ├── jwt_service.py
│   ├── log_service.py
│   ├── rbac_service.py
│   ├── user_service.py
│   ├── whitelist_profile_service.py
│   └── whitelist_service.py
├── utils/
│   ├── __init__.py
│   └── request_ip.py
├── tests/
│   ├── __init__.py
│   ├── test_agent_full.py
│   ├── test_agents.py
│   ├── test_audit.py
│   ├── test_groups.py
│   ├── test_request_ip.py
│   ├── test_teacher_data_filtering.py
│   ├── test_users_auth.py
│   └── test_whitelist_and_logs.py
├── views/
│   ├── static/
│   │   ├── css/
│   │   │   ├── admin_audit.css
│   │   │   ├── admin_users.css
│   │   │   ├── agents.css
│   │   │   ├── base.css
│   │   │   ├── custom_select.css
│   │   │   ├── dashboard.css
│   │   │   ├── error_404.css
│   │   │   ├── error_500.css
│   │   │   ├── group_detail.css
│   │   │   ├── groups.css
│   │   │   ├── login.css
│   │   │   ├── logs.css
│   │   │   ├── profile.css
│   │   │   └── whitelist.css
│   │   └── js/
│   │       ├── admin_users.js
│   │       ├── agents.js
│   │       ├── auth.js
│   │       ├── base.js
│   │       ├── dashboard.js
│   │       ├── error_404.js
│   │       ├── error_500.js
│   │       ├── group_detail.js
│   │       ├── groups.js
│   │       ├── logs.js
│   │       └── whitelist.js
│   └── templates/
│       ├── components/
│       │   ├── empty_state.html
│       │   ├── hero.html
│       │   └── stat_card.html
│       ├── 404.html
│       ├── 500.html
│       ├── admin_audit.html
│       ├── admin_users.html
│       ├── agents.html
│       ├── api_keys.html
│       ├── base.html
│       ├── dashboard.html
│       ├── error_base.html
│       ├── group_detail.html
│       ├── groups.html
│       ├── login.html
│       ├── logs.html
│       ├── profile.html
│       └── whitelist.html
├── .env-example
├── app.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── time_utils.py
```

## Ý nghĩa các package chính

| Package | Vai trò |
| --- | --- |
| `server/app.py` | Entrypoint mỏng: patch gevent, export `create_app`, chạy SocketIO khi gọi trực tiếp. |
| `server/bootstrap` | App factory, container wiring, startup task theo env. |
| `server/routes` | Page routes, error handlers, SocketIO inbound events. |
| `server/controllers` | Định nghĩa route API, validate request, gọi service. |
| `server/services` | Business logic, RBAC filtering, SocketIO events. |
| `server/models` | MongoDB collection access và indexes; sau refactor đây là tầng duy nhất trong server app được phép gọi `.collection` trực tiếp. |
| `server/middleware` | API Key, JWT, login, permission, ownership decorators. |
| `server/config` | RBAC role/permission definitions. |
| `server/utils` | Helper dùng chung, gồm chuẩn hóa client IP từ proxy headers. |
| `server/views` | HTML templates, CSS, JS dashboard. |
| `server/tests` | Test API, auth, RBAC, whitelist/logs/groups/agents. |
