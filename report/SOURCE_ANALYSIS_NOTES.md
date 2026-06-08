# Ghi chú phân tích source

## Phạm vi đã đọc

- Python source trong `agent/` và `server/`.
- `server/requirements.txt`, `agent/requirements.txt`, `server/Dockerfile`, `server/docker-compose.yml`, `server/.env-example`.
- Test source trong `server/tests/` để mô tả phạm vi kiểm thử.

## Phạm vi cố ý không dùng làm nguồn chính

- Không dùng tài liệu cũ trong `docs/` để suy luận kiến trúc hiện tại.
- Không đọc `server/.env` để tránh lộ secret.
- Không chạy `dist/SAINT.exe`, Agent GUI, Server thật, Docker compose, packet capture hoặc lệnh firewall.

## Phương pháp

- Trích route API từ `server/controllers/*.py`; các blueprint được đăng ký tập trung trong `server/bootstrap/container.py` với prefix `/api`.
- Trích route web/page từ `server/routes/pages.py`, error handler từ `server/routes/errors.py`, SocketIO inbound handler từ `server/routes/socketio_events.py`.
- Trích class/function bằng AST Python, không import module.
- Trích collection MongoDB từ `server/models/` và `server/services/jwt_service.py`.
- Trích SocketIO event bằng search pattern `socketio.emit` và `@socketio.on`.

## Cập nhật sau refactor 2026-05-26

- `server/app.py` không còn chứa controller composition, page route, error handler hoặc SocketIO handler; file này giữ `gevent.monkey.patch_all()`, export `create_app` và chạy server khi gọi trực tiếp.
- App factory thật nằm ở `server/bootstrap/app_factory.py`; container/model/service/controller wiring nằm ở `server/bootstrap/container.py`; startup tasks chỉ còn admin bootstrap theo env, còn API key bootstrap đã bỏ khỏi boot path trong `server/bootstrap/startup_tasks.py`.
- Guard hiện tại: `rg -n "\.collection\." server/controllers server/services server/middleware` không còn kết quả; truy cập Mongo trực tiếp được giữ trong model layer.
- Đã smoke test `from app import create_app`, gọi `create_app()` nhiều lần và `/api/health`; các bộ test liên quan group, teacher filtering, whitelist/logs, request IP, audit và admin auth đã pass.

## Thống kê source

| Nhóm | Số module Python |
| --- | ---: |
| Agent | 62 |
| Server, gồm tests | 62 |
| Server API routes | 69 controller rules + `/api/health`, `/api/config` |
