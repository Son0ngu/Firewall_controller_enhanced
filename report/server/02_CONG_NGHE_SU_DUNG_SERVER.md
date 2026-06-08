# Công nghệ sử dụng - Server

| Dependency | Vai trò trong source |
| --- | --- |
| pymongo | MongoDB driver. |
| pydantic | Validate/schema dữ liệu. |
| flask | Web framework cho REST API và server-rendered dashboard. |
| flask-socketio | WebSocket/SocketIO để đẩy trạng thái real-time. |
| flask-cors | CORS cho API. |
| python-dotenv | Nạp biến môi trường từ `.env`. |
| pyjwt | JWT access/refresh token. |
| bcrypt | Hash mật khẩu. |
| email_validator | Validate email user. |
| gevent | Async worker cho SocketIO. |
| gevent-websocket | WebSocket transport cho gevent. |
| tzdata | Thư viện hỗ trợ runtime. |
| python-snappy | Nén dữ liệu MongoDB/network nếu driver dùng. |

## Runtime và triển khai

| Thành phần | Source | Vai trò |
| --- | --- | --- |
| Flask app factory | `server/bootstrap/app_factory.py` | Khởi tạo app, CORS, SocketIO, DB, template filter, page/error/socketio routes. |
| App entrypoint | `server/app.py` | Giữ `gevent.monkey.patch_all()`, export `create_app` và chạy server khi gọi trực tiếp. |
| Dependency/container wiring | `server/bootstrap/container.py` | Khởi tạo model/service/controller, auth/RBAC middleware, register blueprint và attach runtime services lên Flask app. |
| Startup tasks | `server/bootstrap/startup_tasks.py` | Admin bootstrap chỉ khi có env/credentials; API key bootstrap không còn tự chạy. |
| Page/error/SocketIO routes | `server/routes/` | Tách web page route, error handler và SocketIO inbound handler khỏi `server/app.py`. |
| MongoDB config | `server/database/config.py` | Kết nối MongoDB, config theo env. |
| Docker | `server/Dockerfile`, `server/docker-compose.yml` | Đóng gói/deploy Server. |
| Server templates | `server/views/templates/` | Dashboard/admin pages server-rendered. |
| Static JS/CSS | `server/views/static/` | Tương tác dashboard, table, auth, SocketIO client. |
