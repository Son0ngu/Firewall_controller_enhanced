import os
import sys


_TEST_ENV = {
    "SECRET_KEY": "pytest-secret-key-2026-06-08-strong",
    "JWT_SECRET_KEY": "pytest-jwt-secret-key-2026-06-08-strong",
    "JWT_REFRESH_SECRET_KEY": "pytest-jwt-refresh-secret-key-2026-06-08-strong",
    "API_KEY_HMAC_SECRET": "pytest-api-key-hmac-secret-2026-06-08-strong",
}
os.environ.update(_TEST_ENV)

jwt_service_module = sys.modules.get("services.jwt_service")
if jwt_service_module is not None:
    jwt_service_module.JWT_SECRET_KEY = _TEST_ENV["JWT_SECRET_KEY"]
    jwt_service_module.JWT_REFRESH_SECRET_KEY = _TEST_ENV["JWT_REFRESH_SECRET_KEY"]
