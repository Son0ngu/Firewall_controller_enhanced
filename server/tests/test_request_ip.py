import os
import sys

from bson import ObjectId
from flask import Flask

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from services.audit_service import AuditService
from utils.request_ip import get_client_ip


class FakeAuditModel:
    def __init__(self):
        self.entries = []

    def log(self, audit_data):
        self.entries.append(dict(audit_data))
        return audit_data


def test_get_client_ip_uses_forwarded_for_first_ip():
    app = Flask(__name__)

    with app.test_request_context(
        headers={"X-Forwarded-For": "10.20.30.40, 127.0.0.1"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        assert get_client_ip() == "10.20.30.40"


def test_get_client_ip_uses_real_ip_when_forwarded_for_missing():
    app = Flask(__name__)

    with app.test_request_context(
        headers={"X-Real-IP": "192.168.1.25"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        assert get_client_ip() == "192.168.1.25"


def test_get_client_ip_falls_back_to_remote_addr():
    app = Flask(__name__)

    with app.test_request_context(environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert get_client_ip() == "127.0.0.1"


def test_get_client_ip_outside_request_context_uses_default():
    assert get_client_ip() == "unknown"


def test_audit_service_auto_ip_uses_forwarded_header():
    app = Flask(__name__)
    audit_model = FakeAuditModel()
    audit_service = AuditService(audit_model)
    user = {"_id": ObjectId(), "username": "admin", "role": "admin"}

    with app.test_request_context(
        headers={"X-Forwarded-For": "10.20.30.40, 127.0.0.1"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        audit_service.log_action(
            user=user,
            action="test.forwarded_ip",
            resource_type="test",
        )

    assert audit_model.entries[0]["ip_address"] == "10.20.30.40"
