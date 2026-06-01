import os
import sys

from bson import ObjectId
from flask import Flask, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from middleware.auth import init_auth_middleware, require_api_key
from models.api_key_model import APIKeyModel
from services.api_key_service import APIKeyService


class _InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class _UpdateResult:
    def __init__(self, modified_count):
        self.modified_count = modified_count


class _FakeCollection:
    def __init__(self):
        self.docs = []

    def create_index(self, *args, **kwargs):
        return None

    def insert_one(self, doc):
        stored = dict(doc)
        stored["_id"] = ObjectId()
        self.docs.append(stored)
        return _InsertResult(stored["_id"])

    def find_one(self, query, projection=None):
        for doc in self.docs:
            if all(doc.get(key) == value for key, value in query.items()):
                return doc
        return None

    def update_one(self, query, update):
        doc = self.find_one(query)
        if not doc:
            return _UpdateResult(0)

        for key, value in update.get("$set", {}).items():
            doc[key] = value
        for key, value in update.get("$inc", {}).items():
            doc[key] = doc.get(key, 0) + value
        return _UpdateResult(1)


class _FakeDb:
    def __init__(self):
        self.api_keys = _FakeCollection()


def _model():
    return APIKeyModel(_FakeDb())


def _doc_by_key_id(model, key_id):
    return model.collection.find_one({"_id": ObjectId(key_id)})


def test_expired_api_key_is_rejected_and_does_not_increment_usage():
    model = _model()
    created = model.create_api_key(
        name="Expired agent key",
        expires_in_days=-1,
        permissions=["agent_register"],
    )

    result = model.validate_api_key(created["api_key"], "agent_register")

    assert result == {"valid": False, "error": "API key has expired"}

    stored = _doc_by_key_id(model, created["key_id"])
    assert stored["usage_count"] == 0
    assert stored["last_used_at"] is None


def test_unexpired_api_key_is_valid_and_increments_usage():
    model = _model()
    created = model.create_api_key(
        name="Live agent key",
        expires_in_days=1,
        permissions=["agent_register"],
    )

    result = model.validate_api_key(created["api_key"], "agent_register")

    assert result["valid"] is True
    assert result["key_id"] == created["key_id"]

    stored = _doc_by_key_id(model, created["key_id"])
    assert stored["usage_count"] == 1
    assert stored["last_used_at"] is not None


def test_never_expires_api_key_is_valid():
    model = _model()
    created = model.create_api_key(
        name="Never expires key",
        expires_in_days=0,
        permissions=["agent_register"],
    )

    assert created["expires_at"] is None
    assert model.validate_api_key(created["api_key"], "agent_register")["valid"] is True


def test_require_api_key_returns_401_for_expired_key():
    model = _model()
    service = APIKeyService(model)
    created = model.create_api_key(
        name="Expired middleware key",
        expires_in_days=-1,
        permissions=["agent_register"],
    )

    init_auth_middleware(service)
    app = Flask(__name__)

    @app.route("/api/protected", methods=["POST"])
    @require_api_key("agent_register")
    def protected():
        return jsonify({"success": True})

    response = app.test_client().post(
        "/api/protected",
        headers={"X-API-Key": created["api_key"]},
        json={"hostname": "PC-01"},
    )

    assert response.status_code == 401
    assert response.get_json() == {
        "success": False,
        "error": "API key has expired",
    }
