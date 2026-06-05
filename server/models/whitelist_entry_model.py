"""Model for first-class whitelist entry rows.

This collection is the migration target for group embedded whitelist entries.
Global entries still live in ``db.whitelist`` during the compatibility
window; group scoped rows are written here first and embedded
``groups.whitelist[]`` remains a read fallback for one release.
"""

import logging
from typing import Dict, List, Optional

from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

from time_utils import now_vietnam, parse_agent_timestamp, to_vietnam


def _coerce_active(value, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", "inactive"}
    return bool(value)


class WhitelistEntryModel:
    """Repository for ``whitelist_entries`` collection."""

    def __init__(self, db: Database):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.db = db
        self.collection: Collection = db.whitelist_entries
        self._create_indexes()

    def _create_indexes(self) -> None:
        try:
            self.collection.create_index([("scope", ASCENDING)])
            self.collection.create_index([("group_id", ASCENDING)])
            self.collection.create_index([("is_active", ASCENDING)])
            self.collection.create_index([("legacy_embedded_id", ASCENDING)], sparse=True)
            self.collection.create_index([
                ("scope", ASCENDING),
                ("group_id", ASCENDING),
                ("type", ASCENDING),
                ("value", ASCENDING),
                ("is_active", ASCENDING),
            ])
        except Exception as exc:
            self.logger.warning(f"Error creating whitelist_entries indexes: {exc}")

    def _normalise_entry(self, entry_data: Dict) -> Dict:
        now = now_vietnam()
        entry = {**(entry_data or {})}
        entry.setdefault("scope", "group")
        entry.setdefault("type", "domain")
        entry.setdefault("category", "uncategorized")
        entry.setdefault("priority", "normal")
        entry.setdefault("is_active", True)
        entry["is_active"] = _coerce_active(entry.get("is_active"), default=True)
        entry.setdefault("created_at", now)
        entry.setdefault("added_date", now)
        entry["updated_at"] = entry.get("updated_at") or now
        if entry.get("value"):
            entry["value"] = str(entry["value"]).strip().lower()
        if entry.get("group_id") is not None:
            entry["group_id"] = str(entry["group_id"])
        if entry.get("legacy_embedded_id") is not None:
            entry["legacy_embedded_id"] = str(entry["legacy_embedded_id"])
        return entry

    def _serialise(self, entry: Dict) -> Dict:
        if not entry:
            return entry
        out = {**entry}
        if out.get("_id") is not None:
            out["_id"] = str(out["_id"])
        for field in ("created_at", "added_date", "updated_at", "expiry_date"):
            value = out.get(field)
            if not value:
                continue
            try:
                if hasattr(value, "isoformat"):
                    out[field] = to_vietnam(value).isoformat()
                elif isinstance(value, str):
                    out[field] = parse_agent_timestamp(value).isoformat()
            except Exception:
                pass
        out.setdefault("id", out.get("_id"))
        out.setdefault("scope", "group")
        out.setdefault("type", "domain")
        out.setdefault("category", "uncategorized")
        out.setdefault("priority", "normal")
        out.setdefault("is_active", True)
        return out

    def insert_entry(self, entry_data: Dict) -> str:
        entry = self._normalise_entry(entry_data)
        result = self.collection.insert_one(entry)
        return str(result.inserted_id)

    def bulk_insert_entries(self, entries: List[Dict]) -> List[str]:
        if not entries:
            return []
        normalised = [self._normalise_entry(entry) for entry in entries]
        result = self.collection.insert_many(normalised)
        return [str(inserted_id) for inserted_id in result.inserted_ids]

    def list_entries(self, group_id: str = None, include_inactive: bool = True) -> List[Dict]:
        query = {"scope": "group"}
        if group_id:
            query["group_id"] = str(group_id)
        if not include_inactive:
            query["is_active"] = True
        cursor = self.collection.find(query).sort("added_date", ASCENDING)
        return [self._serialise(entry) for entry in cursor]

    def list_group_entries(self, group_id: str, include_inactive: bool = True) -> List[Dict]:
        query = {"scope": "group", "group_id": str(group_id)}
        if not include_inactive:
            query["is_active"] = True
        cursor = self.collection.find(query).sort("added_date", ASCENDING)
        return [self._serialise(entry) for entry in cursor]

    def find_group_entry_by_value(self, group_id: str, value: str,
                                  entry_type: str = "domain",
                                  active_only: bool = False) -> Optional[Dict]:
        query = {
            "scope": "group",
            "group_id": str(group_id),
            "value": str(value).strip().lower(),
            "type": entry_type or "domain",
        }
        if active_only:
            query["is_active"] = True
        entry = self.collection.find_one(query)
        return self._serialise(entry) if entry else None

    def find_entry_by_id(self, entry_id: str, active_only: bool = False) -> Optional[Dict]:
        try:
            query = {"_id": ObjectId(entry_id)}
            if active_only:
                query["is_active"] = True
            entry = self.collection.find_one(query)
            return self._serialise(entry) if entry else None
        except Exception:
            return None

    def find_entry_access_info(self, entry_id: str) -> Optional[Dict]:
        try:
            entry = self.collection.find_one(
                {"_id": ObjectId(entry_id)},
                {"scope": 1, "group_id": 1},
            )
            return self._serialise(entry) if entry else None
        except Exception:
            return None

    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        try:
            payload = {**(update_data or {}), "updated_at": now_vietnam()}
            if payload.get("value"):
                payload["value"] = str(payload["value"]).strip().lower()
            if "is_active" in payload:
                payload["is_active"] = _coerce_active(payload.get("is_active"), default=True)
            result = self.collection.update_one(
                {"_id": ObjectId(entry_id)},
                {"$set": payload},
            )
            return result.matched_count > 0
        except Exception as exc:
            self.logger.error(f"Error updating whitelist entry {entry_id}: {exc}")
            return False

    def delete_entry(self, entry_id: str) -> bool:
        try:
            result = self.collection.delete_one({"_id": ObjectId(entry_id)})
            return result.deleted_count > 0
        except Exception as exc:
            self.logger.error(f"Error deleting whitelist entry {entry_id}: {exc}")
            return False

    def count_group_entries(self, group_id: str) -> int:
        return self.collection.count_documents({
            "scope": "group",
            "group_id": str(group_id),
        })
