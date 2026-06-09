"""
Whitelist Service - Business logic for whitelist operations
- Clean and simple
"""

import logging
import warnings
from typing import Dict, List, Optional, TYPE_CHECKING
from datetime import datetime, timedelta

from bson import ObjectId

from models.whitelist_model import WhitelistModel

if TYPE_CHECKING:
    from models.whitelist_entry_model import WhitelistEntryModel
else:
    try:
        from models.whitelist_entry_model import WhitelistEntryModel
    except Exception:  # pragma: no cover - keeps legacy isolated tests importable
        WhitelistEntryModel = None

# Import time utilities - vietnam ONLY
from time_utils import (
    now_iso,
    now_vietnam,
    parse_agent_timestamp,
    to_vietnam,
)

# Pseudo-ID format for legacy embedded group entries is centralised. New
# group entries use real ObjectIds from ``whitelist_entries``; pseudo-ID
# remains only as a compatibility fallback during the migration window.
from services.whitelist_entry_id import (
    GroupEntryRef,
    is_group_pseudo_id,
    make_group_pseudo_id,
    parse_group_pseudo_id,
)
from services.whitelist_normalization import canonicalize_whitelist_entry

logger = logging.getLogger(__name__)


def _coerce_active(value, default: bool = True) -> bool:
    """Coerce UI/API active flags without treating ``"false"`` as truthy."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", "inactive"}
    return bool(value)


def _apply_entry_update(entry: Dict, update_data: Dict) -> None:
    """Mutate an embedded whitelist entry in place with ``update_data``.

    Centralised so both pseudo-ID and ObjectId update paths apply the same
    field-coercion rules. ``is_active`` is coerced to a real bool because
    JSON deserialisation has historically delivered strings here.
    """
    for k, v in update_data.items():
        if k in ("updated_at",):
            continue
        if k == "is_active":
            entry[k] = _coerce_active(v)
        else:
            entry[k] = v


# Target removal: 2026-Q4 (after the unified whitelist_entries migration
# has run in production and access logs confirm no remaining callers). If
# you are reading this past that date, grep for callers and delete the five
# ``*_domain[s]`` methods + this helper.
LEGACY_DOMAIN_API_REMOVAL = "2026-Q4"
LEGACY_GROUP_PSEUDO_ID_REMOVAL = "after whitelist_entries production cutover"


def _warn_legacy_domain_api(method_name: str) -> None:
    """Emit a single DeprecationWarning when a legacy domain API is called.

    The five ``*_domain[s]`` methods predate the unified entry API
    (``add_entry``/``delete_entry``/``bulk_*``). They still ship because
    older callers (some CLI scripts, integration tests) import them by
    name, but new code MUST use the entry API — the next phase removes
    these methods and replaces them with a thin compat shim, then drops
    that shim too. Planned removal: see ``LEGACY_DOMAIN_API_REMOVAL``.
    """
    warnings.warn(
        f"WhitelistService.{method_name}() is deprecated — use the entry API "
        f"(add_entry / delete_entry / bulk_*). Scheduled for removal in "
        f"{LEGACY_DOMAIN_API_REMOVAL} after the unified whitelist_entries "
        f"migration lands.",
        DeprecationWarning,
        stacklevel=3,
    )


def _log_legacy_group_pseudo_id_usage(
    operation: str,
    ref: Optional[GroupEntryRef],
    raw_id: str,
) -> None:
    """Emit a grep-friendly marker while legacy pseudo-IDs are still accepted."""
    group_id = ref.group_id if ref else "unknown"
    entry_type = ref.entry_type if ref else "unknown"
    logger.warning(
        "legacy_group_pseudo_id_used operation=%s group_id=%s "
        "entry_type=%s removal=%s raw_id=%s",
        operation,
        group_id,
        entry_type,
        LEGACY_GROUP_PSEUDO_ID_REMOVAL,
        raw_id,
    )

class WhitelistService:
    """Service class for whitelist business logic - vietnam ONLY"""
    
    def __init__(self, whitelist_model: WhitelistModel, agent_model, group_model, socketio=None,
                 entry_model: Optional["WhitelistEntryModel"] = None,
                 policy_service=None, profile_service=None):
        """Initialize WhitelistService with model and socketio"""
        self.model = whitelist_model
        self.agent_model = agent_model
        self.group_model = group_model
        self.entry_model = entry_model
        self.socketio = socketio
        self.policy_service = policy_service
        self.profile_service = profile_service
        self.logger = logging.getLogger(self.__class__.__name__)

    def validate_teacher_entry_access(self, item_id: str, teacher_group_ids: List[str],
                                      action: str) -> tuple:
        """Validate teacher access to a global/group whitelist entry.

        Returns (allowed, error_message). Missing/malformed entries are left to
        the operation itself so existing 404/validation behavior is preserved.
        """
        teacher_groups = {str(group_id) for group_id in (teacher_group_ids or [])}
        action = action or "edit"

        # Pseudo-ID path: ``group::<group_id>::<type>::<value>``. The parsing
        # used to be inline here (and in four other places). Now we go
        # through whitelist_entry_id so the format has one owner.
        ref = parse_group_pseudo_id(item_id)
        if ref is not None:
            _log_legacy_group_pseudo_id_usage(
                f"teacher_{action}", ref, item_id
            )
            if str(ref.group_id) not in teacher_groups:
                return False, f"No permission to {action} this entry"
            return True, None

        entry = self.entry_model.find_entry_access_info(item_id) if self.entry_model else None
        if entry:
            entry_group = entry.get("group_id")
            if entry.get("scope") == "global" and not entry_group:
                if action == "delete":
                    return False, "Teachers cannot delete from global whitelist"
                return False, "Teachers cannot edit global whitelist"
            if not entry_group or str(entry_group) not in teacher_groups:
                return False, f"No permission to {action} this entry"
            return True, None

        entry = self.model.find_entry_access_info(item_id)
        if not entry:
            try:
                group = self.group_model.find_group_with_embedded_entry(ObjectId(item_id))
            except Exception:
                # Malformed entry id from a teacher → fail closed (an auth gate
                # must not default to "allowed" on bad input).
                return False, "Invalid entry id"

            if not group:
                return True, None
            if str(group.get("_id")) not in teacher_groups:
                return False, f"No permission to {action} this entry"
            return True, None

        if entry.get("scope") == "global" and not entry.get("group_id"):
            if action == "delete":
                return False, "Teachers cannot delete from global whitelist"
            return False, "Teachers cannot edit global whitelist"

        entry_group = entry.get("group_id")
        if entry_group and str(entry_group) not in teacher_groups:
            return False, f"No permission to {action} this entry"

        return True, None
    
    def get_all_entries(
        self,
        filters: Dict = None,
        limit: int = None,
        offset: int = 0,
    ) -> Dict:
        """Return raw management whitelist rows, not effective merged rows.

        The admin UI needs to inspect and edit configured entries as they
        physically exist: global entries, first-class group entries, and legacy
        embedded ``groups.whitelist[]`` rows. Agent sync still uses
        ``get_agent_sync_data`` / ``get_scoped_whitelist`` for effective merge.
        """
        filters = filters or {}
        entries = self._collect_management_entries()
        entries = self._filter_management_entries(entries, filters)
        total_count = len(entries)
        if limit is not None:
            entries = entries[offset:offset + limit]
        
        return {
            "items": entries,
            "domains": entries,
            "success": True,
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "server_time": now_iso()
        }

    def _collect_management_entries(self) -> List[Dict]:
        """Collect global, first-class group, and legacy embedded rows."""
        groups = self.group_model.list_groups({}) if self.group_model else []
        group_lookup = {str(group.get("_id")): group for group in groups or []}
        source_rank = {
            "groups.whitelist": 1,
            "whitelist": 2,
            "whitelist_entries": 3,
        }
        merged: Dict[tuple, Dict] = {}

        def put(raw_entry: Dict, source: str, group: Optional[Dict] = None) -> None:
            formatted = self._format_management_entry(raw_entry, source, group_lookup, group)
            if not formatted:
                return
            key = (
                formatted.get("scope", "global"),
                formatted.get("group_id") or "",
                formatted.get("type", "domain"),
                formatted.get("value", ""),
            )
            current = merged.get(key)
            if not current or source_rank.get(source, 0) >= source_rank.get(current.get("source"), 0):
                merged[key] = formatted

        # Legacy/global collection. Some older rows may carry scope=group here.
        for entry in self.model.find_raw_entries({}, sort_field="added_date"):
            put(entry, "whitelist")

        if self.entry_model:
            for entry in self.entry_model.list_entries(include_inactive=True):
                group = group_lookup.get(str(entry.get("group_id") or ""))
                put(entry, "whitelist_entries", group)

        # Embedded fallback for groups that have not migrated to whitelist_entries.
        for group in groups or []:
            for entry in self._normalize_group_entries(group, include_inactive=True):
                put(entry, "groups.whitelist", group)

        entries = list(merged.values())
        entries.sort(key=lambda item: str(item.get("added_date") or ""), reverse=True)
        return entries

    def _format_management_entry(
        self,
        entry: Dict,
        source: str,
        group_lookup: Dict[str, Dict],
        group: Optional[Dict] = None,
    ) -> Optional[Dict]:
        entry_type, value = canonicalize_whitelist_entry(
            entry.get("type", "domain"),
            entry.get("value") or entry.get("domain") or entry.get("ip") or entry.get("url") or "",
        )
        if not value:
            return None

        scope = entry.get("scope", "global")
        group_id = str(entry.get("group_id") or "")
        if scope == "group" and group_id and not group:
            group = group_lookup.get(group_id)

        raw_id = entry.get("_id") or entry.get("id")
        entry_id = str(raw_id) if raw_id is not None else None
        is_active = _coerce_active(entry.get("is_active", entry.get("active", True)))

        added_date = entry.get("added_date") or entry.get("created_at")
        if added_date is not None:
            try:
                added_date = added_date.isoformat() if hasattr(added_date, "isoformat") else str(added_date)
            except Exception:
                added_date = None

        formatted = {
            "_id": entry_id,
            "id": entry_id,
            "type": entry_type,
            "value": value,
            "category": entry.get("category") or entry.get("description") or "uncategorized",
            "priority": entry.get("priority", "normal"),
            "added_by": entry.get("added_by", "unknown"),
            "is_active": is_active,
            "active": is_active,
            "scope": scope,
            "added_date": added_date,
            "source": source,
        }
        if entry.get("notes"):
            formatted["notes"] = entry.get("notes")
        if group_id:
            formatted["group_id"] = group_id
            formatted["group_name"] = entry.get("group_name") or (group or {}).get("name")
        return formatted

    def _filter_management_entries(self, entries: List[Dict], filters: Dict) -> List[Dict]:
        type_filter = (filters.get("type") or "").strip().lower()
        status_filter = (filters.get("status") or "").strip().lower()
        scope_filter = (filters.get("scope") or "").strip().lower()
        group_filter = str(filters.get("group_id") or "").strip()
        search = (filters.get("search") or "").strip().lower()

        filtered = []
        for entry in entries:
            if type_filter and entry.get("type") != type_filter:
                continue
            if status_filter in {"active", "inactive"}:
                should_be_active = status_filter == "active"
                if _coerce_active(entry.get("is_active", True)) != should_be_active:
                    continue
            if group_filter:
                if entry.get("scope") != "group" or str(entry.get("group_id") or "") != group_filter:
                    continue
            elif scope_filter and entry.get("scope", "global") != scope_filter:
                continue
            if search:
                haystack = " ".join(
                    str(entry.get(key, "") or "").lower()
                    for key in ("value", "category", "notes", "group_name", "type", "scope")
                )
                if search not in haystack:
                    continue
            filtered.append(entry)
        return filtered
    
    def add_entry(self, entry_data: Dict, client_ip: str) -> Dict:
        """Add new entry to whitelist - vietnam ONLY"""
        entry_type = entry_data.get("type", "domain")
        value = entry_data.get("value", "").strip().lower()
        
        if not value:
            raise ValueError("Value is required")

        entry_type, value = canonicalize_whitelist_entry(entry_type, value)
        
        # Validate entry using model
        validation_result = self.model.validate_entry_value(entry_type, value)
        if not validation_result["valid"]:
            raise ValueError(validation_result["message"])

        scope = entry_data.get("scope", "global")
        group_id = entry_data.get("group_id")
        is_active = _coerce_active(
            entry_data.get("is_active", entry_data.get("active")),
            default=True,
        )
        if scope == "group" and group_id:
            group = self.group_model.find_by_id(group_id)
            if not group:
                raise ValueError("Group not found")

            existing_collection = (
                self.entry_model.find_group_entry_by_value(group_id, value, entry_type)
                if self.entry_model else None
            )
            existing_embedded = any(
                (
                    (entry.get("value") if isinstance(entry, dict) else str(entry)) == value
                    and (entry.get("type", "domain") if isinstance(entry, dict) else "domain") == entry_type
                )
                for entry in group.get("whitelist", [])
            )
            if existing_collection or existing_embedded:
                raise ValueError("Entry already exists in group whitelist")

            current_time = now_vietnam()
            category_value = (
                entry_data.get("category")
                or entry_data.get("description")
                or "uncategorized"
            )
            processed_entry = {
                "_id": ObjectId(),
                "scope": "group",
                "group_id": str(group_id),
                "type": entry_type,
                "value": value,
                "category": category_value,
                "priority": entry_data.get("priority", "normal"),
                "added_by": client_ip,
                "added_date": current_time,
                "is_active": is_active,
            }
            if entry_data.get("notes"):
                processed_entry["notes"] = entry_data.get("notes")

            if self.entry_model:
                entry_id = self.entry_model.insert_entry(processed_entry)
                self.group_model.bump_whitelist_version(str(group_id))
            else:
                current_whitelist = group.get("whitelist", [])
                self.group_model.update_group(str(group_id), {
                    "whitelist": current_whitelist + [processed_entry],
                    "whitelist_version": group.get("whitelist_version", 1) + 1,
                })
                entry_id = str(processed_entry["_id"])

            if self.socketio:
                self.socketio.emit("whitelist_added", {
                    "type": entry_type,
                    "value": value,
                    "category": processed_entry["category"],
                    "scope": "group",
                    "group_id": str(group_id),
                    "added_by": client_ip,
                    "timestamp": now_iso(),
                })

            return {
                "id": entry_id,
                "message": f"{entry_type.capitalize()} added to group whitelist",
                "timestamp": now_iso(),
                "server_time": now_iso(),
            }
        
        # Check for duplicates in global whitelist (both active and inactive)
        existing = self.model.find_entry_by_value(value, active_only=False)
        if existing and existing.get("scope", "global") == "global":
            if existing.get("is_active", True):
                raise ValueError("Entry already exists in global whitelist")
            else:
                # Re-activate the existing inactive entry instead of creating duplicate
                return self.model.reactivate_entry(existing["_id"])
        
        # Use vietnam time for timestamps
        current_time = now_vietnam()
        logger.info(f"Adding entry with vietnam timestamp: {current_time}")
        
        # Create processed entry.
        # Frontend may send the categorical label as either `category` or
        # `description` (legacy form field) - accept both.
        category_value = (
            entry_data.get("category")
            or entry_data.get("description")
            or "uncategorized"
        )
        processed_entry = {
            "type": entry_type,
            "value": value,
            "category": category_value,
            "priority": entry_data.get("priority", "normal"),
            "added_by": client_ip,
            "added_date": current_time,
            "is_active": is_active
        }

        # Add optional fields if specified
        if entry_data.get("notes"):
            processed_entry["notes"] = entry_data.get("notes")
        
        if entry_data.get("expiry_date"):
            try:
                # Parse expiry date using vietnam parsing
                expiry_vietnam = parse_agent_timestamp(entry_data["expiry_date"])
                processed_entry["expiry_date"] = expiry_vietnam
                
            except Exception as e:
                logger.warning(f"Invalid expiry date format: {e}")
                raise ValueError("Invalid expiry date format")
                
        elif entry_data.get("is_temporary"):
            processed_entry["is_temporary"] = True
            processed_entry["expiry_date"] = current_time + timedelta(hours=24)
        
        if entry_data.get("max_requests_per_hour"):
            try:
                processed_entry["max_requests_per_hour"] = int(entry_data["max_requests_per_hour"])
            except (ValueError, TypeError):
                pass
        
        if entry_type == "domain" and entry_data.get("dns_config"):
            dns_config = entry_data["dns_config"]
            if dns_config.get("verify"):
                dns_result = self.model.verify_dns(value)
                if not dns_result["valid"]:
                    raise ValueError(f"DNS verification failed: {dns_result['message']}")
                processed_entry["dns_info"] = dns_result["info"]
            processed_entry["dns_config"] = dns_config
        
        # Insert entry using model
        try:
            entry_id = self.model.insert_entry(processed_entry)
            logger.info(f"Successfully inserted entry with ID: {entry_id}")
        except Exception as e:
            logger.error(f"Failed to insert entry: {e}")
            raise
        
        # Broadcast notification via SocketIO - vietnam only
        if self.socketio:
            self.socketio.emit("whitelist_added", {
                "type": entry_type,
                "value": value,
                "category": processed_entry["category"],
                "added_by": client_ip,
                "timestamp": now_iso()  # vietnam ISO
            })
        
        return {
            "id": entry_id,
            "message": f"{entry_type.capitalize()} added to whitelist",
            "timestamp": now_iso(),  # vietnam ISO
            "server_time": now_iso()  # vietnam ISO
        }
    
    def test_entry(self, entry_data: Dict) -> Dict:
        """Test an entry before adding it - vietnam ONLY"""
        try:
            entry_type = entry_data.get("type", "domain")
            value = entry_data.get("value", "").strip().lower()
            
            if not value:
                return {"valid": False, "message": "Value is required"}

            entry_type, value = canonicalize_whitelist_entry(entry_type, value)
            
            # Validate entry using model
            validation_result = self.model.validate_entry_value(entry_type, value)
            
            if not validation_result["valid"]:
                return validation_result
            
            # Check for duplicates
            existing = self.model.find_entry_by_value(value)
            if existing:
                return {"valid": False, "message": "Entry already exists"}
            
            # Additional tests based on type
            if entry_type == "domain":
                try:
                    # Test DNS resolution
                    import socket
                    socket.getaddrinfo(value, None, socket.AF_INET)
                    dns_info = f"DNS resolution successful"
                except Exception as e:
                    dns_info = f"DNS resolution failed: {str(e)}"
                
                return {
                    "valid": True,
                    "message": "Entry is valid",
                    "dns_info": dns_info,
                    "server_time": now_iso()  # vietnam ISO
                }
            
            return {
                "valid": True, 
                "message": "Entry is valid",
                "server_time": now_iso()  # vietnam ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error testing entry: {e}")
            return {
                "valid": False, 
                "message": f"Test failed: {str(e)}",
                "server_time": now_iso()  # vietnam ISO
            }
    
    def test_dns(self, domain: str) -> Dict:
        """Test DNS resolution for a domain - vietnam ONLY"""
        try:
            if not domain:
                return {
                    "valid": False, 
                    "message": "Domain is required",
                    "server_time": now_iso()  # vietnam ISO
                }
            
            domain = domain.strip().lower()
            
            # Validate domain format first
            validation_result = self.model.validate_entry_value("domain", domain)
            if not validation_result["valid"]:
                return {
                    **validation_result,
                    "server_time": now_iso()  # vietnam ISO
                }
            
            # Test DNS resolution
            import socket
            try:
                results = socket.getaddrinfo(domain, None, socket.AF_INET)
                ips = []
                for result in results:
                    ip = result[4][0]
                    if ip not in ips:
                        ips.append(ip)
                
                return {
                    "valid": True,
                    "message": f"DNS resolution successful",
                    "domain": domain,
                    "ips": ips,
                    "count": len(ips),
                    "server_time": now_iso()  # vietnam ISO
                }
                
            except Exception as e:
                return {
                    "valid": False,
                    "message": f"DNS resolution failed: {str(e)}",
                    "domain": domain,
                    "server_time": now_iso()  # vietnam ISO
                }
                
        except Exception as e:
            self.logger.error(f"Error testing DNS: {e}")
            return {
                "valid": False, 
                "message": f"DNS test failed: {str(e)}",
                "server_time": now_iso()  # vietnam ISO
            }
    
    def _get_detailed_changes(self, since_dt: datetime) -> Dict:
        """Get detailed changes since specified time - vietnam ONLY"""
        try:
            changes = {
                "added": [],
                "removed": [],
                "modified": [],
                "active_domains": []
            }
            
            # Get ALL currently active domains
            all_active_query = {"is_active": True}
            all_active_entries = self.model.find_raw_entries(all_active_query)
            changes["active_domains"] = [entry.get("value") for entry in all_active_entries]
            
            #  ADD: Debug logging
            self.logger.debug(f"Total active domains in DB: {len(changes['active_domains'])}")
            self.logger.debug(f"Active domains: {changes['active_domains']}")
            
            # Get newly added entries
            added_query = {
                "is_active": True,
                "added_date": {"$gte": since_dt}
            }
            added_entries = self.model.find_raw_entries(added_query)
            
            #  ADD: Debug logging
            self.logger.debug(f"Newly added since {since_dt}: {len(added_entries)}")
            
            for entry in added_entries:
                changes["added"].append({
                    "value": entry.get("value"),
                    "type": entry.get("type", "domain"),
                    "category": entry.get("category", "uncategorized"),
                    "added_date": entry.get("added_date").isoformat() if entry.get("added_date") else None,
                    "added_by": entry.get("added_by", "system")
                })
            
            # For hard deletes, we rely on active_domains comparison in agent
            # For soft deletes (is_active = False)
            deactivated_query = {
                "is_active": False,
                "updated_at": {"$gte": since_dt}
            }
            deactivated_entries = self.model.find_raw_entries(deactivated_query)
            
            #  ADD: Debug logging
            self.logger.debug(f"Deactivated since {since_dt}: {len(deactivated_entries)}")
            
            for entry in deactivated_entries:
                changes["removed"].append({
                    "value": entry.get("value"),
                    "type": entry.get("type", "domain"),
                    "category": entry.get("category", "uncategorized"),
                    "removed_date": entry.get("updated_at").isoformat() if entry.get("updated_at") else None,
                    "reason": "deactivated"
                })
            
            self.logger.info(f"Change details: {len(changes['added'])} added, "
                            f"{len(changes['removed'])} removed, "
                            f"{len(changes['active_domains'])} total active")
            
            return changes
            
        except Exception as e:
            self.logger.error(f"Error getting detailed changes: {e}")
            return {"added": [], "removed": [], "modified": [], "active_domains": []}
    
    def _canonicalize_entries(self, entries: List[Dict]) -> List[Dict]:
        """Canonicalize type/value pairs before returning whitelist payloads."""
        canonical = []
        for entry in entries or []:
            entry_type, value = canonicalize_whitelist_entry(
                entry.get("type", "domain"),
                entry.get("value", ""),
            )
            if not value:
                continue
            canonical.append({**entry, "type": entry_type, "value": value})
        return canonical

    def _normalize_group_entries(self, group, include_inactive: bool = True) -> List[Dict]:
        """Normalize entries from group.whitelist into a list of dicts.

        Args:
            include_inactive: when False, entries with `is_active=False` are
                skipped (used for agent sync). UI listings keep the default
                True so admins can see & re-activate disabled items.
        """
        entries = []
        group_id = str(group.get("_id")) if group else None
        group_name = group.get("name") if group else None

        for entry in group.get("whitelist", []):
            if not entry:
                continue
            if isinstance(entry, dict):
                value = (
                    entry.get("value")
                    or entry.get("domain")
                    or entry.get("ip")
                    or entry.get("url")
                    or entry.get("port")
                    or entry.get("process")
                )
                entry_type = entry.get("type", "domain")
                priority = entry.get("priority", "normal")
                category = entry.get("category", "uncategorized")
                is_active = _coerce_active(entry.get("is_active"), default=True)
                # The migration script
                # ``2026_backfill_group_whitelist_entry_ids.py`` stamps each
                # embedded entry with a real ObjectId. Prefer it when
                # present so the frontend sees a stable identifier across
                # rename/value changes; fall back to the pseudo-ID for
                # entries that pre-date the migration.
                real_oid = entry.get("_id")
            else:
                value = entry
                entry_type = "domain"
                priority = "normal"
                category = "uncategorized"
                is_active = True
                real_oid = None

            if value is None or str(value).strip() == "":
                self.logger.warning("Skipping group whitelist entry without value: %s", entry)
                continue
            value = str(value).strip().lower()
            entry_type, value = canonicalize_whitelist_entry(entry_type, value)
            if not value:
                self.logger.warning("Skipping group whitelist entry after normalization: %s", entry)
                continue

            if not include_inactive and not is_active:
                continue

            # Frontend identifier. Real ObjectId wins; pseudo-ID is the
            # backwards-compat path for un-migrated rows. Format details
            # live in services.whitelist_entry_id.
            if real_oid is not None:
                entry_id = str(real_oid)
            else:
                entry_id = make_group_pseudo_id(group_id, entry_type, value)

            entries.append({
                "_id": entry_id,
                "id": entry_id,
                "value": value,
                "type": entry_type,
                "priority": priority,
                "category": category,
                "is_active": is_active,
                "scope": "group",
                "group_id": group_id,
                "group_name": group_name,
            })
        return entries

    def _normalize_collection_group_entries(self, entries: List[Dict],
                                            group: Dict) -> List[Dict]:
        """Normalize first-class ``whitelist_entries`` rows for UI/sync."""
        group_id = str(group.get("_id")) if group else None
        group_name = group.get("name") if group else None
        normalised = []
        for entry in entries or []:
            entry_id = str(entry.get("_id") or entry.get("id"))
            entry_type, value = canonicalize_whitelist_entry(
                entry.get("type", "domain"),
                entry.get("value", ""),
            )
            if not value:
                continue
            normalised.append({
                "_id": entry_id,
                "id": entry_id,
                "value": value,
                "type": entry_type,
                "priority": entry.get("priority", "normal"),
                "category": entry.get("category", "uncategorized"),
                "is_active": _coerce_active(entry.get("is_active"), default=True),
                "scope": "group",
                "group_id": str(entry.get("group_id") or group_id),
                "group_name": group_name,
                "added_by": entry.get("added_by", "unknown"),
                "added_date": entry.get("added_date"),
                "notes": entry.get("notes"),
                "legacy_embedded_id": entry.get("legacy_embedded_id"),
            })
        return normalised

    def _get_group_entries(self, group: Dict,
                           include_inactive: bool = True) -> List[Dict]:
        """Read group whitelist from collection first, embedded array fallback.

        During the migration window a group can legitimately have both new
        ``whitelist_entries`` rows and legacy ``groups.whitelist[]`` rows.
        Merge both sources so partially migrated groups do not lose old
        embedded entries; collection rows win when they describe the same
        type/value pair.
        """
        if not group:
            return []
        embedded_entries = self._normalize_group_entries(
            group, include_inactive=include_inactive
        )
        group_id = str(group.get("_id"))
        if self.entry_model:
            entries = self.entry_model.list_group_entries(
                group_id, include_inactive=include_inactive
            )
            if entries:
                merged = {}
                for entry in embedded_entries:
                    key = f"{entry.get('type', 'domain')}:{entry.get('value')}"
                    merged[key] = entry
                for entry in self._normalize_collection_group_entries(entries, group):
                    key = f"{entry.get('type', 'domain')}:{entry.get('value')}"
                    merged[key] = entry
                return list(merged.values())
        return embedded_entries

    def _merge_whitelists(self, global_entries: List[Dict], group_entries: List[Dict]) -> List[Dict]:
        """Merge global and group whitelists.
        When the same type:value exists in both scopes, group entry wins
        (more specific scope takes priority) with consistent _id and scope.
        """
        merged = {}
        for entry in global_entries + group_entries:
            key = f"{entry.get('type', 'domain')}:{entry.get('value')}"
            existing = merged.get(key)

            if existing:
                # Group scope is more specific than global, so a group entry
                # wins regardless of the order entries arrive in. A same-scope
                # collision keeps the entry seen later (last-wins).
                incoming_scope = entry.get("scope", "global")
                existing_scope = existing.get("scope", "global")
                incoming_is_group = incoming_scope == "group"
                existing_is_group = existing_scope == "group"

                if existing_is_group and not incoming_is_group:
                    winner, loser = existing, entry
                else:
                    winner, loser = entry, existing

                entry_copy = {**winner}
                # Preserve a "high" priority flag from either side.
                if winner.get("priority") == "high" or loser.get("priority") == "high":
                    entry_copy["priority"] = "high"
                merged[key] = entry_copy
            else:
                merged[key] = {**entry}

        return list(merged.values())

    def get_scoped_whitelist(self, agent_id: Optional[str] = None, group_id: Optional[str] = None) -> Dict:
        """Return global and group whitelist entries with version metadata."""
        try:
            target_group_id = group_id
            agent = None

            if agent_id:
                agent = self.agent_model.find_by_agent_id(agent_id)
                if not agent:
                    raise ValueError("Agent not found")
                target_group_id = target_group_id or agent.get("group_id")

            group = self.group_model.find_by_id(target_group_id) if target_group_id else None
            if not group:
                group = self.group_model.ensure_pending_group()
                target_group_id = str(group.get("_id"))
                if agent and not agent.get("group_id"):
                    self.agent_model.update_agent(agent_id, {"group_id": target_group_id, "status": agent.get("status", "pending")})

            global_entries = self._canonicalize_entries(
                self.model.get_entries_for_sync(scope="global")
            )
            for entry in global_entries:
                entry.setdefault("scope", "global")

            group_entries = self._get_group_entries(group)
            combined = self._merge_whitelists(global_entries, group_entries)

            return {
                "success": True,
                "global": global_entries,
                "group": group_entries,
                "merged": combined,
                "global_version": self.model.get_global_version(),
                "group_version": group.get("whitelist_version", 1),
                "group_id": str(group.get("_id")),
                "group_name": group.get("name"),
                "timestamp": now_iso(),
            }
        except Exception as exc:
            self.logger.error(f"Error getting scoped whitelist: {exc}")
            return {
                "success": False,
                "error": str(exc),
                "global": [],
                "group": [],
                "merged": [],
                "timestamp": now_iso(),
            }

    def get_agent_sync_data(self, since_datetime=None, agent_id: str = None,
                            global_version: Optional[int] = None, group_version: Optional[int] = None,
                            agent_policy_mode: str = "none") -> Dict:
        """Get whitelist data for agent synchronization with group awareness.
        Note: since_datetime is kept for API compatibility but ignored (always full sync)."""
        try:
            if not agent_id:
                raise ValueError("agent_id is required for sync")

            agent = self.agent_model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")

            group_id = agent.get("group_id")
            group = self.group_model.find_by_id(group_id) if group_id else None
            if not group:
                group = self.group_model.ensure_pending_group()
                group_id = str(group.get("_id"))
                if not agent.get("group_id"):
                    self.agent_model.update_agent(agent_id, {"group_id": group_id, "status": agent.get("status", "pending")})

            current_global_version = self.model.get_global_version()
            current_group_version = group.get("whitelist_version", 1)

            # Check if agent has an active policy override BEFORE version short-circuit.
            # Skip the version cache when EITHER condition holds (independently
            # forces a full sync):
            #   - policy is currently active (isolate/custom_whitelist) → agent
            #     needs the policy-modified whitelist
            #   - effective mode differs from the mode the agent last applied
            #     (override was just turned on/off) → agent needs fresh data
            policy_changed = False
            if self.policy_service:
                effective_mode = self.policy_service.policy_model.get_effective_mode(agent_id)
                policy_active = effective_mode != "none"
                policy_mode_changed = effective_mode != agent_policy_mode
                policy_changed = policy_active or policy_mode_changed

            if not policy_changed and global_version == current_global_version and group_version == current_group_version:
                return {
                    "domains": [],
                    "timestamp": now_iso(),
                    "count": 0,
                    "type": "versioned",
                    "success": True,
                    "server_time": now_iso(),
                    "global_version": current_global_version,
                    "group_version": current_group_version,
                    "group_id": str(group.get("_id")),
                    "up_to_date": True,
                }
            global_entries = self._canonicalize_entries(
                self.model.get_entries_for_sync(scope="global")
            )

            # Check for active whitelist profile - overrides group base whitelist
            active_profile = None
            if self.profile_service:
                active_profile = self.profile_service.get_active_profile(str(group.get("_id")))

            if active_profile:
                # Use active profile's domains instead of group base whitelist
                profile_group = dict(group)
                profile_group["whitelist"] = active_profile.get("domains", [])
                group_entries = self._normalize_group_entries(profile_group, include_inactive=False)
            else:
                # Use group.whitelist as base
                group_entries = self._get_group_entries(group, include_inactive=False)

            combined = self._merge_whitelists(global_entries, group_entries)

            # ── Apply per-agent policy override (isolate / custom_whitelist) ──
            policy_mode = "none"
            policy_active = False
            if self.policy_service:
                try:
                    from flask import request as _req
                    server_host = _req.host.split(":")[0] if _req else None
                except Exception:
                    server_host = None

                policy_result = self.policy_service.apply_policy_to_sync(
                    agent_id, combined, server_host=server_host
                )
                combined = policy_result["domains"]
                policy_mode = policy_result["policy_mode"]
                policy_active = policy_result["policy_active"]

            response = {
                "domains": combined,
                "timestamp": now_iso(),
                "count": len(combined),
                "type": "full",
                "success": True,
                "server_time": now_iso(),
                "global_version": current_global_version,
                "group_version": current_group_version,
                "group_id": str(group.get("_id")),
                "agent_id": agent_id,
                "policy_mode": policy_mode,
                "policy_active": policy_active,
            }

            return response
            
        except Exception as e:
            self.logger.error(f"Error in agent sync: {e}")
            return {
                "domains": [],
                "timestamp": now_iso(),
                "count": 0,
                "type": "error",
                "success": False,
                "error": str(e),
                "server_time": now_iso(),
                "changes": {"added": [], "removed": [], "modified": [], "active_domains": []}
            }
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry from global or group scope by id.

        Resolution order:
          1. ``db.whitelist`` collection — global rows AND scope-tagged
             group rows that live in the collection (with real ObjectIds).
          2. Embedded ``groups.whitelist[]`` rows that carry a real
             ``_id`` (post-migration, or new via ``bulk_add_entries``).
             We probe by ObjectId via ``find_group_with_embedded_entry``.
          3. Pseudo-ID path (``group::<gid>::<type>::<value>``) — handled
             by callers BEFORE reaching this method; see
             :meth:`bulk_delete_entries` and the controller. We don't
             accept pseudo-IDs here so the contract stays "real id only".

        Raises ``ValueError("Entry not found")`` if neither lookup hits —
        controllers translate that to a 404.
        """
        # 1) Global collection row.
        entry = self.model.find_entry_by_id(entry_id)
        if entry:
            success = self.model.delete_entry(entry_id)
            if success and self.socketio:
                self.socketio.emit("whitelist_deleted", {
                    "id": entry_id,
                    "value": entry.get("value"),
                    "type": entry.get("type", "domain"),
                    "timestamp": now_iso()
                })
            return success

        # 2) First-class group entry row in whitelist_entries.
        collection_entry = self.entry_model.find_entry_by_id(entry_id) if self.entry_model else None
        if collection_entry:
            success = self.entry_model.delete_entry(entry_id)
            if success:
                group_id = collection_entry.get("group_id")
                if group_id:
                    self.group_model.bump_whitelist_version(str(group_id))
                if self.socketio:
                    self.socketio.emit("whitelist_deleted", {
                        "id": entry_id,
                        "value": collection_entry.get("value"),
                        "type": collection_entry.get("type", "domain"),
                        "scope": "group",
                        "timestamp": now_iso()
                    })
            return success

        # 3) Embedded row by real ObjectId. Only attempt if the id is a
        # valid ObjectId hex string — otherwise it's clearly something
        # else (e.g. a UUID or a malformed string).
        try:
            oid = ObjectId(entry_id)
        except Exception:
            raise ValueError("Entry not found")

        success = self._delete_group_entry_by_oid(oid)
        if success:
            if self.socketio:
                self.socketio.emit("whitelist_deleted", {
                    "id": entry_id,
                    "scope": "group",
                    "timestamp": now_iso(),
                })
            return True

        raise ValueError("Entry not found")

    def bulk_delete_entries(self, item_ids: List[str]) -> Dict:
        """Bulk delete multiple whitelist entries (Global and Group)"""
        deleted_count = 0
        errors = []
        
        # Group deletes by group_id to optimize updates
        group_deletes = {} # group_id -> list of (value, type)
        
        for item_id in item_ids:
            try:
                ref = parse_group_pseudo_id(item_id)
                if ref is not None:
                    _log_legacy_group_pseudo_id_usage(
                        "bulk_delete", ref, item_id
                    )
                    group_deletes.setdefault(ref.group_id, []).append(
                        (ref.value, ref.entry_type)
                    )
                elif is_group_pseudo_id(item_id):
                    # Prefix matched but parse failed → malformed pseudo-ID.
                    errors.append(f"Invalid group item ID: {item_id}")
                else:
                    # Global collection entry, or new-style real ObjectId
                    # for migrated embedded entries.
                    if self.delete_entry(item_id):
                        deleted_count += 1
                    else:
                        errors.append(f"Failed to delete {item_id}")
            except Exception as e:
                errors.append(f"Error processing {item_id}: {str(e)}")
        
        # Process group deletes
        for gid, items in group_deletes.items():
            try:
                group = self.group_model.find_by_id(gid)
                if group:
                    original_len = len(group.get("whitelist", []))
                    # Filter out items to be deleted
                    # items is list of (value, type)
                    new_whitelist = []
                    # Track which requested (value, type) pairs actually matched
                    # so deleted_count reflects requests fulfilled (1 per id),
                    # consistent with the global path, instead of the raw number
                    # of array elements removed (which over-counts duplicates).
                    matched = set()
                    for entry in group.get("whitelist", []):
                        # Normalize entry
                        e_val = entry.get("value") if isinstance(entry, dict) else entry
                        e_type = entry.get("type", "domain") if isinstance(entry, dict) else "domain"

                        # Check if should be deleted
                        should_delete = False
                        for d_val, d_type in items:
                            if d_val == e_val and d_type == e_type:
                                should_delete = True
                                matched.add((d_val, d_type))
                                break

                        if not should_delete:
                            new_whitelist.append(entry)

                    if len(new_whitelist) != original_len:
                        self.group_model.update_group(gid, {
                            "whitelist": new_whitelist,
                            "whitelist_version": group.get("whitelist_version", 1) + 1
                        })
                        deleted_count += len(matched)
            except Exception as e:
                errors.append(f"Error updating group {gid}: {str(e)}")

        return {
            "success": True,
            "deleted_count": deleted_count,
            "error_count": len(errors),
            "errors": errors[:10],
            "server_time": now_iso()
        }
    
    def bulk_add_entries(self, entries_data: List[Dict], client_ip: str) -> Dict:
        """Bulk add entries to whitelist - now with group support"""
        if not entries_data:
            raise ValueError("No entries provided")
        
        if len(entries_data) > 1000:
            raise ValueError("Maximum 1000 entries allowed per bulk operation")
        
        current_time = now_vietnam()
        
        # Split into global and group-specific entries
        global_entries = []
        group_entries_map = {}  # group_id -> [entries]
        errors = []
        
        for i, entry_data in enumerate(entries_data):
            try:
                entry_type = entry_data.get("type", "domain")
                value = entry_data.get("value", "").strip().lower()
                scope = entry_data.get("scope", "global")
                group_id = entry_data.get("group_id")
                
                if not value:
                    errors.append(f"Entry {i+1}: Value is required")
                    continue

                entry_type, value = canonicalize_whitelist_entry(entry_type, value)
                
                validation_result = self.model.validate_entry_value(entry_type, value)
                if not validation_result["valid"]:
                    errors.append(f"Entry {i+1}: {validation_result['message']}")
                    continue
                
                # Check duplicates in current batch (within same scope)
                if scope == "group" and group_id:
                    batch_group = group_entries_map.get(group_id, [])
                    if any(e.get("value") == value for e in batch_group):
                        errors.append(f"Entry {i+1}: Duplicate value in batch (group)")
                        continue
                else:
                    if any(e.get("value") == value for e in global_entries):
                        errors.append(f"Entry {i+1}: Duplicate value in batch (global)")
                        continue
                
                # Process entry. Stamp a real ObjectId so the embedded
                # group whitelist entry has a stable, server-canonical id
                # — frontend can reference it as ``_id`` without falling
                # back to the legacy pseudo-ID format.
                processed_entry = {
                    "_id": ObjectId(),
                    "type": entry_type,
                    "value": value,
                    "category": entry_data.get("category", "uncategorized"),
                    "notes": entry_data.get("notes", "Bulk import"),
                    "priority": entry_data.get("priority", "normal"),
                    "added_by": client_ip,
                    "added_date": current_time,
                    "is_active": _coerce_active(
                        entry_data.get("is_active", entry_data.get("active")),
                        default=True,
                    ),
                }

                if scope == "group" and group_id:
                    if group_id not in group_entries_map:
                        group_entries_map[group_id] = []
                    group_entries_map[group_id].append(processed_entry)
                else:
                    # Check global duplicate
                    existing = self.model.find_entry_by_value(value)
                    if existing:
                        errors.append(f"Entry {i+1}: Global entry already exists")
                        continue
                    global_entries.append(processed_entry)
                
            except Exception as e:
                errors.append(f"Entry {i+1}: {str(e)}")
        
        # Insert Global Entries
        inserted_ids = []
        if global_entries:
            inserted_ids = self.model.bulk_insert_entries(global_entries)
        
        # Update Group Entries
        group_success_count = 0
        for grp_id, entries in group_entries_map.items():
            try:
                group = self.group_model.find_by_id(grp_id)
                if not group:
                    errors.append(f"Group {grp_id} not found for bulk import")
                    continue

                current_whitelist = group.get("whitelist", [])
                existing_collection_entries = (
                    self.entry_model.list_group_entries(grp_id)
                    if self.entry_model else []
                )

                # Filter out duplicates
                new_unique = []
                for ne in entries:
                    def _matches_current(curr):
                        curr_value = curr.get("value") if isinstance(curr, dict) else str(curr)
                        curr_type = curr.get("type", "domain") if isinstance(curr, dict) else "domain"
                        return curr_value == ne["value"] and curr_type == ne["type"]

                    collection_duplicate = any(
                        e.get("value") == ne["value"] and e.get("type", "domain") == ne["type"]
                        for e in existing_collection_entries
                    )
                    embedded_duplicate = any(_matches_current(curr) for curr in current_whitelist)

                    if not collection_duplicate and not embedded_duplicate:
                        new_unique.append(ne)
                    else:
                        errors.append(f"Entry {ne['value']} already exists in group {group.get('name')}")

                if new_unique:
                    if self.entry_model:
                        collection_rows = []
                        for entry in new_unique:
                            row = {**entry}
                            row["scope"] = "group"
                            row["group_id"] = str(grp_id)
                            collection_rows.append(row)
                        inserted_group_ids = self.entry_model.bulk_insert_entries(collection_rows)
                        if inserted_group_ids:
                            self.group_model.bump_whitelist_version(str(grp_id))
                            group_success_count += len(inserted_group_ids)
                    else:
                        updated_whitelist = current_whitelist + new_unique
                        self.group_model.update_group(grp_id, {
                            "whitelist": updated_whitelist,
                            "whitelist_version": (group.get("whitelist_version", 1) + 1)
                        })
                        group_success_count += len(new_unique)
                    
            except Exception as e:
                errors.append(f"Failed to update group {grp_id}: {str(e)}")

        total_inserted = len(inserted_ids) + group_success_count
        
        # Notify
        if total_inserted > 0 and self.socketio:
            self.socketio.emit("whitelist_bulk_added", {
                "count": total_inserted,
                "added_by": client_ip,
                "timestamp": now_iso()
            })
        
        return {
            "inserted_count": total_inserted,
            "error_count": len(errors),
            "errors": errors[:10],
            "success": total_inserted > 0,
            "server_time": now_iso()
        }
    
    def get_statistics(self) -> Dict:
        """Get whitelist statistics - vietnam ONLY"""
        try:
            stats = self.model.get_statistics()
            stats["server_time"] = now_iso()  # vietnam ISO
            return stats
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {
                "total": 0,
                "active": 0,
                "inactive": 0,
                "by_type": {},
                "error": str(e),
                "server_time": now_iso()  # vietnam ISO
            }
    
    def update_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update an entry — supports global ObjectIds AND group pseudo-IDs.

        Pseudo-ID format is owned by ``services.whitelist_entry_id``; keep
        the prefix check there so a future "drop pseudo-IDs entirely"
        migration is a one-line change.
        """
        if is_group_pseudo_id(entry_id):
            return self._update_group_entry(entry_id, update_data)

        collection_entry = self.entry_model.find_entry_by_id(entry_id) if self.entry_model else None
        if collection_entry:
            if 'value' in update_data:
                value = update_data['value'].strip().lower()
                entry_type = update_data.get('type', collection_entry.get('type', 'domain'))
                entry_type, value = canonicalize_whitelist_entry(entry_type, value)
                validation_result = self.model.validate_entry_value(entry_type, value)
                if not validation_result["valid"]:
                    raise ValueError(validation_result["message"])
                update_data['value'] = value
                update_data['type'] = entry_type

            success = self.entry_model.update_entry(entry_id, update_data)
            if success:
                group_id = collection_entry.get("group_id")
                if group_id:
                    self.group_model.bump_whitelist_version(str(group_id))
                if self.socketio:
                    self.socketio.emit("whitelist_updated", {
                        "id": entry_id,
                        "value": update_data.get('value', collection_entry.get('value')),
                        "type": update_data.get('type', collection_entry.get('type', 'domain')),
                        "scope": "group",
                        "timestamp": now_iso()
                    })
            return success

        entry = self.model.find_entry_by_id(entry_id)
        if not entry:
            raise ValueError("Entry not found")

        # Validate update data
        if 'value' in update_data:
            value = update_data['value'].strip().lower()
            entry_type = update_data.get('type', entry.get('type', 'domain'))
            entry_type, value = canonicalize_whitelist_entry(entry_type, value)

            validation_result = self.model.validate_entry_value(entry_type, value)
            if not validation_result["valid"]:
                raise ValueError(validation_result["message"])

            update_data['value'] = value
            update_data['type'] = entry_type

        # Update timestamp
        update_data['updated_at'] = now_vietnam()

        success = self.model.update_entry(entry_id, update_data)

        if success and self.socketio:
            self.socketio.emit("whitelist_updated", {
                "id": entry_id,
                "value": update_data.get('value', entry.get('value')),
                "type": update_data.get('type', entry.get('type', 'domain')),
                "timestamp": now_iso()
            })

        return success

    def _update_group_entry(self, entry_id: str, update_data: Dict) -> bool:
        """Update a group whitelist entry by pseudo-ID OR real ObjectId.

        Two identifier shapes are accepted because we're in the middle of
        migrating embedded entries from pseudo-IDs (synthesised on every
        list) to real ObjectIds (stamped at insert time):

          - Pseudo-ID ``group::<gid>::<type>::<value>`` — legacy rows that
            haven't been touched by the backfill script, or callers built
            against the old contract. Resolved via ``parse_group_pseudo_id``.
          - Real ObjectId hex string — new rows that went through
            ``bulk_add_entries`` (which stamps ``_id``) or that were touched
            by the backfill migration. We scan every group's embedded
            whitelist for a matching ``_id``.

        Returns True if exactly one matching entry was updated. Legacy
        string entries (bare-value strings, predate the dict schema) are
        upgraded to dict so the update can persist.
        """
        ref = parse_group_pseudo_id(entry_id)
        if ref is not None:
            _log_legacy_group_pseudo_id_usage("update", ref, entry_id)
            return self._update_group_entry_by_match(
                ref.group_id, value=ref.value, entry_type=ref.entry_type,
                update_data=update_data,
            )
        if is_group_pseudo_id(entry_id):
            raise ValueError(f"Invalid group entry ID: {entry_id}")

        # Real ObjectId path. We don't know which group the entry lives in,
        # so we scan groups that have a non-empty whitelist. This is O(N
        # groups) but acceptable: edit traffic is admin-only and rare.
        try:
            oid = ObjectId(entry_id)
        except Exception:
            raise ValueError(f"Invalid entry id: {entry_id}")
        return self._update_group_entry_by_oid(oid, update_data)

    def _update_group_entry_by_match(self, gid: str, *, value: str,
                                     entry_type: str, update_data: Dict) -> bool:
        group = self.group_model.find_by_id(gid)
        if not group:
            raise ValueError(f"Group {gid} not found")

        whitelist = group.get("whitelist", [])
        updated = False
        for i, entry in enumerate(whitelist):
            e_val = entry.get("value") if isinstance(entry, dict) else entry
            e_type = entry.get("type", "domain") if isinstance(entry, dict) else "domain"
            if e_val == value and e_type == entry_type:
                if not isinstance(entry, dict):
                    entry = {
                        "value": e_val, "type": e_type,
                        "category": "uncategorized", "priority": "normal",
                        "is_active": True,
                    }
                    whitelist[i] = entry
                if "value" in update_data:
                    new_type, new_value = canonicalize_whitelist_entry(
                        update_data.get("type", e_type),
                        update_data["value"],
                    )
                    validation_result = self.model.validate_entry_value(new_type, new_value)
                    if not validation_result["valid"]:
                        raise ValueError(validation_result["message"])
                    update_data = {**update_data, "type": new_type, "value": new_value}
                _apply_entry_update(entry, update_data)
                updated = True
                break

        if updated:
            self.group_model.update_group(gid, {"whitelist": whitelist})
        return updated

    def _update_group_entry_by_oid(self, oid: ObjectId, update_data: Dict) -> bool:
        # We use the group_model's repo method to find the group that owns
        # this embedded entry. ``find_group_with_embedded_entry`` is a thin
        # query that filters on ``whitelist._id`` — the dotted-path Mongo
        # query mongodb supports natively for arrays of subdocuments.
        group = self.group_model.find_group_with_embedded_entry(oid)
        if not group:
            return False
        whitelist = group.get("whitelist", [])
        for entry in whitelist:
            if isinstance(entry, dict) and entry.get("_id") == oid:
                if "value" in update_data:
                    new_type, new_value = canonicalize_whitelist_entry(
                        update_data.get("type", entry.get("type", "domain")),
                        update_data["value"],
                    )
                    validation_result = self.model.validate_entry_value(new_type, new_value)
                    if not validation_result["valid"]:
                        raise ValueError(validation_result["message"])
                    update_data = {**update_data, "type": new_type, "value": new_value}
                _apply_entry_update(entry, update_data)
                self.group_model.update_group(str(group["_id"]),
                                              {"whitelist": whitelist})
                return True
        return False

    def _delete_group_entry(self, group_id: str, value: str, entry_type: str = "domain") -> bool:
        """Delete an entry from a group's whitelist by (value, type).

        Used by the pseudo-ID delete path. Real-ObjectId deletes go through
        :meth:`_delete_group_entry_by_oid` instead.
        """
        group = self.group_model.find_by_id(group_id)
        if not group:
            return False

        whitelist = group.get("whitelist", [])
        original_len = len(whitelist)
        whitelist = [
            e for e in whitelist
            if not (
                (e.get("value") if isinstance(e, dict) else e) == value
                and (e.get("type", "domain") if isinstance(e, dict) else "domain") == entry_type
            )
        ]

        if len(whitelist) < original_len:
            self.group_model.update_group(group_id, {"whitelist": whitelist})
            return True
        return False

    def _delete_group_entry_by_oid(self, oid: ObjectId) -> bool:
        """Delete an embedded whitelist entry by its real ObjectId.

        Companion to :meth:`_delete_group_entry`; called when the caller
        passes a real ``_id`` (from the new canonical id contract) rather
        than the legacy pseudo-ID. Returns True on success, False if no
        group owns that id (treated as 404 by the controller).
        """
        group = self.group_model.find_group_with_embedded_entry(oid)
        if not group:
            return False
        whitelist = group.get("whitelist", [])
        original_len = len(whitelist)
        whitelist = [e for e in whitelist
                     if not (isinstance(e, dict) and e.get("_id") == oid)]
        if len(whitelist) < original_len:
            self.group_model.update_group(str(group["_id"]),
                                          {"whitelist": whitelist})
            return True
        return False

    # sync_for_agent removed - dead code, replaced by get_agent_sync_data()

    def add_domain(self, domain_value: str, category: str = "general") -> Dict:
        """Add new domain to whitelist — vietnam ONLY.

        Deprecated: prefer :meth:`add_entry` which handles scope/group_id and
        all entry types (domain, ip, ip_range) through one path.
        """
        _warn_legacy_domain_api("add_domain")
        try:
            # Check if domain already exists
            existing = self.model.find_entry_by_value(domain_value)
            if existing:
                return {
                    "success": False,
                    "error": "Domain already exists in whitelist",
                    "existing_entry": existing,
                    "server_time": now_iso()  # vietnam ISO
                }
            
            # Validate domain
            validation = self.model.validate_entry_value("domain", domain_value)
            if not validation.get("valid"):
                return {
                    "success": False,
                    "error": validation.get("message", "Invalid domain"),
                    "server_time": now_iso()  # vietnam ISO
                }
            
            # Create entry data
            entry_data = {
                "value": domain_value.strip().lower(),
                "type": "domain",
                "category": category,
                "is_active": True,
                "priority": "normal",
                "added_by": "admin"
            }
            
            # Insert domain
            entry_id = self.model.insert_entry(entry_data)
            
            return {
                "success": True,
                "entry_id": entry_id,
                "domain": domain_value,
                "category": category,
                "server_time": now_iso()  # vietnam ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error adding domain {domain_value}: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # vietnam ISO
            }
    
    def import_domains(self, domains: List[str], category: str = "imported") -> Dict:
        """Import multiple domains — vietnam ONLY.

        Deprecated: prefer :meth:`bulk_add_entries`, which accepts the unified
        entry shape (type, value, scope, group_id) and reports per-row errors.
        """
        _warn_legacy_domain_api("import_domains")
        try:
            added_count = 0
            duplicate_count = 0
            error_count = 0
            errors = []
            
            for domain in domains:
                try:
                    domain = domain.strip().lower()
                    if not domain:
                        continue
                    
                    # Check if already exists
                    if self.model.find_entry_by_value(domain):
                        duplicate_count += 1
                        continue
                    
                    # Validate domain
                    validation = self.model.validate_entry_value("domain", domain)
                    if not validation.get("valid"):
                        error_count += 1
                        errors.append(f"{domain}: {validation.get('message')}")
                        continue
                    
                    # Create entry
                    entry_data = {
                        "value": domain,
                        "type": "domain",
                        "category": category,
                        "is_active": True,
                        "priority": "normal",
                        "added_by": "import"
                    }
                    
                    self.model.insert_entry(entry_data)
                    added_count += 1
                    
                except Exception as e:
                    error_count += 1
                    errors.append(f"{domain}: {str(e)}")
            
            return {
                "success": True,
                "added_count": added_count,
                "duplicate_count": duplicate_count,
                "error_count": error_count,
                "errors": errors[:10],  # Limit error list
                "total_processed": len(domains),
                "server_time": now_iso()  # vietnam ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error importing domains: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # vietnam ISO
            }
    
    def export_domains(self, format: str = "json", category: str = None) -> Dict:
        """Export domains in specified format — vietnam ONLY.

        Deprecated: prefer :meth:`export_entries` (returns unified entry rows
        including scope/group_id, suitable for re-import via the entry API).
        """
        _warn_legacy_domain_api("export_domains")
        try:
            # Build query
            query = {}
            if category:
                query["category"] = category
            
            # Get domains
            domains = self.model.find_all_entries(query)
            
            if format == "txt":
                # Text format - one domain per line
                domain_list = [domain["value"] for domain in domains]
                text_data = "\n".join(domain_list)
                
                return {
                    "success": True,
                    "data": text_data,
                    "count": len(domain_list),
                    "format": format,
                    "server_time": now_iso()  # vietnam ISO
                }
            else:
                # JSON format
                return {
                    "success": True,
                    "data": domains,
                    "count": len(domains),
                    "format": format,
                    "server_time": now_iso()  # vietnam ISO
                }
                
        except Exception as e:
            self.logger.error(f"Error exporting domains: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  #  ISO
            }
