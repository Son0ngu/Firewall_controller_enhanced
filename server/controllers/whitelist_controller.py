"""
Whitelist Controller - handles whitelist HTTP requests
RBAC: inject_current_user on web-facing endpoints for teacher data filtering.
- Agent endpoint (agent-sync) keeps require_jwt - NOT affected
- Web-facing endpoints apply teacher ownership filter on group-level whitelist
"""

import logging
from flask import Blueprint, request, jsonify, g
from typing import Dict, Tuple
from models.whitelist_model import WhitelistModel
from services.whitelist_service import WhitelistService
from services.rbac_service import RBACService
from utils.request_ip import get_client_ip

# Import time utilities - vietnam ONLY
from time_utils import now_iso, parse_agent_timestamp

# Import auth middleware for JWT validation
from middleware.auth import require_jwt, require_jwt_or_api_key
from middleware.rbac import inject_current_user, require_login

class WhitelistController:
    """Controller for whitelist operations"""

    def __init__(self, whitelist_model: WhitelistModel, whitelist_service: WhitelistService,
                 rbac_service: RBACService, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = whitelist_model
        self.service = whitelist_service
        self.rbac_service = rbac_service
        self.socketio = socketio
        self.blueprint = Blueprint('whitelist', __name__)
        self._register_routes()

    def _register_routes(self):
        """Register all whitelist routes"""

        # Agent sync endpoint - requires JWT token (NOT affected by RBAC)
        self.blueprint.add_url_rule('/whitelist/agent-sync',
                                   methods=['GET'],
                                   view_func=require_jwt(self.agent_sync))

        # Web-facing endpoints - require login first, then inject_current_user
        # for teacher-scope filtering inside each handler.
        self.blueprint.add_url_rule('/whitelist',
                                   methods=['GET'],
                                   view_func=require_login(inject_current_user(self.list_domains)))

        self.blueprint.add_url_rule('/whitelist',
                                   methods=['POST'],
                                   view_func=require_login(inject_current_user(self.add_domain)))

        self.blueprint.add_url_rule('/whitelist/<domain_id>',
                                   methods=['DELETE'],
                                   view_func=require_login(inject_current_user(self.delete_domain)))

        self.blueprint.add_url_rule('/whitelist/import',
                                   methods=['POST'],
                                   view_func=require_login(inject_current_user(self.import_domains)))

        self.blueprint.add_url_rule('/whitelist/export',
                                   methods=['GET'],
                                   view_func=require_login(inject_current_user(self.export_domains)))

        self.blueprint.add_url_rule('/whitelist/statistics',
                                   methods=['GET'],
                                   view_func=require_login(inject_current_user(self.get_statistics)))

        # Bulk operations
        self.blueprint.add_url_rule('/whitelist/bulk',
                                   methods=['POST'],
                                   view_func=require_login(inject_current_user(self.bulk_add_entries)))

        self.blueprint.add_url_rule('/whitelist/bulk-update',
                                   methods=['POST'],
                                   view_func=require_login(inject_current_user(self.bulk_update_entries)))

        self.blueprint.add_url_rule('/whitelist/bulk-delete',
                                   methods=['POST'],
                                   view_func=require_login(inject_current_user(self.bulk_delete_entries)))

    # ========================================================================
    # RBAC HELPERS
    # ========================================================================

    def _is_teacher(self):
        """Thin wrapper — calls ``RBACService.is_teacher_request`` statically.

        Static so a mocked ``rbac_service`` in tests doesn't swallow the call
        and return a MagicMock instead of the expected ``(bool, user)`` tuple.
        """
        return RBACService.is_teacher_request(getattr(g, 'current_user', None))

    def _teacher_can_access_group(self, user, group_id):
        """Check if teacher owns this group_id.

        Mirrors ``RBACService.assert_group_access`` but consults
        ``get_teacher_group_ids`` directly so existing tests that mock that
        return value keep working. New code should prefer
        ``self.rbac_service.assert_group_access(user, group_id)`` — both
        paths apply the same rule (group_id ∈ teacher's assigned groups);
        the service method is just the canonical entry point.
        """
        if not group_id:
            return False
        teacher_group_ids = self.rbac_service.get_teacher_group_ids(user)
        if teacher_group_ids is None:
            return True  # admin
        return str(group_id) in teacher_group_ids

    # ========================================================================
    # AGENT SYNC (NOT affected by RBAC)
    # ========================================================================

    def agent_sync(self):
        """Sync whitelist for agents - vietnam ONLY"""
        try:
            since = request.args.get('since')
            agent_id = request.args.get('agent_id')
            global_version = request.args.get('global_version')
            group_version = request.args.get('group_version')
            agent_policy_mode = request.args.get('policy_mode', 'none')

            self.logger.debug(f"Agent sync request - since: {since}, agent_id: {agent_id}")

            since_datetime = None
            if since:
                try:
                    since_datetime = parse_agent_timestamp(since)
                except Exception as e:
                    self.logger.warning(f"Invalid since parameter: {since}, error: {e}")

            result = self.service.get_agent_sync_data(
                since_datetime, agent_id,
                int(global_version) if global_version else None,
                int(group_version) if group_version else None,
                agent_policy_mode=agent_policy_mode,
            )

            if not isinstance(result, dict):
                result = {"domains": [], "error": "Invalid response format", "success": False}
            if "domains" not in result:
                result["domains"] = []

            # Preserve service's success field - don't override errors
            if "success" not in result:
                result["success"] = True
            result["agent_id"] = agent_id
            result["timestamp"] = now_iso()
            result["count"] = len(result.get("domains", []))

            status_code = 200 if result["success"] else 502
            return jsonify(result), status_code

        except Exception as e:
            self.logger.error(f"Error in agent sync: {str(e)}", exc_info=True)
            return jsonify({
                "success": False, "error": "Sync failed: " + str(e),
                "domains": [], "timestamp": now_iso(), "count": 0, "type": "error"
            }), 500

    # ========================================================================
    # WEB-FACING ENDPOINTS (with teacher data filtering)
    # ========================================================================

    def list_domains(self):
        """List whitelist entries through the unified entry API."""
        try:
            agent_id = request.args.get('agent_id')
            group_id = request.args.get('group_id')
            effective = str(request.args.get('effective', '')).lower() in {'1', 'true', 'yes'}

            is_teacher, user = self._is_teacher()

            if agent_id or effective:
                # RBAC: Teacher can only view whitelist of their own groups
                if is_teacher and group_id:
                    if not self._teacher_can_access_group(user, group_id):
                        return self._error_response("No permission to view whitelist for this Group", 403)

                scoped = self.service.get_scoped_whitelist(agent_id=agent_id, group_id=group_id)
                status_code = 200 if scoped.get("success") else 400
                return jsonify(scoped), status_code

            # Get pagination parameters
            limit = min(int(request.args.get('limit', 100)), 1000)
            offset = int(request.args.get('offset', 0))
            filters = {}
            for key in ('search', 'type', 'status', 'scope', 'group_id'):
                value = request.args.get(key, '').strip()
                if value:
                    filters[key] = value

            if is_teacher and group_id:
                if not self._teacher_can_access_group(user, group_id):
                    return self._error_response("No permission to view whitelist for this Group", 403)

            # RBAC: Teacher - fetch ALL then filter + paginate in Python
            # (post-filter approach; for large datasets, push filter into model)
            if is_teacher:
                teacher_group_ids = self.rbac_service.get_teacher_group_ids(user)
                if teacher_group_ids is not None:
                    # Fetch all entries (no pagination at DB level) before
                    # teacher-scope filtering.
                    all_result = self.service.get_all_entries(filters)
                    all_domains = (
                        all_result.get("items")
                        or all_result.get("domains", [])
                    ) if isinstance(all_result, dict) else []

                    # Filter: teacher sees global + their groups
                    filtered = []
                    for d in all_domains:
                        d_scope = d.get("scope", "global")
                        d_group = str(d.get("group_id", "")) if d.get("group_id") else None
                        if d_scope == "global" or (d_group and d_group in teacher_group_ids):
                            filtered.append(d)

                    # Apply pagination on filtered result
                    total = len(filtered)
                    paginated = filtered[offset:offset + limit]
                    result = {
                        "success": True,
                        "items": paginated,
                        "domains": paginated,
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "timestamp": now_iso(),
                    }
                    return jsonify(result), 200

            # Admin: unified entry list with legacy-compatible `domains`.
            result = self.service.get_all_entries(filters, limit=limit, offset=offset)

            if isinstance(result, dict):
                result["timestamp"] = now_iso()

            return jsonify(result), 200

        except Exception as e:
            self.logger.error(f"Error listing domains: {e}")
            return self._error_response("Failed to list domains", 500)

    def add_domain(self):
        """Add new entry to whitelist"""
        try:
            if not request.is_json:
                return self._error_response("Request must be JSON", 400)

            data = request.get_json() or {}
            entry_value = data.get('value', '').strip().lower()
            if not entry_value:
                return self._error_response("Value is required", 400)

            entry_type = data.get('type', 'domain')
            client_ip = get_client_ip()

            # RBAC: Teachers use Whitelist Profiles; group whitelist writes are admin-only.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return self._error_response(
                    "Teachers cannot modify group whitelist. Use Whitelist Profiles.",
                    403,
                )

            result = self.service.add_entry({**data, "type": entry_type, "value": entry_value}, client_ip)

            response_body = {"success": True, "timestamp": now_iso(), **result}

            if self.socketio and result.get('success'):
                self.socketio.emit('whitelist_updated', {
                    'action': 'added', 'type': entry_type, 'value': entry_value,
                    'category': data.get('category') or data.get('description') or 'uncategorized',
                    'timestamp': now_iso()
                })

            return jsonify(response_body), 201

        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error adding entry: {e}")
            return self._error_response("Failed to add domain", 500)

    def delete_domain(self, domain_id: str):
        """Delete domain from whitelist - vietnam ONLY"""
        try:
            self.logger.info(f"Attempting to delete domain: {domain_id}")

            if not domain_id or len(domain_id) < 10:
                return jsonify({
                    "success": False, "error": "Invalid domain ID format", "timestamp": now_iso()
                }), 400

            # RBAC: Teachers use Whitelist Profiles; group whitelist writes are admin-only.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return self._error_response(
                    "Teachers cannot modify group whitelist. Use Whitelist Profiles.",
                    403,
                )

            result = self.service.bulk_delete_entries([domain_id])
            deleted_count = int(result.get("deleted_count", 0) or 0)
            if deleted_count > 0:
                result = {
                    **result,
                    "success": True,
                    "entry_id": domain_id,
                    "message": "Item removed successfully",
                }
            else:
                errors = result.get("errors") or []
                result = {
                    **result,
                    "success": False,
                    "error": errors[0] if errors else "Entry not found",
                    "entry_id": domain_id,
                }

            if self.socketio and result.get('success'):
                self.socketio.emit('whitelist_updated', {
                    'action': 'deleted', 'domain_id': domain_id, 'timestamp': now_iso()
                })

            if isinstance(result, dict):
                result["timestamp"] = now_iso()

            status_code = 200 if result.get('success') else 404
            return jsonify(result), status_code

        except Exception as e:
            self.logger.error(f"Error deleting domain {domain_id}: {e}")
            return jsonify({
                "success": False, "error": f"Failed to delete domain: {str(e)}",
                "timestamp": now_iso()
            }), 500

    def import_domains(self):
        """Import multiple domains - vietnam ONLY"""
        try:
            if not request.is_json:
                return self._error_response("Request must be JSON", 400)

            data = request.get_json()
            if not data or 'domains' not in data:
                return self._error_response("Domains list is required", 400)

            domains = data['domains']
            if not isinstance(domains, list):
                return self._error_response("Domains must be a list", 400)

            # RBAC: Teachers use Whitelist Profiles; group whitelist writes are admin-only.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return self._error_response(
                    "Teachers cannot modify group whitelist. Use Whitelist Profiles.",
                    403,
                )

            result = self.service.import_domains(domains, data.get('category', 'imported'))

            if self.socketio and result.get('success'):
                self.socketio.emit('whitelist_updated', {
                    'action': 'imported', 'count': result.get('added_count', 0),
                    'category': data.get('category', 'imported'), 'timestamp': now_iso()
                })

            if isinstance(result, dict):
                result["timestamp"] = now_iso()

            return jsonify(result), 200

        except Exception as e:
            self.logger.error(f"Error importing domains: {e}")
            return self._error_response("Failed to import domains", 500)

    def export_domains(self):
        """Export whitelist domains - vietnam ONLY"""
        try:
            # RBAC: Teacher does NOT have logs:export (but whitelist:read is enough for viewing)
            # Teacher can export their own group whitelist
            format = request.args.get('format', 'json')
            category = request.args.get('category')

            result = self.service.export_domains(format, category)

            if result.get('success'):
                if isinstance(result, dict):
                    result["timestamp"] = now_iso()

                if format == 'txt':
                    from flask import Response
                    return Response(
                        result['data'], mimetype='text/plain',
                        headers={'Content-Disposition': 'attachment; filename=whitelist.txt'}
                    )
                else:
                    return jsonify(result), 200
            else:
                return self._error_response(result.get('error', 'Export failed'), 500)

        except Exception as e:
            self.logger.error(f"Error exporting domains: {e}")
            return self._error_response("Failed to export domains", 500)

    def get_statistics(self):
        """Get whitelist statistics - vietnam ONLY"""
        try:
            stats = self.service.get_statistics()
            return jsonify({
                'success': True, 'statistics': stats, 'timestamp': now_iso()
            }), 200
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return self._error_response("Failed to get statistics", 500)

    # ========================================================================
    # BULK OPERATIONS
    # ========================================================================

    def bulk_add_entries(self):
        """Bulk add multiple whitelist entries"""
        try:
            data = request.get_json()
            if not data or 'items' not in data:
                return jsonify({"success": False, "error": "No items provided"}), 400

            items = data['items']
            if not isinstance(items, list):
                return jsonify({"success": False, "error": "Items must be an array"}), 400
            if len(items) == 0:
                return jsonify({"success": False, "error": "No items to import"}), 400
            if len(items) > 1000:
                return jsonify({"success": False, "error": "Maximum 1000 items per bulk operation"}), 400

            # RBAC: Teachers use Whitelist Profiles; group whitelist writes are admin-only.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return self._error_response(
                    "Teachers cannot modify group whitelist. Use Whitelist Profiles.",
                    403,
                )

            client_ip = get_client_ip()

            result = self.service.bulk_add_entries(items, client_ip)
            return jsonify(result), 200 if result['success'] else 400

        except Exception as e:
            self.logger.error(f"Error in bulk add: {e}")
            return jsonify({"success": False, "error": str(e), "server_time": now_iso()}), 500

    def bulk_update_entries(self):
        """Bulk update multiple whitelist entries"""
        try:
            data = request.get_json()
            if not data or 'item_ids' not in data:
                return jsonify({"success": False, "error": "No item IDs provided"}), 400

            item_ids = data['item_ids']
            active = data.get('is_active', data.get('active', True))

            if not isinstance(item_ids, list):
                return jsonify({"success": False, "error": "Item IDs must be an array"}), 400

            # RBAC: Teachers use Whitelist Profiles; group whitelist writes are admin-only.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return self._error_response(
                    "Teachers cannot modify group whitelist. Use Whitelist Profiles.",
                    403,
                )

            updated_count = 0
            errors = []
            for item_id in item_ids:
                try:
                    success = self.service.update_entry(item_id, {"is_active": active})
                    if success:
                        updated_count += 1
                    else:
                        errors.append(f"Failed to update {item_id}")
                except Exception as e:
                    errors.append(f"Error updating {item_id}: {str(e)}")

            return jsonify({
                "success": True, "updated_count": updated_count,
                "error_count": len(errors), "errors": errors[:10],
                "server_time": now_iso()
            }), 200

        except Exception as e:
            self.logger.error(f"Error in bulk update: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    def bulk_delete_entries(self):
        """Bulk delete multiple whitelist entries"""
        try:
            data = request.get_json()
            if not data or 'item_ids' not in data:
                return jsonify({"success": False, "error": "No item IDs provided"}), 400

            item_ids = data['item_ids']
            if not isinstance(item_ids, list):
                return jsonify({"success": False, "error": "Item IDs must be an array"}), 400

            # RBAC: Teachers use Whitelist Profiles; group whitelist writes are admin-only.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return self._error_response(
                    "Teachers cannot modify group whitelist. Use Whitelist Profiles.",
                    403,
                )

            result = self.service.bulk_delete_entries(item_ids)
            return jsonify(result), 200

        except Exception as e:
            self.logger.error(f"Error in bulk delete: {e}")
            return jsonify({"success": False, "error": str(e)}), 500

    # ========================================================================
    # HELPER
    # ========================================================================

    def _error_response(self, message: str, status_code: int) -> Tuple:
        """Create error response - vietnam ONLY"""
        return jsonify({
            "success": False, "error": message, "timestamp": now_iso()
        }), status_code
