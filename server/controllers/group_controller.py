"""
Group Controller - handles group HTTP requests.
RBAC: require_login on web-facing endpoints for teacher data filtering.
- Admin request: no filter (toan quyen)
- Teacher request: filter by teacher_ids (assigned groups)
"""

import logging
from flask import Blueprint, request, jsonify, g

from services.group_service import GroupService
from services.rbac_service import RBACService
from middleware.rbac import require_admin, require_login


class GroupController:
    def __init__(self, group_service: GroupService, rbac_service: RBACService):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.service = group_service
        self.rbac_service = rbac_service
        self.blueprint = Blueprint('groups', __name__)
        self._register_routes()

    def _register_routes(self):
        # All web-facing routes require an authenticated admin/teacher session.
        self.blueprint.add_url_rule('/groups', 'list_groups',
            require_login(self.list_groups), methods=['GET'])
        self.blueprint.add_url_rule('/groups', 'create_group',
            require_login(require_admin(self.create_group)), methods=['POST'])
        self.blueprint.add_url_rule('/groups/<group_id>', 'get_group',
            require_login(self.get_group), methods=['GET'])
        self.blueprint.add_url_rule('/groups/<group_id>', 'update_group',
            require_login(require_admin(self.update_group)), methods=['PATCH'])
        self.blueprint.add_url_rule('/groups/<group_id>', 'delete_group',
            require_login(require_admin(self.delete_group)), methods=['DELETE'])
        # Admin-only: assign teachers to group
        self.blueprint.add_url_rule('/groups/<group_id>/teachers', 'set_teachers',
            require_login(require_admin(self.set_teachers)), methods=['POST'])

    def _is_teacher(self):
        """Thin wrapper around ``RBACService.is_teacher_request`` for backwards-compat.

        Calls the **static** method on the class — not via ``self.rbac_service``
        — so tests that pass a MagicMock for the service still get the real
        rule check (the role string compare is stateless anyway).
        """
        return RBACService.is_teacher_request(getattr(g, 'current_user', None))

    def list_groups(self):
        try:
            is_teacher, user = self._is_teacher()
            query_filter = None
            if is_teacher:
                query_filter = self.rbac_service.get_group_query_filter(user)

            groups = self.service.list_groups(query_filter=query_filter)
            return jsonify({"success": True, "data": groups}), 200
        except Exception as exc:
            self.logger.error(f"Failed to list groups: {exc}")
            return jsonify({"success": False, "error": str(exc)}), 500

    def get_group(self, group_id: str):
        """Get single group details"""
        try:
            group = self.service.get_group(group_id)

            # Teacher ownership check
            is_teacher, user = self._is_teacher()
            if is_teacher and not self.rbac_service.can_access_group(user, group):
                return jsonify({"success": False, "error": "No permission for this Group"}), 403

            return jsonify({"success": True, "data": group}), 200
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 404
        except Exception as exc:
            self.logger.error(f"Failed to get group {group_id}: {exc}")
            return jsonify({"success": False, "error": str(exc)}), 500

    def create_group(self):
        try:
            data = request.get_json() or {}
            name = data.get("name")
            if not name:
                return jsonify({"success": False, "error": "Name is required"}), 400
            description = data.get("description", "")
            whitelist = data.get("whitelist", [])

            # Set created_by if request is from admin/teacher web UI
            created_by = None
            user = getattr(g, 'current_user', None)
            if user:
                created_by = user.get("_id")

            group = self.service.create_group(name, description, whitelist, created_by=created_by)
            return jsonify({"success": True, "data": group}), 201
        except Exception as exc:
            self.logger.error(f"Failed to create group: {exc}")
            return jsonify({"success": False, "error": str(exc)}), 400

    def update_group(self, group_id: str):
        try:
            # Group management is admin-only. Teachers use whitelist profiles
            # for lesson-specific rules and cannot mutate group policy.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return jsonify({"success": False, "error": "Admin access only"}), 403

            data = request.get_json() or {}
            updated = self.service.update_group(group_id, data)
            return jsonify({"success": True, "data": updated}), 200
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 404
        except Exception as exc:
            self.logger.error(f"Failed to update group {group_id}: {exc}")
            return jsonify({"success": False, "error": str(exc)}), 400

    def delete_group(self, group_id: str):
        try:
            # Group management is admin-only. Teachers use whitelist profiles
            # for lesson-specific rules and cannot mutate group policy.
            is_teacher, user = self._is_teacher()
            if is_teacher:
                return jsonify({"success": False, "error": "Admin access only"}), 403

            self.service.delete_group(group_id)
            return jsonify({"success": True, "message": "Group deleted"}), 200
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            self.logger.error(f"Failed to delete group {group_id}: {exc}")
            return jsonify({"success": False, "error": str(exc)}), 400

    def set_teachers(self, group_id: str):
        """Admin-only: Set the list of teacher_ids for a group."""
        try:
            user = getattr(g, 'current_user', None)
            if not user or user.get('role') != 'admin':
                return jsonify({"success": False, "error": "Admin access only"}), 403

            data = request.get_json() or {}
            teacher_ids = data.get("teacher_ids", [])
            if not isinstance(teacher_ids, list):
                return jsonify({"success": False, "error": "teacher_ids must be a list"}), 400

            # Convert string IDs to ObjectId
            from bson import ObjectId
            oid_list = []
            for tid in teacher_ids:
                try:
                    oid_list.append(ObjectId(tid))
                except Exception:
                    return jsonify({"success": False, "error": f"Invalid teacher ID: {tid}"}), 400

            updated = self.service.model.set_teachers(group_id, oid_list)
            if not updated:
                return jsonify({"success": False, "error": "Group not found"}), 404

            return jsonify({"success": True, "data": {"teacher_ids": [str(t) for t in oid_list]}}), 200
        except Exception as exc:
            self.logger.error(f"Failed to set teachers for group {group_id}: {exc}")
            return jsonify({"success": False, "error": str(exc)}), 400
