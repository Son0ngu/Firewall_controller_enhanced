"""
RBAC Configuration - Role hierarchy, permissions mapping.
Only 2 roles: admin (full access) and teacher (limited by ownership).
Format permission: resource:action
"""

# ============================================================================
# ROLE HIERARCHY
# ============================================================================

ROLE_HIERARCHY = {
    "admin": 100,    # Full access
    "teacher": 50,   # Limited by ownership
}

VALID_ROLES = list(ROLE_HIERARCHY.keys())

# ============================================================================
# PERMISSION DEFINITIONS - resource:action format
# ============================================================================

TEACHER_PERMISSIONS = [
    # Profile
    "profile:read",
    "profile:change_password",

    # Dashboard
    "dashboard:read",

    # Groups (view only Groups assigned by admin)
    "groups:read",

    # Whitelist Profiles (per-teacher whitelist in Group)
    "whitelist_profile:create",
    "whitelist_profile:update",
    "whitelist_profile:delete",
    "whitelist_profile:activate",

    # Agents (view only Agents in own Groups)
    "agents:read",
    "agents:detail",

    # Whitelist (read-only; teachers edit lesson-specific Whitelist Profiles)
    "whitelist:read",

    # Logs (view only logs from Agents in own Groups)
    "logs:read",
]

ADMIN_EXTRA_PERMISSIONS = [
    # User management (Admin only)
    "users:create",
    "users:read",
    "users:update",
    "users:delete",
    "users:reset_password",

    # Full agent management
    "agents:delete",
    "agents:command",

    # Group lifecycle and management
    "groups:create",
    "groups:update",
    "groups:delete",
    "groups:manage_agents",

    # Full whitelist management
    "whitelist:create",
    "whitelist:update",
    "whitelist:delete",
    "whitelist:sync",

    # API Keys
    "api_keys:read",
    "api_keys:create",
    "api_keys:revoke",

    # Full logs access
    "logs:export",
    "logs:delete",

    # System
    "system:config",
    "audit:read",
]

# Admin inherits all teacher permissions + exclusive permissions
ROLE_PERMISSIONS = {
    "teacher": TEACHER_PERMISSIONS,
    "admin": TEACHER_PERMISSIONS + ADMIN_EXTRA_PERMISSIONS,
}

# All permissions in the system
ALL_PERMISSIONS = list(set(TEACHER_PERMISSIONS + ADMIN_EXTRA_PERMISSIONS))
ALL_PERMISSIONS.sort()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_all_permissions(role: str) -> list:
    """Get all permissions for a role."""
    return ROLE_PERMISSIONS.get(role, [])


def check_permission(role: str, permission: str) -> bool:
    """Check if role has specific permission."""
    return permission in get_all_permissions(role)


def can_access_group(user: dict, group: dict) -> bool:
    """
    Check if user can access a specific group.
    Admin: always True (full access)
    Teacher: if user._id in group.teacher_ids OR group.created_by == user._id (legacy)
    """
    if user.get("role") == "admin":
        return True
    user_id = user.get("_id")
    # Check teacher_ids list
    teacher_ids = group.get("teacher_ids") or []
    if any(str(tid) == str(user_id) for tid in teacher_ids):
        return True
    # Legacy fallback: created_by
    return str(group.get("created_by")) == str(user_id)


def is_admin(role: str) -> bool:
    """Check if role is admin."""
    return role == "admin"
