"""Startup tasks that are intentionally run when the app boots."""

import os
import logging

logger = logging.getLogger(__name__)


def run_startup_tasks(user_service, api_key_service) -> None:
    """Run safe startup tasks that existed in the old app factory."""
    admin_username = os.environ.get("DEFAULT_ADMIN_USERNAME")
    admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD")
    if admin_username and admin_password:
        created_admin = user_service.ensure_default_admin(admin_username, admin_password)
        if created_admin:
            logger.info("RBAC defaults seeded from environment")
        else:
            logger.info("Default admin bootstrap skipped (already exists or credentials were rejected)")
    else:
        logger.info("Default admin bootstrap skipped (set DEFAULT_ADMIN_USERNAME and DEFAULT_ADMIN_PASSWORD to enable)")

    logger.info("Default API key bootstrap skipped; create API keys explicitly in the admin UI or seed script")
