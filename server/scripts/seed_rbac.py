"""
Seed RBAC - Script to initialize default admin user.
Run once on deploy or manually when provisioning.

Usage:
    cd server
    python scripts/seed_rbac.py --username myadmin --password mypassword123

    # Or provide DEFAULT_ADMIN_USERNAME / DEFAULT_ADMIN_PASSWORD in the environment
"""

import os
import sys
import logging
import argparse

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from database.config import get_config, get_database
from models.user_model import UserModel
from models.audit_model import AuditModel
from services.audit_service import AuditService
from services.user_service import UserService
from config.rbac_config import ROLE_PERMISSIONS, VALID_ROLES

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("seed_rbac")


def seed_rbac(admin_username: str = None, admin_password: str = None):
    """Seed default admin user (roles are defined in config, not database)"""

    logger.info("=" * 60)
    logger.info("SAINT RBAC Seeder")
    logger.info("=" * 60)

    # Connect to database
    config = get_config()
    db = get_database(config)
    logger.info(f"Connected to database: {config.MONGO_DBNAME}")

    # Initialize models & services (V2 architecture)
    user_model = UserModel(db)
    audit_model = AuditModel(db)
    audit_service = AuditService(audit_model)
    user_service = UserService(user_model, audit_service)

    # Step 1: Show role config (roles are in config file, not database)
    logger.info("\n--- Step 1: Role Configuration (from config/rbac_config.py) ---")
    for role_name in VALID_ROLES:
        perms = ROLE_PERMISSIONS.get(role_name, [])
        logger.info(f"  Role: {role_name:10} | {len(perms)} permissions")

    # Step 2: Seed default admin
    logger.info("\n--- Step 2: Seeding default admin user ---")
    admin = user_service.ensure_default_admin(admin_username, admin_password)

    if admin:
        logger.info("  Admin created successfully!")
    else:
        if admin_username and admin_password:
            logger.info("  Admin user already exists or seed credentials were rejected")
        else:
            logger.info("  Admin user already exists or credentials were not provided")

    # Show all users
    all_users = user_model.get_all_users()
    logger.info(f"\n  Total users in system: {len(all_users)}")
    for user in all_users:
        logger.info(
            f"    - {user['username']:15} | role={user['role']:12} | "
            f"active={'Yes' if user.get('is_active') else 'No'}"
        )

    logger.info("\n" + "=" * 60)
    logger.info("RBAC Seeding complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed RBAC admin user")
    parser.add_argument("--username", default=os.environ.get("DEFAULT_ADMIN_USERNAME"), help="Admin username")
    parser.add_argument("--password", default=os.environ.get("DEFAULT_ADMIN_PASSWORD"), help="Admin password")
    args = parser.parse_args()

    seed_rbac(args.username, args.password)
