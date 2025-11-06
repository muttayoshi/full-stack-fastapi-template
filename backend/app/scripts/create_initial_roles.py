"""
Script to create initial roles in the database.

This script creates common roles that can be used across the application:
- admin: Full administrative access
- editor: Can create and edit content
- viewer: Read-only access
- moderator: Can moderate content and users

Run this script after database migration:
    python -m app.scripts.create_initial_roles
"""

import logging
from sqlmodel import Session, select

from app.core.db import engine
from app.users.models import Role

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_initial_roles() -> None:
    """Create initial roles if they don't exist."""

    initial_roles = [
        {
            "name": "admin",
            "description": "Full administrative access to the system",
            "is_active": True,
        },
        {
            "name": "editor",
            "description": "Can create, edit, and publish content",
            "is_active": True,
        },
        {
            "name": "viewer",
            "description": "Read-only access to content",
            "is_active": True,
        },
        {
            "name": "moderator",
            "description": "Can moderate content and manage users",
            "is_active": True,
        },
        {
            "name": "contributor",
            "description": "Can create content but cannot publish",
            "is_active": True,
        },
    ]

    with Session(engine) as session:
        for role_data in initial_roles:
            # Check if role already exists
            statement = select(Role).where(Role.name == role_data["name"])
            existing_role = session.exec(statement).first()

            if existing_role:
                logger.info(f"Role '{role_data['name']}' already exists, skipping...")
                continue

            # Create new role
            role = Role(**role_data)
            session.add(role)
            logger.info(f"Created role: {role_data['name']}")

        session.commit()
        logger.info("Initial roles created successfully!")


if __name__ == "__main__":
    logger.info("Creating initial roles...")
    create_initial_roles()
    logger.info("Done!")

