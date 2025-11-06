import logging
import secrets
import uuid
from typing import Any

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from app.core.config import settings
from app.core.security import get_password_hash
from app.users import repositories
from app.users.models import Role, User, UserRole
from app.users.schemas import (
    RoleCreate,
    RoleUpdate,
    UserCreate,
    UserRoleCreate,
    UserRoleUpdate,
    UserRoleWithDetails,
    UserUpdate,
)

logger = logging.getLogger(__name__)


class UserService:
    """Business logic for user operations."""

    @staticmethod
    def create_user(*, session: Session, user_create: UserCreate) -> User:
        """Create a new user."""
        return repositories.create_user(session=session, user_create=user_create)

    @staticmethod
    def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
        """Update an existing user."""
        return repositories.update_user(
            session=session, db_user=db_user, user_in=user_in
        )

    @staticmethod
    def get_user_by_email(*, session: Session, email: str) -> User | None:
        """Get a user by email."""
        return repositories.get_user_by_email(session=session, email=email)

    @staticmethod
    def get_user_by_id(*, session: Session, user_id: uuid.UUID) -> User | None:
        """Get a user by ID."""
        return repositories.get_user_by_id(session=session, user_id=user_id)

    @staticmethod
    def authenticate(*, session: Session, email: str, password: str) -> User | None:
        """Authenticate a user."""
        return repositories.authenticate(
            session=session, email=email, password=password
        )


class OAuthService:
    """Service for OAuth authentication"""

    def __init__(self, session: Session):
        self.session = session

    def link_google_account(
        self, google_id: str, email: str, full_name: str | None = None
    ) -> User | None:
        """Link Google account to existing user, return None if user doesn't exist"""

        user = repositories.get_user_by_google_id(
            session=self.session, google_id=google_id
        )

        if user:
            return user

        # Try to find by email (must exist in database)
        user = repositories.get_user_by_email(session=self.session, email=email)
        if user:
            # Link Google account to existing user
            user.google_id = google_id
            if not user.full_name and full_name:
                user.full_name = full_name

            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
            return user

        return None

    def create_or_link_google_account(
        self, google_id: str, email: str, full_name: str | None = None
    ) -> User:
        """Create new user or link Google account to existing user"""
        try:
            # Try to find user by google_id first (already linked)
            user = repositories.get_user_by_google_id(
                session=self.session, google_id=google_id
            )

            if user:
                logger.info(
                    "User logged in with Google account",
                    extra={
                        "google_id": google_id,
                        "email": email,
                        "user_id": str(user.id),
                    },
                )
                return user

            # Try to find by email
            user = repositories.get_user_by_email(session=self.session, email=email)
            if user:
                # Link Google account to existing user
                user.google_id = google_id
                if not user.full_name and full_name:
                    user.full_name = full_name
                self.session.add(user)
                self.session.commit()
                self.session.refresh(user)
                logger.info(
                    "Linked Google account to existing user",
                    extra={
                        "google_id": google_id,
                        "email": email,
                        "user_id": str(user.id),
                    },
                )
                return user

            # User doesn't exist - create new user
            # Generate a secure random password that will never be used
            # (user will only login via Google)
            random_password = secrets.token_urlsafe(32)
            hashed_password = get_password_hash(random_password)

            new_user = User(
                email=email,
                full_name=full_name or email.split("@")[0],
                google_id=google_id,
                is_active=True,
                is_superuser=False,
                hashed_password=hashed_password,
            )
            self.session.add(new_user)
            self.session.commit()
            self.session.refresh(new_user)
            logger.info(
                "Created new user from Google OAuth",
                extra={
                    "google_id": google_id,
                    "email": email,
                    "user_id": str(new_user.id),
                },
            )
            return new_user

        except SQLAlchemyError as e:
            logger.error(
                "Database error during Google account creation/linking",
                extra={"google_id": google_id, "email": email, "error": str(e)},
            )
            self.session.rollback()
            raise
        except Exception as e:
            logger.error(
                "Unexpected error during Google account creation/linking",
                extra={"google_id": google_id, "email": email, "error": str(e)},
            )
            self.session.rollback()
            raise

    async def exchange_google_code_for_user_info(
        self, code: str
    ) -> dict[str, Any] | None:
        """Exchange Google authorization code for user information"""
        if not settings.google_oauth_enabled:
            logger.error("Google OAuth is not enabled. Missing configuration.")
            return None

        # Exchange authorization code for access token
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": "postmessage",  # Standard for @react-oauth/google
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # Get access token
                logger.debug("Exchanging authorization code for access token")
                token_response = await client.post(token_url, data=token_data)
                token_response.raise_for_status()
                token_info = token_response.json()

                access_token = token_info.get("access_token")
                if not access_token:
                    logger.error("No access token received from Google")
                    return None

                # Get user info using access token
                logger.debug("Fetching user info from Google")
                userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
                headers = {"Authorization": f"Bearer {access_token}"}

                userinfo_response = await client.get(userinfo_url, headers=headers)
                userinfo_response.raise_for_status()
                user_info = userinfo_response.json()

                # Validate required fields
                if not user_info.get("id") or not user_info.get("email"):
                    logger.error("Missing required fields in Google user info")
                    return None

                logger.info(
                    "Successfully retrieved user info from Google",
                    extra={"email": user_info.get("email")},
                )

                return {
                    "google_id": user_info.get("id"),
                    "email": user_info.get("email"),
                    "full_name": user_info.get("name"),
                    "picture": user_info.get("picture"),
                    "verified_email": user_info.get("verified_email", False),
                }

            except httpx.HTTPStatusError as e:
                logger.error(
                    "Google OAuth HTTP error",
                    extra={
                        "status_code": e.response.status_code,
                        "response_body": e.response.text,
                    },
                )
                return None
            except httpx.RequestError as e:
                logger.error(
                    "Google OAuth request error",
                    extra={"error": str(e), "error_type": type(e).__name__},
                )
                return None
            except httpx.TimeoutException as e:
                logger.error(
                    "Google OAuth request timed out",
                    extra={"error": str(e), "error_type": type(e).__name__},
                    exc_info=True,
                )
                return None
            except Exception as e:
                logger.error(
                    "Unexpected error during Google OAuth",
                    extra={"error": str(e), "error_type": type(e).__name__},
                    exc_info=True,
                )
                return None


class RoleService:
    """Business logic for role operations."""

    @staticmethod
    def create_role(*, session: Session, role_create: RoleCreate) -> Role:
        """Create a new role."""
        # Check if role with same name already exists
        existing_role = repositories.get_role_by_name(
            session=session, name=role_create.name
        )
        if existing_role:
            raise ValueError(f"Role with name '{role_create.name}' already exists")

        return repositories.create_role(session=session, role_create=role_create)

    @staticmethod
    def update_role(*, session: Session, db_role: Role, role_in: RoleUpdate) -> Role:
        """Update an existing role."""
        # If updating name, check if new name already exists
        if role_in.name and role_in.name != db_role.name:
            existing_role = repositories.get_role_by_name(
                session=session, name=role_in.name
            )
            if existing_role:
                raise ValueError(f"Role with name '{role_in.name}' already exists")

        return repositories.update_role(
            session=session, db_role=db_role, role_in=role_in
        )

    @staticmethod
    def get_role_by_id(*, session: Session, role_id: uuid.UUID) -> Role | None:
        """Get a role by ID."""
        return repositories.get_role_by_id(session=session, role_id=role_id)

    @staticmethod
    def get_role_by_name(*, session: Session, name: str) -> Role | None:
        """Get a role by name."""
        return repositories.get_role_by_name(session=session, name=name)

    @staticmethod
    def get_roles(
        *,
        session: Session,
        skip: int = 0,
        limit: int = 100,
        is_active: bool | None = None,
    ) -> list[Role]:
        """Get all roles with pagination."""
        return repositories.get_roles(
            session=session, skip=skip, limit=limit, is_active=is_active
        )

    @staticmethod
    def count_roles(*, session: Session, is_active: bool | None = None) -> int:
        """Count total roles."""
        return repositories.count_roles(session=session, is_active=is_active)

    @staticmethod
    def delete_role(*, session: Session, role_id: uuid.UUID) -> bool:
        """Delete a role by ID."""
        return repositories.delete_role(session=session, role_id=role_id)


class UserRoleService:
    """Business logic for user role assignment operations."""

    @staticmethod
    def create_user_role(
        *, session: Session, user_role_create: UserRoleCreate
    ) -> UserRole:
        """Create a new user role assignment."""
        # Validate user exists
        user = repositories.get_user_by_id(
            session=session, user_id=user_role_create.user_id
        )
        if not user:
            raise ValueError(f"User with ID '{user_role_create.user_id}' not found")

        # Validate role exists
        role = repositories.get_role_by_id(
            session=session, role_id=user_role_create.role_id
        )
        if not role:
            raise ValueError(f"Role with ID '{user_role_create.role_id}' not found")

        # Validate site exists if site_id is provided
        if user_role_create.site_id:
            from app.sites import repositories as site_repositories

            site = site_repositories.get_site_by_id(
                session=session, site_id=user_role_create.site_id
            )
            if not site:
                raise ValueError(f"Site with ID '{user_role_create.site_id}' not found")

        # Check if assignment already exists
        existing = repositories.get_user_role_by_user_and_role(
            session=session,
            user_id=user_role_create.user_id,
            role_id=user_role_create.role_id,
            site_id=user_role_create.site_id,
        )
        if existing:
            raise ValueError("User role assignment already exists")

        return repositories.create_user_role(
            session=session, user_role_create=user_role_create
        )

    @staticmethod
    def update_user_role(
        *, session: Session, db_user_role: UserRole, user_role_in: UserRoleUpdate
    ) -> UserRole:
        """Update an existing user role assignment."""
        # Validate role exists if changing role
        if user_role_in.role_id:
            role = repositories.get_role_by_id(
                session=session, role_id=user_role_in.role_id
            )
            if not role:
                raise ValueError(f"Role with ID '{user_role_in.role_id}' not found")

        # Validate site exists if changing site
        if user_role_in.site_id:
            from app.sites import repositories as site_repositories

            site = site_repositories.get_site_by_id(
                session=session, site_id=user_role_in.site_id
            )
            if not site:
                raise ValueError(f"Site with ID '{user_role_in.site_id}' not found")

        return repositories.update_user_role(
            session=session, db_user_role=db_user_role, user_role_in=user_role_in
        )

    @staticmethod
    def get_user_role_by_id(
        *, session: Session, user_role_id: uuid.UUID
    ) -> UserRole | None:
        """Get a user role by ID."""
        return repositories.get_user_role_by_id(
            session=session, user_role_id=user_role_id
        )

    @staticmethod
    def get_user_roles_by_user_id(
        *,
        session: Session,
        user_id: uuid.UUID,
        site_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> list[UserRole]:
        """Get all roles for a specific user, optionally filtered by site."""
        return repositories.get_user_roles_by_user_id(
            session=session, user_id=user_id, site_id=site_id, is_active=is_active
        )

    @staticmethod
    def get_user_roles_with_details(
        *,
        session: Session,
        user_id: uuid.UUID,
        site_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> list[UserRoleWithDetails]:
        """Get user roles with role and site details."""
        user_roles = repositories.get_user_roles_by_user_id(
            session=session, user_id=user_id, site_id=site_id, is_active=is_active
        )

        result = []
        for ur in user_roles:
            role = repositories.get_role_by_id(session=session, role_id=ur.role_id)
            site_name = None
            if ur.site_id:
                from app.sites import repositories as site_repositories

                site = site_repositories.get_site_by_id(
                    session=session, site_id=ur.site_id
                )
                site_name = site.name if site else None

            result.append(
                UserRoleWithDetails(
                    id=ur.id,
                    user_id=ur.user_id,
                    role_id=ur.role_id,
                    role_name=role.name if role else "Unknown",
                    site_id=ur.site_id,
                    site_name=site_name,
                    is_active=ur.is_active,
                )
            )

        return result

    @staticmethod
    def get_user_roles_by_role_id(
        *, session: Session, role_id: uuid.UUID, is_active: bool | None = None
    ) -> list[UserRole]:
        """Get all user role assignments for a specific role."""
        return repositories.get_user_roles_by_role_id(
            session=session, role_id=role_id, is_active=is_active
        )

    @staticmethod
    def delete_user_role(*, session: Session, user_role_id: uuid.UUID) -> bool:
        """Delete a user role assignment by ID."""
        return repositories.delete_user_role(session=session, user_role_id=user_role_id)

    @staticmethod
    def get_user_roles(
        *,
        session: Session,
        skip: int = 0,
        limit: int = 100,
        user_id: uuid.UUID | None = None,
        role_id: uuid.UUID | None = None,
        site_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> list[UserRole]:
        """Get all user role assignments with pagination and filters."""
        return repositories.get_user_roles(
            session=session,
            skip=skip,
            limit=limit,
            user_id=user_id,
            role_id=role_id,
            site_id=site_id,
            is_active=is_active,
        )

    @staticmethod
    def count_user_roles(
        *,
        session: Session,
        user_id: uuid.UUID | None = None,
        role_id: uuid.UUID | None = None,
        site_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> int:
        """Count total user role assignments with filters."""
        return repositories.count_user_roles(
            session=session,
            user_id=user_id,
            role_id=role_id,
            site_id=site_id,
            is_active=is_active,
        )

    @staticmethod
    def has_role(
        *,
        session: Session,
        user_id: uuid.UUID,
        role_name: str,
        site_id: uuid.UUID | None = None,
    ) -> bool:
        """Check if user has specific role (optionally for specific site)."""
        role = repositories.get_role_by_name(session=session, name=role_name)
        if not role:
            return False

        user_roles = repositories.get_user_roles_by_user_id(
            session=session, user_id=user_id, site_id=site_id, is_active=True
        )

        return any(ur.role_id == role.id for ur in user_roles)
