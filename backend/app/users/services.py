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
from app.users.models import User
from app.users.schemas import UserCreate, UserUpdate

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
            except httpx.TimeoutException:
                logger.error("Google OAuth request timed out")
                return None
            except Exception as e:
                logger.error(
                    "Unexpected error during Google OAuth",
                    extra={"error": str(e), "error_type": type(e).__name__},
                    exc_info=True,
                )
                return None
