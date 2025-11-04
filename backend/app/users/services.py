import uuid
from typing import Any

from sqlmodel import Session

from app.users import repositories
from app.users.models import User
from app.users.schemas import UserCreate, UserUpdate


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
