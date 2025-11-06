import uuid
from typing import Any

from sqlmodel import Session, select

from app.core.security import get_password_hash, verify_password
from app.users.models import Role, User, UserRole
from app.users.schemas import (
    RoleCreate,
    RoleUpdate,
    UserCreate,
    UserRoleCreate,
    UserRoleUpdate,
    UserUpdate,
)

# ============================================================================
# User CRUD Operations
# ============================================================================


def create_user(*, session: Session, user_create: UserCreate) -> User:
    """Create a new user in the database."""
    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password)}
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    """Update an existing user in the database."""
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if "password" in user_data:
        password = user_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["hashed_password"] = hashed_password
    db_user.sqlmodel_update(user_data, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


def get_user_by_email(*, session: Session, email: str) -> User | None:
    """Get a user by email."""
    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user


def get_user_by_google_id(*, session: Session, google_id: str) -> User | None:
    """Get a user by google_id."""
    statement = select(User).where(User.google_id == google_id)
    session_user = session.exec(statement).first()
    return session_user


def get_user_by_id(*, session: Session, user_id: uuid.UUID) -> User | None:
    """Get a user by ID."""
    return session.get(User, user_id)


def authenticate(*, session: Session, email: str, password: str) -> User | None:
    """Authenticate a user by email and password."""
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        return None
    if not verify_password(password, db_user.hashed_password):
        return None
    return db_user


# ============================================================================
# Role CRUD Operations
# ============================================================================


def create_role(*, session: Session, role_create: RoleCreate) -> Role:
    """Create a new role in the database."""
    db_obj = Role.model_validate(role_create)
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_role(*, session: Session, db_role: Role, role_in: RoleUpdate) -> Role:
    """Update an existing role in the database."""
    role_data = role_in.model_dump(exclude_unset=True)
    db_role.sqlmodel_update(role_data)
    session.add(db_role)
    session.commit()
    session.refresh(db_role)
    return db_role


def get_role_by_id(*, session: Session, role_id: uuid.UUID) -> Role | None:
    """Get a role by ID."""
    return session.get(Role, role_id)


def get_role_by_name(*, session: Session, name: str) -> Role | None:
    """Get a role by name."""
    statement = select(Role).where(Role.name == name)
    return session.exec(statement).first()


def get_roles(
    *, session: Session, skip: int = 0, limit: int = 100, is_active: bool | None = None
) -> list[Role]:
    """Get all roles with pagination."""
    statement = select(Role)
    if is_active is not None:
        statement = statement.where(Role.is_active == is_active)
    statement = statement.offset(skip).limit(limit)
    return list(session.exec(statement).all())


def count_roles(*, session: Session, is_active: bool | None = None) -> int:
    """Count total roles."""
    statement = select(Role)
    if is_active is not None:
        statement = statement.where(Role.is_active == is_active)
    return len(list(session.exec(statement).all()))


def delete_role(*, session: Session, role_id: uuid.UUID) -> bool:
    """Delete a role by ID."""
    role = session.get(Role, role_id)
    if not role:
        return False
    session.delete(role)
    session.commit()
    return True


# ============================================================================
# UserRole CRUD Operations
# ============================================================================


def create_user_role(*, session: Session, user_role_create: UserRoleCreate) -> UserRole:
    """Create a new user role assignment in the database."""
    db_obj = UserRole.model_validate(user_role_create)
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user_role(
    *, session: Session, db_user_role: UserRole, user_role_in: UserRoleUpdate
) -> UserRole:
    """Update an existing user role assignment in the database."""
    user_role_data = user_role_in.model_dump(exclude_unset=True)
    db_user_role.sqlmodel_update(user_role_data)
    session.add(db_user_role)
    session.commit()
    session.refresh(db_user_role)
    return db_user_role


def get_user_role_by_id(
    *, session: Session, user_role_id: uuid.UUID
) -> UserRole | None:
    """Get a user role by ID."""
    return session.get(UserRole, user_role_id)


def get_user_roles_by_user_id(
    *,
    session: Session,
    user_id: uuid.UUID,
    site_id: uuid.UUID | None = None,
    is_active: bool | None = None,
) -> list[UserRole]:
    """Get all roles for a specific user, optionally filtered by site."""
    statement = select(UserRole).where(UserRole.user_id == user_id)

    if site_id is not None:
        # Get roles for specific site OR global roles (site_id is None)
        statement = statement.where(
            (UserRole.site_id == site_id) | (UserRole.site_id.is_(None))
        )

    if is_active is not None:
        statement = statement.where(UserRole.is_active == is_active)

    return list(session.exec(statement).all())


def get_user_roles_by_role_id(
    *, session: Session, role_id: uuid.UUID, is_active: bool | None = None
) -> list[UserRole]:
    """Get all user role assignments for a specific role."""
    statement = select(UserRole).where(UserRole.role_id == role_id)
    if is_active is not None:
        statement = statement.where(UserRole.is_active == is_active)
    return list(session.exec(statement).all())


def get_user_role_by_user_and_role(
    *,
    session: Session,
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    site_id: uuid.UUID | None = None,
) -> UserRole | None:
    """Get a specific user role assignment."""
    statement = select(UserRole).where(
        UserRole.user_id == user_id,
        UserRole.role_id == role_id,
        UserRole.site_id == site_id,
    )
    return session.exec(statement).first()


def delete_user_role(*, session: Session, user_role_id: uuid.UUID) -> bool:
    """Delete a user role assignment by ID."""
    user_role = session.get(UserRole, user_role_id)
    if not user_role:
        return False
    session.delete(user_role)
    session.commit()
    return True


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
    statement = select(UserRole)

    if user_id is not None:
        statement = statement.where(UserRole.user_id == user_id)

    if role_id is not None:
        statement = statement.where(UserRole.role_id == role_id)

    if site_id is not None:
        statement = statement.where(UserRole.site_id == site_id)

    if is_active is not None:
        statement = statement.where(UserRole.is_active == is_active)

    statement = statement.offset(skip).limit(limit)
    return list(session.exec(statement).all())


def count_user_roles(
    *,
    session: Session,
    user_id: uuid.UUID | None = None,
    role_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
    is_active: bool | None = None,
) -> int:
    """Count total user role assignments with filters."""
    statement = select(UserRole)

    if user_id is not None:
        statement = statement.where(UserRole.user_id == user_id)

    if role_id is not None:
        statement = statement.where(UserRole.role_id == role_id)

    if site_id is not None:
        statement = statement.where(UserRole.site_id == site_id)

    if is_active is not None:
        statement = statement.where(UserRole.is_active == is_active)

    return len(list(session.exec(statement).all()))
