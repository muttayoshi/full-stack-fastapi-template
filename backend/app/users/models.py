import uuid

# Import for type checking
from typing import TYPE_CHECKING, Any

from sqlmodel import Field, Relationship, SQLModel

from app.core.auditlog import AuditMixin

if TYPE_CHECKING:
    from app.items.models import Item
    from app.sites.models import Site


# Database model, database table inferred from class name
class User(SQLModel, AuditMixin, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=255)
    hashed_password: str
    is_active: bool = True
    is_superuser: bool = False
    full_name: str | None = Field(default=None, max_length=255)
    google_id: str | None = Field(
        default=None, unique=True, index=True
    )  # Google OAuth ID
    items: list["Item"] = Relationship(back_populates="owner", cascade_delete=True)  # type: ignore
    user_roles: list["UserRole"] = Relationship(
        back_populates="user", cascade_delete=True
    )  # type: ignore

    def _get_audit_data(self) -> dict[str, Any]:
        """Override untuk exclude sensitive fields dari audit log"""
        data = super()._get_audit_data()
        # Remove sensitive fields
        data.pop("hashed_password", None)
        return data


class Role(SQLModel, AuditMixin, table=True):
    """
    Role model for role-based access control (RBAC).

    Examples: 'admin', 'editor', 'viewer', 'manager', etc.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(
        unique=True,
        index=True,
        max_length=50,
        description="Role name (e.g., 'admin', 'editor')",
    )
    description: str | None = Field(
        default=None, max_length=255, description="Role description"
    )
    is_active: bool = Field(default=True, description="Whether this role is active")

    # Relationships
    user_roles: list["UserRole"] | None = Relationship(
        back_populates="role", cascade_delete=True
    )

    def __str__(self) -> str:
        return self.name


class UserRole(SQLModel, AuditMixin, table=True):
    """
    Junction table for many-to-many relationship between User, Role, and Site.
    Allows one user to have multiple roles, and different roles per site.
    """

    __tablename__ = "user_role"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    role_id: uuid.UUID = Field(foreign_key="role.id", index=True)
    site_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="site.id",
        index=True,
        description="Site ID - if None, role applies to all sites",
    )

    # Optional: Add extra fields for junction table
    is_active: bool = Field(
        default=True, description="Whether this role assignment is active"
    )

    # Relationships
    user: "User" = Relationship(back_populates="user_roles")
    role: "Role" = Relationship(back_populates="user_roles")
    site: "Site" = Relationship()
