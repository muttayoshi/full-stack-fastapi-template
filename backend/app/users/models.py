import uuid

# Import for type checking
from typing import TYPE_CHECKING, Any

from sqlmodel import Field, Relationship, SQLModel

from app.core.auditlog import AuditMixin

if TYPE_CHECKING:
    from app.items.models import Item


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

    def _get_audit_data(self) -> dict[str, Any]:
        """Override untuk exclude sensitive fields dari audit log"""
        data = super()._get_audit_data()
        # Remove sensitive fields
        data.pop("hashed_password", None)
        return data
