import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel

from app.core.auditlog import AuditMixin

if TYPE_CHECKING:
    pass


class Site(SQLModel, AuditMixin, table=True):
    """
    Site model - inspired by Django's contrib.sites framework.
    Allows managing multiple sites/domains from a single application.

    Use cases:
    - Multi-tenancy support
    - Different domains for same application
    - Environment-specific URLs (dev, staging, production)
    - Generate correct absolute URLs based on current site
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    domain: str = Field(
        unique=True,
        index=True,
        max_length=255,
        description="Backend domain (e.g., 'api.example.com' or 'localhost:8000')",
    )
    name: str = Field(max_length=255)
    frontend_domain: str = Field(
        max_length=255,
        description="Frontend domain for redirects (e.g., 'example.com' or 'localhost:5173')",
    )
    is_active: bool = Field(default=True)
    is_default: bool = Field(default=False, index=True)

    # Optional: Additional configuration per site
    settings: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))

    def __str__(self) -> str:
        return f"{self.name} ({self.domain})"

    def get_frontend_url(self, path: str = "") -> str:
        """
        Build absolute frontend URL for redirects.

        Args:
            path: Frontend path (e.g., '/reset-password' or 'reset-password')

        Returns:
            Absolute frontend URL (e.g., 'https://example.com/reset-password')
        """
        # Determine scheme (http or https)
        scheme = "https" if not self.frontend_domain.startswith("localhost") else "http"

        # Ensure path starts with /
        if path and not path.startswith("/"):
            path = f"/{path}"

        return f"{scheme}://{self.frontend_domain}{path}"
