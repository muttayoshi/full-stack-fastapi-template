import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import JSON
from sqlmodel import Column, Field, SQLModel


class AuditAction(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class AuditLog(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    table_name: str = Field(max_length=100, index=True)  # Nama tabel yang diubah
    record_id: str = Field(max_length=100, index=True)  # ID record yang diubah
    action: AuditAction = Field(index=True)  # CREATE, UPDATE, DELETE
    old_values: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSON)
    )  # Data sebelum perubahan
    new_values: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSON)
    )  # Data setelah perubahan
    changed_fields: list[str] | None = Field(
        default=None, sa_column=Column(JSON)
    )  # Field yang berubah
    user_id: uuid.UUID | None = Field(
        default=None, foreign_key="user.id"
    )  # User yang melakukan perubahan
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    ip_address: str | None = Field(default=None, max_length=45)  # IP address user
    user_agent: str | None = Field(default=None, max_length=500)  # Browser/client info
    session_id: str | None = Field(default=None, max_length=100)  # Session ID
    additional_info: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSON)
    )  # Info tambahan
