"""Database models for chat functionality."""
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlmodel import Field, Relationship, SQLModel

from app.core.auditlog import AuditMixin

if TYPE_CHECKING:
    from app.users.models import User


class Room(SQLModel, AuditMixin, table=True):
    """Chat room model."""

    __tablename__ = "chat_room"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(max_length=255, index=True)
    description: str | None = Field(default=None, max_length=1000)
    is_private: bool = Field(default=False)
    created_by: uuid.UUID = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Relationships
    members: list["RoomMember"] = Relationship(
        back_populates="room", cascade_delete=True
    )  # type: ignore
    messages: list["Message"] = Relationship(
        back_populates="room", cascade_delete=True
    )  # type: ignore


class RoomMember(SQLModel, table=True):
    """Association table for room members."""

    __tablename__ = "chat_room_member"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    room_id: uuid.UUID = Field(foreign_key="chat_room.id", index=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    joined_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_admin: bool = Field(default=False)

    # Relationships
    room: Room = Relationship(back_populates="members")  # type: ignore
    user: "User" = Relationship()  # type: ignore


class Message(SQLModel, AuditMixin, table=True):
    """Chat message model."""

    __tablename__ = "chat_message"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    room_id: uuid.UUID | None = Field(
        default=None, foreign_key="chat_room.id", index=True
    )
    sender_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    recipient_id: uuid.UUID | None = Field(
        default=None, foreign_key="user.id", index=True
    )  # For direct messages
    content: str = Field(max_length=4000)
    message_type: str = Field(default="text", max_length=50)  # text, image, file, etc.
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    is_read: bool = Field(default=False)

    # Relationships
    room: Room | None = Relationship(back_populates="messages")  # type: ignore
    sender: "User" = Relationship(
        sa_relationship_kwargs={"foreign_keys": "Message.sender_id"}
    )  # type: ignore
    recipient: Optional["User"] = Relationship(  # type: ignore
        sa_relationship_kwargs={"foreign_keys": "Message.recipient_id"}
    )

