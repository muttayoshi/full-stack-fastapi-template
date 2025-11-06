"""Pydantic schemas for chat functionality."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field


# Room Schemas
class RoomBase(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    is_private: bool = Field(default=False)


class RoomCreate(RoomBase):
    """Schema for creating a new room."""

    pass


class RoomUpdate(BaseModel):
    """Schema for updating a room."""

    name: str | None = None
    description: str | None = None


class RoomPublic(RoomBase):
    """Public room data."""

    id: uuid.UUID
    created_by: uuid.UUID
    created_at: datetime
    member_count: int = 0
    is_member: bool = False  # Whether current user is a member


class RoomDetail(RoomPublic):
    """Detailed room data with members."""

    members: list["RoomMemberPublic"] = []


class RoomsPublic(BaseModel):
    """List of rooms."""

    data: list[RoomPublic]
    count: int


# Room Member Schemas
class RoomMemberBase(BaseModel):
    user_id: uuid.UUID


class RoomMemberCreate(RoomMemberBase):
    """Schema for adding a member to a room."""

    pass


class RoomMemberPublic(BaseModel):
    """Public room member data."""

    id: uuid.UUID
    user_id: uuid.UUID
    joined_at: datetime
    is_admin: bool
    user_email: str | None = None
    user_full_name: str | None = None


# Message Schemas
class MessageBase(BaseModel):
    content: str = Field(..., max_length=4000)
    message_type: str = Field(default="text", max_length=50)


class MessageCreate(MessageBase):
    """Schema for creating a message."""

    room_id: uuid.UUID | None = None
    recipient_id: uuid.UUID | None = None


class MessageUpdate(BaseModel):
    """Schema for updating a message."""

    content: str | None = None
    is_read: bool | None = None


class MessagePublic(MessageBase):
    """Public message data."""

    id: uuid.UUID
    room_id: uuid.UUID | None
    sender_id: uuid.UUID
    recipient_id: uuid.UUID | None
    created_at: datetime
    is_read: bool
    sender_email: str | None = None
    sender_full_name: str | None = None


class MessagesPublic(BaseModel):
    """List of messages."""

    data: list[MessagePublic]
    count: int


# WebSocket Schemas
class WSMessage(BaseModel):
    """WebSocket message format."""

    type: str  # message, join_room, leave_room, typing, etc.
    room_id: uuid.UUID | None = None
    recipient_id: uuid.UUID | None = None
    content: str | None = None
    message_type: str = "text"
    message_id: uuid.UUID | None = None
    sender_id: uuid.UUID | None = None
    created_at: datetime | None = None


class WSResponse(BaseModel):
    """WebSocket response format."""

    type: str  # message, error, success, user_joined, user_left, etc.
    data: dict | None = None
    message: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
