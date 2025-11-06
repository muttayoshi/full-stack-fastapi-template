"""
Test script untuk WebSocket Chat Feature
Jalankan: python -m pytest backend/tests/test_chat.py -v
"""

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.chat.schemas import MessageCreate, RoomCreate, RoomMemberCreate
from app.chat.services import MessageService, RoomService
from app.users.models import User


def test_create_room(session: Session, normal_user: User) -> None:
    """Test creating a chat room."""
    room_data = RoomCreate(
        name="Test Room",
        description="A test chat room",
        is_private=False,
    )

    room = RoomService.create_room(session, room_data, normal_user.id)

    assert room.name == "Test Room"
    assert room.description == "A test chat room"
    assert room.is_private is False
    assert room.created_by == normal_user.id

    # Verify creator is automatically added as admin member
    members = RoomService.get_room_members(session, room.id)
    assert len(members) == 1
    assert members[0].user_id == normal_user.id
    assert members[0].is_admin is True


def test_add_member_to_room(
    session: Session, normal_user: User, other_user: User
) -> None:
    """Test adding a member to a room."""
    # Create room
    room_data = RoomCreate(name="Test Room", is_private=False)
    room = RoomService.create_room(session, room_data, normal_user.id)

    # Add member
    member_data = RoomMemberCreate(user_id=other_user.id)
    member = RoomService.add_member(session, room.id, member_data)

    assert member is not None
    assert member.user_id == other_user.id
    assert member.room_id == room.id
    assert member.is_admin is False

    # Verify total members
    members = RoomService.get_room_members(session, room.id)
    assert len(members) == 2


def test_create_room_message(session: Session, normal_user: User) -> None:
    """Test creating a message in a room."""
    # Create room
    room_data = RoomCreate(name="Test Room", is_private=False)
    room = RoomService.create_room(session, room_data, normal_user.id)

    # Create message
    message_data = MessageCreate(
        room_id=room.id,
        content="Hello, World!",
        message_type="text",
    )
    message = MessageService.create_message(session, message_data, normal_user.id)

    assert message.content == "Hello, World!"
    assert message.sender_id == normal_user.id
    assert message.room_id == room.id
    assert message.message_type == "text"
    assert message.is_read is False


def test_create_direct_message(
    session: Session, normal_user: User, other_user: User
) -> None:
    """Test creating a direct message between two users."""
    message_data = MessageCreate(
        recipient_id=other_user.id,
        content="Hi there!",
        message_type="text",
    )
    message = MessageService.create_message(session, message_data, normal_user.id)

    assert message.content == "Hi there!"
    assert message.sender_id == normal_user.id
    assert message.recipient_id == other_user.id
    assert message.room_id is None


def test_get_room_messages(session: Session, normal_user: User) -> None:
    """Test retrieving room messages."""
    # Create room
    room_data = RoomCreate(name="Test Room", is_private=False)
    room = RoomService.create_room(session, room_data, normal_user.id)

    # Create multiple messages
    for i in range(5):
        message_data = MessageCreate(
            room_id=room.id,
            content=f"Message {i}",
            message_type="text",
        )
        MessageService.create_message(session, message_data, normal_user.id)

    # Get messages
    messages, count = MessageService.get_room_messages(
        session, room.id, skip=0, limit=10
    )

    assert count == 5
    assert len(messages) == 5


def test_get_direct_messages(
    session: Session, normal_user: User, other_user: User
) -> None:
    """Test retrieving direct messages between two users."""
    # Create messages from normal_user to other_user
    for i in range(3):
        message_data = MessageCreate(
            recipient_id=other_user.id,
            content=f"Message from normal {i}",
            message_type="text",
        )
        MessageService.create_message(session, message_data, normal_user.id)

    # Create messages from other_user to normal_user
    for i in range(2):
        message_data = MessageCreate(
            recipient_id=normal_user.id,
            content=f"Message from other {i}",
            message_type="text",
        )
        MessageService.create_message(session, message_data, other_user.id)

    # Get messages
    messages, count = MessageService.get_direct_messages(
        session, normal_user.id, other_user.id, skip=0, limit=10
    )

    assert count == 5
    assert len(messages) == 5


def test_mark_message_as_read(
    session: Session, normal_user: User, other_user: User
) -> None:
    """Test marking a message as read."""
    # Create direct message
    message_data = MessageCreate(
        recipient_id=other_user.id,
        content="Read this!",
        message_type="text",
    )
    message = MessageService.create_message(session, message_data, normal_user.id)

    assert message.is_read is False

    # Mark as read by recipient
    updated_message = MessageService.mark_as_read(session, message.id, other_user.id)

    assert updated_message is not None
    assert updated_message.is_read is True


def test_room_api_endpoints(
    client: TestClient, normal_user_token_headers: dict
) -> None:
    """Test room API endpoints."""
    # Create room
    response = client.post(
        "/api/v1/chat/rooms",
        headers=normal_user_token_headers,
        json={
            "name": "API Test Room",
            "description": "Testing via API",
            "is_private": False,
        },
    )
    assert response.status_code == 201
    room_data = response.json()
    room_id = room_data["id"]

    # Get all rooms
    response = client.get(
        "/api/v1/chat/rooms",
        headers=normal_user_token_headers,
    )
    assert response.status_code == 200
    assert response.json()["count"] >= 1

    # Get room details
    response = client.get(
        f"/api/v1/chat/rooms/{room_id}",
        headers=normal_user_token_headers,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "API Test Room"

    # Update room
    response = client.patch(
        f"/api/v1/chat/rooms/{room_id}",
        headers=normal_user_token_headers,
        json={"name": "Updated Room Name"},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Updated Room Name"

    # Delete room
    response = client.delete(
        f"/api/v1/chat/rooms/{room_id}",
        headers=normal_user_token_headers,
    )
    assert response.status_code == 204


def test_websocket_connection(client: TestClient, normal_user_token: str) -> None:
    """Test WebSocket connection."""
    with client.websocket_connect(
        f"/api/v1/chat/ws?token={normal_user_token}"
    ) as websocket:
        # Receive welcome message
        data = websocket.receive_json()
        assert data["type"] == "connected"
        assert "Welcome" in data["message"]
