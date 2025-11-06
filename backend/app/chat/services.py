"""Service layer for chat functionality."""
import uuid

from sqlmodel import Session

from app.chat.models import Message, Room, RoomMember
from app.chat.repositories import (
    MessageRepository,
    RoomMemberRepository,
    RoomRepository,
)
from app.chat.schemas import MessageCreate, RoomCreate, RoomMemberCreate, RoomUpdate


class RoomService:
    """Service for managing chat rooms."""

    @staticmethod
    def create_room(
        session: Session, room_create: RoomCreate, creator_id: uuid.UUID
    ) -> Room:
        """Create a new chat room."""
        room = Room(
            name=room_create.name,
            description=room_create.description,
            is_private=room_create.is_private,
            created_by=creator_id,
        )
        room = RoomRepository.create(session, room)

        # Add creator as admin member
        member = RoomMember(
            room_id=room.id,
            user_id=creator_id,
            is_admin=True,
        )
        RoomMemberRepository.create(session, member)

        return room

    @staticmethod
    def get_room(session: Session, room_id: uuid.UUID) -> Room | None:
        """Get a room by ID."""
        return RoomRepository.get_by_id(session, room_id)

    @staticmethod
    def get_rooms(
        session: Session, skip: int = 0, limit: int = 100
    ) -> tuple[list[Room], int]:
        """Get all rooms with pagination."""
        return RoomRepository.get_all(session, skip=skip, limit=limit)

    @staticmethod
    def get_public_rooms(
        session: Session, skip: int = 0, limit: int = 100
    ) -> tuple[list[Room], int]:
        """Get all public (non-private) rooms with pagination."""
        return RoomRepository.get_public_rooms(session, skip=skip, limit=limit)

    @staticmethod
    def get_user_rooms(
        session: Session, user_id: uuid.UUID, skip: int = 0, limit: int = 100
    ) -> tuple[list[Room], int]:
        """Get all rooms a user is a member of."""
        return RoomRepository.get_user_rooms(session, user_id, skip=skip, limit=limit)

    @staticmethod
    def update_room(
        session: Session, room_id: uuid.UUID, room_update: RoomUpdate
    ) -> Room | None:
        """Update a room."""
        room = RoomRepository.get_by_id(session, room_id)
        if not room:
            return None

        update_data = room_update.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(room, key, value)

        return RoomRepository.update(session, room)

    @staticmethod
    def delete_room(session: Session, room_id: uuid.UUID) -> bool:
        """Delete a room."""
        room = RoomRepository.get_by_id(session, room_id)
        if not room:
            return False

        RoomRepository.delete(session, room)
        return True

    @staticmethod
    def add_member(
        session: Session, room_id: uuid.UUID, member_create: RoomMemberCreate
    ) -> RoomMember | None:
        """Add a member to a room."""
        # Check if user is already a member
        existing = RoomMemberRepository.get_by_room_and_user(
            session, room_id, member_create.user_id
        )
        if existing:
            return existing

        member = RoomMember(
            room_id=room_id,
            user_id=member_create.user_id,
        )
        return RoomMemberRepository.create(session, member)

    @staticmethod
    def remove_member(session: Session, room_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Remove a member from a room."""
        member = RoomMemberRepository.get_by_room_and_user(session, room_id, user_id)
        if not member:
            return False

        RoomMemberRepository.delete(session, member)
        return True

    @staticmethod
    def get_room_members(session: Session, room_id: uuid.UUID) -> list[RoomMember]:
        """Get all members of a room."""
        return RoomMemberRepository.get_by_room(session, room_id)

    @staticmethod
    def is_user_member(
        session: Session, room_id: uuid.UUID, user_id: uuid.UUID
    ) -> bool:
        """Check if a user is a member of a room."""
        return (
            RoomMemberRepository.get_by_room_and_user(session, room_id, user_id)
            is not None
        )

    @staticmethod
    def is_user_admin(session: Session, room_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Check if a user is an admin of a room."""
        return (
            RoomMemberRepository.get_admin_by_room_and_user(session, room_id, user_id)
            is not None
        )


class MessageService:
    """Service for managing chat messages."""

    @staticmethod
    def create_message(
        session: Session, message_create: MessageCreate, sender_id: uuid.UUID
    ) -> Message:
        """Create a new message."""
        message = Message(
            room_id=message_create.room_id,
            sender_id=sender_id,
            recipient_id=message_create.recipient_id,
            content=message_create.content,
            message_type=message_create.message_type,
        )
        return MessageRepository.create(session, message)

    @staticmethod
    def get_message(session: Session, message_id: uuid.UUID) -> Message | None:
        """Get a message by ID."""
        return MessageRepository.get_by_id(session, message_id)

    @staticmethod
    def get_room_messages(
        session: Session,
        room_id: uuid.UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Message], int]:
        """Get all messages in a room."""
        return MessageRepository.get_room_messages(
            session, room_id, skip=skip, limit=limit
        )

    @staticmethod
    def get_direct_messages(
        session: Session,
        user_id: uuid.UUID,
        other_user_id: uuid.UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Message], int]:
        """Get direct messages between two users."""
        return MessageRepository.get_direct_messages(
            session, user_id, other_user_id, skip=skip, limit=limit
        )

    @staticmethod
    def mark_as_read(
        session: Session, message_id: uuid.UUID, user_id: uuid.UUID
    ) -> Message | None:
        """Mark a message as read."""
        message = MessageRepository.get_by_id(session, message_id)
        if not message:
            return None

        # Only recipient can mark as read
        if message.recipient_id == user_id:
            message.is_read = True
            return MessageRepository.update(session, message)

        return message

    @staticmethod
    def mark_direct_messages_as_read(
        session: Session, user_id: uuid.UUID, other_user_id: uuid.UUID
    ) -> int:
        """Mark all unread direct messages from other_user to user as read."""
        return MessageRepository.mark_direct_messages_as_read(
            session, user_id, other_user_id
        )

    @staticmethod
    def mark_room_messages_as_read(
        session: Session, room_id: uuid.UUID, user_id: uuid.UUID
    ) -> int:
        """Mark all unread messages in a room as read for the current user.
        Note: Room messages don't have a recipient_id, so we mark based on sender != user."""
        return MessageRepository.mark_room_messages_as_read(session, room_id, user_id)

    @staticmethod
    def delete_message(session: Session, message_id: uuid.UUID) -> bool:
        """Delete a message."""
        message = MessageRepository.get_by_id(session, message_id)
        if not message:
            return False

        MessageRepository.delete(session, message)
        return True

    @staticmethod
    def get_user_conversations(session: Session, user_id: uuid.UUID) -> list[dict]:
        """Get list of users that the given user has conversations with."""
        messages = MessageRepository.get_user_direct_messages(session, user_id)

        # Group by other user
        conversations = {}
        for message in messages:
            # Determine the other user
            other_user_id = (
                message.recipient_id
                if message.sender_id == user_id
                else message.sender_id
            )

            if other_user_id and other_user_id not in conversations:
                # Count unread messages from this user
                unread_count = MessageRepository.count_unread_direct_messages(
                    session, other_user_id, user_id
                )

                conversations[other_user_id] = {
                    "user_id": other_user_id,
                    "last_message": message.content,
                    "last_message_at": message.created_at,
                    "unread_count": unread_count,
                }

        return list(conversations.values())
