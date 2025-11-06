"""Service layer for chat functionality."""
import uuid

from sqlmodel import Session, func, select

from app.chat.models import Message, Room, RoomMember
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
        session.add(room)
        session.commit()
        session.refresh(room)

        # Add creator as admin member
        member = RoomMember(
            room_id=room.id,
            user_id=creator_id,
            is_admin=True,
        )
        session.add(member)
        session.commit()

        return room

    @staticmethod
    def get_room(session: Session, room_id: uuid.UUID) -> Room | None:
        """Get a room by ID."""
        return session.get(Room, room_id)

    @staticmethod
    def get_rooms(
        session: Session, skip: int = 0, limit: int = 100
    ) -> tuple[list[Room], int]:
        """Get all rooms with pagination."""
        count_statement = select(func.count()).select_from(Room)
        count = session.exec(count_statement).one()

        statement = (
            select(Room).offset(skip).limit(limit).order_by(Room.created_at.desc())
        )
        rooms = list(session.exec(statement).all())

        return rooms, count

    @staticmethod
    def get_public_rooms(
        session: Session, skip: int = 0, limit: int = 100
    ) -> tuple[list[Room], int]:
        """Get all public (non-private) rooms with pagination."""
        count_statement = (
            select(func.count()).select_from(Room).where(Room.is_private.is_(False))
        )
        count = session.exec(count_statement).one()

        statement = (
            select(Room)
            .where(Room.is_private.is_(False))
            .offset(skip)
            .limit(limit)
            .order_by(Room.created_at.desc())
        )
        rooms = list(session.exec(statement).all())

        return rooms, count

    @staticmethod
    def get_user_rooms(
        session: Session, user_id: uuid.UUID, skip: int = 0, limit: int = 100
    ) -> tuple[list[Room], int]:
        """Get all rooms a user is a member of."""
        # Join Room with RoomMember to get user's rooms
        statement = (
            select(Room)
            .join(RoomMember, Room.id == RoomMember.room_id)
            .where(RoomMember.user_id == user_id)
            .offset(skip)
            .limit(limit)
            .order_by(Room.created_at.desc())
        )
        rooms = list(session.exec(statement).all())

        # Count total
        count_statement = (
            select(func.count())
            .select_from(Room)
            .join(RoomMember, Room.id == RoomMember.room_id)
            .where(RoomMember.user_id == user_id)
        )
        count = session.exec(count_statement).one()

        return rooms, count

    @staticmethod
    def update_room(
        session: Session, room_id: uuid.UUID, room_update: RoomUpdate
    ) -> Room | None:
        """Update a room."""
        room = session.get(Room, room_id)
        if not room:
            return None

        update_data = room_update.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(room, key, value)

        session.add(room)
        session.commit()
        session.refresh(room)
        return room

    @staticmethod
    def delete_room(session: Session, room_id: uuid.UUID) -> bool:
        """Delete a room."""
        room = session.get(Room, room_id)
        if not room:
            return False

        session.delete(room)
        session.commit()
        return True

    @staticmethod
    def add_member(
        session: Session, room_id: uuid.UUID, member_create: RoomMemberCreate
    ) -> RoomMember | None:
        """Add a member to a room."""
        # Check if user is already a member
        statement = select(RoomMember).where(
            RoomMember.room_id == room_id,
            RoomMember.user_id == member_create.user_id,
        )
        existing = session.exec(statement).first()
        if existing:
            return existing

        member = RoomMember(
            room_id=room_id,
            user_id=member_create.user_id,
        )
        session.add(member)
        session.commit()
        session.refresh(member)
        return member

    @staticmethod
    def remove_member(session: Session, room_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Remove a member from a room."""
        statement = select(RoomMember).where(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
        )
        member = session.exec(statement).first()
        if not member:
            return False

        session.delete(member)
        session.commit()
        return True

    @staticmethod
    def get_room_members(session: Session, room_id: uuid.UUID) -> list[RoomMember]:
        """Get all members of a room."""
        statement = select(RoomMember).where(RoomMember.room_id == room_id)
        return list(session.exec(statement).all())

    @staticmethod
    def is_user_member(
        session: Session, room_id: uuid.UUID, user_id: uuid.UUID
    ) -> bool:
        """Check if a user is a member of a room."""
        statement = select(RoomMember).where(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
        )
        return session.exec(statement).first() is not None

    @staticmethod
    def is_user_admin(session: Session, room_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Check if a user is an admin of a room."""
        statement = select(RoomMember).where(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
            RoomMember.is_admin.is_(True),
        )
        return session.exec(statement).first() is not None


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
        session.add(message)
        session.commit()
        session.refresh(message)
        return message

    @staticmethod
    def get_message(session: Session, message_id: uuid.UUID) -> Message | None:
        """Get a message by ID."""
        return session.get(Message, message_id)

    @staticmethod
    def get_room_messages(
        session: Session,
        room_id: uuid.UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Message], int]:
        """Get all messages in a room."""
        count_statement = (
            select(func.count()).select_from(Message).where(Message.room_id == room_id)
        )
        count = session.exec(count_statement).one()

        statement = (
            select(Message)
            .where(Message.room_id == room_id)
            .order_by(Message.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        messages = list(session.exec(statement).all())

        return messages, count

    @staticmethod
    def get_direct_messages(
        session: Session,
        user_id: uuid.UUID,
        other_user_id: uuid.UUID,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Message], int]:
        """Get direct messages between two users."""
        # Messages where user is sender and other is recipient OR vice versa
        count_statement = (
            select(func.count())
            .select_from(Message)
            .where(
                Message.room_id.is_(None),
                (
                    (
                        (Message.sender_id == user_id)
                        & (Message.recipient_id == other_user_id)
                    )
                    | (
                        (Message.sender_id == other_user_id)
                        & (Message.recipient_id == user_id)
                    )
                ),
            )
        )
        count = session.exec(count_statement).one()

        statement = (
            select(Message)
            .where(
                Message.room_id.is_(None),
                (
                    (
                        (Message.sender_id == user_id)
                        & (Message.recipient_id == other_user_id)
                    )
                    | (
                        (Message.sender_id == other_user_id)
                        & (Message.recipient_id == user_id)
                    )
                ),
            )
            .order_by(Message.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        messages = list(session.exec(statement).all())

        return messages, count

    @staticmethod
    def mark_as_read(
        session: Session, message_id: uuid.UUID, user_id: uuid.UUID
    ) -> Message | None:
        """Mark a message as read."""
        message = session.get(Message, message_id)
        if not message:
            return None

        # Only recipient can mark as read
        if message.recipient_id == user_id:
            message.is_read = True
            session.add(message)
            session.commit()
            session.refresh(message)

        return message

    @staticmethod
    def delete_message(session: Session, message_id: uuid.UUID) -> bool:
        """Delete a message."""
        message = session.get(Message, message_id)
        if not message:
            return False

        session.delete(message)
        session.commit()
        return True

    @staticmethod
    def get_user_conversations(session: Session, user_id: uuid.UUID) -> list[dict]:
        """Get list of users that the given user has conversations with."""
        from sqlmodel import or_

        # Get all users that have direct messages with current user
        # Messages where user is sender or recipient
        statement = (
            select(Message)
            .where(
                Message.room_id.is_(None),
                or_(
                    Message.sender_id == user_id,
                    Message.recipient_id == user_id,
                ),
            )
            .order_by(Message.created_at.desc())
        )
        messages = list(session.exec(statement).all())

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
                unread_statement = (
                    select(func.count())
                    .select_from(Message)
                    .where(
                        Message.room_id.is_(None),
                        Message.sender_id == other_user_id,
                        Message.recipient_id == user_id,
                        Message.is_read.is_(False),
                    )
                )
                unread_count = session.exec(unread_statement).one()

                conversations[other_user_id] = {
                    "user_id": other_user_id,
                    "last_message": message.content,
                    "last_message_at": message.created_at,
                    "unread_count": unread_count,
                }

        return list(conversations.values())
