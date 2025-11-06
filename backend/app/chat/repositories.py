"""Repository layer for chat functionality."""
import uuid

from sqlalchemy import update
from sqlmodel import Session, and_, func, or_, select

from app.chat.models import Message, Room, RoomMember
from app.users.models import User


class RoomRepository:
    """Repository for database operations on Room model."""

    @staticmethod
    def create(session: Session, room: Room) -> Room:
        """Create a new room in database."""
        session.add(room)
        session.commit()
        session.refresh(room)
        return room

    @staticmethod
    def get_by_id(session: Session, room_id: uuid.UUID) -> Room | None:
        """Get a room by ID."""
        return session.get(Room, room_id)

    @staticmethod
    def get_all(
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
        statement = (
            select(Room)
            .join(RoomMember, Room.id == RoomMember.room_id)
            .where(RoomMember.user_id == user_id)
            .offset(skip)
            .limit(limit)
            .order_by(Room.created_at.desc())
        )
        rooms = list(session.exec(statement).all())

        count_statement = (
            select(func.count())
            .select_from(Room)
            .join(RoomMember, Room.id == RoomMember.room_id)
            .where(RoomMember.user_id == user_id)
        )
        count = session.exec(count_statement).one()

        return rooms, count

    @staticmethod
    def update(session: Session, room: Room) -> Room:
        """Update a room in database."""
        session.add(room)
        session.commit()
        session.refresh(room)
        return room

    @staticmethod
    def delete(session: Session, room: Room) -> None:
        """Delete a room from database."""
        session.delete(room)
        session.commit()


class RoomMemberRepository:
    """Repository for database operations on RoomMember model."""

    @staticmethod
    def create(session: Session, member: RoomMember) -> RoomMember:
        """Create a new room member in database."""
        session.add(member)
        session.commit()
        session.refresh(member)
        return member

    @staticmethod
    def get_by_room_and_user(
        session: Session, room_id: uuid.UUID, user_id: uuid.UUID
    ) -> RoomMember | None:
        """Get a room member by room_id and user_id."""
        statement = select(RoomMember).where(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
        )
        return session.exec(statement).first()

    @staticmethod
    def get_by_room(session: Session, room_id: uuid.UUID) -> list[RoomMember]:
        """Get all members of a room."""
        statement = select(RoomMember).where(RoomMember.room_id == room_id)
        return list(session.exec(statement).all())

    @staticmethod
    def get_admin_by_room_and_user(
        session: Session, room_id: uuid.UUID, user_id: uuid.UUID
    ) -> RoomMember | None:
        """Get an admin member by room_id and user_id."""
        statement = select(RoomMember).where(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user_id,
            RoomMember.is_admin.is_(True),
        )
        return session.exec(statement).first()

    @staticmethod
    def delete(session: Session, member: RoomMember) -> None:
        """Delete a room member from database."""
        session.delete(member)
        session.commit()


class MessageRepository:
    """Repository for database operations on Message model."""

    @staticmethod
    def create(session: Session, message: Message) -> Message:
        """Create a new message in database."""
        session.add(message)
        session.commit()
        session.refresh(message)
        return message

    @staticmethod
    def get_by_id(session: Session, message_id: uuid.UUID) -> Message | None:
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
    def get_user_direct_messages(
        session: Session, user_id: uuid.UUID
    ) -> list[Message]:
        """Get all direct messages for a user."""
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
        return list(session.exec(statement).all())

    @staticmethod
    def count_unread_direct_messages(
        session: Session, sender_id: uuid.UUID, recipient_id: uuid.UUID
    ) -> int:
        """Count unread direct messages from sender to recipient."""
        statement = (
            select(func.count())
            .select_from(Message)
            .where(
                Message.room_id.is_(None),
                Message.sender_id == sender_id,
                Message.recipient_id == recipient_id,
                Message.is_read.is_(False),
            )
        )
        return session.exec(statement).one()

    @staticmethod
    def update(session: Session, message: Message) -> Message:
        """Update a message in database."""
        session.add(message)
        session.commit()
        session.refresh(message)
        return message

    @staticmethod
    def mark_direct_messages_as_read(
        session: Session, user_id: uuid.UUID, other_user_id: uuid.UUID
    ) -> int:
        """Mark all unread direct messages from other_user to user as read."""
        statement = (
            update(Message)
            .where(
                Message.room_id.is_(None),
                Message.sender_id == other_user_id,
                Message.recipient_id == user_id,
                Message.is_read.is_(False),
            )
            .values(is_read=True)
        )
        result = session.exec(statement)
        session.commit()
        return result.rowcount  # type: ignore

    @staticmethod
    def mark_room_messages_as_read(
        session: Session, room_id: uuid.UUID, user_id: uuid.UUID
    ) -> int:
        """Mark all unread messages in a room as read for the current user."""
        statement = (
            update(Message)
            .where(
                Message.room_id == room_id,
                Message.sender_id != user_id,
                Message.is_read.is_(False),
            )
            .values(is_read=True)
        )
        result = session.exec(statement)
        session.commit()
        return result.rowcount  # type: ignore

    @staticmethod
    def delete(session: Session, message: Message) -> None:
        """Delete a message from database."""
        session.delete(message)
        session.commit()


class UserRepository:
    """Repository for database operations on User model for chat."""

    @staticmethod
    def get_by_id(session: Session, user_id: uuid.UUID) -> User | None:
        """Get a user by ID."""
        return session.get(User, user_id)

    @staticmethod
    def get_active_users_for_chat(
        session: Session,
        current_user_id: uuid.UUID,
        skip: int = 0,
        limit: int = 100,
        search: str = "",
    ) -> tuple[list[User], int]:
        """Get active users for chat with pagination and search."""
        query = select(User).where(
            User.id != current_user_id, User.is_active.is_(True)
        )

        if search:
            query = query.where(
                or_(
                    User.email.contains(search),
                    and_(
                        User.full_name.isnot(None),
                        User.full_name.contains(search)
                    )
                )
            )

        # Count
        count_query = (
            select(func.count())
            .select_from(User)
            .where(User.id != current_user_id, User.is_active.is_(True))
        )
        if search:
            count_query = count_query.where(
                or_(
                    User.email.contains(search),
                    and_(
                        User.full_name.isnot(None),
                        User.full_name.contains(search)
                    )
                )
            )
        count = session.exec(count_query).one()

        # Get users
        query = query.offset(skip).limit(limit).order_by(User.email)
        users = list(session.exec(query).all())

        return users, count

