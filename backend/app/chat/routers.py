"""API routers for chat functionality."""
import json
import uuid
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from sqlmodel import Session

from app.api.deps import CurrentUser, SessionDep
from app.chat.schemas import (
    MessageCreate,
    MessagePublic,
    MessagesPublic,
    RoomCreate,
    RoomDetail,
    RoomMemberCreate,
    RoomMemberPublic,
    RoomPublic,
    RoomsPublic,
    RoomUpdate,
    WSMessage,
    WSResponse,
)
from app.chat.services import MessageService, RoomService
from app.chat.websocket import manager
from app.core import security
from app.core.config import settings
from app.users.models import User

router = APIRouter(prefix="/chat", tags=["chat"])


# ============================================================================
# WebSocket Endpoint
# ============================================================================


async def get_current_user_ws(
    token: str = Query(...),
    session: Session = Depends(SessionDep),
) -> User | None:
    """Get current user from WebSocket token.

    Note: WebSocket should be accepted before calling this function.
    """
    import logging

    import jwt
    from jwt.exceptions import InvalidTokenError
    from pydantic import ValidationError

    from app.users.schemas import TokenPayload

    logger = logging.getLogger(__name__)

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (InvalidTokenError, ValidationError) as e:
        logger.error("WebSocket auth failed - Invalid token: %s", e)
        return None

    user = session.get(User, token_data.sub)
    if not user:
        logger.error("WebSocket auth failed - User not found: %s", token_data.sub)
        return None
    if not user.is_active:
        logger.error("WebSocket auth failed - Inactive user: %s", user.email)
        return None

    logger.info("WebSocket auth successful - User: %s", user.email)
    return user


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
) -> None:
    """
    WebSocket endpoint for real-time chat.

    Connect with: ws://localhost:8000/api/v1/chat/ws?token=YOUR_JWT_TOKEN

    Message format:
    {
        "type": "message" | "join_room" | "leave_room" | "typing",
        "room_id": "uuid" (optional),
        "recipient_id": "uuid" (optional, for direct messages),
        "content": "message content",
        "message_type": "text" | "image" | "file"
    }
    """
    # Accept WebSocket connection first
    import logging

    from app.core.db import engine

    logger = logging.getLogger(__name__)

    await websocket.accept()
    logger.info("WebSocket connection accepted from client")

    # Create database session manually (will be used throughout the connection)

    db = Session(engine)

    try:
        # Authenticate user
        user = await get_current_user_ws(token, db)
        if not user:
            # User authentication failed, close connection with error
            logger.warning("Authentication failed, closing connection")
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Authentication failed"
            )
            return

        # Register user in connection manager (websocket already accepted)
        manager.active_connections[user.id] = websocket
        logger.info("User %s connected via WebSocket", user.email)

        # Send welcome message
        welcome_msg = WSResponse(
            type="connected",
            message=f"Welcome {user.full_name or user.email}!",
            data={"user_id": str(user.id)},
        )
        await manager.send_personal_message(
            welcome_msg.model_dump(mode="json"), user.id
        )

        # Main message loop
        try:
            while True:
                # Receive message
                data = await websocket.receive_text()

                try:
                    ws_msg = WSMessage(**json.loads(data))
                except Exception as e:
                    error_msg = WSResponse(
                        type="error",
                        message=f"Invalid message format: {str(e)}",
                    )
                    await manager.send_personal_message(
                        error_msg.model_dump(mode="json"), user.id
                    )
                    continue

                # Handle different message types
                if ws_msg.type == "message":
                    # Create message in database
                    if ws_msg.room_id:
                        # Room message
                        # Check if user is member of room
                        if not RoomService.is_user_member(db, ws_msg.room_id, user.id):
                            error_msg = WSResponse(
                                type="error",
                                message="You are not a member of this room",
                            )
                            await manager.send_personal_message(
                                error_msg.model_dump(mode="json"), user.id
                            )
                            continue

                        # Create message
                        message_create = MessageCreate(
                            room_id=ws_msg.room_id,
                            content=ws_msg.content or "",
                            message_type=ws_msg.message_type,
                        )
                        message = MessageService.create_message(
                            db, message_create, user.id
                        )

                        # Broadcast to room
                        response = WSResponse(
                            type="message",
                            data={
                                "id": str(message.id),
                                "room_id": str(message.room_id),
                                "sender_id": str(message.sender_id),
                                "sender_email": user.email,
                                "sender_full_name": user.full_name,
                                "content": message.content,
                                "message_type": message.message_type,
                                "created_at": message.created_at.isoformat(),
                            },
                        )
                        await manager.broadcast_to_room(
                            response.model_dump(mode="json"), ws_msg.room_id
                        )

                    elif ws_msg.recipient_id:
                        # Direct message
                        message_create = MessageCreate(
                            recipient_id=ws_msg.recipient_id,
                            content=ws_msg.content or "",
                            message_type=ws_msg.message_type,
                        )
                        message = MessageService.create_message(
                            db, message_create, user.id
                        )

                        # Send to recipient
                        response = WSResponse(
                            type="message",
                            data={
                                "id": str(message.id),
                                "sender_id": str(message.sender_id),
                                "sender_email": user.email,
                                "sender_full_name": user.full_name,
                                "recipient_id": str(message.recipient_id),
                                "content": message.content,
                                "message_type": message.message_type,
                                "created_at": message.created_at.isoformat(),
                            },
                        )
                        # Send to both sender and recipient
                        await manager.send_personal_message(
                            response.model_dump(mode="json"), user.id
                        )
                        await manager.send_personal_message(
                            response.model_dump(mode="json"), ws_msg.recipient_id
                        )

                elif ws_msg.type == "join_room":
                    if ws_msg.room_id:
                        # Check if user is member
                        if RoomService.is_user_member(db, ws_msg.room_id, user.id):
                            manager.subscribe_to_room(user.id, ws_msg.room_id)

                            # Notify room
                            response = WSResponse(
                                type="user_joined",
                                data={
                                    "room_id": str(ws_msg.room_id),
                                    "user_id": str(user.id),
                                    "user_email": user.email,
                                    "user_full_name": user.full_name,
                                },
                                message=f"{user.full_name or user.email} joined the room",
                            )
                            await manager.broadcast_to_room(
                                response.model_dump(mode="json"), ws_msg.room_id
                            )

                elif ws_msg.type == "leave_room":
                    if ws_msg.room_id:
                        # Unsubscribe from WebSocket room
                        manager.unsubscribe_from_room(user.id, ws_msg.room_id)

                        # Notify room
                        response = WSResponse(
                            type="user_left",
                            data={
                                "room_id": str(ws_msg.room_id),
                                "user_id": str(user.id),
                                "user_email": user.email,
                                "user_full_name": user.full_name,
                            },
                            message=f"{user.full_name or user.email} left the room",
                        )
                        await manager.broadcast_to_room(
                            response.model_dump(mode="json"), ws_msg.room_id
                        )

                        # Send confirmation to user
                        confirm_msg = WSResponse(
                            type="left_room",
                            data={"room_id": str(ws_msg.room_id)},
                            message="You left the room",
                        )
                        await manager.send_personal_message(
                            confirm_msg.model_dump(mode="json"), user.id
                        )

                elif ws_msg.type == "typing":
                    # Broadcast typing indicator
                    if ws_msg.room_id:
                        response = WSResponse(
                            type="typing",
                            data={
                                "room_id": str(ws_msg.room_id),
                                "user_id": str(user.id),
                                "user_email": user.email,
                                "user_full_name": user.full_name,
                            },
                        )
                        await manager.broadcast_to_room(
                            response.model_dump(mode="json"),
                            ws_msg.room_id,
                            exclude_user=user.id,
                        )

        except WebSocketDisconnect:
            manager.disconnect(user.id)
            logger.info("User %s disconnected", user.email)
        except Exception as e:
            manager.disconnect(user.id)
            logger.error("WebSocket error for user %s: %s", user.email, e)
    finally:
        # Close database session
        db.close()
        logger.debug("Database session closed")


# ============================================================================
# Room Endpoints
# ============================================================================


@router.post("/rooms", response_model=RoomPublic, status_code=status.HTTP_201_CREATED)
def create_room(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    room_in: RoomCreate,
) -> Any:
    """Create a new chat room."""
    room = RoomService.create_room(session, room_in, current_user.id)

    # Count members
    members = RoomService.get_room_members(session, room.id)

    return RoomPublic(
        id=room.id,
        name=room.name,
        description=room.description,
        is_private=room.is_private,
        created_by=room.created_by,
        created_at=room.created_at,
        member_count=len(members),
        is_member=True,  # Creator is always a member
    )


@router.get("/rooms", response_model=RoomsPublic)
def get_rooms(
    session: SessionDep,
    current_user: CurrentUser,
    skip: int = 0,
    limit: int = Query(default=100, le=100),
    show_all: bool = Query(
        default=False, description="Show all public rooms, not just user's rooms"
    ),
) -> Any:
    """Get all chat rooms. By default shows only public rooms. Use show_all=true to see all public rooms available."""
    if show_all:
        # Get all public rooms (including ones user is not a member of)
        rooms, count = RoomService.get_public_rooms(session, skip=skip, limit=limit)
    else:
        # Get only rooms user is a member of
        rooms, count = RoomService.get_user_rooms(
            session, current_user.id, skip=skip, limit=limit
        )

    # Add member count and is_member flag for each room
    rooms_public = []
    for room in rooms:
        members = RoomService.get_room_members(session, room.id)
        is_member = RoomService.is_user_member(session, room.id, current_user.id)
        rooms_public.append(
            RoomPublic(
                id=room.id,
                name=room.name,
                description=room.description,
                is_private=room.is_private,
                created_by=room.created_by,
                created_at=room.created_at,
                member_count=len(members),
                is_member=is_member,
            )
        )

    return RoomsPublic(data=rooms_public, count=count)


@router.get("/rooms/my", response_model=RoomsPublic)
def get_my_rooms(
    session: SessionDep,
    current_user: CurrentUser,
    skip: int = 0,
    limit: int = Query(default=100, le=100),
) -> Any:
    """Get rooms the current user is a member of."""
    rooms, count = RoomService.get_user_rooms(
        session, current_user.id, skip=skip, limit=limit
    )

    # Add member count for each room
    rooms_public = []
    for room in rooms:
        members = RoomService.get_room_members(session, room.id)
        rooms_public.append(
            RoomPublic(
                id=room.id,
                name=room.name,
                description=room.description,
                is_private=room.is_private,
                created_by=room.created_by,
                created_at=room.created_at,
                member_count=len(members),
                is_member=True,  # Always true for my rooms
            )
        )

    return RoomsPublic(data=rooms_public, count=count)


@router.get("/rooms/{room_id}", response_model=RoomDetail)
def get_room(
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
) -> Any:
    """Get a specific room with members."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if user is member (or if room is not private)
    is_member = RoomService.is_user_member(session, room_id, current_user.id)
    if room.is_private and not is_member and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied to private room")

    # Get members
    members = RoomService.get_room_members(session, room_id)
    members_public = []
    for member in members:
        user = session.get(User, member.user_id)
        members_public.append(
            RoomMemberPublic(
                id=member.id,
                user_id=member.user_id,
                joined_at=member.joined_at,
                is_admin=member.is_admin,
                user_email=user.email if user else None,
                user_full_name=user.full_name if user else None,
            )
        )

    return RoomDetail(
        id=room.id,
        name=room.name,
        description=room.description,
        is_private=room.is_private,
        created_by=room.created_by,
        created_at=room.created_at,
        member_count=len(members),
        members=members_public,
    )


@router.patch("/rooms/{room_id}", response_model=RoomPublic)
def update_room(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
    room_in: RoomUpdate,
) -> Any:
    """Update a room. Only admins can update."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if user is admin
    is_admin = RoomService.is_user_admin(session, room_id, current_user.id)
    if not is_admin and not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Not authorized to update this room"
        )

    room = RoomService.update_room(session, room_id, room_in)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    members = RoomService.get_room_members(session, room.id)
    is_member = RoomService.is_user_member(session, room.id, current_user.id)

    return RoomPublic(
        id=room.id,
        name=room.name,
        description=room.description,
        is_private=room.is_private,
        created_by=room.created_by,
        created_at=room.created_at,
        member_count=len(members),
        is_member=is_member,
    )


@router.delete("/rooms/{room_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_room(
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
) -> None:
    """Delete a room. Only creator or superuser can delete."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if user is creator or superuser
    if room.created_by != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this room"
        )

    RoomService.delete_room(session, room_id)


# ============================================================================
# Room Member Endpoints
# ============================================================================


@router.post(
    "/rooms/{room_id}/members",
    response_model=RoomMemberPublic,
    status_code=status.HTTP_201_CREATED,
)
def add_room_member(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
    member_in: RoomMemberCreate,
) -> Any:
    """Add a member to a room."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if current user is admin or adding themselves to non-private room
    is_admin = RoomService.is_user_admin(session, room_id, current_user.id)

    if room.is_private and not is_admin and not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Only admins can add members to private rooms"
        )

    # Verify user exists
    user = session.get(User, member_in.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    member = RoomService.add_member(session, room_id, member_in)
    if not member:
        raise HTTPException(status_code=400, detail="Failed to add member")

    return RoomMemberPublic(
        id=member.id,
        user_id=member.user_id,
        joined_at=member.joined_at,
        is_admin=member.is_admin,
        user_email=user.email,
        user_full_name=user.full_name,
    )


@router.post(
    "/rooms/{room_id}/join",
    response_model=RoomMemberPublic,
    status_code=status.HTTP_201_CREATED,
)
def join_room(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
) -> Any:
    """Join a room (shortcut for adding yourself as a member)."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if room is private
    if room.is_private:
        raise HTTPException(
            status_code=403, detail="Cannot join private room without invitation"
        )

    # Add current user as member
    member_in = RoomMemberCreate(user_id=current_user.id)
    member = RoomService.add_member(session, room_id, member_in)
    if not member:
        raise HTTPException(status_code=400, detail="Failed to join room")

    return RoomMemberPublic(
        id=member.id,
        user_id=member.user_id,
        joined_at=member.joined_at,
        is_admin=member.is_admin,
        user_email=current_user.email,
        user_full_name=current_user.full_name,
    )


@router.post("/rooms/{room_id}/leave", status_code=status.HTTP_204_NO_CONTENT)
def leave_room(
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
) -> None:
    """Leave a room (shortcut for removing yourself as a member)."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Don't allow removing the creator if they're the only admin
    if room.created_by == current_user.id:
        # Count admins
        members = RoomService.get_room_members(session, room_id)
        admin_count = sum(1 for m in members if m.is_admin)
        if admin_count == 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot leave room as the only admin. Please assign another admin first or delete the room.",
            )

    success = RoomService.remove_member(session, room_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="You are not a member of this room")


@router.delete(
    "/rooms/{room_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT
)
def remove_room_member(
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    """Remove a member from a room."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if current user is admin or removing themselves
    is_admin = RoomService.is_user_admin(session, room_id, current_user.id)
    is_self = user_id == current_user.id

    if not is_admin and not is_self and not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Not authorized to remove this member"
        )

    # Don't allow removing the creator if they're the only admin
    if room.created_by == user_id:
        # Count admins
        members = RoomService.get_room_members(session, room_id)
        admin_count = sum(1 for m in members if m.is_admin)
        if admin_count == 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the creator if they're the only admin",
            )

    success = RoomService.remove_member(session, room_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Member not found in room")


# ============================================================================
# Message Endpoints
# ============================================================================


@router.get("/rooms/{room_id}/messages", response_model=MessagesPublic)
def get_room_messages(
    session: SessionDep,
    current_user: CurrentUser,
    room_id: uuid.UUID,
    skip: int = 0,
    limit: int = Query(default=50, le=100),
) -> Any:
    """Get messages in a room."""
    room = RoomService.get_room(session, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if user is member
    is_member = RoomService.is_user_member(session, room_id, current_user.id)
    if not is_member and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="You are not a member of this room")

    messages, count = MessageService.get_room_messages(
        session, room_id, skip=skip, limit=limit
    )

    # Convert to public schema
    messages_public = []
    for message in messages:
        sender = session.get(User, message.sender_id)
        messages_public.append(
            MessagePublic(
                id=message.id,
                room_id=message.room_id,
                sender_id=message.sender_id,
                recipient_id=message.recipient_id,
                content=message.content,
                message_type=message.message_type,
                created_at=message.created_at,
                is_read=message.is_read,
                sender_email=sender.email if sender else None,
                sender_full_name=sender.full_name if sender else None,
            )
        )

    return MessagesPublic(data=messages_public, count=count)


@router.get("/messages/direct/{other_user_id}", response_model=MessagesPublic)
def get_direct_messages(
    session: SessionDep,
    current_user: CurrentUser,
    other_user_id: uuid.UUID,
    skip: int = 0,
    limit: int = Query(default=50, le=100),
) -> Any:
    """Get direct messages with another user."""
    # Verify other user exists
    other_user = session.get(User, other_user_id)
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    messages, count = MessageService.get_direct_messages(
        session, current_user.id, other_user_id, skip=skip, limit=limit
    )

    # Convert to public schema
    messages_public = []
    for message in messages:
        sender = session.get(User, message.sender_id)
        messages_public.append(
            MessagePublic(
                id=message.id,
                room_id=message.room_id,
                sender_id=message.sender_id,
                recipient_id=message.recipient_id,
                content=message.content,
                message_type=message.message_type,
                created_at=message.created_at,
                is_read=message.is_read,
                sender_email=sender.email if sender else None,
                sender_full_name=sender.full_name if sender else None,
            )
        )

    return MessagesPublic(data=messages_public, count=count)


@router.patch("/messages/{message_id}/read", response_model=MessagePublic)
def mark_message_as_read(
    session: SessionDep,
    current_user: CurrentUser,
    message_id: uuid.UUID,
) -> Any:
    """Mark a message as read."""
    message = MessageService.mark_as_read(session, message_id, current_user.id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    sender = session.get(User, message.sender_id)

    return MessagePublic(
        id=message.id,
        room_id=message.room_id,
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        content=message.content,
        message_type=message.message_type,
        created_at=message.created_at,
        is_read=message.is_read,
        sender_email=sender.email if sender else None,
        sender_full_name=sender.full_name if sender else None,
    )


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(
    session: SessionDep,
    current_user: CurrentUser,
    message_id: uuid.UUID,
) -> None:
    """Delete a message. Only sender or superuser can delete."""
    message = MessageService.get_message(session, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Check if user is sender or superuser
    if message.sender_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this message"
        )

    MessageService.delete_message(session, message_id)


# ============================================================================
# Direct Message / User Endpoints
# ============================================================================


@router.get("/users", response_model=Any)
def get_users_for_chat(
    session: SessionDep,
    current_user: CurrentUser,
    skip: int = 0,
    limit: int = Query(default=100, le=100),
    search: str = Query(default="", description="Search users by email or name"),
) -> Any:
    """Get users for direct messaging."""
    from sqlmodel import func, or_, select

    # Build query
    query = select(User).where(User.id != current_user.id, User.is_active.is_(True))

    # Add search filter if provided
    if search:
        query = query.where(
            or_(
                User.email.contains(search),
                User.full_name.contains(search)
                if User.full_name.isnot(None)
                else False,
            )
        )

    # Get count
    count_query = (
        select(func.count())
        .select_from(User)
        .where(User.id != current_user.id, User.is_active.is_(True))
    )
    if search:
        count_query = count_query.where(
            or_(
                User.email.contains(search),
                User.full_name.contains(search)
                if User.full_name.isnot(None)
                else False,
            )
        )
    count = session.exec(count_query).one()

    # Get users
    query = query.offset(skip).limit(limit).order_by(User.email)
    users = list(session.exec(query).all())

    # Format response
    users_data = [
        {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "is_online": manager.is_user_online(user.id),
        }
        for user in users
    ]

    return {"data": users_data, "count": count}


@router.get("/conversations", response_model=Any)
def get_conversations(
    session: SessionDep,
    current_user: CurrentUser,
) -> Any:
    """Get list of users that current user has direct message conversations with."""
    conversations = MessageService.get_user_conversations(session, current_user.id)

    # Format response with user details and last message
    conversations_data = []
    for conv in conversations:
        other_user = session.get(User, conv["user_id"])
        if other_user:
            conversations_data.append(
                {
                    "user_id": str(conv["user_id"]),
                    "user_email": other_user.email,
                    "user_full_name": other_user.full_name,
                    "last_message": conv["last_message"],
                    "last_message_at": conv["last_message_at"].isoformat()
                    if conv["last_message_at"]
                    else None,
                    "unread_count": conv["unread_count"],
                    "is_online": manager.is_user_online(conv["user_id"]),
                }
            )

    return {"data": conversations_data, "count": len(conversations_data)}
