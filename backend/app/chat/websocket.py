"""WebSocket connection manager for chat functionality."""
import json
import uuid
from typing import Dict, Set

from fastapi import WebSocket


class ConnectionManager:
    """Manage WebSocket connections for chat."""

    def __init__(self) -> None:
        # Active connections: {user_id: WebSocket}
        self.active_connections: Dict[uuid.UUID, WebSocket] = {}
        # Room subscriptions: {room_id: {user_id, user_id, ...}}
        self.room_subscriptions: Dict[uuid.UUID, Set[uuid.UUID]] = {}

    async def connect(self, websocket: WebSocket, user_id: uuid.UUID) -> None:
        """Accept and store a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: uuid.UUID) -> None:
        """Remove a WebSocket connection."""
        if user_id in self.active_connections:
            del self.active_connections[user_id]

        # Remove user from all room subscriptions
        for room_id in list(self.room_subscriptions.keys()):
            if user_id in self.room_subscriptions[room_id]:
                self.room_subscriptions[room_id].discard(user_id)
                # Clean up empty rooms
                if not self.room_subscriptions[room_id]:
                    del self.room_subscriptions[room_id]

    def subscribe_to_room(self, user_id: uuid.UUID, room_id: uuid.UUID) -> None:
        """Subscribe a user to a room."""
        if room_id not in self.room_subscriptions:
            self.room_subscriptions[room_id] = set()
        self.room_subscriptions[room_id].add(user_id)

    def unsubscribe_from_room(self, user_id: uuid.UUID, room_id: uuid.UUID) -> None:
        """Unsubscribe a user from a room."""
        if room_id in self.room_subscriptions:
            self.room_subscriptions[room_id].discard(user_id)
            # Clean up empty rooms
            if not self.room_subscriptions[room_id]:
                del self.room_subscriptions[room_id]

    async def send_personal_message(
        self, message: dict, user_id: uuid.UUID
    ) -> bool:
        """Send a message to a specific user."""
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_text(json.dumps(message))
                return True
            except Exception:
                # Connection might be broken
                self.disconnect(user_id)
        return False

    async def broadcast_to_room(
        self, message: dict, room_id: uuid.UUID, exclude_user: uuid.UUID | None = None
    ) -> int:
        """Broadcast a message to all users in a room."""
        sent_count = 0
        if room_id not in self.room_subscriptions:
            return sent_count

        for user_id in list(self.room_subscriptions[room_id]):
            if exclude_user and user_id == exclude_user:
                continue

            if await self.send_personal_message(message, user_id):
                sent_count += 1

        return sent_count

    async def broadcast_to_all(self, message: dict) -> int:
        """Broadcast a message to all connected users."""
        sent_count = 0
        for user_id in list(self.active_connections.keys()):
            if await self.send_personal_message(message, user_id):
                sent_count += 1
        return sent_count

    def get_room_users(self, room_id: uuid.UUID) -> Set[uuid.UUID]:
        """Get all users subscribed to a room."""
        return self.room_subscriptions.get(room_id, set()).copy()

    def is_user_online(self, user_id: uuid.UUID) -> bool:
        """Check if a user is currently connected."""
        return user_id in self.active_connections

    def get_online_users(self) -> Set[uuid.UUID]:
        """Get all currently connected users."""
        return set(self.active_connections.keys())


# Global connection manager instance
manager = ConnectionManager()

