#!/usr/bin/env python3
"""
Script untuk testing WebSocket Chat functionality
Testing:
1. Room discovery (show_all=true)
2. Join room
3. Leave room
4. Direct messaging
5. Get users list
6. Get conversations
"""

import logging

import requests

BASE_URL = "http://localhost:8000/api/v1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def login(email: str, password: str) -> str | None:
    """Login and get access token"""
    response = requests.post(
        f"{BASE_URL}/login/access-token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if response.status_code == 200:
        token = response.json()["access_token"]
        logger.info(f"Login successful for {email}")
        return token
    else:
        logger.warning(f"Login failed for {email}: {response.text}")
        return None


def create_room(token: str, name: str, is_private: bool = False) -> str | None:
    """Create a new room"""
    response = requests.post(
        f"{BASE_URL}/chat/rooms",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={
            "name": name,
            "description": f"Test room: {name}",
            "is_private": is_private,
        },
    )
    if response.status_code == 201:
        room_id = response.json()["id"]
        logger.info(f"Room created: {name} (ID: {room_id})")
        return room_id
    else:
        logger.warning(f"Failed to create room: {response.text}")
        return None


def get_all_rooms(token: str, show_all: bool = False):
    """Get all rooms"""
    params = {"show_all": "true"} if show_all else {}
    response = requests.get(
        f"{BASE_URL}/chat/rooms",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
    )
    if response.status_code == 200:
        data = response.json()
        logger.info(f"Got {data['count']} rooms (show_all={show_all})")
        # Remove print of each room for CI
        return data["data"]
    else:
        logger.warning(f"Failed to get rooms: {response.text}")
        return []


def join_room(token: str, room_id: str):
    """Join a room"""
    response = requests.post(
        f"{BASE_URL}/chat/rooms/{room_id}/join",
        headers={"Authorization": f"Bearer {token}"},
    )
    if response.status_code == 201:
        logger.info(f"Joined room: {room_id}")
        return True
    else:
        logger.warning(f"Failed to join room: {response.text}")
        return False


def leave_room(token: str, room_id: str):
    """Leave a room"""
    response = requests.post(
        f"{BASE_URL}/chat/rooms/{room_id}/leave",
        headers={"Authorization": f"Bearer {token}"},
    )
    if response.status_code == 204:
        logger.info(f"Left room: {room_id}")
        return True
    else:
        logger.warning(f"Failed to leave room: {response.text}")
        return False


def get_users(token: str, search: str = ""):
    """Get users for direct messaging"""
    params = {"search": search} if search else {}
    response = requests.get(
        f"{BASE_URL}/chat/users",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
    )
    if response.status_code == 200:
        data = response.json()
        logger.info(f"Got {data['count']} users")
        # Remove print of each user for CI
        return data["data"]
    else:
        logger.warning(f"Failed to get users: {response.text}")
        return []


def get_conversations(token: str):
    """Get conversations"""
    response = requests.get(
        f"{BASE_URL}/chat/conversations", headers={"Authorization": f"Bearer {token}"}
    )
    if response.status_code == 200:
        data = response.json()
        logger.info(f"Got {data['count']} conversations")
        # Remove print of each conversation for CI
        return data["data"]
    else:
        logger.warning(f"Failed to get conversations: {response.text}")
        return []


def test_scenario():
    """Test complete scenario"""
    logger.info("WEBSOCKET CHAT - TESTING SCENARIO")

    # Login as two different users
    token_a = login("admin@example.com", "changethis")
    if not token_a:
        logger.error("Cannot continue without User A token")
        return

    room_id = create_room(token_a, "Testing Room", is_private=False)
    if not room_id:
        logger.error("Cannot continue without room")
        return

    token_b = login("user@example.com", "password")
    if not token_b:
        logger.warning(
            "User B not found. Please create user@example.com via /docs endpoint first"
        )
        token_b = None

    if token_b:
        # Step 4: User B discovers all public rooms
        get_all_rooms(token_b, show_all=True)
        # Step 5: User B joins the room created by User A
        join_room(token_b, room_id)
        # Step 6: Verify User B is now a member
        get_all_rooms(token_b, show_all=True)
        # Step 7: User B leaves the room
        leave_room(token_b, room_id)
        # Step 8: Get users list for direct messaging
        get_users(token_a)
        # Step 9: Get conversations
        get_conversations(token_a)

    logger.info("Testing completed!")
    logger.info("Next steps:")
    logger.info("1. Open chat-demo-enhanced.html in two different browsers")
    logger.info("2. Login as different users")
    logger.info("3. Test room discovery, join, leave, and direct messaging")
    logger.info("4. Open WebSocket connection and send messages in real-time")


if __name__ == "__main__":
    try:
        test_scenario()
    except Exception as e:
        logger.error(f"Error during testing: {e}")
        import traceback

        traceback.print_exc()
