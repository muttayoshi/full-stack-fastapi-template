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

import requests
import json
from typing import Optional

BASE_URL = "http://localhost:8000/api/v1"

def login(email: str, password: str) -> Optional[str]:
    """Login and get access token"""
    response = requests.post(
        f"{BASE_URL}/login/access-token",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if response.status_code == 200:
        token = response.json()["access_token"]
        print(f"✅ Login successful for {email}")
        return token
    else:
        print(f"❌ Login failed for {email}: {response.text}")
        return None

def create_room(token: str, name: str, is_private: bool = False) -> Optional[str]:
    """Create a new room"""
    response = requests.post(
        f"{BASE_URL}/chat/rooms",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "name": name,
            "description": f"Test room: {name}",
            "is_private": is_private
        }
    )
    if response.status_code == 201:
        room_id = response.json()["id"]
        print(f"✅ Room created: {name} (ID: {room_id})")
        return room_id
    else:
        print(f"❌ Failed to create room: {response.text}")
        return None

def get_all_rooms(token: str, show_all: bool = False):
    """Get all rooms"""
    params = {"show_all": "true"} if show_all else {}
    response = requests.get(
        f"{BASE_URL}/chat/rooms",
        headers={"Authorization": f"Bearer {token}"},
        params=params
    )
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Got {data['count']} rooms (show_all={show_all})")
        for room in data['data']:
            member_status = "✓ Member" if room.get('is_member') else "✗ Not member"
            print(f"   - {room['name']} ({member_status}, {room['member_count']} members)")
        return data['data']
    else:
        print(f"❌ Failed to get rooms: {response.text}")
        return []

def join_room(token: str, room_id: str):
    """Join a room"""
    response = requests.post(
        f"{BASE_URL}/chat/rooms/{room_id}/join",
        headers={"Authorization": f"Bearer {token}"}
    )
    if response.status_code == 201:
        print(f"✅ Joined room: {room_id}")
        return True
    else:
        print(f"❌ Failed to join room: {response.text}")
        return False

def leave_room(token: str, room_id: str):
    """Leave a room"""
    response = requests.post(
        f"{BASE_URL}/chat/rooms/{room_id}/leave",
        headers={"Authorization": f"Bearer {token}"}
    )
    if response.status_code == 204:
        print(f"✅ Left room: {room_id}")
        return True
    else:
        print(f"❌ Failed to leave room: {response.text}")
        return False

def get_users(token: str, search: str = ""):
    """Get users for direct messaging"""
    params = {"search": search} if search else {}
    response = requests.get(
        f"{BASE_URL}/chat/users",
        headers={"Authorization": f"Bearer {token}"},
        params=params
    )
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Got {data['count']} users")
        for user in data['data'][:5]:  # Show first 5
            status = "🟢 Online" if user.get('is_online') else "⚫ Offline"
            print(f"   - {user.get('full_name') or user['email']} ({status})")
        return data['data']
    else:
        print(f"❌ Failed to get users: {response.text}")
        return []

def get_conversations(token: str):
    """Get conversations"""
    response = requests.get(
        f"{BASE_URL}/chat/conversations",
        headers={"Authorization": f"Bearer {token}"}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Got {data['count']} conversations")
        for conv in data['data']:
            unread = f" ({conv['unread_count']} unread)" if conv['unread_count'] > 0 else ""
            print(f"   - {conv.get('user_full_name') or conv['user_email']}{unread}")
            print(f"     Last: {conv['last_message'][:50]}...")
        return data['data']
    else:
        print(f"❌ Failed to get conversations: {response.text}")
        return []

def test_scenario():
    """Test complete scenario"""
    print("\n" + "="*60)
    print("WEBSOCKET CHAT - TESTING SCENARIO")
    print("="*60 + "\n")

    # Login as two different users
    print("📝 Step 1: Login as User A (admin)")
    token_a = login("admin@example.com", "changethis")
    if not token_a:
        print("❌ Cannot continue without User A token")
        return

    print("\n📝 Step 2: Create a public room as User A")
    room_id = create_room(token_a, "Testing Room", is_private=False)
    if not room_id:
        print("❌ Cannot continue without room")
        return

    print("\n📝 Step 3: Login as User B")
    # Try to login as another user (you may need to create this user first)
    token_b = login("user@example.com", "password")
    if not token_b:
        print("⚠️  User B not found. Creating test user...")
        # You would need to create user first via /users endpoint
        print("   Please create user@example.com via /docs endpoint first")
        token_b = None

    if token_b:
        print("\n📝 Step 4: User B discovers all public rooms")
        rooms = get_all_rooms(token_b, show_all=True)

        print("\n📝 Step 5: User B joins the room created by User A")
        join_room(token_b, room_id)

        print("\n📝 Step 6: Verify User B is now a member")
        get_all_rooms(token_b, show_all=True)

        print("\n📝 Step 7: User B leaves the room")
        leave_room(token_b, room_id)

        print("\n📝 Step 8: Get users list for direct messaging")
        get_users(token_a)

        print("\n📝 Step 9: Get conversations")
        get_conversations(token_a)

    print("\n" + "="*60)
    print("✅ Testing completed!")
    print("="*60 + "\n")

    print("Next steps:")
    print("1. Open chat-demo-enhanced.html in two different browsers")
    print("2. Login as different users")
    print("3. Test room discovery, join, leave, and direct messaging")
    print("4. Open WebSocket connection and send messages in real-time")

if __name__ == "__main__":
    try:
        test_scenario()
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

