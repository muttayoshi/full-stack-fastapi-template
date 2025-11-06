#!/usr/bin/env python3
"""Test script to verify mark as read functionality."""
import sys
from pathlib import Path

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from app.core.db import engine
from sqlmodel import Session, select
from app.chat.models import Message
from app.chat.services import MessageService
import uuid

def test_mark_as_read():
    """Test the mark as read functionality."""
    with Session(engine) as session:
        # Check all messages
        statement = select(Message)
        messages = session.exec(statement).all()

        print(f"Total messages in database: {len(messages)}")

        # Count unread messages
        unread_statement = select(Message).where(Message.is_read == False)
        unread_messages = session.exec(unread_statement).all()

        print(f"Unread messages: {len(unread_messages)}")

        # Show sample of unread messages
        for msg in unread_messages[:5]:
            print(f"  - Message ID: {msg.id}")
            print(f"    Sender: {msg.sender_id}")
            print(f"    Recipient: {msg.recipient_id}")
            print(f"    Room: {msg.room_id}")
            print(f"    Content: {msg.content[:50]}...")
            print(f"    Is Read: {msg.is_read}")
            print()

        if unread_messages:
            print("\nTesting mark_direct_messages_as_read...")
            # Get a sample direct message
            for msg in unread_messages:
                if msg.recipient_id and msg.sender_id:
                    count = MessageService.mark_direct_messages_as_read(
                        session, msg.recipient_id, msg.sender_id
                    )
                    print(f"Marked {count} messages as read from {msg.sender_id} to {msg.recipient_id}")
                    break

        # Check again
        unread_messages_after = session.exec(select(Message).where(Message.is_read == False)).all()
        print(f"\nUnread messages after marking: {len(unread_messages_after)}")

if __name__ == "__main__":
    test_mark_as_read()

