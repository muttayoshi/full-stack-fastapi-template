#!/usr/bin/env python3
"""Test script to verify mark as read functionality."""
import sys
from pathlib import Path

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from sqlmodel import Session, select

from app.chat.models import Message
from app.chat.services import MessageService
from app.core.db import engine


def test_mark_as_read():
    """Test the mark as read functionality."""
    with Session(engine) as session:
        # Check all messages
        statement = select(Message)
        session.exec(statement).all()

        # Count unread messages
        unread_statement = select(Message).where(Message.is_read == False)  # noqa: E712
        unread_messages = session.exec(unread_statement).all()

        if unread_messages:
            # Get a sample direct message
            for msg in unread_messages:
                if msg.recipient_id and msg.sender_id:
                    MessageService.mark_direct_messages_as_read(
                        session, msg.recipient_id, msg.sender_id
                    )
                    break

        # Check again
        session.exec(
            select(Message).where(Message.is_read == False)  # noqa: E712
        ).all()
