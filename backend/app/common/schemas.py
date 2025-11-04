"""Common schemas used across multiple domains."""

from sqlmodel import SQLModel


# Generic message schema
class Message(SQLModel):
    """Generic message response schema."""

    message: str


"""Common package - Contains shared/generic models and schemas used across the application."""


__all__ = [
    "Message",
]
