import uuid

from pydantic import BaseModel, EmailStr
from sqlmodel import Field, SQLModel


# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True, max_length=255)
    is_active: bool = True
    is_superuser: bool = False
    full_name: str | None = Field(default=None, max_length=255)
    google_id: str | None = Field(default=None, max_length=255)


# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserRegister(SQLModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on update, all are optional
class UserUpdate(UserBase):
    email: EmailStr | None = Field(default=None, max_length=255)  # type: ignore
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserUpdateMe(SQLModel):
    full_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = Field(default=None, max_length=255)


class UpdatePassword(SQLModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


# Properties to return via API, id is always required
class UserPublic(UserBase):
    id: uuid.UUID


class UsersPublic(SQLModel):
    data: list[UserPublic]
    count: int


# Authentication schemas


# JSON payload containing access token
class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# Contents of JWT token
class TokenPayload(SQLModel):
    sub: str | None = None


# Password reset schema
class NewPassword(SQLModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


# Google OAuth schemas
class GoogleAuthRequest(BaseModel):
    """Request schema for Google OAuth authentication"""

    code: str = Field(
        description="Authorization code from Google OAuth",
        min_length=1,
        max_length=2048,
    )


class GoogleAuthResponse(BaseModel):
    """Response schema for Google OAuth authentication"""

    access_token: str
    token_type: str = "bearer"
    user: "UserPublic"


# Base schema - shared properties
class RoleBase(SQLModel):
    name: str = Field(min_length=1, max_length=50, description="Role name")
    description: str | None = Field(default=None, max_length=255)
    is_active: bool = Field(default=True)


# Create request
class RoleCreate(RoleBase):
    pass


# Update request
class RoleUpdate(SQLModel):
    name: str | None = Field(default=None, min_length=1, max_length=50)
    description: str | None = None
    is_active: bool | None = None


# Public response
class RolePublic(RoleBase):
    id: uuid.UUID


# List response
class RolesPublic(SQLModel):
    data: list[RolePublic]
    count: int


# Base schema - shared properties
class UserRoleBase(SQLModel):
    user_id: uuid.UUID
    role_id: uuid.UUID
    site_id: uuid.UUID | None = Field(
        default=None, description="Site ID - if None, role applies to all sites"
    )
    is_active: bool = Field(default=True)


# Create request
class UserRoleCreate(UserRoleBase):
    pass


# Update request
class UserRoleUpdate(SQLModel):
    role_id: uuid.UUID | None = None
    site_id: uuid.UUID | None = None
    is_active: bool | None = None


# Public response
class UserRolePublic(UserRoleBase):
    id: uuid.UUID


# Public response with role details
class UserRoleWithDetails(SQLModel):
    id: uuid.UUID
    user_id: uuid.UUID
    role_id: uuid.UUID
    role_name: str
    site_id: uuid.UUID | None
    site_name: str | None = None
    is_active: bool


# List response
class UserRolesPublic(SQLModel):
    data: list[UserRolePublic]
    count: int
