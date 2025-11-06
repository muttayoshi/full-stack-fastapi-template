import logging
import uuid
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlmodel import col, delete, func, select

from app.api.deps import (
    CurrentUser,
    SessionDep,
    get_current_active_superuser,
)
from app.common.schemas import Message
from app.core import security
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.items.models import Item
from app.users.models import User
from app.users.schemas import (
    GoogleAuthRequest,
    GoogleAuthResponse,
    NewPassword,
    Token,
    UpdatePassword,
    UserCreate,
    UserPublic,
    UserRegister,
    UsersPublic,
    UserUpdate,
    UserUpdateMe,
)
from app.users.services import OAuthService, UserService
from app.utils import (
    generate_new_account_email,
    generate_password_reset_token,
    generate_reset_password_email,
    send_email,
    verify_password_reset_token,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# OAuth router
oauth_router = APIRouter(prefix="/oauth", tags=["oauth"])

# Authentication endpoints
auth_router = APIRouter(tags=["login"])

users_router = APIRouter(prefix="/users", tags=["users"])


@auth_router.post("/login/access-token")
def login_access_token(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = UserService.authenticate(
        session=session, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=security.create_access_token(
            user.id, expires_delta=access_token_expires
        )
    )


@auth_router.post("/login/test-token", response_model=UserPublic)
def test_token(current_user: CurrentUser) -> Any:
    """
    Test access token
    """
    return current_user


@auth_router.post("/password-recovery/{email}")
def recover_password(email: str, session: SessionDep) -> Message:
    """
    Password Recovery
    """
    user = UserService.get_user_by_email(session=session, email=email)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    password_reset_token = generate_password_reset_token(email=email)
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )
    send_email(
        email_to=user.email,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return Message(message="Password recovery email sent")


@auth_router.post("/reset-password/")
def reset_password(session: SessionDep, body: NewPassword) -> Message:
    """
    Reset password
    """
    email = verify_password_reset_token(token=body.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = UserService.get_user_by_email(session=session, email=email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    hashed_password = get_password_hash(password=body.new_password)
    user.hashed_password = hashed_password
    session.add(user)
    session.commit()
    return Message(message="Password updated successfully")


@auth_router.post(
    "/password-recovery-html-content/{email}",
    dependencies=[Depends(get_current_active_superuser)],
    response_class=HTMLResponse,
)
def recover_password_html_content(email: str, session: SessionDep) -> Any:
    """
    HTML Content for Password Recovery
    """
    user = UserService.get_user_by_email(session=session, email=email)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this username does not exist in the system.",
        )
    password_reset_token = generate_password_reset_token(email=email)
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )

    return HTMLResponse(
        content=email_data.html_content, headers={"subject:": email_data.subject}
    )


# User management endpoints
@users_router.get(
    "/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UsersPublic,
)
def read_users(session: SessionDep, skip: int = 0, limit: int = 100) -> Any:
    """
    Retrieve users.
    """

    count_statement = select(func.count()).select_from(User)
    count = session.exec(count_statement).one()

    statement = select(User).offset(skip).limit(limit)
    users = session.exec(statement).all()

    return UsersPublic(data=users, count=count)


@users_router.post(
    "/", dependencies=[Depends(get_current_active_superuser)], response_model=UserPublic
)
def create_user(*, session: SessionDep, user_in: UserCreate) -> Any:
    """
    Create new user.
    """
    user = UserService.get_user_by_email(session=session, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )

    user = UserService.create_user(session=session, user_create=user_in)
    if settings.emails_enabled and user_in.email:
        email_data = generate_new_account_email(
            email_to=user_in.email, username=user_in.email, password=user_in.password
        )
        send_email(
            email_to=user_in.email,
            subject=email_data.subject,
            html_content=email_data.html_content,
        )
    return user


@users_router.patch("/me", response_model=UserPublic)
def update_user_me(
    *, session: SessionDep, user_in: UserUpdateMe, current_user: CurrentUser
) -> Any:
    """
    Update own user.
    """

    if user_in.email:
        existing_user = UserService.get_user_by_email(
            session=session, email=user_in.email
        )
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(
                status_code=409, detail="User with this email already exists"
            )
    user_data = user_in.model_dump(exclude_unset=True)
    current_user.sqlmodel_update(user_data)
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user


@users_router.patch("/me/password", response_model=Message)
def update_password_me(
    *, session: SessionDep, body: UpdatePassword, current_user: CurrentUser
) -> Any:
    """
    Update own password.
    """
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=400, detail="New password cannot be the same as the current one"
        )
    hashed_password = get_password_hash(body.new_password)
    current_user.hashed_password = hashed_password
    session.add(current_user)
    session.commit()
    return Message(message="Password updated successfully")


@users_router.get("/me", response_model=UserPublic)
def read_user_me(current_user: CurrentUser) -> Any:
    """
    Get current user.
    """
    return current_user


@users_router.delete("/me", response_model=Message)
def delete_user_me(session: SessionDep, current_user: CurrentUser) -> Any:
    """
    Delete own user.
    """
    if current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Super users are not allowed to delete themselves"
        )
    session.delete(current_user)
    session.commit()
    return Message(message="User deleted successfully")


@users_router.post("/signup", response_model=UserPublic)
def register_user(session: SessionDep, user_in: UserRegister) -> Any:
    """
    Create new user without the need to be logged in.
    """
    user = UserService.get_user_by_email(session=session, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system",
        )
    user_create = UserCreate.model_validate(user_in)
    user = UserService.create_user(session=session, user_create=user_create)
    return user


@users_router.get("/{user_id}", response_model=UserPublic)
def read_user_by_id(
    user_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> Any:
    """
    Get a specific user by id.
    """
    user = UserService.get_user_by_id(session=session, user_id=user_id)
    if user == current_user:
        return user
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="The user doesn't have enough privileges",
        )
    return user


@users_router.patch(
    "/{user_id}",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
)
def update_user(
    *,
    session: SessionDep,
    user_id: uuid.UUID,
    user_in: UserUpdate,
) -> Any:
    """
    Update a user.
    """

    db_user = UserService.get_user_by_id(session=session, user_id=user_id)
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="The user with this id does not exist in the system",
        )
    if user_in.email:
        existing_user = UserService.get_user_by_email(
            session=session, email=user_in.email
        )
        if existing_user and existing_user.id != user_id:
            raise HTTPException(
                status_code=409, detail="User with this email already exists"
            )

    db_user = UserService.update_user(session=session, db_user=db_user, user_in=user_in)
    return db_user


@users_router.delete("/{user_id}", dependencies=[Depends(get_current_active_superuser)])
def delete_user(
    session: SessionDep, current_user: CurrentUser, user_id: uuid.UUID
) -> Message:
    """
    Delete a user.
    """
    user = UserService.get_user_by_id(session=session, user_id=user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user == current_user:
        raise HTTPException(
            status_code=403, detail="Super users are not allowed to delete themselves"
        )
    statement = delete(Item).where(col(Item.owner_id) == user_id)
    session.exec(statement)  # type: ignore
    session.delete(user)
    session.commit()
    return Message(message="User deleted successfully")


# Private endpoints for local development
class PrivateUserCreate(BaseModel):
    email: str
    password: str
    full_name: str
    is_verified: bool = False


private_router = APIRouter(tags=["private"], prefix="/private")


@private_router.post("/users/", response_model=UserPublic)
def create_user_private(user_in: PrivateUserCreate, session: SessionDep) -> Any:
    """
    Create a new user.
    """

    user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
    )

    session.add(user)
    session.commit()

    return user


@oauth_router.post("/google", response_model=GoogleAuthResponse)
async def google_login(
    session: SessionDep, auth_request: GoogleAuthRequest
) -> GoogleAuthResponse:
    """
    Google OAuth Login

    Exchange Google authorization code for access token.
    This endpoint will:
    1. Validate the Google authorization code
    2. Get user info from Google
    3. Create new user or link Google account to existing user
    4. Return access token for the user

    Note: If user doesn't exist, a new account will be created automatically.
    """
    if not settings.google_oauth_enabled:
        logger.warning("Attempt to use Google OAuth when it's not configured")
        raise HTTPException(
            status_code=503,
            detail="Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.",
        )

    # Validate authorization code is not empty
    if not auth_request.code or not auth_request.code.strip():
        logger.warning("Empty authorization code received")
        raise HTTPException(
            status_code=400,
            detail="Authorization code is required",
        )

    oauth_service = OAuthService(session)

    try:
        # Exchange code for user info
        user_info = await oauth_service.exchange_google_code_for_user_info(
            auth_request.code
        )

        if not user_info:
            logger.warning("Failed to exchange Google authorization code")
            raise HTTPException(
                status_code=400,
                detail="Failed to authenticate with Google. Invalid or expired authorization code.",
            )

        # Verify email is verified by Google
        if not user_info.get("verified_email", False):
            logger.warning(
                "Unverified email attempted Google login",
                extra={"email": user_info.get("email")},
            )
            raise HTTPException(
                status_code=400,
                detail="Google account email is not verified. Please verify your email with Google first.",
            )

        # Create new user or link Google account to existing user
        user = oauth_service.create_or_link_google_account(
            google_id=user_info["google_id"],
            email=user_info["email"],
            full_name=user_info.get("full_name"),
        )

        if not user.is_active:
            logger.warning(
                "Inactive user attempted Google login",
                extra={"user_id": str(user.id), "email": user.email},
            )
            raise HTTPException(status_code=400, detail="Inactive user")

        # Generate access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = security.create_access_token(
            user.id, expires_delta=access_token_expires
        )

        logger.info(
            "User successfully authenticated via Google OAuth",
            extra={"user_id": str(user.id), "email": user.email},
        )

        return GoogleAuthResponse(
            access_token=access_token,
            token_type="bearer",
            user=UserPublic.model_validate(user),
        )

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(
            "Unexpected error during Google OAuth login",
            extra={"error": str(e), "error_type": type(e).__name__},
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during authentication. Please try again later.",
        )


# Include all routers in the main router
router.include_router(auth_router)
router.include_router(users_router)
router.include_router(oauth_router)

if settings.ENVIRONMENT == "local":
    router.include_router(private_router)
