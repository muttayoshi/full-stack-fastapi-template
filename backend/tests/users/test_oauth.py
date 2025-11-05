"""Tests for OAuth authentication endpoints"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.users.models import User
from app.users.services import OAuthService


def test_google_oauth_disabled(client: TestClient) -> None:
    """Test Google OAuth endpoint when OAuth is disabled"""
    with patch.object(settings, "google_oauth_enabled", False):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "test_code"}
        )
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"].lower()


def test_google_oauth_empty_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with empty code"""
    with patch.object(settings, "google_oauth_enabled", True):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": ""}
        )
        assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_google_oauth_invalid_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with invalid code"""
    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=None)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "invalid_code"}
            )
            assert response.status_code == 400
            assert "invalid" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_unverified_email(client: TestClient) -> None:
    """Test Google OAuth endpoint with unverified email"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "test@example.com",
        "full_name": "Test User",
        "verified_email": False,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 400
            assert "not verified" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_success_new_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login with new user creation"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "newuser@example.com",
        "full_name": "New User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
            assert data["user"]["email"] == "newuser@example.com"
            assert data["user"]["full_name"] == "New User"


@pytest.mark.asyncio
async def test_google_oauth_success_existing_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login linking to existing user"""
    # Create existing user
    existing_user = User(
        email="existing@example.com",
        hashed_password="hashed_password",
        full_name="Existing User",
        is_active=True,
    )
    db.add(existing_user)
    db.commit()

    mock_user_info = {
        "google_id": "987654321",
        "email": "existing@example.com",
        "full_name": "Existing User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["user"]["email"] == "existing@example.com"

            # Verify google_id was linked
            db.refresh(existing_user)
            assert existing_user.google_id == "987654321"


@pytest.mark.asyncio
async def test_google_oauth_inactive_user(
    client: TestClient, db: Session
) -> None:
    """Test Google OAuth login with inactive user"""
    # Create inactive user with Google ID
    inactive_user = User(
        email="inactive@example.com",
        hashed_password="hashed_password",
        full_name="Inactive User",
        google_id="111222333",
        is_active=False,
    )
    db.add(inactive_user)
    db.commit()

    mock_user_info = {
        "google_id": "111222333",
        "email": "inactive@example.com",
        "full_name": "Inactive User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 400
            assert "inactive" in response.json()["detail"].lower()


class TestOAuthService:
    """Test OAuthService class methods"""

    @pytest.mark.asyncio
    async def test_exchange_google_code_for_user_info_success(
        self, db: Session
    ) -> None:
        """Test successful exchange of Google code for user info"""
        oauth_service = OAuthService(db)

        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "test_token"}
        mock_token_response.raise_for_status = MagicMock()

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.json.return_value = {
            "id": "123456789",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }
        mock_userinfo_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_token_response
            )
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_userinfo_response
            )

            user_info = await oauth_service.exchange_google_code_for_user_info(
                "test_code"
            )

            assert user_info is not None
            assert user_info["google_id"] == "123456789"
            assert user_info["email"] == "test@example.com"
            assert user_info["full_name"] == "Test User"
            assert user_info["verified_email"] is True

    @pytest.mark.asyncio
    async def test_exchange_google_code_oauth_disabled(
        self, db: Session
    ) -> None:
        """Test exchange when OAuth is disabled"""
        oauth_service = OAuthService(db)

        with patch.object(settings, "GOOGLE_CLIENT_ID", None):
            with patch.object(settings, "GOOGLE_CLIENT_SECRET", None):
                user_info = await oauth_service.exchange_google_code_for_user_info(
                    "test_code"
                )
                assert user_info is None

    def test_create_or_link_google_account_new_user(
        self, db: Session
    ) -> None:
        """Test creating a new user from Google OAuth"""
        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="new_google_id",
            email="newuser@example.com",
            full_name="New User"
        )

        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.full_name == "New User"
        assert user.google_id == "new_google_id"
        assert user.is_active is True
        assert user.is_superuser is False

    def test_create_or_link_google_account_existing_user(
        self, db: Session
    ) -> None:
        """Test linking Google account to existing user"""
        # Create existing user without Google ID
        existing_user = User(
            email="existing@example.com",
            hashed_password="hashed_password",
            full_name="Existing User",
            is_active=True,
        )
        db.add(existing_user)
        db.commit()
        db.refresh(existing_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="linked_google_id",
            email="existing@example.com",
            full_name="Updated Name"
        )

        assert user.id == existing_user.id
        assert user.google_id == "linked_google_id"
        assert user.email == "existing@example.com"

    def test_create_or_link_google_account_already_linked(
        self, db: Session
    ) -> None:
        """Test login with already linked Google account"""
        # Create user with Google ID
        linked_user = User(
            email="linked@example.com",
            hashed_password="hashed_password",
            full_name="Linked User",
            google_id="already_linked_id",
            is_active=True,
        )
        db.add(linked_user)
        db.commit()
        db.refresh(linked_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="already_linked_id",
            email="linked@example.com",
            full_name="Linked User"
        )

        assert user.id == linked_user.id
        assert user.google_id == "already_linked_id"
"""Tests for OAuth authentication endpoints"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.users.models import User
from app.users.services import OAuthService


def test_google_oauth_disabled(client: TestClient) -> None:
    """Test Google OAuth endpoint when OAuth is disabled"""
    with patch.object(settings, "google_oauth_enabled", False):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "test_code"}
        )
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"].lower()


def test_google_oauth_empty_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with empty code"""
    with patch.object(settings, "google_oauth_enabled", True):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": ""}
        )
        assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_google_oauth_invalid_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with invalid code"""
    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=None)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "invalid_code"}
            )
            assert response.status_code == 400
            assert "invalid" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_unverified_email(client: TestClient) -> None:
    """Test Google OAuth endpoint with unverified email"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "test@example.com",
        "full_name": "Test User",
        "verified_email": False,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 400
            assert "not verified" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_success_new_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login with new user creation"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "newuser@example.com",
        "full_name": "New User",
        "verified_email": True,
    }

    with patch.object(
        OAuthService,
        "exchange_google_code_for_user_info",
        new=AsyncMock(return_value=mock_user_info)
    ):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "valid_code"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "newuser@example.com"
        assert data["user"]["full_name"] == "New User"


@pytest.mark.asyncio
async def test_google_oauth_success_existing_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login linking to existing user"""
    # Create existing user
    existing_user = User(
        email="existing@example.com",
        hashed_password="hashed_password",
        full_name="Existing User",
        is_active=True,
    )
    db.add(existing_user)
    db.commit()

    mock_user_info = {
        "google_id": "987654321",
        "email": "existing@example.com",
        "full_name": "Existing User",
        "verified_email": True,
    }

    with patch.object(
        OAuthService,
        "exchange_google_code_for_user_info",
        new=AsyncMock(return_value=mock_user_info)
    ):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "valid_code"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["email"] == "existing@example.com"

        # Verify google_id was linked
        db.refresh(existing_user)
        assert existing_user.google_id == "987654321"


@pytest.mark.asyncio
async def test_google_oauth_inactive_user(
    client: TestClient, db: Session
) -> None:
    """Test Google OAuth login with inactive user"""
    # Create inactive user with Google ID
    inactive_user = User(
        email="inactive@example.com",
        hashed_password="hashed_password",
        full_name="Inactive User",
        google_id="111222333",
        is_active=False,
    )
    db.add(inactive_user)
    db.commit()

    mock_user_info = {
        "google_id": "111222333",
        "email": "inactive@example.com",
        "full_name": "Inactive User",
        "verified_email": True,
    }

    with patch.object(
        OAuthService,
        "exchange_google_code_for_user_info",
        new=AsyncMock(return_value=mock_user_info)
    ):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "valid_code"}
        )
        assert response.status_code == 400
        assert "inactive" in response.json()["detail"].lower()


class TestOAuthService:
    """Test OAuthService class methods"""

    @pytest.mark.asyncio
    async def test_exchange_google_code_for_user_info_success(
        self, db: Session
    ) -> None:
        """Test successful exchange of Google code for user info"""
        oauth_service = OAuthService(db)

        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "test_token"}
        mock_token_response.raise_for_status = MagicMock()

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.json.return_value = {
            "id": "123456789",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }
        mock_userinfo_response.raise_for_status = MagicMock()

        with patch.object(settings, "google_oauth_enabled", True):
            with patch("httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_token_response
                )
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                    return_value=mock_userinfo_response
                )

                user_info = await oauth_service.exchange_google_code_for_user_info(
                    "test_code"
                )

                assert user_info is not None
                assert user_info["google_id"] == "123456789"
                assert user_info["email"] == "test@example.com"
                assert user_info["full_name"] == "Test User"
                assert user_info["verified_email"] is True

    @pytest.mark.asyncio
    async def test_exchange_google_code_oauth_disabled(
        self, db: Session
    ) -> None:
        """Test exchange when OAuth is disabled"""
        oauth_service = OAuthService(db)

        with patch.object(settings, "google_oauth_enabled", False):
            user_info = await oauth_service.exchange_google_code_for_user_info(
                "test_code"
            )
            assert user_info is None

    def test_create_or_link_google_account_new_user(
        self, db: Session
    ) -> None:
        """Test creating a new user from Google OAuth"""
        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="new_google_id",
            email="newuser@example.com",
            full_name="New User"
        )

        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.full_name == "New User"
        assert user.google_id == "new_google_id"
        assert user.is_active is True
        assert user.is_superuser is False

    def test_create_or_link_google_account_existing_user(
        self, db: Session
    ) -> None:
        """Test linking Google account to existing user"""
        # Create existing user without Google ID
        existing_user = User(
            email="existing@example.com",
            hashed_password="hashed_password",
            full_name="Existing User",
            is_active=True,
        )
        db.add(existing_user)
        db.commit()
        db.refresh(existing_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="linked_google_id",
            email="existing@example.com",
            full_name="Updated Name"
        )

        assert user.id == existing_user.id
        assert user.google_id == "linked_google_id"
        assert user.email == "existing@example.com"

    def test_create_or_link_google_account_already_linked(
        self, db: Session
    ) -> None:
        """Test login with already linked Google account"""
        # Create user with Google ID
        linked_user = User(
            email="linked@example.com",
            hashed_password="hashed_password",
            full_name="Linked User",
            google_id="already_linked_id",
            is_active=True,
        )
        db.add(linked_user)
        db.commit()
        db.refresh(linked_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="already_linked_id",
            email="linked@example.com",
            full_name="Linked User"
        )

        assert user.id == linked_user.id
        assert user.google_id == "already_linked_id"
"""Tests for OAuth authentication endpoints"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.users.models import User
from app.users.services import OAuthService


def test_google_oauth_disabled(client: TestClient) -> None:
    """Test Google OAuth endpoint when OAuth is disabled"""
    with patch.object(settings, "google_oauth_enabled", False):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "test_code"}
        )
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"].lower()


def test_google_oauth_empty_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with empty code"""
    with patch.object(settings, "google_oauth_enabled", True):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": ""}
        )
        assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_google_oauth_invalid_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with invalid code"""
    with patch.object(
        OAuthService,
        "exchange_google_code_for_user_info",
        new=AsyncMock(return_value=None)
    ):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "invalid_code"}
        )
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_unverified_email(client: TestClient) -> None:
    """Test Google OAuth endpoint with unverified email"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "test@example.com",
        "full_name": "Test User",
        "verified_email": False,
    }

    with patch.object(
        OAuthService,
        "exchange_google_code_for_user_info",
        new=AsyncMock(return_value=mock_user_info)
    ):
        response = client.post(
            "/api/v1/users/oauth/google",
            json={"code": "valid_code"}
        )
        assert response.status_code == 400
        assert "not verified" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_success_new_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login with new user creation"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "newuser@example.com",
        "full_name": "New User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
            assert data["user"]["email"] == "newuser@example.com"
            assert data["user"]["full_name"] == "New User"


@pytest.mark.asyncio
async def test_google_oauth_success_existing_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login linking to existing user"""
    # Create existing user
    existing_user = User(
        email="existing@example.com",
        hashed_password="hashed_password",
        full_name="Existing User",
        is_active=True,
    )
    db.add(existing_user)
    db.commit()

    mock_user_info = {
        "google_id": "987654321",
        "email": "existing@example.com",
        "full_name": "Existing User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["user"]["email"] == "existing@example.com"

            # Verify google_id was linked
            db.refresh(existing_user)
            assert existing_user.google_id == "987654321"


@pytest.mark.asyncio
async def test_google_oauth_inactive_user(
    client: TestClient, db: Session
) -> None:
    """Test Google OAuth login with inactive user"""
    # Create inactive user with Google ID
    inactive_user = User(
        email="inactive@example.com",
        hashed_password="hashed_password",
        full_name="Inactive User",
        google_id="111222333",
        is_active=False,
    )
    db.add(inactive_user)
    db.commit()

    mock_user_info = {
        "google_id": "111222333",
        "email": "inactive@example.com",
        "full_name": "Inactive User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 400
            assert "inactive" in response.json()["detail"].lower()


class TestOAuthService:
    """Test OAuthService class methods"""

    @pytest.mark.asyncio
    async def test_exchange_google_code_for_user_info_success(
        self, db: Session
    ) -> None:
        """Test successful exchange of Google code for user info"""
        oauth_service = OAuthService(db)

        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "test_token"}
        mock_token_response.raise_for_status = MagicMock()

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.json.return_value = {
            "id": "123456789",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }
        mock_userinfo_response.raise_for_status = MagicMock()

        with patch.object(settings, "google_oauth_enabled", True):
            with patch("httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_token_response
                )
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                    return_value=mock_userinfo_response
                )

                user_info = await oauth_service.exchange_google_code_for_user_info(
                    "test_code"
                )

                assert user_info is not None
                assert user_info["google_id"] == "123456789"
                assert user_info["email"] == "test@example.com"
                assert user_info["full_name"] == "Test User"
                assert user_info["verified_email"] is True

    @pytest.mark.asyncio
    async def test_exchange_google_code_oauth_disabled(
        self, db: Session
    ) -> None:
        """Test exchange when OAuth is disabled"""
        oauth_service = OAuthService(db)

        with patch.object(settings, "google_oauth_enabled", False):
            user_info = await oauth_service.exchange_google_code_for_user_info(
                "test_code"
            )
            assert user_info is None

    def test_create_or_link_google_account_new_user(
        self, db: Session
    ) -> None:
        """Test creating a new user from Google OAuth"""
        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="new_google_id",
            email="newuser@example.com",
            full_name="New User"
        )

        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.full_name == "New User"
        assert user.google_id == "new_google_id"
        assert user.is_active is True
        assert user.is_superuser is False

    def test_create_or_link_google_account_existing_user(
        self, db: Session
    ) -> None:
        """Test linking Google account to existing user"""
        # Create existing user without Google ID
        existing_user = User(
            email="existing@example.com",
            hashed_password="hashed_password",
            full_name="Existing User",
            is_active=True,
        )
        db.add(existing_user)
        db.commit()
        db.refresh(existing_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="linked_google_id",
            email="existing@example.com",
            full_name="Updated Name"
        )

        assert user.id == existing_user.id
        assert user.google_id == "linked_google_id"
        assert user.email == "existing@example.com"

    def test_create_or_link_google_account_already_linked(
        self, db: Session
    ) -> None:
        """Test login with already linked Google account"""
        # Create user with Google ID
        linked_user = User(
            email="linked@example.com",
            hashed_password="hashed_password",
            full_name="Linked User",
            google_id="already_linked_id",
            is_active=True,
        )
        db.add(linked_user)
        db.commit()
        db.refresh(linked_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="already_linked_id",
            email="linked@example.com",
            full_name="Linked User"
        )

        assert user.id == linked_user.id
        assert user.google_id == "already_linked_id"
"""Tests for OAuth authentication endpoints"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.users.models import User
from app.users.services import OAuthService


def test_google_oauth_disabled(client: TestClient) -> None:
    """Test Google OAuth endpoint when OAuth is disabled"""
    # Mock the underlying env vars to make google_oauth_enabled False
    with patch.object(settings, "GOOGLE_CLIENT_ID", None):
        with patch.object(settings, "GOOGLE_CLIENT_SECRET", None):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "test_code"}
            )
            assert response.status_code == 503
            assert "not configured" in response.json()["detail"].lower()


def test_google_oauth_empty_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with empty code"""
    response = client.post(
        "/api/v1/users/oauth/google",
        json={"code": ""}
    )
    assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_google_oauth_invalid_code(client: TestClient) -> None:
    """Test Google OAuth endpoint with invalid code"""
    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=None)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "invalid_code"}
            )
            assert response.status_code == 400
            assert "invalid" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_unverified_email(client: TestClient) -> None:
    """Test Google OAuth endpoint with unverified email"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "test@example.com",
        "full_name": "Test User",
        "verified_email": False,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 400
            assert "not verified" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_google_oauth_success_new_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login with new user creation"""
    mock_user_info = {
        "google_id": "123456789",
        "email": "newuser@example.com",
        "full_name": "New User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
            assert data["user"]["email"] == "newuser@example.com"
            assert data["user"]["full_name"] == "New User"


@pytest.mark.asyncio
async def test_google_oauth_success_existing_user(
    client: TestClient, db: Session
) -> None:
    """Test successful Google OAuth login linking to existing user"""
    # Create existing user
    existing_user = User(
        email="existing@example.com",
        hashed_password="hashed_password",
        full_name="Existing User",
        is_active=True,
    )
    db.add(existing_user)
    db.commit()

    mock_user_info = {
        "google_id": "987654321",
        "email": "existing@example.com",
        "full_name": "Existing User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["user"]["email"] == "existing@example.com"

            # Verify google_id was linked
            db.refresh(existing_user)
            assert existing_user.google_id == "987654321"


@pytest.mark.asyncio
async def test_google_oauth_inactive_user(
    client: TestClient, db: Session
) -> None:
    """Test Google OAuth login with inactive user"""
    # Create inactive user with Google ID
    inactive_user = User(
        email="inactive@example.com",
        hashed_password="hashed_password",
        full_name="Inactive User",
        google_id="111222333",
        is_active=False,
    )
    db.add(inactive_user)
    db.commit()

    mock_user_info = {
        "google_id": "111222333",
        "email": "inactive@example.com",
        "full_name": "Inactive User",
        "verified_email": True,
    }

    with patch.object(settings, "google_oauth_enabled", True):
        with patch.object(
            OAuthService,
            "exchange_google_code_for_user_info",
            new=AsyncMock(return_value=mock_user_info)
        ):
            response = client.post(
                "/api/v1/users/oauth/google",
                json={"code": "valid_code"}
            )
            assert response.status_code == 400
            assert "inactive" in response.json()["detail"].lower()


class TestOAuthService:
    """Test OAuthService class methods"""

    @pytest.mark.asyncio
    async def test_exchange_google_code_for_user_info_success(
        self, db: Session
    ) -> None:
        """Test successful exchange of Google code for user info"""
        oauth_service = OAuthService(db)

        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "test_token"}
        mock_token_response.raise_for_status = MagicMock()

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.json.return_value = {
            "id": "123456789",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }
        mock_userinfo_response.raise_for_status = MagicMock()

        with patch.object(settings, "google_oauth_enabled", True):
            with patch("httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_token_response
                )
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                    return_value=mock_userinfo_response
                )

                user_info = await oauth_service.exchange_google_code_for_user_info(
                    "test_code"
                )

                assert user_info is not None
                assert user_info["google_id"] == "123456789"
                assert user_info["email"] == "test@example.com"
                assert user_info["full_name"] == "Test User"
                assert user_info["verified_email"] is True

    @pytest.mark.asyncio
    async def test_exchange_google_code_oauth_disabled(
        self, db: Session
    ) -> None:
        """Test exchange when OAuth is disabled"""
        oauth_service = OAuthService(db)

        with patch.object(settings, "google_oauth_enabled", False):
            user_info = await oauth_service.exchange_google_code_for_user_info(
                "test_code"
            )
            assert user_info is None

    def test_create_or_link_google_account_new_user(
        self, db: Session
    ) -> None:
        """Test creating a new user from Google OAuth"""
        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="new_google_id",
            email="newuser@example.com",
            full_name="New User"
        )

        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.full_name == "New User"
        assert user.google_id == "new_google_id"
        assert user.is_active is True
        assert user.is_superuser is False

    def test_create_or_link_google_account_existing_user(
        self, db: Session
    ) -> None:
        """Test linking Google account to existing user"""
        # Create existing user without Google ID
        existing_user = User(
            email="existing@example.com",
            hashed_password="hashed_password",
            full_name="Existing User",
            is_active=True,
        )
        db.add(existing_user)
        db.commit()
        db.refresh(existing_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="linked_google_id",
            email="existing@example.com",
            full_name="Updated Name"
        )

        assert user.id == existing_user.id
        assert user.google_id == "linked_google_id"
        assert user.email == "existing@example.com"

    def test_create_or_link_google_account_already_linked(
        self, db: Session
    ) -> None:
        """Test login with already linked Google account"""
        # Create user with Google ID
        linked_user = User(
            email="linked@example.com",
            hashed_password="hashed_password",
            full_name="Linked User",
            google_id="already_linked_id",
            is_active=True,
        )
        db.add(linked_user)
        db.commit()
        db.refresh(linked_user)

        oauth_service = OAuthService(db)

        user = oauth_service.create_or_link_google_account(
            google_id="already_linked_id",
            email="linked@example.com",
            full_name="Linked User"
        )

        assert user.id == linked_user.id
        assert user.google_id == "already_linked_id"

