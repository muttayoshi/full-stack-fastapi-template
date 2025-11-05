"""
Unit tests for OAuth service
"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import HTTPStatusError, RequestError, Response
from sqlmodel import Session

from app.core.security import verify_password
from app.users.models import User
from app.users.services import OAuthService


@pytest.fixture
def mock_session():
    """Create a mock database session"""
    return MagicMock(spec=Session)


@pytest.fixture
def oauth_service(mock_session):
    """Create an OAuthService instance with mock session"""
    return OAuthService(mock_session)


@pytest.fixture
def mock_google_user_info():
    """Sample Google user info response"""
    return {
        "google_id": "123456789",
        "email": "test@example.com",
        "full_name": "Test User",
        "picture": "https://example.com/photo.jpg",
        "verified_email": True,
    }


class TestOAuthService:
    """Test cases for OAuthService"""

    def test_link_google_account_existing_google_id(self, oauth_service, mock_session):
        """Test linking when user with google_id already exists"""
        existing_user = User(
            id=uuid.uuid4(),
            email="test@example.com",
            google_id="123456789",
            hashed_password="hashed",
            full_name="Test User",
        )

        with patch("app.users.repositories.get_user_by_google_id", return_value=existing_user):
            result = oauth_service.link_google_account(
                google_id="123456789",
                email="test@example.com",
                full_name="Test User",
            )

        assert result == existing_user
        mock_session.commit.assert_not_called()

    def test_link_google_account_existing_email(self, oauth_service, mock_session):
        """Test linking when user with email exists but no google_id"""
        existing_user = User(
            id=uuid.uuid4(),
            email="test@example.com",
            google_id=None,
            hashed_password="hashed",
            full_name="Test User",
        )

        with patch("app.users.repositories.get_user_by_google_id", return_value=None):
            with patch("app.users.repositories.get_user_by_email", return_value=existing_user):
                result = oauth_service.link_google_account(
                    google_id="123456789",
                    email="test@example.com",
                    full_name="Test User",
                )

        assert result.google_id == "123456789"
        mock_session.add.assert_called_once_with(existing_user)
        mock_session.commit.assert_called_once()

    def test_link_google_account_no_existing_user(self, oauth_service, mock_session):
        """Test linking when no user exists"""
        with patch("app.users.repositories.get_user_by_google_id", return_value=None):
            with patch("app.users.repositories.get_user_by_email", return_value=None):
                result = oauth_service.link_google_account(
                    google_id="123456789",
                    email="test@example.com",
                    full_name="Test User",
                )

        assert result is None
        mock_session.commit.assert_not_called()

    def test_create_or_link_google_account_new_user(self, oauth_service, mock_session):
        """Test creating a new user when no existing user"""
        with patch("app.users.repositories.get_user_by_google_id", return_value=None):
            with patch("app.users.repositories.get_user_by_email", return_value=None):
                result = oauth_service.create_or_link_google_account(
                    google_id="123456789",
                    email="test@example.com",
                    full_name="Test User",
                )

        assert result.email == "test@example.com"
        assert result.google_id == "123456789"
        assert result.full_name == "Test User"
        assert result.is_active is True
        assert result.is_superuser is False
        # Password should be properly hashed
        assert verify_password("random", result.hashed_password) is False
        mock_session.add.assert_called()
        mock_session.commit.assert_called()

    def test_create_or_link_google_account_link_existing(self, oauth_service, mock_session):
        """Test linking to existing user by email"""
        existing_user = User(
            id=uuid.uuid4(),
            email="test@example.com",
            google_id=None,
            hashed_password="hashed",
            full_name=None,
        )

        with patch("app.users.repositories.get_user_by_google_id", return_value=None):
            with patch("app.users.repositories.get_user_by_email", return_value=existing_user):
                result = oauth_service.create_or_link_google_account(
                    google_id="123456789",
                    email="test@example.com",
                    full_name="Test User",
                )

        assert result.google_id == "123456789"
        assert result.full_name == "Test User"
        mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_exchange_google_code_success(self, oauth_service, mock_google_user_info):
        """Test successful Google code exchange"""
        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {"access_token": "test-token"}

        mock_userinfo_response = MagicMock()
        mock_userinfo_response.json.return_value = {
            "id": "123456789",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_token_response
            mock_client_instance.get.return_value = mock_userinfo_response

            with patch("app.users.services.settings.google_oauth_enabled", True):
                result = await oauth_service.exchange_google_code_for_user_info("test-code")

        assert result["google_id"] == "123456789"
        assert result["email"] == "test@example.com"
        assert result["full_name"] == "Test User"
        assert result["verified_email"] is True

    @pytest.mark.asyncio
    async def test_exchange_google_code_disabled(self, oauth_service):
        """Test when Google OAuth is disabled"""
        with patch("app.users.services.settings.google_oauth_enabled", False):
            result = await oauth_service.exchange_google_code_for_user_info("test-code")

        assert result is None

    @pytest.mark.asyncio
    async def test_exchange_google_code_http_error(self, oauth_service):
        """Test handling of HTTP errors"""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 400
        mock_response.text = "Bad Request"

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.side_effect = HTTPStatusError(
                "Error", request=MagicMock(), response=mock_response
            )

            with patch("app.users.services.settings.google_oauth_enabled", True):
                result = await oauth_service.exchange_google_code_for_user_info("test-code")

        assert result is None

    @pytest.mark.asyncio
    async def test_exchange_google_code_request_error(self, oauth_service):
        """Test handling of network errors"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.side_effect = RequestError("Network error")

            with patch("app.users.services.settings.google_oauth_enabled", True):
                result = await oauth_service.exchange_google_code_for_user_info("test-code")

        assert result is None

    @pytest.mark.asyncio
    async def test_exchange_google_code_no_access_token(self, oauth_service):
        """Test when Google doesn't return access token"""
        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {}  # No access token

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_token_response

            with patch("app.users.services.settings.google_oauth_enabled", True):
                result = await oauth_service.exchange_google_code_for_user_info("test-code")

        assert result is None

