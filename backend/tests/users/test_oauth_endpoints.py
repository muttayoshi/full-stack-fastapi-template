"""
Integration tests for OAuth endpoints
"""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.users.models import User


class TestOAuthEndpoints:
    """Test cases for OAuth API endpoints"""

    def test_google_login_disabled(self, client: TestClient) -> None:
        """Test Google login when OAuth is disabled"""
        with patch("app.users.routers.settings.google_oauth_enabled", False):
            response = client.post(
                f"{settings.API_V1_STR}/oauth/google",
                json={"code": "test-code"},
            )

        assert response.status_code == 503
        assert "not configured" in response.json()["detail"].lower()

    def test_google_login_invalid_code(self, client: TestClient) -> None:
        """Test Google login with invalid authorization code"""
        mock_oauth_service = AsyncMock()
        mock_oauth_service.exchange_google_code_for_user_info.return_value = None

        with patch("app.users.routers.settings.google_oauth_enabled", True):
            with patch("app.users.routers.OAuthService") as mock_service_class:
                mock_service_class.return_value = mock_oauth_service
                response = client.post(
                    f"{settings.API_V1_STR}/oauth/google",
                    json={"code": "invalid-code"},
                )

        assert response.status_code == 400
        assert "invalid authorization code" in response.json()["detail"].lower()

    def test_google_login_unverified_email(self, client: TestClient) -> None:
        """Test Google login with unverified email"""
        mock_oauth_service = AsyncMock()
        mock_oauth_service.exchange_google_code_for_user_info.return_value = {
            "google_id": "123456789",
            "email": "test@example.com",
            "full_name": "Test User",
            "verified_email": False,
        }

        with patch("app.users.routers.settings.google_oauth_enabled", True):
            with patch("app.users.routers.OAuthService") as mock_service_class:
                mock_service_class.return_value = mock_oauth_service
                response = client.post(
                    f"{settings.API_V1_STR}/oauth/google",
                    json={"code": "test-code"},
                )

        assert response.status_code == 400
        assert "not verified" in response.json()["detail"].lower()

    def test_google_login_success_new_user(
        self, client: TestClient, db: Session
    ) -> None:
        """Test successful Google login creating new user"""
        mock_user_info = {
            "google_id": "123456789",
            "email": "newuser@example.com",
            "full_name": "New User",
            "verified_email": True,
        }

        with patch("app.users.routers.settings.google_oauth_enabled", True):
            with patch(
                "app.users.services.OAuthService.exchange_google_code_for_user_info"
            ) as mock_exchange:
                mock_exchange.return_value = mock_user_info
                response = client.post(
                    f"{settings.API_V1_STR}/oauth/google",
                    json={"code": "test-code"},
                )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "newuser@example.com"
        assert data["user"]["google_id"] == "123456789"

    def test_google_login_success_existing_user(
        self, client: TestClient, db: Session
    ) -> None:
        """Test successful Google login linking to existing user"""
        # Create existing user without google_id
        from app.core.security import get_password_hash

        existing_user = User(
            email="existing@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Existing User",
            is_active=True,
        )
        db.add(existing_user)
        db.commit()
        db.refresh(existing_user)

        mock_user_info = {
            "google_id": "987654321",
            "email": "existing@example.com",
            "full_name": "Existing User",
            "verified_email": True,
        }

        with patch("app.users.routers.settings.google_oauth_enabled", True):
            with patch(
                "app.users.services.OAuthService.exchange_google_code_for_user_info"
            ) as mock_exchange:
                mock_exchange.return_value = mock_user_info
                response = client.post(
                    f"{settings.API_V1_STR}/oauth/google",
                    json={"code": "test-code"},
                )

        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == "existing@example.com"
        assert data["user"]["google_id"] == "987654321"

        # Verify user was updated in database
        db.refresh(existing_user)
        assert existing_user.google_id == "987654321"

    def test_google_login_inactive_user(self, client: TestClient, db: Session) -> None:
        """Test Google login with inactive user"""
        from app.core.security import get_password_hash

        # Create inactive user
        inactive_user = User(
            email="inactive@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Inactive User",
            is_active=False,
            google_id="123456789",
        )
        db.add(inactive_user)
        db.commit()

        mock_user_info = {
            "google_id": "123456789",
            "email": "inactive@example.com",
            "full_name": "Inactive User",
            "verified_email": True,
        }

        with patch("app.users.routers.settings.google_oauth_enabled", True):
            with patch(
                "app.users.services.OAuthService.exchange_google_code_for_user_info"
            ) as mock_exchange:
                mock_exchange.return_value = mock_user_info
                response = client.post(
                    f"{settings.API_V1_STR}/oauth/google",
                    json={"code": "test-code"},
                )

        assert response.status_code == 400
        assert "inactive" in response.json()["detail"].lower()

