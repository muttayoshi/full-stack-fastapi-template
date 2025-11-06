"""
Tests for Role and UserRole models, services, and endpoints.
"""

import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from app.users.schemas import RoleCreate, UserRoleCreate
from app.users.services import RoleService, UserRoleService


def test_create_role(
    client: TestClient,
    superuser_token_headers: dict[str, str],
    db: Session,  # noqa:ARG001
) -> None:
    """Test creating a new role."""
    data = {
        "name": "test-role",
        "description": "Test role description",
        "is_active": True,
    }
    response = client.post(
        f"{settings.API_V1_STR}/roles/",
        headers=superuser_token_headers,
        json=data,
    )
    assert response.status_code == 200
    content = response.json()
    assert content["name"] == data["name"]
    assert content["description"] == data["description"]
    assert content["is_active"] == data["is_active"]
    assert "id" in content


def test_create_duplicate_role(
    client: TestClient,
    superuser_token_headers: dict[str, str],
    db: Session,  # noqa:ARG001
) -> None:
    """Test that creating duplicate role name fails."""
    data = {
        "name": "duplicate-role",
        "description": "Test role",
        "is_active": True,
    }
    # Create first role
    response1 = client.post(
        f"{settings.API_V1_STR}/roles/",
        headers=superuser_token_headers,
        json=data,
    )
    assert response1.status_code == 200

    # Try to create duplicate
    response2 = client.post(
        f"{settings.API_V1_STR}/roles/",
        headers=superuser_token_headers,
        json=data,
    )
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()


def test_read_roles(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test reading list of roles."""
    # Create test roles
    for i in range(3):
        RoleService.create_role(
            session=db,
            role_create=RoleCreate(
                name=f"test-role-{i}",
                description=f"Test role {i}",
                is_active=True,
            ),
        )

    response = client.get(
        f"{settings.API_V1_STR}/roles/",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    content = response.json()
    assert "data" in content
    assert "count" in content
    assert len(content["data"]) >= 3


def test_read_role_by_id(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test reading a specific role by ID."""
    # Create a role
    role = RoleService.create_role(
        session=db,
        role_create=RoleCreate(
            name="test-read-role",
            description="Test role",
            is_active=True,
        ),
    )

    response = client.get(
        f"{settings.API_V1_STR}/roles/{role.id}",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    content = response.json()
    assert content["id"] == str(role.id)
    assert content["name"] == role.name


def test_update_role(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test updating a role."""
    # Create a role
    role = RoleService.create_role(
        session=db,
        role_create=RoleCreate(
            name="test-update-role",
            description="Original description",
            is_active=True,
        ),
    )

    # Update the role
    update_data = {
        "description": "Updated description",
        "is_active": False,
    }
    response = client.patch(
        f"{settings.API_V1_STR}/roles/{role.id}",
        headers=superuser_token_headers,
        json=update_data,
    )
    assert response.status_code == 200
    content = response.json()
    assert content["description"] == update_data["description"]
    assert content["is_active"] == update_data["is_active"]


def test_delete_role(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test deleting a role."""
    # Create a role
    role = RoleService.create_role(
        session=db,
        role_create=RoleCreate(
            name="test-delete-role",
            description="To be deleted",
            is_active=True,
        ),
    )

    # Delete the role
    response = client.delete(
        f"{settings.API_V1_STR}/roles/{role.id}",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200

    # Verify it's deleted
    response = client.get(
        f"{settings.API_V1_STR}/roles/{role.id}",
        headers=superuser_token_headers,
    )
    assert response.status_code == 404


def test_create_user_role(
    client: TestClient,
    superuser_token_headers: dict[str, str],
    db: Session,
) -> None:
    """Test creating a user role assignment."""
    from app.sites.schemas import SiteCreate
    from app.sites.services import SiteService
    from app.users.schemas import UserCreate
    from app.users.services import UserService

    # Create test user
    user = UserService.create_user(
        session=db,
        user_create=UserCreate(
            email="testuser@example.com",
            password="testpassword123",
            full_name="Test User",
        ),
    )

    # Create test role
    role = RoleService.create_role(
        session=db,
        role_create=RoleCreate(
            name="test-user-role",
            description="Test role for user",
            is_active=True,
        ),
    )

    # Create test site
    site = SiteService.create_site(
        session=db,
        site_create=SiteCreate(
            domain="test.example.com",
            name="Test Site",
            frontend_domain="test.example.com",
            is_active=True,
        ),
    )

    # Create user role assignment
    data = {
        "user_id": str(user.id),
        "role_id": str(role.id),
        "site_id": str(site.id),
        "is_active": True,
    }
    response = client.post(
        f"{settings.API_V1_STR}/user-roles/",
        headers=superuser_token_headers,
        json=data,
    )
    assert response.status_code == 200
    content = response.json()
    assert content["user_id"] == data["user_id"]
    assert content["role_id"] == data["role_id"]
    assert content["site_id"] == data["site_id"]


def test_create_global_user_role(
    client: TestClient,
    superuser_token_headers: dict[str, str],
    db: Session,
) -> None:
    """Test creating a global user role assignment (site_id=None)."""
    from app.users.schemas import UserCreate
    from app.users.services import UserService

    # Create test user
    user = UserService.create_user(
        session=db,
        user_create=UserCreate(
            email="globaluser@example.com",
            password="testpassword123",
            full_name="Global User",
        ),
    )

    # Create test role
    role = RoleService.create_role(
        session=db,
        role_create=RoleCreate(
            name="global-role",
            description="Global role for all sites",
            is_active=True,
        ),
    )

    # Create global user role assignment
    data = {
        "user_id": str(user.id),
        "role_id": str(role.id),
        "site_id": None,  # Global role
        "is_active": True,
    }
    response = client.post(
        f"{settings.API_V1_STR}/user-roles/",
        headers=superuser_token_headers,
        json=data,
    )
    assert response.status_code == 200
    content = response.json()
    assert content["site_id"] is None


def test_read_user_roles_by_user(
    client: TestClient,
    superuser_token_headers: dict[str, str],
    db: Session,
) -> None:
    """Test reading user roles for a specific user."""
    from app.users.schemas import UserCreate
    from app.users.services import UserService

    # Create test user
    user = UserService.create_user(
        session=db,
        user_create=UserCreate(
            email="roleuser@example.com",
            password="testpassword123",
            full_name="Role User",
        ),
    )

    # Create and assign roles
    role1 = RoleService.create_role(
        session=db,
        role_create=RoleCreate(name="role1", is_active=True),
    )
    role2 = RoleService.create_role(
        session=db,
        role_create=RoleCreate(name="role2", is_active=True),
    )

    UserRoleService.create_user_role(
        session=db,
        user_role_create=UserRoleCreate(
            user_id=user.id,
            role_id=role1.id,
            site_id=None,
            is_active=True,
        ),
    )
    UserRoleService.create_user_role(
        session=db,
        user_role_create=UserRoleCreate(
            user_id=user.id,
            role_id=role2.id,
            site_id=None,
            is_active=True,
        ),
    )

    # Read user roles
    response = client.get(
        f"{settings.API_V1_STR}/user-roles/user/{user.id}",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    content = response.json()
    assert len(content) == 2
    role_names = [r["role_name"] for r in content]
    assert "role1" in role_names
    assert "role2" in role_names


def test_read_my_user_roles(
    client: TestClient,
    normal_user_token_headers: dict[str, str],
    db: Session,  # noqa:ARG001
) -> None:
    """Test reading current user's roles."""

    # Get current user
    response = client.get(
        f"{settings.API_V1_STR}/users/me",
        headers=normal_user_token_headers,
    )
    # Get user's roles
    response = client.get(
        f"{settings.API_V1_STR}/user-roles/me",
        headers=normal_user_token_headers,
    )
    assert response.status_code == 200
    content = response.json()
    assert isinstance(content, list)


def test_has_role_service(db: Session) -> None:
    """Test the has_role service method."""
    from app.users.schemas import UserCreate
    from app.users.services import UserService

    # Create test user
    user = UserService.create_user(
        session=db,
        user_create=UserCreate(
            email="hasrole@example.com",
            password="testpassword123",
            full_name="Has Role User",
        ),
    )

    # Create test role
    role = RoleService.create_role(
        session=db,
        role_create=RoleCreate(
            name="has-role-test",
            description="Test role",
            is_active=True,
        ),
    )

    # Initially user doesn't have role
    assert not UserRoleService.has_role(
        session=db,
        user_id=user.id,
        role_name="has-role-test",
    )

    # Assign role
    UserRoleService.create_user_role(
        session=db,
        user_role_create=UserRoleCreate(
            user_id=user.id,
            role_id=role.id,
            site_id=None,
            is_active=True,
        ),
    )

    # Now user has role
    assert UserRoleService.has_role(
        session=db,
        user_id=user.id,
        role_name="has-role-test",
    )


def test_role_permissions(
    client: TestClient, normal_user_token_headers: dict[str, str]
) -> None:
    """Test that normal users cannot create/update/delete roles."""
    # Try to create role as normal user
    data = {
        "name": "unauthorized-role",
        "description": "Should fail",
        "is_active": True,
    }
    response = client.post(
        f"{settings.API_V1_STR}/roles/",
        headers=normal_user_token_headers,
        json=data,
    )
    assert response.status_code == 403


def test_user_role_permissions(
    client: TestClient, normal_user_token_headers: dict[str, str]
) -> None:
    """Test that normal users cannot create/update/delete user role assignments."""
    data = {
        "user_id": str(uuid.uuid4()),
        "role_id": str(uuid.uuid4()),
        "site_id": None,
        "is_active": True,
    }
    response = client.post(
        f"{settings.API_V1_STR}/user-roles/",
        headers=normal_user_token_headers,
        json=data,
    )
    assert response.status_code == 403
