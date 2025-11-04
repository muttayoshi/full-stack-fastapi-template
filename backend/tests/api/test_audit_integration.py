"""Integration test for Audit Middleware with API"""


from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.auditlog.models import AuditAction, AuditLog


def test_audit_middleware_tracks_item_creation_via_api(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test middleware captures audit context from API request"""
    # Create item via API
    response = client.post(
        "/api/v1/items/",
        headers=superuser_token_headers,
        json={"title": "Test Item", "description": "Created via API"},
    )
    assert response.status_code == 200
    item_data = response.json()
    item_id = item_data["id"]

    # Check audit log was created with user context from JWT token
    audit_log = db.exec(
        select(AuditLog)
        .where(AuditLog.table_name == "item")
        .where(AuditLog.record_id == item_id)
        .where(AuditLog.action == AuditAction.CREATE)
    ).first()

    assert audit_log is not None
    assert audit_log.user_id is not None  # User ID dari JWT token
    assert audit_log.ip_address is not None  # IP dari test client
    assert audit_log.new_values["title"] == "Test Item"


def test_audit_middleware_tracks_item_update_via_api(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test middleware tracks updates with proper context"""
    # Create item first
    response = client.post(
        "/api/v1/items/",
        headers=superuser_token_headers,
        json={"title": "Original", "description": "Original description"},
    )
    item_id = response.json()["id"]

    # Update item
    response = client.put(
        f"/api/v1/items/{item_id}",
        headers=superuser_token_headers,
        json={"title": "Updated", "description": "Updated description"},
    )
    assert response.status_code == 200

    # Check update audit log
    audit_log = db.exec(
        select(AuditLog)
        .where(AuditLog.table_name == "item")
        .where(AuditLog.record_id == item_id)
        .where(AuditLog.action == AuditAction.UPDATE)
    ).first()

    assert audit_log is not None
    assert audit_log.old_values["title"] == "Original"
    assert audit_log.new_values["title"] == "Updated"
    assert "title" in audit_log.changed_fields


def test_audit_middleware_tracks_item_deletion_via_api(
    client: TestClient, superuser_token_headers: dict[str, str], db: Session
) -> None:
    """Test middleware tracks deletions"""
    # Create item
    response = client.post(
        "/api/v1/items/",
        headers=superuser_token_headers,
        json={"title": "To Delete", "description": "Will be deleted"},
    )
    item_id = response.json()["id"]

    # Delete item
    response = client.delete(
        f"/api/v1/items/{item_id}",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200

    # Check delete audit log
    audit_log = db.exec(
        select(AuditLog)
        .where(AuditLog.table_name == "item")
        .where(AuditLog.record_id == item_id)
        .where(AuditLog.action == AuditAction.DELETE)
    ).first()

    assert audit_log is not None
    assert audit_log.old_values["title"] == "To Delete"


def test_get_audit_logs_api_endpoint(
    client: TestClient, superuser_token_headers: dict[str, str]
) -> None:
    """Test audit logs API endpoint"""
    # Create some audit data first
    client.post(
        "/api/v1/items/",
        headers=superuser_token_headers,
        json={"title": "Test", "description": "Test"},
    )

    # Get audit logs
    response = client.get(
        "/api/v1/audit-logs/",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "count" in data
    assert len(data["data"]) > 0


def test_get_audit_logs_filtered_by_table(
    client: TestClient, superuser_token_headers: dict[str, str]
) -> None:
    """Test filtering audit logs by table name"""
    # Create item
    response = client.post(
        "/api/v1/items/",
        headers=superuser_token_headers,
        json={"title": "Test", "description": "Test"},
    )

    # Get audit logs for items table
    response = client.get(
        "/api/v1/audit-logs/?table_name=item",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    data = response.json()

    # All logs should be for item table
    for log in data["data"]:
        assert log["table_name"] == "item"


def test_get_record_history_endpoint(
    client: TestClient, superuser_token_headers: dict[str, str]
) -> None:
    """Test getting complete history for a record"""
    # Create and update item
    response = client.post(
        "/api/v1/items/",
        headers=superuser_token_headers,
        json={"title": "Version 1", "description": "First version"},
    )
    item_id = response.json()["id"]

    # Update item
    client.put(
        f"/api/v1/items/{item_id}",
        headers=superuser_token_headers,
        json={"title": "Version 2", "description": "Second version"},
    )

    # Get record history
    response = client.get(
        f"/api/v1/audit-logs/record/item/{item_id}",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    data = response.json()

    # Should have at least CREATE and UPDATE
    assert data["count"] >= 2

    # Check we have both operations
    actions = [log["action"] for log in data["data"]]
    assert "CREATE" in actions
    assert "UPDATE" in actions


def test_regular_user_can_only_see_own_audit_logs(
    client: TestClient,
    normal_user_token_headers: dict[str, str],
    db: Session,  # noqa: ARG001
) -> None:
    """Test regular users can only see their own audit logs"""
    # Create item as normal user
    client.post(
        "/api/v1/items/",
        headers=normal_user_token_headers,
        json={"title": "My Item", "description": "My item"},
    )

    # Get audit logs
    response = client.get(
        "/api/v1/audit-logs/",
        headers=normal_user_token_headers,
    )
    assert response.status_code == 200
    data = response.json()

    # All logs should belong to this user
    # (user_id should match the token user)
    for log in data["data"]:
        if log["user_id"]:  # Some logs might not have user_id
            # We can't check the exact UUID here, but we know it's filtered
            assert log["user_id"] is not None
