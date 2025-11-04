import uuid
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, col, func, select

from app.auditlog.models import AuditAction, AuditLog


def create_audit_log(
    *,
    session: Session,
    table_name: str,
    record_id: str,
    action: AuditAction,
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
    changed_fields: list[str] | None = None,
    user_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    session_id: str | None = None,
    additional_info: dict[str, Any] | None = None,
) -> AuditLog:
    """Create a new audit log entry in the database."""
    audit_log = AuditLog(
        table_name=table_name,
        record_id=record_id,
        action=action,
        old_values=old_values,
        new_values=new_values,
        changed_fields=changed_fields,
        user_id=user_id,
        timestamp=datetime.now(timezone.utc),
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=session_id,
        additional_info=additional_info,
    )
    session.add(audit_log)
    # Don't commit or flush here when called from event handlers
    # The session will be committed by the parent transaction
    return audit_log


def get_audit_logs(
    *,
    session: Session,
    table_name: str | None = None,
    record_id: str | None = None,
    user_id: uuid.UUID | None = None,
    action: AuditAction | None = None,
    skip: int = 0,
    limit: int = 100,
) -> tuple[list[AuditLog], int]:
    """Get audit logs with filters and pagination."""
    # Build count query
    count_query = select(func.count()).select_from(AuditLog)

    # Build data query
    query = select(AuditLog)

    # Apply filters
    if table_name:
        count_query = count_query.where(AuditLog.table_name == table_name)
        query = query.where(AuditLog.table_name == table_name)
    if record_id:
        count_query = count_query.where(AuditLog.record_id == record_id)
        query = query.where(AuditLog.record_id == record_id)
    if user_id:
        count_query = count_query.where(AuditLog.user_id == user_id)
        query = query.where(AuditLog.user_id == user_id)
    if action:
        count_query = count_query.where(AuditLog.action == action)
        query = query.where(AuditLog.action == action)

    # Get count
    count = session.exec(count_query).one()

    # Apply ordering and pagination
    query = query.order_by(col(AuditLog.timestamp).desc())
    query = query.offset(skip).limit(limit)

    # Execute query
    audit_logs = session.exec(query).all()

    return list(audit_logs), count


def get_record_history(
    *,
    session: Session,
    table_name: str,
    record_id: str,
    skip: int = 0,
    limit: int = 100,
) -> tuple[list[AuditLog], int]:
    """Get audit history for a specific record."""
    return get_audit_logs(
        session=session,
        table_name=table_name,
        record_id=record_id,
        skip=skip,
        limit=limit,
    )


def get_user_activities(
    *, session: Session, user_id: uuid.UUID, skip: int = 0, limit: int = 50
) -> tuple[list[AuditLog], int]:
    """Get activities for a specific user."""
    return get_audit_logs(session=session, user_id=user_id, skip=skip, limit=limit)


def get_audit_log_by_id(*, session: Session, audit_id: uuid.UUID) -> AuditLog | None:
    """Get a specific audit log by ID."""
    return session.get(AuditLog, audit_id)
