"""API Router for Audit Logs"""

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from sqlmodel import col, select

from app.api.deps import CurrentUser, SessionDep
from app.auditlog.models import AuditAction, AuditLog
from app.auditlog.schemas import AuditLogPublic, AuditLogsPublic

router = APIRouter()


@router.get("/", response_model=AuditLogsPublic)
def get_audit_logs(
    session: SessionDep,
    current_user: CurrentUser,
    skip: int = 0,
    limit: int = Query(default=100, le=100),
    table_name: str | None = None,
    record_id: str | None = None,
    action: AuditAction | None = None,
    user_id: uuid.UUID | None = None,
) -> Any:
    """
    Retrieve audit logs.

    - **Superusers**: Dapat melihat semua audit logs
    - **Regular users**: Hanya dapat melihat audit logs mereka sendiri
    """
    # Build query
    statement = select(AuditLog)

    # Non-superusers can only see their own audit logs
    if not current_user.is_superuser:
        statement = statement.where(AuditLog.user_id == current_user.id)
    elif user_id:
        # Superusers can filter by specific user
        statement = statement.where(AuditLog.user_id == user_id)

    # Apply filters
    if table_name:
        statement = statement.where(AuditLog.table_name == table_name)
    if record_id:
        statement = statement.where(AuditLog.record_id == record_id)
    if action:
        statement = statement.where(AuditLog.action == action)

    # Count total
    count_statement = select(AuditLog.id).where(statement.whereclause)
    count = len(session.exec(count_statement).all())

    # Get paginated results
    statement = statement.order_by(col(AuditLog.timestamp).desc()).offset(skip).limit(limit)
    audit_logs = list(session.exec(statement).all())

    return AuditLogsPublic(data=audit_logs, count=count)


@router.get("/{audit_log_id}", response_model=AuditLogPublic)
def get_audit_log(
    session: SessionDep,
    current_user: CurrentUser,
    audit_log_id: uuid.UUID,
) -> Any:
    """
    Get specific audit log by ID.

    Regular users can only access their own audit logs.
    """
    audit_log = session.get(AuditLog, audit_log_id)
    if not audit_log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    # Non-superusers can only see their own audit logs
    if not current_user.is_superuser and audit_log.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to access this audit log",
        )

    return audit_log


@router.get("/record/{table_name}/{record_id}", response_model=AuditLogsPublic)
def get_record_history(
    session: SessionDep,
    current_user: CurrentUser,
    table_name: str,
    record_id: str,
    skip: int = 0,
    limit: int = Query(default=100, le=100),
) -> Any:
    """
    Get complete audit history for a specific record.

    Returns all CREATE, UPDATE, DELETE operations for the given record.
    """
    # Build query
    statement = (
        select(AuditLog)
        .where(AuditLog.table_name == table_name)
        .where(AuditLog.record_id == record_id)
    )

    # Non-superusers can only see their own audit logs
    if not current_user.is_superuser:
        statement = statement.where(AuditLog.user_id == current_user.id)

    # Count total
    count_statement = select(AuditLog.id).where(statement.whereclause)
    count = len(session.exec(count_statement).all())

    # Get paginated results ordered by timestamp
    statement = statement.order_by(col(AuditLog.timestamp).desc()).offset(skip).limit(limit)
    audit_logs = list(session.exec(statement).all())

    return AuditLogsPublic(data=audit_logs, count=count)


@router.get("/user/{user_id}", response_model=AuditLogsPublic)
def get_user_audit_logs(
    session: SessionDep,
    current_user: CurrentUser,
    user_id: uuid.UUID,
    skip: int = 0,
    limit: int = Query(default=100, le=100),
) -> Any:
    """
    Get all audit logs for a specific user.

    Only superusers can access other users' audit logs.
    """
    # Non-superusers can only see their own audit logs
    if not current_user.is_superuser and user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to access other users' audit logs",
        )

    # Build query
    statement = select(AuditLog).where(AuditLog.user_id == user_id)

    # Count total
    count_statement = select(AuditLog.id).where(statement.whereclause)
    count = len(session.exec(count_statement).all())

    # Get paginated results
    statement = statement.order_by(col(AuditLog.timestamp).desc()).offset(skip).limit(limit)
    audit_logs = list(session.exec(statement).all())

    return AuditLogsPublic(data=audit_logs, count=count)
