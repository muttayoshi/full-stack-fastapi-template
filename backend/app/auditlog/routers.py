"""API Router for Audit Logs"""

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import CurrentUser, SessionDep
from app.auditlog.models import AuditAction
from app.auditlog.schemas import AuditLogPublic, AuditLogsPublic
from app.auditlog.services import AuditLogService

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


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
    # Non-superusers can only see their own audit logs
    filter_user_id = current_user.id if not current_user.is_superuser else user_id

    # Get audit logs using service
    audit_logs, count = AuditLogService.get_audit_logs(
        session,
        user_id=filter_user_id,
        table_name=table_name,
        record_id=record_id,
        action=action,
        skip=skip,
        limit=limit,
    )

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
    audit_log = AuditLogService.get_audit_log_by_id(session, audit_log_id)
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
    # Non-superusers can only see their own audit logs
    filter_user_id = current_user.id if not current_user.is_superuser else None

    # Get record history using service
    audit_logs, count = AuditLogService.get_record_history(
        session,
        table_name=table_name,
        record_id=record_id,
        user_id=filter_user_id,
        skip=skip,
        limit=limit,
    )

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

    # Get user audit logs using service
    audit_logs, count = AuditLogService.get_user_audit_logs(
        session, user_id=user_id, skip=skip, limit=limit
    )

    return AuditLogsPublic(data=audit_logs, count=count)
