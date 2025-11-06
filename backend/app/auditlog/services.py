"""Service layer for audit log functionality."""
import uuid

from sqlmodel import Session

from app.auditlog.models import AuditAction, AuditLog
from app.auditlog.repositories import AuditLogRepository


class AuditLogService:
    """Service for managing audit logs."""

    @staticmethod
    def get_audit_logs(
        session: Session,
        user_id: uuid.UUID | None = None,
        table_name: str | None = None,
        record_id: str | None = None,
        action: AuditAction | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[list[AuditLog], int]:
        """Get audit logs with filters."""
        return AuditLogRepository.get_all(
            session,
            user_id=user_id,
            table_name=table_name,
            record_id=record_id,
            action=action,
            skip=skip,
            limit=limit,
        )

    @staticmethod
    def get_audit_log_by_id(
        session: Session, audit_log_id: uuid.UUID
    ) -> AuditLog | None:
        """Get a specific audit log by ID."""
        return AuditLogRepository.get_by_id(session, audit_log_id)

    @staticmethod
    def get_record_history(
        session: Session,
        table_name: str,
        record_id: str,
        user_id: uuid.UUID | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[list[AuditLog], int]:
        """Get complete audit history for a specific record."""
        return AuditLogRepository.get_record_history(
            session,
            table_name=table_name,
            record_id=record_id,
            user_id=user_id,
            skip=skip,
            limit=limit,
        )

    @staticmethod
    def get_user_audit_logs(
        session: Session, user_id: uuid.UUID, skip: int = 0, limit: int = 100
    ) -> tuple[list[AuditLog], int]:
        """Get all audit logs for a specific user."""
        return AuditLogRepository.get_by_user(
            session, user_id=user_id, skip=skip, limit=limit
        )
