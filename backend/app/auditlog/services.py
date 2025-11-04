import uuid
from typing import Any

from sqlmodel import Session

from app.auditlog import repositories
from app.auditlog.models import AuditAction, AuditLog


class AuditService:
    """Business logic for audit log operations."""

    @staticmethod
    def log_change(
        *,
        session: Session,
        table_name: str,
        record_id: str,
        action: AuditAction,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        user_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        additional_info: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Log perubahan data ke audit log"""

        # Tentukan field yang berubah jika ada old_values dan new_values
        changed_fields = []
        if old_values and new_values:
            changed_fields = [
                field
                for field in new_values.keys()
                if field in old_values and old_values[field] != new_values[field]
            ]

        return repositories.create_audit_log(
            session=session,
            table_name=table_name,
            record_id=record_id,
            action=action,
            old_values=old_values,
            new_values=new_values,
            changed_fields=changed_fields,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            additional_info=additional_info,
        )

    @staticmethod
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
        """Ambil audit logs berdasarkan filter"""
        return repositories.get_audit_logs(
            session=session,
            table_name=table_name,
            record_id=record_id,
            user_id=user_id,
            action=action,
            skip=skip,
            limit=limit,
        )

    @staticmethod
    def get_record_history(
        *, session: Session, table_name: str, record_id: str, skip: int = 0, limit: int = 100
    ) -> tuple[list[AuditLog], int]:
        """Ambil riwayat perubahan untuk record tertentu"""
        return repositories.get_record_history(
            session=session, table_name=table_name, record_id=record_id, skip=skip, limit=limit
        )

    @staticmethod
    def get_user_activities(
        *, session: Session, user_id: uuid.UUID, skip: int = 0, limit: int = 50
    ) -> tuple[list[AuditLog], int]:
        """Ambil aktivitas user tertentu"""
        return repositories.get_user_activities(
            session=session, user_id=user_id, skip=skip, limit=limit
        )

    @staticmethod
    def get_audit_log_by_id(
        *, session: Session, audit_id: uuid.UUID
    ) -> AuditLog | None:
        """Get a specific audit log by ID"""
        return repositories.get_audit_log_by_id(session=session, audit_id=audit_id)
