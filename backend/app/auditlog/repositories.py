"""Repository layer for audit log functionality."""
import uuid

from sqlmodel import Session, col, select

from app.auditlog.models import AuditAction, AuditLog


class AuditLogRepository:
    """Repository for database operations on AuditLog model."""

    @staticmethod
    def get_all(
        session: Session,
        user_id: uuid.UUID | None = None,
        table_name: str | None = None,
        record_id: str | None = None,
        action: AuditAction | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[list[AuditLog], int]:
        """Get audit logs with filters and pagination."""
        # Build query
        statement = select(AuditLog)

        # Apply filters
        if user_id:
            statement = statement.where(AuditLog.user_id == user_id)
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
        statement = (
            statement.order_by(col(AuditLog.timestamp).desc()).offset(skip).limit(limit)
        )
        audit_logs = list(session.exec(statement).all())

        return audit_logs, count

    @staticmethod
    def get_by_id(session: Session, audit_log_id: uuid.UUID) -> AuditLog | None:
        """Get a specific audit log by ID."""
        return session.get(AuditLog, audit_log_id)

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
        # Build query
        statement = (
            select(AuditLog)
            .where(AuditLog.table_name == table_name)
            .where(AuditLog.record_id == record_id)
        )

        # Filter by user if provided
        if user_id:
            statement = statement.where(AuditLog.user_id == user_id)

        # Count total
        count_statement = select(AuditLog.id).where(statement.whereclause)
        count = len(session.exec(count_statement).all())

        # Get paginated results ordered by timestamp
        statement = (
            statement.order_by(col(AuditLog.timestamp).desc()).offset(skip).limit(limit)
        )
        audit_logs = list(session.exec(statement).all())

        return audit_logs, count

    @staticmethod
    def get_by_user(
        session: Session, user_id: uuid.UUID, skip: int = 0, limit: int = 100
    ) -> tuple[list[AuditLog], int]:
        """Get all audit logs for a specific user."""
        # Build query
        statement = select(AuditLog).where(AuditLog.user_id == user_id)

        # Count total
        count_statement = select(AuditLog.id).where(statement.whereclause)
        count = len(session.exec(count_statement).all())

        # Get paginated results
        statement = (
            statement.order_by(col(AuditLog.timestamp).desc()).offset(skip).limit(limit)
        )
        audit_logs = list(session.exec(statement).all())

        return audit_logs, count
