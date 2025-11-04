import logging
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, TypeVar

from sqlalchemy import event
from sqlalchemy.orm import InstanceState
from sqlalchemy.orm import Session as SASession
from sqlmodel import SQLModel

if TYPE_CHECKING:
    from app.auditlog.models import AuditLog

T = TypeVar("T", bound=SQLModel)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Context variables for thread-safe async support
_user_id_var: ContextVar[uuid.UUID | None] = ContextVar("user_id", default=None)
_ip_address_var: ContextVar[str | None] = ContextVar("ip_address", default=None)
_user_agent_var: ContextVar[str | None] = ContextVar("user_agent", default=None)
_session_id_var: ContextVar[str | None] = ContextVar("session_id", default=None)
_additional_info_var: ContextVar[dict[str, Any] | None] = ContextVar(
    "additional_info", default=None
)


class AuditContext:
    """Context untuk menyimpan informasi audit saat ini menggunakan contextvars"""

    @property
    def user_id(self) -> uuid.UUID | None:
        return _user_id_var.get()

    @user_id.setter
    def user_id(self, value: uuid.UUID | None):
        _user_id_var.set(value)

    @property
    def ip_address(self) -> str | None:
        return _ip_address_var.get()

    @ip_address.setter
    def ip_address(self, value: str | None):
        _ip_address_var.set(value)

    @property
    def user_agent(self) -> str | None:
        return _user_agent_var.get()

    @user_agent.setter
    def user_agent(self, value: str | None):
        _user_agent_var.set(value)

    @property
    def session_id(self) -> str | None:
        return _session_id_var.get()

    @session_id.setter
    def session_id(self, value: str | None):
        _session_id_var.set(value)

    @property
    def additional_info(self) -> dict[str, Any] | None:
        return _additional_info_var.get()

    @additional_info.setter
    def additional_info(self, value: dict[str, Any] | None):
        _additional_info_var.set(value)


# Global audit context
audit_context = AuditContext()


@contextmanager
def audit_context_manager(
    user_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    session_id: str | None = None,
    additional_info: dict[str, Any] | None = None,
):
    """Context manager untuk mengatur informasi audit"""
    # Save old values
    old_user_id = audit_context.user_id
    old_ip_address = audit_context.ip_address
    old_user_agent = audit_context.user_agent
    old_session_id = audit_context.session_id
    old_additional_info = audit_context.additional_info

    # Set new values
    audit_context.user_id = user_id
    audit_context.ip_address = ip_address
    audit_context.user_agent = user_agent
    audit_context.session_id = session_id
    audit_context.additional_info = additional_info

    try:
        yield
    finally:
        # Restore old values
        audit_context.user_id = old_user_id
        audit_context.ip_address = old_ip_address
        audit_context.user_agent = old_user_agent
        audit_context.session_id = old_session_id
        audit_context.additional_info = old_additional_info


def _create_audit_log_object(
    table_name: str,
    record_id: str,
    action: "AuditAction",
    old_values: dict[str, Any] | None = None,
    new_values: dict[str, Any] | None = None,
):
    """Create audit log object without adding to session"""
    from datetime import datetime, timezone

    from app.auditlog.models import AuditLog

    # Determine changed fields
    changed_fields = []
    if old_values and new_values:
        changed_fields = [
            field
            for field in new_values.keys()
            if field in old_values and old_values[field] != new_values[field]
        ]

    return AuditLog(
        table_name=table_name,
        record_id=record_id,
        action=action,
        old_values=old_values,
        new_values=new_values,
        changed_fields=changed_fields,
        user_id=audit_context.user_id,
        timestamp=datetime.now(timezone.utc),
        ip_address=audit_context.ip_address,
        user_agent=audit_context.user_agent,
        session_id=audit_context.session_id,
        additional_info=audit_context.additional_info,
    )


class AuditMixin:
    """Mixin untuk model yang perlu dilacak perubahannya"""

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Register event listeners
        event.listen(cls, "before_update", cls._before_update)
        event.listen(cls, "before_delete", cls._before_delete)

    def _get_audit_data(self) -> dict[str, Any]:
        """Ambil data untuk audit log"""
        from datetime import datetime

        data = {}
        # Menggunakan __table__ yang tersedia di SQLModel instance
        if hasattr(self, "__table__"):
            for column in self.__table__.columns:
                value = getattr(self, column.name, None)

                # Skip SQLAlchemy internal objects like LoaderCallableStatus
                if value is not None and type(value).__name__ == "LoaderCallableStatus":
                    continue

                # Skip complex objects that might be relationships
                if hasattr(value, "_sa_instance_state"):
                    continue

                # Skip collections
                if isinstance(value, list | set | dict):
                    continue

                # Convert UUID to string untuk JSON serialization
                if isinstance(value, uuid.UUID):
                    value = str(value)
                # Convert datetime to ISO format string untuk JSON serialization
                elif isinstance(value, datetime):
                    value = value.isoformat()
                data[column.name] = value
        return data

    @staticmethod
    def _before_update(mapper, connection, target):
        """Sebelum update - simpan data lama untuk audit"""
        # Simpan data lama di instance state untuk digunakan di after_update
        if hasattr(target, "__dict__"):
            state: InstanceState = target.__dict__.get("_sa_instance_state")
            if state and state.committed_state:
                # Convert committed state to proper format (handle UUID, datetime, etc.)
                from datetime import datetime

                old_data = {}
                for key, value in state.committed_state.items():
                    # Skip SQLAlchemy internal objects like LoaderCallableStatus
                    if (
                        value is not None
                        and type(value).__name__ == "LoaderCallableStatus"
                    ):
                        continue

                    # Skip relationship attributes (lists, sets, other complex objects)
                    # Only include scalar values that are JSON serializable
                    if isinstance(value, list | set | dict) and key != "changed_fields":
                        continue

                    # Skip if it has _sa_instance_state (it's a model instance)
                    if (
                        hasattr(value, "__dict__")
                        and "_sa_instance_state" in value.__dict__
                    ):
                        continue

                    # Convert UUID to string for JSON serialization
                    if isinstance(value, uuid.UUID):
                        value = str(value)
                    # Convert datetime to ISO format string for JSON serialization
                    elif isinstance(value, datetime):
                        value = value.isoformat()
                    old_data[key] = value
                target._old_audit_data = old_data

    @staticmethod
    def _before_delete(mapper, connection, target):
        """Sebelum delete - simpan data untuk audit"""
        target._old_audit_data = target._get_audit_data()


# Session-level event listener to handle all audit logs after flush
@event.listens_for(SASession, "after_flush")
def receive_after_flush(session, flush_context):  # noqa: ARG001
    """After flush - log all changes to audit"""
    try:
        from app.auditlog.models import AuditAction

        # Collect audit logs to be created
        audit_logs = []

        # Handle new objects (inserts)
        for obj in session.new:
            if isinstance(obj, AuditMixin):
                # Skip if this is an AuditLog itself to prevent recursion
                if obj.__class__.__name__ == "AuditLog":
                    continue

                audit_log = _create_audit_log_object(
                    table_name=obj.__table__.name,
                    record_id=str(obj.id),
                    action=AuditAction.CREATE,
                    new_values=obj._get_audit_data(),
                )
                audit_logs.append(audit_log)

        # Handle modified objects (updates)
        for obj in session.dirty:
            if isinstance(obj, AuditMixin):
                # Skip if this is an AuditLog itself
                if obj.__class__.__name__ == "AuditLog":
                    continue

                old_values = getattr(obj, "_old_audit_data", None)
                new_values = obj._get_audit_data()

                # Only log if there are actual changes
                if old_values and old_values != new_values:
                    audit_log = _create_audit_log_object(
                        table_name=obj.__table__.name,
                        record_id=str(obj.id),
                        action=AuditAction.UPDATE,
                        old_values=old_values,
                        new_values=new_values,
                    )
                    audit_logs.append(audit_log)

        # Handle deleted objects
        for obj in session.deleted:
            if isinstance(obj, AuditMixin):
                # Skip if this is an AuditLog itself
                if obj.__class__.__name__ == "AuditLog":
                    continue

                old_values = getattr(obj, "_old_audit_data", None)
                audit_log = _create_audit_log_object(
                    table_name=obj.__table__.name,
                    record_id=str(obj.id),
                    action=AuditAction.DELETE,
                    old_values=old_values,
                )
                audit_logs.append(audit_log)

        # Add all audit logs to session at once, outside the flush process
        for audit_log in audit_logs:
            session.add(audit_log)

    except Exception as e:
        # Log error but don't interrupt the main operation
        logger.error(f"Failed to create audit logs: {e}")


def get_client_info_from_request(request) -> dict[str, str | None]:
    """Extract client information from FastAPI request"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "session_id": request.headers.get("x-session-id")
        or request.cookies.get("session_id"),
    }