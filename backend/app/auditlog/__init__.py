"""Audit Log package - Contains audit logging functionality."""

from app.auditlog.models import AuditAction, AuditLog
from app.auditlog.schemas import (
    AuditLogBase,
    AuditLogListResponse,
    AuditLogResponse,
)
from app.auditlog.services import AuditLogService

# Backward compatibility alias
AuditService = AuditLogService

__all__ = [
    "AuditAction",
    "AuditLog",
    "AuditLogBase",
    "AuditLogListResponse",
    "AuditLogResponse",
    "AuditLogService",
    "AuditService",
]
