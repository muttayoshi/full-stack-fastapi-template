import uuid
from collections.abc import Callable

import jwt
from fastapi import Request, Response
from jwt.exceptions import InvalidTokenError
from starlette.middleware.base import BaseHTTPMiddleware

from app.core import security
from app.core.auditlog import audit_context, get_client_info_from_request
from app.core.config import settings


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware untuk mengatur audit context berdasarkan request"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract client info dari request
        client_info = get_client_info_from_request(request)

        # Set audit context untuk request ini
        audit_context.ip_address = client_info.get("ip_address")
        audit_context.user_agent = client_info.get("user_agent")
        audit_context.session_id = client_info.get("session_id")

        # Ambil user_id dari JWT token jika ada
        user_id = self._extract_user_id_from_token(request)
        if user_id:
            audit_context.user_id = user_id

        try:
            # Process request
            response = await call_next(request)
            return response
        finally:
            # Clear audit context setelah request selesai (di finally block untuk memastikan selalu clear)
            audit_context.user_id = None
            audit_context.ip_address = None
            audit_context.user_agent = None
            audit_context.session_id = None
            audit_context.additional_info = None

    def _extract_user_id_from_token(self, request: Request) -> uuid.UUID | None:
        """Extract user_id dari JWT token di authorization header"""
        try:
            # Ambil authorization header
            authorization = request.headers.get("Authorization")
            if not authorization:
                return None

            # Parse bearer token
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer":
                return None

            # Decode JWT token
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
            )

            # Ambil user_id dari payload (sub claim)
            user_id_str = payload.get("sub")
            if user_id_str:
                return uuid.UUID(user_id_str)

        except (InvalidTokenError, ValueError, KeyError):
            # Jika token invalid atau tidak ada, tidak masalah
            # Audit log tetap akan dibuat tanpa user_id
            pass

        return None
