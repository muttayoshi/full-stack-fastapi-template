"""
Sites Middleware - Automatically detects and sets the current site based on request.
"""
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.site import get_site_by_request, set_current_site


class SitesMiddleware(BaseHTTPMiddleware):
    """
    Middleware to detect and set the current site based on the request host.
    Similar to Django's contrib.sites.middleware.CurrentSiteMiddleware
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Get host from request headers
        host = request.headers.get("host", "")

        # Get database session
        from sqlmodel import Session

        from app.core.db import engine

        with Session(engine) as session:
            # Find the appropriate site
            site = get_site_by_request(session, host)

            # Set the current site in context
            set_current_site(site)

            # Store site in request state for easy access
            request.state.site = site

        response = await call_next(request)

        # Clean up context after request
        set_current_site(None)

        return response