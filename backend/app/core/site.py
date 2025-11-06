"""
Sites framework - inspired by Django's contrib.sites
Provides site management and context for multi-domain applications.
"""
from contextvars import ContextVar
from typing import TYPE_CHECKING

from sqlmodel import Session, select

if TYPE_CHECKING:
    from app.sites.models import Site

# Context variable to store current site for the request
_current_site: ContextVar["Site | None"] = ContextVar("current_site", default=None)


def get_current_site() -> "Site | None":
    """Get the current site from context."""
    return _current_site.get()


def set_current_site(site: "Site | None") -> None:
    """Set the current site in context."""
    _current_site.set(site)


def get_site_by_domain(session: Session, domain: str) -> "Site | None":
    """
    Get a site by its domain.

    Args:
        session: Database session
        domain: Domain name (e.g., 'example.com' or 'localhost:8000')

    Returns:
        Site object if found, None otherwise
    """
    from app.sites.models import Site

    statement = select(Site).where(Site.domain == domain, Site.is_active == True)  # noqa: E712
    return session.exec(statement).first()


def get_default_site(session: Session) -> "Site | None":
    """
    Get the default site.

    Args:
        session: Database session

    Returns:
        Default Site object if found, None otherwise
    """
    from app.sites.models import Site

    statement = select(Site).where(Site.is_default == True, Site.is_active == True)  # noqa: E712
    return session.exec(statement).first()


def get_site_by_request(session: Session, host: str) -> "Site | None":
    """
    Get site based on request host header.

    Tries to match exact domain first, then falls back to default site.

    Args:
        session: Database session
        host: Host header from request (e.g., 'example.com:8000')

    Returns:
        Site object
    """
    # Try exact match first
    site = get_site_by_domain(session, host)

    if site:
        return site

    # Try without port
    if ":" in host:
        domain_without_port = host.split(":")[0]
        site = get_site_by_domain(session, domain_without_port)
        if site:
            return site

    # Fall back to default site
    return get_default_site(session)


def build_absolute_uri(path: str, site: "Site | None" = None) -> str:
    """
    Build an absolute backend URI for a given path.

    Args:
        path: Relative path (e.g., '/api/v1/users')
        site: Site object (uses current site from context if not provided)

    Returns:
        Absolute backend URL (e.g., 'https://api.example.com/api/v1/users')
    """
    if site is None:
        site = get_current_site()

    if site is None:
        raise ValueError("No site available to build absolute URI")

    # Determine scheme (http or https)
    scheme = "https" if not site.domain.startswith("localhost") else "http"

    # Ensure path starts with /
    if not path.startswith("/"):
        path = f"/{path}"

    return f"{scheme}://{site.domain}{path}"


def build_frontend_url(path: str = "", site: "Site | None" = None) -> str:
    """
    Build an absolute frontend URL for redirects.

    This is useful for:
    - Email links (reset password, verify email, etc.)
    - OAuth callbacks
    - Redirect responses

    Args:
        path: Frontend path (e.g., '/reset-password' or 'reset-password')
        site: Site object (uses current site from context if not provided)

    Returns:
        Absolute frontend URL (e.g., 'https://example.com/reset-password')

    Examples:
        >>> build_frontend_url("/reset-password?token=abc123")
        'https://example.com/reset-password?token=abc123'

        >>> build_frontend_url("verify-email")
        'https://example.com/verify-email'
    """
    if site is None:
        site = get_current_site()

    if site is None:
        raise ValueError("No site available to build frontend URL")

    return site.get_frontend_url(path)