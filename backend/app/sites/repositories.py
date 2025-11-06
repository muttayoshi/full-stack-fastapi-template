"""
Site repository for database operations
"""
import uuid

from sqlmodel import Session, func, select

from app.sites.models import Site
from app.sites.schemas import SiteCreate, SiteUpdate


def create_site(*, session: Session, site_create: SiteCreate) -> Site:
    """Create a new site."""
    db_site = Site.model_validate(site_create)

    # If this is set as default, unset any existing default
    if db_site.is_default:
        _unset_other_defaults(session=session, exclude_id=None)

    session.add(db_site)
    session.commit()
    session.refresh(db_site)
    return db_site


def get_site_by_id(*, session: Session, site_id: uuid.UUID) -> Site | None:
    """Get a site by ID."""
    return session.get(Site, site_id)


def get_site_by_domain(*, session: Session, domain: str) -> Site | None:
    """Get a site by domain."""
    statement = select(Site).where(Site.domain == domain)
    return session.exec(statement).first()


def get_sites(*, session: Session, skip: int = 0, limit: int = 100) -> list[Site]:
    """Get list of sites."""
    statement = select(Site).offset(skip).limit(limit)
    return list(session.exec(statement).all())


def get_sites_count(*, session: Session) -> int:
    """Get total count of sites."""
    statement = select(func.count()).select_from(Site)
    return session.exec(statement).one()


def update_site(*, session: Session, db_site: Site, site_update: SiteUpdate) -> Site:
    """Update a site."""
    site_data = site_update.model_dump(exclude_unset=True)

    # If setting as default, unset other defaults
    if site_data.get("is_default"):
        _unset_other_defaults(session=session, exclude_id=db_site.id)

    db_site.sqlmodel_update(site_data)
    session.add(db_site)
    session.commit()
    session.refresh(db_site)
    return db_site


def delete_site(*, session: Session, site_id: uuid.UUID) -> None:
    """Delete a site."""
    site = session.get(Site, site_id)
    if site:
        session.delete(site)
        session.commit()


def _unset_other_defaults(*, session: Session, exclude_id: uuid.UUID | None) -> None:
    """Helper to unset is_default on other sites."""
    statement = select(Site).where(Site.is_default == True)  # noqa: E712
    if exclude_id:
        statement = statement.where(Site.id != exclude_id)

    sites = session.exec(statement).all()
    for site in sites:
        site.is_default = False
        session.add(site)