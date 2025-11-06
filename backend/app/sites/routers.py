"""
Sites API endpoints
"""
import uuid

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep
from app.sites.models import Site
from app.sites.schemas import SiteCreate, SitePublic, SitesPublic, SiteUpdate
from app.sites.services import SiteService

router = APIRouter(prefix="/sites", tags=["sites"])


@router.post("/", response_model=SitePublic)
def create_site(
    *, session: SessionDep, current_user: CurrentUser, site_in: SiteCreate
) -> Site:
    """
    Create new site. Only for superusers.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    service = SiteService(session)
    return service.create_site(site_in)


@router.get("/", response_model=SitesPublic)
def read_sites(
    session: SessionDep, current_user: CurrentUser, skip: int = 0, limit: int = 100
) -> SitesPublic:
    """
    Retrieve sites. Only for superusers.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    service = SiteService(session)
    sites, count = service.get_sites(skip=skip, limit=limit)

    return SitesPublic(
        data=[SitePublic.model_validate(site) for site in sites], count=count
    )


@router.get("/current", response_model=SitePublic | None)
def get_current_site_endpoint(session: SessionDep) -> Site | None:
    """
    Get the current site based on request host.
    This endpoint is public to allow frontend to know which site they're on.
    """
    service = SiteService(session)
    return service.get_current_site()


@router.get("/{site_id}", response_model=SitePublic)
def read_site(
    session: SessionDep, current_user: CurrentUser, site_id: uuid.UUID
) -> Site:
    """
    Get site by ID. Only for superusers.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    service = SiteService(session)
    return service.get_site_by_id(site_id)


@router.patch("/{site_id}", response_model=SitePublic)
def update_site(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    site_id: uuid.UUID,
    site_in: SiteUpdate,
) -> Site:
    """
    Update a site. Only for superusers.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    service = SiteService(session)
    return service.update_site(site_id, site_in)


@router.delete("/{site_id}")
def delete_site(
    session: SessionDep, current_user: CurrentUser, site_id: uuid.UUID
) -> dict[str, str]:
    """
    Delete a site. Only for superusers.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    service = SiteService(session)
    service.delete_site(site_id)
    return {"message": "Site deleted successfully"}
