"""
Site service for business logic
"""
import uuid

from fastapi import HTTPException
from sqlmodel import Session

from app.sites.models import Site
from app.sites import repositories as site_repository
from app.sites.schemas import SiteCreate, SiteUpdate


class SiteService:
    """Service for site business logic"""

    def __init__(self, session: Session):
        self.session = session

    def create_site(self, site_in: SiteCreate) -> Site:
        """
        Create a new site.

        Business rules:
        - Domain must be unique
        - If set as default, unset other defaults (handled in repository)
        """
        # Check if domain already exists
        existing_site = site_repository.get_site_by_domain(
            session=self.session, domain=site_in.domain
        )
        if existing_site:
            raise HTTPException(
                status_code=400,
                detail=f"Site with domain {site_in.domain} already exists",
            )

        return site_repository.create_site(session=self.session, site_create=site_in)

    def get_site_by_id(self, site_id: uuid.UUID) -> Site:
        """
        Get site by ID.

        Raises:
            HTTPException: If site not found
        """
        site = site_repository.get_site_by_id(session=self.session, site_id=site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        return site

    def get_site_by_domain(self, domain: str) -> Site | None:
        """Get site by domain"""
        return site_repository.get_site_by_domain(session=self.session, domain=domain)

    def get_sites(self, skip: int = 0, limit: int = 100) -> tuple[list[Site], int]:
        """
        Get all sites with count.

        Returns:
            Tuple of (sites list, total count)
        """
        sites = site_repository.get_sites(session=self.session, skip=skip, limit=limit)
        count = site_repository.get_sites_count(session=self.session)
        return sites, count

    def update_site(self, site_id: uuid.UUID, site_in: SiteUpdate) -> Site:
        """
        Update a site.

        Business rules:
        - Domain must remain unique if changed
        - Cannot set is_default=False on the only default site

        Raises:
            HTTPException: If site not found or validation fails
        """
        site = self.get_site_by_id(site_id)

        # If updating domain, check if new domain already exists
        if site_in.domain and site_in.domain != site.domain:
            existing_site = site_repository.get_site_by_domain(
                session=self.session, domain=site_in.domain
            )
            if existing_site:
                raise HTTPException(
                    status_code=400,
                    detail=f"Site with domain {site_in.domain} already exists",
                )

        return site_repository.update_site(
            session=self.session, db_site=site, site_update=site_in
        )

    def delete_site(self, site_id: uuid.UUID) -> None:
        """
        Delete a site.

        Business rules:
        - Cannot delete the default site

        Raises:
            HTTPException: If site not found or is default site
        """
        site = self.get_site_by_id(site_id)

        # Prevent deleting default site
        if site.is_default:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the default site. Set another site as default first.",
            )

        site_repository.delete_site(session=self.session, site_id=site_id)

    def get_default_site(self) -> Site | None:
        """Get the default site"""
        from app.core.site import get_default_site

        return get_default_site(self.session)

    def get_current_site(self) -> Site | None:
        """Get current site from context"""
        from app.core.site import get_current_site

        return get_current_site()