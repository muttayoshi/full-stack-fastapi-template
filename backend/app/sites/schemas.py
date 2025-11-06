"""
Site schemas for API requests and responses
"""
import uuid

from pydantic import BaseModel, ConfigDict, Field


class SiteBase(BaseModel):
    """Base schema for Site"""
    domain: str = Field(
        ...,
        max_length=255,
        description="Backend domain (e.g., api.example.com or localhost:8000)",
    )
    name: str = Field(..., max_length=255, description="Human-readable site name")
    frontend_domain: str = Field(
        ...,
        max_length=255,
        description="Frontend domain for redirects (e.g., example.com or localhost:5173)",
    )
    is_active: bool = Field(default=True, description="Whether the site is active")
    is_default: bool = Field(
        default=False, description="Whether this is the default site"
    )
    settings: dict | None = Field(
        default=None, description="Additional site-specific settings"
    )


class SiteCreate(SiteBase):
    """Schema for creating a new site"""
    pass


class SiteUpdate(BaseModel):
    """Schema for updating a site"""
    domain: str | None = None
    name: str | None = None
    frontend_domain: str | None = None
    is_active: bool | None = None
    is_default: bool | None = None
    settings: dict | None = None


class SitePublic(SiteBase):
    """Public schema for Site"""
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID


class SitesPublic(BaseModel):
    """Schema for list of sites"""
    data: list[SitePublic]
    count: int
