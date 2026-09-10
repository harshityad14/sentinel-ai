"""Common API response and pagination schemas."""

from typing import Generic, TypeVar, List, Optional
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard envelope for paginated collections."""

    items: List[T] = Field(description="Page of records")
    total: int = Field(description="Total number of records matching query")
    limit: int = Field(description="Maximum items per page")
    offset: int = Field(description="Offset in result set")
    has_more: bool = Field(description="Whether more records exist beyond this page")


class HealthResponse(BaseModel):
    """System health status."""

    status: str = Field(default="healthy", description="Application service status")
    service: str = Field(default="sentinel-api", description="Service identifier")
    version: str = Field(description="Service version")
    timestamp: str = Field(description="Current system time ISO 8601")


class ReadinessResponse(BaseModel):
    """Database and dependency readiness status."""

    status: str = Field(description="'ready' if operational, otherwise 'unhealthy'")
    database: bool = Field(description="Database connectivity status")
    environment: str = Field(description="Active environment")
    version: str = Field(description="Service version")


class ErrorResponse(BaseModel):
    """Standardized error envelope."""

    error: str = Field(description="Error type or code")
    message: str = Field(description="Human-readable error description")
    details: Optional[dict] = Field(default=None, description="Optional error context or field errors")
