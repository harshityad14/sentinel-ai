"""SentinelAI FastAPI application entrypoint and factory."""

import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.db.base import Base
from app.db.session import engine, check_db_health
from app.api.v1.router import api_v1_router
from app.middleware.security_headers import SecurityHeadersMiddleware
import app.models  # Register all models with Base

START_TIME = time.time()


# Setup structured backend logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("sentinel.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan managing startup and shutdown routines."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version} (env: {settings.environment})")
    
    # Initialize database tables if in sqlite dev/test mode
    if settings.database_url.startswith("sqlite"):
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Initialized local SQLite database schema")
        except Exception as exc:
            logger.error(f"Failed to initialize SQLite database: {exc}")

    db_ready = check_db_health(engine)
    if db_ready:
        logger.info("Database connectivity check: OK")
    else:
        logger.warning("Database connectivity check: FAILED (service may be in degraded state)")

    yield

    logger.info(f"Shutting down {settings.app_name} and releasing database connections")
    engine.dispose()


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="SentinelAI — AI-Powered Passive Network Threat Detection & Security Operations Platform API",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Security: CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Security: Hardened HTTP security headers (CSP, HSTS, frame protection)
    app.add_middleware(SecurityHeadersMiddleware)

    # Security: Trusted host middleware (if configured)
    if settings.trusted_hosts and "*" not in settings.trusted_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.trusted_hosts,
        )

    # Structured error handling: HTTP exceptions
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTP_ERROR",
                "message": str(exc.detail),
                "status_code": exc.status_code,
            },
        )

    # Structured error handling: Request validation errors
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning(f"Request validation failure on {request.url.path}: {exc.errors()}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "VALIDATION_ERROR",
                "message": "Invalid request parameters or payload",
                "details": exc.errors(),
            },
        )

    # Structured error handling: Unhandled internal exceptions (never leak secrets/traces)
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled error processing {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred.",
            },
        )

    # Root health endpoint
    @app.get("/health", tags=["System Health & Status"])
    def root_health():
        db_healthy = check_db_health(engine)
        return {
            "status": "healthy" if db_healthy else "degraded",
            "service": settings.app_name,
            "version": settings.app_version,
            "environment": settings.environment,
            "phase": "Phase 5 - Backend & Persistence",
            "passive_mode": True,
            "database": "connected" if db_healthy else "disconnected",
        }

    # Prometheus metrics endpoint
    @app.get("/metrics", tags=["Observability & Metrics"])
    def prometheus_metrics():
        uptime = time.time() - START_TIME
        db_healthy = 1 if check_db_health(engine) else 0
        metrics = [
            "# HELP sentinel_api_info Information about SentinelAI API",
            "# TYPE sentinel_api_info gauge",
            f'sentinel_api_info{{version="{settings.app_version}",environment="{settings.environment}",passive_mode="true"}} 1',
            "# HELP sentinel_api_uptime_seconds Time since SentinelAI API process started",
            "# TYPE sentinel_api_uptime_seconds gauge",
            f"sentinel_api_uptime_seconds {uptime:.2f}",
            "# HELP sentinel_database_status Database connectivity status (1=connected, 0=disconnected)",
            "# TYPE sentinel_database_status gauge",
            f"sentinel_database_status {db_healthy}",
            "# HELP sentinel_passive_mode_enforced Passive-only monitoring invariant enforcement",
            "# TYPE sentinel_passive_mode_enforced gauge",
            "sentinel_passive_mode_enforced 1",
        ]
        return Response(
            content="\n".join(metrics) + "\n",
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    # Mount v1 endpoints
    app.include_router(api_v1_router, prefix="/api/v1")

    return app


app = create_app()
