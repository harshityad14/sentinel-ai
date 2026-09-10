"""Security Headers Middleware for SentinelAI API.

Injects defense-in-depth HTTP security headers including CSP, HSTS,
frame options, and content sniffing protection.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing secure response headers."""

    CSP_POLICY = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self';"
    )

    PERMISSIONS_POLICY = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # Baseline security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = self.PERMISSIONS_POLICY
        response.headers["Content-Security-Policy"] = self.CSP_POLICY

        # HSTS only emitted over HTTPS or when behind TLS-terminating reverse proxy
        is_https = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response
