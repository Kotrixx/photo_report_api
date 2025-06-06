import jwt
import logging
import os
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from dotenv import load_dotenv

from app.utils.security_utils.security_utils import (
    decode_and_validate_token,
    extract_token_from_header,
    is_token_revoked
)

# Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """
    JWT-only authentication middleware for FastAPI.
    Completely removes cookie-based authentication support.
    """

    def __init__(self, app, exclude_paths: list = None):
        super().__init__(app)
        # Default public routes that don't require authentication
        self.public_routes = {
            "/docs", "/redoc", "/openapi.json", "/favicon.ico",
            "/login", "/register", "/health", "/ping"
        }

        # Add any additional excluded paths
        if exclude_paths:
            self.public_routes.update(exclude_paths)

    async def dispatch(self, request: Request, call_next):
        """
        Process JWT authentication for protected routes.
        """
        # Skip authentication for public routes
        if self._is_public_route(request.url.path):
            return await call_next(request)

        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Determine if route requires authentication
        if not self._requires_authentication(request.url.path):
            return await call_next(request)

        try:
            # Extract and validate JWT token
            token = extract_token_from_header(request)
            payload = await decode_and_validate_token(token, "access")

            # Store user data in request state
            request.state.user = payload
            request.state.user_id = payload.get("user_uid")
            request.state.username = payload.get("sub")

            # Log successful authentication for monitoring
            logger.info(
                f"Authenticated user {payload.get('sub')} for {request.method} {request.url.path}"
            )

        except HTTPException as e:
            # Log authentication failures for security monitoring
            logger.warning(
                f"Authentication failed for {request.method} {request.url.path} "
                f"from {request.client.host}: {e.detail}"
            )
            return JSONResponse(
                {"detail": e.detail, "type": "authentication_error"},
                status_code=e.status_code
            )
        except Exception as e:
            logger.error(f"Unexpected error in JWT middleware: {e}", exc_info=True)
            return JSONResponse(
                {"detail": "Internal authentication error", "type": "server_error"},
                status_code=500
            )

        # Proceed with the request
        response = await call_next(request)
        return response

    def _is_public_route(self, path: str) -> bool:
        """Check if the route is public and doesn't require authentication."""
        return any(path.startswith(route) for route in self.public_routes)

    def _requires_authentication(self, path: str) -> bool:
        """Determine if a route requires authentication."""
        # Define protected route patterns
        protected_patterns = ["/user/", "/admin/", "/protected/", "/api/"]

        # Check if path matches any protected pattern
        return any(pattern in path for pattern in protected_patterns)


class RoleBasedAccessMiddleware(BaseHTTPMiddleware):
    """
    Optional: Role-based access control middleware.
    Use this in addition to JWTAuthMiddleware for routes that need role checking.
    """

    def __init__(self, app, admin_routes: list = None):
        super().__init__(app)
        self.admin_routes = admin_routes or ["/admin/"]

    async def dispatch(self, request: Request, call_next):
        """Check user roles for admin routes."""

        # Skip if user is not authenticated (handled by JWT middleware)
        if not hasattr(request.state, 'user'):
            return await call_next(request)

        # Check admin routes
        if any(request.url.path.startswith(route) for route in self.admin_routes):
            user_data = request.state.user
            user_role = user_data.get("role", "user")

            if user_role != "admin":
                logger.warning(
                    f"Access denied for user {user_data.get('sub')} "
                    f"to admin route {request.url.path}"
                )
                return JSONResponse(
                    {"detail": "Admin access required", "type": "authorization_error"},
                    status_code=403
                )

        return await call_next(request)


# Alternative: Dependency-based authentication (more FastAPI-idiomatic)
class JWTDependency:
    """
    Alternative to middleware: Use as a dependency for specific routes.
    This gives you more granular control over which routes require auth.
    """

    def __init__(self, required_role: str = None):
        self.required_role = required_role

    async def __call__(self, request: Request):
        try:
            token = extract_token_from_header(request)
            payload = await decode_and_validate_token(token, "access")

            # Check role if required
            if self.required_role:
                user_role = payload.get("role", "user")
                if user_role != self.required_role:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Role '{self.required_role}' required"
                    )

            return payload

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"JWT dependency error: {e}")
            raise HTTPException(status_code=500, detail="Authentication error")


# Create dependency instances
require_auth = JWTDependency()
require_admin = JWTDependency(required_role="admin")

# Usage in main.py:
"""
from fastapi import FastAPI
from middleware import JWTAuthMiddleware, RoleBasedAccessMiddleware

app = FastAPI()

# Add JWT middleware
app.add_middleware(
    JWTAuthMiddleware,
    exclude_paths=["/public", "/webhook"]  # Optional additional public paths
)

# Optional: Add role-based access control
app.add_middleware(
    RoleBasedAccessMiddleware,
    admin_routes=["/admin/", "/dashboard/admin/"]
)

# Alternative: Use as dependency in specific routes
@app.get("/protected")
async def protected_route(user_data: dict = Depends(require_auth)):
    return {"user": user_data["sub"]}

@app.get("/admin")
async def admin_route(user_data: dict = Depends(require_admin)):
    return {"admin": user_data["sub"]}
"""