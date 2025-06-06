import os
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import RedirectResponse, JSONResponse, Response
from starlette.requests import Request
from dotenv import load_dotenv

# Import your updated modules
from app.middleware.auth_middleware import JWTAuthMiddleware
from app.models.database import init_db
from app.routes import security_api as security_routes
from app.routes.v1_0.brand import brand_api as brand_routes
from app.routes.v1_0.categories import categories_api as categories_routes
from app.routes.v1_0.franchise import franchise_api as franchise_routes
from app.routes.v1_0.products import products_api as products_routes
from app.routes.v1_0.user import user_api as user_routes
from app.utils.security_utils.security_utils import BasicAuth, basic_auth

# Load environment variables
load_dotenv()


# Application lifespan
async def app_lifespan(app: FastAPI):
    """Initialize database and other startup tasks."""
    await init_db()
    yield


# Environment-based configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")

# Default origins for development
if not ALLOWED_ORIGINS or ALLOWED_ORIGINS == [""]:
    origins = [
        "http://localhost:8080",
        "http://localhost:5000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080"
    ]
else:
    origins = ALLOWED_ORIGINS

# Production origins (update these to your actual domains)
if ENVIRONMENT == "production":
    origins.extend([
        "https://green.ecm.energyatech.com",
        "https://onestoreasd.netlify.app",
        "https://onestore-figures.netlify.app",
        "https://ecommerce-toys01.vercel.app",
        "https://photo-report-api.onrender.com"  # Add your API domain too
    ])

print(f"🌐 CORS allowed origins: {origins}")
print(f"🚀 Running in {ENVIRONMENT} mode")


class CustomCORSMiddleware(BaseHTTPMiddleware):
    """
    Custom CORS middleware optimized for JWT authentication.
    Handles preflight requests before authentication middleware.
    """

    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin")

        # Handle preflight requests immediately (before JWT validation)
        if request.method == "OPTIONS":
            return self._create_preflight_response(origin)

        # Process the actual request
        response = await call_next(request)

        # Add CORS headers to response
        if origin in origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "false"  # JWT doesn't need credentials
            response.headers["Access-Control-Expose-Headers"] = "Authorization, Content-Type"

        return response

    def _create_preflight_response(self, origin: str) -> Response:
        """Create response for OPTIONS preflight requests."""
        if origin not in origins:
            return Response(status_code=403, content="Origin not allowed")

        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, User-Agent, X-Requested-With",
                "Access-Control-Max-Age": "86400",  # 24 hours
                "Access-Control-Allow-Credentials": "false",  # No cookies needed for JWT
                "Content-Length": "0"
            }
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Add HSTS only in production with HTTPS
        if ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        return response


# Define middleware stack (order matters!)
middleware = [
    # 1. Custom CORS (must be first to handle preflight)
    Middleware(CustomCORSMiddleware),

    # 2. Security headers
    Middleware(SecurityHeadersMiddleware),

    # 3. Trusted host protection
    Middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "localhost",
            "127.0.0.1",
            "photo-report-api.onrender.com",  # Your API domain
            "onestore-figures.netlify.app",  # Your frontend domain
            "*.energyatech.com",
            "*.netlify.app",
            "*.vercel.app",
            "*.onrender.com"  # Allow all onrender subdomains
        ] if ENVIRONMENT == "production" else ["*"]
    ),

    # 4. JWT Authentication (last, so CORS is handled first)
    Middleware(
        JWTAuthMiddleware,
        exclude_paths=[
            "/docs", "/redoc", "/openapi.json",
            "/login", "/login_basic", "/register",
            "/health", "/ping", "/favicon.ico",
            # Add your public endpoints here
        ]
    )
]

# Initialize FastAPI app
api_app = FastAPI(
    title="JWT Authentication API",
    description="Cross-domain JWT authentication API for e-commerce platform",
    version="1.0.0",
    lifespan=app_lifespan,
    docs_url=None,  # Custom docs with auth
    redoc_url=None,
    openapi_url=None,  # Custom OpenAPI with auth
    middleware=middleware,
)


def config():
    """Configure API routes."""
    # Include all your existing routes
    api_app.include_router(security_routes.auth_router, prefix="")
    api_app.include_router(user_routes.router, prefix="/v1.0")
    api_app.include_router(products_routes.router, prefix="/v1.0")
    api_app.include_router(franchise_routes.router, prefix="/v1.0")
    api_app.include_router(brand_routes.router, prefix="/v1.0")
    api_app.include_router(categories_routes.router, prefix="/v1.0")


# Configure routes
config()


# Protected documentation endpoints
@api_app.get("/openapi.json")
async def get_open_api_endpoint(auth: BasicAuth = Depends(basic_auth)):
    """Get OpenAPI schema (protected by basic auth)."""
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for API documentation",
            headers={"WWW-Authenticate": "Basic"},
        )

    return JSONResponse(
        get_openapi(
            title="E-commerce API",
            version="1.0.0",
            description="JWT-based e-commerce API with cross-domain support",
            routes=api_app.routes
        )
    )


@api_app.get("/docs")
async def get_documentation(auth: BasicAuth = Depends(basic_auth)):
    """Get Swagger UI documentation (protected by basic auth)."""
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for API documentation",
            headers={"WWW-Authenticate": "Basic"},
        )

    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="E-commerce API Documentation",
        swagger_favicon_url="/favicon.ico"
    )


# Public health check endpoint
@api_app.get("/health")
async def health_check():
    """Public health check endpoint."""
    return {
        "status": "healthy",
        "service": "e-commerce-api",
        "version": "1.0.0",
        "environment": ENVIRONMENT
    }


# Root endpoint
@api_app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "E-commerce JWT Authentication API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "environment": ENVIRONMENT
    }


# Global exception handlers
@api_app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={
            "detail": "Endpoint not found",
            "path": str(request.url.path)
        }
    )


@api_app.exception_handler(422)
async def validation_exception_handler(request: Request, exc):
    """Handle validation errors."""
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Validation error",
            "errors": exc.errors() if hasattr(exc, 'errors') else str(exc)
        }
    )


@api_app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc):
    """Handle internal server errors."""
    import logging
    logger = logging.getLogger(__name__)
    logger.error(f"Internal server error: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error" if ENVIRONMENT == "production" else str(exc),
            "type": "server_error"
        }
    )


# Development vs Production configuration
if ENVIRONMENT == "development":
    # Development: Enable debug mode
    import logging

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("🔧 Development mode: Debug logging enabled")

    # Add development-specific middleware or configurations here
    pass
else:
    # Production: Optimize for performance
    import logging

    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.info("🚀 Production mode: Optimized configuration")

# Application entry point
if __name__ == "__main__":
    # Configuration for different environments
    if ENVIRONMENT == "development":
        uvicorn.run(
            "main:api_app",  # Update this to your actual module name
            host="0.0.0.0",
            port=5000,
            reload=True,
            log_level="info"
        )
    else:
        uvicorn.run(
            "main:api_app",
            host="0.0.0.0",
            port=int(os.getenv("PORT", 5000)),
            reload=False,
            log_level="warning",
            workers=int(os.getenv("WORKERS", 4))
        )
