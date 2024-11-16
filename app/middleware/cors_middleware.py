from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware


def cors_middleware(app: FastAPI):
    """
    Configure middlewares for the FastAPI application.
    :param: app (FastAPI): The FastAPI application instance.
    """
    # Configure CORS
    origins = [
        "http://localhost",
        "http://localhost:5000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5000",
        "https://test-hosting-map.web.app",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Configure Trusted Hosts
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*"]
    )
