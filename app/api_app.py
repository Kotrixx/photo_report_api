import base64
import httpx
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security import OAuth2PasswordBearer
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import HTMLResponse, RedirectResponse, JSONResponse
from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.cors_middleware import cors_middleware
from app.middleware.logging_middleware import request_logger
from app.models.database import init_db
from app.routes.v1_0.device import device_api as device_routes
from app.routes.v1_0.readings import readings_api as readings_routes
from app.routes.v1_0.security import security_api as security_routes
from app.routes.v1_0.user import user_api as user_routes
from app.routes.v1_0.user import permissions_api as permissions_routes
from app.routes.v1_0.user import resources_api as resources_routes
from fastapi import FastAPI, Depends, HTTPException, Response, Request


async def app_lifespan(app: FastAPI):
    await init_db()
    yield


api_app = FastAPI(lifespan=app_lifespan)


def config():
    api_app.include_router(device_routes.router, prefix="/v1.0")
    api_app.include_router(readings_routes.router, prefix="/v1.0")
    api_app.include_router(security_routes.router, prefix="/v1.0")
    api_app.include_router(user_routes.router, prefix="/v1.0")
    api_app.include_router(resources_routes.router, prefix="/v1.0")
    api_app.include_router(permissions_routes.router, prefix="/v1.0")


config()

# Configurar middleware para logging
api_app.middleware("http")(request_logger)
origins = [
    "http://localhost",
    "http://localhost:5000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000",
    "https://test-hosting-map.web.app",
]

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Trusted Hosts
api_app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*"]
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@api_app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        return Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)

    try:
        _, auth_value = auth.split(" ")
        decoded = base64.b64decode(auth_value).decode("ascii")
        username, _, password = decoded.partition(":")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/v1.0/security/token",
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if response.status_code == 200:
            token_data = response.json()
            token = token_data["access_token"]
            redirect_response = RedirectResponse(url="/docs")
            redirect_response.set_cookie(
                key="Authorization",
                value=f"Bearer {token}",
                httponly=True,
                max_age=1800,
                expires=1800,
            )
            return redirect_response
        else:
            raise HTTPException(status_code=response.status_code, detail=response.json())

    except Exception as e:
        import traceback
        print(f"Error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)


if __name__ == "__main__":
    uvicorn.run("api_app:api_app", host="0.0.0.0", port=5000, reload=True)
