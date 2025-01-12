import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.security import OAuth2PasswordBearer, HTTPBasicCredentials
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import RedirectResponse, JSONResponse

from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.logging_middleware import request_logger
from app.models.database import init_db
from app.routes.security_api import security, authenticate_user, custom_http_basic
from app.routes.v1_0.device import device_api as device_routes
from app.routes.v1_0.readings import readings_api as readings_routes
from app.routes import security_api as security_routes
from app.routes.v1_0.user import user_api as user_routes
#from app.routes.v1_0.user import resources_api as resources_routes
#from app.routes.v1_0.user import role_api as role_routes
from fastapi import FastAPI, Depends


async def app_lifespan(app: FastAPI):
    await init_db()
    yield


api_app = FastAPI(lifespan=app_lifespan)


def config():
    api_app.include_router(device_routes.router, prefix="/v1.0")
    api_app.include_router(readings_routes.router, prefix="/v1.0")
    api_app.include_router(security_routes.router, prefix="")
    api_app.include_router(user_routes.router, prefix="/v1.0")
    # api_app.include_router(resources_routes.router, prefix="/v1.0")
    # api_app.include_router(role_routes.router, prefix="/v1.0")


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
api_app.add_middleware(AuthMiddleware)

# Configure Trusted Hosts
api_app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*"]
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@api_app.get("/openapi.json")
async def get_open_api_endpoint(user=Depends(custom_http_basic)):
    return JSONResponse(get_openapi(title="FastAPI", version="1.0", routes=api_app.routes))


@api_app.get("/docs")
async def get_documentation(user=Depends(custom_http_basic)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Documentation")


if __name__ == "__main__":
    uvicorn.run("api_app:api_app", host="0.0.0.0", port=5000, reload=True)
