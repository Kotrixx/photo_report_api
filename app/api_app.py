import uvicorn
# from app.routes.v1_0.user import resources_api as resources_routes
# from app.routes.v1_0.user import role_api as role_routes
from fastapi import FastAPI, Depends
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.security import OAuth2PasswordBearer
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import RedirectResponse, JSONResponse

from app.middleware.auth_middleware import AuthMiddleware
from app.models.database import init_db
from app.routes import security_api as security_routes
from app.routes.v1_0.device import device_api as device_routes
from app.routes.v1_0.readings import readings_api as readings_routes
from app.routes.v1_0.user import user_api as user_routes
from app.utils.security_utils.security_utils import BasicAuth, basic_auth


async def app_lifespan(app: FastAPI):
    await init_db()
    yield


# Configurar middleware para logging
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

origins = [
    "http://localhost:8080",
    "http://localhost:5000",
    "http://green.ecm.energyatech.com",
    "https://green.ecm.energyatech.com",
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    ),
    Middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*"]
    ),
    Middleware(
        AuthMiddleware
    )
]

api_app = FastAPI(
    lifespan=app_lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    middleware=middleware,
)


def config():
    api_app.include_router(device_routes.router, prefix="/v1.0")
    api_app.include_router(readings_routes.router, prefix="/v1.0")
    api_app.include_router(security_routes.router, prefix="")
    api_app.include_router(user_routes.router, prefix="/v1.0")
    # api_app.include_router(resources_routes.router, prefix="/v1.0")
    # api_app.include_router(role_routes.router, prefix="/v1.0")


config()


@api_app.get("/openapi.json")
async def get_open_api_endpoint(auth: BasicAuth = Depends(basic_auth)):
    if auth is None:
        return RedirectResponse(url="/login_basic")
    return JSONResponse(
        get_openapi(title="FastAPI", version="1.0", routes=api_app.routes)
    )


@api_app.get("/docs")
async def get_documentation(auth: BasicAuth = Depends(basic_auth)):
    if auth is None:
        return RedirectResponse(url="/login_basic")
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


if __name__ == "__main__":
    uvicorn.run("api_app:api_app", host="0.0.0.0", port=5000, reload=True)
