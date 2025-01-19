from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi import HTTPException

class TokenExtractorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.headers.get("Authorization") or request.cookies.get("Authorization")
        if token:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            request.state.token = token
        else:
            request.state.token = None
        return await call_next(request)
