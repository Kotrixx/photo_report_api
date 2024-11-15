from datetime import datetime, timezone

from beanie import PydanticObjectId
from fastapi import HTTPException
from starlette import status
from app.routes.v1_0.device import router


@router.get("/")
async def get_devices():
    return "hola"
