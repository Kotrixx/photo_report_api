from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from starlette.responses import JSONResponse
from typing import Optional
from datetime import datetime, timezone

from app.models.schemas import LoginData
from app.models.models import User
from app.utils.security_utils.security_utils import (
    get_user_and_identifier,
    generate_tokens,
    verify_password,
    decode_and_validate_token,
    revoke_token,
    refresh_token_bearer,
    access_token_bearer,
    get_current_user,
    perform_logout
)

# Create router for authentication endpoints
auth_router = APIRouter()


@auth_router.post("/login")
async def login(login_data: LoginData):
    """
    JWT-only login endpoint.
    Returns access and refresh tokens.
    """
    try:
        # Get user and validate credentials
        user, identifier = await get_user_and_identifier(login_data)

        if not verify_password(login_data.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas"
            )

        if user.status == "inactive":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Cuenta de usuario inactiva"
            )

        # Generate JWT tokens
        tokens = generate_tokens(user, identifier)

        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": tokens["expires_in"],
            "user": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                # Add other non-sensitive user fields as needed
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        # Capturar el error detallado para diagnóstico
        print(f"Error inesperado: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor, por favor intente más tarde. {e}"
        )


@auth_router.post("/login-form")
async def login_form(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Alternative login endpoint that accepts form data (OAuth2 compatible).
    Useful for FastAPI's automatic OpenAPI docs authentication.
    """
    # Create LoginData from form
    login_data = LoginData(
        username=form_data.username,
        password=form_data.password
    )

    # Reuse the main login logic
    return await login(login_data)


@auth_router.post("/refresh")
async def refresh_access_token(token_data: dict = Depends(refresh_token_bearer)):
    """
    Refresh access token using refresh token.
    """
    try:
        user_uid = token_data.get("user_uid")
        identifier = token_data.get("sub")

        if not user_uid or not identifier:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token payload"
            )

        # Verify user still exists and is active
        user = await User.find_one(User.id == user_uid)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )

        # Generate new tokens
        new_tokens = generate_tokens(user, identifier)

        # Optionally revoke the old refresh token for security
        old_jti = token_data.get("jti")
        if old_jti:
            await revoke_token(old_jti)

        return {
            "access_token": new_tokens["access_token"],
            "refresh_token": new_tokens["refresh_token"],
            "token_type": new_tokens["token_type"],
            "expires_in": new_tokens["expires_in"]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@auth_router.post("/logout")
async def logout(request: Request):
    """
    Logout by revoking the current access token.
    JWT-only implementation (no cookies).
    """
    return await perform_logout(request)


@auth_router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current authenticated user information.
    """
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active,
        # Add other fields as needed, but exclude sensitive data
    }


@auth_router.post("/verify-token")
async def verify_token(token_data: dict = Depends(access_token_bearer)):
    """
    Verify if an access token is valid.
    Useful for client-side token validation.
    """
    return {
        "valid": True,
        "user_id": token_data.get("user_uid"),
        "username": token_data.get("sub"),
        "expires_at": token_data.get("exp")
    }


@auth_router.post("/revoke-all-tokens")
async def revoke_all_user_tokens(current_user: User = Depends(get_current_user)):
    """
    Revoke all tokens for the current user.
    This could be implemented by incrementing a user's token version
    or by adding all their tokens to the revocation list.
    """
    try:
        # Implementation depends on your revocation strategy
        # Option 1: Increment user's jwt_version (requires adding this field to User model)
        # current_user.jwt_version += 1
        # await current_user.save()

        # Option 2: Add logic to revoke all tokens for this user
        # This is more complex and requires tracking all issued tokens

        return {"message": "All tokens revoked successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke tokens"
        )


# Protected route examples
@auth_router.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    """
    Example of a protected route that requires valid JWT.
    """
    return {
        "message": f"Hello {current_user.username}!",
        "user_id": str(current_user.id)
    }


# Admin-only route example
@auth_router.get("/admin-only")
async def admin_only_route(token_data: dict = Depends(access_token_bearer)):
    """
    Example of admin-only route.
    You'll need to implement role checking based on your user model.
    """
    # Check if user has admin role (implement based on your user model)
    user_role = token_data.get("role", "user")  # Assuming role is in token
    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return {"message": "Admin access granted"}


# Health check endpoint (public)
@auth_router.get("/health")
async def health_check():
    """
    Public health check endpoint.
    """
    return {
        "status": "healthy",
        "service": "authentication",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }