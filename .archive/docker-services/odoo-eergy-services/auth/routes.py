# -*- coding: utf-8 -*-
"""
Authentication Routes
OAuth2 login/logout endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends
from typing import Dict
import structlog

from .models import LoginRequest, LoginResponse, User, UserRole, OAuth2Token
from .oauth2 import OAuth2Handler, get_current_user
from .permissions import get_user_permissions

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest) -> LoginResponse:
    """
    OAuth2 login endpoint

    Flow:
    1. Frontend redirects user to OAuth provider
    2. User authenticates with provider
    3. Provider redirects back with authorization code
    4. Frontend calls this endpoint with code
    5. We exchange code for provider access token
    6. We get user info from provider
    7. We create our own JWT tokens
    8. Return tokens to frontend

    Args:
        request: Login request with provider and authorization code

    Returns:
        LoginResponse with access_token, refresh_token, and user info

    Raises:
        HTTPException: If authentication fails
    """
    logger.info("login_attempt",
               provider=request.provider)

    try:
        # 1. Exchange authorization code for provider access token
        token_response = await OAuth2Handler.exchange_code_for_token(
            provider=request.provider,
            code=request.authorization_code,
            redirect_uri=request.redirect_uri
        )

        provider_access_token = token_response.get("access_token")

        # 2. Get user info from provider
        user_info = await OAuth2Handler.get_user_info(
            provider=request.provider,
            access_token=provider_access_token
        )

        # 3. Create or update user
        # TODO: Load from database, for now create from provider data
        user = User(
            id=user_info.get("id") or user_info.get("sub"),
            email=user_info.get("email"),
            name=user_info.get("name") or user_info.get("displayName"),
            provider=request.provider,
            provider_user_id=user_info.get("id") or user_info.get("sub"),
            roles=[UserRole.VIEWER],  # Default role, TODO: load from DB
        )

        # 4. Create our JWT tokens
        access_token = OAuth2Handler.create_access_token(user)
        refresh_token = OAuth2Handler.create_refresh_token(user)

        logger.info("login_success",
                   user_id=user.id,
                   email=user.email,
                   provider=request.provider)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=3600,  # 1 hour
            user=user
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("login_failed",
                    provider=request.provider,
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/refresh", response_model=OAuth2Token)
async def refresh_token(refresh_token: str) -> OAuth2Token:
    """
    Refresh access token using refresh token

    Args:
        refresh_token: JWT refresh token

    Returns:
        New OAuth2Token with access_token

    Raises:
        HTTPException: If refresh token invalid
    """
    try:
        # Decode refresh token
        token_data = OAuth2Handler.decode_token(refresh_token)

        # Validate it's a refresh token
        if token_data.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        # TODO: Load user from database
        user = User(
            id=token_data.sub,
            email=token_data.email,
            name=token_data.name,
            roles=[UserRole(role) for role in token_data.roles],
            provider="jwt",
            provider_user_id=token_data.sub
        )

        # Create new access token
        access_token = OAuth2Handler.create_access_token(user)

        logger.info("token_refreshed", user_id=user.id)

        return OAuth2Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=3600
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("token_refresh_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to refresh token"
        )


@router.get("/me", response_model=User)
async def get_current_user_info(
    user: User = Depends(get_current_user)
) -> User:
    """
    Get current authenticated user information

    Args:
        user: Current user from JWT token

    Returns:
        User object with current user info
    """
    logger.info("user_info_requested", user_id=user.id, email=user.email)
    return user


@router.get("/me/permissions")
async def get_my_permissions(
    user: User = Depends(get_current_user)
) -> Dict[str, list]:
    """
    Get current user's permissions

    Args:
        user: Current user from JWT token

    Returns:
        Dict with user permissions
    """
    permissions = get_user_permissions(user)

    return {
        "user_id": user.id,
        "email": user.email,
        "roles": [role.value for role in user.roles],
        "permissions": [perm.value for perm in permissions]
    }


@router.post("/logout")
async def logout(user: User = Depends(get_current_user)) -> Dict[str, str]:
    """
    Logout endpoint (client-side token deletion)

    Note: JWT tokens are stateless, so "logout" is handled client-side
    by deleting the tokens. For true server-side logout, implement
    a token blacklist in Redis.

    Args:
        user: Current user

    Returns:
        Success message
    """
    logger.info("user_logout", user_id=user.id, email=user.email)

    # TODO: Add token to blacklist in Redis if implementing server-side logout

    return {"message": "Logged out successfully"}
