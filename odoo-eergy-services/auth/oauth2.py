# -*- coding: utf-8 -*-
"""
OAuth2/OIDC Authentication Handler
Supports Google, Azure AD, and custom OIDC providers
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import structlog
import httpx
import os

from .models import User, UserRole, TokenData, OAuth2Token
from config import settings

logger = structlog.get_logger()

# Security
security = HTTPBearer()

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30


class OAuth2Handler:
    """Handle OAuth2/OIDC authentication flows"""

    PROVIDERS = {
        "google": {
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        },
        "azure": {
            "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/v1.0/me",
            "client_id": os.getenv("AZURE_CLIENT_ID"),
            "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
        },
    }

    @classmethod
    async def exchange_code_for_token(
        cls,
        provider: str,
        code: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token

        Args:
            provider: OAuth provider (google, azure)
            code: Authorization code from OAuth callback
            redirect_uri: Redirect URI used in auth request

        Returns:
            Dict with token information

        Raises:
            HTTPException: If provider invalid or token exchange fails
        """
        if provider not in cls.PROVIDERS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported provider: {provider}"
            )

        provider_config = cls.PROVIDERS[provider]

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    provider_config["token_url"],
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "client_id": provider_config["client_id"],
                        "client_secret": provider_config["client_secret"],
                    },
                    timeout=10.0
                )

                response.raise_for_status()
                return response.json()

            except httpx.HTTPError as e:
                logger.error("oauth_token_exchange_failed",
                           provider=provider,
                           error=str(e))
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to exchange authorization code"
                )

    @classmethod
    async def get_user_info(cls, provider: str, access_token: str) -> Dict[str, Any]:
        """
        Get user information from OAuth provider

        Args:
            provider: OAuth provider
            access_token: Access token from provider

        Returns:
            Dict with user info (email, name, etc)
        """
        provider_config = cls.PROVIDERS[provider]

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    provider_config["userinfo_url"],
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10.0
                )

                response.raise_for_status()
                return response.json()

            except httpx.HTTPError as e:
                logger.error("oauth_userinfo_failed",
                           provider=provider,
                           error=str(e))
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to get user info from provider"
                )

    @classmethod
    def create_access_token(cls, user: User) -> str:
        """
        Create JWT access token for user

        Args:
            user: User object

        Returns:
            JWT token string
        """
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode = {
            "sub": user.id,
            "email": user.email,
            "name": user.name,
            "roles": [role.value for role in user.roles],
            "company_id": user.company_id,
            "exp": int(expire.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
        }

        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        logger.info("access_token_created",
                   user_id=user.id,
                   email=user.email,
                   expires_at=expire.isoformat())

        return encoded_jwt

    @classmethod
    def create_refresh_token(cls, user: User) -> str:
        """
        Create JWT refresh token for user

        Args:
            user: User object

        Returns:
            JWT refresh token string
        """
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode = {
            "sub": user.id,
            "type": "refresh",
            "exp": int(expire.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
        }

        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        return encoded_jwt

    @classmethod
    def decode_token(cls, token: str) -> TokenData:
        """
        Decode and validate JWT token

        Args:
            token: JWT token string

        Returns:
            TokenData object

        Raises:
            HTTPException: If token invalid or expired
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

            # Validate expiration
            exp = payload.get("exp")
            if exp and datetime.utcnow().timestamp() > exp:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            token_data = TokenData(**payload)
            return token_data

        except JWTError as e:
            logger.warning("jwt_decode_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Dependency to get current authenticated user from JWT token

    Args:
        credentials: HTTP Bearer token from request

    Returns:
        User object

    Raises:
        HTTPException: If token invalid or user not found
    """
    token = credentials.credentials

    # Decode token
    token_data = OAuth2Handler.decode_token(token)

    # TODO: Load user from database using token_data.sub
    # For now, create user from token data
    user = User(
        id=token_data.sub,
        email=token_data.email,
        name=token_data.name,
        roles=[UserRole(role) for role in token_data.roles],
        company_id=token_data.company_id,
        provider="jwt",  # Placeholder
        provider_user_id=token_data.sub
    )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    logger.info("user_authenticated",
               user_id=user.id,
               email=user.email,
               roles=[r.value for r in user.roles])

    return user


def require_auth(func):
    """
    Decorator to require authentication for endpoint

    Usage:
        @app.get("/protected")
        @require_auth
        async def protected_endpoint(user: User = Depends(get_current_user)):
            return {"user": user.email}
    """
    async def wrapper(*args, **kwargs):
        return await func(*args, **kwargs)
    return wrapper
