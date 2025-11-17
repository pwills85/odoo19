# -*- coding: utf-8 -*-
"""
Authentication Models
User and role definitions
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    """User roles with hierarchical permissions"""
    ADMIN = "admin"              # Full access to everything
    OPERATOR = "operator"        # Can generate and send DTEs
    ACCOUNTANT = "accountant"    # Can view and download DTEs
    VIEWER = "viewer"            # Read-only access
    API_CLIENT = "api_client"    # Programmatic access only


class User(BaseModel):
    """User model with authentication info"""

    id: str = Field(..., description="Unique user identifier (sub from JWT)")
    email: EmailStr = Field(..., description="User email address")
    name: str = Field(..., description="Full name")
    roles: List[UserRole] = Field(default=[UserRole.VIEWER], description="User roles")
    company_id: Optional[str] = Field(None, description="Associated company RUT")

    # OAuth2 fields
    provider: str = Field(..., description="OAuth provider (google, azure, etc)")
    provider_user_id: str = Field(..., description="User ID from provider")

    # Metadata
    created_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = Field(default=True)

    # Rate limiting
    requests_per_minute: int = Field(default=60, description="API rate limit")

    class Config:
        use_enum_values = True

    def has_role(self, role: UserRole) -> bool:
        """Check if user has specific role"""
        return role in self.roles

    def has_any_role(self, roles: List[UserRole]) -> bool:
        """Check if user has any of the specified roles"""
        return any(role in self.roles for role in roles)

    def is_admin(self) -> bool:
        """Check if user is admin"""
        return UserRole.ADMIN in self.roles

    def can_generate_dte(self) -> bool:
        """Check if user can generate DTEs"""
        return self.has_any_role([UserRole.ADMIN, UserRole.OPERATOR])

    def can_view_dte(self) -> bool:
        """Check if user can view DTEs"""
        return self.has_any_role([UserRole.ADMIN, UserRole.OPERATOR, UserRole.ACCOUNTANT, UserRole.VIEWER])


class TokenData(BaseModel):
    """JWT token payload data"""
    sub: str = Field(..., description="Subject (user ID)")
    email: EmailStr
    name: str
    roles: List[UserRole]
    company_id: Optional[str] = None
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")

    class Config:
        use_enum_values = True


class OAuth2Token(BaseModel):
    """OAuth2 token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class LoginRequest(BaseModel):
    """Login request payload"""
    provider: str = Field(..., description="OAuth provider (google, azure)")
    authorization_code: str = Field(..., description="Authorization code from OAuth flow")
    redirect_uri: str = Field(..., description="Redirect URI used in auth request")


class LoginResponse(BaseModel):
    """Login response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    user: User
