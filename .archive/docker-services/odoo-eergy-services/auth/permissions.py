# -*- coding: utf-8 -*-
"""
RBAC - Role-Based Access Control
Permission system for DTE service
"""

from fastapi import HTTPException, status, Depends
from typing import List, Callable
from enum import Enum
from functools import wraps
import structlog

from .models import User, UserRole
from .oauth2 import get_current_user

logger = structlog.get_logger()


class Permission(str, Enum):
    """
    Fine-grained permissions for DTE operations
    Permissions are cumulative based on role hierarchy
    """

    # DTE Operations
    DTE_GENERATE = "dte:generate"           # Generate DTE XML
    DTE_SIGN = "dte:sign"                   # Sign DTE
    DTE_SEND = "dte:send"                   # Send to SII
    DTE_VIEW = "dte:view"                   # View DTE details
    DTE_DOWNLOAD = "dte:download"           # Download DTE XML/PDF
    DTE_CANCEL = "dte:cancel"               # Cancel/void DTE
    DTE_RESEND = "dte:resend"               # Resend failed DTE

    # Certificate Management
    CERT_UPLOAD = "cert:upload"             # Upload certificates
    CERT_VIEW = "cert:view"                 # View certificate info
    CERT_DELETE = "cert:delete"             # Delete certificates

    # CAF Management
    CAF_UPLOAD = "caf:upload"               # Upload CAF files
    CAF_VIEW = "caf:view"                   # View CAF info
    CAF_DELETE = "caf:delete"               # Delete CAF

    # Status & Reporting
    STATUS_VIEW = "status:view"             # View DTE status
    STATUS_POLL = "status:poll"             # Manually poll SII
    REPORT_VIEW = "report:view"             # View reports
    REPORT_GENERATE = "report:generate"     # Generate reports

    # Admin Operations
    USER_MANAGE = "user:manage"             # Manage users
    SETTINGS_MANAGE = "settings:manage"     # Manage settings
    LOGS_VIEW = "logs:view"                 # View system logs
    METRICS_VIEW = "metrics:view"           # View metrics

    # API Access
    API_READ = "api:read"                   # Read-only API access
    API_WRITE = "api:write"                 # Write API access
    API_ADMIN = "api:admin"                 # Admin API access


# Role → Permissions mapping
ROLE_PERMISSIONS: dict[UserRole, List[Permission]] = {
    UserRole.VIEWER: [
        Permission.DTE_VIEW,
        Permission.DTE_DOWNLOAD,
        Permission.STATUS_VIEW,
        Permission.REPORT_VIEW,
        Permission.CAF_VIEW,
        Permission.CERT_VIEW,
        Permission.API_READ,
    ],

    UserRole.ACCOUNTANT: [
        # All viewer permissions
        *ROLE_PERMISSIONS.get(UserRole.VIEWER, []),
        # Plus
        Permission.REPORT_GENERATE,
        Permission.METRICS_VIEW,
    ],

    UserRole.OPERATOR: [
        # All accountant permissions
        *ROLE_PERMISSIONS.get(UserRole.ACCOUNTANT, []),
        # Plus
        Permission.DTE_GENERATE,
        Permission.DTE_SIGN,
        Permission.DTE_SEND,
        Permission.DTE_RESEND,
        Permission.STATUS_POLL,
        Permission.CAF_UPLOAD,
        Permission.CAF_VIEW,
        Permission.API_WRITE,
    ],

    UserRole.ADMIN: [
        # All permissions
        *[perm for perm in Permission],
    ],

    UserRole.API_CLIENT: [
        Permission.DTE_GENERATE,
        Permission.DTE_SIGN,
        Permission.DTE_SEND,
        Permission.DTE_VIEW,
        Permission.STATUS_VIEW,
        Permission.API_READ,
        Permission.API_WRITE,
    ],
}


def get_user_permissions(user: User) -> List[Permission]:
    """
    Get all permissions for user based on their roles

    Args:
        user: User object

    Returns:
        List of permissions
    """
    permissions = set()

    for role in user.roles:
        role_perms = ROLE_PERMISSIONS.get(role, [])
        permissions.update(role_perms)

    return list(permissions)


def check_permission(user: User, permission: Permission) -> bool:
    """
    Check if user has specific permission

    Args:
        user: User object
        permission: Permission to check

    Returns:
        True if user has permission, False otherwise
    """
    user_permissions = get_user_permissions(user)
    has_perm = permission in user_permissions

    logger.debug("permission_check",
                user_id=user.id,
                permission=permission.value,
                has_permission=has_perm,
                user_roles=[r.value for r in user.roles])

    return has_perm


def require_permission(permission: Permission) -> Callable:
    """
    Decorator to require specific permission for endpoint

    Args:
        permission: Required permission

    Returns:
        Decorator function

    Usage:
        @app.post("/api/dte/generate")
        @require_permission(Permission.DTE_GENERATE)
        async def generate_dte(user: User = Depends(get_current_user)):
            # Only users with DTE_GENERATE permission can access
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User = Depends(get_current_user), **kwargs):
            if not check_permission(user, permission):
                logger.warning("permission_denied",
                             user_id=user.id,
                             email=user.email,
                             required_permission=permission.value,
                             user_roles=[r.value for r in user.roles])

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied. Required: {permission.value}"
                )

            return await func(*args, user=user, **kwargs)

        return wrapper
    return decorator


def require_any_permission(*permissions: Permission) -> Callable:
    """
    Decorator to require ANY of the specified permissions

    Args:
        permissions: List of acceptable permissions

    Returns:
        Decorator function

    Usage:
        @app.get("/api/dte/view")
        @require_any_permission(Permission.DTE_VIEW, Permission.API_READ)
        async def view_dte(user: User = Depends(get_current_user)):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User = Depends(get_current_user), **kwargs):
            has_any = any(check_permission(user, perm) for perm in permissions)

            if not has_any:
                logger.warning("permission_denied_any",
                             user_id=user.id,
                             email=user.email,
                             required_permissions=[p.value for p in permissions],
                             user_roles=[r.value for r in user.roles])

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied. Required one of: {[p.value for p in permissions]}"
                )

            return await func(*args, user=user, **kwargs)

        return wrapper
    return decorator


def require_all_permissions(*permissions: Permission) -> Callable:
    """
    Decorator to require ALL of the specified permissions

    Args:
        permissions: List of required permissions

    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User = Depends(get_current_user), **kwargs):
            has_all = all(check_permission(user, perm) for perm in permissions)

            if not has_all:
                logger.warning("permission_denied_all",
                             user_id=user.id,
                             email=user.email,
                             required_permissions=[p.value for p in permissions],
                             user_roles=[r.value for r in user.roles])

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied. Required all of: {[p.value for p in permissions]}"
                )

            return await func(*args, user=user, **kwargs)

        return wrapper
    return decorator


def require_role(role: UserRole) -> Callable:
    """
    Decorator to require specific role

    Args:
        role: Required role

    Returns:
        Decorator function

    Usage:
        @app.post("/api/admin/users")
        @require_role(UserRole.ADMIN)
        async def manage_users(user: User = Depends(get_current_user)):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User = Depends(get_current_user), **kwargs):
            if not user.has_role(role):
                logger.warning("role_denied",
                             user_id=user.id,
                             email=user.email,
                             required_role=role.value,
                             user_roles=[r.value for r in user.roles])

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role denied. Required: {role.value}"
                )

            return await func(*args, user=user, **kwargs)

        return wrapper
    return decorator


def require_company_access(company_id: str) -> Callable:
    """
    Decorator to require access to specific company

    Args:
        company_id: Company RUT

    Returns:
        Decorator function

    Usage:
        @app.get("/api/company/{company_id}/dtes")
        @require_company_access
        async def get_company_dtes(
            company_id: str,
            user: User = Depends(get_current_user)
        ):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User = Depends(get_current_user), **kwargs):
            # Admins have access to all companies
            if user.is_admin():
                return await func(*args, user=user, **kwargs)

            # Check if user's company matches
            if user.company_id != company_id:
                logger.warning("company_access_denied",
                             user_id=user.id,
                             email=user.email,
                             user_company=user.company_id,
                             requested_company=company_id)

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this company's data"
                )

            return await func(*args, user=user, **kwargs)

        return wrapper
    return decorator
