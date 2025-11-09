# -*- coding: utf-8 -*-
"""
Authentication Module
OAuth2/OIDC implementation for DTE Service
"""

from .oauth2 import OAuth2Handler, get_current_user, require_auth
from .permissions import Permission, require_permission, check_permission
from .models import User, UserRole

__all__ = [
    'OAuth2Handler',
    'get_current_user',
    'require_auth',
    'Permission',
    'require_permission',
    'check_permission',
    'User',
    'UserRole',
]
