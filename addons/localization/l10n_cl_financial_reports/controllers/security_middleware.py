# -*- coding: utf-8 -*-
"""
Compat wrapper del middleware de seguridad para este módulo.
Reexporta utilidades desde `controllers/security_middleware.py` del proyecto.
"""

try:
    # Intentar importar desde el paquete raíz del proyecto
    from controllers.security_middleware import (
        secure_api_endpoint,
        SecurityConfig,
        SecurityUtils,
        validate_jwt_token,
        rate_limit,
        sanitize_input,
        audit_log,
    )  # type: ignore
except Exception as import_error:  # pragma: no cover
    # Fallback: definir stubs que fallen explícitamente para no ocultar errores
    raise import_error


