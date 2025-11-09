# -*- coding: utf-8 -*-
"""
Compat wrapper del middleware de seguridad para este módulo.
Reexporta utilidades desde `controllers/security_middleware.py` del proyecto.
"""

try:
    # Intentar importar desde el paquete raíz del proyecto
    pass  # type: ignore
except Exception as import_error:  # pragma: no cover
    # Fallback: definir stubs que fallen explícitamente para no ocultar errores
    raise import_error


