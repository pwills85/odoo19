# -*- coding: utf-8 -*-
"""
RUT Utilities for SII Integration - Eergy Services
Delegates to python-stdnum for validation (same as Odoo native).

Author: Eergygroup
Date: 2025-10-24
Architecture: Consolidated from 8 duplicate implementations
"""

from stdnum.cl.rut import is_valid, format, compact


def format_rut_for_sii(rut: str) -> str:
    """
    Formatea RUT para XML SII (sin puntos).

    SII requiere formato: 12345678-9 (sin puntos, con guión)

    Args:
        rut: RUT en cualquier formato (12.345.678-9, 12345678-9, 123456789, etc)

    Returns:
        RUT formato SII: 12345678-9

    Raises:
        ValueError: Si RUT es inválido

    Examples:
        >>> format_rut_for_sii('12.345.678-5')
        '12345678-5'
        >>> format_rut_for_sii('76086428-5')
        '76086428-5'
        >>> format_rut_for_sii('76.086.428-5')
        '76086428-5'
    """
    if not rut:
        raise ValueError("RUT no puede estar vacío")

    if not is_valid(rut):
        raise ValueError(f"RUT inválido: {rut}")

    # Compactar (sin puntos, guiones, espacios)
    clean = compact(rut)

    # Formato SII: XXXXXXXX-Y (sin puntos)
    if len(clean) < 2:
        raise ValueError(f"RUT demasiado corto: {rut}")

    return f"{clean[:-1]}-{clean[-1]}"


def format_rut_dotted(rut: str) -> str:
    """
    Formatea RUT con puntos para display (formato chileno estándar).

    Args:
        rut: RUT en cualquier formato

    Returns:
        RUT formato display: 12.345.678-9

    Raises:
        ValueError: Si RUT es inválido

    Examples:
        >>> format_rut_dotted('123456785')
        '12.345.678-5'
        >>> format_rut_dotted('76086428-5')
        '76.086.428-5'
    """
    if not rut:
        raise ValueError("RUT no puede estar vacío")

    if not is_valid(rut):
        raise ValueError(f"RUT inválido: {rut}")

    # python-stdnum.cl.rut.format() retorna: 12.345.678-9
    return format(rut)


def validate_rut(rut: str) -> bool:
    """
    Valida RUT chileno usando algoritmo Módulo 11.

    Delega a python-stdnum (misma biblioteca que Odoo nativo).

    Args:
        rut: RUT en cualquier formato

    Returns:
        True si válido, False si inválido

    Examples:
        >>> validate_rut('12.345.678-5')
        True
        >>> validate_rut('12345678-5')
        True
        >>> validate_rut('12345678-9')
        False
        >>> validate_rut('76.086.428-5')
        True
    """
    return is_valid(rut)


def clean_rut(rut: str) -> str:
    """
    Limpia RUT removiendo puntos, guiones y espacios.

    Args:
        rut: RUT en cualquier formato

    Returns:
        RUT limpio: 123456785

    Examples:
        >>> clean_rut('12.345.678-5')
        '123456785'
        >>> clean_rut('76.086.428-5')
        '760864285'
    """
    if not rut:
        return ''

    return compact(rut)
