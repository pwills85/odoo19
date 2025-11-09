# -*- coding: utf-8 -*-
"""
Input Validators - Security & Data Quality
===========================================

Comprehensive input validation for AI service endpoints.
Prevents injection attacks, validates business logic, ensures data quality.

Author: EERGYGROUP - Gap Closure Sprint
Date: 2025-10-23
Architecture: RUT validation delegated to python-stdnum (same as Odoo native)
"""

import re
from typing import Any, Dict, List, Optional
import structlog
from stdnum.cl.rut import is_valid, compact

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════
# RUT VALIDATION (Chilean Tax ID)
# Delegated to python-stdnum (same library as Odoo native)
# ═══════════════════════════════════════════════════════════

def validate_rut(rut: str) -> bool:
    """
    Validate Chilean RUT format and checksum.

    Delegates to python-stdnum (same as Odoo native validation).

    Args:
        rut: RUT string (e.g., "12.345.678-9" or "12345678-9")

    Returns:
        True if valid, False otherwise

    Examples:
        >>> validate_rut("12.345.678-9")
        True
        >>> validate_rut("12345678-K")
        True
        >>> validate_rut("00000000-0")
        False
    """
    if not rut or not isinstance(rut, str):
        return False

    return is_valid(rut)


def sanitize_rut(rut: str) -> Optional[str]:
    """
    Sanitize and format RUT to standard format.

    Validates first, then formats using python-stdnum.

    Args:
        rut: Input RUT (any format)

    Returns:
        Formatted RUT (e.g., "12345678-5") or None if invalid
    """
    if not rut or not isinstance(rut, str):
        return None

    try:
        # Validate first before sanitizing
        if not is_valid(rut):
            return None

        # Usar compact de stdnum (limpia el RUT)
        clean = compact(rut)
        # Formato: XXXXXXXX-Y
        return f"{clean[:-1]}-{clean[-1]}"
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════
# DTE VALIDATION
# ═══════════════════════════════════════════════════════════

VALID_DTE_TYPES = {
    33,  # Factura Electrónica
    34,  # Factura Exenta Electrónica
    39,  # Boleta Electrónica
    41,  # Boleta Exenta Electrónica
    43,  # Liquidación Factura Electrónica
    46,  # Factura de Compra Electrónica
    52,  # Guía de Despacho Electrónica
    56,  # Nota de Débito Electrónica
    61,  # Nota de Crédito Electrónica
    110, # Factura de Exportación Electrónica
    111, # Nota de Débito de Exportación Electrónica
    112, # Nota de Crédito de Exportación Electrónica
}


def validate_dte_type(tipo: int) -> bool:
    """
    Validate DTE type code.

    Args:
        tipo: DTE type code

    Returns:
        True if valid DTE type
    """
    return tipo in VALID_DTE_TYPES


def validate_dte_amount(amount: float, min_value: float = 0.0, max_value: float = 1_000_000_000.0) -> bool:
    """
    Validate DTE amount is within reasonable bounds.

    Args:
        amount: Amount to validate
        min_value: Minimum allowed (default: 0)
        max_value: Maximum allowed (default: 1B CLP)

    Returns:
        True if valid
    """
    if not isinstance(amount, (int, float)):
        return False

    return min_value <= amount <= max_value


def validate_dte_data(dte_data: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Comprehensive DTE data validation.

    Args:
        dte_data: DTE data dictionary

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Required fields
    required = ["tipo", "folio", "monto_total"]
    for field in required:
        if field not in dte_data:
            errors.append(f"Missing required field: {field}")

    if errors:
        return False, errors

    # Validate tipo
    tipo = dte_data.get("tipo")
    if not validate_dte_type(tipo):
        errors.append(f"Invalid DTE type: {tipo}")

    # Validate folio
    folio = dte_data.get("folio")
    if not isinstance(folio, int) or folio <= 0:
        errors.append(f"Invalid folio: {folio} (must be positive integer)")

    # Validate monto_total
    monto = dte_data.get("monto_total")
    if not validate_dte_amount(monto):
        errors.append(f"Invalid amount: {monto}")

    # Validate RUT emisor if present
    if "rut_emisor" in dte_data:
        if not validate_rut(dte_data["rut_emisor"]):
            errors.append(f"Invalid RUT emisor: {dte_data['rut_emisor']}")

    # Validate RUT receptor if present
    if "rut_receptor" in dte_data:
        if not validate_rut(dte_data["rut_receptor"]):
            errors.append(f"Invalid RUT receptor: {dte_data['rut_receptor']}")

    return len(errors) == 0, errors


# ═══════════════════════════════════════════════════════════
# STRING SANITIZATION (Security)
# ═══════════════════════════════════════════════════════════

def sanitize_string(text: str, max_length: int = 1000) -> str:
    """
    Sanitize string to prevent injection attacks.

    - Removes control characters
    - Limits length
    - Strips whitespace

    Args:
        text: Input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not isinstance(text, str):
        return ""

    # Remove control characters (except \n, \r, \t)
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
        logger.warning("string_truncated", original_length=len(text), max_length=max_length)

    return sanitized.strip()


def validate_company_id(company_id: int) -> bool:
    """
    Validate company ID.

    Args:
        company_id: Company ID to validate

    Returns:
        True if valid
    """
    if not isinstance(company_id, int):
        return False

    return company_id > 0


# ═══════════════════════════════════════════════════════════
# NUMERIC VALIDATION
# ═══════════════════════════════════════════════════════════

def validate_positive_number(value: Any, allow_zero: bool = False) -> bool:
    """
    Validate number is positive.

    Args:
        value: Value to validate
        allow_zero: Whether to allow zero

    Returns:
        True if valid
    """
    if not isinstance(value, (int, float)):
        return False

    if allow_zero:
        return value >= 0
    else:
        return value > 0


def validate_percentage(value: float) -> bool:
    """
    Validate percentage (0-100).

    Args:
        value: Percentage value

    Returns:
        True if valid
    """
    if not isinstance(value, (int, float)):
        return False

    return 0 <= value <= 100


# ═══════════════════════════════════════════════════════════
# API KEY VALIDATION
# ═══════════════════════════════════════════════════════════

def validate_api_key_format(api_key: str) -> bool:
    """
    Validate API key format (basic check).

    Args:
        api_key: API key string

    Returns:
        True if format looks valid
    """
    if not isinstance(api_key, str):
        return False

    # Must be at least 16 chars, alphanumeric + special chars
    if len(api_key) < 16:
        return False

    # Basic format check (no whitespace, reasonable chars)
    if not re.match(r'^[A-Za-z0-9_\-\.]+$', api_key):
        return False

    return True
