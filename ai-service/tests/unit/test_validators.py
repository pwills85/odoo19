# -*- coding: utf-8 -*-
"""
Unit Tests - Validators
========================

Tests for input validation functions.

Author: EERGYGROUP - Gap Closure Sprint
Date: 2025-10-23
"""

import pytest
from utils.validators import (
    validate_rut,
    sanitize_rut,
    validate_dte_type,
    validate_dte_amount,
    validate_dte_data,
    sanitize_string,
    validate_company_id,
    validate_positive_number,
    validate_percentage
)


class TestRUTValidation:
    """Tests for Chilean RUT validation"""

    def test_valid_rut_with_dots(self):
        """Test valid RUT with dots"""
        assert validate_rut("12.345.678-9") is True

    def test_valid_rut_without_dots(self):
        """Test valid RUT without dots"""
        assert validate_rut("12345678-9") is True

    def test_valid_rut_with_k(self):
        """Test valid RUT with K checksum"""
        assert validate_rut("12345678-K") is True
        assert validate_rut("12345678-k") is True  # lowercase should work

    def test_invalid_rut_checksum(self):
        """Test invalid RUT checksum"""
        assert validate_rut("12345678-0") is False

    def test_invalid_rut_format(self):
        """Test invalid RUT formats"""
        assert validate_rut("") is False
        assert validate_rut("abc") is False
        assert validate_rut("123") is False

    def test_sanitize_rut(self):
        """Test RUT sanitization"""
        assert sanitize_rut("12.345.678-9") == "12345678-9"
        assert sanitize_rut("12345678-9") == "12345678-9"
        assert sanitize_rut("invalid") is None


class TestDTEValidation:
    """Tests for DTE validation"""

    def test_valid_dte_types(self):
        """Test valid DTE types"""
        assert validate_dte_type(33) is True  # Factura
        assert validate_dte_type(34) is True  # Factura Exenta
        assert validate_dte_type(52) is True  # Guía Despacho
        assert validate_dte_type(61) is True  # Nota Crédito

    def test_invalid_dte_types(self):
        """Test invalid DTE types"""
        assert validate_dte_type(0) is False
        assert validate_dte_type(999) is False
        assert validate_dte_type(-1) is False

    def test_valid_dte_amounts(self):
        """Test valid DTE amounts"""
        assert validate_dte_amount(0) is True
        assert validate_dte_amount(1000.50) is True
        assert validate_dte_amount(1_000_000) is True

    def test_invalid_dte_amounts(self):
        """Test invalid DTE amounts"""
        assert validate_dte_amount(-100) is False
        assert validate_dte_amount(2_000_000_000) is False  # Too large
        assert validate_dte_amount("abc") is False

    def test_validate_dte_data_valid(self):
        """Test validation of complete DTE data"""
        dte = {
            "tipo": 33,
            "folio": 12345,
            "monto_total": 100000,
            "rut_emisor": "12345678-9",
            "rut_receptor": "98765432-1"
        }
        is_valid, errors = validate_dte_data(dte)
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_dte_data_missing_field(self):
        """Test validation with missing required field"""
        dte = {
            "tipo": 33,
            "folio": 12345
            # Missing monto_total
        }
        is_valid, errors = validate_dte_data(dte)
        assert is_valid is False
        assert any("monto_total" in err for err in errors)

    def test_validate_dte_data_invalid_rut(self):
        """Test validation with invalid RUT"""
        dte = {
            "tipo": 33,
            "folio": 12345,
            "monto_total": 100000,
            "rut_emisor": "00000000-0"  # Invalid checksum
        }
        is_valid, errors = validate_dte_data(dte)
        assert is_valid is False
        assert any("RUT" in err for err in errors)


class TestStringValidation:
    """Tests for string sanitization"""

    def test_sanitize_normal_string(self):
        """Test sanitization of normal string"""
        result = sanitize_string("  Hello World  ")
        assert result == "Hello World"

    def test_sanitize_string_max_length(self):
        """Test string length limiting"""
        long_string = "a" * 2000
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100

    def test_sanitize_control_characters(self):
        """Test removal of control characters"""
        result = sanitize_string("Hello\x00World\x08Test")
        assert "\x00" not in result
        assert "\x08" not in result


class TestNumericValidation:
    """Tests for numeric validation"""

    def test_validate_positive_number(self):
        """Test positive number validation"""
        assert validate_positive_number(1) is True
        assert validate_positive_number(0.5) is True
        assert validate_positive_number(0, allow_zero=True) is True
        assert validate_positive_number(0, allow_zero=False) is False
        assert validate_positive_number(-1) is False

    def test_validate_percentage(self):
        """Test percentage validation"""
        assert validate_percentage(0) is True
        assert validate_percentage(50) is True
        assert validate_percentage(100) is True
        assert validate_percentage(-1) is False
        assert validate_percentage(101) is False

    def test_validate_company_id(self):
        """Test company ID validation"""
        assert validate_company_id(1) is True
        assert validate_company_id(999) is True
        assert validate_company_id(0) is False
        assert validate_company_id(-1) is False
        assert validate_company_id("abc") is False
