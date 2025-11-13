# -*- coding: utf-8 -*-
"""
✅ FIX [T3 CICLO3]: Tests para validators module
Tests with @pytest.parametrize for RUT validation and other validators
"""

import pytest
from validators.rut_validator import validate_rut, calculate_rut_dv


class TestRUTValidator:
    """Tests para validación de RUT chileno"""

    @pytest.mark.parametrize("rut,expected", [
        # RUTs válidos
        ("76.123.456-7", True),
        ("12.345.678-5", True),
        ("11.111.111-1", True),
        ("1.111.111-K", True),
        ("22.222.222-2", True),
        
        # RUTs inválidos (dígito verificador incorrecto)
        ("76.123.456-8", False),
        ("12.345.678-0", False),
        ("11.111.111-2", False),
        
        # Formatos inválidos
        ("invalid-rut", False),
        ("", False),
        ("12345678", False),  # Sin guión ni puntos
        ("12.345.678", False),  # Sin dígito verificador
        
        # Edge cases
        ("1-9", True),  # RUT más corto posible
        ("99.999.999-9", True),
        (None, False),
        ("0-0", False),  # RUT cero
    ])
    def test_validate_rut_parametrized(self, rut, expected):
        """Test validación RUT con múltiples casos"""
        result = validate_rut(rut)
        assert result == expected, f"Failed for RUT: {rut}"

    def test_validate_rut_with_spaces(self):
        """Test RUT con espacios debe limpiarlos"""
        assert validate_rut(" 76.123.456-7 ") == True
        assert validate_rut("76 123 456-7") == False  # Espacios intermedios no válidos

    def test_validate_rut_case_insensitive_k(self):
        """Test que K mayúscula y minúscula sean aceptadas"""
        assert validate_rut("1.111.111-K") == True
        assert validate_rut("1.111.111-k") == True

    @pytest.mark.parametrize("rut_number,expected_dv", [
        ("76123456", "7"),
        ("12345678", "5"),
        ("11111111", "1"),
        ("1111111", "K"),
        ("22222222", "2"),
    ])
    def test_calculate_rut_dv(self, rut_number, expected_dv):
        """Test cálculo de dígito verificador"""
        result = calculate_rut_dv(rut_number)
        assert result == expected_dv


class TestOtherValidators:
    """Tests para otros validators si existen"""

    def test_placeholder(self):
        """Placeholder test - expandir cuando haya más validators"""
        assert True


# Fixtures compartidos
@pytest.fixture
def valid_ruts():
    """Fixture con lista de RUTs válidos para tests"""
    return [
        "76.123.456-7",
        "12.345.678-5",
        "11.111.111-1",
        "1.111.111-K",
    ]


@pytest.fixture
def invalid_ruts():
    """Fixture con lista de RUTs inválidos para tests"""
    return [
        "76.123.456-8",  # DV incorrecto
        "invalid-rut",
        "",
        None,
        "12345678",  # Sin formato
    ]
