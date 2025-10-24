# -*- coding: utf-8 -*-
"""
Tests para recepción de DTE 71 (Boleta de Honorarios Electrónica)

FASE 1 - Tarea 1.1
"""

import pytest
from validators.received_dte_validator import ReceivedDTEValidator


class TestBHEReception:
    """Test cases for DTE 71 (BHE) reception and validation"""

    def test_bhe_valid_with_retention(self):
        """Test BHE válida con retención 10%"""
        validator = ReceivedDTEValidator()

        bhe_data = {
            'dte_type': '71',
            'folio': '9876',
            'fecha_emision': '2025-10-22',
            'emisor': {
                'rut': '76086428-5',  # RUT válido
                'razon_social': 'Juan Pérez - Ingeniero'
            },
            'receptor': {
                'rut': '96874030-K',  # RUT válido
                'razon_social': 'MI EMPRESA DE INGENIERIA LTDA'
            },
            'totales': {
                'monto_bruto': 1000000,  # $1.000.000 bruto
                'retencion': 100000,      # $100.000 retención (10%)
                'monto_neto': 0,          # BHE no tiene neto afecto
                'monto_exento': 900000,  # Monto exento (después de retención)
                'total': 900000,          # $900.000 neto a pagar
                'iva': 0,                 # BHE sin IVA
            },
            'items': [
                {
                    'numero_linea': 1,
                    'nombre': 'Servicios profesionales de ingeniería',
                    'cantidad': 40,
                    'precio_unitario': 25000,
                    'monto_total': 1000000,
                }
            ],
            'ted': {
                'rut_emisor': '76086428-5',
                'tipo_dte': '71',
                'folio': '9876',
                'fecha_emision': '2025-10-22',
                'monto_total': 900000,  # Total después de retención
                'firma': 'DD_TIMBRE_AQUI=='
            },
            'signature': {
                'signature_value': 'FIRMA_DIGITAL_AQUI==',
                'x509_certificate': 'CERT_BASE64_AQUI=='
            },
        }

        is_valid, errors, warnings = validator.validate(bhe_data)

        assert is_valid, f"BHE should be valid. Errors: {errors}"
        assert len(errors) == 0
        # Puede tener warnings informativos pero no errores
        print(f"✅ BHE válida - Warnings: {warnings}")

    def test_bhe_without_retention_warning(self):
        """Test BHE sin retención genera warning"""
        validator = ReceivedDTEValidator()

        bhe_data = {
            'dte_type': '71',
            'folio': '9877',
            'fecha_emision': '2025-10-22',
            'emisor': {
                'rut': '76086428-5',
                'razon_social': 'Juan Pérez'
            },
            'receptor': {
                'rut': '96874030-K',
                'razon_social': 'MI EMPRESA'
            },
            'totales': {
                'monto_bruto': 500000,
                'retencion': 0,  # ⚠️ Sin retención
                'monto_neto': 0,
                'monto_exento': 500000,  # BHE exento
                'total': 500000,
                'iva': 0,
            },
            'items': [{'numero_linea': 1, 'nombre': 'Servicio', 'cantidad': 1, 'precio_unitario': 500000, 'monto_total': 500000}],
            'ted': {
                'rut_emisor': '76086428-5',
                'tipo_dte': '71',
                'folio': '9877',
                'fecha_emision': '2025-10-22',
                'monto_total': 500000,
                'firma': 'DD_TIMBRE=='
            },
            'signature': {
                'signature_value': 'FIRMA==',
                'x509_certificate': 'CERT=='
            },
        }

        is_valid, errors, warnings = validator.validate(bhe_data)

        assert is_valid  # Sigue siendo válida
        assert any('retención 10%' in w for w in warnings), \
            f"Should warn about missing retention. Warnings: {warnings}"
        print(f"⚠️ BHE sin retención genera warning: {warnings}")

    def test_bhe_with_iva_error(self):
        """Test BHE con IVA genera error (no permitido)"""
        validator = ReceivedDTEValidator()

        bhe_data = {
            'dte_type': '71',
            'folio': '9878',
            'fecha_emision': '2025-10-22',
            'emisor': {
                'rut': '12345678-9',
                'razon_social': 'Juan Pérez'
            },
            'receptor': {
                'rut': '76123456-7',
                'razon_social': 'MI EMPRESA'
            },
            'totales': {
                'monto_bruto': 1000000,
                'retencion': 100000,
                'iva': 190000,  # ❌ BHE no debe tener IVA
                'total': 1090000,
            },
            'items': [{'numero_linea': 1, 'nombre': 'Servicio', 'monto_total': 1000000}],
            'ted': {
                'rut_emisor': '12345678-9',
                'tipo_dte': '71',
                'folio': '9878',
                'fecha_emision': '2025-10-22',
                'monto_total': 1000000,
                'firma': 'DD_TIMBRE=='
            },
            'signature': {
                'signature_value': 'FIRMA==',
                'x509_certificate': 'CERT=='
            },
        }

        is_valid, errors, warnings = validator.validate(bhe_data)

        assert not is_valid, "BHE with IVA should be INVALID"
        assert any('IVA' in e and '71' in e for e in errors), \
            f"Should error about IVA in BHE. Errors: {errors}"
        print(f"❌ BHE con IVA correctamente rechazada: {errors}")

    def test_bhe_incorrect_retention_warning(self):
        """Test BHE con retención incorrecta (no 10%) genera warning"""
        validator = ReceivedDTEValidator()

        bhe_data = {
            'dte_type': '71',
            'folio': '9879',
            'fecha_emision': '2025-10-22',
            'emisor': {
                'rut': '76086428-5',
                'razon_social': 'Juan Pérez'
            },
            'receptor': {
                'rut': '96874030-K',
                'razon_social': 'MI EMPRESA'
            },
            'totales': {
                'monto_bruto': 1000000,
                'retencion': 50000,  # ⚠️ 5% instead of 10%
                'monto_neto': 0,
                'monto_exento': 950000,  # BHE exento
                'total': 950000,
                'iva': 0,
            },
            'items': [{'numero_linea': 1, 'nombre': 'Servicio', 'cantidad': 1, 'precio_unitario': 1000000, 'monto_total': 1000000}],
            'ted': {
                'rut_emisor': '76086428-5',
                'tipo_dte': '71',
                'folio': '9879',
                'fecha_emision': '2025-10-22',
                'monto_total': 950000,
                'firma': 'DD_TIMBRE=='
            },
            'signature': {
                'signature_value': 'FIRMA==',
                'x509_certificate': 'CERT=='
            },
        }

        is_valid, errors, warnings = validator.validate(bhe_data)

        assert is_valid  # Sigue siendo válida (solo warning)
        assert any('difiere del 10%' in w for w in warnings), \
            f"Should warn about incorrect retention %. Warnings: {warnings}"
        print(f"⚠️ BHE con retención incorrecta genera warning: {warnings}")

    def test_bhe_in_valid_dte_types_list(self):
        """Test que DTE 71 está en la lista de tipos válidos"""
        assert '71' in ReceivedDTEValidator.VALID_DTE_TYPES, \
            "DTE 71 (BHE) must be in VALID_DTE_TYPES list"
        print("✅ DTE 71 está en VALID_DTE_TYPES")


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v', '--tb=short'])
