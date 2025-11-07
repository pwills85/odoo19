# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.addons.l10n_cl_financial_reports.utils import rut


class TestRUTUtils(TransactionCase):
    """
    Tests para utilidades de RUT chileno (validate_rut y format_rut)
    """

    def test_01_validate_rut_valid_with_dash(self):
        """Test que validate_rut retorna True para RUT válido con guion"""
        # RUT 12.345.678-5 es válido (verificador correcto)
        self.assertTrue(rut.validate_rut('12.345.678-5'))
        self.assertTrue(rut.validate_rut('12345678-5'))

    def test_02_validate_rut_valid_without_format(self):
        """Test que validate_rut retorna True para RUT válido sin formato"""
        self.assertTrue(rut.validate_rut('123456785'))

    def test_03_validate_rut_valid_with_k(self):
        """Test que validate_rut retorna True para RUT válido con verificador K"""
        # RUT 11.111.111-K es válido
        self.assertTrue(rut.validate_rut('11.111.111-K'))
        self.assertTrue(rut.validate_rut('11111111K'))
        self.assertTrue(rut.validate_rut('11111111k'))  # lowercase k should work

    def test_04_validate_rut_invalid_verifier(self):
        """Test que validate_rut retorna False para RUT con verificador incorrecto"""
        # RUT 12.345.678-9 es inválido (verificador correcto es 5)
        self.assertFalse(rut.validate_rut('12.345.678-9'))
        self.assertFalse(rut.validate_rut('12345678-9'))
        self.assertFalse(rut.validate_rut('123456789'))

    def test_05_validate_rut_empty_string(self):
        """Test que validate_rut retorna False para cadena vacía"""
        self.assertFalse(rut.validate_rut(''))
        self.assertFalse(rut.validate_rut(None))

    def test_06_validate_rut_invalid_format(self):
        """Test que validate_rut retorna False para formato inválido"""
        self.assertFalse(rut.validate_rut('abc'))
        self.assertFalse(rut.validate_rut('12-abc-678'))
        self.assertFalse(rut.validate_rut('1'))  # Too short

    def test_07_validate_rut_with_spaces(self):
        """Test que validate_rut maneja RUTs con espacios"""
        self.assertTrue(rut.validate_rut('12 345 678-5'))
        self.assertTrue(rut.validate_rut(' 12.345.678-5 '))  # Spaces at edges

    def test_08_validate_rut_real_valid_ruts(self):
        """Test con RUTs chilenos válidos reales"""
        valid_ruts = [
            '76.123.456-7',
            '12.345.678-5',
            '11.111.111-K',
            '22.222.222-3',
            '7.654.321-K',
        ]
        for valid_rut in valid_ruts:
            self.assertTrue(
                rut.validate_rut(valid_rut),
                f"RUT {valid_rut} debería ser válido"
            )

    def test_09_format_rut_from_plain_number(self):
        """Test que format_rut formatea correctamente desde número sin formato"""
        self.assertEqual(rut.format_rut('123456785'), '12.345.678-5')
        self.assertEqual(rut.format_rut('11111111K'), '11.111.111-K')

    def test_10_format_rut_already_formatted(self):
        """Test que format_rut mantiene RUT ya formateado"""
        self.assertEqual(rut.format_rut('12.345.678-5'), '12.345.678-5')

    def test_11_format_rut_with_dash_only(self):
        """Test que format_rut formatea RUT con guion pero sin puntos"""
        self.assertEqual(rut.format_rut('12345678-5'), '12.345.678-5')

    def test_12_format_rut_with_spaces(self):
        """Test que format_rut elimina espacios y formatea"""
        self.assertEqual(rut.format_rut('12 345 678-5'), '12.345.678-5')
        self.assertEqual(rut.format_rut(' 12345678-5 '), '12.345.678-5')

    def test_13_format_rut_empty_string(self):
        """Test que format_rut retorna cadena vacía para input vacío"""
        self.assertEqual(rut.format_rut(''), '')
        self.assertEqual(rut.format_rut(None), '')

    def test_14_format_rut_invalid_format(self):
        """Test que format_rut retorna cadena vacía para formato inválido"""
        self.assertEqual(rut.format_rut('abc'), '')
        self.assertEqual(rut.format_rut('1'), '')  # Too short

    def test_15_format_rut_short_rut(self):
        """Test que format_rut maneja RUTs cortos (ej: 1.234.567-8)"""
        self.assertEqual(rut.format_rut('12345678'), '1.234.567-8')
        self.assertEqual(rut.format_rut('1234567'), '123.456-7')

    def test_16_format_rut_lowercase_k(self):
        """Test que format_rut convierte 'k' minúscula a 'K' mayúscula"""
        self.assertEqual(rut.format_rut('11111111k'), '11.111.111-K')

    def test_17_validate_and_format_consistency(self):
        """Test que validate_rut y format_rut son consistentes"""
        test_ruts = [
            '123456785',
            '12345678-5',
            '12.345.678-5',
            '11111111K',
            '76.123.456-7',
        ]

        for test_rut in test_ruts:
            # Si validate retorna True, format debe retornar un RUT formateado
            if rut.validate_rut(test_rut):
                formatted = rut.format_rut(test_rut)
                self.assertNotEqual(formatted, '', f"format_rut falló para {test_rut}")
                # El RUT formateado también debe ser válido
                self.assertTrue(
                    rut.validate_rut(formatted),
                    f"RUT formateado {formatted} no es válido"
                )

    def test_18_edge_case_verificador_0(self):
        """Test caso especial: verificador 0 (cuando 11 - (suma % 11) = 11)"""
        # RUT con verificador 0: 24.123.456-0
        self.assertTrue(rut.validate_rut('24.123.456-0'))
        self.assertEqual(rut.format_rut('241234560'), '24.123.456-0')

    def test_19_calcular_verificador_internal(self):
        """Test función interna _calcular_verificador"""
        # 12345678 -> verificador 5
        self.assertEqual(rut._calcular_verificador('12345678'), '5')

        # 11111111 -> verificador K
        self.assertEqual(rut._calcular_verificador('11111111'), 'K')

        # 24123456 -> verificador 0
        self.assertEqual(rut._calcular_verificador('24123456'), '0')

    def test_20_formatear_numero_con_puntos_internal(self):
        """Test función interna _formatear_numero_con_puntos"""
        self.assertEqual(rut._formatear_numero_con_puntos('12345678'), '12.345.678')
        self.assertEqual(rut._formatear_numero_con_puntos('1234567'), '1.234.567')
        self.assertEqual(rut._formatear_numero_con_puntos('123456'), '123.456')
        self.assertEqual(rut._formatear_numero_con_puntos('12345'), '12.345')
        self.assertEqual(rut._formatear_numero_con_puntos('1234'), '1.234')
        self.assertEqual(rut._formatear_numero_con_puntos('123'), '123')
        self.assertEqual(rut._formatear_numero_con_puntos('12'), '12')
        self.assertEqual(rut._formatear_numero_con_puntos('1'), '1')
