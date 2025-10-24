# -*- coding: utf-8 -*-
"""
Tests para RUT Validator
"""

import unittest
from odoo.addons.l10n_cl_dte.tools.rut_validator import (
    RUTValidator,
    validate_rut,
    format_rut,
    clean_rut
)


class TestRUTValidator(unittest.TestCase):
    """Tests para validación de RUT chileno"""
    
    def test_rut_valido_persona(self):
        """Test: RUT de persona válido"""
        self.assertTrue(validate_rut('12.345.678-5'))
        self.assertTrue(validate_rut('12345678-5'))
        self.assertTrue(validate_rut('123456785'))
    
    def test_rut_valido_empresa(self):
        """Test: RUT de empresa válido"""
        self.assertTrue(validate_rut('76.123.456-K'))
        self.assertTrue(validate_rut('76123456-K'))
        self.assertTrue(validate_rut('76123456K'))
    
    def test_rut_invalido(self):
        """Test: RUT inválido"""
        self.assertFalse(validate_rut('12.345.678-9'))  # DV incorrecto
        self.assertFalse(validate_rut('00000000-0'))    # RUT cero
        self.assertFalse(validate_rut('INVALID'))        # No numérico
        self.assertFalse(validate_rut(''))              # Vacío
        self.assertFalse(validate_rut(None))            # None
    
    def test_rut_con_k(self):
        """Test: RUT con dígito verificador K"""
        self.assertTrue(validate_rut('11.111.111-K'))
        self.assertTrue(validate_rut('11111111-K'))
        self.assertTrue(validate_rut('11111111K'))
        
        # K en minúscula (debe funcionar)
        self.assertTrue(validate_rut('11111111k'))
    
    def test_clean_rut(self):
        """Test: Limpieza de RUT"""
        self.assertEqual(clean_rut('12.345.678-5'), '123456785')
        self.assertEqual(clean_rut('12345678-5'), '123456785')
        self.assertEqual(clean_rut('12 345 678-5'), '123456785')
        self.assertEqual(clean_rut('76.123.456-k'), '76123456K')
    
    def test_split_rut(self):
        """Test: Separación de RUT"""
        numero, dv = RUTValidator.split_rut('123456785')
        self.assertEqual(numero, '12345678')
        self.assertEqual(dv, '5')
        
        numero, dv = RUTValidator.split_rut('76123456K')
        self.assertEqual(numero, '76123456')
        self.assertEqual(dv, 'K')
    
    def test_calculate_dv(self):
        """Test: Cálculo de dígito verificador"""
        self.assertEqual(RUTValidator.calculate_dv('12345678'), '5')
        self.assertEqual(RUTValidator.calculate_dv('76123456'), 'K')
        self.assertEqual(RUTValidator.calculate_dv('11111111'), 'K')
    
    def test_format_rut(self):
        """Test: Formateo de RUT"""
        self.assertEqual(format_rut('123456785'), '12.345.678-5')
        self.assertEqual(format_rut('76123456K'), '76.123.456-K')
        self.assertEqual(format_rut('11111111K'), '11.111.111-K')
        
        # RUT inválido retorna None
        self.assertIsNone(format_rut('12345678-9'))
        self.assertIsNone(format_rut('INVALID'))
    
    def test_is_company_rut(self):
        """Test: Identificación de RUT empresa vs persona"""
        # Empresas (RUT >= 50.000.000)
        self.assertTrue(RUTValidator.is_company_rut('76.123.456-K'))
        self.assertTrue(RUTValidator.is_company_rut('99.999.999-9'))
        
        # Personas (RUT < 50.000.000)
        self.assertFalse(RUTValidator.is_company_rut('12.345.678-5'))
        self.assertFalse(RUTValidator.is_company_rut('25.000.000-K'))
    
    def test_ruts_reales_conocidos(self):
        """Test: RUTs reales conocidos válidos"""
        # RUTs de entidades públicas chilenas (públicamente conocidos)
        ruts_validos = [
            '60.910.000-1',  # Banco de Chile
            '97.004.000-5',  # Servicio de Impuestos Internos
            '61.533.000-4',  # Universidad de Chile
        ]
        
        for rut in ruts_validos:
            with self.subTest(rut=rut):
                self.assertTrue(validate_rut(rut), f'RUT {rut} debería ser válido')
    
    def test_edge_cases(self):
        """Test: Casos borde"""
        # RUT mínimo válido
        self.assertTrue(validate_rut('1.000.000-6'))
        
        # RUT con ceros
        self.assertTrue(validate_rut('10.000.000-K'))
        
        # RUT muy corto
        self.assertFalse(validate_rut('1-9'))
        
        # RUT con caracteres especiales
        self.assertFalse(validate_rut('12.345.678-@'))
    
    def test_diferentes_formatos(self):
        """Test: Diferentes formatos del mismo RUT válido"""
        rut_formats = [
            '12.345.678-5',
            '12345678-5',
            '123456785',
            '12 345 678-5',
            '12.345.678 - 5',
        ]
        
        for rut in rut_formats:
            with self.subTest(rut=rut):
                self.assertTrue(validate_rut(rut), f'Formato {rut} debería ser válido')


if __name__ == '__main__':
    unittest.main()

