# -*- coding: utf-8 -*-

"""
Tests Tramos Impuesto Único Chile - P0 Critical
================================================

Verificar:
- Tramos se cargan desde BD (no hardcoded)
- Cálculo correcto en cada tramo
- Transición entre tramos
- Rebaja zona extrema (50%)
- Versionamiento de tramos
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError
from datetime import date


@tagged('post_install', '-at_install', 'tax_brackets')
class TestTaxBrackets(TransactionCase):
    """Test modelo hr.tax.bracket y cálculo de impuesto"""
    
    def setUp(self):
        super().setUp()
        
        self.TaxBracketModel = self.env['hr.tax.bracket']
        self.IndicatorModel = self.env['hr.economic.indicators']
        
        # Crear indicadores para testing
        self.indicator = self.IndicatorModel.create({
            'period': date(2025, 1, 1),
            'uf': 39383.07,
            'utm': 68647,
            'uta': 823764,
            'minimum_wage': 500000,
            'afp_limit': 87.8,
        })
    
    def test_brackets_exist_in_database(self):
        """Verificar que tramos 2025 existen en BD (no hardcoded)"""
        brackets = self.TaxBracketModel.search([
            ('vigencia_desde', '=', '2025-01-01')
        ])
        
        self.assertGreaterEqual(
            len(brackets), 8,
            "Deben existir al menos 8 tramos de impuesto en BD"
        )
    
    def test_bracket_validation_range(self):
        """Test validación de rangos"""
        with self.assertRaises(ValidationError):
            self.TaxBracketModel.create({
                'tramo': 99,
                'desde': 100.0,
                'hasta': 50.0,  # Inválido: hasta < desde
                'tasa': 10.0,
                'vigencia_desde': date(2025, 1, 1),
            })
    
    def test_bracket_validation_tasa(self):
        """Test validación de tasa"""
        with self.assertRaises(ValidationError):
            self.TaxBracketModel.create({
                'tramo': 99,
                'desde': 0.0,
                'hasta': 10.0,
                'tasa': 150.0,  # Inválido: >100%
                'vigencia_desde': date(2025, 1, 1),
            })
    
    def test_bracket_validation_vigencia_day(self):
        """Test que vigencia debe ser día 1"""
        with self.assertRaises(ValidationError):
            self.TaxBracketModel.create({
                'tramo': 99,
                'desde': 0.0,
                'hasta': 10.0,
                'tasa': 10.0,
                'vigencia_desde': date(2025, 1, 15),  # Inválido: no es día 1
            })
    
    def test_get_brackets_for_date(self):
        """Test obtener tramos vigentes para fecha"""
        brackets = self.TaxBracketModel.get_brackets_for_date(date(2025, 6, 15))
        
        self.assertGreater(len(brackets), 0, "Debe retornar tramos vigentes")
        
        # Verificar que están ordenados
        for i in range(len(brackets) - 1):
            self.assertLessEqual(
                brackets[i].desde,
                brackets[i+1].desde,
                "Tramos deben estar ordenados por 'desde'"
            )
    
    def test_calculate_tax_tramo1_exento(self):
        """Test tramo 1 exento (0 UTM - 13.5 UTM)"""
        # Base: 500.000 CLP = ~7.3 UTM (exento)
        base_tributable = 500000
        
        tax = self.TaxBracketModel.calculate_tax(
            base_tributable,
            date(2025, 1, 1),
            extreme_zone=False
        )
        
        self.assertEqual(tax, 0.0, "Tramo 1 debe estar exento (impuesto = 0)")
    
    def test_calculate_tax_tramo2_4percent(self):
        """Test tramo 2 (13.5 - 30 UTM) = 4%"""
        # Base: 1.500.000 CLP = ~21.8 UTM
        # (21.8 * 4%) - 0.54 = 0.872 - 0.54 = 0.332 UTM
        # 0.332 * 68.647 = ~22.790 CLP
        base_tributable = 1500000
        
        tax = self.TaxBracketModel.calculate_tax(
            base_tributable,
            date(2025, 1, 1),
            extreme_zone=False
        )
        
        # Verificar que está en rango esperado
        self.assertGreater(tax, 0, "Tramo 2 debe tener impuesto > 0")
        self.assertLess(tax, 50000, "Impuesto tramo 2 debe ser < 50k para 1.5M")
    
    def test_calculate_tax_tramo3_8percent(self):
        """Test tramo 3 (30 - 50 UTM) = 8%"""
        # Base: 2.500.000 CLP = ~36.4 UTM
        # (36.4 * 8%) - 1.74 = 2.912 - 1.74 = 1.172 UTM
        # 1.172 * 68.647 = ~80.454 CLP
        base_tributable = 2500000
        
        tax = self.TaxBracketModel.calculate_tax(
            base_tributable,
            date(2025, 1, 1),
            extreme_zone=False
        )
        
        self.assertGreater(tax, 50000, "Tramo 3 debe tener impuesto > 50k")
        self.assertLess(tax, 150000, "Impuesto tramo 3 debe ser < 150k para 2.5M")
    
    def test_calculate_tax_extreme_zone_50percent_rebaja(self):
        """Test rebaja zona extrema (50% del impuesto)"""
        base_tributable = 2500000
        
        # Calcular sin zona extrema
        tax_normal = self.TaxBracketModel.calculate_tax(
            base_tributable,
            date(2025, 1, 1),
            extreme_zone=False
        )
        
        # Calcular con zona extrema
        tax_extreme = self.TaxBracketModel.calculate_tax(
            base_tributable,
            date(2025, 1, 1),
            extreme_zone=True
        )
        
        # Zona extrema debe ser 50% del normal
        self.assertAlmostEqual(
            tax_extreme,
            tax_normal * 0.5,
            delta=1,
            msg="Zona extrema debe aplicar rebaja 50%"
        )
    
    def test_calculate_tax_tramo8_sin_limite(self):
        """Test tramo 8 sin límite superior (>310 UTM) = 40%"""
        # Base: 25.000.000 CLP = ~364 UTM (tramo 8)
        base_tributable = 25000000
        
        tax = self.TaxBracketModel.calculate_tax(
            base_tributable,
            date(2025, 1, 1),
            extreme_zone=False
        )
        
        # Debe aplicar tasa 40%
        self.assertGreater(tax, 1000000, "Tramo 8 debe tener impuesto significativo")
    
    def test_no_brackets_for_date_raises_error(self):
        """Test error si no hay tramos para fecha"""
        with self.assertRaises(ValidationError):
            self.TaxBracketModel.get_brackets_for_date(date(2000, 1, 1))
    
    def test_bracket_name_generation(self):
        """Test generación automática de nombre"""
        bracket = self.TaxBracketModel.search([('tramo', '=', 2)], limit=1)
        
        if bracket:
            self.assertIn("Tramo 2", bracket.name)
            self.assertIn("13.5", bracket.name)
            self.assertIn("4", bracket.name)  # Tasa
    
    def test_tax_calculation_deterministic(self):
        """Test que cálculo es determinista (mismos inputs = mismo output)"""
        base = 2000000
        target_date = date(2025, 1, 1)
        
        # Calcular 3 veces
        tax1 = self.TaxBracketModel.calculate_tax(base, target_date)
        tax2 = self.TaxBracketModel.calculate_tax(base, target_date)
        tax3 = self.TaxBracketModel.calculate_tax(base, target_date)
        
        self.assertEqual(tax1, tax2, "Cálculo debe ser determinista")
        self.assertEqual(tax2, tax3, "Cálculo debe ser determinista")
    
    def test_no_hardcoded_brackets_in_code(self):
        """Test que no existen tramos hardcoded en código productivo"""
        # Este test es simbólico: verifica que podemos crear/modificar tramos
        # sin tocar código Python
        
        # Crear nuevo tramo de prueba
        new_bracket = self.TaxBracketModel.create({
            'tramo': 99,
            'desde': 500.0,
            'hasta': 0.0,
            'tasa': 50.0,
            'rebaja': 100.0,
            'vigencia_desde': date(2026, 1, 1),
        })
        
        self.assertTrue(new_bracket, "Debe poder crear tramos dinámicamente")
        
        # Limpiar
        new_bracket.unlink()
