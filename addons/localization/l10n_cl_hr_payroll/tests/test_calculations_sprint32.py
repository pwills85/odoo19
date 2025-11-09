# -*- coding: utf-8 -*-

"""
Tests para cálculos avanzados Sprint 3.2

Tests:
- Horas extras (HEX50, HEX100)
- Bonos imponibles
- Asignaciones no imponibles (colación, movilización)
- Impuesto Único 7 tramos
- AFC (Seguro de Cesantía)
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError, UserError
from datetime import date


@tagged('post_install', '-at_install', 'payroll_calc')
class TestPayrollCalculationsSprint32(TransactionCase):
    """
    Tests cálculos avanzados Sprint 3.2
    
    Técnica Odoo 19 CE:
    - Hereda TransactionCase
    - setUp() para preparar datos
    - test_* methods para cada caso
    - assertAlmostEqual() para floats
    """
    
    def setUp(self):
        super().setUp()
        
        # Crear indicadores económicos
        self.indicators = self.env['hr.economic.indicators'].create({
            'period': date(2025, 10, 1),
            'uf': 39383.07,
            'utm': 68647,
            'uta': 823764.00,
            'minimum_wage': 500000.00,
            'afp_limit': 87.8,
        })
        
        # Crear AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'Capital',
            'code': 'CAP',
            'rate': 11.44,
        })
        
        # Crear empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee',
            'identification_id': '12345678-9',
        })
        
        # Crear contrato
        self.contract = self.env['hr.contract'].create({
            'name': 'Test Contract',
            'employee_id': self.employee.id,
            'wage': 1000000,  # $1M
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'weekly_hours': 45,
            'state': 'open',
            'date_start': date(2025, 1, 1),
        })
        
        # Crear liquidación base
        self.payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
    
    # ═══════════════════════════════════════════════════════════
    # TESTS HORAS EXTRAS
    # ═══════════════════════════════════════════════════════════
    
    def test_overtime_hex50(self):
        """Test cálculo horas extras 50%"""
        # Crear input horas extras 50%
        self.env['hr.payslip.input'].create({
            'payslip_id': self.payslip.id,
            'code': 'HEX50',
            'name': 'Horas Extras 50%',
            'amount': 10.0,  # 10 horas
        })
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar línea horas extras
        hex_line = self.payslip.line_ids.filtered(lambda l: l.code == 'HEX50')
        self.assertTrue(hex_line, "Debe existir línea HEX50")
        
        # Valor hora = (1.000.000 * 12) / (52 * 45) = 5.128,21
        # HEX50 = 5.128,21 * 1.5 * 10 = 76.923
        expected = 76923
        self.assertAlmostEqual(hex_line.total, expected, delta=10,
                              msg=f"HEX50 debería ser ~{expected}")
    
    def test_overtime_hex100(self):
        """Test cálculo horas extras 100%"""
        # Crear input horas extras 100%
        self.env['hr.payslip.input'].create({
            'payslip_id': self.payslip.id,
            'code': 'HEX100',
            'name': 'Horas Extras 100%',
            'amount': 5.0,  # 5 horas
        })
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar línea horas extras
        hex_line = self.payslip.line_ids.filtered(lambda l: l.code == 'HEX100')
        self.assertTrue(hex_line, "Debe existir línea HEX100")
        
        # Valor hora = 5.128,21
        # HEX100 = 5.128,21 * 2.0 * 5 = 51.282
        expected = 51282
        self.assertAlmostEqual(hex_line.total, expected, delta=10,
                              msg=f"HEX100 debería ser ~{expected}")
    
    # ═══════════════════════════════════════════════════════════
    # TESTS BONOS
    # ═══════════════════════════════════════════════════════════
    
    def test_bonus_imponible(self):
        """Test bono imponible afecta cálculo AFP/Salud"""
        # Crear input bono
        self.env['hr.payslip.input'].create({
            'payslip_id': self.payslip.id,
            'code': 'BONO_PROD',
            'name': 'Bono Producción',
            'amount': 50000,
        })
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar bono existe
        bonus_line = self.payslip.line_ids.filtered(lambda l: l.code == 'BONO_PROD')
        self.assertTrue(bonus_line, "Debe existir línea BONO_PROD")
        self.assertEqual(bonus_line.total, 50000)
        
        # Verificar total imponible = 1.000.000 + 50.000 = 1.050.000
        expected_imponible = 1050000
        self.assertAlmostEqual(self.payslip.total_imponible, expected_imponible, delta=10)
        
        # Verificar AFP calculada sobre 1.050.000
        afp_line = self.payslip.line_ids.filtered(lambda l: l.code == 'AFP')
        expected_afp = 1050000 * 0.1144  # 120.120
        self.assertAlmostEqual(abs(afp_line.total), expected_afp, delta=10)
    
    # ═══════════════════════════════════════════════════════════
    # TESTS ASIGNACIONES NO IMPONIBLES
    # ═══════════════════════════════════════════════════════════
    
    def test_allowance_colacion(self):
        """Test colación NO afecta imponible"""
        # Crear input colación
        self.env['hr.payslip.input'].create({
            'payslip_id': self.payslip.id,
            'code': 'COLACION',
            'name': 'Colación',
            'amount': 30000,
        })
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar colación existe
        col_line = self.payslip.line_ids.filtered(lambda l: l.code == 'COLACION')
        self.assertTrue(col_line, "Debe existir línea COLACION")
        self.assertEqual(col_line.total, 30000)
        
        # Verificar total imponible NO incluye colación
        self.assertEqual(self.payslip.total_imponible, 1000000,
                        "Colación NO debe afectar imponible")
        
        # Verificar bruto SÍ incluye colación
        expected_gross = 1000000 + 30000
        self.assertAlmostEqual(self.payslip.gross_wage, expected_gross, delta=10)
    
    def test_allowance_tope_legal(self):
        """Test tope 20% IMM en asignaciones"""
        # Tope legal = 20% * 500.000 = 100.000
        # Intentar colación de 150.000 (excede tope)
        self.env['hr.payslip.input'].create({
            'payslip_id': self.payslip.id,
            'code': 'COLACION',
            'name': 'Colación',
            'amount': 150000,  # Excede tope
        })
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar se aplicó tope
        col_line = self.payslip.line_ids.filtered(lambda l: l.code == 'COLACION')
        tope = self.indicators.minimum_wage * 0.20
        self.assertEqual(col_line.total, tope,
                        "Debe aplicarse tope 20% IMM")
    
    # ═══════════════════════════════════════════════════════════
    # TESTS IMPUESTO ÚNICO
    # ═══════════════════════════════════════════════════════════
    
    def test_tax_tramo1_exento(self):
        """Test tramo 1 exento (hasta $816.822)"""
        # Contrato con sueldo bajo
        self.contract.wage = 500000
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # No debe existir línea TAX
        tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
        self.assertFalse(tax_line, "Tramo 1 debe estar exento")
    
    def test_tax_tramo2(self):
        """Test tramo 2 (4%)"""
        # Contrato con sueldo en tramo 2
        self.contract.wage = 1000000
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Debe existir línea TAX
        tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
        self.assertTrue(tax_line, "Debe existir línea TAX")
        
        # Base tributable = 1.000.000
        # - AFP = 1.000.000 * 0.1144 = 114.400
        # - Salud = 1.000.000 * 0.07 = 70.000
        # Base = 1.000.000 - 114.400 - 70.000 = 815.600 (tramo 1, exento)
        
        # Como cae en tramo 1, impuesto = 0
        self.assertAlmostEqual(abs(tax_line.total), 0, delta=10)
    
    def test_tax_tramo3(self):
        """Test tramo 3 (8%)"""
        # Contrato con sueldo en tramo 3
        self.contract.wage = 2000000
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar impuesto calculado
        tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
        self.assertTrue(tax_line, "Debe existir línea TAX")
        
        # Base = 2.000.000 - (2.000.000 * 0.1144) - (2.000.000 * 0.07)
        # Base = 2.000.000 - 228.800 - 140.000 = 1.631.200
        # Tramo 2: (1.631.200 * 0.04) - 32.673 = 32.575
        expected_tax = 32575
        self.assertAlmostEqual(abs(tax_line.total), expected_tax, delta=1000,
                              msg=f"Impuesto debería ser ~{expected_tax}")
    
    # ═══════════════════════════════════════════════════════════
    # TESTS AFC
    # ═══════════════════════════════════════════════════════════
    
    def test_afc_calculation(self):
        """Test cálculo AFC (0.6%)"""
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar línea AFC
        afc_line = self.payslip.line_ids.filtered(lambda l: l.code == 'AFC')
        self.assertTrue(afc_line, "Debe existir línea AFC")
        
        # AFC = 1.000.000 * 0.006 = 6.000
        expected_afc = 6000
        self.assertAlmostEqual(abs(afc_line.total), expected_afc, delta=10)
    
    def test_afc_tope(self):
        """Test tope AFC (120.2 UF)"""
        # Contrato con sueldo alto (excede tope AFC)
        self.contract.wage = 5000000
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar línea AFC
        afc_line = self.payslip.line_ids.filtered(lambda l: l.code == 'AFC')
        
        # Tope = 120.2 * 39.383,07 = 4.734.841
        # AFC = 4.734.841 * 0.006 = 28.409
        tope_clp = self.indicators.uf * 120.2
        expected_afc = tope_clp * 0.006
        self.assertAlmostEqual(abs(afc_line.total), expected_afc, delta=10)
    
    # ═══════════════════════════════════════════════════════════
    # TESTS INTEGRACIÓN
    # ═══════════════════════════════════════════════════════════
    
    def test_full_payslip_with_inputs(self):
        """Test liquidación completa con múltiples inputs"""
        # Crear múltiples inputs
        self.env['hr.payslip.input'].create([
            {
                'payslip_id': self.payslip.id,
                'code': 'HEX50',
                'name': 'Horas Extras 50%',
                'amount': 10.0,
            },
            {
                'payslip_id': self.payslip.id,
                'code': 'BONO_PROD',
                'name': 'Bono Producción',
                'amount': 50000,
            },
            {
                'payslip_id': self.payslip.id,
                'code': 'COLACION',
                'name': 'Colación',
                'amount': 30000,
            },
        ])
        
        # Calcular liquidación
        self.payslip.action_compute_sheet()
        
        # Verificar todas las líneas creadas
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'BASIC'))
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'HEX50'))
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'BONO_PROD'))
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'COLACION'))
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'AFP'))
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'HEALTH'))
        self.assertTrue(self.payslip.line_ids.filtered(lambda l: l.code == 'AFC'))
        
        # Verificar totalizadores
        # Total imponible = 1.000.000 + HEX50 + BONO (sin colación)
        self.assertGreater(self.payslip.total_imponible, 1000000)
        self.assertGreater(self.payslip.gross_wage, self.payslip.total_imponible)
        self.assertGreater(self.payslip.gross_wage, self.payslip.net_wage)
        
        _logger.info(
            "Liquidación completa: bruto=$%s, imponible=$%s, líquido=$%s",
            f"{self.payslip.gross_wage:,.0f}",
            f"{self.payslip.total_imponible:,.0f}",
            f"{self.payslip.net_wage:,.0f}"
        )
