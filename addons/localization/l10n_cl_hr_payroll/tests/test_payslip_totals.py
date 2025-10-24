# -*- coding: utf-8 -*-

from odoo.tests import common, tagged
from datetime import date


@tagged('post_install', '-at_install', 'payroll_sopa')
class TestPayslipTotals(common.TransactionCase):
    """Test Totalizadores SOPA 2025 - Odoo 19 CE"""
    
    def setUp(self):
        super(TestPayslipTotals, self).setUp()
        
        # Crear empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee SOPA',
        })
        
        # Obtener o crear AFP
        afp = self.env['hr.afp'].search([('code', '=', 'CAPITAL')], limit=1)
        if not afp:
            afp = self.env['hr.afp'].create({
                'name': 'AFP Capital',
                'code': 'CAPITAL',
                'rate': 11.44,
            })
        
        # Crear contrato
        self.contract = self.env['hr.contract'].create({
            'name': 'Test Contract SOPA',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'state': 'open',
            'afp_id': afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'date_start': date(2025, 1, 1),
        })
        
        # Crear indicadores económicos
        self.indicators = self.env['hr.economic.indicators'].create({
            'year': 2025,
            'month': 10,
            'uf': 39383.07,
            'utm': 68647,
            'uta': 823764,
            'afp_limit': 87.8,
        })
    
    def test_01_total_imponible_single_line(self):
        """Test total_imponible con solo sueldo base"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar total_imponible = sueldo base
        self.assertEqual(
            payslip.total_imponible, 1000000,
            f"total_imponible debe ser 1.000.000, obtuvo {payslip.total_imponible:,.0f}"
        )
    
    def test_02_afp_uses_total_imponible(self):
        """Test AFP usa total_imponible correctamente"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        payslip.action_compute_sheet()
        
        # AFP = 1.000.000 * 11.44% = 114.400
        afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')
        
        self.assertEqual(len(afp_line), 1, "Debe existir exactamente 1 línea AFP")
        self.assertAlmostEqual(
            abs(afp_line.total), 114400, 
            delta=10,
            msg=f"AFP debe ser ~114.400, obtuvo {abs(afp_line.total):,.0f}"
        )
    
    def test_03_health_fonasa_uses_total_imponible(self):
        """Test FONASA usa total_imponible correctamente"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        payslip.action_compute_sheet()
        
        # FONASA = 1.000.000 * 7% = 70.000
        health_line = payslip.line_ids.filtered(lambda l: l.code == 'HEALTH')
        
        self.assertEqual(len(health_line), 1, "Debe existir exactamente 1 línea HEALTH")
        self.assertAlmostEqual(
            abs(health_line.total), 70000, 
            delta=10,
            msg=f"FONASA debe ser ~70.000, obtuvo {abs(health_line.total):,.0f}"
        )
    
    def test_04_net_wage_calculation(self):
        """Test cálculo líquido a pagar"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        payslip.action_compute_sheet()
        
        # Líquido = 1.000.000 - 114.400 (AFP) - 70.000 (FONASA) = 815.600
        expected_net = 815600
        
        self.assertAlmostEqual(
            payslip.net_wage, expected_net, 
            delta=100,
            msg=f"Líquido debe ser ~{expected_net:,.0f}, obtuvo {payslip.net_wage:,.0f}"
        )
    
    def test_05_sequence_generation(self):
        """Test generación automática de número secuencial"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        # Verificar que se generó número
        self.assertTrue(payslip.number, "Número debe ser generado automáticamente")
        self.assertNotEqual(payslip.number, '/', "Número no debe ser '/'")
        self.assertTrue(
            payslip.number.startswith('LIQ-'),
            f"Número debe empezar con 'LIQ-', obtuvo: {payslip.number}"
        )
    
    def test_06_line_categories_correct(self):
        """Test líneas tienen categorías correctas"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        payslip.action_compute_sheet()
        
        # Verificar categoría BASE
        basic_line = payslip.line_ids.filtered(lambda l: l.code == 'BASIC')
        self.assertTrue(basic_line.category_id, "Línea BASIC debe tener categoría")
        self.assertEqual(basic_line.category_id.code, 'BASE', "Categoría debe ser BASE")
        
        # Verificar categoría LEGAL para descuentos
        afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')
        self.assertTrue(afp_line.category_id.parent_id, "AFP debe tener categoría padre")
        self.assertEqual(
            afp_line.category_id.parent_id.code, 'DESC',
            "Padre de categoría AFP debe ser DESC"
        )
