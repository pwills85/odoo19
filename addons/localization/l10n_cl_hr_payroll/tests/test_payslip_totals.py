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
            'period': date(2025, 10, 1),
            'uf': 39383.07,
            'utm': 68647,
            'uta': 823764,
            'minimum_wage': 500000.00,
            'afp_limit': 87.8,
        })

        # Estructura salarial
        self.struct = self.env.ref('l10n_cl_hr_payroll.structure_base_cl',
                                   raise_if_not_found=False)
        if not self.struct:
            self.struct = self.env['hr.payroll.structure'].create({
                'name': 'Estructura Chile',
                'code': 'CL_BASE'
            })
    
    def test_01_total_imponible_single_line(self):
        """Test total_imponible incluye sueldo base + gratificación"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        # Calcular
        payslip.action_compute_sheet()

        # Verificar total_imponible = sueldo base + gratificación prorrateada
        # Gratificación legal = 25% / 12 meses = 2.0833% mensual
        # $1.000.000 * 2.0833% = $20.833
        # Total imponible = $1.000.000 + $20.833 = $1.020.833
        self.assertAlmostEqual(
            payslip.total_imponible, 1020833,
            delta=100,
            msg=f"total_imponible debe ser ~1.020.833 (incluye gratificación), obtuvo {payslip.total_imponible:,.0f}"
        )
    
    def test_02_afp_uses_total_imponible(self):
        """Test AFP usa total_imponible correctamente (incluye gratificación)"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        payslip.action_compute_sheet()

        # AFP = total_imponible * 11.44%
        # Total imponible = $1.020.833 (sueldo + gratificación)
        # AFP = $1.020.833 * 11.44% = $116.783
        afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')

        self.assertEqual(len(afp_line), 1, "Debe existir exactamente 1 línea AFP")
        self.assertAlmostEqual(
            abs(afp_line.total), 116783,
            delta=100,
            msg=f"AFP debe ser ~116.783 (incluye gratificación), obtuvo {abs(afp_line.total):,.0f}"
        )
    
    def test_03_health_fonasa_uses_total_imponible(self):
        """Test FONASA usa total_imponible correctamente (incluye gratificación)"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        payslip.action_compute_sheet()

        # FONASA = total_imponible * 7%
        # Total imponible = $1.020.833 (sueldo + gratificación)
        # FONASA = $1.020.833 * 7% = $71.458
        health_line = payslip.line_ids.filtered(lambda l: l.code == 'HEALTH')

        self.assertEqual(len(health_line), 1, "Debe existir exactamente 1 línea HEALTH")
        self.assertAlmostEqual(
            abs(health_line.total), 71458,
            delta=100,
            msg=f"FONASA debe ser ~71.458 (incluye gratificación), obtuvo {abs(health_line.total):,.0f}"
        )
    
    def test_04_net_wage_calculation(self):
        """Test cálculo líquido a pagar (incluye gratificación)"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        payslip.action_compute_sheet()

        # Cálculo aproximado con gratificación:
        # Bruto = $1.055.542 (sueldo + gratificación + otros haberes)
        # Descuentos: AFP $116.783 + FONASA $71.458 + otros = ~$194.367
        # Líquido ≈ $861.175
        expected_net = 861175

        self.assertAlmostEqual(
            payslip.net_wage, expected_net,
            delta=1000,
            msg=f"Líquido debe ser ~{expected_net:,.0f} (incluye gratificación), obtuvo {payslip.net_wage:,.0f}"
        )
    
    def test_05_sequence_generation(self):
        """Test generación automática de número secuencial"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
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
            'struct_id': self.struct.id,
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
