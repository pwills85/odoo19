# -*- coding: utf-8 -*-
"""
Test corrección tasa SIS 1.57%

Valida que el Seguro de Invalidez y Sobrevivencia (SIS) 
se calcule correctamente con la tasa 1.57% según D.L. 3.500, Art. 68
"""

from odoo.tests import tagged, TransactionCase
from datetime import date


@tagged('post_install', '-at_install', 'l10n_cl', 'p1_fix', 'sis')
class TestSISRateFix(TransactionCase):
    """Test corrección tasa SIS 1.57%"""

    def setUp(self):
        super().setUp()
        
        # Crear compañía de prueba
        self.company = self.env['res.company'].create({
            'name': 'Test Company SIS',
            'vat': '76876876-8',
            'country_id': self.env.ref('base.cl').id,
        })
        
        # Crear empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee SIS',
            'company_id': self.company.id,
        })
        
        # Crear AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Test',
            'code': 'TEST',
            'rate': 11.44,
            'sis_rate': 1.57,  # ✅ Tasa correcta
        })
        
        # Crear indicador económico (UF)
        self.env['hr.economic.indicators'].create({
            'period': date(2025, 11, 1),
            'uf': 38500.0,
            'utm': 67200.0,
        })
        
        # Crear contrato
        self.contract = self.env['hr.contract'].create({
            'name': 'Contrato Test SIS',
            'employee_id': self.employee.id,
            'wage': 1000000,  # $1.000.000
            'date_start': date(2025, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id,
            'company_id': self.company.id,
        })

    def test_sis_rate_157_percent(self):
        """Validar SIS exactamente 1.57% (no 1.53%)"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
            'company_id': self.company.id,
        })
        payslip.compute_sheet()
        
        # Validar SIS = 1.57% (15.700 CLP)
        expected_sis = 1000000 * 0.0157  # 15.700
        
        self.assertAlmostEqual(
            payslip.aporte_sis_amount,
            expected_sis,
            places=0,
            msg=f"SIS debe ser 1.57% = ${expected_sis:,.0f} (actual: ${payslip.aporte_sis_amount:,.0f})"
        )
    
    def test_sis_rate_with_high_salary(self):
        """Validar SIS con tope 87.8 UF"""
        # Crear empleado con sueldo alto
        high_salary_contract = self.env['hr.contract'].create({
            'name': 'Contrato Alto Sueldo',
            'employee_id': self.employee.id,
            'wage': 10000000,  # $10.000.000 (supera tope)
            'date_start': date(2025, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id,
            'company_id': self.company.id,
        })
        
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': high_salary_contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
            'company_id': self.company.id,
        })
        payslip.compute_sheet()
        
        # Tope: 87.8 UF * 38.500 = 3.380.300
        tope_afp_clp = 87.8 * 38500
        expected_sis = tope_afp_clp * 0.0157  # 53.070,71
        
        self.assertAlmostEqual(
            payslip.aporte_sis_amount,
            expected_sis,
            delta=100,  # Tolerancia ±100 por redondeos
            msg=f"SIS con tope debe ser ${expected_sis:,.0f} (actual: ${payslip.aporte_sis_amount:,.0f})"
        )
    
    def test_sis_rate_not_153(self):
        """Validar que NO se use tasa incorrecta 1.53%"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
            'company_id': self.company.id,
        })
        payslip.compute_sheet()
        
        # Tasa incorrecta 1.53%
        wrong_sis = 1000000 * 0.0153  # 15.300 (INCORRECTO)
        
        self.assertNotAlmostEqual(
            payslip.aporte_sis_amount,
            wrong_sis,
            places=0,
            msg=f"SIS NO debe ser 1.53% = ${wrong_sis:,.0f}"
        )
        
        # Validar diferencia de $400 entre tasas
        difference = abs(payslip.aporte_sis_amount - wrong_sis)
        expected_difference = 1000000 * (0.0157 - 0.0153)  # 400
        
        self.assertAlmostEqual(
            difference,
            expected_difference,
            places=0,
            msg=f"Diferencia entre tasas debe ser ${expected_difference:,.0f}"
        )
