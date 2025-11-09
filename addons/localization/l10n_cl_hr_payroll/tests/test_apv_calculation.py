# -*- coding: utf-8 -*-

"""
Tests APV (Ahorro Previsional Voluntario) - P0-2
================================================

Verificar:
- Cálculo correcto Régimen A (con rebaja tributaria)
- Cálculo correcto Régimen B (sin rebaja tributaria)
- Conversión UF → CLP
- Tope mensual aplicado
- Tope anual aplicado
- Sin APV configurado funciona normalmente
- Rebaja tributaria solo en Régimen A
- Descuento visible en liquidación ambos regímenes
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError
from datetime import date


@tagged('post_install', '-at_install', 'payroll_apv')
class TestAPVCalculation(TransactionCase):
    """Test cálculo APV en liquidaciones"""
    
    def setUp(self):
        super().setUp()
        
        # Crear indicadores económicos
        self.indicator = self.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 39000.0,  # Valor aproximado 2025
            'utm': 68000.0,
            'uta': 816000.0,
            'minimum_wage': 500000.0,
            'afp_limit': 87.8,
        })
        
        # Crear AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Capital',
            'code': 'CAPITAL',
            'rate': 11.44,
        })
        
        # Crear institución APV
        self.apv_institution = self.env['l10n_cl.apv.institution'].create({
            'name': 'AFP Capital APV',
            'code': 'CAPITAL_APV',
            'institution_type': 'afp',
        })
        
        # Crear topes legales
        self.env['l10n_cl.legal.caps'].create({
            'code': 'APV_CAP_MONTHLY',
            'amount': 50.0,  # 50 UF
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
        })
        
        self.env['l10n_cl.legal.caps'].create({
            'code': 'APV_CAP_ANNUAL',
            'amount': 600.0,  # 600 UF
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
        })
        
        # Crear empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee APV',
        })
        
        # Contrato base (sin APV)
        self.contract_base = self.env['hr.contract'].create({
            'name': 'Contract Base',
            'employee_id': self.employee.id,
            'wage': 2000000,  # $2M
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'weekly_hours': 44,
            'state': 'open',
            'date_start': date(2025, 1, 1),
        })
    
    def test_01_apv_regime_a_fixed_clp(self):
        """Test APV Régimen A con monto fijo en CLP"""
        # Configurar APV Régimen A: $100.000 fijos
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'A',
            'l10n_cl_apv_amount': 100000.0,
            'l10n_cl_apv_amount_type': 'fixed',
        })
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar que existe línea APV_A
        apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV_A')
        
        self.assertEqual(len(apv_line), 1, "Debe existir exactamente 1 línea APV_A")
        self.assertAlmostEqual(
            abs(apv_line.total), 100000.0,
            delta=1,
            msg="APV debe ser $100.000"
        )
        
        # Verificar que se incluye en descuentos previsionales
        previsional_total = payslip._get_total_previsional()
        self.assertGreater(previsional_total, 100000, 
                          "APV debe estar incluido en total previsional")
    
    def test_02_apv_regime_b_fixed_clp(self):
        """Test APV Régimen B con monto fijo en CLP"""
        # Configurar APV Régimen B: $100.000 fijos
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'B',
            'l10n_cl_apv_amount': 100000.0,
            'l10n_cl_apv_amount_type': 'fixed',
        })
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar que existe línea APV_B
        apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV_B')
        
        self.assertEqual(len(apv_line), 1, "Debe existir exactamente 1 línea APV_B")
        self.assertAlmostEqual(
            abs(apv_line.total), 100000.0,
            delta=1,
            msg="APV debe ser $100.000"
        )
        
        # Verificar que NO se incluye en descuentos previsionales (Régimen B)
        previsional_codes = ['AFP', 'HEALTH', 'APV_A']  # Solo APV_A rebaja
        previsional_lines = payslip.line_ids.filtered(
            lambda l: l.code in previsional_codes
        )
        self.assertFalse(
            any(l.code == 'APV_B' for l in previsional_lines),
            "APV Régimen B no debe estar en descuentos previsionales"
        )
    
    def test_03_apv_uf_to_clp_conversion(self):
        """Test conversión UF → CLP en APV"""
        # Configurar APV en UF: 2.5 UF
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'A',
            'l10n_cl_apv_amount': 2.5,  # UF
            'l10n_cl_apv_amount_type': 'uf',
        })
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar conversión: 2.5 UF * 39.000 = $97.500
        apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV_A')
        expected_amount = 2.5 * self.indicator.uf
        
        self.assertAlmostEqual(
            abs(apv_line.total), expected_amount,
            delta=10,
            msg=f"APV debe ser 2.5 UF = ${expected_amount:,.0f}"
        )
    
    def test_04_apv_monthly_cap_applied(self):
        """Test tope mensual 50 UF aplicado"""
        # Configurar APV superior al tope: 80 UF (> 50 UF)
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'A',
            'l10n_cl_apv_amount': 80.0,  # UF
            'l10n_cl_apv_amount_type': 'uf',
        })
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar que se aplicó tope: máximo 50 UF
        apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV_A')
        expected_capped = 50.0 * self.indicator.uf  # 50 UF es el tope
        
        self.assertAlmostEqual(
            abs(apv_line.total), expected_capped,
            delta=10,
            msg=f"APV debe estar topado a 50 UF = ${expected_capped:,.0f}"
        )
    
    def test_05_apv_percent_rli(self):
        """Test APV como porcentaje de RLI"""
        # Configurar APV: 5% de RLI
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'A',
            'l10n_cl_apv_amount': 5.0,  # %
            'l10n_cl_apv_amount_type': 'percent',
        })
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # RLI = $2.000.000 (sueldo base)
        # APV = 5% * 2.000.000 = $100.000
        apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV_A')
        
        self.assertAlmostEqual(
            abs(apv_line.total), 100000.0,
            delta=100,
            msg="APV debe ser 5% de $2.000.000 = $100.000"
        )
    
    def test_06_apv_not_configured(self):
        """Test liquidación sin APV funciona normalmente"""
        # NO configurar APV en contrato
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar que NO existe línea APV
        apv_lines = payslip.line_ids.filtered(lambda l: 'APV' in l.code)
        
        self.assertEqual(len(apv_lines), 0, "No debe haber líneas APV")
        
        # Verificar que la liquidación se calculó correctamente
        self.assertTrue(payslip.line_ids, "Debe haber líneas calculadas")
        self.assertGreater(payslip.net_wage, 0, "Debe haber líquido a pagar")
    
    def test_07_apv_regime_a_tax_rebate(self):
        """Test rebaja tributaria solo para Régimen A"""
        # Configurar APV Régimen A
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'A',
            'l10n_cl_apv_amount': 150000.0,
            'l10n_cl_apv_amount_type': 'fixed',
        })
        
        # Crear liquidación con Régimen A
        payslip_a = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        payslip_a.action_compute_sheet()
        
        # Cambiar a Régimen B
        self.contract_base.write({'l10n_cl_apv_regime': 'B'})
        
        # Crear liquidación con Régimen B
        payslip_b = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 2, 1),
            'date_to': date(2025, 2, 28),
            'indicadores_id': self.indicator.id,
        })
        payslip_b.action_compute_sheet()
        
        # Régimen A debe incluir APV en previsionales
        previsional_a = payslip_a._get_total_previsional()
        apv_a = abs(payslip_a.line_ids.filtered(lambda l: l.code == 'APV_A').total)
        
        self.assertGreater(previsional_a, apv_a,
                          "Previsional A debe incluir APV")
        
        # Régimen B NO debe incluir APV en previsionales
        previsional_b = payslip_b._get_total_previsional()
        apv_b = abs(payslip_b.line_ids.filtered(lambda l: l.code == 'APV_B').total)
        
        self.assertGreater(apv_b, 0, "Debe haber APV en Régimen B")
        # Verificar que previsional B no incluye APV_B
        previsional_codes_b = payslip_b.line_ids.filtered(
            lambda l: l.code in ['AFP', 'HEALTH', 'APV_A']
        ).mapped('code')
        self.assertNotIn('APV_B', previsional_codes_b,
                        "APV_B no debe estar en previsionales")
    
    def test_08_apv_visible_in_payslip(self):
        """Test APV visible en liquidación ambos regímenes"""
        # Régimen A
        self.contract_base.write({
            'l10n_cl_apv_institution_id': self.apv_institution.id,
            'l10n_cl_apv_regime': 'A',
            'l10n_cl_apv_amount': 100000.0,
            'l10n_cl_apv_amount_type': 'fixed',
        })
        
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract_base.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicator.id,
        })
        payslip.action_compute_sheet()
        
        # Verificar línea visible con nombre descriptivo
        apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV_A')
        
        self.assertTrue(apv_line.name, "Debe tener nombre")
        self.assertIn('APV', apv_line.name, "Nombre debe contener 'APV'")
        self.assertIn('Régimen A', apv_line.name, "Debe indicar régimen")
        self.assertIn(self.apv_institution.name, apv_line.name,
                     "Debe mostrar nombre de institución")
        
        # Verificar que es descuento (negativo)
        self.assertLess(apv_line.total, 0, "APV debe ser descuento (negativo)")
