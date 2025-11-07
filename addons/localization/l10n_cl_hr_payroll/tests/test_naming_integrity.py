# -*- coding: utf-8 -*-

"""
Test de Integridad de Nombres - P0 Critical
=============================================

Verifica que tests usen campos que existen en modelos.
Este test DEBE pasar antes de merge.

GATE CI: Falla si encuentra referencias a campos inexistentes.
"""

from odoo.tests import tagged, TransactionCase


@tagged('post_install', '-at_install', 'naming_integrity')
class TestNamingIntegrity(TransactionCase):
    """
    Test de integridad de nombres entre modelos y tests
    
    Verifica:
    - hr.economic.indicators usa 'period' (Date) no 'year'/'month'
    - hr.economic.indicators usa 'minimum_wage' no 'sueldo_minimo'
    - hr.contract usa 'weekly_hours' no 'jornada_semanal'
    - Secuencias usan prefijo 'LIQ-'
    """
    
    def setUp(self):
        super().setUp()
        self.IndicatorModel = self.env['hr.economic.indicators']
        self.ContractModel = self.env['hr.contract']
        self.SequenceModel = self.env['ir.sequence']
    
    def test_indicator_has_period_field(self):
        """Verificar que hr.economic.indicators tiene campo 'period'"""
        self.assertIn(
            'period',
            self.IndicatorModel._fields,
            "hr.economic.indicators debe tener campo 'period' (Date)"
        )
    
    def test_indicator_no_year_month_fields(self):
        """Verificar que hr.economic.indicators NO tiene 'year'/'month' separados"""
        self.assertNotIn(
            'year',
            self.IndicatorModel._fields,
            "hr.economic.indicators NO debe tener campo 'year' (usar 'period')"
        )
        self.assertNotIn(
            'month',
            self.IndicatorModel._fields,
            "hr.economic.indicators NO debe tener campo 'month' (usar 'period')"
        )
    
    def test_indicator_has_minimum_wage(self):
        """Verificar que hr.economic.indicators tiene 'minimum_wage'"""
        self.assertIn(
            'minimum_wage',
            self.IndicatorModel._fields,
            "hr.economic.indicators debe tener campo 'minimum_wage'"
        )
    
    def test_indicator_no_sueldo_minimo(self):
        """Verificar que hr.economic.indicators NO tiene 'sueldo_minimo'"""
        self.assertNotIn(
            'sueldo_minimo',
            self.IndicatorModel._fields,
            "hr.economic.indicators NO debe tener campo 'sueldo_minimo' (usar 'minimum_wage')"
        )
    
    def test_contract_has_weekly_hours(self):
        """Verificar que hr.contract tiene 'weekly_hours'"""
        self.assertIn(
            'weekly_hours',
            self.ContractModel._fields,
            "hr.contract debe tener campo 'weekly_hours'"
        )
    
    def test_contract_no_jornada_semanal(self):
        """Verificar que hr.contract NO tiene 'jornada_semanal'"""
        self.assertNotIn(
            'jornada_semanal',
            self.ContractModel._fields,
            "hr.contract NO debe tener campo 'jornada_semanal' (usar 'weekly_hours')"
        )
    
    def test_payslip_sequence_prefix(self):
        """Verificar que secuencia hr.payslip usa prefijo 'LIQ-'"""
        sequence = self.SequenceModel.search([
            ('code', '=', 'hr.payslip')
        ], limit=1)
        
        if sequence:
            self.assertTrue(
                sequence.prefix and 'LIQ' in sequence.prefix,
                f"Secuencia hr.payslip debe usar prefijo con 'LIQ', tiene: {sequence.prefix}"
            )
    
    def test_indicator_field_types(self):
        """Verificar tipos de campos en hr.economic.indicators"""
        # period debe ser Date
        period_field = self.IndicatorModel._fields.get('period')
        self.assertIsNotNone(period_field, "Campo 'period' debe existir")
        self.assertEqual(
            period_field.type,
            'date',
            "Campo 'period' debe ser tipo Date"
        )
        
        # minimum_wage debe ser Float
        wage_field = self.IndicatorModel._fields.get('minimum_wage')
        self.assertIsNotNone(wage_field, "Campo 'minimum_wage' debe existir")
        self.assertEqual(
            wage_field.type,
            'float',
            "Campo 'minimum_wage' debe ser tipo Float"
        )
    
    def test_contract_field_types(self):
        """Verificar tipos de campos en hr.contract"""
        # weekly_hours debe ser Integer
        hours_field = self.ContractModel._fields.get('weekly_hours')
        self.assertIsNotNone(hours_field, "Campo 'weekly_hours' debe existir")
        self.assertEqual(
            hours_field.type,
            'integer',
            "Campo 'weekly_hours' debe ser tipo Integer"
        )
