# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase


class TestCompanyCurrencyIdFields(TransactionCase):
    """Tests campo company_currency_id en modelos payroll"""

    def test_payslip_has_company_currency_id(self):
        """Verificar company_currency_id existe en hr.payslip base"""
        model = self.env['hr.payslip']
        self.assertIn('company_currency_id', model._fields)
        field = model._fields['company_currency_id']
        self.assertEqual(field.related, 'company_id.currency_id')
        self.assertTrue(field.store)

    def test_company_currency_id_functional(self):
        """Verificar que company_currency_id funciona correctamente"""
        # Crear empleado de prueba
        employee = self.env['hr.employee'].create({
            'name': 'Test Employee Currency',
        })

        # Crear contrato de prueba
        contract = self.env['hr.contract'].create({
            'name': 'Test Contract Currency',
            'employee_id': employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
            'state': 'open',
        })

        # Crear payslip
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip Currency',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': '2025-01-01',
            'date_to': '2025-01-31',
        })

        # Verificar que company_currency_id se pobló correctamente
        self.assertTrue(payslip.company_currency_id)
        self.assertEqual(payslip.company_currency_id, payslip.company_id.currency_id)
        self.assertEqual(payslip.company_currency_id, payslip.currency_id)
