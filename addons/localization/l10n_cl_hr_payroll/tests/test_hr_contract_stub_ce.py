# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestHrContractStubCE(TransactionCase):
    """Tests para stub hr.contract CE"""

    def setUp(self):
        super().setUp()
        self.Employee = self.env['hr.employee']
        self.Contract = self.env['hr.contract']

        self.employee = self.Employee.create({
            'name': 'Test Employee Contract Stub',
        })

    def test_contract_create_basic(self):
        """Test creación contrato básico"""
        contract = self.Contract.create({
            'name': 'Test Contract',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
        })

        self.assertEqual(contract.state, 'draft')
        self.assertEqual(contract.wage, 1500000)
        self.assertTrue(contract.currency_id)

    def test_contract_wage_positive_constraint(self):
        """Test constraint sueldo positivo"""
        with self.assertRaises(ValidationError):
            self.Contract.create({
                'name': 'Invalid Contract',
                'employee_id': self.employee.id,
                'wage': -1000,
                'date_start': '2025-01-01',
            })

    def test_contract_dates_coherence(self):
        """Test coherencia fechas"""
        with self.assertRaises(ValidationError):
            self.Contract.create({
                'name': 'Invalid Dates Contract',
                'employee_id': self.employee.id,
                'wage': 1500000,
                'date_start': '2025-12-31',
                'date_end': '2025-01-01',
            })

    def test_contract_overlap_prevention(self):
        """Test prevención contratos superpuestos"""
        # Crear primer contrato vigente
        contract1 = self.Contract.create({
            'name': 'Contract 1',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
            'date_end': '2025-12-31',
            'state': 'open',
        })

        # Intentar crear contrato superpuesto
        with self.assertRaises(ValidationError):
            self.Contract.create({
                'name': 'Overlapping Contract',
                'employee_id': self.employee.id,
                'wage': 1600000,
                'date_start': '2025-06-01',
                'date_end': '2026-06-01',
                'state': 'open',
            })

    def test_contract_actions(self):
        """Test acciones abrir/cerrar contrato"""
        contract = self.Contract.create({
            'name': 'Test Actions Contract',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
        })

        # Activar
        contract.action_open()
        self.assertEqual(contract.state, 'open')

        # Cerrar
        contract.action_close()
        self.assertEqual(contract.state, 'close')
        self.assertTrue(contract.date_end)
