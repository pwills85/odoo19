# -*- coding: utf-8 -*-
"""Tests de seguridad multi-company para Account Financial Report"""

from odoo.tests import TransactionCase, tagged
from odoo.exceptions import AccessError


@tagged('security', 'multi_company')
class TestMultiCompanySecurity(TransactionCase):
    """Test de seguridad multi-company."""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Crear dos compañías
        cls.company_1 = cls.env['res.company'].create({
            'name': 'Test Company 1',
            'currency_id': cls.env.ref('base.CLP').id,
        })
        cls.company_2 = cls.env['res.company'].create({
            'name': 'Test Company 2', 
            'currency_id': cls.env.ref('base.CLP').id,
        })
        
        # Crear usuarios con acceso a diferentes compañías
        cls.user_company_1 = cls.env['res.users'].create({
            'name': 'User Company 1',
            'login': 'user_c1',
            'company_ids': [(6, 0, [cls.company_1.id])],
            'company_id': cls.company_1.id,
        })
        
        cls.user_company_2 = cls.env['res.users'].create({
            'name': 'User Company 2',
            'login': 'user_c2',
            'company_ids': [(6, 0, [cls.company_2.id])],
            'company_id': cls.company_2.id,
        })
        
        cls.user_multi = cls.env['res.users'].create({
            'name': 'Multi Company User',
            'login': 'user_multi',
            'company_ids': [(6, 0, [cls.company_1.id, cls.company_2.id])],
            'company_id': cls.company_1.id,
        })
    
    def test_01_company_isolation(self):
        """Test que los datos están aislados por compañía."""
        # Crear reporte en company 1
        report_c1 = self.env['financial.report.service'].with_user(
            self.user_company_1
        ).with_company(self.company_1).create({
            'name': 'Report Company 1',
            'company_id': self.company_1.id,
        })
        
        # Usuario de company 2 no debe poder acceder
        with self.assertRaises(AccessError):
            report_c1.with_user(self.user_company_2).read(['name'])
    
    def test_02_multi_company_access(self):
        """Test que usuario multi-company puede acceder correctamente."""
        # Crear reportes en ambas compañías
        report_c1 = self.env['financial.report.service'].with_company(
            self.company_1
        ).create({
            'name': 'Report Company 1',
            'company_id': self.company_1.id,
        })
        
        report_c2 = self.env['financial.report.service'].with_company(
            self.company_2
        ).create({
            'name': 'Report Company 2',
            'company_id': self.company_2.id,
        })
        
        # Usuario multi-company puede acceder a ambos
        reports = self.env['financial.report.service'].with_user(
            self.user_multi
        ).search([])
        
        self.assertIn(report_c1, reports)
        self.assertIn(report_c2, reports)
    
    def test_03_sudo_with_company_check(self):
        """Test que sudo respeta las restricciones de company."""
        # Crear dato sensible en company 1
        sensitive_data = self.env['financial.report.kpi'].with_company(
            self.company_1
        ).create({
            'name': 'Sensitive KPI',
            'company_id': self.company_1.id,
            'value': 1000000,
        })
        
        # Incluso con sudo, debe respetar company
        with self.assertRaises(AccessError):
            sensitive_data.with_user(
                self.user_company_2
            ).with_user(self.env.user).write({'value': 0})
    
    def test_04_search_domain_injection(self):
        """Test contra inyección de dominio en búsquedas."""
        # Intentar bypass de seguridad con dominio malicioso
        malicious_domain = [
            '|', ('company_id', '!=', self.company_1.id),
            ('company_id', '=', self.company_2.id)
        ]
        
        # Debe retornar solo registros de la compañía actual
        results = self.env['financial.report.service'].with_user(
            self.user_company_1
        ).search(malicious_domain)
        
        for record in results:
            self.assertEqual(record.company_id, self.company_1)
