# -*- coding: utf-8 -*-
from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError


@tagged('post_install', '-at_install', 'l10n_cl')
class TestPrevired105Validation(TransactionCase):
    """Test Previred 105-field validation wizard"""
    
    def setUp(self):
        super().setUp()
        
        # Create employee with complete data
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee',
            'identification_id': '12345678-9',
            'birthday': '1990-01-01',
        })
        
        # Create AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Test',
            'code': 'TEST',
            'rate': 10.0,
        })
        
        # Create contract with AFP
        self.contract = self.env['hr.contract'].create({
            'name': 'Test Contract',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': '2025-01-01',
            'afp_id': self.afp.id,
            'health_system': 'fonasa',
        })
        
        # Create payslip run
        self.payslip_run = self.env['hr.payslip.run'].create({
            'name': 'Enero 2025',
            'date_start': '2025-01-01',
            'date_end': '2025-01-31',
        })
        
        # Create payslip
        self.payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'payslip_run_id': self.payslip_run.id,
            'date_from': '2025-01-01',
            'date_to': '2025-01-31',
        })
        
        # Compute payslip
        self.payslip.compute_sheet()
    
    def test_validation_wizard_detects_missing_rut(self):
        """Test: Wizard detecta RUT faltante"""
        # Remover RUT empleado
        self.payslip.employee_id.identification_id = False
        
        # Crear wizard
        wizard = self.env['previred.validation.wizard'].create({
            'payslip_run_id': self.payslip_run.id,
        })
        
        # Validar
        wizard.action_validate()
        
        # Verificar error
        self.assertEqual(wizard.validation_status, 'failed')
        self.assertGreater(wizard.error_count, 0)
        self.assertIn('RUT faltante', wizard.validation_result)
        self.assertFalse(wizard.can_generate_lre)
    
    def test_validation_wizard_passes_with_complete_data(self):
        """Test: Wizard aprueba con datos completos"""
        # Crear wizard
        wizard = self.env['previred.validation.wizard'].create({
            'payslip_run_id': self.payslip_run.id,
        })
        
        # Validar
        wizard.action_validate()
        
        # Verificar éxito (puede tener warnings pero 0 errors)
        self.assertIn(wizard.validation_status, ['passed', 'warning'])
        self.assertEqual(wizard.error_count, 0)
        self.assertTrue(wizard.can_generate_lre)
    
    def test_cannot_generate_lre_with_errors(self):
        """Test: No puede generar LRE con errores"""
        # Crear wizard con errores simulados
        wizard = self.env['previred.validation.wizard'].create({
            'payslip_run_id': self.payslip_run.id,
            'validation_status': 'failed',
            'error_count': 5,
        })
        
        # Intentar generar LRE
        with self.assertRaises(ValidationError) as cm:
            wizard.action_generate_lre()
        
        self.assertIn('errores de validación', str(cm.exception).lower())
    
    def test_validation_detects_missing_afp(self):
        """Test: Wizard detecta AFP faltante"""
        # Remover AFP del contrato
        self.payslip.contract_id.afp_id = False
        
        # Crear wizard
        wizard = self.env['previred.validation.wizard'].create({
            'payslip_run_id': self.payslip_run.id,
        })
        
        # Validar
        wizard.action_validate()
        
        # Verificar error
        self.assertEqual(wizard.validation_status, 'failed')
        self.assertGreater(wizard.error_count, 0)
        self.assertIn('AFP no configurada', wizard.validation_result)
    
    def test_validation_detects_missing_health_deduction(self):
        """Test: Wizard detecta descuento salud faltante"""
        # Remover líneas de salud
        self.payslip.line_ids.filtered(
            lambda l: l.code in ('SALUD_FONASA', 'SALUD_ISAPRE')
        ).unlink()
        
        # Crear wizard
        wizard = self.env['previred.validation.wizard'].create({
            'payslip_run_id': self.payslip_run.id,
        })
        
        # Validar
        wizard.action_validate()
        
        # Verificar error
        self.assertEqual(wizard.validation_status, 'failed')
        self.assertGreater(wizard.error_count, 0)
        self.assertIn('salud faltante', wizard.validation_result.lower())
