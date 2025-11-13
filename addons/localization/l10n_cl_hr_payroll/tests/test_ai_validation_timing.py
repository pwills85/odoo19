# -*- coding: utf-8 -*-
from odoo.tests import tagged, TransactionCase
from odoo.exceptions import UserError
from unittest.mock import patch, MagicMock


@tagged('post_install', '-at_install', 'l10n_cl')
class TestAIValidationTiming(TransactionCase):
    """Test AI validation timing in payslip workflow"""
    
    def setUp(self):
        super().setUp()
        
        # Create employee
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee',
        })
        
        # Create contract
        self.contract = self.env['hr.contract'].create({
            'name': 'Test Contract',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': '2025-01-01',
        })
        
        # Create payslip
        self.payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': '2025-01-01',
            'date_to': '2025-01-31',
        })
        
        # Enable AI validation
        self.env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_hr_payroll.ai_validation_enabled',
            'True'
        )
    
    def test_action_done_without_compute_raises_error(self):
        """Test: No se puede confirmar sin calcular primero"""
        with self.assertRaises(UserError) as cm:
            self.payslip.action_done()
        
        self.assertIn('calcular la liquidación antes', str(cm.exception))
    
    def test_action_done_validates_with_ai_before_confirm(self):
        """Test: Validación IA se ejecuta ANTES de confirmar"""
        # Calcular liquidación (creates line_ids)
        self.payslip.compute_sheet()
        
        # Mock validación IA (alta confianza)
        with patch.object(type(self.payslip), 'validate_with_ai') as mock_validate:
            mock_validate.return_value = {
                'success': True,
                'confidence': 95.0,
                'errors': [],
                'warnings': [],
                'recommendation': 'approve'
            }
            
            # Confirmar
            result = self.payslip.action_done()
            
            # Validar que IA fue llamada ANTES de cambiar estado
            mock_validate.assert_called_once()
            self.assertEqual(self.payslip.state, 'done')
            self.assertTrue(result)
    
    def test_action_done_shows_wizard_if_low_confidence(self):
        """Test: Confianza baja (<80%) muestra wizard advertencia"""
        self.payslip.compute_sheet()
        
        # Mock validación IA (baja confianza)
        with patch.object(type(self.payslip), 'validate_with_ai') as mock_validate:
            mock_validate.return_value = {
                'success': True,
                'confidence': 65.0,
                'errors': [],
                'warnings': ['AFP rate mismatch'],
                'recommendation': 'review'
            }
            
            # Confirmar (debe retornar wizard)
            result = self.payslip.action_done()
            
            self.assertEqual(result['type'], 'ir.actions.act_window')
            self.assertEqual(result['res_model'], 'payroll.ai.validation.wizard')
            # Estado NO debe cambiar a 'done' aún
            self.assertNotEqual(self.payslip.state, 'done')
    
    def test_action_done_graceful_degradation_if_ai_fails(self):
        """Test: Si IA falla, permite confirmación manual"""
        self.payslip.compute_sheet()
        
        # Mock validación IA (error)
        with patch.object(type(self.payslip), 'validate_with_ai') as mock_validate:
            mock_validate.side_effect = Exception('AI service timeout')
            
            # Confirmar (debe continuar a pesar del error)
            result = self.payslip.action_done()
            
            # Validar degradación elegante
            self.assertEqual(self.payslip.state, 'done')
            self.assertEqual(self.payslip.ai_validation_status, 'error')
            self.assertTrue(result)
