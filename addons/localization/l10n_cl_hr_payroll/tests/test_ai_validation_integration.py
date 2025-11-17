# -*- coding: utf-8 -*-

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import UserError
from unittest.mock import patch, MagicMock
from datetime import date

@tagged('post_install', 'ai_integration', 'payroll')
class TestAIValidationIntegration(TransactionCase):
    """Test integración validación IA en liquidaciones"""
    
    def setUp(self):
        super().setUp()
        
        # Crear empleado y contrato test
        self.employee = self.env['hr.employee'].create({
            'name': 'Test AI Validation',
            'identification_id': '12345678-9'
        })
        
        self.contract = self.env['hr.contract'].create({
            'name': 'Contrato Test AI',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': date(2025, 1, 1),
            'state': 'open'
        })
        
        # Habilitar validación IA
        self.env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_hr_payroll.ai_validation_enabled',
            'True'
        )
    
    @patch('requests.post')
    def test_ai_validation_approve(self, mock_post):
        """Test: IA aprueba liquidación (confidence >80%)"""
        
        # Mock respuesta AI-Service (aprobación)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'success': True,
            'confidence': 92.5,
            'errors': [],
            'warnings': [],
            'recommendation': 'approve'
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
        })
        
        payslip.compute_sheet()
        
        # Validar con IA
        result = payslip.validate_with_ai()
        
        # Assertions
        self.assertTrue(result['success'], "Validación IA debe ser exitosa")
        self.assertEqual(payslip.ai_validation_status, 'approved')
        self.assertAlmostEqual(payslip.ai_confidence, 92.5, places=1)
        self.assertFalse(payslip.ai_errors)
        
        # Verificar que se llamó endpoint correcto
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn('/api/payroll/validate', call_args[0][0])
    
    @patch('requests.post')
    def test_ai_validation_reject_blocks_confirmation(self, mock_post):
        """Test: IA rechaza liquidación → Bloquea confirmación"""
        
        # Mock respuesta AI-Service (rechazo)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'success': False,
            'confidence': 35.0,
            'errors': [
                'Descuento excesivo: 55% del bruto (máximo: 40%)',
                'Total líquido negativo: -$200.000'
            ],
            'warnings': [],
            'recommendation': 'reject'
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
        })
        
        payslip.compute_sheet()
        payslip.write({'state': 'verify'})
        
        # Intentar confirmar → Debe lanzar UserError
        with self.assertRaises(UserError) as cm:
            payslip.action_done()
        
        # Verificar mensaje error contiene errores IA
        error_msg = str(cm.exception)
        self.assertIn('Descuento excesivo', error_msg)
        self.assertIn('Total líquido negativo', error_msg)
        
        # Verificar estado
        self.assertEqual(payslip.ai_validation_status, 'rejected')
        self.assertEqual(payslip.state, 'verify', "No debe confirmar si IA rechaza")
    
    @patch('requests.post')
    def test_ai_validation_review_shows_wizard(self, mock_post):
        """Test: IA recomienda review con confianza <70% → Muestra wizard"""
        
        # Mock respuesta AI-Service (review)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'success': True,
            'confidence': 65.0,
            'errors': [],
            'warnings': [
                'Salario 20% sobre media para cargo',
                'Descuento AFP ligeramente alto'
            ],
            'recommendation': 'review'
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
        })
        
        payslip.compute_sheet()
        payslip.write({'state': 'verify'})
        
        # Intentar confirmar → Debe retornar wizard
        result = payslip.action_done()
        
        # Assertions
        self.assertIsInstance(result, dict, "Debe retornar action dict")
        self.assertEqual(result.get('res_model'), 'payroll.ai.validation.wizard')
        self.assertEqual(result.get('target'), 'new')
        self.assertEqual(payslip.ai_validation_status, 'review')
        self.assertAlmostEqual(payslip.ai_confidence, 65.0, places=1)
    
    @patch('requests.post')
    def test_ai_validation_disabled(self, mock_post):
        """Test: Validación IA deshabilitada en config"""
        
        # Deshabilitar IA
        self.env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_hr_payroll.ai_validation_enabled',
            'False'
        )
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
        })
        
        payslip.compute_sheet()
        
        # Validar con IA
        result = payslip.validate_with_ai()
        
        # Assertions
        self.assertEqual(payslip.ai_validation_status, 'disabled')
        self.assertEqual(payslip.ai_confidence, 0.0)
        self.assertFalse(mock_post.called, "No debe llamar AI-Service si está deshabilitado")
        
        # Re-habilitar IA
        self.env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_hr_payroll.ai_validation_enabled',
            'True'
        )
    
    @patch('requests.post')
    def test_ai_validation_graceful_degradation(self, mock_post):
        """Test: AI-Service no disponible → Graceful degradation"""
        
        # Mock error de conexión
        mock_post.side_effect = Exception("Connection refused")
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
        })
        
        payslip.compute_sheet()
        
        # Validar con IA
        result = payslip.validate_with_ai()
        
        # Assertions
        self.assertFalse(result['success'], "Debe reportar fallo")
        self.assertEqual(result['recommendation'], 'review')
        self.assertEqual(payslip.ai_validation_status, 'pending')
        self.assertIn('Connection refused', payslip.ai_warnings or '')
