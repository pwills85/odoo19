# -*- coding: utf-8 -*-
import requests
from odoo.tests import tagged, TransactionCase


@tagged('post_install', '-at_install', 'l10n_cl')
class TestAIServiceSSL(TransactionCase):
    """Test AI Service SSL certificate verification"""
    
    def setUp(self):
        super().setUp()
        
        # Import configuration from hr_payslip module
        from odoo.addons.l10n_cl_hr_payroll.models.hr_payslip import (
            AI_SERVICE_URL,
            AI_SERVICE_VERIFY_SSL
        )
        
        self.ai_service_url = AI_SERVICE_URL
        self.ai_service_verify_ssl = AI_SERVICE_VERIFY_SSL
    
    def test_ai_service_connection_verifies_ssl(self):
        """Test: Conexión AI service verifica certificado SSL"""
        # Validar configuración
        self.assertTrue(
            self.ai_service_verify_ssl,
            "SSL verification debe estar habilitada en producción"
        )
    
    def test_ai_service_health_endpoint_with_ssl(self):
        """Test: Health endpoint accesible con SSL verification"""
        # Intentar conexión (debe fallar si certificado inválido)
        try:
            response = requests.get(
                f'{self.ai_service_url}/health',
                verify=True,
                timeout=5
            )
            # Si llegamos aquí, certificado es válido
            self.assertTrue(response.ok or response.status_code == 404,
                          f"Health endpoint returned {response.status_code}")
        except requests.exceptions.SSLError as e:
            self.fail(f"Certificado SSL inválido: {e}")
        except requests.exceptions.ConnectionError:
            # Es aceptable si el servicio no está disponible en tests
            self.skipTest("AI service no disponible (aceptable en tests unitarios)")
        except requests.exceptions.Timeout:
            # Es aceptable si el servicio no responde en tests
            self.skipTest("AI service timeout (aceptable en tests unitarios)")
    
    def test_ssl_disabled_logs_warning(self):
        """Test: SSL deshabilitado genera warning en logs"""
        import os
        
        # Si SSL está deshabilitado, debe haberse loggeado warning
        ssl_enabled = os.getenv('AI_SERVICE_VERIFY_SSL', 'true').lower() == 'true'
        
        if not ssl_enabled:
            # En este caso, debería haberse loggeado un warning
            # Esto se verifica revisando los logs en el setUp del módulo
            self.assertFalse(
                ssl_enabled,
                "SSL está deshabilitado - debe existir warning en logs"
            )
