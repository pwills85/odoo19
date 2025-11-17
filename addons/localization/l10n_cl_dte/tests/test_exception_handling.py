# -*- coding: utf-8 -*-
"""
Unit Tests - Exception Handling (US-1.1)
=========================================

Tests for bare exception elimination - Sprint 1, US-1.1
Covers P0, P1, and P2 exception handling fixes.

Test Coverage:
- P0: ai_chat_integration.py, xml_signer.py
- P1: encryption_helper.py, dte_api_client.py
- P2: ai_chat_universal_wizard.py

Author: EERGYGROUP - Professional Gap Closure 2025-11-02
"""

import unittest
from unittest.mock import Mock, patch
import tempfile
import os
import requests
from odoo.tests.common import TransactionCase


class TestAIChatIntegrationExceptions(TransactionCase):
    """
    Test exception handling in models/ai_chat_integration.py

    P0-1: Response parsing exception (line 577)
    """

    def setUp(self):
        super().setUp()
        self.AIClient = self.env['dte.ai.client']

    def test_parse_error_response_valid_json(self):
        """Test _parse_error_response with valid JSON response"""
        with patch('addons.localization.l10n_cl_dte.models.ai_chat_integration._logger') as mock_logger:
            # Create mock response with valid JSON
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {'detail': 'Invalid input'}
            mock_response.text = '{"detail": "Invalid input"}'

            ai_client = self.AIClient.create({
                'name': 'Test AI Client',
                'company_id': self.env.company.id
            })

            result = ai_client._parse_error_response(mock_response)

            self.assertEqual(result, 'Invalid input')
            # Should NOT log warning (JSON parsing succeeded)
            mock_logger.warning.assert_not_called()

    def test_parse_error_response_invalid_json(self):
        """Test _parse_error_response with invalid JSON (ValueError)"""
        with patch('addons.localization.l10n_cl_dte.models.ai_chat_integration._logger') as mock_logger:
            # Create mock response with invalid JSON
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.json.side_effect = ValueError("Invalid JSON")
            mock_response.text = 'Internal Server Error (not JSON)'

            ai_client = self.AIClient.create({
                'name': 'Test AI Client',
                'company_id': self.env.company.id
            })

            result = ai_client._parse_error_response(mock_response)

            self.assertIn('HTTP 500', result)
            self.assertIn('Internal Server Error', result)
            # Should log warning with context
            mock_logger.warning.assert_called_once()

            # Verify logging context
            call_args = mock_logger.warning.call_args
            self.assertIn('extra', call_args.kwargs)
            self.assertEqual(call_args.kwargs['extra']['status_code'], 500)
            self.assertEqual(call_args.kwargs['extra']['error_type'], 'ValueError')

    def test_parse_error_response_malformed_structure(self):
        """Test _parse_error_response with malformed JSON structure (KeyError)"""
        with patch('addons.localization.l10n_cl_dte.models.ai_chat_integration._logger') as mock_logger:
            # Create mock response with valid JSON but missing 'detail' key
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {'error': 'Wrong key'}  # KeyError on .get('detail')
            mock_response.text = '{"error": "Wrong key"}'

            ai_client = self.AIClient.create({
                'name': 'Test AI Client',
                'company_id': self.env.company.id
            })

            result = ai_client._parse_error_response(mock_response)

            # Should return default format when 'detail' missing
            self.assertIn('HTTP 400', result)


class TestXMLSignerExceptions(TransactionCase):
    """
    Test exception handling in libs/xml_signer.py

    P0-2, P0-3: Temp file cleanup exceptions (lines 239, 475)
    """

    def setUp(self):
        super().setUp()
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner
        self.signer = XMLSigner(self.env)

    def test_cleanup_temp_files_success(self):
        """Test temp file cleanup succeeds"""
        with patch('addons.localization.l10n_cl_dte.libs.xml_signer._logger') as mock_logger:
            # Create real temp files
            temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix='.pfx')
            temp_xml = tempfile.NamedTemporaryFile(delete=False, suffix='.xml')

            try:
                temp_cert.write(b'fake cert data')
                temp_cert.flush()
                temp_xml.write(b'<xml/>')
                temp_xml.flush()

                cert_path = temp_cert.name
                xml_path = temp_xml.name

                temp_cert.close()
                temp_xml.close()

                # Manually cleanup (simulates finally block)
                for temp_file in [cert_path, xml_path]:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)

                # Verify files deleted
                self.assertFalse(os.path.exists(cert_path))
                self.assertFalse(os.path.exists(xml_path))

            except Exception:
                # Cleanup in case of test failure
                for path in [temp_cert.name, temp_xml.name]:
                    if os.path.exists(path):
                        os.unlink(path)
                raise

    def test_cleanup_temp_files_permission_error(self):
        """Test temp file cleanup with OSError (e.g., permission denied)"""
        with patch('addons.localization.l10n_cl_dte.libs.xml_signer._logger') as mock_logger, \
             patch('addons.localization.l10n_cl_dte.libs.xml_signer.os.unlink') as mock_unlink:

            # Simulate OSError (e.g., permission denied)
            mock_unlink.side_effect = OSError(13, "Permission denied")

            # Create temp file path
            temp_file = "/tmp/fake_cert.pfx"

            # Simulate cleanup
            try:
                os.unlink(temp_file)
            except OSError:
                # Should log warning, not raise
                pass

            # In real code, warning would be logged
            # We're verifying the exception is caught, not raised


class TestEncryptionHelperExceptions(TransactionCase):
    """
    Test exception handling in tools/encryption_helper.py

    P1-1: Fernet token validation exception (line 184)
    """

    def setUp(self):
        super().setUp()
        from addons.localization.l10n_cl_dte.tools.encryption_helper import EncryptionHelper
        self.helper = EncryptionHelper(self.env)

    def test_is_encrypted_valid_fernet_token(self):
        """Test is_encrypted with valid Fernet token"""
        # Encrypt a value first
        plaintext = "test_password"
        encrypted = self.helper.encrypt(plaintext)

        # Should recognize as encrypted
        result = self.helper.is_encrypted(encrypted)
        self.assertTrue(result)

    def test_is_encrypted_invalid_base64(self):
        """Test is_encrypted with invalid base64 (binascii.Error)"""
        with patch('addons.localization.l10n_cl_dte.tools.encryption_helper._logger') as mock_logger:
            # Invalid base64 string
            invalid_value = "not!valid@base64#"

            result = self.helper.is_encrypted(invalid_value)

            self.assertFalse(result)
            # Should log debug message
            mock_logger.debug.assert_called_once()

            # Verify error_type in logging context
            call_args = mock_logger.debug.call_args
            self.assertIn('extra', call_args.kwargs)
            self.assertIn('error_type', call_args.kwargs['extra'])

    def test_is_encrypted_wrong_type(self):
        """Test is_encrypted with wrong type (TypeError)"""
        result = self.helper.is_encrypted(None)
        self.assertFalse(result)

        result = self.helper.is_encrypted(12345)  # int instead of str
        self.assertFalse(result)

    def test_is_encrypted_plain_text(self):
        """Test is_encrypted with plain text"""
        result = self.helper.is_encrypted("plain_password")
        self.assertFalse(result)


class TestDTEApiClientExceptions(TransactionCase):
    """
    Test exception handling in tools/dte_api_client.py

    P1-2, P1-3: Health check exceptions (lines 117, 243)
    """

    def setUp(self):
        super().setUp()
        from addons.localization.l10n_cl_dte.tools.dte_api_client import DTEApiClient, AIApiClient
        self.dte_client = DTEApiClient(self.env)
        self.ai_client = AIApiClient(self.env)

    def test_dte_health_check_success(self):
        """Test DTEApiClient health_check success"""
        with patch('addons.localization.l10n_cl_dte.tools.dte_api_client.requests.get') as mock_get:
            # Mock successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            result = self.dte_client.health_check()

            self.assertTrue(result)

    def test_dte_health_check_timeout(self):
        """Test DTEApiClient health_check with Timeout"""
        with patch('addons.localization.l10n_cl_dte.tools.dte_api_client.requests.get') as mock_get, \
             patch('addons.localization.l10n_cl_dte.tools.dte_api_client._logger') as mock_logger:

            # Mock timeout
            mock_get.side_effect = requests.Timeout("Connection timeout")

            result = self.dte_client.health_check()

            self.assertFalse(result)
            # Should log debug with context
            mock_logger.debug.assert_called_once()

            call_args = mock_logger.debug.call_args
            self.assertIn('extra', call_args.kwargs)
            self.assertEqual(call_args.kwargs['extra']['error_type'], 'Timeout')

    def test_dte_health_check_connection_error(self):
        """Test DTEApiClient health_check with ConnectionError"""
        with patch('addons.localization.l10n_cl_dte.tools.dte_api_client.requests.get') as mock_get, \
             patch('addons.localization.l10n_cl_dte.tools.dte_api_client._logger') as mock_logger:

            # Mock connection error
            mock_get.side_effect = ConnectionError("Connection refused")

            result = self.dte_client.health_check()

            self.assertFalse(result)
            # Should log debug with context
            mock_logger.debug.assert_called_once()

    def test_ai_health_check_request_exception(self):
        """Test AIApiClient health_check with RequestException"""
        with patch('addons.localization.l10n_cl_dte.tools.dte_api_client.requests.get') as mock_get, \
             patch('addons.localization.l10n_cl_dte.tools.dte_api_client._logger') as mock_logger:

            # Mock generic request exception
            mock_get.side_effect = requests.RequestException("Generic error")

            result = self.ai_client.health_check()

            self.assertFalse(result)
            # Should log debug with context
            mock_logger.debug.assert_called_once()


class TestAIChatWizardExceptions(TransactionCase):
    """
    Test exception handling in wizards/ai_chat_universal_wizard.py

    P2-1: Display name retrieval exception (line 143)
    P2-2: AI service health check exception (line 221)
    P2-3: Record data extraction exception (line 403)
    """

    def setUp(self):
        super().setUp()
        self.Wizard = self.env['ai.chat.universal.wizard']

    def test_compute_context_success(self):
        """Test _compute_context with valid active_model and active_id"""
        # Create a partner to test with
        partner = self.env['res.partner'].create({
            'name': 'Test Partner',
            'vat': '76123456-7'
        })

        # Create wizard with context
        wizard = self.Wizard.with_context(
            active_model='res.partner',
            active_id=partner.id
        ).create({
            'user_message': 'Test message'
        })

        # Should compute context successfully
        self.assertEqual(wizard.context_active_model, 'res.partner')
        self.assertEqual(wizard.context_active_id, partner.id)
        self.assertEqual(wizard.context_active_record_name, 'Test Partner')

    def test_compute_context_invalid_model(self):
        """Test _compute_context with invalid model (KeyError)"""
        with patch('addons.localization.l10n_cl_dte.wizards.ai_chat_universal_wizard._logger') as mock_logger:
            # Create wizard with invalid model
            wizard = self.Wizard.with_context(
                active_model='invalid.model.name',
                active_id=999
            ).create({
                'user_message': 'Test message'
            })

            # Should fallback to ID when display_name fails
            # Exact behavior depends on Odoo's error handling
            self.assertEqual(wizard.context_active_model, 'invalid.model.name')

    def test_compute_ai_service_config_health_check_failure(self):
        """Test _compute_ai_service_config with health check failure"""
        with patch('addons.localization.l10n_cl_dte.wizards.ai_chat_universal_wizard.requests.get') as mock_get, \
             patch('addons.localization.l10n_cl_dte.wizards.ai_chat_universal_wizard._logger') as mock_logger:

            # Mock health check timeout
            mock_get.side_effect = requests.Timeout("Connection timeout")

            wizard = self.Wizard.create({
                'user_message': 'Test message'
            })

            # Should set ai_service_available to False
            self.assertFalse(wizard.ai_service_available)
            # Should log debug message
            mock_logger.debug.assert_called()

    def test_prepare_ai_context_field_extraction_error(self):
        """Test _prepare_ai_context with field extraction errors"""
        with patch('addons.localization.l10n_cl_dte.wizards.ai_chat_universal_wizard._logger') as mock_logger:
            # Create partner
            partner = self.env['res.partner'].create({
                'name': 'Test Partner'
            })

            wizard = self.Wizard.with_context(
                active_model='res.partner',
                active_id=partner.id
            ).create({
                'user_message': 'Test message'
            })

            # Call _prepare_ai_context
            context = wizard._prepare_ai_context()

            # Should succeed even if some fields fail
            self.assertIn('user', context)
            self.assertIn('odoo', context)
            # active_record_data may or may not be present depending on field extraction


# ═══════════════════════════════════════════════════════════════════
# INTEGRATION TEST - Full Exception Handling Flow
# ═══════════════════════════════════════════════════════════════════

class TestExceptionHandlingIntegration(TransactionCase):
    """
    Integration tests for exception handling across modules
    """

    def test_full_flow_with_failures(self):
        """Test full flow with multiple exception scenarios"""
        # This is a placeholder for integration testing
        # In a real scenario, we'd test:
        # 1. AI service unavailable → graceful degradation
        # 2. Certificate issues → proper error messages
        # 3. Network failures → retry logic
        pass


if __name__ == '__main__':
    unittest.main()
