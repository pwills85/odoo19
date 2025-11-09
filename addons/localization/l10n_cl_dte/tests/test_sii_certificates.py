# -*- coding: utf-8 -*-
"""
Tests for SII Certificate Management (Multi-Environment)
=========================================================

Valida la carga dinámica de certificados SII según environment:
- Staging (Maullin): Ambiente de certificación y testing
- Production (Palena): Ambiente de producción real

Sprint: H10 (P1 High Priority) - Official SII Certificate Management
Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-09
"""

from odoo.tests.common import TransactionCase
from pathlib import Path
import os


class TestSIICertificates(TransactionCase):
    """Test suite for SII certificate loading and validation"""

    def setUp(self):
        super().setUp()
        self.config_param = self.env['ir.config_parameter'].sudo()

        # Import validator module
        from odoo.addons.l10n_cl_dte.libs import caf_signature_validator
        self.validator_module = caf_signature_validator

    def test_01_certificate_path_detection_staging(self):
        """Test certificate path detection for staging environment (Maullin)"""
        # Set staging environment
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'sandbox')

        # Get environment detection
        environment = self.validator_module._get_sii_environment_from_odoo()

        # Assert: staging detected
        self.assertEqual(environment, 'staging', "Environment should be 'staging' for sandbox")

    def test_02_certificate_path_detection_production(self):
        """Test certificate path detection for production environment (Palena)"""
        # Set production environment
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'production')

        # Get environment detection
        environment = self.validator_module._get_sii_environment_from_odoo()

        # Assert: production detected
        self.assertEqual(environment, 'production', "Environment should be 'production'")

    def test_03_certificate_path_mapping_testing(self):
        """Test environment mapping: 'testing' -> staging"""
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'testing')
        environment = self.validator_module._get_sii_environment_from_odoo()
        self.assertEqual(environment, 'staging', "Testing should map to staging")

    def test_04_certificate_path_mapping_certification(self):
        """Test environment mapping: 'certification' -> staging"""
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'certification')
        environment = self.validator_module._get_sii_environment_from_odoo()
        self.assertEqual(environment, 'staging', "Certification should map to staging")

    def test_05_certificate_file_not_found_error_staging(self):
        """Test error when certificate file missing for staging"""
        # Set staging environment
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'sandbox')

        # Verify certificate path
        cert_path = Path(__file__).parent.parent / 'data' / 'certificates' / 'staging' / 'sii_cert_maullin.pem'

        if not cert_path.exists():
            # Assert: FileNotFoundError raised with helpful message
            with self.assertRaises(FileNotFoundError) as context:
                self.validator_module._get_sii_certificate_content()

            # Assert: Error message contains instructions
            error_msg = str(context.exception)
            self.assertIn('CERTIFICADO SII NO ENCONTRADO', error_msg)
            self.assertIn('staging', error_msg)
            self.assertIn('Maullin', error_msg)
            self.assertIn('maullin.sii.cl', error_msg)
            self.assertIn('sii_cert_maullin.pem', error_msg)

    def test_06_certificate_file_not_found_error_production(self):
        """Test error when certificate file missing for production"""
        # Set production environment
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'production')

        # Verify certificate path
        cert_path = Path(__file__).parent.parent / 'data' / 'certificates' / 'production' / 'sii_cert_palena.pem'

        if not cert_path.exists():
            # Assert: FileNotFoundError raised with helpful message
            with self.assertRaises(FileNotFoundError) as context:
                self.validator_module._get_sii_certificate_content()

            # Assert: Error message contains instructions
            error_msg = str(context.exception)
            self.assertIn('CERTIFICADO SII NO ENCONTRADO', error_msg)
            self.assertIn('production', error_msg)
            self.assertIn('Palena', error_msg)
            self.assertIn('palena.sii.cl', error_msg)
            self.assertIn('sii_cert_palena.pem', error_msg)

    def test_07_certificate_loading_staging_if_exists(self):
        """Test certificate loading for staging environment (if file exists)"""
        # Set staging environment
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'testing')

        # Verify certificate path
        cert_path = Path(__file__).parent.parent / 'data' / 'certificates' / 'staging' / 'sii_cert_maullin.pem'

        if cert_path.exists():
            # Load certificate
            cert_content = self.validator_module._get_sii_certificate_content()

            # Assert: Valid PEM format
            self.assertIn('-----BEGIN CERTIFICATE-----', cert_content, "Should be valid PEM certificate")
            self.assertIn('-----END CERTIFICATE-----', cert_content, "Should be valid PEM certificate")
            self.assertGreater(len(cert_content), 100, "Certificate too short")

    def test_08_certificate_loading_production_if_exists(self):
        """Test certificate loading for production environment (if file exists)"""
        # Set production environment
        self.config_param.set_param('l10n_cl_dte.sii_environment', 'production')

        # Verify certificate path
        cert_path = Path(__file__).parent.parent / 'data' / 'certificates' / 'production' / 'sii_cert_palena.pem'

        if cert_path.exists():
            # Load certificate
            cert_content = self.validator_module._get_sii_certificate_content()

            # Assert: Valid PEM format
            self.assertIn('-----BEGIN CERTIFICATE-----', cert_content, "Should be valid PEM certificate")
            self.assertIn('-----END CERTIFICATE-----', cert_content, "Should be valid PEM certificate")
            self.assertGreater(len(cert_content), 100, "Certificate too short")

    def test_09_default_environment_is_sandbox(self):
        """Test default environment is 'sandbox' (Maullin)"""
        # Get default value from config parameter
        default_env = self.config_param.get_param('l10n_cl_dte.sii_environment', 'sandbox')

        # Assert: Default is sandbox
        self.assertEqual(default_env, 'sandbox', "Default environment should be 'sandbox'")

    def test_10_environment_variable_fallback(self):
        """Test environment variable fallback when Odoo config not available"""
        # Set OS environment variable
        original_env = os.getenv('L10N_CL_SII_ENVIRONMENT')

        try:
            # Test staging fallback
            os.environ['L10N_CL_SII_ENVIRONMENT'] = 'staging'
            # Note: This test would need to be run in isolation to truly test fallback
            # In normal operation, Odoo config takes precedence

            # Test production fallback
            os.environ['L10N_CL_SII_ENVIRONMENT'] = 'production'

            # Just verify the function doesn't crash
            environment = self.validator_module._get_sii_environment_from_odoo()
            self.assertIn(environment, ['staging', 'production'], "Environment should be valid")

        finally:
            # Restore original environment
            if original_env:
                os.environ['L10N_CL_SII_ENVIRONMENT'] = original_env
            elif 'L10N_CL_SII_ENVIRONMENT' in os.environ:
                del os.environ['L10N_CL_SII_ENVIRONMENT']

    def test_11_readme_files_exist(self):
        """Test that README files exist with instructions"""
        # Staging README
        staging_readme = Path(__file__).parent.parent / 'data' / 'certificates' / 'staging' / 'README.md'
        self.assertTrue(staging_readme.exists(), "Staging README should exist")

        # Production README
        production_readme = Path(__file__).parent.parent / 'data' / 'certificates' / 'production' / 'README.md'
        self.assertTrue(production_readme.exists(), "Production README should exist")

        # Verify staging README content
        with open(staging_readme, 'r', encoding='utf-8') as f:
            staging_content = f.read()
            self.assertIn('Maullin', staging_content, "Staging README should mention Maullin")
            self.assertIn('maullin.sii.cl', staging_content, "Staging README should have Maullin URL")

        # Verify production README content
        with open(production_readme, 'r', encoding='utf-8') as f:
            production_content = f.read()
            self.assertIn('Palena', production_content, "Production README should mention Palena")
            self.assertIn('palena.sii.cl', production_content, "Production README should have Palena URL")

    def test_12_config_parameters_documentation(self):
        """Test that config parameters are documented"""
        # Check environment description parameter exists
        description = self.config_param.get_param('l10n_cl_dte.sii_environment.description')
        self.assertIsNotNone(description, "Environment description should exist")
        self.assertIn('Maullin', description, "Description should mention Maullin")
        self.assertIn('Palena', description, "Description should mention Palena")

        # Check certificate URL parameters
        maullin_url = self.config_param.get_param('l10n_cl_dte.sii_certificate_maullin_url')
        palena_url = self.config_param.get_param('l10n_cl_dte.sii_certificate_palena_url')

        self.assertIsNotNone(maullin_url, "Maullin URL parameter should exist")
        self.assertIsNotNone(palena_url, "Palena URL parameter should exist")
