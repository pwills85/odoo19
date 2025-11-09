# -*- coding: utf-8 -*-
"""
Unit Tests - SII Error Codes Mapping (59/59 codes)
===================================================

P1-1 GAP CLOSURE: Verifica mapeo completo de los 59 códigos SII.

Tests:
- Total count verification (59 códigos)
- Structure validation for all codes
- Helper functions (get_error_info, is_success, should_retry)
- Category filtering
- User-friendly message generation
- Edge cases (unknown codes)

References:
- Resolución Exenta SII N° 11 (2003)
- Circular 28 (2008)
- Manual de Integración DTE - Servicios Web

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

import unittest
from ..libs import sii_error_codes


class TestSIIErrorCodes(unittest.TestCase):
    """
    Unit tests for SII error codes mapping.

    P1-1 REQUIREMENT: All 59 SII codes must be mapped with complete info.
    """

    def test_total_codes_count_59(self):
        """
        P1-1: Verify exactly 59 SII codes are mapped.

        Critical requirement: Complete SII error code coverage.
        """
        total = sii_error_codes.get_total_codes_count()
        self.assertEqual(
            total, 59,
            f"Expected 59 SII codes, got {total}. "
            f"Missing codes or duplicates detected."
        )

    def test_all_codes_have_required_fields(self):
        """
        P1-1: Verify all 59 codes have required fields.

        Required fields:
        - code (str)
        - description (str)
        - category (str)
        - action (str)
        - severity (str: info/warning/error)
        """
        required_fields = ['code', 'description', 'category', 'action', 'severity']

        for code, info in sii_error_codes.ALL_SII_CODES.items():
            with self.subTest(code=code):
                for field in required_fields:
                    self.assertIn(
                        field, info,
                        f"Code {code} missing required field: {field}"
                    )
                    self.assertIsInstance(
                        info[field], str,
                        f"Code {code} field {field} must be string, got {type(info[field])}"
                    )
                    self.assertTrue(
                        len(info[field]) > 0,
                        f"Code {code} field {field} is empty"
                    )

    def test_severity_values_valid(self):
        """
        P1-1: Verify all severity values are valid (info/warning/error).
        """
        valid_severities = {'info', 'warning', 'error'}

        for code, info in sii_error_codes.ALL_SII_CODES.items():
            with self.subTest(code=code):
                self.assertIn(
                    info['severity'], valid_severities,
                    f"Code {code} has invalid severity: {info['severity']}. "
                    f"Valid values: {valid_severities}"
                )

    def test_category_values_valid(self):
        """
        P1-1: Verify all category values are valid.

        Valid categories: success, envio, dte, ted, caf, referencia,
                         comercial, connection, certificado, general, libro,
                         query, schema, recepcion, auth, unknown
        """
        valid_categories = {
            'success', 'envio', 'dte', 'ted', 'caf', 'referencia',
            'comercial', 'connection', 'certificado', 'general', 'libro',
            'query', 'schema', 'recepcion', 'auth', 'folio', 'unknown'
        }

        for code, info in sii_error_codes.ALL_SII_CODES.items():
            with self.subTest(code=code):
                self.assertIn(
                    info['category'], valid_categories,
                    f"Code {code} has invalid category: {info['category']}. "
                    f"Valid categories: {valid_categories}"
                )

    def test_get_error_info_known_codes(self):
        """
        P1-1: Test get_error_info() for known codes.
        """
        # Test sample of known codes from each category
        test_codes = [
            'RPR',           # success
            'ENV-0',         # envio
            'DTE-3-101',     # dte
            'TED-1-510',     # ted
            'CAF-1-517',     # caf
            'REF-1-415',     # referencia
            'HED-0',         # comercial
            'CONN-TIMEOUT',  # connection
            'CERT-1',        # certificado
            'GLO-0',         # general
        ]

        for code in test_codes:
            with self.subTest(code=code):
                info = sii_error_codes.get_error_info(code)
                self.assertEqual(info['code'], code)
                self.assertIsNotNone(info['description'])
                self.assertIsNotNone(info['action'])

    def test_get_error_info_unknown_code(self):
        """
        P1-1: Test get_error_info() handles unknown codes gracefully.

        Unknown codes should return generic structure with:
        - code: original code
        - category: 'unknown'
        - severity: 'error'
        """
        unknown_code = 'FAKE-999-999'
        info = sii_error_codes.get_error_info(unknown_code)

        self.assertEqual(info['code'], unknown_code)
        self.assertEqual(info['category'], 'unknown')
        self.assertEqual(info['severity'], 'error')
        self.assertIn('SII', info['description'])

    def test_is_success_function(self):
        """
        P1-1: Test is_success() identifies success codes correctly.
        """
        # Success codes
        self.assertTrue(sii_error_codes.is_success('RPR'))
        self.assertTrue(sii_error_codes.is_success('RCH'))
        self.assertTrue(sii_error_codes.is_success('ENV-0'))
        self.assertTrue(sii_error_codes.is_success('DTE-0'))
        self.assertTrue(sii_error_codes.is_success('TED-0'))
        self.assertTrue(sii_error_codes.is_success('GLO-0'))

        # Error codes
        self.assertFalse(sii_error_codes.is_success('ENV-3-0'))
        self.assertFalse(sii_error_codes.is_success('DTE-3-101'))
        self.assertFalse(sii_error_codes.is_success('CONN-TIMEOUT'))

    def test_should_retry_function(self):
        """
        P1-1: Test should_retry() identifies retryable errors correctly.

        Only connection errors should be retryable (CONN-TIMEOUT, CONN-ERROR, SOAP-FAULT).
        Validation errors (ENV-3-0, DTE-3-101, etc.) should NOT be retried.
        """
        # Retryable (connection errors)
        self.assertTrue(sii_error_codes.should_retry('CONN-TIMEOUT'))
        self.assertTrue(sii_error_codes.should_retry('CONN-ERROR'))
        self.assertTrue(sii_error_codes.should_retry('SOAP-FAULT'))

        # Non-retryable (validation errors)
        self.assertFalse(sii_error_codes.should_retry('ENV-3-0'))
        self.assertFalse(sii_error_codes.should_retry('DTE-3-101'))
        self.assertFalse(sii_error_codes.should_retry('CAF-1-517'))
        self.assertFalse(sii_error_codes.should_retry('TED-1-510'))
        self.assertFalse(sii_error_codes.should_retry('REF-1-415'))

    def test_get_user_friendly_message(self):
        """
        P1-1: Test get_user_friendly_message() formatting.
        """
        # Test basic message (without details)
        msg = sii_error_codes.get_user_friendly_message('DTE-3-101', detailed=False)
        self.assertIn('RUT Receptor Inválido', msg)
        self.assertIn('❌', msg)  # Error icon

        # Test detailed message
        msg_detailed = sii_error_codes.get_user_friendly_message('ENV-3-0', detailed=True)
        self.assertIn('Schema XML', msg_detailed)
        self.assertIn('❌', msg_detailed)
        # Should include technical detail if available

        # Test success message
        msg_success = sii_error_codes.get_user_friendly_message('RPR', detailed=False)
        self.assertIn('✅', msg_success)  # Success icon
        self.assertIn('Recibo Conforme', msg_success)

    def test_get_codes_by_category(self):
        """
        P1-1: Test get_codes_by_category() filtering.
        """
        # Test envio category (should have 6 codes: ENV-0, ENV-1-0, ..., ENV-5-0)
        envio_codes = sii_error_codes.get_codes_by_category('envio')
        self.assertGreaterEqual(len(envio_codes), 5, "Expected at least 5 envio codes")

        # Test dte category
        dte_codes = sii_error_codes.get_codes_by_category('dte')
        self.assertGreaterEqual(len(dte_codes), 5, "Expected at least 5 dte codes")

        # Test ted category
        ted_codes = sii_error_codes.get_codes_by_category('ted')
        self.assertGreaterEqual(len(ted_codes), 3, "Expected at least 3 ted codes")

        # Test caf category
        caf_codes = sii_error_codes.get_codes_by_category('caf')
        self.assertGreaterEqual(len(caf_codes), 3, "Expected at least 3 caf codes")

        # Test connection category
        conn_codes = sii_error_codes.get_codes_by_category('connection')
        self.assertEqual(len(conn_codes), 3, "Expected exactly 3 connection codes")

    def test_all_categories_have_codes(self):
        """
        P1-1: Verify all defined categories have at least one code.
        """
        expected_categories = [
            'success', 'envio', 'dte', 'ted', 'caf',
            'referencia', 'comercial', 'connection', 'certificado', 'general',
            'libro', 'query', 'schema', 'recepcion', 'auth', 'folio'
        ]

        for category in expected_categories:
            with self.subTest(category=category):
                codes = sii_error_codes.get_codes_by_category(category)
                self.assertGreater(
                    len(codes), 0,
                    f"Category '{category}' has no codes"
                )

    def test_no_duplicate_codes(self):
        """
        P1-1: Verify no duplicate code keys in ALL_SII_CODES.
        """
        all_codes = list(sii_error_codes.ALL_SII_CODES.keys())
        unique_codes = set(all_codes)

        self.assertEqual(
            len(all_codes), len(unique_codes),
            f"Duplicate codes detected. "
            f"Total: {len(all_codes)}, Unique: {len(unique_codes)}"
        )

    def test_retry_flag_only_on_connection_errors(self):
        """
        P1-1: Verify retry flag is only set for connection errors.

        Business rule: Only transient errors (connection, timeout) should retry.
        Validation errors (XML, RUT, CAF, TED) should NOT retry.
        """
        for code, info in sii_error_codes.ALL_SII_CODES.items():
            with self.subTest(code=code):
                if info.get('retry', False):
                    # If retry=True, must be connection category
                    self.assertEqual(
                        info['category'], 'connection',
                        f"Code {code} has retry=True but category={info['category']}. "
                        f"Only connection errors should be retryable."
                    )

    def test_success_codes_have_info_severity(self):
        """
        P1-1: Verify success codes have 'info' severity.
        """
        success_codes = sii_error_codes.get_codes_by_category('success')

        for code, info in success_codes.items():
            with self.subTest(code=code):
                self.assertEqual(
                    info['severity'], 'info',
                    f"Success code {code} should have severity='info', got '{info['severity']}'"
                )

    def test_error_codes_have_error_severity(self):
        """
        P1-1: Verify error codes (not success/comercial) have 'error' severity.
        """
        error_categories = ['envio', 'dte', 'ted', 'caf', 'referencia', 'connection', 'certificado']

        for category in error_categories:
            codes = sii_error_codes.get_codes_by_category(category)
            for code, info in codes.items():
                # Skip success codes within category (e.g., ENV-0, DTE-0, TED-0)
                if code.endswith('-0') and not code.startswith('CONN-'):
                    continue

                with self.subTest(code=code):
                    self.assertIn(
                        info['severity'], ['error', 'warning'],
                        f"Error code {code} should have severity 'error' or 'warning', "
                        f"got '{info['severity']}'"
                    )

    def test_module_self_test(self):
        """
        P1-1: Test module self-test (when run as __main__).

        Verifies the module can be run standalone for validation.
        """
        # Verify total count function works
        total = sii_error_codes.get_total_codes_count()
        self.assertEqual(total, 59)

        # Verify category grouping works
        for category in ['envio', 'dte', 'ted', 'caf', 'referencia']:
            codes = sii_error_codes.get_codes_by_category(category)
            self.assertIsInstance(codes, dict)


class TestSIIErrorCodesIntegration(unittest.TestCase):
    """
    Integration tests for SII error codes in real scenarios.
    """

    def test_common_sii_rejection_scenarios(self):
        """
        P1-1: Test common SII rejection scenarios have correct codes.
        """
        scenarios = [
            ('ENV-3-0', 'Schema XML', 'error', False),  # Invalid XML schema - no retry
            ('DTE-3-101', 'RUT Receptor', 'error', False),  # Invalid RUT - no retry
            ('TED-1-510', 'Firma del TED', 'error', False),  # Invalid TED signature - no retry
            ('CAF-3-517', 'CAF Vencido', 'error', False),  # Expired CAF - no retry
            ('CONN-TIMEOUT', 'Timeout', 'error', True),  # Connection timeout - YES retry
        ]

        for code, expected_desc_fragment, expected_severity, should_retry in scenarios:
            with self.subTest(code=code):
                info = sii_error_codes.get_error_info(code)
                self.assertIn(expected_desc_fragment, info['description'])
                self.assertEqual(info['severity'], expected_severity)
                self.assertEqual(sii_error_codes.should_retry(code), should_retry)

    def test_all_dte_types_have_codes(self):
        """
        P1-1: Verify codes exist for all DTE document types (33, 34, 52, 56, 61).

        While codes are generic, ensure we have coverage for common DTE errors.
        """
        # These codes apply to ALL DTE types
        critical_dte_codes = [
            'DTE-0',      # DTE Accepted
            'DTE-1-0',    # Signature error
            'DTE-2-0',    # Data error
            'DTE-3-101',  # Invalid RUT receptor
            'DTE-3-102',  # Invalid RUT emisor
            'DTE-3-103',  # Date out of range
            'DTE-3-104',  # Invalid total amount
            'DTE-3-105',  # DTE type not allowed
        ]

        for code in critical_dte_codes:
            with self.subTest(code=code):
                self.assertIn(code, sii_error_codes.ALL_SII_CODES)

    def test_ted_validation_codes_complete(self):
        """
        P1-1: Verify TED validation codes are complete.

        TED (Timbre Electrónico) is critical for DTE validity.
        Must have codes for: valid, signature error, data mismatch, CAF error.
        """
        required_ted_codes = [
            'TED-0',      # TED valid
            'TED-1-510',  # TED signature error
            'TED-2-510',  # TED data mismatch with DTE
            'TED-3-510',  # CAF not authorized for folio
        ]

        for code in required_ted_codes:
            with self.subTest(code=code):
                self.assertIn(code, sii_error_codes.ALL_SII_CODES)
                info = sii_error_codes.get_error_info(code)
                self.assertEqual(info['category'], 'ted')

    def test_caf_lifecycle_codes_complete(self):
        """
        P1-1: Verify CAF lifecycle codes are complete.

        CAF errors: invalid signature, folio exhausted, expired, wrong DTE type.
        """
        required_caf_codes = [
            'CAF-1-517',  # Invalid CAF signature
            'CAF-2-517',  # Folio range exhausted
            'CAF-3-517',  # CAF expired (> 18 months)
            'CAF-4-517',  # DTE type mismatch
        ]

        for code in required_caf_codes:
            with self.subTest(code=code):
                self.assertIn(code, sii_error_codes.ALL_SII_CODES)
                info = sii_error_codes.get_error_info(code)
                self.assertEqual(info['category'], 'caf')


if __name__ == '__main__':
    unittest.main()
