# -*- coding: utf-8 -*-
from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


@tagged('post_install', '-at_install', 'dte_scope')
class TestDTEScopeB2B(TransactionCase):
    """
    Test DTE types are limited to EERGYGROUP B2B scope.

    Contract scope: 33, 34, 52, 56, 61 only
    Excluded: 39, 41, 46, 70 (out of B2B scope)
    """

    def setUp(self):
        super().setUp()
        self.DteInbox = self.env['dte.inbox']

    def test_valid_dte_types_b2b(self):
        """Valid B2B DTE types should be allowed."""
        valid_types = ['33', '34', '52', '56', '61']

        for dte_type in valid_types:
            with self.subTest(dte_type=dte_type):
                record = self.DteInbox.create({
                    'dte_type': dte_type,
                    'folio': '12345',
                    'emisor_rut': '76123456-7',
                    'emisor_name': 'Test Supplier',
                    'fecha_emision': '2025-11-01',
                    'monto_total': 100000,
                    'monto_neto': 84034,
                    'monto_iva': 15966,
                    'raw_xml': '<test>mock xml</test>',
                })
                self.assertEqual(record.dte_type, dte_type)

    def test_invalid_dte_types_excluded(self):
        """Out-of-scope DTE types (39,41,46,70) should be rejected."""
        invalid_types = ['39', '41', '46', '70']

        for dte_type in invalid_types:
            with self.subTest(dte_type=dte_type):
                with self.assertRaises(ValidationError):
                    self.DteInbox.create({
                        'dte_type': dte_type,
                        'folio': '12345',
                        'emisor_rut': '76123456-7',
                        'emisor_name': 'Test Supplier',
                        'fecha_emision': '2025-11-01',
                        'monto_total': 100000,
                        'monto_neto': 84034,
                        'monto_iva': 15966,
                        'raw_xml': '<test>mock xml</test>',
                    })

    def test_dte_structure_validator_scope(self):
        """DTE_TYPES_VALID constant should only include B2B types."""
        from addons.localization.l10n_cl_dte.libs.dte_structure_validator import DTEStructureValidator

        expected = ['33', '34', '52', '56', '61']
        self.assertEqual(set(DTEStructureValidator.DTE_TYPES_VALID), set(expected),
                         "DTE_TYPES_VALID must match EERGYGROUP B2B scope")

        # Ensure excluded types are NOT present
        excluded = ['39', '41', '46', '70']
        for dte_type in excluded:
            self.assertNotIn(dte_type, DTEStructureValidator.DTE_TYPES_VALID,
                             f"DTE type {dte_type} should be excluded (out of B2B scope)")
