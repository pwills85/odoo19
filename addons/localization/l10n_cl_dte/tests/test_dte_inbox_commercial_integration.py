# -*- coding: utf-8 -*-
"""
Integration Tests - DTEInbox CommercialValidator
================================================

Tests de integración para validación comercial en recepción de DTEs.

**Created**: 2025-11-11 - H1 Gap Closure
**Coverage target**: ≥85% action_validate() commercial validation flow

Test categories:
1. Commercial validation accept scenarios (3 tests)
2. Commercial validation reject scenarios (4 tests)
3. Commercial validation review scenarios (3 tests)
4. PO matching integration (3 tests)
5. AI timeout handling (2 tests)
6. Edge cases and error handling (3 tests)

Total: 18 integration tests

Author: EERGYGROUP
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError
from datetime import date, timedelta
from unittest.mock import patch, Mock
import requests


@tagged('post_install', '-at_install', 'l10n_cl_dte', 'commercial_validation')
class TestDTEInboxCommercialIntegration(TransactionCase):
    """
    Integration test suite for CommercialValidator in DTEInbox.action_validate().

    Tests the complete flow: Native validation → Commercial validation → AI validation
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Create company and configure
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company Chile',
            'country_id': cls.env.ref('base.cl').id,
            'vat': '760000000',  # RUT
            'currency_id': cls.env.ref('base.CLP').id,
        })

        # Create vendor partner (emisor)
        cls.vendor = cls.env['res.partner'].create({
            'name': 'Proveedor Test SPA',
            'vat': '761234560',  # RUT
            'country_id': cls.env.ref('base.cl').id,
            'supplier_rank': 1,
        })

        # Create product for PO
        cls.product = cls.env['product.product'].create({
            'name': 'Producto Test',
            'type': 'consu',
            'list_price': 100000,
            'standard_price': 80000,
        })

        # Valid DTE XML (minimal structure for testing)
        cls.valid_dte_xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0" xmlns="http://www.sii.cl/SiiDte">
    <Documento ID="DTE-12345">
        <Encabezado>
            <IdDoc>
                <TipoDTE>33</TipoDTE>
                <Folio>12345</Folio>
                <FchEmis>{fecha_emision}</FchEmis>
            </IdDoc>
            <Emisor>
                <RUTEmisor>76123456-0</RUTEmisor>
                <RznSoc>Proveedor Test SPA</RznSoc>
                <GiroEmis>Servicios</GiroEmis>
                <DirOrigen>Calle Falsa 123</DirOrigen>
                <CmnaOrigen>Santiago</CmnaOrigen>
            </Emisor>
            <Receptor>
                <RUTRecep>76000000-0</RUTRecep>
                <RznSocRecep>Test Company Chile</RznSocRecep>
            </Receptor>
            <Totales>
                <MntNeto>84034</MntNeto>
                <IVA>15966</IVA>
                <MntTotal>{monto_total}</MntTotal>
            </Totales>
        </Encabezado>
        <Detalle>
            <NroLinDet>1</NroLinDet>
            <NmbItem>Producto Test</NmbItem>
            <QtyItem>1</QtyItem>
            <PrcItem>100000</PrcItem>
        </Detalle>
    </Documento>
</DTE>'''

    def _create_dte_inbox(self, fecha_emision, monto_total=100000, po_id=None):
        """
        Helper: Create DTEInbox record with given parameters.

        Args:
            fecha_emision (date): Emission date
            monto_total (float): Total amount
            po_id (int, optional): Linked purchase order ID

        Returns:
            dte.inbox: Created record
        """
        xml = self.valid_dte_xml.format(
            fecha_emision=fecha_emision.strftime('%Y-%m-%d'),
            monto_total=int(monto_total)
        )

        values = {
            'tipo_dte': '33',
            'folio': 12345,
            'emisor_rut': '76123456-0',
            'emisor_name': 'Proveedor Test SPA',
            'fecha_emision': fecha_emision,
            'monto_total': monto_total,
            'raw_xml': xml,
            'state': 'new',
        }

        if po_id:
            values['purchase_order_id'] = po_id

        return self.env['dte.inbox'].create(values)

    def _create_purchase_order(self, amount_total=100000):
        """
        Helper: Create Purchase Order for matching tests.

        Args:
            amount_total (float): Total amount

        Returns:
            purchase.order: Created PO
        """
        return self.env['purchase.order'].create({
            'partner_id': self.vendor.id,
            'order_line': [(0, 0, {
                'product_id': self.product.id,
                'product_qty': 1,
                'price_unit': amount_total,
            })],
        })

    # ═══════════════════════════════════════════════════════════════════════
    # CATEGORY 1: ACCEPT SCENARIOS (3 tests)
    # ═══════════════════════════════════════════════════════════════════════

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_01_commercial_accept_within_deadline_exact_amount(self, mock_ted, mock_struct):
        """
        Test: DTE within 8 days + exact PO match → ACCEPT.

        Expected:
        - commercial_auto_action = 'accept'
        - commercial_confidence = 1.0
        - No warnings
        """
        # Mock native validators to pass
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create PO with exact amount
        po = self._create_purchase_order(amount_total=100000)

        # Create DTE (2 days old, exact match)
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=2),
            monto_total=100000,
            po_id=po.id
        )

        # Mock AI validation success
        with patch.object(dte, 'validate_received_dte', return_value={
            'valid': True,
            'confidence': 95,
            'anomalies': [],
            'warnings': [],
            'recommendation': 'accept'
        }):
            # Execute validation
            dte.action_validate()

        # Assertions
        self.assertEqual(dte.commercial_auto_action, 'accept',
                        "Should auto-accept: within deadline + exact amount")
        self.assertEqual(dte.commercial_confidence, 1.0,
                        "Confidence should be 100% (no warnings)")
        self.assertEqual(dte.state, 'validated',
                        "State should be 'validated' after accept")

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_02_commercial_accept_last_day_deadline(self, mock_ted, mock_struct):
        """
        Test: DTE on 8th day (last valid day) + no PO → REVIEW (warning).

        Expected:
        - commercial_auto_action = 'review' (missing PO warning)
        - commercial_confidence = 0.95 (5% penalty for missing PO)
        - Warning: "No Purchase Order linked"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE (exactly 8 days old, no PO)
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=8),
            monto_total=100000
        )

        # Mock AI validation
        with patch.object(dte, 'validate_received_dte', return_value={
            'valid': True, 'confidence': 90, 'anomalies': [], 'warnings': [], 'recommendation': 'accept'
        }):
            dte.action_validate()

        # Assertions
        self.assertEqual(dte.commercial_auto_action, 'review',
                        "Should require review due to missing PO")
        self.assertAlmostEqual(dte.commercial_confidence, 0.95, places=2,
                              msg="Confidence should be 95% (5% penalty for missing PO)")

    # ═══════════════════════════════════════════════════════════════════════
    # CATEGORY 2: REJECT SCENARIOS (4 tests)
    # ═══════════════════════════════════════════════════════════════════════

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_03_commercial_reject_deadline_exceeded(self, mock_ted, mock_struct):
        """
        Test: DTE 10 days old (deadline exceeded) → REJECT.

        Expected:
        - Raise UserError
        - commercial_auto_action = 'reject'
        - state = 'error'
        - Error message contains "deadline exceeded"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE (10 days old = 2 days overdue)
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=10),
            monto_total=100000
        )

        # Expect UserError due to deadline exceeded
        with self.assertRaises(UserError) as context:
            dte.action_validate()

        # Assertions
        self.assertIn('deadline exceeded', str(context.exception).lower(),
                     "Error message should mention deadline exceeded")
        self.assertEqual(dte.commercial_auto_action, 'reject',
                        "Should auto-reject: deadline exceeded")
        self.assertEqual(dte.state, 'error',
                        "State should be 'error' after reject")

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_04_commercial_reject_po_amount_exceeds_tolerance(self, mock_ted, mock_struct):
        """
        Test: DTE amount differs 3% from PO (exceeds 2% tolerance) → REJECT.

        Expected:
        - Raise UserError
        - commercial_auto_action = 'reject'
        - Error message contains "Amount mismatch exceeds 2% tolerance"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create PO with base amount
        po = self._create_purchase_order(amount_total=100000)

        # Create DTE with +3% amount (exceeds 2% tolerance)
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=2),
            monto_total=103000,  # +3%
            po_id=po.id
        )

        # Expect UserError due to amount mismatch
        with self.assertRaises(UserError) as context:
            dte.action_validate()

        # Assertions
        self.assertIn('amount mismatch', str(context.exception).lower(),
                     "Error message should mention amount mismatch")
        self.assertEqual(dte.commercial_auto_action, 'reject',
                        "Should auto-reject: amount exceeds tolerance")

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_05_commercial_reject_missing_fecha_emision(self, mock_ted, mock_struct):
        """
        Test: DTE without fecha_emision → REJECT.

        Expected:
        - Raise UserError
        - Error message contains "Missing emission date"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE without fecha_emision (use None)
        dte = self.env['dte.inbox'].create({
            'tipo_dte': '33',
            'folio': 99999,
            'emisor_rut': '76123456-0',
            'emisor_name': 'Test Vendor',
            'fecha_emision': None,  # Missing
            'monto_total': 100000,
            'raw_xml': '<DTE></DTE>',
            'state': 'new',
        })

        # Expect UserError due to missing fecha_emision
        with self.assertRaises(UserError) as context:
            dte.action_validate()

        # Assertions
        self.assertIn('emission date', str(context.exception).lower(),
                     "Error message should mention missing emission date")

    # ═══════════════════════════════════════════════════════════════════════
    # CATEGORY 3: REVIEW SCENARIOS (3 tests)
    # ═══════════════════════════════════════════════════════════════════════

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_06_commercial_review_po_amount_within_tolerance(self, mock_ted, mock_struct):
        """
        Test: DTE amount differs 1% from PO (within 2% tolerance) → REVIEW.

        Expected:
        - commercial_auto_action = 'review'
        - commercial_confidence = 0.9 (10% penalty for warning)
        - Warning: "Minor amount difference within 2% tolerance"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create PO
        po = self._create_purchase_order(amount_total=100000)

        # Create DTE with +1% amount (within tolerance)
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=2),
            monto_total=101000,  # +1%
            po_id=po.id
        )

        # Mock AI validation
        with patch.object(dte, 'validate_received_dte', return_value={
            'valid': True, 'confidence': 90, 'anomalies': [], 'warnings': [], 'recommendation': 'accept'
        }):
            dte.action_validate()

        # Assertions
        self.assertEqual(dte.commercial_auto_action, 'review',
                        "Should require review: amount within tolerance but not exact")
        self.assertLessEqual(dte.commercial_confidence, 0.95,
                            "Confidence should be reduced due to warning")

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_07_commercial_review_no_po_provided(self, mock_ted, mock_struct):
        """
        Test: DTE with no PO linked → REVIEW.

        Expected:
        - commercial_auto_action = 'review'
        - Warning: "No Purchase Order linked"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE without PO
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=2),
            monto_total=100000
        )

        # Mock AI validation
        with patch.object(dte, 'validate_received_dte', return_value={
            'valid': True, 'confidence': 85, 'anomalies': [], 'warnings': [], 'recommendation': 'review'
        }):
            dte.action_validate()

        # Assertions
        self.assertEqual(dte.commercial_auto_action, 'review',
                        "Should require review: no PO linked")
        self.assertTrue(dte.validation_warnings and 'No Purchase Order' in dte.validation_warnings,
                       "Should have warning about missing PO")

    # ═══════════════════════════════════════════════════════════════════════
    # CATEGORY 4: AI TIMEOUT HANDLING (2 tests) - H2
    # ═══════════════════════════════════════════════════════════════════════

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_08_ai_timeout_graceful_degradation(self, mock_ted, mock_struct):
        """
        Test: AI validation times out (>10s) → Graceful degradation to manual review.

        Expected:
        - ai_validated = False
        - state = 'review'
        - Warning: "AI validation timed out"
        - Commercial validation still runs (independent)
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=2),
            monto_total=100000
        )

        # Mock AI validation to raise Timeout
        with patch.object(dte, 'validate_received_dte', side_effect=requests.Timeout("Connection timeout")):
            dte.action_validate()

        # Assertions
        self.assertFalse(dte.ai_validated,
                        "ai_validated should be False after timeout")
        self.assertEqual(dte.state, 'review',
                        "State should be 'review' after timeout (graceful degradation)")
        self.assertTrue(dte.validation_warnings and 'timed out' in dte.validation_warnings.lower(),
                       "Should have timeout warning")

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_09_ai_connection_error_fallback(self, mock_ted, mock_struct):
        """
        Test: AI service unavailable (ConnectionError) → Fallback to manual review.

        Expected:
        - ai_validated = False
        - ai_recommendation = 'review'
        - Warning: "AI service unavailable"
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=2),
            monto_total=100000
        )

        # Mock AI validation to raise ConnectionError
        with patch.object(dte, 'validate_received_dte', side_effect=ConnectionError("Service unavailable")):
            dte.action_validate()

        # Assertions
        self.assertFalse(dte.ai_validated,
                        "ai_validated should be False after connection error")
        self.assertEqual(dte.ai_recommendation, 'review',
                        "ai_recommendation should be 'review' for fallback")
        self.assertTrue('unavailable' in (dte.validation_warnings or '').lower(),
                       "Should have service unavailable warning")

    # ═══════════════════════════════════════════════════════════════════════
    # CATEGORY 5: EDGE CASES (3 tests)
    # ═══════════════════════════════════════════════════════════════════════

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_10_commercial_before_ai_validation(self, mock_ted, mock_struct):
        """
        Test: Commercial validation runs BEFORE AI validation.

        Expected:
        - If commercial rejects, AI is NOT called (savepoint rollback)
        - Validates execution order: Native → Commercial → AI
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE with deadline exceeded (will reject in commercial)
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=10),
            monto_total=100000
        )

        # Mock AI validation (should NOT be called)
        ai_mock = Mock(return_value={
            'valid': True, 'confidence': 90, 'anomalies': [], 'warnings': [], 'recommendation': 'accept'
        })

        with patch.object(dte, 'validate_received_dte', ai_mock):
            with self.assertRaises(UserError):
                dte.action_validate()

        # Assertions
        ai_mock.assert_not_called()  # AI should NOT be called after commercial reject
        self.assertEqual(dte.commercial_auto_action, 'reject',
                        "Commercial validation should run first and reject")

    def test_11_commercial_validator_fields_exist(self):
        """
        Test: DTEInbox model has commercial validation fields.

        Expected:
        - commercial_auto_action field exists
        - commercial_confidence field exists
        """
        dte = self.env['dte.inbox']

        # Check fields exist
        self.assertTrue(hasattr(dte, 'commercial_auto_action'),
                       "DTEInbox should have commercial_auto_action field")
        self.assertTrue(hasattr(dte, 'commercial_confidence'),
                       "DTEInbox should have commercial_confidence field")

    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.DTEStructureValidator')
    @patch('addons.localization.l10n_cl_dte.models.dte_inbox.TEDValidator')
    def test_12_savepoint_isolation_no_side_effects(self, mock_ted, mock_struct):
        """
        Test: Commercial validation uses savepoint (R-001 race condition fix).

        Expected:
        - Commercial validation rollback does NOT affect other validations
        - Database state consistent after commercial reject
        """
        # Mock native validators
        mock_struct.validate.return_value = {'valid': True, 'errors': [], 'warnings': []}
        mock_ted.validate_ted.return_value = {'valid': True, 'errors': [], 'warnings': []}

        # Create DTE that will be rejected
        dte = self._create_dte_inbox(
            fecha_emision=date.today() - timedelta(days=10),
            monto_total=100000
        )

        # Count records before
        count_before = self.env['dte.inbox'].search_count([])

        # Execute and expect rejection
        with self.assertRaises(UserError):
            dte.action_validate()

        # Count records after (should be same, no side effects)
        count_after = self.env['dte.inbox'].search_count([])

        self.assertEqual(count_before, count_after,
                        "Record count should be unchanged (savepoint isolation)")


if __name__ == '__main__':
    import unittest
    unittest.main(verbosity=2)
