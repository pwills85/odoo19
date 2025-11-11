# -*- coding: utf-8 -*-
"""
Unit Tests - CommercialValidator
==================================

Tests for commercial validation rules (Pure Python, no Odoo dependencies).

**Created**: 2025-11-11 - H1 Gap Closure
**Coverage target**: ≥95% CommercialValidator class

Test categories:
1. Deadline validation (8-day SII rule) - 4 test cases
2. PO matching (2% tolerance) - 6 test cases
3. Confidence scoring - 2 test cases

Author: EERGYGROUP
"""

import unittest
from datetime import date, timedelta
import sys
import os

# Add libs/ to path for standalone testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'libs'))

from commercial_validator import CommercialValidator


class TestCommercialValidatorDeadline(unittest.TestCase):
    """Test suite: 8-day SII deadline validation."""

    def setUp(self):
        """Setup validator instance (no Odoo env)."""
        self.validator = CommercialValidator(env=None)

    def test_01_deadline_ok_within_8_days(self):
        """Test: DTE emitted 1 day ago → 7 days remaining (PASS)."""
        dte_data = {
            'fecha_emision': date.today() - timedelta(days=1),
            'monto_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data)

        self.assertTrue(result['valid'], "Validation should pass within deadline")
        self.assertEqual(len(result['errors']), 0, "No errors expected")
        self.assertEqual(result['details']['deadline_status'], 'ok')
        # Note: 'review' due to missing PO warning
        self.assertIn(result['auto_action'], ['review', 'accept'])

    def test_02_deadline_exceeded_10_days_old(self):
        """Test: DTE emitted 10 days ago → 2 days overdue (REJECT)."""
        dte_data = {
            'fecha_emision': date.today() - timedelta(days=10),
            'monto_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data)

        self.assertFalse(result['valid'], "Validation should fail (deadline exceeded)")
        self.assertEqual(result['auto_action'], 'reject')
        self.assertGreater(len(result['errors']), 0, "Should have deadline error")
        self.assertIn('deadline exceeded', result['errors'][0].lower())
        self.assertEqual(result['details']['deadline_status'], 'exceeded')

    def test_03_deadline_exactly_8_days(self):
        """Test: DTE emitted exactly 8 days ago → Last valid day (PASS)."""
        dte_data = {
            'fecha_emision': date.today() - timedelta(days=8),
            'monto_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data)

        self.assertTrue(result['valid'], "Should pass on 8th day")
        self.assertEqual(result['details']['deadline_status'], 'ok')

    def test_04_deadline_missing_fecha_emision(self):
        """Test: Missing fecha_emision field → REJECT."""
        dte_data = {
            'monto_total': 100000
            # Missing 'fecha_emision'
        }

        result = self.validator.validate_commercial_rules(dte_data)

        self.assertFalse(result['valid'])
        self.assertEqual(result['auto_action'], 'reject')
        self.assertIn('Missing emission date', result['errors'][0])


class TestCommercialValidatorPOMatch(unittest.TestCase):
    """Test suite: PO matching with 2% tolerance."""

    def setUp(self):
        """Setup validator instance."""
        self.validator = CommercialValidator(env=None)

    def test_05_po_match_exact_amount(self):
        """Test: DTE matches PO exactly → ACCEPT."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 100000
        }
        po_data = {
            'amount_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertTrue(result['valid'])
        self.assertEqual(result['auto_action'], 'accept')
        self.assertEqual(len(result['errors']), 0)
        self.assertEqual(len(result['warnings']), 0)
        self.assertEqual(result['details']['po_match'], 'exact')
        self.assertGreaterEqual(result['confidence'], 0.95)

    def test_06_po_match_within_tolerance_1_percent(self):
        """Test: DTE differs 1% from PO (within 2% tolerance) → REVIEW."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 101000  # +1% vs PO
        }
        po_data = {
            'amount_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertTrue(result['valid'], "Should pass within tolerance")
        self.assertEqual(result['auto_action'], 'review', "Should require review")
        self.assertEqual(len(result['errors']), 0)
        self.assertEqual(len(result['warnings']), 1, "Should have 1 warning")
        self.assertIn('Minor amount difference', result['warnings'][0])
        self.assertEqual(result['details']['po_match'], 'partial')

    def test_07_po_match_exceeds_tolerance_3_percent(self):
        """Test: DTE differs 3% from PO (exceeds 2% tolerance) → REJECT."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 103000  # +3% vs PO
        }
        po_data = {
            'amount_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertFalse(result['valid'], "Should fail (exceeds tolerance)")
        self.assertEqual(result['auto_action'], 'reject')
        self.assertGreater(len(result['errors']), 0)
        self.assertIn('Amount mismatch exceeds', result['errors'][0])
        self.assertEqual(result['details']['po_match'], 'failed')

    def test_08_po_match_negative_difference(self):
        """Test: DTE amount less than PO (within tolerance) → REVIEW."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 99000  # -1% vs PO
        }
        po_data = {
            'amount_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertTrue(result['valid'])
        self.assertEqual(result['auto_action'], 'review')
        self.assertEqual(len(result['warnings']), 1)

    def test_09_po_match_zero_amount(self):
        """Test: PO amount is zero → REJECT (invalid PO)."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 100000
        }
        po_data = {
            'amount_total': 0
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertFalse(result['valid'])
        self.assertIn('zero', result['errors'][0].lower())

    def test_10_po_missing_no_po_provided(self):
        """Test: No PO provided → REVIEW (manual check required)."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data=None)

        self.assertTrue(result['valid'], "Should pass but require review")
        self.assertEqual(result['auto_action'], 'review')
        self.assertGreater(len(result['warnings']), 0)
        self.assertIn('No Purchase Order', result['warnings'][0])
        self.assertEqual(result['details']['po_match'], 'missing')


class TestCommercialValidatorConfidence(unittest.TestCase):
    """Test suite: Confidence scoring."""

    def setUp(self):
        """Setup validator instance."""
        self.validator = CommercialValidator(env=None)

    def test_11_confidence_perfect_match(self):
        """Test: Perfect match (no errors/warnings) → 100% confidence."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 100000
        }
        po_data = {
            'amount_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertEqual(result['confidence'], 1.0)
        self.assertEqual(result['auto_action'], 'accept')

    def test_12_confidence_with_warnings(self):
        """Test: Warnings present → Reduced confidence (≥85%)."""
        dte_data = {
            'fecha_emision': date.today(),
            'monto_total': 101000  # +1% (warning)
        }
        po_data = {
            'amount_total': 100000
        }

        result = self.validator.validate_commercial_rules(dte_data, po_data)

        self.assertLess(result['confidence'], 1.0, "Confidence should be reduced")
        self.assertGreaterEqual(result['confidence'], 0.85, "Confidence should be ≥85%")
        self.assertEqual(result['auto_action'], 'review')


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
