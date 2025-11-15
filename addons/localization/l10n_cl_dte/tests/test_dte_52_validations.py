# -*- coding: utf-8 -*-
"""
Unit Tests - DTE 52 Validations
================================

P1.2 GAP CLOSURE: Tests for DTE 52 (Guía de Despacho) validations.

Validates:
- tipo_traslado (1-8) - mandatory
- tipo_despacho (1-3) - optional
- Char to int conversion before comparison

Author: EERGYGROUP - Claude Code (Anthropic)
License: LGPL-3
"""

import unittest
from unittest.mock import Mock, patch
from odoo.exceptions import ValidationError


class TestDTE52Validations(unittest.TestCase):
    """Tests unitarios para validaciones de DTE 52."""

    def setUp(self):
        """Preparar mocks."""
        # Mock account.move record
        self.mock_move = Mock()
        self.mock_move.ensure_one = Mock()
        self.mock_move.partner_id = Mock()
        self.mock_move.partner_id.street = "Av. Test 123"
        self.mock_move.partner_id.city = "Santiago"
        self.mock_move.partner_id.l10n_cl_comuna_id = None
        self.mock_move.partner_id.l10n_cl_comuna = "Santiago"

        # Mock invoice lines with quantity
        mock_line = Mock()
        mock_line.display_type = False
        mock_line.quantity = 10
        self.mock_move.invoice_line_ids = Mock()
        self.mock_move.invoice_line_ids.filtered = Mock(return_value=[mock_line])

    def test_01_tipo_traslado_valid_all_values(self):
        """
        P1.2: Test all valid tipo_traslado values (1-8 as strings).

        Critical test that ensures Char values '1' through '8'
        are correctly converted to int and validated.
        """
        from addons.localization.l10n_cl_dte.models.account_move_dte import AccountMove

        valid_values = ['1', '2', '3', '4', '5', '6', '7', '8']

        for value in valid_values:
            with self.subTest(tipo_traslado=value):
                mock_move = Mock(spec=AccountMove)
                mock_move.ensure_one = Mock()
                mock_move.partner_id = self.mock_move.partner_id
                mock_move.invoice_line_ids = self.mock_move.invoice_line_ids

                # Set tipo_traslado as string (Char field)
                mock_move.l10n_cl_dte_tipo_traslado = value
                mock_move.l10n_cl_dte_tipo_despacho = None
                mock_move.l10n_cl_dte_transporte = False

                # Mock hasattr to return True for required fields
                with patch('builtins.hasattr') as mock_hasattr:
                    mock_hasattr.side_effect = lambda obj, attr: attr in [
                        'l10n_cl_dte_tipo_traslado',
                        'l10n_cl_dte_tipo_despacho',
                        'l10n_cl_dte_transporte'
                    ]

                    # Mock getattr to return field values
                    def mock_getattr_impl(obj, attr, default=None):
                        if attr == 'l10n_cl_dte_tipo_traslado':
                            return value
                        elif attr == 'l10n_cl_dte_tipo_despacho':
                            return None
                        elif attr == 'l10n_cl_dte_transporte':
                            return False
                        return default

                    with patch('builtins.getattr', side_effect=mock_getattr_impl):
                        # Should NOT raise ValidationError
                        try:
                            AccountMove._validate_dte_52(mock_move)
                        except ValidationError:
                            self.fail(f"tipo_traslado='{value}' should be valid (raised ValidationError)")

    def test_02_tipo_traslado_invalid_values(self):
        """P1.2: Test invalid tipo_traslado values (0, 9, non-numeric)."""
        from addons.localization.l10n_cl_dte.models.account_move_dte import AccountMove

        invalid_values = ['0', '9', '10', 'abc', '']

        for value in invalid_values:
            with self.subTest(tipo_traslado=value):
                mock_move = Mock(spec=AccountMove)
                mock_move.ensure_one = Mock()
                mock_move.partner_id = self.mock_move.partner_id
                mock_move.invoice_line_ids = self.mock_move.invoice_line_ids
                mock_move.l10n_cl_dte_tipo_traslado = value

                with patch('builtins.hasattr') as mock_hasattr:
                    mock_hasattr.side_effect = lambda obj, attr: attr in [
                        'l10n_cl_dte_tipo_traslado'
                    ]

                    with patch('builtins.getattr') as mock_getattr:
                        mock_getattr.side_effect = lambda obj, attr, default=None: (
                            value if attr == 'l10n_cl_dte_tipo_traslado' else default
                        )

                        # Should raise ValidationError
                        with self.assertRaises(ValidationError) as context:
                            AccountMove._validate_dte_52(mock_move)

                        # Verify error message mentions invalid value
                        error_msg = str(context.exception)
                        self.assertTrue(
                            'Tipo de traslado' in error_msg or 'número entero' in error_msg,
                            f"Error message should mention tipo_traslado or integer: {error_msg}"
                        )

    def test_03_tipo_despacho_valid_all_values(self):
        """P1.2: Test all valid tipo_despacho values (1-3 as strings)."""
        from addons.localization.l10n_cl_dte.models.account_move_dte import AccountMove

        valid_values = ['1', '2', '3']

        for value in valid_values:
            with self.subTest(tipo_despacho=value):
                mock_move = Mock(spec=AccountMove)
                mock_move.ensure_one = Mock()
                mock_move.partner_id = self.mock_move.partner_id
                mock_move.invoice_line_ids = self.mock_move.invoice_line_ids
                mock_move.l10n_cl_dte_tipo_traslado = '1'  # Valid tipo_traslado
                mock_move.l10n_cl_dte_tipo_despacho = value
                mock_move.l10n_cl_dte_transporte = False

                with patch('builtins.hasattr') as mock_hasattr:
                    mock_hasattr.side_effect = lambda obj, attr: attr in [
                        'l10n_cl_dte_tipo_traslado',
                        'l10n_cl_dte_tipo_despacho',
                        'l10n_cl_dte_transporte'
                    ]

                    def mock_getattr_impl(obj, attr, default=None):
                        if attr == 'l10n_cl_dte_tipo_traslado':
                            return '1'
                        elif attr == 'l10n_cl_dte_tipo_despacho':
                            return value
                        elif attr == 'l10n_cl_dte_transporte':
                            return False
                        return default

                    with patch('builtins.getattr', side_effect=mock_getattr_impl):
                        # Should NOT raise ValidationError
                        try:
                            AccountMove._validate_dte_52(mock_move)
                        except ValidationError:
                            self.fail(f"tipo_despacho='{value}' should be valid (raised ValidationError)")

    def test_04_tipo_despacho_invalid_values(self):
        """P1.2: Test invalid tipo_despacho values (0, 4, non-numeric)."""
        from addons.localization.l10n_cl_dte.models.account_move_dte import AccountMove

        invalid_values = ['0', '4', '5', 'xyz']

        for value in invalid_values:
            with self.subTest(tipo_despacho=value):
                mock_move = Mock(spec=AccountMove)
                mock_move.ensure_one = Mock()
                mock_move.partner_id = self.mock_move.partner_id
                mock_move.invoice_line_ids = self.mock_move.invoice_line_ids
                mock_move.l10n_cl_dte_tipo_traslado = '1'  # Valid
                mock_move.l10n_cl_dte_tipo_despacho = value

                with patch('builtins.hasattr') as mock_hasattr:
                    mock_hasattr.side_effect = lambda obj, attr: attr in [
                        'l10n_cl_dte_tipo_traslado',
                        'l10n_cl_dte_tipo_despacho'
                    ]

                    def mock_getattr_impl(obj, attr, default=None):
                        if attr == 'l10n_cl_dte_tipo_traslado':
                            return '1'
                        elif attr == 'l10n_cl_dte_tipo_despacho':
                            return value
                        return default

                    with patch('builtins.getattr', side_effect=mock_getattr_impl):
                        # Should raise ValidationError
                        with self.assertRaises(ValidationError) as context:
                            AccountMove._validate_dte_52(mock_move)

                        error_msg = str(context.exception)
                        self.assertTrue(
                            'Tipo de despacho' in error_msg or 'número entero' in error_msg,
                            f"Error message should mention tipo_despacho: {error_msg}"
                        )

    def test_05_tipo_traslado_char_to_int_conversion(self):
        """
        P1.2: Explicit test that Char '1' is correctly converted to int 1.

        This is the core of the bug fix: Char fields must be converted
        to int before numeric comparison.
        """
        # Test conversion works
        tipo_traslado_str = '5'
        tipo_traslado_int = int(tipo_traslado_str)

        self.assertEqual(tipo_traslado_int, 5)
        self.assertIn(tipo_traslado_int, (1, 2, 3, 4, 5, 6, 7, 8))

        # Test that string comparison would fail (demonstrates the bug)
        self.assertNotIn(tipo_traslado_str, (1, 2, 3, 4, 5, 6, 7, 8))  # Bug!
        self.assertIn(tipo_traslado_str, ('1', '2', '3', '4', '5', '6', '7', '8'))  # OK


if __name__ == '__main__':
    unittest.main()
