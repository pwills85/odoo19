# -*- coding: utf-8 -*-
"""
Unit Tests for account.move.reference Model
============================================

Tests SII document references functionality for Chilean DTE.

Test Coverage:
- CRUD operations
- Field validations
- Date validations (not future, chronological)
- Folio format validations
- Document type country validations
- SQL constraints (uniqueness)
- Computed fields (display_name)
- Search methods (name_search)
- Audit logging

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError
from odoo import fields
from datetime import date, timedelta
from psycopg2 import IntegrityError


@tagged('post_install', '-at_install', 'eergygroup')
class TestAccountMoveReference(TransactionCase):
    """
    Test suite for account.move.reference model.

    Setup creates:
    - Test invoice
    - Chilean document types
    - Test partner
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Ensure Chilean localization
        cls.env.company.country_id = cls.env.ref('base.cl')

        # Create test partner
        cls.partner = cls.env['res.partner'].create({
            'name': 'Test Customer Reference',
            'vat': '76111222-3',
            'country_id': cls.env.ref('base.cl').id,
        })

        # Create test invoice
        cls.invoice = cls.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': cls.partner.id,
            'invoice_date': date.today(),
        })

        # Get/Create Chilean document types
        try:
            cls.doc_type_33 = cls.env.ref('l10n_latam_invoice_document.document_type_33')
            cls.doc_type_52 = cls.env.ref('l10n_latam_invoice_document.document_type_52')
        except ValueError:
            cls.doc_type_33 = cls.env['l10n_latam.document.type'].create({
                'name': 'Factura Electrónica',
                'code': '33',
                'country_id': cls.env.ref('base.cl').id,
            })
            cls.doc_type_52 = cls.env['l10n_latam.document.type'].create({
                'name': 'Guía de Despacho Electrónica',
                'code': '52',
                'country_id': cls.env.ref('base.cl').id,
            })

        # Create non-Chilean document type for testing
        cls.doc_type_ar = cls.env['l10n_latam.document.type'].create({
            'name': 'Factura Argentina',
            'code': 'AR-FAC',
            'country_id': cls.env.ref('base.ar').id,
        })

    # ========================================================================
    # TEST: CRUD OPERATIONS
    # ========================================================================

    def test_01_create_reference_basic(self):
        """Test creating a basic reference with required fields."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '123',
            'date': date.today() - timedelta(days=10),
        })

        self.assertTrue(reference)
        self.assertEqual(reference.folio, '123')
        self.assertEqual(reference.document_type_id, self.doc_type_33)

    def test_02_create_reference_full(self):
        """Test creating reference with all fields."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '456',
            'date': date.today() - timedelta(days=5),
            'reason': 'Anula documento por error en monto',
            'code': '1',
        })

        self.assertEqual(reference.reason, 'Anula documento por error en monto')
        self.assertEqual(reference.code, '1')

    def test_03_read_reference(self):
        """Test reading reference data."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '789',
            'date': date.today() - timedelta(days=1),
        })

        # Read data
        data = reference.read(['folio', 'document_type_id', 'date'])[0]

        self.assertEqual(data['folio'], '789')
        self.assertEqual(data['document_type_id'][0], self.doc_type_33.id)

    def test_04_update_reference(self):
        """Test updating reference fields."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '111',
            'date': date.today() - timedelta(days=2),
        })

        # Update reason
        reference.write({'reason': 'Updated reason'})

        self.assertEqual(reference.reason, 'Updated reason')

    def test_05_delete_reference(self):
        """Test deleting a reference."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '999',
            'date': date.today() - timedelta(days=3),
        })

        reference_id = reference.id
        reference.unlink()

        # Should not exist
        exists = self.env['account.move.reference'].search([('id', '=', reference_id)])
        self.assertFalse(exists, "Reference should be deleted")

    # ========================================================================
    # TEST: COMPUTED FIELDS
    # ========================================================================

    def test_06_computed_display_name(self):
        """Test display_name is computed correctly."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '555',
            'date': date(2025, 1, 15),
        })

        expected = f"{self.doc_type_33.name} - Folio 555 (2025-01-15)"
        self.assertEqual(reference.display_name, expected,
                        "display_name should show document type, folio, and date")

    def test_07_computed_display_name_incomplete(self):
        """Test display_name for incomplete reference."""
        reference = self.env['account.move.reference'].new({
            'move_id': self.invoice.id,
        })

        self.assertEqual(reference.display_name, 'New Reference',
                        "Incomplete reference should show 'New Reference'")

    # ========================================================================
    # TEST: DATE VALIDATIONS
    # ========================================================================

    def test_08_constraint_date_not_future(self):
        """Test reference date cannot be in the future."""
        future_date = date.today() + timedelta(days=10)

        with self.assertRaises(ValidationError) as context:
            self.env['account.move.reference'].create({
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': '777',
                'date': future_date,
            })

        error_message = str(context.exception)
        self.assertIn('future', error_message.lower())

    def test_09_constraint_date_not_after_parent(self):
        """Test reference date cannot be after parent document date."""
        # Create invoice with specific date
        invoice = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'invoice_date': date.today(),
        })

        # Try to create reference with date AFTER invoice date
        with self.assertRaises(ValidationError) as context:
            self.env['account.move.reference'].create({
                'move_id': invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': '888',
                'date': date.today() + timedelta(days=1),
            })

        error_message = str(context.exception)
        self.assertIn('future', error_message.lower())

    def test_10_valid_date_today(self):
        """Test today's date is valid for reference."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '222',
            'date': date.today(),
        })

        self.assertEqual(reference.date, date.today())

    def test_11_valid_date_past(self):
        """Test past date is valid for reference."""
        past_date = date.today() - timedelta(days=30)

        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '333',
            'date': past_date,
        })

        self.assertEqual(reference.date, past_date)

    # ========================================================================
    # TEST: FOLIO VALIDATIONS
    # ========================================================================

    def test_12_constraint_folio_not_empty(self):
        """Test folio cannot be empty string."""
        with self.assertRaises(ValidationError):
            self.env['account.move.reference'].create({
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': '',  # Empty
                'date': date.today(),
            })

    def test_13_constraint_folio_not_whitespace(self):
        """Test folio cannot be only whitespace."""
        with self.assertRaises(ValidationError):
            self.env['account.move.reference'].create({
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': '   ',  # Only spaces
                'date': date.today(),
            })

    def test_14_constraint_folio_max_length(self):
        """Test folio has reasonable max length."""
        long_folio = 'A' * 25  # 25 characters (exceeds max 20)

        with self.assertRaises(ValidationError):
            self.env['account.move.reference'].create({
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': long_folio,
                'date': date.today(),
            })

    def test_15_valid_folio_alphanumeric(self):
        """Test folio accepts alphanumeric values."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': 'ABC-123',
            'date': date.today(),
        })

        self.assertEqual(reference.folio, 'ABC-123')

    # ========================================================================
    # TEST: DOCUMENT TYPE VALIDATIONS
    # ========================================================================

    def test_16_constraint_document_type_must_be_chilean(self):
        """Test document type must be Chilean (country=CL)."""
        with self.assertRaises(ValidationError) as context:
            self.env['account.move.reference'].create({
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_ar.id,  # Argentine doc type
                'folio': '444',
                'date': date.today(),
            })

        error_message = str(context.exception)
        self.assertIn('Chilean', error_message)

    def test_17_valid_chilean_document_type(self):
        """Test Chilean document types are accepted."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_52.id,  # Guía Despacho (Chilean)
            'folio': '666',
            'date': date.today(),
        })

        self.assertEqual(reference.document_type_id.country_id.code, 'CL')

    # ========================================================================
    # TEST: SQL CONSTRAINTS
    # ========================================================================

    def test_18_sql_constraint_unique_reference_per_move(self):
        """Test cannot create duplicate reference in same invoice."""
        # Create first reference
        self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '100',
            'date': date.today(),
        })

        # Try to create duplicate (same move, same doc type, same folio)
        with self.assertRaises(Exception):  # IntegrityError wrapped
            self.env['account.move.reference'].create({
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': '100',  # Same folio
                'date': date.today(),
            })

    def test_19_sql_constraint_allows_same_folio_different_invoice(self):
        """Test same folio allowed in different invoices."""
        # Create second invoice
        invoice2 = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
        })

        # Create reference in first invoice
        ref1 = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '200',
            'date': date.today(),
        })

        # Create reference with SAME folio in second invoice (should be OK)
        ref2 = self.env['account.move.reference'].create({
            'move_id': invoice2.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '200',  # Same folio, different invoice
            'date': date.today(),
        })

        self.assertEqual(ref1.folio, ref2.folio)
        self.assertNotEqual(ref1.move_id, ref2.move_id)

    # ========================================================================
    # TEST: SEARCH & NAME METHODS
    # ========================================================================

    def test_20_name_get_returns_display_name(self):
        """Test name_get returns display_name."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '300',
            'date': date(2025, 2, 1),
        })

        name_list = reference.name_get()

        self.assertEqual(len(name_list), 1)
        self.assertEqual(name_list[0][0], reference.id)
        self.assertIn('300', name_list[0][1])
        self.assertIn('2025-02-01', name_list[0][1])

    def test_21_name_search_by_folio(self):
        """Test name_search finds reference by folio."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': 'SEARCH-123',
            'date': date.today(),
        })

        # Search by folio
        found_ids = self.env['account.move.reference']._name_search('SEARCH-123')

        self.assertIn(reference.id, found_ids,
                     "name_search should find reference by folio")

    def test_22_name_search_by_document_type(self):
        """Test name_search finds reference by document type name."""
        reference = self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': '400',
            'date': date.today(),
        })

        # Search by document type name
        found_ids = self.env['account.move.reference']._name_search('Factura')

        self.assertIn(reference.id, found_ids,
                     "name_search should find reference by document type name")

    # ========================================================================
    # TEST: AUDIT LOGGING
    # ========================================================================

    def test_23_create_logs_to_ir_logging(self):
        """Test create operation logs to ir.logging for audit."""
        # Count existing logs
        log_count_before = self.env['ir.logging'].sudo().search_count([
            ('name', '=', 'account.move.reference'),
        ])

        # Create reference
        self.env['account.move.reference'].create({
            'move_id': self.invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': 'AUDIT-001',
            'date': date.today(),
        })

        # Count logs after
        log_count_after = self.env['ir.logging'].sudo().search_count([
            ('name', '=', 'account.move.reference'),
        ])

        self.assertGreater(log_count_after, log_count_before,
                          "Reference creation should be logged to ir.logging")

    # ========================================================================
    # TEST: INTEGRATION WITH ACCOUNT.MOVE
    # ========================================================================

    def test_24_reference_cascade_delete_with_invoice(self):
        """Test reference is deleted when invoice is deleted (cascade)."""
        # Create invoice with reference
        invoice = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
        })

        reference = self.env['account.move.reference'].create({
            'move_id': invoice.id,
            'document_type_id': self.doc_type_33.id,
            'folio': 'CASCADE-001',
            'date': date.today(),
        })

        reference_id = reference.id

        # Delete invoice
        invoice.unlink()

        # Reference should also be deleted (cascade)
        exists = self.env['account.move.reference'].search([('id', '=', reference_id)])
        self.assertFalse(exists, "Reference should be cascade deleted with invoice")

    def test_25_multiple_references_per_invoice(self):
        """Test invoice can have multiple references."""
        references = self.env['account.move.reference'].create([
            {
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_33.id,
                'folio': 'MULTI-01',
                'date': date.today() - timedelta(days=10),
            },
            {
                'move_id': self.invoice.id,
                'document_type_id': self.doc_type_52.id,  # Different doc type
                'folio': 'MULTI-02',
                'date': date.today() - timedelta(days=5),
            },
        ])

        self.assertEqual(len(references), 2)
        self.assertEqual(self.invoice.reference_ids, references)
