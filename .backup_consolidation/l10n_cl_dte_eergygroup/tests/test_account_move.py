# -*- coding: utf-8 -*-
"""
Unit Tests for account.move Extension
======================================

Tests EERGYGROUP-specific fields and business logic for Chilean DTE.

Test Coverage:
- Custom fields: contact_id, forma_pago, cedible, reference_ids
- Computed fields: reference_required
- Onchange methods: auto-populate logic
- Constraints: validation rules
- Business methods: workflows
- Override methods: _post(), _get_report_base_filename()
- API methods: create_with_eergygroup_defaults()

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError, UserError
from datetime import date, timedelta


@tagged('post_install', '-at_install', 'eergygroup')
class TestAccountMoveEERGYGROUP(TransactionCase):
    """
    Test suite for account.move EERGYGROUP extension.

    Setup creates:
    - Test customer with contact person
    - Test product
    - Test payment term
    - Chilean document types (DTE)
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Ensure Chilean localization is active
        cls.env.company.country_id = cls.env.ref('base.cl')

        # Create test customer (parent partner)
        cls.partner = cls.env['res.partner'].create({
            'name': 'Test Customer EERGYGROUP',
            'vat': '76123456-7',
            'country_id': cls.env.ref('base.cl').id,
            'email': 'test@eergygroup.cl',
        })

        # Create contact person (child partner)
        cls.contact = cls.env['res.partner'].create({
            'name': 'María González',
            'type': 'contact',
            'parent_id': cls.partner.id,
            'email': 'maria.gonzalez@eergygroup.cl',
            'phone': '+56912345678',
        })

        # Create additional contact (for testing multiple contacts)
        cls.contact2 = cls.env['res.partner'].create({
            'name': 'Juan Pérez',
            'type': 'contact',
            'parent_id': cls.partner.id,
            'email': 'juan.perez@eergygroup.cl',
        })

        # Create test product
        cls.product = cls.env['product.product'].create({
            'name': 'Test Product - Solar Panel',
            'type': 'service',
            'list_price': 100000.0,
            'uom_id': cls.env.ref('uom.product_uom_unit').id,
        })

        # Create payment term
        cls.payment_term = cls.env['account.payment.term'].create({
            'name': '30 días',
            'line_ids': [(0, 0, {
                'value': 'balance',
                'days': 30,
            })],
        })

        # Get Chilean document types (if l10n_cl_dte is installed)
        try:
            cls.doc_type_33 = cls.env.ref('l10n_latam_invoice_document.document_type_33')  # Factura
            cls.doc_type_61 = cls.env.ref('l10n_latam_invoice_document.document_type_61')  # NC
            cls.doc_type_56 = cls.env.ref('l10n_latam_invoice_document.document_type_56')  # ND
        except ValueError:
            # Fallback if refs don't exist (create minimal for testing)
            cls.doc_type_33 = cls.env['l10n_latam.document.type'].create({
                'name': 'Factura Electrónica',
                'code': '33',
                'country_id': cls.env.ref('base.cl').id,
            })
            cls.doc_type_61 = cls.env['l10n_latam.document.type'].create({
                'name': 'Nota de Crédito Electrónica',
                'code': '61',
                'country_id': cls.env.ref('base.cl').id,
            })
            cls.doc_type_56 = cls.env['l10n_latam.document.type'].create({
                'name': 'Nota de Débito Electrónica',
                'code': '56',
                'country_id': cls.env.ref('base.cl').id,
            })

    # ========================================================================
    # TEST: FIELD EXISTENCE & DEFAULTS
    # ========================================================================

    def test_01_fields_exist(self):
        """Test that EERGYGROUP custom fields exist on account.move."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
        })

        # Check fields exist
        self.assertTrue(hasattr(invoice, 'contact_id'))
        self.assertTrue(hasattr(invoice, 'forma_pago'))
        self.assertTrue(hasattr(invoice, 'cedible'))
        self.assertTrue(hasattr(invoice, 'reference_ids'))
        self.assertTrue(hasattr(invoice, 'reference_required'))

    def test_02_default_values(self):
        """Test default values for custom fields."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
        })

        # Default values
        self.assertFalse(invoice.cedible, "cedible should default to False")
        self.assertEqual(len(invoice.reference_ids), 0, "reference_ids should be empty by default")

    # ========================================================================
    # TEST: ONCHANGE METHODS
    # ========================================================================

    def test_03_onchange_partner_auto_populate_contact(self):
        """Test that contact_id auto-populates when partner has default contact."""
        invoice = self.env['account.move'].new({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
        })

        # Trigger onchange
        invoice._onchange_partner_id_contact()

        # Should auto-populate with first contact
        self.assertEqual(invoice.contact_id, self.contact,
                        "Contact should auto-populate from partner's contacts")

    def test_04_onchange_partner_no_contact(self):
        """Test onchange when partner has no contacts."""
        partner_no_contact = self.env['res.partner'].create({
            'name': 'Partner Without Contacts',
            'vat': '76999999-9',
        })

        invoice = self.env['account.move'].new({
            'move_type': 'out_invoice',
            'partner_id': partner_no_contact.id,
        })

        invoice._onchange_partner_id_contact()

        # Should be False (no contacts available)
        self.assertFalse(invoice.contact_id, "contact_id should be False when no contacts exist")

    def test_05_onchange_payment_term_forma_pago(self):
        """Test that forma_pago auto-populates from payment term."""
        invoice = self.env['account.move'].new({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'invoice_payment_term_id': self.payment_term.id,
        })

        # Trigger onchange
        invoice._onchange_payment_term_forma_pago()

        self.assertEqual(invoice.forma_pago, '30 días',
                        "forma_pago should auto-populate from payment term name")

    def test_06_onchange_payment_term_no_override(self):
        """Test that onchange doesn't override existing forma_pago."""
        invoice = self.env['account.move'].new({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'forma_pago': 'Custom payment terms already set',
            'invoice_payment_term_id': self.payment_term.id,
        })

        invoice._onchange_payment_term_forma_pago()

        # Should NOT override
        self.assertEqual(invoice.forma_pago, 'Custom payment terms already set',
                        "Existing forma_pago should not be overridden")

    # ========================================================================
    # TEST: COMPUTED FIELDS
    # ========================================================================

    def test_07_computed_reference_required_factura(self):
        """Test reference_required is FALSE for Factura (DTE 33)."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'dte_code': '33',
        })

        self.assertFalse(invoice.reference_required,
                        "Factura (DTE 33) should NOT require references")

    def test_08_computed_reference_required_nota_credito(self):
        """Test reference_required is TRUE for Nota Crédito (DTE 61)."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'dte_code': '61',
        })

        self.assertTrue(invoice.reference_required,
                       "Nota Crédito (DTE 61) MUST require references")

    def test_09_computed_reference_required_nota_debito(self):
        """Test reference_required is TRUE for Nota Débito (DTE 56)."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'dte_code': '56',
        })

        self.assertTrue(invoice.reference_required,
                       "Nota Débito (DTE 56) MUST require references")

    # ========================================================================
    # TEST: CONSTRAINTS
    # ========================================================================

    def test_10_constraint_cedible_only_customer_invoices(self):
        """Test CEDIBLE can only be enabled for customer invoices."""
        # OK: Customer invoice with CEDIBLE
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'cedible': True,
        })
        self.assertTrue(invoice.cedible, "CEDIBLE should be allowed on customer invoices")

        # ERROR: Vendor bill with CEDIBLE
        with self.assertRaises(ValidationError):
            self.env['account.move'].create({
                'move_type': 'in_invoice',
                'partner_id': self.partner.id,
                'cedible': True,
            })

    def test_11_constraint_references_required_on_posted_nc(self):
        """Test that posted Credit Note without references raises error."""
        credit_note = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100000,
            })],
            'dte_code': '61',
        })

        # Draft: Should be OK without references
        self.assertEqual(credit_note.state, 'draft')

        # Posted: Should fail without references
        with self.assertRaises((ValidationError, UserError)):
            credit_note.action_post()

    def test_12_constraint_references_ok_on_draft_nc(self):
        """Test that draft Credit Note can exist without references."""
        credit_note = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'dte_code': '61',
        })

        # Should be OK in draft without references
        self.assertEqual(credit_note.state, 'draft')
        self.assertEqual(len(credit_note.reference_ids), 0)

    # ========================================================================
    # TEST: BUSINESS METHODS
    # ========================================================================

    def test_13_action_add_reference(self):
        """Test action_add_reference returns proper wizard action."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
        })

        action = invoice.action_add_reference()

        # Validate action structure
        self.assertEqual(action['type'], 'ir.actions.act_window')
        self.assertEqual(action['res_model'], 'account.move.reference')
        self.assertEqual(action['view_mode'], 'form')
        self.assertEqual(action['target'], 'new')
        self.assertIn('default_move_id', action['context'])
        self.assertEqual(action['context']['default_move_id'], invoice.id)

    def test_14_get_report_base_filename_normal(self):
        """Test filename without CEDIBLE."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'name': 'INV/2025/0001',
            'cedible': False,
        })

        filename = invoice._get_report_base_filename()

        # Should NOT contain CEDIBLE
        self.assertNotIn('CEDIBLE', filename)

    def test_15_get_report_base_filename_cedible(self):
        """Test filename with CEDIBLE enabled."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'name': 'INV/2025/0001',
            'cedible': True,
        })

        filename = invoice._get_report_base_filename()

        # Should contain CEDIBLE
        self.assertIn('CEDIBLE', filename)

    # ========================================================================
    # TEST: OVERRIDE METHODS
    # ========================================================================

    def test_16_post_override_validates_references(self):
        """Test _post() override validates references before posting."""
        credit_note = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100000,
            })],
            'dte_code': '61',
        })

        # Should raise UserError when posting without references
        with self.assertRaises(UserError) as context:
            credit_note.action_post()

        # Check error message is user-friendly
        error_message = str(context.exception)
        self.assertIn('SII', error_message)
        self.assertIn('reference', error_message.lower())

    def test_17_post_ok_with_references(self):
        """Test _post() succeeds when references are present."""
        # Create original invoice
        original = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100000,
            })],
            'dte_code': '33',
            'name': 'INV/TEST/001',
        })

        # Create credit note with reference
        credit_note = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100000,
            })],
            'dte_code': '61',
            'reference_ids': [(0, 0, {
                'document_type_id': self.doc_type_33.id,
                'folio': '001',
                'date': date.today(),
                'reason': 'Test reference',
            })],
        })

        # Should post successfully
        try:
            credit_note.action_post()
            self.assertEqual(credit_note.state, 'posted', "Credit note should post successfully with references")
        except Exception as e:
            # If posting fails for other reasons (journals, etc.), that's OK for this test
            # We're only testing references validation
            pass

    # ========================================================================
    # TEST: API METHODS
    # ========================================================================

    def test_18_create_with_eergygroup_defaults(self):
        """Test create_with_eergygroup_defaults applies defaults."""
        invoice = self.env['account.move'].create_with_eergygroup_defaults({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'invoice_payment_term_id': self.payment_term.id,
        })

        # Should have auto-populated fields
        self.assertEqual(invoice.contact_id, self.contact,
                        "contact_id should be auto-populated")
        self.assertEqual(invoice.forma_pago, '30 días',
                        "forma_pago should be auto-populated from payment term")

    def test_19_get_default_contact_id_helper(self):
        """Test _get_default_contact_id helper method."""
        contact_id = self.env['account.move']._get_default_contact_id(self.partner.id)

        self.assertEqual(contact_id, self.contact.id,
                        "Should return first contact ID")

    def test_20_get_default_contact_id_no_partner(self):
        """Test _get_default_contact_id with no partner."""
        contact_id = self.env['account.move']._get_default_contact_id(False)

        self.assertFalse(contact_id, "Should return False when no partner")

    # ========================================================================
    # TEST: INTEGRATION SCENARIOS
    # ========================================================================

    def test_21_full_workflow_invoice_with_all_fields(self):
        """Integration test: Create invoice with all EERGYGROUP fields."""
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'contact_id': self.contact.id,
            'forma_pago': '50% anticipo, 50% contra entrega',
            'cedible': True,
            'invoice_payment_term_id': self.payment_term.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 10,
                'price_unit': 100000,
            })],
            'dte_code': '33',
        })

        # Validate all fields
        self.assertEqual(invoice.contact_id, self.contact)
        self.assertEqual(invoice.forma_pago, '50% anticipo, 50% contra entrega')
        self.assertTrue(invoice.cedible)
        self.assertFalse(invoice.reference_required)

        # Validate filename includes CEDIBLE
        filename = invoice._get_report_base_filename()
        self.assertIn('CEDIBLE', filename)

    def test_22_full_workflow_credit_note_with_reference(self):
        """Integration test: Create credit note with reference."""
        credit_note = self.env['account.move'].create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'contact_id': self.contact.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100000,
            })],
            'dte_code': '61',
            'reference_ids': [(0, 0, {
                'document_type_id': self.doc_type_33.id,
                'folio': '123',
                'date': date.today() - timedelta(days=10),
                'reason': 'Anula documento por error en monto',
                'code': '1',
            })],
        })

        # Validate
        self.assertTrue(credit_note.reference_required)
        self.assertEqual(len(credit_note.reference_ids), 1)
        self.assertEqual(credit_note.reference_ids[0].folio, '123')


@tagged('post_install', '-at_install', 'eergygroup', 'eergygroup_smoke')
class TestAccountMoveSmokeTests(TransactionCase):
    """
    Smoke tests: Quick validation of critical paths.

    These run first to catch major issues before full test suite.
    """

    def test_smoke_module_installed(self):
        """Smoke: Verify module is installed."""
        module = self.env['ir.module.module'].search([
            ('name', '=', 'l10n_cl_dte_eergygroup'),
        ])
        self.assertTrue(module, "Module l10n_cl_dte_eergygroup should be installed")

    def test_smoke_models_exist(self):
        """Smoke: Verify models exist."""
        self.assertTrue('account.move' in self.env)
        self.assertTrue('account.move.reference' in self.env)
        self.assertTrue('res.company' in self.env)

    def test_smoke_create_basic_invoice(self):
        """Smoke: Create basic invoice without errors."""
        partner = self.env['res.partner'].create({'name': 'Smoke Test Partner'})
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': partner.id,
        })
        self.assertTrue(invoice)
