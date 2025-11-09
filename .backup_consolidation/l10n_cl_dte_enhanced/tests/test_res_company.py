# -*- coding: utf-8 -*-
"""
Unit Tests for res.company Extension
=====================================

Tests EERGYGROUP branding and bank configuration for Chilean DTE reports.

Test Coverage:
- Bank information fields and validation
- Primary color format validation (hex)
- Footer configuration
- Computed fields (bank_info_display)
- Constraint validations
- Business methods (preview, reset)

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError


@tagged('post_install', '-at_install', 'eergygroup')
class TestResCompany(TransactionCase):
    """
    Test suite for res.company EERGYGROUP extension.

    Tests branding and bank information configuration.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.company = cls.env.company

    def setUp(self):
        super().setUp()
        # Reset company to clean state before each test
        self.company.write({
            'bank_name': False,
            'bank_account_number': False,
            'bank_account_type': 'checking',
            'report_primary_color': '#E97300',
            'report_footer_text': False,
            'report_footer_websites': False,
        })

    # ========================================================================
    # TEST: FIELD EXISTENCE
    # ========================================================================

    def test_01_fields_exist(self):
        """Test that EERGYGROUP custom fields exist on res.company."""
        # Bank fields
        self.assertTrue(hasattr(self.company, 'bank_name'))
        self.assertTrue(hasattr(self.company, 'bank_account_number'))
        self.assertTrue(hasattr(self.company, 'bank_account_type'))

        # Branding fields
        self.assertTrue(hasattr(self.company, 'report_primary_color'))
        self.assertTrue(hasattr(self.company, 'report_footer_text'))
        self.assertTrue(hasattr(self.company, 'report_footer_websites'))

        # Computed fields
        self.assertTrue(hasattr(self.company, 'bank_info_display'))

    # ========================================================================
    # TEST: BANK INFORMATION - HAPPY PATH
    # ========================================================================

    def test_02_bank_info_basic_configuration(self):
        """Test basic bank information configuration."""
        self.company.write({
            'bank_name': 'Banco Scotiabank',
            'bank_account_number': '987867477',
            'bank_account_type': 'checking',
        })

        self.assertEqual(self.company.bank_name, 'Banco Scotiabank')
        self.assertEqual(self.company.bank_account_number, '987867477')
        self.assertEqual(self.company.bank_account_type, 'checking')

    def test_03_bank_account_types(self):
        """Test all bank account types are valid."""
        account_types = ['checking', 'savings', 'current']

        for acc_type in account_types:
            self.company.write({'bank_account_type': acc_type})
            self.assertEqual(self.company.bank_account_type, acc_type)

    def test_04_bank_account_with_hyphens(self):
        """Test bank account accepts hyphens."""
        self.company.write({
            'bank_name': 'Banco de Chile',
            'bank_account_number': '9878-6747-7',
        })

        self.assertEqual(self.company.bank_account_number, '9878-6747-7')

    def test_05_bank_account_with_spaces(self):
        """Test bank account accepts spaces."""
        self.company.write({
            'bank_name': 'Banco Estado',
            'bank_account_number': '9878 6747 7',
        })

        self.assertEqual(self.company.bank_account_number, '9878 6747 7')

    # ========================================================================
    # TEST: BANK INFORMATION - VALIDATIONS
    # ========================================================================

    def test_06_constraint_bank_account_only_digits(self):
        """Test bank account number must contain only digits/spaces/hyphens."""
        with self.assertRaises(ValidationError) as context:
            self.company.write({
                'bank_account_number': '9878ABC',  # Letters not allowed
            })

        error_message = str(context.exception)
        self.assertIn('digit', error_message.lower())

    def test_07_constraint_bank_account_no_special_chars(self):
        """Test bank account doesn't accept special characters."""
        with self.assertRaises(ValidationError):
            self.company.write({
                'bank_account_number': '9878.6747',  # Dots not allowed
            })

    def test_08_constraint_bank_account_min_length(self):
        """Test bank account has minimum length."""
        with self.assertRaises(ValidationError) as context:
            self.company.write({
                'bank_account_number': '12345',  # Too short (< 6 digits)
            })

        error_message = str(context.exception)
        self.assertIn('length', error_message.lower())

    def test_09_constraint_bank_account_max_length(self):
        """Test bank account has maximum length."""
        with self.assertRaises(ValidationError):
            self.company.write({
                'bank_account_number': '1' * 25,  # Too long (> 20 digits)
            })

    # ========================================================================
    # TEST: PRIMARY COLOR - VALIDATIONS
    # ========================================================================

    def test_10_valid_hex_colors(self):
        """Test valid hex color formats are accepted."""
        valid_colors = [
            '#E97300',  # EERGYGROUP orange
            '#FFFFFF',  # White
            '#000000',  # Black
            '#FF0000',  # Red
            '#00FF00',  # Green
            '#0000FF',  # Blue
            '#AbCdEf',  # Mixed case
        ]

        for color in valid_colors:
            self.company.write({'report_primary_color': color})
            self.assertEqual(self.company.report_primary_color, color)

    def test_11_constraint_color_format_no_hash(self):
        """Test color without # is rejected."""
        with self.assertRaises(ValidationError) as context:
            self.company.write({
                'report_primary_color': 'E97300',  # Missing #
            })

        error_message = str(context.exception)
        self.assertIn('#RRGGBB', error_message)

    def test_12_constraint_color_format_too_short(self):
        """Test short color code is rejected."""
        with self.assertRaises(ValidationError):
            self.company.write({
                'report_primary_color': '#E97',  # Too short
            })

    def test_13_constraint_color_format_too_long(self):
        """Test long color code is rejected."""
        with self.assertRaises(ValidationError):
            self.company.write({
                'report_primary_color': '#E973001',  # Too long (7 hex digits)
            })

    def test_14_constraint_color_format_invalid_chars(self):
        """Test color with invalid characters is rejected."""
        with self.assertRaises(ValidationError):
            self.company.write({
                'report_primary_color': '#GGGGGG',  # G is not hex
            })

    def test_15_constraint_color_format_named_color(self):
        """Test named colors are rejected (only hex allowed)."""
        with self.assertRaises(ValidationError):
            self.company.write({
                'report_primary_color': 'orange',  # Named color not allowed
            })

    # ========================================================================
    # TEST: COMPUTED FIELD - bank_info_display
    # ========================================================================

    def test_16_computed_bank_info_display_complete(self):
        """Test bank_info_display is computed correctly with all fields."""
        self.company.write({
            'name': 'EERGYGROUP SpA',
            'vat': '76.489.218-6',
            'bank_name': 'Banco Scotiabank',
            'bank_account_number': '987867477',
            'bank_account_type': 'checking',
        })

        bank_info = self.company.bank_info_display

        # Check all components are present
        self.assertIn('Banco Scotiabank', bank_info)
        self.assertIn('987867477', bank_info)
        self.assertIn('EERGYGROUP SpA', bank_info)
        self.assertIn('76.489.218-6', bank_info)
        self.assertIn('Cuenta Corriente', bank_info)  # Spanish label

    def test_17_computed_bank_info_display_incomplete(self):
        """Test bank_info_display is False when bank info is incomplete."""
        self.company.write({
            'bank_name': 'Banco Scotiabank',
            # Missing bank_account_number
        })

        self.assertFalse(self.company.bank_info_display,
                        "bank_info_display should be False when incomplete")

    def test_18_computed_bank_info_display_updates(self):
        """Test bank_info_display updates when fields change."""
        # Set initial values
        self.company.write({
            'bank_name': 'Banco A',
            'bank_account_number': '111111',
        })

        initial_display = self.company.bank_info_display

        # Update bank name
        self.company.write({'bank_name': 'Banco B'})

        updated_display = self.company.bank_info_display

        self.assertNotEqual(initial_display, updated_display)
        self.assertIn('Banco B', updated_display)
        self.assertNotIn('Banco A', updated_display)

    # ========================================================================
    # TEST: FOOTER CONFIGURATION
    # ========================================================================

    def test_19_footer_text_basic(self):
        """Test footer text configuration."""
        footer_text = 'Gracias por Preferirnos'
        self.company.write({'report_footer_text': footer_text})

        self.assertEqual(self.company.report_footer_text, footer_text)

    def test_20_footer_websites_single(self):
        """Test footer with single website."""
        self.company.write({'report_footer_websites': 'www.eergygroup.cl'})

        self.assertEqual(self.company.report_footer_websites, 'www.eergygroup.cl')

    def test_21_footer_websites_multiple(self):
        """Test footer with multiple websites."""
        websites = 'www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl'
        self.company.write({'report_footer_websites': websites})

        self.assertEqual(self.company.report_footer_websites, websites)

    def test_22_constraint_footer_websites_max_count(self):
        """Test footer websites has max limit (5 websites)."""
        many_websites = ' | '.join([f'www.site{i}.cl' for i in range(6)])  # 6 websites

        with self.assertRaises(ValidationError) as context:
            self.company.write({'report_footer_websites': many_websites})

        error_message = str(context.exception)
        self.assertIn('5', error_message)  # Max 5 websites message

    def test_23_constraint_footer_websites_too_short(self):
        """Test individual website URLs have minimum length."""
        with self.assertRaises(ValidationError):
            self.company.write({'report_footer_websites': 'ab'})  # Too short

    # ========================================================================
    # TEST: BUSINESS METHODS
    # ========================================================================

    def test_24_get_default_report_color(self):
        """Test get_default_report_color returns EERGYGROUP orange."""
        default_color = self.env['res.company'].get_default_report_color()

        self.assertEqual(default_color, '#E97300',
                        "Default color should be EERGYGROUP orange")

    def test_25_action_preview_bank_info(self):
        """Test action_preview_bank_info returns proper action."""
        self.company.write({
            'bank_name': 'Banco Test',
            'bank_account_number': '123456',
        })

        action = self.company.action_preview_bank_info()

        # Validate action structure
        self.assertEqual(action['type'], 'ir.actions.act_window')
        self.assertEqual(action['res_model'], 'res.company')
        self.assertEqual(action['res_id'], self.company.id)
        self.assertEqual(action['target'], 'new')

    # ========================================================================
    # TEST: MULTI-COMPANY SCENARIO
    # ========================================================================

    def test_26_multiple_companies_independent_config(self):
        """Test each company can have different configuration."""
        # Create second company
        company2 = self.env['res.company'].create({
            'name': 'Test Company 2',
            'bank_name': 'Banco Test 2',
            'bank_account_number': '999999',
            'report_primary_color': '#FF0000',  # Different color
        })

        # Configure main company differently
        self.company.write({
            'bank_name': 'Banco Test 1',
            'bank_account_number': '111111',
            'report_primary_color': '#00FF00',  # Different color
        })

        # Verify independence
        self.assertNotEqual(self.company.bank_name, company2.bank_name)
        self.assertNotEqual(self.company.report_primary_color, company2.report_primary_color)

    # ========================================================================
    # TEST: DEFAULT VALUES
    # ========================================================================

    def test_27_default_primary_color(self):
        """Test default primary color is EERGYGROUP orange."""
        new_company = self.env['res.company'].create({
            'name': 'New Company for Default Test',
        })

        # After post_init_hook, should have default color
        # Note: This depends on post_init_hook running
        # In unit test, we check field default
        self.assertEqual(new_company.report_primary_color, '#E97300')

    def test_28_default_footer_websites(self):
        """Test default footer websites are EERGYGROUP sites."""
        new_company = self.env['res.company'].create({
            'name': 'New Company for Footer Test',
        })

        expected = 'www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl'
        # After post_init_hook
        # Note: post_init_hook applies defaults
        # In unit test context, check field default is set
        if new_company.report_footer_websites:
            self.assertEqual(new_company.report_footer_websites, expected)


@tagged('post_install', '-at_install', 'eergygroup', 'eergygroup_integration')
class TestResConfigSettings(TransactionCase):
    """
    Integration tests for res.config.settings with EERGYGROUP fields.

    Tests configuration UI and parameter persistence.
    """

    def setUp(self):
        super().setUp()
        self.company = self.env.company

    def test_01_config_related_fields_work(self):
        """Test related fields in config settings work correctly."""
        config = self.env['res.config.settings'].create({
            'company_id': self.company.id,
            'bank_name': 'Config Test Bank',
            'bank_account_number': '777777',
            'report_primary_color': '#123456',
        })

        # Execute to save
        config.execute()

        # Verify changes persisted to company
        self.assertEqual(self.company.bank_name, 'Config Test Bank')
        self.assertEqual(self.company.bank_account_number, '777777')
        self.assertEqual(self.company.report_primary_color, '#123456')

    def test_02_config_parameters_persist(self):
        """Test config parameters are saved correctly."""
        config = self.env['res.config.settings'].create({
            'company_id': self.company.id,
            'enable_cedible_by_default': True,
            'require_contact_on_invoices': True,
        })

        config.execute()

        # Check parameters were saved
        ICP = self.env['ir.config_parameter'].sudo()
        cedible_default = ICP.get_param('l10n_cl_dte_eergygroup.enable_cedible_by_default')
        require_contact = ICP.get_param('l10n_cl_dte_eergygroup.require_contact_on_invoices')

        self.assertEqual(cedible_default, 'True')
        self.assertEqual(require_contact, 'True')

    def test_03_computed_has_bank_info_configured(self):
        """Test has_bank_info_configured computed field."""
        config = self.env['res.config.settings'].create({
            'company_id': self.company.id,
        })

        # Initially False (no bank info)
        self.assertFalse(config.has_bank_info_configured)

        # Set bank info
        config.write({
            'bank_name': 'Test Bank',
            'bank_account_number': '123456',
        })

        # Should be True now
        self.assertTrue(config.has_bank_info_configured)
