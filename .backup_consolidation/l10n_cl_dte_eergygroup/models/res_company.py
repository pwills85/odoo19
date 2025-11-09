# -*- coding: utf-8 -*-
"""
Company Extension for EERGYGROUP Branding
==========================================

Extends res.company to add EERGYGROUP-specific configuration for
Chilean electronic invoicing reports:

Configuration Areas:
1. Bank Information: Display on invoices for customer payments
2. Corporate Branding: Configurable colors and styling
3. Footer Content: Custom messages and websites

Technical Implementation:
- All fields stored in res.company (multi-company ready)
- Computed fields for formatted display
- Validation constraints for data integrity
- Default values via data XML

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import re


class ResCompany(models.Model):
    """
    Extension of res.company for EERGYGROUP DTE branding and bank configuration.

    Key Features:
    - Bank account information (name, number, type)
    - Corporate branding (primary color hex)
    - Report footer customization (text, websites)

    Multi-Company:
    - Each company can have different configuration
    - Inheritance-safe (no conflicts with base module)
    """
    _inherit = 'res.company'

    # ========================================================================
    # BANK INFORMATION FIELDS
    # ========================================================================

    bank_name = fields.Char(
        string='Bank Name',
        help='Bank name to display on customer invoices.\n'
             'Example: "Banco Scotiabank", "Banco de Chile"\n\n'
             'This appears in the payment instructions section of DTE reports.',
    )

    bank_account_number = fields.Char(
        string='Bank Account Number',
        help='Bank account number for receiving customer payments.\n'
             'Enter numbers only (hyphens and spaces allowed).\n\n'
             'Example: "987867477" or "9878-6747-7"\n\n'
             'This appears on all customer invoices.',
    )

    bank_account_type = fields.Selection(
        selection=[
            ('checking', 'Checking Account (Cuenta Corriente)'),
            ('savings', 'Savings Account (Cuenta de Ahorro)'),
            ('current', 'Current Account (Cuenta Vista)'),
        ],
        string='Account Type',
        default='checking',
        help='Type of bank account for customer payments.\n\n'
             'Most common in Chile: Checking Account (Cuenta Corriente)',
    )

    # ========================================================================
    # BRANDING FIELDS
    # ========================================================================

    report_primary_color = fields.Char(
        string='Primary Color',
        default='#E97300',  # EERGYGROUP Orange
        help='Primary color for DTE reports in hex format.\n\n'
             'Format: #RRGGBB (6 hexadecimal characters)\n'
             'Example: #E97300 (EERGYGROUP orange)\n\n'
             'Applied to:\n'
             '- Table headers\n'
             '- Section titles\n'
             '- CEDIBLE section\n'
             '- Total rows',
    )

    # ========================================================================
    # FOOTER FIELDS
    # ========================================================================

    report_footer_text = fields.Text(
        string='Report Footer Text',
        help='Custom text displayed in invoice footer.\n\n'
             'Example: "Gracias por Preferirnos, somos un equipo de profesionales..."\n\n'
             'Keep it concise (max 2-3 lines) for optimal PDF layout.',
        translate=True,  # Allow translation to other languages
    )

    report_footer_websites = fields.Char(
        string='Footer Websites',
        help='Websites to display in invoice footer.\n\n'
             'Format: Separate multiple websites with " | "\n'
             'Example: "www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl"\n\n'
             'Displayed below footer text.',
        default='www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',
    )

    # ========================================================================
    # COMPUTED FIELDS
    # ========================================================================

    bank_info_display = fields.Text(
        string='Bank Info Display',
        compute='_compute_bank_info_display',
        help='Formatted bank information for invoice display.\n'
             'Auto-generated from bank fields.'
    )

    # ========================================================================
    # COMPUTE METHODS
    # ========================================================================

    @api.depends('bank_name', 'bank_account_number', 'bank_account_type', 'name', 'vat')
    def _compute_bank_info_display(self):
        """
        Compute formatted bank information for display on invoices.

        Format:
        "Depositar o transferir a: [Bank Name], [Account Type]: [Account Number],
         A Nombre de: [Company Name], RUT: [Company RUT]"

        Technical Note:
        - Not stored (computed on-the-fly)
        - Used by QWeb report template
        - Returns False if required fields missing (graceful degradation)

        Business Logic:
        - All bank fields required for complete display
        - Partial info not shown (prevents confusing customers)
        """
        for company in self:
            if company.bank_name and company.bank_account_number:
                # Get human-readable account type label
                account_type_label = dict(
                    company._fields['bank_account_type'].selection
                ).get(company.bank_account_type, 'Cuenta')

                # Format complete bank info
                company.bank_info_display = _(
                    "Depositar o transferir a: %s, %s: %s, "
                    "A Nombre de: %s, RUT: %s"
                ) % (
                    company.bank_name,
                    account_type_label,
                    company.bank_account_number,
                    company.name,
                    company.vat or 'N/A',
                )
            else:
                # If incomplete, return False (report will hide section)
                company.bank_info_display = False

    # ========================================================================
    # CONSTRAINTS
    # ========================================================================

    @api.constrains('report_primary_color')
    def _check_color_format(self):
        """
        Validate primary color format is hex (#RRGGBB).

        SII/Business Requirement:
        - Must be valid CSS color for PDF generation
        - Hex format ensures consistency across browsers/PDF engines

        Raises:
            ValidationError: If color format is invalid

        Examples:
            ✓ Valid: "#E97300", "#FFFFFF", "#000000"
            ✗ Invalid: "E97300" (missing #), "#E973" (too short), "orange" (named color)

        Technical Note:
        - Regex pattern: ^#[0-9A-Fa-f]{6}$
        - Case-insensitive (A-F or a-f both valid)
        """
        for company in self:
            if company.report_primary_color:
                # Regex: # followed by exactly 6 hex digits
                if not re.match(r'^#[0-9A-Fa-f]{6}$', company.report_primary_color):
                    raise ValidationError(_(
                        "Primary color must be in hex format: #RRGGBB\n\n"
                        "Current value: %s\n\n"
                        "Examples:\n"
                        "  ✓ #E97300 (EERGYGROUP orange)\n"
                        "  ✓ #FFFFFF (white)\n"
                        "  ✓ #000000 (black)\n\n"
                        "Invalid formats:\n"
                        "  ✗ E97300 (missing #)\n"
                        "  ✗ #E973 (too short)\n"
                        "  ✗ orange (named colors not allowed)"
                    ) % company.report_primary_color)

    @api.constrains('bank_account_number')
    def _check_bank_account_format(self):
        """
        Validate bank account number format (basic check).

        Business Rules:
        - Only digits, spaces, and hyphens allowed
        - Reasonable length (6-20 characters)
        - Not empty if set

        Raises:
            ValidationError: If account number format is invalid

        Technical Note:
        - Does NOT validate account exists in bank (out of scope)
        - Only prevents obviously invalid entries
        - Allows flexibility for different bank formats
        """
        for company in self:
            if company.bank_account_number:
                # Remove allowed separators
                account_clean = company.bank_account_number.replace(' ', '').replace('-', '')

                # Check only digits remain
                if not account_clean.isdigit():
                    raise ValidationError(_(
                        "Bank account number must contain only digits, spaces, or hyphens.\n\n"
                        "Current value: %s\n\n"
                        "Examples:\n"
                        "  ✓ 987867477\n"
                        "  ✓ 9878-6747-7\n"
                        "  ✓ 9878 6747 7\n\n"
                        "Invalid:\n"
                        "  ✗ 9878ABC (letters not allowed)\n"
                        "  ✗ 9878.6747 (dots not allowed)"
                    ) % company.bank_account_number)

                # Check reasonable length
                if len(account_clean) < 6 or len(account_clean) > 20:
                    raise ValidationError(_(
                        "Bank account number length must be between 6 and 20 digits.\n\n"
                        "Current: %s (%d digits)\n\n"
                        "Please verify the account number."
                    ) % (company.bank_account_number, len(account_clean)))

    @api.constrains('report_footer_websites')
    def _check_footer_websites_format(self):
        """
        Validate footer websites format (basic check).

        Business Rules:
        - Multiple websites separated by " | "
        - Each website should look like a domain (no strict validation)
        - Max 5 websites (UI constraint)

        Raises:
            ValidationError: If format is clearly wrong

        Technical Note:
        - Does NOT validate URLs are reachable (out of scope)
        - Does NOT require http:// prefix (cleaner display)
        - Flexible validation for different domain formats
        """
        for company in self:
            if company.report_footer_websites:
                websites = company.report_footer_websites.split('|')

                # Check max 5 websites
                if len(websites) > 5:
                    raise ValidationError(_(
                        "Maximum 5 websites allowed in footer.\n\n"
                        "Current: %d websites\n\n"
                        "Please remove some websites or contact support."
                    ) % len(websites))

                # Check each website looks reasonable
                for website in websites:
                    website_clean = website.strip()
                    if len(website_clean) < 3:
                        raise ValidationError(_(
                            "Website '%s' is too short.\n\n"
                            "Please enter valid website domains."
                        ) % website_clean)

    # ========================================================================
    # BUSINESS METHODS
    # ========================================================================

    def action_preview_bank_info(self):
        """
        Preview formatted bank information.

        Opens a wizard showing how bank info will appear on invoices.

        Returns:
            dict: Action to open preview wizard

        UX Note:
        - Helps users verify bank info formatting before saving
        - Shows exactly what customers will see
        """
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Bank Information Preview'),
            'res_model': 'res.company',
            'view_mode': 'form',
            'views': [(False, 'form')],
            'res_id': self.id,
            'target': 'new',
            'context': {
                'dialog_size': 'medium',
                'form_view_initial_mode': 'readonly',
            },
        }

    @api.model
    def get_default_report_color(self):
        """
        Get default primary color for reports.

        Returns:
            str: Hex color code

        Technical Note:
        - Used by report templates when company color not set
        - Ensures consistent branding even in edge cases
        - Can be overridden by system parameter
        """
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte_eergygroup.default_primary_color',
            '#E97300'  # EERGYGROUP orange
        )
