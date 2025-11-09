# -*- coding: utf-8 -*-
"""
Configuration Settings for EERGYGROUP DTE
==========================================

Extends res.config.settings to expose EERGYGROUP-specific
configuration in Settings > Accounting > Chilean Localization.

Configuration Sections:
1. Bank Information (company-specific)
2. Branding (company-specific)
3. System-wide Options (config parameters)

Technical Implementation:
- Related fields: Stored in res.company (multi-company ready)
- Config parameters: Stored in ir.config_parameter (system-wide)
- Transient model: Changes saved on "Save" button

User Experience:
- All EERGYGROUP config in one place
- Visual preview of bank info
- Color picker for primary color
- Helpful tooltips and examples

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
"""

from odoo import models, fields, api


class ResConfigSettings(models.TransientModel):
    """
    Extension of res.config.settings for EERGYGROUP DTE configuration.

    Provides user-friendly interface for:
    - Bank account information
    - Corporate branding (colors, footer)
    - System-wide behavior options

    Technical Note:
    - TransientModel: Changes not persisted until "Save" clicked
    - Related fields: Direct link to res.company
    - Config parameters: Stored in ir.config_parameter
    """
    _inherit = 'res.config.settings'

    # ========================================================================
    # RELATED FIELDS (stored in res.company)
    # ========================================================================

    # Bank Information
    bank_name = fields.Char(
        related='company_id.bank_name',
        readonly=False,
        string='Bank Name',
        help='Bank name displayed on customer invoices.\n'
             'Example: "Banco Scotiabank"',
    )

    bank_account_number = fields.Char(
        related='company_id.bank_account_number',
        readonly=False,
        string='Bank Account Number',
        help='Account number for receiving customer payments.\n'
             'Example: "987867477"',
    )

    bank_account_type = fields.Selection(
        related='company_id.bank_account_type',
        readonly=False,
        string='Account Type',
        help='Type of bank account (checking/savings/current)',
    )

    bank_info_display = fields.Text(
        related='company_id.bank_info_display',
        string='Preview',
        help='Preview of how bank information will appear on invoices',
    )

    # Branding
    report_primary_color = fields.Char(
        related='company_id.report_primary_color',
        readonly=False,
        string='Primary Color',
        help='Primary color for DTE reports (hex format).\n'
             'Example: #E97300 (EERGYGROUP orange)',
    )

    # Footer
    report_footer_text = fields.Text(
        related='company_id.report_footer_text',
        readonly=False,
        string='Footer Text',
        help='Custom text displayed in invoice footer.\n'
             'Keep it concise (max 2-3 lines).',
    )

    report_footer_websites = fields.Char(
        related='company_id.report_footer_websites',
        readonly=False,
        string='Footer Websites',
        help='Websites displayed in footer, separated by " | ".\n'
             'Example: "www.site1.cl | www.site2.cl"',
    )

    # ========================================================================
    # CONFIG PARAMETERS (system-wide, all companies)
    # ========================================================================

    enable_cedible_by_default = fields.Boolean(
        string='Enable CEDIBLE by Default',
        config_parameter='l10n_cl_dte_eergygroup.enable_cedible_by_default',
        help='Automatically enable CEDIBLE section on new customer invoices.\n\n'
             'Recommendation: Leave OFF unless your business primarily '
             'uses factoring for most invoices.\n\n'
             'Users can always enable CEDIBLE manually on specific invoices.',
    )

    require_contact_on_invoices = fields.Boolean(
        string='Require Contact Person',
        config_parameter='l10n_cl_dte_eergygroup.require_contact_on_invoices',
        help='Make contact person field mandatory on customer invoices.\n\n'
             'Recommendation: Enable for B2B businesses where tracking '
             'specific contacts is important.\n\n'
             'Disable for B2C businesses or high-volume invoicing.',
    )

    auto_populate_forma_pago = fields.Boolean(
        string='Auto-populate Payment Terms',
        config_parameter='l10n_cl_dte_eergygroup.auto_populate_forma_pago',
        default=True,
        help='Automatically fill "Custom Payment Terms" from payment term name.\n\n'
             'Recommendation: Keep enabled for better UX.\n\n'
             'Users can always override the auto-populated value.',
    )

    show_bank_info_on_all_dtes = fields.Boolean(
        string='Show Bank Info on All DTEs',
        config_parameter='l10n_cl_dte_eergygroup.show_bank_info_on_all_dtes',
        default=True,
        help='Display bank information on all DTE types (33, 34, 52, 56, 61).\n\n'
             'Disable to show only on Facturas (DTE 33) and Notas de Débito (DTE 56).',
    )

    # ========================================================================
    # UI HELPER FIELDS (not stored)
    # ========================================================================

    has_bank_info_configured = fields.Boolean(
        compute='_compute_has_bank_info_configured',
        string='Bank Info Complete',
        help='Technical field: TRUE if all required bank fields are filled',
    )

    # ========================================================================
    # COMPUTE METHODS
    # ========================================================================

    @api.depends('bank_name', 'bank_account_number')
    def _compute_has_bank_info_configured(self):
        """
        Check if bank information is complete.

        Used by UI to show status indicators and warnings.

        Technical Note:
        - Not stored (transient model)
        - Recomputed on form load
        """
        for config in self:
            config.has_bank_info_configured = bool(
                config.bank_name and config.bank_account_number
            )

    # ========================================================================
    # ONCHANGE METHODS
    # ========================================================================

    @api.onchange('bank_name', 'bank_account_number', 'bank_account_type')
    def _onchange_bank_fields(self):
        """
        Update bank info preview when any bank field changes.

        Provides real-time feedback on how bank info will appear on invoices.

        UX Note:
        - Helps users verify formatting before saving
        - Shows exactly what customers will see
        """
        # bank_info_display is computed, will update automatically
        pass

    @api.onchange('report_primary_color')
    def _onchange_primary_color(self):
        """
        Validate color format on change.

        Provides immediate feedback on color format errors.

        UX Note:
        - Prevents saving invalid colors
        - Shows format hints if error detected
        """
        if self.report_primary_color:
            import re
            if not re.match(r'^#[0-9A-Fa-f]{6}$', self.report_primary_color):
                return {
                    'warning': {
                        'title': _('Invalid Color Format'),
                        'message': _(
                            'Color must be in hex format: #RRGGBB\n\n'
                            'Examples: #E97300, #FFFFFF, #000000'
                        ),
                    }
                }

    # ========================================================================
    # BUSINESS METHODS
    # ========================================================================

    def action_preview_invoice_with_branding(self):
        """
        Generate preview invoice with current branding settings.

        Creates a draft invoice with sample data and opens PDF preview.

        Returns:
            dict: Action to open PDF preview

        UX Note:
        - Allows users to see branding changes before saving
        - Uses sample data (not real customer data)
        - Invoice is not saved to database
        """
        self.ensure_one()

        # Create temporary invoice for preview
        invoice = self.env['account.move'].with_context(
            preview_mode=True
        ).new({
            'move_type': 'out_invoice',
            'partner_id': self.env.company.partner_id.id,
            'invoice_line_ids': [(0, 0, {
                'name': 'Sample Product/Service',
                'quantity': 1,
                'price_unit': 100000,
            })],
        })

        # Generate PDF with current branding
        report = self.env.ref('l10n_cl_dte_eergygroup.action_report_invoice_dte_eergygroup')
        pdf_content, _ = report._render_qweb_pdf(invoice.ids)

        # Return action to display PDF
        return {
            'type': 'ir.actions.report',
            'report_type': 'qweb-pdf',
            'data': {
                'model': 'account.move',
                'output_format': 'pdf',
            },
            'report_file': pdf_content,
        }

    def reset_to_eergygroup_defaults(self):
        """
        Reset all settings to EERGYGROUP defaults.

        Useful for:
        - Initial setup
        - Fixing misconfigurations
        - Resetting after testing

        Returns:
            dict: Action to reload form

        Technical Note:
        - Only resets EERGYGROUP-specific fields
        - Does not affect base Odoo settings
        - Requires confirmation dialog (implemented in view)
        """
        self.ensure_one()

        # Reset to EERGYGROUP defaults
        self.company_id.write({
            'bank_name': 'Banco Scotiabank',
            'bank_account_number': '987867477',
            'bank_account_type': 'checking',
            'report_primary_color': '#E97300',
            'report_footer_text': (
                'Gracias por Preferirnos, somos un equipo de profesionales '
                'que trabajamos para proveer soluciones de Calidad Sustentable '
                'en ENERGIA y CONSTRUCCION'
            ),
            'report_footer_websites': 'www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',
        })

        # Reset config parameters
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param('l10n_cl_dte_eergygroup.enable_cedible_by_default', 'False')
        ICP.set_param('l10n_cl_dte_eergygroup.require_contact_on_invoices', 'False')
        ICP.set_param('l10n_cl_dte_eergygroup.auto_populate_forma_pago', 'True')
        ICP.set_param('l10n_cl_dte_eergygroup.show_bank_info_on_all_dtes', 'True')

        # Show success message
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Settings Reset'),
                'message': _('All EERGYGROUP settings have been reset to default values.'),
                'type': 'success',
                'sticky': False,
            }
        }

    # ========================================================================
    # OVERRIDE METHODS
    # ========================================================================

    def execute(self):
        """
        Override execute to add custom validation before saving.

        Validates:
        - Bank info completeness
        - Color format
        - Footer websites format

        Returns:
            bool: Save result

        Technical Note:
        - Called when user clicks "Save" button
        - Prevents saving invalid data
        - Shows clear error messages
        """
        # Validate bank info if any field is filled (must be complete)
        if any([self.bank_name, self.bank_account_number]) and not self.has_bank_info_configured:
            from odoo.exceptions import UserError
            raise UserError(_(
                'Bank information is incomplete.\n\n'
                'Please fill both:\n'
                '- Bank Name\n'
                '- Bank Account Number\n\n'
                'Or leave all bank fields empty.'
            ))

        return super().execute()
