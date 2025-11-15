# -*- coding: utf-8 -*-
"""
res.company Extension - Bank Information Only
==============================================

Extends res.company with bank information fields for invoice display.

NOTE: This module contains ONLY functional fields (bank information).
Branding fields (colors, logos, footer) are in separate branding modules.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class ResCompany(models.Model):
    """
    Extension of res.company with bank information for invoices.

    FUNCTIONAL ONLY - No branding/aesthetic fields here.
    """
    _inherit = 'res.company'

    # ═══════════════════════════════════════════════════════════════════════
    # BANK INFORMATION FIELDS (Functional)
    # ═══════════════════════════════════════════════════════════════════════

    bank_name = fields.Char(
        string='Bank Name',
        help='Name of the bank where the company account is held. '
             'Example: "Banco de Chile", "Banco Santander", "Banco Scotiabank".'
    )

    bank_account_number = fields.Char(
        string='Bank Account Number',
        help='Bank account number for receiving payments. '
             'Can include spaces or hyphens for readability (e.g., "9878 6747 7" or "9878-6747-7").'
    )

    bank_account_type = fields.Selection([
        ('checking', 'Checking Account (Cuenta Corriente)'),
        ('savings', 'Savings Account (Cuenta de Ahorro)'),
        ('current', 'Current Account (Cuenta Vista)'),
    ], string='Account Type', default='checking',
       help='Type of bank account. Most common in Chile is "Cuenta Corriente" (checking).')

    # ═══════════════════════════════════════════════════════════════════════
    # COMPUTED FIELD - Formatted Bank Information
    # ═══════════════════════════════════════════════════════════════════════

    bank_info_display = fields.Text(
        string='Bank Information (Formatted)',
        compute='_compute_bank_info_display',
        store=True,
        help='Formatted bank information ready for display on invoices. '
             'Includes bank name, account number, account type, and company name/RUT.'
    )

    @api.depends('bank_name', 'bank_account_number', 'bank_account_type', 'name', 'vat')
    def _compute_bank_info_display(self):
        """
        Compute formatted bank information for invoice display.

        Format (Chilean standard):
        {Bank Name}
        {Account Type} N° {Account Number}
        Titular: {Company Name}
        RUT: {Company VAT}
        """
        for company in self:
            if company.bank_name and company.bank_account_number:
                # Get account type label in Spanish
                account_type_label = dict(
                    company._fields['bank_account_type'].selection
                ).get(company.bank_account_type, '')

                # Format bank information (Chilean standard)
                company.bank_info_display = _(
                    "{bank}\n{type} N° {account}\nTitular: {name}\nRUT: {vat}"
                ).format(
                    bank=company.bank_name,
                    type=account_type_label,
                    account=company.bank_account_number,
                    name=company.name,
                    vat=company.vat or '',
                )
            else:
                company.bank_info_display = False

    # ═══════════════════════════════════════════════════════════════════════
    # CONSTRAINT METHODS - Validation
    # ═══════════════════════════════════════════════════════════════════════

    @api.constrains('bank_account_number')
    def _check_bank_account_format(self):
        """
        Validate bank account number format.

        Rules:
        - Only digits, spaces, or hyphens allowed
        - 6-20 digits (excluding spaces/hyphens)
        """
        for company in self:
            if company.bank_account_number:
                # Remove spaces and hyphens for validation
                account_clean = company.bank_account_number.replace(' ', '').replace('-', '')

                # Check: only digits allowed (after removing spaces/hyphens)
                if not account_clean.isdigit():
                    raise ValidationError(_(
                        "Bank account number must contain only digits, spaces, or hyphens. "
                        "Invalid characters found."
                    ))

                # Check: length between 6 and 20 digits
                if len(account_clean) < 6 or len(account_clean) > 20:
                    raise ValidationError(_(
                        "Bank account number must be between 6 and 20 digits "
                        "(excluding spaces/hyphens). Current length: %d digits."
                    ) % len(account_clean))

    # ═══════════════════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════════════════

    def action_preview_bank_info(self):
        """
        Open preview dialog showing formatted bank information.

        Returns:
            dict: Action to open company form in dialog mode
        """
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Bank Information Preview'),
            'res_model': 'res.company',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_id': self.id},
        }
