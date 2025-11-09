# -*- coding: utf-8 -*-
"""
res.config.settings Extension - Bank Information Quick Access
==============================================================

Extends res.config.settings to provide quick access to bank information
configuration from Accounting Settings.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

from odoo import models, fields, api, _


class ResConfigSettings(models.TransientModel):
    """
    Extension of res.config.settings for bank information quick access.

    Provides related fields and action methods for bank information
    configuration from Accounting Settings.
    """
    _inherit = 'res.config.settings'

    # ═══════════════════════════════════════════════════════════════════════
    # RELATED FIELDS - Bank Information
    # ═══════════════════════════════════════════════════════════════════════

    bank_name = fields.Char(
        related='company_id.bank_name',
        string='Bank Name',
        readonly=False,
        help='Name of the bank where the company account is held'
    )

    bank_account_number = fields.Char(
        related='company_id.bank_account_number',
        string='Bank Account Number',
        readonly=False,
        help='Bank account number for receiving payments'
    )

    bank_account_type = fields.Selection(
        related='company_id.bank_account_type',
        string='Account Type',
        readonly=False,
        help='Type of bank account'
    )

    # ═══════════════════════════════════════════════════════════════════════
    # ACTION METHODS
    # ═══════════════════════════════════════════════════════════════════════

    def action_open_company_bank_info(self):
        """
        Open company form focused on Bank Information tab.

        Returns:
            dict: Action to open company form in dialog mode
        """
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Company Bank Information'),
            'res_model': 'res.company',
            'res_id': self.company_id.id,
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'form_view_initial_mode': 'edit',
                'default_id': self.company_id.id,
            },
            'views': [(False, 'form')],
        }
