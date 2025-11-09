# -*- coding: utf-8 -*-
"""
Contingency Mode Management Wizard
===================================

Wizard para gestión de modo de contingencia SII.

Migration from: odoo-eergy-services/routes/contingency.py (2025-10-24)
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class ContingencyWizard(models.TransientModel):
    """
    Wizard for Contingency Mode Management.

    Actions:
    - Enable contingency mode
    - Disable contingency mode
    - Upload pending DTEs
    """
    _name = 'contingency.wizard'
    _description = 'Contingency Mode Management'

    action = fields.Selection([
        ('enable', 'Enable Contingency Mode'),
        ('disable', 'Disable Contingency Mode'),
        ('upload_pending', 'Upload Pending DTEs to SII')
    ], string='Action', required=True, default='enable')

    reason = fields.Selection([
        ('manual', 'Manual Activation'),
        ('sii_unavailable', 'SII Unavailable'),
        ('circuit_breaker', 'Circuit Breaker Triggered'),
        ('timeout_threshold', 'Timeout Threshold Exceeded')
    ], string='Reason', default='manual')

    comment = fields.Text(
        string='Comment',
        help='Additional details about the action'
    )

    batch_size = fields.Integer(
        string='Batch Size',
        default=50,
        help='Maximum DTEs to upload in one batch'
    )

    # Display current status
    current_status = fields.Boolean(
        string='Current Status',
        compute='_compute_current_status'
    )

    pending_dtes_count = fields.Integer(
        string='Pending DTEs',
        compute='_compute_pending_dtes_count'
    )

    @api.depends('action')
    def _compute_current_status(self):
        """Compute current contingency status"""
        for wizard in self:
            company = self.env.company
            contingency = self.env['dte.contingency'].search([
                ('company_id', '=', company.id)
            ], limit=1)

            wizard.current_status = contingency.enabled if contingency else False

    @api.depends('action')
    def _compute_pending_dtes_count(self):
        """Compute pending DTEs count"""
        for wizard in self:
            company = self.env.company
            wizard.pending_dtes_count = self.env['dte.contingency.pending'].search_count([
                ('company_id', '=', company.id),
                ('uploaded', '=', False)
            ])

    def execute_action(self):
        """Execute selected action"""
        self.ensure_one()

        company = self.env.company
        contingency = self.env['dte.contingency'].search([
            ('company_id', '=', company.id)
        ], limit=1)

        if not contingency:
            contingency = self.env['dte.contingency'].create({
                'company_id': company.id
            })

        if self.action == 'enable':
            return self._action_enable(contingency)

        elif self.action == 'disable':
            return self._action_disable(contingency)

        elif self.action == 'upload_pending':
            return self._action_upload_pending(contingency)

    def _action_enable(self, contingency):
        """Enable contingency mode"""
        if contingency.enabled:
            raise ValidationError(_('Contingency mode is already enabled'))

        contingency.enable_contingency(
            reason=self.reason,
            comment=self.comment
        )

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Contingency Mode Enabled'),
                'message': _('DTEs will be stored locally until SII is available again.'),
                'type': 'warning',
                'sticky': True
            }
        }

    def _action_disable(self, contingency):
        """Disable contingency mode"""
        if not contingency.enabled:
            raise ValidationError(_('Contingency mode is already disabled'))

        # Check pending DTEs
        if contingency.pending_dtes_count > 0:
            raise ValidationError(
                _(
                    'Cannot disable contingency mode with %s pending DTEs.\n\n'
                    'Please upload pending DTEs first using "Upload Pending DTEs" action.'
                ) % contingency.pending_dtes_count
            )

        contingency.disable_contingency()

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Contingency Mode Disabled'),
                'message': _('DTEs will be sent directly to SII.'),
                'type': 'success',
                'sticky': False
            }
        }

    def _action_upload_pending(self, contingency):
        """Upload pending DTEs"""
        if contingency.pending_dtes_count == 0:
            raise ValidationError(_('No pending DTEs to upload'))

        # Upload batch
        result = self.env['dte.contingency.pending'].upload_all_pending(
            company_id=self.env.company.id,
            batch_size=self.batch_size
        )

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Upload Completed'),
                'message': _(
                    'Total: %s\nSuccess: %s\nFailed: %s'
                ) % (result['total'], result['success'], result['failed']),
                'type': 'success' if result['failed'] == 0 else 'warning',
                'sticky': True
            }
        }
