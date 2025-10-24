# -*- coding: utf-8 -*-
"""
DTE Commercial Response Wizard
===============================

Wizard para enviar respuestas comerciales al SII (Aceptar/Rechazar/Reclamar).

Based on Odoo 18: l10n_cl_fe/wizards/dte_commercial_response.py
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import requests
import logging

_logger = logging.getLogger(__name__)


class DTECommercialResponseWizard(models.TransientModel):
    _name = 'dte.commercial.response.wizard'
    _description = 'DTE Commercial Response Wizard'

    # ═══════════════════════════════════════════════════════════
    # FIELDS
    # ═══════════════════════════════════════════════════════════

    dte_inbox_id = fields.Many2one(
        'dte.inbox',
        string='DTE',
        required=True,
        ondelete='cascade'
    )

    dte_type = fields.Selection(
        related='dte_inbox_id.dte_type',
        string='DTE Type',
        readonly=True
    )

    folio = fields.Char(
        related='dte_inbox_id.folio',
        string='Folio',
        readonly=True
    )

    emisor_name = fields.Char(
        related='dte_inbox_id.emisor_name',
        string='Supplier',
        readonly=True
    )

    monto_total = fields.Monetary(
        related='dte_inbox_id.monto_total',
        string='Total Amount',
        readonly=True
    )

    currency_id = fields.Many2one(
        related='dte_inbox_id.currency_id'
    )

    response_code = fields.Selection([
        ('0', 'Accept Document'),
        ('1', 'Reject Document'),
        ('2', 'Claim - Accept with Observations'),
    ], string='Response', required=True, default='0')

    reason = fields.Text(
        string='Reason / Observations',
        help='Required for rejection or claim'
    )

    # ═══════════════════════════════════════════════════════════
    # VALIDATION
    # ═══════════════════════════════════════════════════════════

    @api.constrains('response_code', 'reason')
    def _check_reason(self):
        """Validate that reason is provided for reject/claim."""
        for wizard in self:
            if wizard.response_code in ['1', '2'] and not wizard.reason:
                raise UserError(
                    _('Reason is required when rejecting or claiming a document')
                )

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_send_response(self):
        """
        Send commercial response to SII.

        Response codes:
        - '0': Accept - Normal acceptance
        - '1': Reject - Document rejected
        - '2': Claim - Accept with observations/claims
        """
        self.ensure_one()

        if self.dte_inbox_id.response_sent:
            raise UserError(_('Response has already been sent for this DTE'))

        try:
            # Get DTE Service URL
            dte_service_url = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.dte_service_url',
                'http://odoo-eergy-services:8001'
            )

            # Get company RUT
            company = self.env.company
            if not company.vat:
                raise UserError(_('Company RUT is not configured'))

            # Prepare request
            request_data = {
                'dte_type': self.dte_inbox_id.dte_type,
                'folio': self.dte_inbox_id.folio,
                'emisor_rut': self.dte_inbox_id.emisor_rut,
                'receptor_rut': company.vat,
                'response_code': self.response_code,
                'reason': self.reason or ''
            }

            _logger.info(f"Sending commercial response for DTE {self.dte_inbox_id.name}: {self.response_code}")

            # Call DTE Service
            response = requests.post(
                f"{dte_service_url}/api/v1/reception/send_response",
                json=request_data,
                timeout=60
            )

            if response.status_code != 200:
                raise UserError(
                    _('Failed to send response to SII: %s') % response.text
                )

            result = response.json()

            if not result.get('success'):
                raise UserError(
                    _('SII rejected the response: %s') % result.get('error', 'Unknown error')
                )

            # Update DTE inbox record
            update_vals = {
                'response_code': self.response_code,
                'response_reason': self.reason,
                'response_sent': True,
                'response_date': fields.Datetime.now(),
                'response_track_id': result.get('track_id'),
            }

            # Update state based on response
            if self.response_code == '0':
                update_vals['state'] = 'accepted'
            elif self.response_code == '1':
                update_vals['state'] = 'rejected'
            elif self.response_code == '2':
                update_vals['state'] = 'claimed'

            self.dte_inbox_id.write(update_vals)

            # Post message
            response_names = {
                '0': 'Accepted',
                '1': 'Rejected',
                '2': 'Claimed (with observations)'
            }

            self.dte_inbox_id.message_post(
                body=_('Commercial response sent to SII: %s<br/>Track ID: %s<br/>Reason: %s') % (
                    response_names.get(self.response_code),
                    result.get('track_id', 'N/A'),
                    self.reason or 'N/A'
                )
            )

            _logger.info(f"Commercial response sent successfully for DTE {self.dte_inbox_id.name}")

            # Show success message
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Success'),
                    'message': _('Commercial response sent to SII successfully'),
                    'type': 'success',
                    'sticky': False,
                }
            }

        except requests.exceptions.Timeout:
            raise UserError(_('Connection to DTE Service timed out'))
        except requests.exceptions.ConnectionError:
            raise UserError(_('Could not connect to DTE Service'))
        except Exception as e:
            _logger.error(f"Failed to send commercial response: {e}")
            raise UserError(_('Failed to send response: %s') % str(e))

    def action_cancel(self):
        """Cancel wizard."""
        return {'type': 'ir.actions.act_window_close'}
