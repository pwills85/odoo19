# -*- coding: utf-8 -*-
"""
DTE Commercial Response Wizard
===============================

Wizard para enviar respuestas comerciales al SII (Aceptar/Rechazar/Reclamar).

P1-7 GAP CLOSURE: Migrated to native libs/ (no HTTP microservice).

Based on Odoo 18: l10n_cl_fe/wizards/dte_commercial_response.py
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
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

        P1-7 GAP CLOSURE: Now uses native libs/ instead of HTTP microservice.

        Response codes:
        - '0': Accept - Normal acceptance
        - '1': Reject - Document rejected (Claim)
        - '2': Reject Goods - Merchandise rejection
        """
        self.ensure_one()

        if self.dte_inbox_id.response_sent:
            raise UserError(_('Response has already been sent for this DTE'))

        try:
            # Get company
            company = self.env.company
            if not company.vat:
                raise UserError(_('Company RUT is not configured'))

            _logger.info(
                f"[CommResponse] Sending response for DTE {self.dte_inbox_id.name}: "
                f"code={self.response_code}"
            )

            # P1-7 GAP CLOSURE: Generate commercial response XML natively
            from ..libs.commercial_response_generator import CommercialResponseGenerator

            # Prepare response data
            response_data = {
                'response_type': self._get_response_type(self.response_code),
                'dte_type': self.dte_inbox_id.dte_type,
                'folio': self.dte_inbox_id.folio,
                'emisor_rut': self.dte_inbox_id.emisor_rut,
                'receptor_rut': company.vat,
                'fecha_recepcion': self.dte_inbox_id.fecha_recepcion.strftime('%Y-%m-%d') if self.dte_inbox_id.fecha_recepcion else fields.Date.today().strftime('%Y-%m-%d'),
                'estado_recepcion': self.response_code,
                'declaracion': self.reason or '',
                'contacto_nombre': self.env.user.name,
                'contacto_email': self.env.user.email,
            }

            # Generate XML
            generator = self.env['commercial.response.generator']
            response_xml = generator.generate_commercial_response_xml(response_data)

            _logger.debug(f"[CommResponse] XML generated ({len(response_xml)} bytes)")

            # Sign XML
            signed_xml = self.env['xml.signer'].sign_xml_dte(
                response_xml,
                certificate_id=company.dte_certificate_id.id
            )

            _logger.debug("[CommResponse] XML signed")

            # Send to SII using SOAP client
            soap_client = self.env['sii.soap.client']
            sii_result = soap_client.send_commercial_response_to_sii(
                signed_xml,
                company.vat
            )

            if not sii_result.get('success'):
                raise UserError(_(
                    'SII rejected the response: %s'
                ) % sii_result.get('error', 'Unknown error'))

            # Update DTE inbox record
            update_vals = {
                'response_code': self.response_code,
                'response_reason': self.reason,
                'response_sent': True,
                'response_date': fields.Datetime.now(),
                'response_track_id': sii_result.get('track_id'),
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
                '1': 'Rejected (Claim)',
                '2': 'Rejected Goods'
            }

            self.dte_inbox_id.message_post(
                body=_('Commercial response sent to SII: %s<br/>Track ID: %s<br/>Reason: %s') % (
                    response_names.get(self.response_code),
                    sii_result.get('track_id', 'N/A'),
                    self.reason or 'N/A'
                )
            )

            _logger.info(f"[CommResponse] ✅ Response sent successfully for DTE {self.dte_inbox_id.name}")

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

        except Exception as e:
            _logger.error(f"[CommResponse] ❌ Failed to send commercial response: {e}")
            raise UserError(_('Failed to send response: %s') % str(e))

    def _get_response_type(self, response_code):
        """
        Map response code to SII response type.

        Args:
            response_code: str ('0', '1', '2')

        Returns:
            str: Response type (RecepcionDTE, RCD, RechazoMercaderias)
        """
        mapping = {
            '0': 'RecepcionDTE',  # Normal acceptance
            '1': 'RCD',  # Reclamo de contenido (claim)
            '2': 'RechazoMercaderias',  # Merchandise rejection
        }
        return mapping.get(response_code, 'RecepcionDTE')

    def action_cancel(self):
        """Cancel wizard."""
        return {'type': 'ir.actions.act_window_close'}
