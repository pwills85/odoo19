# -*- coding: utf-8 -*-
"""
DTE Generate Wizard
===================

Professional wizard for generating and sending DTEs to SII.
Provides user-friendly interface with validation and feedback.

Architecture:
- Pre-flight checks (certificate, CAF, RUT validation)
- Progress indication
- Clear error messages
- Graceful handling of service unavailability
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import base64
import logging

_logger = logging.getLogger(__name__)


class DTEGenerateWizard(models.TransientModel):
    _name = 'dte.generate.wizard'
    _description = 'Generate DTE Wizard'
    _inherit = ['dte.service.integration']  # ⭐ Inherit integration layer

    # ═══════════════════════════════════════════════════════════
    # FIELDS
    # ═══════════════════════════════════════════════════════════

    move_id = fields.Many2one(
        'account.move',
        string='Invoice',
        required=True,
        readonly=True
    )

    dte_type = fields.Selection(
        related='move_id.dte_type',
        string='DTE Type',
        readonly=True
    )

    # Certificate selection
    certificate_id = fields.Many2one(
        'dte.certificate',
        string='Digital Certificate',
        required=True,
        domain="[('company_id', '=', company_id), ('active', '=', True)]"
    )

    # CAF selection
    caf_id = fields.Many2one(
        'dte.caf',
        string='CAF (Folio Authorization)',
        required=True,
        domain="[('company_id', '=', company_id), ('dte_type', '=', dte_type), ('state', '=', 'active')]"
    )

    # Environment
    environment = fields.Selection([
        ('sandbox', 'Sandbox (Maullin)'),
        ('production', 'Production (Palena)'),
    ], string='SII Environment', default='sandbox', required=True)

    # Company
    company_id = fields.Many2one(
        related='move_id.company_id',
        store=True
    )

    # Status display
    status_message = fields.Text(
        string='Status',
        readonly=True,
        default='Ready to generate DTE'
    )

    # Service health
    service_available = fields.Boolean(
        string='DTE Service Available',
        compute='_compute_service_health'
    )

    service_status_message = fields.Char(
        string='Service Status',
        compute='_compute_service_health'
    )

    # Contingency mode
    contingency_active = fields.Boolean(
        string='Contingency Mode Active',
        compute='_compute_contingency_status'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTE METHODS
    # ═══════════════════════════════════════════════════════════

    @api.depends('certificate_id')
    def _compute_service_health(self):
        """Check DTE Service health."""
        for wizard in self:
            health = self.check_dte_service_health()

            wizard.service_available = health.get('available', False)

            if health.get('available'):
                sii_status = 'available' if health.get('sii_available') else 'unavailable'
                wizard.service_status_message = f"Service: OK | SII: {sii_status}"
            else:
                wizard.service_status_message = f"Service: {health.get('error', 'Unavailable')}"

    @api.depends('certificate_id')
    def _compute_contingency_status(self):
        """Check contingency mode status."""
        for wizard in self:
            contingency_status = self.get_contingency_status()
            wizard.contingency_active = contingency_status.get('enabled', False)

    @api.onchange('certificate_id')
    def _onchange_certificate(self):
        """Auto-fill CAF when certificate changes."""
        if self.certificate_id and self.dte_type:
            # Find available CAF for this DTE type
            caf = self.env['dte.caf'].search([
                ('company_id', '=', self.company_id.id),
                ('dte_type', '=', self.dte_type),
                ('state', '=', 'active'),
                ('available_folios', '>', 0),
            ], limit=1)

            if caf:
                self.caf_id = caf
            else:
                self.caf_id = False

    # ═══════════════════════════════════════════════════════════
    # VALIDATIONS
    # ═══════════════════════════════════════════════════════════

    def _validate_pre_generation(self):
        """
        Pre-flight checks before DTE generation.
        Raises UserError if validation fails.
        """
        self.ensure_one()

        # 1. Invoice validations
        if self.move_id.state != 'posted':
            raise UserError(_('Invoice must be posted'))

        if not self.move_id.invoice_line_ids:
            raise UserError(_('Invoice has no lines'))

        # 2. Company validations
        if not self.company_id.vat:
            raise UserError(_('Company RUT is not configured'))

        # 3. Partner validations
        if not self.move_id.partner_id.vat:
            raise UserError(_('Customer RUT is required'))

        # 4. Certificate validations
        if not self.certificate_id:
            raise UserError(_('Digital certificate is required'))

        if not self.certificate_id.cert_file or not self.certificate_id.password:
            raise UserError(_('Certificate file or password missing'))

        # Check certificate validity
        if self.certificate_id.date_end and self.certificate_id.date_end < fields.Date.today():
            raise UserError(_('Certificate has expired'))

        # 5. CAF validations
        if not self.caf_id:
            raise UserError(_('CAF (Folio Authorization) is required'))

        if self.caf_id.available_folios <= 0:
            raise UserError(_('CAF has no available folios. Please request new CAF from SII'))

        # 6. Service health check
        if not self.service_available:
            # Warn but allow (contingency mode)
            if not self.contingency_active:
                raise UserError(
                    _('DTE Service is unavailable and contingency mode is not active.\n\n'
                      'Please contact support or enable contingency mode.')
                )

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_generate_dte(self):
        """
        Main action: Generate and send DTE to SII.
        """
        self.ensure_one()

        try:
            # 1. Pre-flight validations
            self._validate_pre_generation()

            # 2. Prepare DTE data
            dte_data = self._prepare_dte_data()

            # 3. Prepare certificate data
            certificate_data = self._prepare_certificate_data()

            # 4. Update status
            self.move_id.write({
                'dte_status': 'sending',
                'dte_certificate_id': self.certificate_id.id,
                'dte_caf_id': self.caf_id.id,
            })

            # 5. Call DTE Service
            _logger.info(f"Generating DTE for invoice {self.move_id.name}")

            result = self.generate_and_send_dte(
                dte_data=dte_data,
                certificate_data=certificate_data,
                environment=self.environment
            )

            # 6. Process result
            if result.get('success'):
                self._process_success(result)
            else:
                self._process_error(result)

            # 7. Return notification
            return self._show_notification(result)

        except UserError:
            # Re-raise validation errors
            self.move_id.write({'dte_status': 'draft'})
            raise

        except Exception as e:
            # Catch unexpected errors
            _logger.error(f"DTE generation failed: {e}", exc_info=True)

            self.move_id.write({
                'dte_status': 'error',
                'dte_error_message': str(e),
            })

            raise UserError(_('DTE generation failed:\n\n%s') % str(e))

    def _prepare_dte_data(self):
        """
        Prepare invoice data for DTE Service.
        Delegates to account.move method.
        """
        return self.move_id._prepare_dte_data()

    def _prepare_certificate_data(self):
        """
        Prepare certificate data for DTE Service.
        Delegates to account.move method.
        """
        return self.move_id._get_certificate_data()

    def _process_success(self, result):
        """Process successful DTE generation."""
        # Decode XML
        dte_xml = base64.b64decode(result['xml_b64']) if result.get('xml_b64') else False

        # Update invoice
        update_vals = {
            'dte_status': 'contingency' if self.contingency_active else 'sent',
            'dte_folio': result.get('folio'),
            'dte_track_id': result.get('track_id'),
            'dte_xml': dte_xml,
            'dte_sent_date': fields.Datetime.now(),
            'dte_error_message': False,
            'is_contingency': self.contingency_active,
        }

        # QR Code
        if result.get('qr_image_b64'):
            update_vals['dte_qr_image'] = base64.b64decode(result['qr_image_b64'])

        # Response XML
        if result.get('response_xml'):
            update_vals['dte_response_xml'] = result['response_xml']

        self.move_id.write(update_vals)

        # Consume CAF folio
        self.caf_id._consume_folio(result.get('folio'))

        # Post message
        if self.contingency_active:
            self.move_id.message_post(
                body=_('DTE generated in contingency mode (folio: %s). '
                       'Will be sent to SII when service recovers.') % result.get('folio')
            )
        else:
            self.move_id.message_post(
                body=_('DTE sent to SII (Track ID: %s, Folio: %s)') % (
                    result.get('track_id'),
                    result.get('folio')
                )
            )

        _logger.info(f"DTE generation successful for invoice {self.move_id.name}")

    def _process_error(self, result):
        """Process failed DTE generation."""
        error_message = result.get('error_message', 'Unknown error')

        self.move_id.write({
            'dte_status': 'error',
            'dte_error_message': error_message,
        })

        self.move_id.message_post(
            body=_('DTE generation failed: %s') % error_message,
            message_type='notification'
        )

        _logger.error(f"DTE generation failed for invoice {self.move_id.name}: {error_message}")

    def _show_notification(self, result):
        """Show user notification."""
        if result.get('success'):
            if self.contingency_active:
                title = _('DTE Generated (Contingency)')
                message = _('DTE generated with folio %s.\n'
                           'Document stored locally and will be sent to SII when service recovers.') % result.get('folio')
                notification_type = 'warning'
            else:
                title = _('DTE Sent Successfully')
                message = _('DTE sent to SII with Track ID: %s\n'
                           'Folio: %s') % (result.get('track_id'), result.get('folio'))
                notification_type = 'success'
        else:
            title = _('DTE Generation Failed')
            message = result.get('error_message', 'Unknown error')
            notification_type = 'danger'

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': title,
                'message': message,
                'type': notification_type,
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            }
        }

    def action_cancel(self):
        """Cancel wizard."""
        return {'type': 'ir.actions.act_window_close'}
