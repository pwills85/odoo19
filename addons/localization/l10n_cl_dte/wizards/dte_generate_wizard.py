# -*- coding: utf-8 -*-
"""
DTE Generate Wizard - MINIMAL VERSION (ETAPA 2)
==============================================

Wizard simplificado para ETAPA 2.
Solo valida que el wizard abre correctamente.
Implementación completa se realizará en ETAPA 4.
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError

class DTEGenerateWizard(models.TransientModel):
    _name = 'dte.generate.wizard'
    _description = 'Generate DTE Wizard (Minimal)'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    move_id = fields.Many2one(
        'account.move',
        string='Invoice',
        required=True,
        readonly=True,
        default=lambda self: self.env.context.get('active_id')
    )

    dte_code = fields.Char(
        related='move_id.dte_code',
        string='DTE Type',
        readonly=True
    )

    certificate_id = fields.Many2one(
        'dte.certificate',
        string='Digital Certificate',
        required=True,
        domain="[('company_id', '=', company_id), ('active', '=', True)]"
    )

    caf_id = fields.Many2one(
        'dte.caf',
        string='CAF (Folio Authorization)',
        required=True,
        domain="[('company_id', '=', company_id), ('dte_type', '=', dte_code), ('state', '=', 'active')]"
    )

    environment = fields.Selection([
        ('sandbox', 'Sandbox (Maullin)'),
        ('production', 'Production (Palena)'),
    ], string='SII Environment', default='sandbox', required=True)

    company_id = fields.Many2one(
        related='move_id.company_id',
        store=True
    )

    status_message = fields.Text(
        string='Status',
        readonly=True,
        default='✅ ETAPA 2: Wizard minimal funcional.\n'
                'La generación real de DTEs se implementará en ETAPA 4.'
    )

    # ═══════════════════════════════════════════════════════════
    # ONCHANGE METHODS
    # ═══════════════════════════════════════════════════════════

    @api.onchange('certificate_id')
    def _onchange_certificate(self):
        """Auto-fill CAF when certificate changes."""
        if self.certificate_id and self.dte_code:
            caf = self.env['dte.caf'].search([
                ('company_id', '=', self.company_id.id),
                ('dte_type', '=', self.dte_code),
                ('state', '=', 'active'),
                ('folios_disponibles', '>', 0),
            ], limit=1)

            self.caf_id = caf if caf else False

    # ═══════════════════════════════════════════════════════════
    # VALIDATIONS
    # ═══════════════════════════════════════════════════════════

    def _validate_pre_generation(self):
        """Pre-flight checks - MINIMAL VERSION"""
        self.ensure_one()

        # 1. Invoice validations
        if self.move_id.state != 'posted':
            raise UserError(_('Invoice must be posted'))

        # 2. Company validations
        if not self.company_id.vat:
            raise UserError(_('Company RUT is not configured'))

        # 3. Partner validations
        if not self.move_id.partner_id.vat:
            raise UserError(_('Customer RUT is required'))

        # 4. Certificate validations
        if not self.certificate_id:
            raise UserError(_('Digital certificate is required'))

        # 5. CAF validations
        if not self.caf_id:
            raise UserError(_('CAF (Folio Authorization) is required'))

        return True

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_generate_dte(self):
        """
        ETAPA 2: STUB IMPLEMENTATION

        Valida que el wizard abre y funciona correctamente.
        Solo registra la configuración seleccionada.
        NO genera DTE real (implementación en ETAPA 4).
        """
        self.ensure_one()

        # Validaciones básicas
        self._validate_pre_generation()

        # Registrar configuración en factura
        self.move_id.write({
            'dte_certificate_id': self.certificate_id.id,
            'dte_caf_id': self.caf_id.id,
            'dte_environment': self.environment,
        })

        # Log en chatter
        self.move_id.message_post(
            body=_(
                '✅ <strong>DTE Wizard Configurado (ETAPA 2)</strong><br/>'
                'Certificado: %s<br/>'
                'CAF: %s<br/>'
                'Ambiente: %s<br/>'
                '<em>Generación real de DTEs se implementará en ETAPA 4.</em>'
            ) % (
                self.certificate_id.name,
                self.caf_id.name,
                self.environment
            )
        )

        # Notificación usuario
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('✅ Wizard Activado Exitosamente'),
                'message': _(
                    'ETAPA 2 Completada: Wizard funciona correctamente.\n\n'
                    'Configuración guardada:\n'
                    '• Certificado: %s\n'
                    '• Ambiente: %s\n\n'
                    'La generación de DTEs se implementará en ETAPA 4.'
                ) % (self.certificate_id.name, self.environment),
                'type': 'success',
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            }
        }

    def action_cancel(self):
        """Cancel wizard."""
        return {'type': 'ir.actions.act_window_close'}
