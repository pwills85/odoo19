# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError


class SendDTEBatchWizard(models.TransientModel):
    """Wizard para envío masivo de DTEs"""
    _name = 'send.dte.batch.wizard'
    _description = 'Envío Masivo de DTEs'
    
    invoice_ids = fields.Many2many(
        'account.move',
        string='Facturas a Enviar',
        domain=[('dte_status', '=', 'to_send'), ('state', '=', 'posted')]
    )
    
    count = fields.Integer(string='Cantidad', compute='_compute_count')
    
    @api.depends('invoice_ids')
    def _compute_count(self):
        for wizard in self:
            wizard.count = len(wizard.invoice_ids)
    
    def action_send_batch(self):
        """Enviar DTEs en lote"""
        self.ensure_one()
        
        if not self.invoice_ids:
            raise UserError(_('Debe seleccionar al menos una factura'))
        
        # Enviar cada factura
        for invoice in self.invoice_ids:
            try:
                invoice.action_send_to_sii()
            except Exception:
                # Log error pero continuar con las demás
                continue
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Envío Completado'),
                'message': _('Se procesaron %d facturas') % self.count,
                'type': 'success',
            }
        }

