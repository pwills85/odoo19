# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class StockPickingDTE(models.Model):
    """
    Extensión de stock.picking para DTE 52 (Guía de Despacho)
    
    ESTRATEGIA: EXTENDER stock.picking de Odoo base
    Reutilizamos todo el workflow de inventario de Odoo
    """
    _inherit = 'stock.picking'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS DTE 52 (GUÍA DE DESPACHO)
    # ═══════════════════════════════════════════════════════════
    
    genera_dte_52 = fields.Boolean(
        string='Genera Guía Electrónica',
        default=False,
        help='Marcar para generar DTE 52 (Guía de Despacho Electrónica)'
    )
    
    dte_52_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
    ], string='Estado DTE 52', default='draft', copy=False)
    
    dte_52_folio = fields.Char(
        string='Folio DTE 52',
        readonly=True,
        copy=False,
        index=True,
        help='Folio de la guía electrónica'
    )
    
    dte_52_xml = fields.Binary(
        string='XML DTE 52',
        readonly=True,
        copy=False,
        attachment=True
    )
    
    dte_52_timestamp = fields.Datetime(
        string='Timestamp DTE 52',
        readonly=True,
        copy=False
    )
    
    # ═══════════════════════════════════════════════════════════
    # DATOS ADICIONALES PARA GUÍA
    # ═══════════════════════════════════════════════════════════
    
    tipo_traslado = fields.Selection([
        ('1', 'Operación constituye venta'),
        ('2', 'Venta por efectuar'),
        ('3', 'Consignaciones'),
        ('4', 'Entrega gratuita'),
        ('5', 'Traslado interno'),
        ('6', 'Otros traslados'),
        ('7', 'Guía de devolución'),
        ('8', 'Traslado para exportación'),
        ('9', 'Venta para exportación'),
    ], string='Tipo de Traslado',
       default='1',
       help='Indica el motivo del traslado según clasificación SII')
    
    patente_vehiculo = fields.Char(
        string='Patente Vehículo',
        help='Patente del vehículo de transporte (opcional)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIÓN CON FACTURA
    # ═══════════════════════════════════════════════════════════
    
    invoice_id = fields.Many2one(
        'account.move',
        string='Factura Relacionada',
        help='Factura asociada a esta guía de despacho',
        domain=[('move_type', '=', 'out_invoice')]
    )
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_generar_dte_52(self):
        """
        Genera DTE 52 (Guía de Despacho Electrónica)
        """
        self.ensure_one()
        
        if not self.genera_dte_52:
            raise ValidationError(_('Esta guía no genera DTE electrónico'))
        
        if self.state != 'done':
            raise ValidationError(_('Solo se pueden generar DTEs de guías validadas'))
        
        # Validar datos
        self._validate_guia_data()
        
        # Llamar DTE Service para generar DTE 52
        # TODO: Implementar llamada a DTE Service
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Generación de DTE 52 pendiente de implementación completa'),
                'type': 'info',
            }
        }
    
    def _validate_guia_data(self):
        """Validaciones para guía de despacho"""
        self.ensure_one()
        
        if not self.partner_id:
            raise ValidationError(_('Debe especificar el destinatario'))
        
        if not self.partner_id.vat:
            raise ValidationError(_('El destinatario debe tener RUT configurado'))
        
        if not self.move_ids_without_package:
            raise ValidationError(_('La guía debe tener productos'))
    
    def button_validate(self):
        """Override para marcar DTE 52 como 'por enviar' al validar"""
        result = super().button_validate()
        
        for picking in self:
            if picking.genera_dte_52 and picking.state == 'done':
                picking.write({'dte_52_status': 'to_send'})
        
        return result

