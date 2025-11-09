# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class RetencionIUE(models.Model):
    """
    Gestión de Retenciones IUE (Impuesto Único Empleador)
    
    Agrupa retenciones mensuales por profesional para reportes al SII
    """
    _name = 'retencion.iue'
    _description = 'Retención IUE'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'periodo_mes desc, id desc'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        compute='_compute_name',
        store=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )
    
    # ═══════════════════════════════════════════════════════════
    # DATOS DEL PROFESIONAL
    # ═══════════════════════════════════════════════════════════
    
    profesional_rut = fields.Char(
        string='RUT Profesional',
        required=True,
        index=True
    )
    
    profesional_nombre = fields.Char(
        string='Nombre Profesional',
        required=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # PERÍODO
    # ═══════════════════════════════════════════════════════════
    
    periodo_mes = fields.Date(
        string='Período (Mes)',
        required=True,
        help='Primer día del mes de retención'
    )
    
    # ═══════════════════════════════════════════════════════════
    # MONTOS
    # ═══════════════════════════════════════════════════════════
    
    monto_retenido_total = fields.Monetary(
        string='Monto Total Retenido',
        compute='_compute_monto_retenido',
        store=True,
        currency_field='currency_id'
    )
    
    monto_bruto_total = fields.Monetary(
        string='Monto Bruto Total',
        compute='_compute_monto_bruto',
        store=True,
        currency_field='currency_id'
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.company.currency_id
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('confirmed', 'Confirmado'),
        ('reported', 'Reportado a SII'),
        ('paid', 'Pagado al SII'),
    ], string='Estado', default='draft', tracking=True)
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════
    
    purchase_order_ids = fields.One2many(
        'purchase.order',
        'retencion_iue_id',
        string='Liquidaciones de Honorarios',
        help='Órdenes de compra con retención IUE'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('periodo_mes', 'profesional_nombre')
    def _compute_name(self):
        """Genera nombre descriptivo"""
        for record in self:
            if record.periodo_mes and record.profesional_nombre:
                mes = record.periodo_mes.strftime('%B %Y')
                record.name = f'Retención IUE {mes} - {record.profesional_nombre}'
            else:
                record.name = 'Nueva Retención IUE'
    
    @api.depends('purchase_order_ids.monto_retencion_iue')
    def _compute_monto_retenido(self):
        """Suma todas las retenciones del período"""
        for record in self:
            record.monto_retenido_total = sum(
                po.monto_retencion_iue 
                for po in record.purchase_order_ids
            )
    
    @api.depends('purchase_order_ids.monto_bruto_honorarios')
    def _compute_monto_bruto(self):
        """Suma todos los montos brutos del período"""
        for record in self:
            record.monto_bruto_total = sum(
                po.monto_bruto_honorarios 
                for po in record.purchase_order_ids
            )
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_generar_reporte_mensual(self):
        """Genera reporte mensual de retenciones para SII"""
        self.ensure_one()
        
        # TODO: Implementar generación de reporte
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Reporte de retenciones pendiente de implementación'),
                'type': 'info',
            }
        }

