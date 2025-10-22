# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from odoo.addons.l10n_cl_dte.tools.rut_validator import validate_rut
import logging

_logger = logging.getLogger(__name__)


class PurchaseOrderDTE(models.Model):
    """
    Extensión de purchase.order para DTE 34 (Liquidación de Honorarios)
    
    ESTRATEGIA: EXTENDER purchase.order de Odoo base
    Reutilizamos todo el workflow de compras de Odoo
    """
    _inherit = 'purchase.order'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS DTE 34 (LIQUIDACIÓN HONORARIOS)
    # ═══════════════════════════════════════════════════════════
    
    es_liquidacion_honorarios = fields.Boolean(
        string='Es Liquidación de Honorarios',
        default=False,
        help='Marcar si es pago a profesional independiente (DTE 34)'
    )
    
    profesional_rut = fields.Char(
        string='RUT Profesional',
        help='RUT del profesional que recibe el pago'
    )
    
    profesional_nombre = fields.Char(
        string='Nombre Profesional',
        help='Nombre del profesional'
    )
    
    periodo_servicio_inicio = fields.Date(
        string='Período Servicio: Desde',
        help='Inicio del período de servicios prestados'
    )
    
    periodo_servicio_fin = fields.Date(
        string='Período Servicio: Hasta',
        help='Fin del período de servicios prestados'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RETENCIÓN IUE (Impuesto Único Empleador)
    # ═══════════════════════════════════════════════════════════
    
    retencion_iue_porcentaje = fields.Float(
        string='% Retención IUE',
        default=10.0,
        help='Porcentaje de retención (típicamente 10%)'
    )
    
    monto_bruto_honorarios = fields.Monetary(
        string='Monto Bruto',
        compute='_compute_monto_bruto_honorarios',
        store=True,
        help='Suma de líneas de la orden'
    )
    
    monto_retencion_iue = fields.Monetary(
        string='Monto Retención IUE',
        compute='_compute_retencion_iue',
        store=True,
        help='Monto a retener = Monto bruto × % retención'
    )
    
    monto_neto_a_pagar = fields.Monetary(
        string='Monto Neto a Pagar',
        compute='_compute_monto_neto',
        store=True,
        help='Monto a pagar = Monto bruto - Retención'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO DTE 34
    # ═══════════════════════════════════════════════════════════
    
    dte_34_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
    ], string='Estado DTE 34', default='draft', copy=False)
    
    dte_34_folio = fields.Char(
        string='Folio DTE 34',
        readonly=True,
        copy=False,
        index=True
    )
    
    dte_34_xml = fields.Binary(
        string='XML DTE 34',
        readonly=True,
        copy=False,
        attachment=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIÓN CON RETENCIONES
    # ═══════════════════════════════════════════════════════════
    
    retencion_iue_id = fields.Many2one(
        'retencion.iue',
        string='Registro Retención',
        help='Registro de retención mensual asociado'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('order_line.price_subtotal')
    def _compute_monto_bruto_honorarios(self):
        """Calcula monto bruto como suma de líneas"""
        for order in self:
            if order.es_liquidacion_honorarios:
                order.monto_bruto_honorarios = sum(
                    line.price_subtotal for line in order.order_line
                )
            else:
                order.monto_bruto_honorarios = 0.0
    
    @api.depends('monto_bruto_honorarios', 'retencion_iue_porcentaje')
    def _compute_retencion_iue(self):
        """Calcula retención IUE"""
        for order in self:
            if order.es_liquidacion_honorarios:
                order.monto_retencion_iue = (
                    order.monto_bruto_honorarios * 
                    order.retencion_iue_porcentaje / 100.0
                )
            else:
                order.monto_retencion_iue = 0.0
    
    @api.depends('monto_bruto_honorarios', 'monto_retencion_iue')
    def _compute_monto_neto(self):
        """Calcula monto neto a pagar"""
        for order in self:
            order.monto_neto_a_pagar = (
                order.monto_bruto_honorarios - 
                order.monto_retencion_iue
            )
    
    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('profesional_rut')
    def _check_profesional_rut(self):
        """Valida RUT del profesional"""
        for order in self:
            if order.es_liquidacion_honorarios and order.profesional_rut:
                if not validate_rut(order.profesional_rut):
                    raise ValidationError(
                        _('El RUT del profesional es inválido: %s') % order.profesional_rut
                    )
    
    @api.constrains('retencion_iue_porcentaje')
    def _check_retencion_porcentaje(self):
        """Valida porcentaje de retención"""
        for order in self:
            if order.es_liquidacion_honorarios:
                if not (0 <= order.retencion_iue_porcentaje <= 100):
                    raise ValidationError(
                        _('El porcentaje de retención debe estar entre 0% y 100%')
                    )
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_generar_liquidacion_dte34(self):
        """
        Genera DTE 34 (Liquidación de Honorarios)
        """
        self.ensure_one()
        
        if not self.es_liquidacion_honorarios:
            raise ValidationError(_('Esta orden no es una liquidación de honorarios'))
        
        # Validar datos
        self._validate_liquidacion_data()
        
        # Llamar DTE Service para generar DTE 34
        # TODO: Implementar llamada a DTE Service
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Generación de DTE 34 pendiente de implementación completa'),
                'type': 'info',
            }
        }
    
    def _validate_liquidacion_data(self):
        """Validaciones para liquidación de honorarios"""
        self.ensure_one()
        
        if not self.profesional_rut:
            raise ValidationError(_('Debe ingresar el RUT del profesional'))
        
        if not self.profesional_nombre:
            raise ValidationError(_('Debe ingresar el nombre del profesional'))
        
        if not self.periodo_servicio_inicio or not self.periodo_servicio_fin:
            raise ValidationError(_('Debe ingresar el período de servicios'))
        
        if self.monto_bruto_honorarios <= 0:
            raise ValidationError(_('El monto debe ser mayor a cero'))

