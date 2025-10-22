# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class DTECommunication(models.Model):
    """
    Registro de Comunicaciones con el SII
    
    Almacena todas las comunicaciones SOAP con el SII para auditoría y trazabilidad.
    """
    _name = 'dte.communication'
    _description = 'Comunicación DTE con SII'
    _order = 'create_date desc'
    _rec_name = 'display_name'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    display_name = fields.Char(
        string='Nombre',
        compute='_compute_display_name',
        store=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIÓN CON DOCUMENTO
    # ═══════════════════════════════════════════════════════════
    
    move_id = fields.Many2one(
        'account.move',
        string='Factura',
        ondelete='cascade',
        help='Factura asociada a esta comunicación'
    )
    
    purchase_id = fields.Many2one(
        'purchase.order',
        string='Orden de Compra',
        ondelete='cascade',
        help='Orden de compra asociada (DTE 34)'
    )
    
    picking_id = fields.Many2one(
        'stock.picking',
        string='Guía de Despacho',
        ondelete='cascade',
        help='Guía de despacho asociada (DTE 52)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # DATOS DE LA COMUNICACIÓN
    # ═══════════════════════════════════════════════════════════
    
    action_type = fields.Selection([
        ('send_dte', 'Envío DTE'),
        ('query_status', 'Consulta Estado'),
        ('receive_dte', 'Recepción DTE'),
        ('send_consumo', 'Envío Consumo Folios'),
        ('send_libro', 'Envío Libro'),
        ('validate_dte', 'Validación DTE'),
    ], string='Tipo de Acción', required=True)
    
    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('61', 'Nota de Crédito'),
        ('56', 'Nota de Débito'),
        ('52', 'Guía de Despacho'),
        ('34', 'Liquidación de Honorarios'),
    ], string='Tipo DTE')
    
    dte_folio = fields.Char(
        string='Folio DTE',
        help='Folio del DTE enviado/recibido'
    )
    
    track_id = fields.Char(
        string='Track ID SII',
        help='ID de seguimiento retornado por el SII'
    )
    
    # ═══════════════════════════════════════════════════════════
    # REQUEST Y RESPONSE
    # ═══════════════════════════════════════════════════════════
    
    request_xml = fields.Text(
        string='Request XML',
        help='XML enviado al SII'
    )
    
    response_xml = fields.Text(
        string='Response XML',
        help='XML recibido del SII'
    )
    
    response_code = fields.Char(
        string='Código Respuesta',
        help='Código de respuesta del SII'
    )
    
    response_message = fields.Text(
        string='Mensaje Respuesta',
        help='Mensaje de respuesta del SII'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO Y TIMING
    # ═══════════════════════════════════════════════════════════
    
    status = fields.Selection([
        ('pending', 'Pendiente'),
        ('sent', 'Enviado'),
        ('success', 'Éxito'),
        ('error', 'Error'),
        ('timeout', 'Timeout'),
    ], string='Estado', default='pending', required=True)
    
    duration_ms = fields.Integer(
        string='Duración (ms)',
        help='Tiempo de respuesta en milisegundos'
    )
    
    error_message = fields.Text(
        string='Mensaje de Error',
        help='Detalle del error si existe'
    )
    
    # ═══════════════════════════════════════════════════════════
    # AUDITORÍA
    # ═══════════════════════════════════════════════════════════
    
    user_id = fields.Many2one(
        'res.users',
        string='Usuario',
        default=lambda self: self.env.user,
        help='Usuario que inició la comunicación'
    )
    
    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('action_type', 'dte_type', 'dte_folio', 'create_date')
    def _compute_display_name(self):
        """Genera nombre descriptivo"""
        for record in self:
            parts = []
            
            if record.action_type:
                parts.append(dict(record._fields['action_type'].selection).get(record.action_type, ''))
            
            if record.dte_type:
                parts.append(f"DTE {record.dte_type}")
            
            if record.dte_folio:
                parts.append(f"Folio {record.dte_folio}")
            
            if record.create_date:
                parts.append(record.create_date.strftime('%Y-%m-%d %H:%M'))
            
            record.display_name = ' - '.join(parts) if parts else 'Comunicación SII'
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.model
    def log_communication(self, action_type, status, **kwargs):
        """
        Registra una comunicación con el SII.
        
        Args:
            action_type: Tipo de acción ('send_dte', 'query_status', etc)
            status: Estado ('success', 'error', etc)
            **kwargs: Campos adicionales (dte_type, dte_folio, response_xml, etc)
        
        Returns:
            Registro de comunicación creado
        """
        vals = {
            'action_type': action_type,
            'status': status,
        }
        vals.update(kwargs)
        
        return self.create(vals)
    
    def action_retry(self):
        """Reintentar comunicación fallida"""
        self.ensure_one()
        
        if self.status != 'error':
            raise UserError(_('Solo se pueden reintentar comunicaciones con error.'))
        
        # Lógica de reintento según tipo de acción
        if self.action_type == 'send_dte' and self.move_id:
            return self.move_id.action_send_to_sii()
        
        raise UserError(_('Reintento no implementado para este tipo de acción.'))

