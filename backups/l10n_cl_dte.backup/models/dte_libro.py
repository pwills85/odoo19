# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class DTELibro(models.Model):
    """
    Libro de Compra/Venta Electrónico
    
    Reporte mensual obligatorio al SII con detalle de todas las
    operaciones de compra o venta del período.
    """
    _name = 'dte.libro'
    _description = 'Libro Electrónico Compra/Venta'
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
    # TIPO Y PERÍODO
    # ═══════════════════════════════════════════════════════════
    
    tipo_libro = fields.Selection([
        ('venta', 'Libro de Ventas'),
        ('compra', 'Libro de Compras'),
    ], string='Tipo de Libro', required=True, default='venta')
    
    periodo_mes = fields.Date(
        string='Período (Mes)',
        required=True,
        default=fields.Date.today,
        help='Mes del libro electrónico'
    )
    
    # ═══════════════════════════════════════════════════════════
    # DOCUMENTOS INCLUIDOS
    # ═══════════════════════════════════════════════════════════
    
    move_ids = fields.Many2many(
        'account.move',
        string='Documentos',
        help='Facturas/Compras incluidas en el libro'
    )
    
    cantidad_documentos = fields.Integer(
        string='Cantidad Documentos',
        compute='_compute_cantidad_documentos',
        store=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # TOTALES (Usando @api.depends de Odoo 19)
    # ═══════════════════════════════════════════════════════════
    
    total_neto = fields.Monetary(
        string='Total Neto',
        compute='_compute_totales',
        store=True,
        currency_field='currency_id'
    )
    
    total_iva = fields.Monetary(
        string='Total IVA',
        compute='_compute_totales',
        store=True,
        currency_field='currency_id'
    )
    
    total_monto = fields.Monetary(
        string='Monto Total',
        compute='_compute_totales',
        store=True,
        currency_field='currency_id'
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        default=lambda self: self.env.company.currency_id
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('generated', 'Generado'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
    ], string='Estado', default='draft', tracking=True)
    
    xml_file = fields.Binary(
        string='Archivo XML',
        readonly=True,
        attachment=True
    )
    
    track_id = fields.Char(
        string='Track ID SII',
        readonly=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS (Técnicas Odoo 19 CE)
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('periodo_mes', 'tipo_libro')
    def _compute_name(self):
        """Genera nombre descriptivo"""
        for record in self:
            tipo = 'Ventas' if record.tipo_libro == 'venta' else 'Compras'
            mes = record.periodo_mes.strftime('%B %Y') if record.periodo_mes else ''
            record.name = f'Libro {tipo} - {mes}'
    
    @api.depends('move_ids')
    def _compute_cantidad_documentos(self):
        """Cuenta documentos incluidos"""
        for record in self:
            record.cantidad_documentos = len(record.move_ids)
    
    @api.depends('move_ids.amount_untaxed', 'move_ids.amount_tax', 'move_ids.amount_total')
    def _compute_totales(self):
        """
        Calcula totales del libro.
        
        Usa mapped() de Odoo para eficiencia (técnica senior)
        """
        for record in self:
            record.total_neto = sum(record.move_ids.mapped('amount_untaxed'))
            record.total_iva = sum(record.move_ids.mapped('amount_tax'))
            record.total_monto = sum(record.move_ids.mapped('amount_total'))
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_agregar_documentos(self):
        """
        Agrega automáticamente todos los documentos del período.
        
        Query eficiente usando ORM de Odoo 19
        """
        self.ensure_one()
        
        # Calcular rango del mes
        primer_dia = self.periodo_mes.replace(day=1)
        
        from dateutil.relativedelta import relativedelta
        ultimo_dia = (primer_dia + relativedelta(months=1, days=-1))
        
        # Construir domain según tipo de libro
        if self.tipo_libro == 'venta':
            move_types = ['out_invoice', 'out_refund']
        else:  # compra
            move_types = ['in_invoice', 'in_refund']
        
        domain = [
            ('invoice_date', '>=', primer_dia),
            ('invoice_date', '<=', ultimo_dia),
            ('move_type', 'in', move_types),
            ('state', '=', 'posted'),
            ('dte_status', '=', 'accepted'),  # Solo DTEs aceptados por SII
            ('company_id', '=', self.company_id.id),
        ]
        
        if self.dte_type:
            domain.append(('dte_type', '=', self.dte_type))
        
        if self.journal_id:
            domain.append(('journal_id', '=', self.journal_id.id))
        
        # Buscar documentos (ORM Odoo)
        documentos = self.env['account.move'].search(domain)
        
        # Asignar a move_ids
        self.write({'move_ids': [(6, 0, documentos.ids)]})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Documentos Agregados'),
                'message': _('Se agregaron %d documentos al libro') % len(documentos),
                'type': 'success',
            }
        }
    
    def action_generar_y_enviar(self):
        """
        Genera XML del libro y envía al SII.
        
        Llama a DTE Service para generación
        """
        self.ensure_one()
        
        if not self.move_ids:
            raise ValidationError(_('Debe agregar documentos al libro primero'))
        
        # TODO: Llamar a DTE Service para generar XML
        # Por ahora, placeholder
        
        self.write({'state': 'generated'})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Generación de libro se completará en integración final'),
                'type': 'info',
            }
        }

