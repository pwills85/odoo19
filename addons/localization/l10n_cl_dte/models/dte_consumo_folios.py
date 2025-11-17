# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class DTEConsumoFolios(models.Model):
    """
    Reporte de Consumo de Folios
    
    Reporte mensual obligatorio al SII indicando los folios utilizados.
    Debe enviarse mensualmente o según uso.
    """
    _name = 'dte.consumo.folios'
    _description = 'Consumo de Folios'
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
    # PERÍODO Y TIPO
    # ═══════════════════════════════════════════════════════════
    
    periodo_mes = fields.Date(
        string='Período (Mes)',
        required=True,
        default=fields.Date.today,
        help='Mes del consumo de folios'
    )
    
    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Liquidación de Honorarios'),
        ('52', 'Guía de Despacho'),
        ('56', 'Nota de Débito'),
        ('61', 'Nota de Crédito'),
    ], string='Tipo DTE', required=True)
    
    journal_id = fields.Many2one(
        'account.journal',
        string='Diario',
        domain=[('is_dte_journal', '=', True)]
    )
    
    # ═══════════════════════════════════════════════════════════
    # RANGO DE FOLIOS
    # ═══════════════════════════════════════════════════════════
    
    folio_inicio = fields.Integer(
        string='Folio Inicial',
        help='Primer folio utilizado en el período'
    )
    
    folio_fin = fields.Integer(
        string='Folio Final',
        help='Último folio utilizado en el período'
    )
    
    cantidad_folios = fields.Integer(
        string='Cantidad de Folios',
        compute='_compute_cantidad_folios',
        store=True,
        help='Cantidad de folios utilizados'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO Y ARCHIVO
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
        readonly=True,
        help='ID de seguimiento del envío al SII'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('periodo_mes', 'dte_type', 'journal_id')
    def _compute_name(self):
        """Genera nombre descriptivo"""
        for record in self:
            parts = ['Consumo Folios']
            
            if record.periodo_mes:
                parts.append(record.periodo_mes.strftime('%B %Y'))
            
            if record.dte_type:
                dte_name = dict(record._fields['dte_type'].selection).get(record.dte_type, '')
                parts.append(f'DTE {dte_name}' if dte_name else f'DTE {record.dte_type}')
            
            if record.journal_id:
                parts.append(record.journal_id.name)
            
            record.name = ' - '.join(parts) if len(parts) > 1 else 'Consumo de Folios'
    
    @api.depends('folio_inicio', 'folio_fin')
    def _compute_cantidad_folios(self):
        """Calcula cantidad de folios"""
        for record in self:
            if record.folio_inicio and record.folio_fin:
                record.cantidad_folios = record.folio_fin - record.folio_inicio + 1
            else:
                record.cantidad_folios = 0
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_calcular_folios(self):
        """
        Calcula automáticamente los folios utilizados consultando facturas.
        
        Usa ORM de Odoo para query eficiente
        """
        self.ensure_one()
        
        # Calcular primer y último día del mes
        primer_dia = self.periodo_mes.replace(day=1)
        
        # Último día del mes (técnica Odoo 19)
        from dateutil.relativedelta import relativedelta
        ultimo_dia = (primer_dia + relativedelta(months=1, days=-1))
        
        # Query de facturas del período (ORM Odoo)
        domain = [
            ('invoice_date', '>=', primer_dia),
            ('invoice_date', '<=', ultimo_dia),
            ('dte_type', '=', self.dte_type),
            ('state', '=', 'posted'),
            ('dte_folio', '!=', False),
        ]
        
        if self.journal_id:
            domain.append(('journal_id', '=', self.journal_id.id))
        
        # Buscar facturas
        facturas = self.env['account.move'].search(domain, order='dte_folio asc')
        
        if not facturas:
            raise ValidationError(_('No se encontraron DTEs en el período seleccionado'))
        
        # Calcular rango
        folios = [int(f.dte_folio) for f in facturas if f.dte_folio.isdigit()]
        
        if folios:
            self.write({
                'folio_inicio': min(folios),
                'folio_fin': max(folios),
            })
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Folios Calculados'),
                'message': _('Rango: %d - %d (%d folios)') % (min(folios), max(folios), len(folios)),
                'type': 'success',
            }
        }
    
    def action_generar_y_enviar(self):
        """
        Genera XML de consumo y envía al SII.
        
        Llama a DTE Service para generación y envío
        """
        self.ensure_one()
        
        # Validar datos
        if not self.folio_inicio or not self.folio_fin:
            raise ValidationError(_('Debe calcular los folios primero'))
        
        # Preparar datos para DTE Service
        from odoo.addons.l10n_cl_dte.tools.dte_api_client import DTEApiClient
        
        client = DTEApiClient(self.env)
        
        # TODO: Implementar llamada real a DTE Service
        # Por ahora, placeholder
        
        self.write({'state': 'generated'})
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Envío de consumo de folios se completará en integración final'),
                'type': 'info',
            }
        }

