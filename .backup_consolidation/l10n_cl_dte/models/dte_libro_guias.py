# -*- coding: utf-8 -*-
"""
Libro de Guías de Despacho Electrónico

Reporte mensual de guías de despacho (DTE 52) emitidas.
Similar a Libro Compra/Venta pero específico para guías.
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class DTELibroGuias(models.Model):
    """
    Libro de Guías de Despacho

    Reporte mensual opcional (pero recomendado) de guías de despacho.
    Sigue el mismo patrón que dte.libro para consistencia.
    """
    _name = 'dte.libro.guias'
    _description = 'Libro de Guías de Despacho'
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
    # PERÍODO
    # ═══════════════════════════════════════════════════════════

    periodo_mes = fields.Date(
        string='Período (Mes)',
        required=True,
        default=fields.Date.today,
        help='Mes del libro de guías'
    )

    # ═══════════════════════════════════════════════════════════
    # GUÍAS INCLUIDAS
    # ═══════════════════════════════════════════════════════════

    picking_ids = fields.Many2many(
        'stock.picking',
        'libro_guias_picking_rel',
        'libro_id',
        'picking_id',
        string='Guías de Despacho',
        help='Guías incluidas en el libro',
        domain="[('dte_52_status', '=', 'accepted'), ('company_id', '=', company_id)]"  # ⭐ CORREGIDO: dte_status → dte_52_status, eliminado dte_type (siempre es 52)
    )

    cantidad_guias = fields.Integer(
        string='Cantidad Guías',
        compute='_compute_cantidad_guias',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # TOTALES
    # ═══════════════════════════════════════════════════════════

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
    # ESTADO Y ARCHIVOS
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('generated', 'Generado'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
    ], string='Estado', default='draft', tracking=True)

    xml_file = fields.Binary(
        string='Archivo XML',
        readonly=True,
        attachment=True
    )

    xml_filename = fields.Char(
        string='Nombre Archivo',
        compute='_compute_xml_filename'
    )

    track_id = fields.Char(
        string='Track ID SII',
        readonly=True,
        help='Track ID de la solicitud al SII'
    )

    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════

    @api.depends('periodo_mes')
    def _compute_name(self):
        """Genera nombre descriptivo del libro"""
        for record in self:
            if record.periodo_mes:
                mes = record.periodo_mes.strftime('%B %Y')
                record.name = f'Libro Guías - {mes}'
            else:
                record.name = 'Libro Guías - (Sin período)'

    @api.depends('picking_ids')
    def _compute_cantidad_guias(self):
        """Cuenta guías incluidas en el libro"""
        for record in self:
            record.cantidad_guias = len(record.picking_ids)

    @api.depends('picking_ids')
    def _compute_totales(self):
        """
        Calcula total de montos de las guías.

        Nota: Guías pueden tener monto 0 (traslado sin venta)
        """
        for record in self:
            # Suma de montos totales de DTEs
            total = sum(
                picking.sale_id.amount_total if picking.sale_id else 0.0
                for picking in record.picking_ids
            )
            record.total_monto = total

    @api.depends('periodo_mes')
    def _compute_xml_filename(self):
        """Genera nombre del archivo XML"""
        for record in self:
            if record.periodo_mes:
                periodo_str = record.periodo_mes.strftime('%Y%m')
                record.xml_filename = f'LibroGuias_{periodo_str}.xml'
            else:
                record.xml_filename = 'LibroGuias.xml'

    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════

    def action_agregar_guias(self):
        """
        Agrega automáticamente todas las guías del período.

        Query eficiente usando ORM de Odoo 19.
        """
        self.ensure_one()

        # Calcular rango del mes
        primer_dia = self.periodo_mes.replace(day=1)
        ultimo_dia = primer_dia + relativedelta(months=1, days=-1)

        # Domain para buscar guías
        domain = [
            ('scheduled_date', '>=', primer_dia),
            ('scheduled_date', '<=', ultimo_dia),
            ('picking_type_code', '=', 'outgoing'),  # Solo salidas
            ('dte_type', '=', '52'),  # Solo guías de despacho
            ('dte_status', '=', 'accepted'),  # Solo aceptadas por SII
            ('company_id', '=', self.company_id.id),
        ]

        # Buscar guías
        guias = self.env['stock.picking'].search(domain)

        # Asignar a picking_ids
        self.write({'picking_ids': [(6, 0, guias.ids)]})

        _logger.info(
            f"Libro Guías {self.id}: Agregadas {len(guias)} guías del período {self.periodo_mes}"
        )

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Guías Agregadas'),
                'message': _('Se agregaron %d guías de despacho al libro') % len(guias),
                'type': 'success',
                'sticky': False,
            }
        }

    def action_generar_y_enviar(self):
        """
        Genera XML del libro de guías y envía al SII.

        Llama a DTE Service para generación técnica.
        """
        self.ensure_one()

        # Validaciones
        if not self.picking_ids:
            raise ValidationError(_('Debe agregar guías al libro primero'))

        if self.state != 'draft':
            raise ValidationError(_('Solo se pueden enviar libros en estado borrador'))

        # Preparar datos para DTE Service
        try:
            libro_data = self._prepare_libro_guias_data()

            _logger.info(
                f"Libro Guías {self.id}: Enviando {len(self.picking_ids)} guías al DTE Service"
            )

            # TODO: Llamar a DTE Service
            # response = self._call_dte_service(
            #     endpoint='/api/libro-guias/generate-and-send',
            #     data=libro_data
            # )

            # Por ahora, placeholder (hasta implementar endpoint DTE Service)
            _logger.warning(
                "Libro Guías: Endpoint DTE Service no implementado aún. "
                "Marcando como generado (placeholder)"
            )

            self.write({'state': 'generated'})

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('En Desarrollo'),
                    'message': _('Generación de libro de guías se completará en integración final con DTE Service'),
                    'type': 'info',
                    'sticky': True,
                }
            }

        except Exception as e:
            _logger.error(f"Error generando libro de guías {self.id}: {str(e)}")
            raise ValidationError(
                _('Error al generar libro de guías: %s') % str(e)
            )

    def _prepare_libro_guias_data(self):
        """
        Transforma datos de Odoo → formato DTE Service.

        Sigue el patrón de dte_libro.py
        """
        self.ensure_one()

        # Obtener datos de certificado/resolución
        company = self.company_id
        if not company.dte_resolution_number or not company.dte_resolution_date:
            raise ValidationError(
                _('Debe configurar el número y fecha de resolución SII en la empresa')
            )

        # Preparar lista de guías
        guias_data = []
        for picking in self.picking_ids:
            if not picking.dte_folio:
                _logger.warning(f"Picking {picking.id} sin folio DTE, saltando...")
                continue

            guia_dict = {
                'folio': picking.dte_folio,
                'fecha': picking.scheduled_date.strftime('%Y-%m-%d') if picking.scheduled_date else '',
                'rut_destinatario': picking.partner_id.vat or '',
                'razon_social': picking.partner_id.name or 'Sin nombre',
                'monto_total': picking.sale_id.amount_total if picking.sale_id else 0.0,
            }
            guias_data.append(guia_dict)

        # Estructura JSON para DTE Service
        return {
            'rut_emisor': company.vat,
            'periodo': self.periodo_mes.strftime('%Y-%m'),
            'fecha_resolucion': company.dte_resolution_date.strftime('%Y-%m-%d'),
            'nro_resolucion': company.dte_resolution_number,
            'guias': guias_data,
        }

    def action_consultar_estado_sii(self):
        """Consulta estado del libro en SII"""
        self.ensure_one()

        if not self.track_id:
            raise ValidationError(_('No hay Track ID para consultar'))

        # TODO: Implementar consulta a SII
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Consulta Estado'),
                'message': _('Funcionalidad en desarrollo'),
                'type': 'info',
            }
        }

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINS Y VALIDACIONES
    # ═══════════════════════════════════════════════════════════

    @api.constrains('picking_ids')
    def _check_picking_ids(self):
        """Valida que todas las guías sean del mismo mes y empresa"""
        for record in self:
            if not record.picking_ids:
                continue

            primer_dia = record.periodo_mes.replace(day=1)
            ultimo_dia = primer_dia + relativedelta(months=1, days=-1)

            for picking in record.picking_ids:
                # Validar empresa
                if picking.company_id != record.company_id:
                    raise ValidationError(
                        _('Todas las guías deben ser de la misma empresa')
                    )

                # Validar DTE 52
                if picking.dte_type != '52':
                    raise ValidationError(
                        _('Solo se permiten guías de despacho (DTE 52)')
                    )

                # Validar estado aceptado
                if picking.dte_status != 'accepted':
                    raise ValidationError(
                        _('Solo se permiten guías aceptadas por el SII')
                    )

                # Validar que estén en el período
                if picking.scheduled_date:
                    if not (primer_dia <= picking.scheduled_date.date() <= ultimo_dia):
                        raise ValidationError(
                            _('La guía %s está fuera del período seleccionado') % picking.name
                        )
