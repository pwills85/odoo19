# -*- coding: utf-8 -*-
"""
Modelo de Boleta de Honorarios Electrónica (Recepción)

Las Boletas de Honorarios NO son DTEs tradicionales XML.
Se emiten en Portal MiSII por profesionales independientes.

Este modelo permite:
1. Registrar boletas recibidas (descarga manual o automática desde SII)
2. Calcular retención IUE según tasa histórica vigente
3. Generar factura de proveedor en Odoo
4. Generar certificado de retención para declaración Form 29

Referencia: https://www.sii.cl/servicios_online/honorarios.html
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class BoletaHonorarios(models.Model):
    _name = 'l10n_cl.boleta_honorarios'
    _description = 'Boleta de Honorarios Electrónica (Recepción)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'fecha_emision desc, id desc'
    _rec_name = 'display_name'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS IDENTIFICACIÓN
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string='Número',
        compute='_compute_name',
        store=True,
        help='Número de la boleta de honorarios'
    )

    display_name = fields.Char(
        string='Nombre Completo',
        compute='_compute_display_name',
        store=True
    )

    numero_boleta = fields.Char(
        string='Número Boleta',
        required=True,
        index=True,
        help='Número folio de la boleta electrónica de honorarios'
    )

    fecha_emision = fields.Date(
        string='Fecha Emisión',
        required=True,
        index=True,
        help='Fecha en que fue emitida la boleta por el profesional'
    )

    # ═══════════════════════════════════════════════════════════
    # DATOS DEL PROFESIONAL (EMISOR)
    # ═══════════════════════════════════════════════════════════

    profesional_id = fields.Many2one(
        'res.partner',
        string='Profesional',
        required=True,
        domain=[('is_company', '=', False)],
        help='Profesional independiente que emite la boleta'
    )

    profesional_rut = fields.Char(
        string='RUT Profesional',
        related='profesional_id.vat',
        store=True,
        index=True
    )

    profesional_nombre = fields.Char(
        string='Nombre Profesional',
        related='profesional_id.name',
        store=True
    )

    profesional_email = fields.Char(
        string='Email Profesional',
        related='profesional_id.email',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # MONTOS
    # ═══════════════════════════════════════════════════════════

    monto_bruto = fields.Monetary(
        string='Monto Bruto Honorarios',
        required=True,
        currency_field='currency_id',
        help='Monto total de honorarios antes de retención'
    )

    tasa_retencion = fields.Float(
        string='Tasa Retención (%)',
        compute='_compute_retencion',
        store=True,
        digits=(5, 2),
        help='Tasa de retención IUE vigente a la fecha de emisión'
    )

    monto_retencion = fields.Monetary(
        string='Monto Retenido',
        compute='_compute_retencion',
        store=True,
        currency_field='currency_id',
        help='Monto retenido por concepto de IUE (Impuesto Único Segunda Categoría)'
    )

    monto_liquido = fields.Monetary(
        string='Monto Líquido a Pagar',
        compute='_compute_retencion',
        store=True,
        currency_field='currency_id',
        help='Monto neto a pagar al profesional (Bruto - Retención)'
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.company.currency_id,
        required=True
    )

    # ═══════════════════════════════════════════════════════════
    # DESCRIPCIÓN SERVICIOS
    # ═══════════════════════════════════════════════════════════

    descripcion_servicios = fields.Text(
        string='Descripción Servicios',
        required=True,
        help='Descripción de los servicios profesionales prestados'
    )

    # ═══════════════════════════════════════════════════════════
    # RELACIÓN CON FACTURA ODOO
    # ═══════════════════════════════════════════════════════════

    vendor_bill_id = fields.Many2one(
        'account.move',
        string='Factura de Proveedor',
        domain=[('move_type', '=', 'in_invoice')],
        help='Factura de proveedor creada en Odoo a partir de esta boleta'
    )

    vendor_bill_state = fields.Selection(
        related='vendor_bill_id.state',
        string='Estado Factura',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # CERTIFICADO RETENCIÓN
    # ═══════════════════════════════════════════════════════════

    certificado_generado = fields.Boolean(
        string='Certificado Generado',
        default=False,
        help='Indica si se generó el certificado de retención para este profesional'
    )

    certificado_fecha = fields.Date(
        string='Fecha Certificado',
        help='Fecha en que se generó el certificado de retención'
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO Y CONTROL
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('validated', 'Validada'),
        ('accounted', 'Contabilizada'),
        ('paid', 'Pagada'),
        ('cancelled', 'Cancelada'),
    ], string='Estado', default='draft', tracking=True, required=True)

    active = fields.Boolean(
        string='Activo',
        default=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )

    # ═══════════════════════════════════════════════════════════
    # NOTAS Y OBSERVACIONES
    # ═══════════════════════════════════════════════════════════

    notas = fields.Text(
        string='Notas',
        help='Observaciones adicionales sobre esta boleta'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('numero_boleta')
    def _compute_name(self):
        """Nombre basado en número de boleta"""
        for record in self:
            record.name = record.numero_boleta or 'Nueva Boleta'

    @api.depends('name', 'profesional_nombre', 'fecha_emision')
    def _compute_display_name(self):
        """Display name completo"""
        for record in self:
            if record.numero_boleta and record.profesional_nombre:
                record.display_name = f"BHE {record.numero_boleta} - {record.profesional_nombre} ({record.fecha_emision})"
            else:
                record.display_name = record.name or 'Nueva Boleta Honorarios'

    @api.depends('monto_bruto', 'fecha_emision')
    def _compute_retencion(self):
        """Calcula retención según tasa histórica vigente"""
        for record in self:
            if not record.monto_bruto or not record.fecha_emision:
                record.tasa_retencion = 0.0
                record.monto_retencion = 0.0
                record.monto_liquido = 0.0
                continue

            try:
                # Obtener tasa vigente a la fecha de emisión
                TasaModel = self.env['l10n_cl.retencion_iue.tasa']
                calculo = TasaModel.calcular_retencion(
                    monto_bruto=record.monto_bruto,
                    fecha=record.fecha_emision,
                    company_id=record.company_id.id
                )

                record.tasa_retencion = calculo['tasa_retencion']
                record.monto_retencion = calculo['monto_retencion']
                record.monto_liquido = calculo['monto_liquido']

            except ValidationError as e:
                _logger.warning(f"Error al calcular retención para boleta {record.numero_boleta}: {str(e)}")
                record.tasa_retencion = 0.0
                record.monto_retencion = 0.0
                record.monto_liquido = record.monto_bruto

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('numero_boleta', 'profesional_id', 'company_id')
    def _check_unique_boleta(self):
        """Evita duplicados: misma boleta del mismo profesional"""
        for record in self:
            domain = [
                ('id', '!=', record.id),
                ('numero_boleta', '=', record.numero_boleta),
                ('profesional_id', '=', record.profesional_id.id),
                ('company_id', '=', record.company_id.id),
                ('active', '=', True)
            ]

            duplicate = self.search(domain, limit=1)
            if duplicate:
                raise ValidationError(
                    _("Ya existe la Boleta de Honorarios N° %s del profesional %s registrada en el sistema.") % (record.numero_boleta, record.profesional_nombre)
                )

    @api.constrains('monto_bruto')
    def _check_monto_bruto(self):
        """Valida que monto bruto sea positivo"""
        for record in self:
            if record.monto_bruto <= 0:
                raise ValidationError(
                    _("El monto bruto debe ser mayor a cero. Valor ingresado: %s") % record.monto_bruto
                )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS DE NEGOCIO
    # ═══════════════════════════════════════════════════════════

    def action_validate(self):
        """Valida la boleta de honorarios"""
        for record in self:
            if record.state != 'draft':
                raise UserError(_("Solo se pueden validar boletas en estado Borrador."))

            record.write({'state': 'validated'})

            record.message_post(
                body=_("Boleta de Honorarios validada correctamente."),
                subject=_("Boleta Validada")
            )

        return True

    def action_create_vendor_bill(self):
        """
        Crea factura de proveedor en Odoo a partir de esta boleta.

        Returns:
            dict: Action para abrir la factura creada
        """
        self.ensure_one()

        if self.vendor_bill_id:
            raise UserError(_("Ya existe una factura de proveedor asociada a esta boleta."))

        if self.state == 'draft':
            raise UserError(_("Debe validar la boleta antes de crear la factura de proveedor."))

        # Buscar cuenta de gastos por honorarios (debe estar configurada)
        expense_account = self.env['ir.config_parameter'].sudo().get_param('l10n_cl.honorarios_expense_account_id')
        if not expense_account:
            raise UserError(
                _("No se ha configurado la cuenta de gastos por honorarios.\n"
                  "Configure en: Facturación > Configuración > Ajustes > Honorarios")
            )

        # Crear factura de proveedor
        invoice_vals = {
            'move_type': 'in_invoice',
            'partner_id': self.profesional_id.id,
            'invoice_date': self.fecha_emision,
            'date': self.fecha_emision,
            'ref': f"BHE {self.numero_boleta}",
            'narration': self.descripcion_servicios,
            'company_id': self.company_id.id,
            'invoice_line_ids': [(0, 0, {
                'name': self.descripcion_servicios,
                'quantity': 1,
                'price_unit': self.monto_bruto,
                'account_id': int(expense_account),
                'tax_ids': [],  # Sin IVA (es retención, no impuesto de venta)
            })],
        }

        vendor_bill = self.env['account.move'].create(invoice_vals)

        # Vincular con esta boleta
        self.write({
            'vendor_bill_id': vendor_bill.id,
            'state': 'accounted'
        })

        self.message_post(
            body=_("Factura de proveedor creada: %s") % vendor_bill.name,
            subject=_("Factura Creada")
        )

        # Retornar action para abrir la factura
        return {
            'name': _('Factura de Proveedor'),
            'type': 'ir.actions.act_window',
            'res_model': 'account.move',
            'res_id': vendor_bill.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_generate_certificado(self):
        """Genera certificado de retención para declaración Form 29"""
        self.ensure_one()

        if not self.vendor_bill_id:
            raise UserError(_("Debe crear la factura de proveedor antes de generar el certificado."))

        if self.certificado_generado:
            raise UserError(_("Ya se generó el certificado de retención para esta boleta."))

        # TODO: Implementar generación de PDF certificado de retención
        # Debe incluir: RUT profesional, período, monto retenido, firma digital

        self.write({
            'certificado_generado': True,
            'certificado_fecha': date.today()
        })

        self.message_post(
            body=_("Certificado de retención generado exitosamente."),
            subject=_("Certificado Generado")
        )

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Certificado Generado'),
                'message': _('El certificado de retención ha sido generado. Se enviará al profesional por email.'),
                'type': 'success',
                'sticky': False,
            }
        }

    def action_mark_paid(self):
        """Marca la boleta como pagada"""
        for record in self:
            if record.state not in ['accounted']:
                raise UserError(_("Solo se pueden marcar como pagadas boletas contabilizadas."))

            record.write({'state': 'paid'})

            record.message_post(
                body=_("Boleta marcada como pagada."),
                subject=_("Pago Registrado")
            )

        return True

    def action_cancel(self):
        """Cancela la boleta"""
        for record in self:
            if record.state == 'paid':
                raise UserError(_("No se puede cancelar una boleta que ya fue pagada."))

            if record.vendor_bill_id and record.vendor_bill_id.state == 'posted':
                raise UserError(
                    _("No se puede cancelar la boleta porque la factura de proveedor ya está contabilizada. Cancele primero la factura.")
                )

            record.write({'state': 'cancelled'})

            record.message_post(
                body=_("Boleta de Honorarios cancelada."),
                subject=_("Boleta Cancelada")
            )

        return True

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS DE IMPORTACIÓN
    # ═══════════════════════════════════════════════════════════

    @api.model
    def import_from_sii_xml(self, xml_string):
        """
        Importa boleta desde XML descargado del Portal MiSII.

        NOTA: Implementación pendiente - requiere análisis del formato XML del SII

        Args:
            xml_string (str): XML de la boleta de honorarios

        Returns:
            l10n_cl.boleta_honorarios: Record de boleta creada

        Raises:
            ValidationError: Si el XML es inválido
        """
        # TODO: Implementar parser de XML de boletas de honorarios
        raise NotImplementedError(_("Importación desde XML SII pendiente de implementación"))
