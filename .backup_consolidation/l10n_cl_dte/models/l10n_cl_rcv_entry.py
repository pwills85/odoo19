# -*- coding: utf-8 -*-
"""
Modelo para Registro de Compras y Ventas (RCV) - Resolución SII 61/2017

Este modelo implementa el Registro de Compras y Ventas obligatorio según:
- Resolución Exenta SII N° 61 del 14.07.2017
- Resolución Exenta SII N° 68 del 18.08.2017
- Circular N° 4 del 17.01.2017

El RCV reemplaza los antiguos Libros de Compra y Venta desde 01.08.2017.
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class L10nClRCVEntry(models.Model):
    """
    Entrada individual en el Registro de Compras y Ventas (RCV).

    Cada documento tributario (electrónico o no) genera una entrada en el RCV.
    Las entradas se agrupan por período mensual para generación de F29.

    Resolución SII 61/2017: "Créase el Registro de Compras y Ventas, que
    constituirá un registro fidedigno y cronológico de las operaciones sujetas,
    exentas y no gravadas con Impuesto al Valor Agregado."
    """
    _name = 'l10n_cl.rcv.entry'
    _description = 'RCV Entry - Registro de Compras y Ventas Chile'
    _order = 'date desc, id desc'
    _rec_name = 'display_name'

    # ========================
    # CAMPOS IDENTIFICACIÓN
    # ========================
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        index=True
    )

    period_id = fields.Many2one(
        'l10n_cl.rcv.period',
        string='Período RCV',
        required=True,
        index=True,
        ondelete='cascade',
        help='Período mensual al que pertenece esta entrada'
    )

    entry_type = fields.Selection([
        ('sale', 'Venta'),
        ('purchase', 'Compra'),
    ], string='Tipo', required=True, index=True)

    # ========================
    # DATOS DOCUMENTO
    # ========================
    document_type_id = fields.Many2one(
        'l10n_latam.document.type',
        string='Tipo de Documento',
        required=True,
        index=True,
        help='Tipo de DTE según tabla SII'
    )

    folio = fields.Integer(
        string='Folio',
        required=True,
        index=True,
        help='Número de folio del documento'
    )

    date = fields.Date(
        string='Fecha Documento',
        required=True,
        index=True,
        help='Fecha de emisión del documento'
    )

    # ========================
    # DATOS CONTRAPARTE
    # ========================
    partner_id = fields.Many2one(
        'res.partner',
        string='Contacto',
        index=True,
        help='Cliente (venta) o Proveedor (compra)'
    )

    partner_vat = fields.Char(
        string='RUT',
        required=True,
        index=True,
        help='RUT del cliente/proveedor (formato: 12345678-9)'
    )

    partner_name = fields.Char(
        string='Razón Social',
        required=True,
        help='Nombre o razón social del cliente/proveedor'
    )

    # ========================
    # MONTOS
    # ========================
    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.ref('base.CLP'),
        required=True
    )

    amount_untaxed = fields.Monetary(
        string='Monto Neto',
        required=True,
        currency_field='currency_id',
        help='Monto neto (sin IVA)'
    )

    amount_tax = fields.Monetary(
        string='IVA',
        currency_field='currency_id',
        help='Monto IVA'
    )

    amount_exempt = fields.Monetary(
        string='Monto Exento',
        currency_field='currency_id',
        help='Monto exento de IVA'
    )

    amount_total = fields.Monetary(
        string='Monto Total',
        required=True,
        currency_field='currency_id',
        help='Monto total del documento'
    )

    # ========================
    # INTEGRACIÓN ODOO
    # ========================
    move_id = fields.Many2one(
        'account.move',
        string='Factura/DTE',
        index=True,
        ondelete='cascade',
        help='Referencia a account.move que generó esta entrada'
    )

    # ========================
    # SINCRONIZACIÓN SII
    # ========================
    sii_state = fields.Selection([
        ('pending', 'Pendiente Envío'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado por SII'),
        ('rejected', 'Rechazado por SII'),
    ], string='Estado SII', default='pending', index=True)

    sii_sync_date = fields.Datetime(
        string='Fecha Sincronización SII',
        help='Última vez que se sincronizó con RCV del SII'
    )

    sii_discrepancy = fields.Boolean(
        string='Discrepancia SII',
        default=False,
        index=True,
        help='Marca si hay diferencia entre Odoo y SII'
    )

    sii_discrepancy_detail = fields.Text(
        string='Detalle Discrepancia',
        help='Explicación de la discrepancia encontrada'
    )

    # ========================
    # CAMPOS TÉCNICOS
    # ========================
    display_name = fields.Char(
        string='Nombre',
        compute='_compute_display_name',
        store=True
    )

    active = fields.Boolean(
        string='Activo',
        default=True
    )

    notes = fields.Text(
        string='Observaciones'
    )

    # ========================
    # CONSTRAINTS (Odoo 19 CE format)
    # ========================
    _unique_entry = models.Constraint(
        'UNIQUE(company_id, entry_type, document_type_id, folio, partner_vat)',
        'Esta entrada RCV ya existe para este documento.'
    )

    # ========================
    # COMPUTED FIELDS
    # ========================
    @api.depends('entry_type', 'document_type_id', 'folio', 'partner_name')
    def _compute_display_name(self):
        """Genera nombre descriptivo para la entrada"""
        for rec in self:
            doc_name = rec.document_type_id.name if rec.document_type_id else 'Documento'
            type_label = 'Venta' if rec.entry_type == 'sale' else 'Compra'
            rec.display_name = f"{type_label} - {doc_name} N° {rec.folio} - {rec.partner_name[:30]}"

    # ========================
    # VALIDATIONS
    # ========================
    @api.constrains('partner_vat')
    def _check_rut_format(self):
        """Valida formato RUT chileno"""
        for rec in self:
            if rec.partner_vat:
                # Remover puntos y guiones
                rut = rec.partner_vat.replace('.', '').replace('-', '')

                if not rut:
                    raise ValidationError(_('RUT no puede estar vacío'))

                # Validar que tenga al menos 2 caracteres (número + dígito verificador)
                if len(rut) < 2:
                    raise ValidationError(_(
                        'RUT inválido: %s\n'
                        'Debe tener formato: 12345678-9'
                    ) % rec.partner_vat)

    @api.constrains('amount_total', 'amount_untaxed', 'amount_tax', 'amount_exempt')
    def _check_amounts(self):
        """Valida consistencia de montos"""
        for rec in self:
            # Validar que montos no sean negativos
            if rec.amount_total < 0:
                raise ValidationError(_('Monto total no puede ser negativo'))

            # Validar que Neto + IVA + Exento = Total (con tolerancia 1 CLP)
            calculated_total = rec.amount_untaxed + rec.amount_tax + rec.amount_exempt
            if abs(calculated_total - rec.amount_total) > 1:
                raise ValidationError(_(
                    'Error en montos:\n'
                    'Neto ($%s) + IVA ($%s) + Exento ($%s) = $%s\n'
                    'Pero Total declarado es: $%s\n'
                    'Diferencia: $%s'
                ) % (
                    rec.amount_untaxed,
                    rec.amount_tax,
                    rec.amount_exempt,
                    calculated_total,
                    rec.amount_total,
                    abs(calculated_total - rec.amount_total)
                ))

    @api.constrains('date', 'period_id')
    def _check_date_in_period(self):
        """Valida que fecha documento esté en el período correcto"""
        for rec in self:
            if rec.date and rec.period_id:
                period_date = rec.period_id.period_date
                if rec.date.month != period_date.month or rec.date.year != period_date.year:
                    raise ValidationError(_(
                        'Fecha documento (%s) no coincide con período RCV (%s/%s)'
                    ) % (
                        rec.date,
                        period_date.month,
                        period_date.year
                    ))

    # ========================
    # ACTIONS
    # ========================
    def action_view_invoice(self):
        """Abre factura relacionada"""
        self.ensure_one()
        if not self.move_id:
            raise ValidationError(_('Esta entrada RCV no tiene factura asociada'))

        return {
            'type': 'ir.actions.act_window',
            'name': _('Factura/DTE'),
            'res_model': 'account.move',
            'res_id': self.move_id.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_mark_discrepancy_resolved(self):
        """Marca discrepancia como resuelta"""
        self.write({
            'sii_discrepancy': False,
            'sii_discrepancy_detail': False,
        })

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': _('Discrepancia marcada como resuelta'),
                'type': 'success',
            }
        }

    # ========================
    # ORM METHODS
    # ========================
    @api.model
    def create_from_invoice(self, invoice):
        """
        Crea entrada RCV desde una factura (account.move).

        Args:
            invoice (account.move): Factura que genera la entrada

        Returns:
            l10n_cl.rcv.entry: Nueva entrada creada
        """
        if not invoice.is_dte:
            _logger.warning(
                "Intento de crear RCV entry desde invoice no-DTE: %s",
                invoice.id
            )
            return self.env['l10n_cl.rcv.entry']

        # Determinar tipo
        entry_type = 'sale' if invoice.move_type in ('out_invoice', 'out_refund') else 'purchase'

        # Obtener o crear período
        period = self.env['l10n_cl.rcv.period']._get_or_create_period(
            invoice.invoice_date,
            invoice.company_id.id
        )

        # Preparar valores
        vals = {
            'company_id': invoice.company_id.id,
            'period_id': period.id,
            'entry_type': entry_type,
            'document_type_id': invoice.l10n_latam_document_type_id.id,
            'folio': invoice.l10n_cl_sii_folio,
            'date': invoice.invoice_date,
            'partner_id': invoice.partner_id.id,
            'partner_vat': invoice.partner_id.vat or 'Sin RUT',
            'partner_name': invoice.partner_id.name,
            'currency_id': invoice.currency_id.id,
            'amount_untaxed': invoice.amount_untaxed,
            'amount_tax': invoice.amount_tax,
            'amount_exempt': 0.0,  # TODO: Calcular monto exento
            'amount_total': invoice.amount_total,
            'move_id': invoice.id,
            'sii_state': 'pending',
        }

        # Crear entrada
        entry = self.create(vals)

        _logger.info(
            "✅ RCV entry created: %s - %s N° %s",
            entry.entry_type.upper(),
            entry.document_type_id.name,
            entry.folio
        )

        return entry
