# -*- coding: utf-8 -*-
"""
Tasas de Retención BHE (Boleta Honorarios Electrónica)
Tabla histórica 2018-presente con tasas oficiales SII
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class L10nClBheRetentionRate(models.Model):
    """
    Tasas de Retención BHE - Historial Completo

    Permite migrar datos históricos desde 2018 aplicando la tasa correcta
    según fecha de emisión de la BHE.

    Uso:
    - Sistema consulta tasa vigente según fecha BHE
    - Migración histórica usa tasa correspondiente al período
    - Actualizaciones futuras se agregan como nuevos registros
    """
    _name = "l10n_cl.bhe.retention.rate"
    _description = "Tasas de Retención BHE Históricas"
    _order = "date_from desc"
    _rec_name = "display_name"

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string="Nombre",
        compute="_compute_name",
        store=True
    )

    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # PERÍODO DE VIGENCIA
    # ═══════════════════════════════════════════════════════════

    date_from = fields.Date(
        string="Vigente Desde",
        required=True,
        help="Primer día de vigencia de esta tasa"
    )

    date_to = fields.Date(
        string="Vigente Hasta",
        help="Último día de vigencia (vacío = vigente actualmente)"
    )

    # ═══════════════════════════════════════════════════════════
    # TASA DE RETENCIÓN
    # ═══════════════════════════════════════════════════════════

    rate = fields.Float(
        string="Tasa de Retención (%)",
        required=True,
        digits=(5, 2),
        help="Tasa de retención en porcentaje (ej: 14.5 para 14.5%)"
    )

    # ═══════════════════════════════════════════════════════════
    # INFORMACIÓN LEGAL
    # ═══════════════════════════════════════════════════════════

    legal_reference = fields.Char(
        string="Referencia Legal",
        help="Ley, DFL, Circular SII que establece esta tasa"
    )

    notes = fields.Text(
        string="Notas",
        help="Información adicional sobre cambios o aplicabilidad"
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════

    active = fields.Boolean(
        string="Activo",
        default=True
    )

    is_current = fields.Boolean(
        string="Tasa Actual",
        compute="_compute_is_current",
        store=True,
        help="True si es la tasa vigente hoy"
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('date_from', 'rate')
    def _compute_name(self):
        for rec in self:
            if rec.date_from and rec.rate:
                year = rec.date_from.year
                rec.name = f"{rec.rate}% (desde {year})"
            else:
                rec.name = "Tasa BHE"

    @api.depends('name', 'date_from', 'date_to')
    def _compute_display_name(self):
        for rec in self:
            if rec.date_from:
                date_range = rec.date_from.strftime('%d/%m/%Y')
                if rec.date_to:
                    date_range += f" - {rec.date_to.strftime('%d/%m/%Y')}"
                else:
                    date_range += " - Actual"
                rec.display_name = f"{rec.rate}% ({date_range})"
            else:
                rec.display_name = rec.name or "Tasa BHE"

    @api.depends('date_from', 'date_to')
    def _compute_is_current(self):
        today = fields.Date.today()
        for rec in self:
            if rec.date_from:
                is_after_start = today >= rec.date_from
                is_before_end = not rec.date_to or today <= rec.date_to
                rec.is_current = is_after_start and is_before_end
            else:
                rec.is_current = False

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('rate')
    def _check_rate(self):
        for rec in self:
            if rec.rate < 0 or rec.rate > 100:
                raise ValidationError(
                    _("La tasa de retención debe estar entre 0% y 100%.")
                )

    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        for rec in self:
            if rec.date_to and rec.date_from and rec.date_to < rec.date_from:
                raise ValidationError(
                    _("La fecha 'Hasta' debe ser posterior a la fecha 'Desde'.")
                )

    @api.constrains('date_from', 'date_to')
    def _check_no_overlap(self):
        """Verificar que no haya períodos superpuestos"""
        for rec in self:
            domain = [
                ('id', '!=', rec.id),
                ('date_from', '<=', rec.date_to or fields.Date.today()),
            ]
            if rec.date_to:
                domain.append(('date_to', '>=', rec.date_from))
            else:
                # Si no tiene date_to, verificar que no haya otra sin date_to
                domain.append(('date_to', '=', False))

            overlapping = self.search(domain, limit=1)
            if overlapping:
                raise ValidationError(
                    _(f"El período se superpone con: {overlapping.display_name}")
                )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PÚBLICOS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def get_rate_for_date(self, bhe_date):
        """
        Obtiene la tasa de retención vigente para una fecha dada.

        Args:
            bhe_date: Fecha de emisión de la BHE (date o str YYYY-MM-DD)

        Returns:
            float: Tasa de retención (ej: 14.5 para 14.5%)

        Raises:
            ValidationError: Si no existe tasa para esa fecha
        """
        if isinstance(bhe_date, str):
            bhe_date = fields.Date.from_string(bhe_date)

        # Buscar tasa vigente
        rate_record = self.search([
            ('date_from', '<=', bhe_date),
            '|',
            ('date_to', '=', False),
            ('date_to', '>=', bhe_date)
        ], limit=1)

        if not rate_record:
            raise ValidationError(
                _(f"No existe tasa de retención configurada para la fecha {bhe_date}. "
                  f"Por favor configure las tasas históricas en Configuración > BHE > Tasas Retención.")
            )

        _logger.debug(f"Tasa BHE para {bhe_date}: {rate_record.rate}%")
        return rate_record.rate

    @api.model
    def get_current_rate(self):
        """
        Obtiene la tasa de retención vigente actual.

        Returns:
            float: Tasa de retención actual
        """
        return self.get_rate_for_date(fields.Date.today())

    # ═══════════════════════════════════════════════════════════
    # DATA INITIALIZATION
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _load_historical_rates(self):
        """
        Carga tasas históricas oficiales SII.

        Ejecutar solo una vez en instalación inicial.
        """
        historical_rates = [
            {
                'date_from': '2018-01-01',
                'date_to': '2020-12-31',
                'rate': 10.0,
                'legal_reference': 'Art. 50 Código Tributario (hasta 2020)',
                'notes': 'Tasa vigente período 2018-2020'
            },
            {
                'date_from': '2021-01-01',
                'date_to': '2021-12-31',
                'rate': 11.5,
                'legal_reference': 'Ley 21.133 - Reforma Tributaria 2021',
                'notes': 'Primera alza gradual reforma tributaria'
            },
            {
                'date_from': '2022-01-01',
                'date_to': '2022-12-31',
                'rate': 12.25,
                'legal_reference': 'Ley 21.133 - Año 2',
                'notes': 'Segunda alza gradual'
            },
            {
                'date_from': '2023-01-01',
                'date_to': '2023-12-31',
                'rate': 13.0,
                'legal_reference': 'Ley 21.133 - Año 3',
                'notes': 'Tercera alza gradual'
            },
            {
                'date_from': '2024-01-01',
                'date_to': '2024-12-31',
                'rate': 13.75,
                'legal_reference': 'Ley 21.133 - Año 4',
                'notes': 'Cuarta alza gradual'
            },
            {
                'date_from': '2025-01-01',
                'date_to': False,  # Vigente actualmente
                'rate': 14.5,
                'legal_reference': 'Ley 21.133 - Tasa final',
                'notes': 'Tasa final según reforma tributaria. Vigente desde enero 2025.'
            },
        ]

        for rate_data in historical_rates:
            # Verificar si ya existe
            existing = self.search([
                ('date_from', '=', rate_data['date_from']),
                ('rate', '=', rate_data['rate'])
            ])

            if not existing:
                self.create(rate_data)
                _logger.info(f"✅ Tasa BHE creada: {rate_data['rate']}% desde {rate_data['date_from']}")

        _logger.info("✅ Tasas históricas BHE cargadas correctamente")


class L10nClBhe(models.Model):
    """
    Boleta de Honorarios Electrónica (BHE) - Chilean Electronic Fee Receipt
    Document Type 70 according to SII standards

    IMPORTANTE: Este modelo maneja SOLO la RECEPCIÓN de BHE emitidas por terceros.
    Las empresas NO emiten BHE, solo las reciben de prestadores de servicios.
    """
    _name = "l10n_cl.bhe"
    _description = "Boleta de Honorarios Electrónica"
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = "date desc, number desc"
    _check_company_auto = True

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string="Nombre",
        compute="_compute_name",
        store=True
    )

    number = fields.Char(
        string="Número BHE",
        required=True,
        copy=False,
        index=True,
        tracking=True
    )

    date = fields.Date(
        string="Fecha Emisión",
        required=True,
        default=fields.Date.context_today,
        tracking=True,
        help="Fecha de emisión de la BHE por el profesional"
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.company.currency_id,
        required=True
    )

    # ═══════════════════════════════════════════════════════════
    # PRESTADOR DE SERVICIOS (Emisor)
    # ═══════════════════════════════════════════════════════════

    partner_id = fields.Many2one(
        'res.partner',
        string="Prestador de Servicios",
        required=True,
        domain="[('is_company', '=', False)]",
        tracking=True,
        help="Profesional independiente que emite la BHE"
    )

    partner_vat = fields.Char(
        related="partner_id.vat",
        string="RUT Prestador",
        store=True,
        readonly=True
    )

    # ═══════════════════════════════════════════════════════════
    # DESCRIPCIÓN DEL SERVICIO
    # ═══════════════════════════════════════════════════════════

    service_description = fields.Text(
        string="Descripción del Servicio",
        required=True,
        tracking=True,
        help="Detalle de los servicios profesionales prestados"
    )

    # ═══════════════════════════════════════════════════════════
    # MONTOS CON TASA HISTÓRICA
    # ═══════════════════════════════════════════════════════════

    amount_gross = fields.Monetary(
        string="Monto Bruto",
        required=True,
        tracking=True,
        currency_field='currency_id',
        help="Monto total ANTES de retención"
    )

    retention_rate = fields.Float(
        string="Tasa de Retención (%)",
        compute="_compute_retention_rate",
        store=True,
        readonly=False,  # Permite override manual si es necesario
        digits=(5, 2),
        tracking=True,
        help="Tasa de retención calculada según fecha de emisión. "
             "Se obtiene automáticamente de tabla histórica."
    )

    amount_retention = fields.Monetary(
        string="Monto Retención",
        compute="_compute_amounts",
        store=True,
        currency_field='currency_id',
        help="Retención = Bruto * Tasa%"
    )

    amount_net = fields.Monetary(
        string="Monto Líquido",
        compute="_compute_amounts",
        store=True,
        currency_field='currency_id',
        help="Neto = Bruto - Retención (monto a pagar al profesional)"
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('posted', 'Contabilizado'),
        ('sent', 'Enviado al SII'),
        ('accepted', 'Aceptado por SII'),
        ('rejected', 'Rechazado por SII'),
        ('cancelled', 'Anulado')
    ], string='Estado', default='draft', tracking=True, copy=False)

    # ═══════════════════════════════════════════════════════════
    # CONTABILIDAD
    # ═══════════════════════════════════════════════════════════

    move_id = fields.Many2one(
        'account.move',
        string="Asiento Contable",
        readonly=True,
        copy=False,
        help="Asiento generado automáticamente al contabilizar"
    )

    payment_id = fields.Many2one(
        'account.payment',
        string="Pago",
        readonly=True,
        copy=False,
        help="Pago asociado al profesional"
    )

    # ═══════════════════════════════════════════════════════════
    # SII
    # ═══════════════════════════════════════════════════════════

    sii_send_date = fields.Datetime(
        string="Fecha Envío SII",
        readonly=True,
        copy=False
    )

    sii_track_id = fields.Char(
        string="Track ID SII",
        readonly=True,
        copy=False
    )

    sii_status = fields.Char(
        string="Estado SII",
        readonly=True,
        copy=False
    )

    xml_file = fields.Binary(
        string="XML Recibido",
        attachment=True,
        copy=False
    )

    xml_filename = fields.Char(
        string="Nombre Archivo XML",
        compute="_compute_xml_filename",
        store=True
    )

    sii_xml_request = fields.Text(
        string="XML Request SII",
        readonly=True,
        copy=False
    )

    sii_xml_response = fields.Text(
        string="XML Response SII",
        readonly=True,
        copy=False
    )

    # ═══════════════════════════════════════════════════════════
    # NOTAS
    # ═══════════════════════════════════════════════════════════

    notes = fields.Text(
        string="Notas",
        help="Notas adicionales sobre la BHE"
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('number', 'partner_id')
    def _compute_name(self):
        for rec in self:
            if rec.number and rec.partner_id:
                rec.name = f"BHE {rec.number} - {rec.partner_id.name}"
            elif rec.number:
                rec.name = f"BHE {rec.number}"
            else:
                rec.name = "BHE Borrador"

    @api.depends('date')
    def _compute_retention_rate(self):
        """
        Calcula la tasa de retención según la fecha de emisión.
        Consulta tabla histórica de tasas.
        """
        for rec in self:
            if rec.date:
                try:
                    rate_model = self.env['l10n_cl.bhe.retention.rate']
                    rec.retention_rate = rate_model.get_rate_for_date(rec.date)
                    _logger.debug(
                        f"BHE {rec.number}: Tasa {rec.retention_rate}% para fecha {rec.date}"
                    )
                except ValidationError as e:
                    # Si no hay tasa configurada, usar default 14.5% (actual)
                    _logger.warning(f"No se encontró tasa para {rec.date}, usando 14.5%: {e}")
                    rec.retention_rate = 14.5
            else:
                rec.retention_rate = 14.5  # Default actual

    @api.depends('amount_gross', 'retention_rate')
    def _compute_amounts(self):
        for rec in self:
            rec.amount_retention = rec.amount_gross * (rec.retention_rate / 100)
            rec.amount_net = rec.amount_gross - rec.amount_retention

    @api.depends('number')
    def _compute_xml_filename(self):
        for rec in self:
            if rec.number:
                rec.xml_filename = f"BHE_{rec.number}_received.xml"
            else:
                rec.xml_filename = "BHE_received.xml"

    # ═══════════════════════════════════════════════════════════
    # ONCHANGE
    # ═══════════════════════════════════════════════════════════

    @api.onchange('date')
    def _onchange_date_update_rate(self):
        """Actualizar tasa cuando cambia la fecha"""
        if self.date:
            try:
                rate_model = self.env['l10n_cl.bhe.retention.rate']
                self.retention_rate = rate_model.get_rate_for_date(self.date)
            except ValidationError:
                pass  # Ya manejado en compute

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('amount_gross')
    def _check_amount_gross(self):
        for rec in self:
            if rec.amount_gross <= 0:
                raise ValidationError(
                    _("El monto bruto debe ser mayor a cero.")
                )

    @api.constrains('retention_rate')
    def _check_retention_rate(self):
        for rec in self:
            if rec.retention_rate < 0 or rec.retention_rate > 100:
                raise ValidationError(
                    _("La tasa de retención debe estar entre 0% y 100%.")
                )

    _sql_constraints = [
        ('number_partner_unique', 'unique(number, partner_id, company_id)',
         'Ya existe una BHE con este número para este prestador en esta compañía.')
    ]

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_post(self):
        """
        Contabilizar BHE:
        - Genera asiento contable con 3 líneas:
          1. Débito: Gasto Honorarios (cuenta configurada en empresa)
          2. Crédito: Retención Honorarios (cuenta configurada en empresa)
          3. Crédito: Por Pagar Proveedor (cuenta del partner)
        """
        for rec in self:
            if rec.state != 'draft':
                raise ValidationError(_("Solo se pueden contabilizar BHE en estado Borrador."))

            # Obtener cuentas contables desde configuración empresa
            company = rec.company_id
            expense_account = company.l10n_cl_bhe_expense_account_id
            retention_account = company.l10n_cl_bhe_retention_account_id
            journal = company.l10n_cl_bhe_journal_id

            if not expense_account:
                raise ValidationError(
                    _("Configure la cuenta de gasto de honorarios en:\n"
                      "Configuración > Contabilidad > BHE > Cuenta Gasto Honorarios")
                )
            if not retention_account:
                raise ValidationError(
                    _("Configure la cuenta de retención de honorarios en:\n"
                      "Configuración > Contabilidad > BHE > Cuenta Retención Honorarios")
                )
            if not journal:
                raise ValidationError(
                    _("Configure el diario de BHE en:\n"
                      "Configuración > Contabilidad > BHE > Diario BHE")
                )

            # Crear asiento contable
            move_vals = {
                'journal_id': journal.id,
                'date': rec.date,
                'ref': f"BHE {rec.number} - {rec.partner_id.name} ({rec.retention_rate}%)",
                'company_id': rec.company_id.id,
                'line_ids': [
                    # Línea 1: Débito Gasto Honorarios (total bruto)
                    (0, 0, {
                        'name': f"Honorarios - {rec.service_description[:50]}",
                        'account_id': expense_account.id,
                        'debit': rec.amount_gross,
                        'credit': 0.0,
                        'partner_id': rec.partner_id.id,
                    }),
                    # Línea 2: Crédito Retención Honorarios
                    (0, 0, {
                        'name': f"Retención {rec.retention_rate}% - BHE {rec.number}",
                        'account_id': retention_account.id,
                        'debit': 0.0,
                        'credit': rec.amount_retention,
                        'partner_id': rec.partner_id.id,
                    }),
                    # Línea 3: Crédito Por Pagar Proveedor (neto)
                    (0, 0, {
                        'name': f"BHE {rec.number} - Por Pagar",
                        'account_id': rec.partner_id.property_account_payable_id.id,
                        'debit': 0.0,
                        'credit': rec.amount_net,
                        'partner_id': rec.partner_id.id,
                    }),
                ]
            }

            move = self.env['account.move'].create(move_vals)
            move.action_post()

            rec.write({
                'move_id': move.id,
                'state': 'posted'
            })

            _logger.info(
                f"✅ BHE {rec.number} contabilizada - Asiento {move.name} "
                f"(Tasa {rec.retention_rate}%)"
            )

    def action_validate_sii(self):
        """Validar BHE con SII (placeholder - implementar SOAP)"""
        for rec in self:
            if rec.state != 'posted':
                raise ValidationError(_("Solo se pueden validar BHE contabilizadas."))

            # TODO: Implementar validación SII
            rec.write({
                'state': 'accepted',
                'sii_send_date': fields.Datetime.now(),
                'sii_status': 'ACEPTADO'
            })

    def action_cancel(self):
        """Anular BHE y eliminar asiento contable"""
        for rec in self:
            if rec.state == 'cancelled':
                raise ValidationError(_("La BHE ya está anulada."))

            # Eliminar asiento contable si existe
            if rec.move_id:
                if rec.move_id.state == 'posted':
                    rec.move_id.button_draft()
                rec.move_id.unlink()

            rec.write({
                'state': 'cancelled',
                'move_id': False
            })

    def action_draft(self):
        """Volver a borrador"""
        for rec in self:
            if rec.state != 'cancelled':
                raise ValidationError(_("Solo se pueden volver a borrador BHE anuladas."))

            rec.write({'state': 'draft'})

    def print_bhe(self):
        """Imprimir BHE"""
        return self.env.ref('l10n_cl_dte.action_report_bhe').report_action(self)

    def _process_received_xml(self, xml_content):
        """Procesar XML recibido"""
        self.ensure_one()

        self.write({
            'xml_file': xml_content.encode('utf-8'),
            'sii_xml_request': xml_content
        })

    def get_bhe_report_values(self):
        """Obtener valores para reporte PDF"""
        self.ensure_one()

        return {
            'doc': self,
            'company': self.company_id,
            'partner': self.partner_id,
        }
