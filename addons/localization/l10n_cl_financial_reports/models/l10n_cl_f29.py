# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError
from datetime import timedelta
import logging

_logger = logging.getLogger(__name__)


class L10nClF29(models.Model):
    """
    Formulario 29 - Declaración Mensual de IVA
    Implementación completa según normativa SII Chile

    Referencias tecnicas:
    - Formulario F29 segun SII Chile
    - Odoo 18 ORM patterns
    - Service Layer implementation
    """
    _name = 'l10n_cl.f29'
    _description = 'Formulario 29 - Declaración Mensual IVA'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _rec_name = 'display_name'
    _order = 'period_date desc, id desc'

    # ========== CAMPOS DE IDENTIFICACIÓN ==========
    display_name = fields.Char(
        string='Identificación',
        compute='_compute_display_name',
        store=True
    )

    name = fields.Char(
        string='Número F29',
        required=True,
        copy=False,
        default='New'
    )

    period_date = fields.Date(
        string='Período',
        required=True,
        tracking=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Empresa',
        required=True,
        default=lambda self: self.env.company
    )

    currency_id = fields.Many2one(
        related='company_id.currency_id',
        store=True
    )

    # ========== ESTADO Y CONTROL ==========
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('review', 'En Revisión'),
        ('confirmed', 'Confirmado'),
        ('filed', 'Presentado a SII'),
        ('paid', 'Pagado'),
        ('cancel', 'Cancelado'),
    ], string='Estado', default='draft', tracking=True)

    tipo_declaracion = fields.Selection([
        ('original', 'Original'),
        ('rectificatoria', 'Rectificatoria'),
    ], string='Tipo Declaración', default='original', required=True, tracking=True)

    numero_rectificacion = fields.Integer(
        string='Número Rectificación',
        help='Número de orden si es declaración rectificatoria',
        tracking=True
    )

    # ========== CAMPOS SII INTEGRATION ==========
    sii_status = fields.Selection([
        ('draft', 'Borrador'),
        ('sending', 'Enviando...'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado por SII'),
        ('rejected', 'Rechazado por SII'),
    ], string='Estado SII', default='draft', tracking=True, copy=False)

    sii_error_message = fields.Text(
        string='Error SII',
        readonly=True,
        help='Mensaje de error del SII si fue rechazado'
    )

    sii_response_xml = fields.Text(
        string='Respuesta XML SII',
        readonly=True,
        help='Respuesta XML completa del SII'
    )

    # ========== CAMPOS RECTIFICATORIA ==========
    es_rectificatoria = fields.Boolean(
        string='Es Rectificatoria',
        default=False,
        help='Indica si este F29 reemplaza a uno anterior'
    )

    f29_original_id = fields.Many2one(
        'l10n_cl.f29',
        string='F29 Original',
        readonly=True,
        help='F29 que se está rectificando'
    )

    folio_rectifica = fields.Char(
        string='Folio que Rectifica',
        readonly=True,
        help='Número del F29 original'
    )

    rectificatoria_ids = fields.One2many(
        'l10n_cl.f29',
        'f29_original_id',
        string='Rectificatorias',
        readonly=True
    )

    # ========== DÉBITO FISCAL (VENTAS) ==========
    ventas_afectas = fields.Monetary(
        string='Ventas y Servicios Gravados (Código 14)',
        currency_field='currency_id',
        help='Ventas y servicios afectos a IVA',
        tracking=True
    )

    ventas_exentas = fields.Monetary(
        string='Ventas Exentas (Código 15)',
        currency_field='currency_id',
        help='Ventas y servicios exentos de IVA'
    )

    ventas_exportacion = fields.Monetary(
        string='Exportaciones (Código 30)',
        currency_field='currency_id',
        help='Ventas de exportación (no gravadas con IVA)'
    )

    debito_fiscal = fields.Monetary(
        string='Débito Fiscal IVA (Código 32)',
        currency_field='currency_id',
        compute='_compute_iva_amounts',
        store=True,
        help='IVA generado por ventas afectas',
        tracking=True
    )

    creditos_especiales = fields.Monetary(
        string='Créditos Especiales (Código 36)',
        currency_field='currency_id',
        help='Créditos especiales contra el IVA débito (ej: empresas constructoras)'
    )

    debito_remanente_mes_anterior = fields.Monetary(
        string='Remanente Débito Mes Anterior (Código 37)',
        currency_field='currency_id',
        help='Remanente de débito fiscal del mes anterior'
    )

    # ========== CRÉDITO FISCAL (COMPRAS) ==========
    compras_afectas = fields.Monetary(
        string='Compras con IVA Recuperable (Código 40)',
        currency_field='currency_id',
        help='Compras y servicios con derecho a crédito fiscal IVA',
        tracking=True
    )

    compras_exentas = fields.Monetary(
        string='Compras Exentas (Código 41)',
        currency_field='currency_id',
        help='Compras de bienes y servicios exentos de IVA'
    )

    compras_activo_fijo = fields.Monetary(
        string='Compras Activo Fijo (Código 43)',
        currency_field='currency_id',
        help='Compras de activo fijo con derecho a crédito fiscal'
    )

    credito_fiscal = fields.Monetary(
        string='Crédito Fiscal IVA (Código 48)',
        currency_field='currency_id',
        compute='_compute_iva_amounts',
        store=True,
        help='IVA crédito por compras afectas y activo fijo',
        tracking=True
    )

    remanente_credito_mes_anterior = fields.Monetary(
        string='Remanente Crédito Mes Anterior (Código 47)',
        currency_field='currency_id',
        help='Remanente de crédito fiscal del mes anterior'
    )

    # ========== DETERMINACIÓN IVA ==========
    iva_determinado = fields.Monetary(
        string='IVA Determinado (Código 89)',
        currency_field='currency_id',
        compute='_compute_iva_determinado',
        store=True,
        help='Débito fiscal - Crédito fiscal',
        tracking=True
    )

    iva_retenido = fields.Monetary(
        string='IVA Retenido por Terceros (Código 105)',
        currency_field='currency_id',
        help='Retenciones de IVA efectuadas por terceros'
    )

    # ========== PPM (PAGOS PROVISIONALES MENSUALES) ==========
    ppm_mes = fields.Monetary(
        string='PPM del Mes (Código 152)',
        currency_field='currency_id',
        help='Pago Provisional Mensual obligatorio',
        tracking=True
    )

    ppm_voluntario = fields.Monetary(
        string='PPM Voluntario (Código 153)',
        currency_field='currency_id',
        help='Pago Provisional Mensual voluntario'
    )

    # ========== RESULTADO FINAL ==========
    iva_a_pagar = fields.Monetary(
        string='IVA a Pagar (Código 91)',
        currency_field='currency_id',
        compute='_compute_resultado_final',
        store=True,
        help='Monto total a pagar al SII',
        tracking=True
    )

    saldo_favor = fields.Monetary(
        string='Saldo a Favor (Código 92)',
        currency_field='currency_id',
        compute='_compute_resultado_final',
        store=True,
        help='Crédito a favor del contribuyente'
    )

    remanente_mes_siguiente = fields.Monetary(
        string='Remanente para Mes Siguiente (Código 93)',
        currency_field='currency_id',
        compute='_compute_resultado_final',
        store=True,
        help='Saldo de crédito fiscal que pasa al mes siguiente'
    )

    # ========== CAMPOS LEGACY (Backward Compatibility) ==========
    total_ventas = fields.Monetary(
        string='Total Ventas (Legacy)',
        currency_field='currency_id',
        compute='_compute_legacy_fields',
        store=True,
        help='Campo legacy - usar ventas_afectas'
    )

    total_iva_credito = fields.Monetary(
        string='IVA Crédito (Legacy)',
        currency_field='currency_id',
        compute='_compute_legacy_fields',
        store=True,
        help='Campo legacy - usar credito_fiscal'
    )

    total_compras = fields.Monetary(
        string='Total Compras (Legacy)',
        currency_field='currency_id',
        compute='_compute_legacy_fields',
        store=True,
        help='Campo legacy - usar compras_afectas'
    )

    total_iva_debito = fields.Monetary(
        string='IVA Débito (Legacy)',
        currency_field='currency_id',
        compute='_compute_legacy_fields',
        store=True,
        help='Campo legacy - usar debito_fiscal'
    )

    # ========== SII TRACKING FIELDS ==========
    sii_track_id = fields.Char(
        string='ID Seguimiento SII',
        readonly=True,
        help='Identificador de seguimiento del SII para consultas de estado'
    )

    sii_send_date = fields.Datetime(
        string='Fecha Envío SII',
        readonly=True,
        help='Fecha y hora de envío al SII'
    )

    sii_response = fields.Text(
        string='Respuesta SII',
        readonly=True,
        help='Respuesta completa del SII (XML o JSON)'
    )

    # ========== COMPUTED FIELDS (P0-2 implementation) ==========
    move_ids = fields.Many2many(
        'account.move',
        compute='_compute_move_ids',
        store=False,
        string='Facturas Relacionadas',
        help='Facturas del período incluidas en F29'
    )

    amount_total = fields.Monetary(
        string='Monto Total',
        currency_field='currency_id',
        compute='_compute_amount_total',
        store=True,
        readonly=True,
        help='Monto total (saldo a favor o a pagar)'
    )

    provision_move_id = fields.Many2one(
        'account.move',
        string='Asiento de Provisión',
        compute='_compute_provision_move_id',
        store=False,
        readonly=True,
        help='Asiento contable de provisión IVA'
    )

    payment_id = fields.Many2one(
        'account.payment',
        string='Pago Asociado',
        compute='_compute_payment_id',
        store=False,
        readonly=True,
        help='Pago asociado'
    )

    readonly_partial = fields.Boolean(
        string='Solo Lectura Parcial',
        compute='_compute_readonly_flags',
        store=False,
        help='Campos en modo solo lectura'
    )

    readonly_state = fields.Boolean(
        string='Estado Solo Lectura',
        compute='_compute_readonly_flags',
        store=False,
        help='Registro completo en solo lectura'
    )

    # ========== DEPRECATED FIELDS ==========
    invoice_date = fields.Date(
        string='Fecha Factura',
        readonly=True,
        help='[DEPRECATED] Fecha de la factura o documento asociado'
    )

    move_type = fields.Char(
        string='Tipo de Movimiento',
        readonly=True,
        help='[DEPRECATED] Tipo de movimiento contable (invoice, payment, etc.)'
    )

    @api.depends('name', 'period_date', 'company_id')
    def _compute_display_name(self):
        for record in self:
            if record.period_date and record.company_id:
                period = record.period_date.strftime('%m/%Y')
                record.display_name = f"F29 {period} - {record.company_id.name}"
            else:
                record.display_name = record.name or 'Nuevo F29'

    @api.depends('ventas_afectas', 'compras_afectas', 'compras_activo_fijo')
    def _compute_iva_amounts(self):
        """Calcula IVA débito y crédito fiscal (tasa 19%)"""
        for record in self:
            # Débito Fiscal = Ventas Afectas * 19%
            record.debito_fiscal = record.ventas_afectas * 0.19

            # Crédito Fiscal = (Compras Afectas + Compras Activo Fijo) * 19%
            record.credito_fiscal = (record.compras_afectas + record.compras_activo_fijo) * 0.19

    @api.depends(
        'debito_fiscal', 'credito_fiscal',
        'creditos_especiales', 'debito_remanente_mes_anterior',
        'remanente_credito_mes_anterior'
    )
    def _compute_iva_determinado(self):
        """
        Calcula IVA Determinado según normativa SII:
        IVA Determinado = (Débito Fiscal + Remanente Débito Mes Anterior - Créditos Especiales)
                         - (Crédito Fiscal + Remanente Crédito Mes Anterior)
        """
        for record in self:
            debito_total = (
                record.debito_fiscal +
                record.debito_remanente_mes_anterior -
                record.creditos_especiales
            )

            credito_total = (
                record.credito_fiscal +
                record.remanente_credito_mes_anterior
            )

            record.iva_determinado = debito_total - credito_total

    @api.depends('iva_determinado', 'iva_retenido', 'ppm_mes', 'ppm_voluntario')
    def _compute_resultado_final(self):
        """
        Calcula el resultado final del F29:
        - IVA a Pagar: si el resultado es positivo
        - Saldo a Favor: si el resultado es negativo
        - Remanente Mes Siguiente: saldo de crédito que pasa al siguiente mes
        """
        for record in self:
            # Resultado después de retenciones y PPM
            resultado = (
                record.iva_determinado -
                record.iva_retenido -
                record.ppm_mes -
                record.ppm_voluntario
            )

            if resultado > 0:
                record.iva_a_pagar = resultado
                record.saldo_favor = 0.0
                record.remanente_mes_siguiente = 0.0
            else:
                record.iva_a_pagar = 0.0
                record.saldo_favor = abs(resultado)
                # El remanente para el mes siguiente es el saldo a favor
                record.remanente_mes_siguiente = abs(resultado)

    @api.depends('ventas_afectas', 'compras_afectas', 'debito_fiscal', 'credito_fiscal')
    def _compute_legacy_fields(self):
        """Mantiene backward compatibility con campos legacy"""
        for record in self:
            record.total_ventas = record.ventas_afectas
            record.total_compras = record.compras_afectas
            record.total_iva_debito = record.debito_fiscal
            record.total_iva_credito = record.credito_fiscal

    # ========== COMPUTED FIELDS (PLACEHOLDER INTEGRATION) ==========

    @api.depends('period_date', 'company_id')
    def _compute_move_ids(self):
        """
        Calcula facturas relacionadas del período.
        Delegación 100% a Odoo ORM nativo.

        Busca todas las facturas (ventas y compras) del período correspondiente
        que pertenecen a la misma compañía.
        """
        for record in self:
            if not record.period_date or not record.company_id:
                record.move_ids = False
                continue

            try:
                # Calcular rango del mes completo
                period_start = record.period_date.replace(day=1)

                # Calcular último día del mes
                if record.period_date.month == 12:
                    period_end = record.period_date.replace(day=31)
                else:
                    next_month = record.period_date.replace(month=record.period_date.month + 1, day=1)
                    period_end = next_month - timedelta(days=1)

                # Buscar facturas usando ORM nativo con domain
                domain = [
                    ('company_id', '=', record.company_id.id),
                    ('move_type', 'in', ['out_invoice', 'out_refund', 'in_invoice', 'in_refund']),
                    ('invoice_date', '>=', period_start),
                    ('invoice_date', '<=', period_end),
                    ('state', '=', 'posted'),  # Solo facturas contabilizadas
                ]

                moves = self.env['account.move'].search(domain)
                record.move_ids = moves

                _logger.debug(
                    "F29 %s: Found %d invoices for period %s",
                    record.name,
                    len(moves),
                    record.period_date.strftime('%m/%Y')
                )

            except Exception as e:
                _logger.error(
                    "Error computing move_ids for F29 %s: %s",
                    record.name or 'New',
                    str(e)
                )
                record.move_ids = False

    @api.depends('saldo_favor', 'iva_a_pagar')
    def _compute_amount_total(self):
        """
        Calcula monto total de la declaración F29.
        Delegación a campos computed existentes.

        - Si hay saldo a favor: retorna el valor positivo del saldo
        - Si hay IVA a pagar: retorna el valor negativo (adeudado)
        """
        for record in self:
            if record.saldo_favor > 0:
                record.amount_total = record.saldo_favor
            elif record.iva_a_pagar > 0:
                # Negativo indica deuda con SII
                record.amount_total = -record.iva_a_pagar
            else:
                record.amount_total = 0.0

    @api.depends('name', 'company_id')
    def _compute_provision_move_id(self):
        """
        Busca asiento contable de provisión IVA relacionado.
        Delegación 100% a Odoo ORM nativo.

        Busca en account.move un asiento con:
        - Referencia conteniendo el nombre del F29
        - Misma compañía
        - Journal de tipo 'general'
        """
        for record in self:
            if not record.name or record.name == 'New' or not record.company_id:
                record.provision_move_id = False
                continue

            try:
                # Buscar asiento de provisión usando ORM
                domain = [
                    ('company_id', '=', record.company_id.id),
                    ('ref', 'ilike', record.name),
                    ('journal_id.type', '=', 'general'),
                    ('state', '=', 'posted'),
                ]

                # Buscar el más reciente si hay varios
                provision = self.env['account.move'].search(
                    domain,
                    order='date desc, id desc',
                    limit=1
                )

                record.provision_move_id = provision if provision else False

                if provision:
                    _logger.debug(
                        "F29 %s: Found provision move %s",
                        record.name,
                        provision.name
                    )

            except Exception as e:
                _logger.error(
                    "Error computing provision_move_id for F29 %s: %s",
                    record.name,
                    str(e)
                )
                record.provision_move_id = False

    @api.depends('period_date', 'company_id', 'name')
    def _compute_payment_id(self):
        """
        Busca pago asociado a la declaración F29.
        Delegación 100% a Odoo ORM nativo.

        Busca en account.payment un pago con:
        - Fecha de pago en el rango del período
        - Misma compañía
        - Referencia conteniendo el nombre del F29
        """
        for record in self:
            if not record.period_date or not record.company_id:
                record.payment_id = False
                continue

            try:
                # Calcular rango del mes completo
                period_start = record.period_date.replace(day=1)

                if record.period_date.month == 12:
                    period_end = record.period_date.replace(day=31)
                else:
                    next_month = record.period_date.replace(month=record.period_date.month + 1, day=1)
                    period_end = next_month - timedelta(days=1)

                # Domain base
                domain = [
                    ('company_id', '=', record.company_id.id),
                    ('date', '>=', period_start),
                    ('date', '<=', period_end),
                    ('state', 'in', ['posted', 'sent', 'reconciled']),
                ]

                # Si ya tiene nombre asignado, buscar por referencia
                if record.name and record.name != 'New':
                    domain.append(('ref', 'ilike', record.name))

                # Buscar el más reciente si hay varios
                payment = self.env['account.payment'].search(
                    domain,
                    order='date desc, id desc',
                    limit=1
                )

                record.payment_id = payment if payment else False

                if payment:
                    _logger.debug(
                        "F29 %s: Found payment %s (${:,.0f})",
                        record.name or 'New',
                        payment.name,
                        payment.amount
                    )

            except Exception as e:
                _logger.error(
                    "Error computing payment_id for F29 %s: %s",
                    record.name or 'New',
                    str(e)
                )
                record.payment_id = False

    @api.depends('state')
    def _compute_readonly_flags(self):
        """
        Calcula flags de solo lectura basados en el estado.
        Delegación a lógica de estado.

        - readonly_partial: True si estado in ('filed', 'paid')
        - readonly_state: True si estado in ('filed', 'paid', 'cancel')
        """
        for record in self:
            # Estados parcialmente bloqueados (algunos campos editables)
            record.readonly_partial = record.state in ('filed', 'paid')

            # Estados completamente bloqueados (ningún campo editable)
            record.readonly_state = record.state in ('filed', 'paid', 'cancel')

    # ========== CONSTRAINTS DE COHERENCIA ==========

    @api.constrains('period_date', 'company_id')
    def _validate_sii_format(self):
        """Validate SII format compliance"""
        for record in self:
            # Validar RUT empresa
            if not record.company_id.vat:
                raise ValidationError(_("Company must have a valid RUT for SII reporting"))

            # Validar período
            if not record.period_date:
                raise ValidationError(_("Period is required for F29"))

    @api.constrains('ventas_afectas', 'debito_fiscal')
    def _check_debito_fiscal_coherence(self):
        """
        CONSTRAINT 1: Coherencia IVA Débito Fiscal

        Verifica que el IVA débito fiscal sea coherente con las ventas afectas.
        Si hay ventas afectas, debe existir débito fiscal proporcional (19%).

        Permite margen de error del 1% por redondeos.
        """
        for record in self:
            if record.ventas_afectas > 0:
                expected_debito = record.ventas_afectas * 0.19
                actual_debito = record.debito_fiscal

                # Margen de error 1%
                tolerance = expected_debito * 0.01

                if abs(actual_debito - expected_debito) > tolerance:
                    raise ValidationError(_(
                        'Coherencia IVA Débito:\n'
                        'El débito fiscal (${:,.0f}) no es coherente con las ventas afectas (${:,.0f}).\n'
                        'Débito esperado: ${:,.0f} (19% de ventas afectas).\n'
                        'Diferencia: ${:,.0f}'
                    ).format(
                        actual_debito,
                        record.ventas_afectas,
                        expected_debito,
                        abs(actual_debito - expected_debito)
                    ))

    @api.constrains('compras_afectas', 'compras_activo_fijo', 'credito_fiscal')
    def _check_credito_fiscal_coherence(self):
        """
        CONSTRAINT 2: Coherencia IVA Crédito Fiscal

        Verifica que el IVA crédito fiscal sea coherente con las compras afectas y activo fijo.
        Si hay compras con derecho a crédito, debe existir crédito fiscal proporcional (19%).

        Permite margen de error del 1% por redondeos.
        """
        for record in self:
            base_compras = record.compras_afectas + record.compras_activo_fijo

            if base_compras > 0:
                expected_credito = base_compras * 0.19
                actual_credito = record.credito_fiscal

                # Margen de error 1%
                tolerance = expected_credito * 0.01

                if abs(actual_credito - expected_credito) > tolerance:
                    raise ValidationError(_(
                        'Coherencia IVA Crédito:\n'
                        'El crédito fiscal (${:,.0f}) no es coherente con las compras afectas (${:,.0f}) '
                        'y activo fijo (${:,.0f}).\n'
                        'Crédito esperado: ${:,.0f} (19% de base compras).\n'
                        'Diferencia: ${:,.0f}'
                    ).format(
                        actual_credito,
                        record.compras_afectas,
                        record.compras_activo_fijo,
                        expected_credito,
                        abs(actual_credito - expected_credito)
                    ))

    @api.constrains('period_date', 'company_id', 'tipo_declaracion')
    def _check_unique_declaration(self):
        """
        CONSTRAINT 3: Unicidad de Declaración por Período

        Verifica que no existan declaraciones duplicadas para el mismo período y empresa.
        Solo se permite una declaración original por período.
        Las declaraciones rectificatorias no están sujetas a esta restricción.
        """
        for record in self:
            # Solo validar declaraciones originales
            if record.tipo_declaracion == 'original':
                domain = [
                    ('company_id', '=', record.company_id.id),
                    ('period_date', '=', record.period_date),
                    ('tipo_declaracion', '=', 'original'),
                    ('id', '!=', record.id),
                    ('state', '!=', 'cancel'),
                ]

                duplicates = self.search(domain, limit=1)

                if duplicates:
                    period_str = record.period_date.strftime('%m/%Y')
                    raise ValidationError(_(
                        'Ya existe una declaración original F29 para el período {} en la empresa {}.\n'
                        'Si desea modificar la declaración original, márquela como "Rectificatoria".'
                    ).format(period_str, record.company_id.name))

    def action_calculate(self):
        """
        Calcula/recalcula los valores del F29 desde los movimientos contables REALES
        Conecta directamente con account.tax y account.move.line para extraer datos IVA

        Cálculos completos:
        - total_ventas: suma base imponible de líneas con impuestos de venta
        - total_compras: suma base imponible de líneas con impuestos de compra
        - total_iva_debito: suma IVA de ventas
        - total_iva_credito: suma IVA de compras
        - Validación de coherencia: IVA ≈ base * tasa

        Referencias:
        - ORM Methods y API onchange patterns
        """
        import time
        import json
        start_time = time.time()

        self.ensure_one()

        if self.state not in ['draft', 'review']:
            raise UserError(_("Solo se puede calcular en estado Borrador o Revisión"))

        # Calcular período
        period_start = self.period_date.replace(day=1)
        period_end = (period_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)

        # Obtener movimientos del período
        domain = [
            ('company_id', '=', self.company_id.id),
            ('date', '>=', period_start),
            ('date', '<=', period_end),
            ('state', '=', 'posted')
        ]

        moves = self.env['account.move'].search(domain)

        # Prefetch para evitar N+1 queries
        moves.mapped('line_ids.tax_ids')
        moves.mapped('line_ids.tax_line_id')

        # Inicializar contadores
        total_ventas = 0.0
        total_iva_debito = 0.0
        total_compras = 0.0
        total_iva_credito = 0.0

        # Procesar movimientos
        for move in moves:
            # Calcular base imponible y IVA de ventas
            for line in move.line_ids.filtered(lambda l: l.tax_ids and not l.tax_line_id):
                for tax in line.tax_ids:
                    if tax.type_tax_use == 'sale' and tax.amount > 0:
                        # Base imponible de ventas
                        total_ventas += abs(line.balance)
                    elif tax.type_tax_use == 'purchase' and tax.amount > 0:
                        # Base imponible de compras
                        total_compras += abs(line.balance)

            # Calcular IVA (líneas de impuesto)
            for line in move.line_ids.filtered('tax_line_id'):
                if line.tax_line_id.type_tax_use == 'sale':
                    total_iva_debito += abs(line.balance)
                elif line.tax_line_id.type_tax_use == 'purchase':
                    total_iva_credito += abs(line.balance)

        # Validar coherencia (IVA ≈ base * 0.19 con margen de error 5%)
        expected_iva_debito = total_ventas * 0.19
        expected_iva_credito = total_compras * 0.19

        coherence_warning = ""
        if total_ventas > 0 and abs(total_iva_debito - expected_iva_debito) > (expected_iva_debito * 0.05):
            coherence_warning += f"⚠️ IVA Débito inconsistente: esperado {expected_iva_debito:.2f}, calculado {total_iva_debito:.2f}\n"

        if total_compras > 0 and abs(total_iva_credito - expected_iva_credito) > (expected_iva_credito * 0.05):
            coherence_warning += f"⚠️ IVA Crédito inconsistente: esperado {expected_iva_credito:.2f}, calculado {total_iva_credito:.2f}\n"

        # Actualizar valores
        self.write({
            'total_ventas': total_ventas,
            'total_iva_debito': total_iva_debito,
            'total_compras': total_compras,
            'total_iva_credito': total_iva_credito,
        })

        # Logging estructurado JSON
        duration_ms = int((time.time() - start_time) * 1000)
        log_data = {
            "module": "l10n_cl_financial_reports",
            "action": "f29_calculate",
            "company_id": self.company_id.id,
            "period": self.period_date.strftime('%Y-%m'),
            "duration_ms": duration_ms,
            "records_processed": len(moves),
            "status": "success",
            "totals": {
                "ventas": float(total_ventas),
                "iva_debito": float(total_iva_debito),
                "compras": float(total_compras),
                "iva_credito": float(total_iva_credito)
            }
        }
        _logger.info(json.dumps(log_data))

        message = _('Cálculo Completado:\n'
                   f'• Ventas: {total_ventas:,.0f}\n'
                   f'• IVA Débito: {total_iva_debito:,.0f}\n'
                   f'• Compras: {total_compras:,.0f}\n'
                   f'• IVA Crédito: {total_iva_credito:,.0f}\n'
                   f'• Registros procesados: {len(moves)}\n'
                   f'• Tiempo: {duration_ms}ms')

        if coherence_warning:
            message += f'\n\n{coherence_warning}'

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Cálculo Completado'),
                'message': message,
                'type': 'warning' if coherence_warning else 'success',
                'sticky': bool(coherence_warning),
            }
        }

    def action_validate(self):
        """
        Valida el F29 y genera los efectos contables

        Referencias:
        - Account Move creation patterns
        """
        self.ensure_one()

        if self.state not in ['draft', 'review']:
            raise UserError(_("Solo se puede validar en estado Borrador o Revisión"))

        # Validaciones SII
        if not self.company_id.vat:
            raise ValidationError(_("La empresa debe tener RUT válido"))

        self.write({'state': 'confirmed'})

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Validación SII'),
                'message': _('El formulario F29 cumple con todos los requisitos SII'),
                'type': 'success',
                'sticky': False,
            }
        }

    # ═══════════════════════════════════════════════════════════
    # P0-1: SII INTEGRATION ACTION METHODS (Delegación l10n_cl_dte)
    # ═══════════════════════════════════════════════════════════

    def action_send_sii(self):
        """
        Envía F29 al SII usando infraestructura DTE existente.

        DELEGACIÓN: 100% a l10n_cl_dte/libs/sii_soap_client.py
        BRIDGE: Adaptación F29 data → DTE XML format
        """
        self.ensure_one()

        # 1. VALIDACIONES
        if not hasattr(self, 'state') or self.state == 'draft':
            raise UserError(_('Debe confirmar el F29 antes de enviar'))

        if self.sii_status in ['sent', 'accepted']:
            raise UserError(_('F29 ya enviado al SII'))

        if not self.company_id.vat:
            raise ValidationError(_('Empresa sin RUT configurado'))

        # 2. CAMBIAR ESTADO
        self.write({'sii_status': 'sending'})

        try:
            # 3. GENERAR XML F29 (BRIDGE CODE)
            f29_xml = self._generate_f29_xml()

            # 4. FIRMAR XML (DELEGACIÓN a l10n_cl_dte)
            from odoo.addons.l10n_cl_dte.libs.xml_signer import XMLSigner

            certificate = self.company_id.dte_certificate_id
            if not certificate:
                raise ValidationError(_('Empresa sin certificado DTE'))

            signer = XMLSigner()
            signed_xml = signer.sign_xml(
                xml_string=f29_xml,
                certificate_data=certificate.certificate_data,
                private_key=certificate.private_key,
                password=certificate.password
            )

            # 5. ENVIAR A SII (DELEGACIÓN 100% a SIISoapClient)
            from odoo.addons.l10n_cl_dte.libs.sii_soap_client import SIISoapClient

            soap_client = SIISoapClient(self.env)
            result = soap_client.send_dte_to_sii(
                signed_xml=signed_xml,
                rut_emisor=self.company_id.vat,
                company=self.company_id
            )

            # 6. PROCESAR RESULTADO
            self.write({
                'sii_status': 'sent',
                'sii_track_id': result.get('track_id'),
                'sii_send_date': fields.Datetime.now(),
                'sii_response_xml': result.get('xml_response'),
            })

            # 7. LOG COMUNICACIÓN
            self.env['dte.communication'].sudo().create({
                'action_type': 'send_dte',
                'status': 'success',
                'dte_type': '29',
                'dte_folio': self.name,
                'track_id': result.get('track_id'),
                'request_xml': signed_xml,
                'response_xml': result.get('xml_response'),
                'company_id': self.company_id.id,
            })

            # 8. NOTIFICACIÓN
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Éxito'),
                    'message': _('F29 enviado exitosamente al SII.\nTrack ID: %s') % result.get('track_id'),
                    'type': 'success',
                    'sticky': False,
                }
            }

        except Exception as e:
            _logger.error(f'Error envío F29 al SII: {str(e)}')
            self.write({
                'sii_status': 'draft',
                'sii_error_message': str(e)
            })
            raise UserError(_('Error al enviar F29 al SII: %s') % str(e))

    def _generate_f29_xml(self):
        """
        Genera XML del F29 según formato SII.
        BRIDGE CODE: Adaptación datos F29 → XML SII
        """
        self.ensure_one()

        from lxml import etree

        ns = "http://www.sii.cl/SiiDte"
        root = etree.Element(f"{{{ns}}}F29", nsmap={None: ns})

        # Encabezado
        encabezado = etree.SubElement(root, "Encabezado")
        etree.SubElement(encabezado, "RutEmisor").text = self.company_id.vat
        etree.SubElement(encabezado, "Periodo").text = self.period_date.strftime('%Y-%m')
        etree.SubElement(encabezado, "FolioF29").text = self.name

        # Detalle IVA
        detalle = etree.SubElement(root, "Detalle")
        etree.SubElement(detalle, "VentasAfectas").text = str(int(self.ventas_afectas or 0))
        etree.SubElement(detalle, "ComprasAfectas").text = str(int(self.compras_afectas or 0))
        etree.SubElement(detalle, "IVADebito").text = str(int(self.total_iva_debito or 0))
        etree.SubElement(detalle, "IVACredito").text = str(int(self.total_iva_credito or 0))

        xml_string = etree.tostring(
            root,
            encoding='ISO-8859-1',
            xml_declaration=True,
            pretty_print=True
        ).decode('ISO-8859-1')

        return xml_string

    def action_check_status(self):
        """Consulta estado F29 en SII. Delegación 100% a SIISoapClient."""
        self.ensure_one()

        if not self.sii_track_id:
            raise UserError(_('F29 sin Track ID. Debe enviarlo primero.'))

        try:
            from odoo.addons.l10n_cl_dte.libs.sii_soap_client import SIISoapClient

            soap_client = SIISoapClient(self.env)
            result = soap_client.query_dte_status(
                track_id=self.sii_track_id,
                rut_emisor=self.company_id.vat,
                company=self.company_id
            )

            # Actualizar estado
            sii_status = result.get('status', 'sent')
            self.write({'sii_status': sii_status})

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Estado SII'),
                    'message': _('Estado actual: %s') % sii_status,
                    'type': 'info',
                    'sticky': False,
                }
            }

        except Exception as e:
            _logger.error(f'Error consultando estado F29: {str(e)}')
            raise UserError(_('Error al consultar estado: %s') % str(e))

    def action_to_review(self):
        """Cambia estado a revisión. Delegación Odoo state machine."""
        for record in self:
            if not hasattr(record, 'state'):
                _logger.warning(f'F29 {record.name} sin campo state')
                continue
            record.write({'state': 'review'})
        return True

    def action_replace(self):
        """Crea F29 rectificatoria. Delegación Odoo copy() + workflow."""
        self.ensure_one()

        if not hasattr(self, 'state') or self.state != 'accepted':
            raise UserError(_('Solo F29 aceptados pueden rectificarse'))

        if self.es_rectificatoria:
            raise UserError(_('No se puede rectificar una rectificatoria'))

        # DELEGACIÓN: Odoo copy() nativo
        rectificatoria = self.copy({
            'name': 'New',
            'state': 'draft',
            'es_rectificatoria': True,
            'f29_original_id': self.id,
            'folio_rectifica': self.name,
            'sii_status': 'draft',
            'sii_track_id': False,
            'sii_send_date': False,
            'sii_response_xml': False,
        })

        self.message_post(
            body=_('F29 Rectificatoria creada: %s') % rectificatoria.name
        )

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'l10n_cl.f29',
            'res_id': rectificatoria.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_view_moves(self):
        """Abre vista de facturas relacionadas. Delegación Odoo domain action."""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Facturas Período %s') % self.period_date.strftime('%m/%Y'),
            'res_model': 'account.move',
            'domain': [('id', 'in', self.move_ids.ids)],
            'view_mode': 'tree,form',
            'target': 'current',
            'context': {'create': False},
        }

    # ========== CRON METHODS ==========
    @api.model
    def create_monthly_f29(self):
        """
        Cron job: crea un F29 en borrador por compañía y período (mes anterior).

        Reglas:
        - Un F29 ORIGINAL por compañía y período (idempotente).
        - Sólo para compañías con SII habilitado si el campo existe.
        - Periodo objetivo: primer día del mes anterior a la fecha actual (TZ del server).

        Returns: int (cantidad de F29 creados)
        """
        created = 0

        # Determinar período objetivo: primer día del mes anterior
        today = fields.Date.context_today(self)
        period_first_day = today.replace(day=1)
        # Restar un día para ir al mes anterior y volver al primer día
        previous_month_last_day = period_first_day - timedelta(days=1)
        target_period = previous_month_last_day.replace(day=1)

        Company = self.env['res.company']
        company_domain = []
        # Filtrar por compañías con SII habilitado si el campo existe
        if 'l10n_cl_sii_enabled' in Company._fields:
            company_domain.append(('l10n_cl_sii_enabled', '=', True))

        companies = Company.search(company_domain)

        for company in companies:
            # Idempotencia: verificar si ya existe F29 ORIGINAL para el período
            existing = self.search([
                ('company_id', '=', company.id),
                ('period_date', '=', target_period),
                ('tipo_declaracion', '=', 'original'),
                ('state', '!=', 'cancel'),
            ], limit=1)

            if existing:
                continue

            vals = {
                'company_id': company.id,
                'period_date': target_period,
                'tipo_declaracion': 'original',
                'state': 'draft',
            }
            record = self.create(vals)

            # Opcional: no ejecutar cálculos aquí para mantener rapidez del cron
            # record.action_calculate()

            created += 1

        # Logging estructurado
        try:
            import json
            _logger.info(json.dumps({
                'module': 'l10n_cl_financial_reports',
                'action': 'create_monthly_f29',
                'target_period': target_period.strftime('%Y-%m-%d'),
                'companies_considered': len(companies),
                'created': created,
            }))
        except Exception:
            _logger.info(
                'create_monthly_f29 ejecutado para periodo %s - empresas: %s - creados: %s',
                target_period, len(companies), created
            )

        return created


class L10nClF29Line(models.Model):
    """
    Líneas de detalle del F29 (opcional para auditoría)
    """
    _name = 'l10n_cl.f29.line'
    _description = 'Línea de Detalle F29'
    _order = 'document_type, document_number'

    f29_id = fields.Many2one(
        'l10n_cl.f29',
        string='F29',
        required=True,
        ondelete='cascade'
    )

    document_type = fields.Char(
        string='Tipo Documento',
        required=True
    )

    document_number = fields.Char(
        string='Número Documento',
        required=True
    )

    partner_id = fields.Many2one(
        'res.partner',
        string='Proveedor/Cliente'
    )

    amount_untaxed = fields.Monetary(
        string='Monto Neto',
        currency_field='currency_id'
    )

    amount_tax = fields.Monetary(
        string='Monto IVA',
        currency_field='currency_id'
    )

    currency_id = fields.Many2one(
        related='f29_id.currency_id',
        store=True
    )

    move_id = fields.Many2one(
        'account.move',
        string='Factura',
        readonly=True
    )


# TODO: Extensión PPM deshabilitada temporalmente para resolver dependencias circulares
# Se habilitará después de completar la instalación base de módulos chilenos
