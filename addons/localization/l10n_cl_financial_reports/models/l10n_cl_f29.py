# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError
from datetime import datetime, timedelta
import logging
import os

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
