# -*- coding: utf-8 -*-
"""
Modelo para Períodos Mensuales del Registro de Compras y Ventas (RCV)

Agrupa las entradas RCV por mes para facilitar:
- Generación de declaración F29
- Análisis mensual de IVA
- Validación con propuesta SII
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class L10nClRCVPeriod(models.Model):
    """
    Período mensual del Registro de Compras y Ventas (RCV).

    Cada período agrupa todas las entradas RCV de un mes específico,
    permitiendo cálculo de IVA y generación de F29.

    Resolución SII 61/2017: El RCV se mantiene de forma continua y
    se consolida mensualmente para la declaración de IVA (F29).
    """
    _name = 'l10n_cl.rcv.period'
    _description = 'RCV Period - Período Mensual RCV Chile'
    _order = 'period_date desc'
    _rec_name = 'display_name'

    # ========================
    # IDENTIFICACIÓN
    # ========================
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        index=True
    )

    period_date = fields.Date(
        string='Período (Mes/Año)',
        required=True,
        index=True,
        help='Primer día del mes del período'
    )

    display_name = fields.Char(
        string='Nombre',
        compute='_compute_display_name',
        store=True
    )

    state = fields.Selection([
        ('open', 'Abierto'),
        ('closed', 'Cerrado'),
        ('declared', 'Declarado (F29)'),
    ], string='Estado', default='open', index=True)

    # ========================
    # RELACIONES
    # ========================
    entry_ids = fields.One2many(
        'l10n_cl.rcv.entry',
        'period_id',
        string='Entradas RCV'
    )

    # ========================
    # ESTADÍSTICAS VENTAS
    # ========================
    sale_entry_count = fields.Integer(
        string='# Ventas',
        compute='_compute_stats',
        store=True
    )

    total_sales = fields.Monetary(
        string='Total Ventas',
        currency_field='currency_id',
        compute='_compute_stats',
        store=True
    )

    # ========================
    # ESTADÍSTICAS COMPRAS
    # ========================
    purchase_entry_count = fields.Integer(
        string='# Compras',
        compute='_compute_stats',
        store=True
    )

    total_purchases = fields.Monetary(
        string='Total Compras',
        currency_field='currency_id',
        compute='_compute_stats',
        store=True
    )

    # ========================
    # IVA
    # ========================
    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.ref('base.CLP'),
        required=True
    )

    vat_debit = fields.Monetary(
        string='IVA Débito Fiscal',
        currency_field='currency_id',
        compute='_compute_vat',
        store=True,
        help='IVA de ventas (a pagar al SII)'
    )

    vat_credit = fields.Monetary(
        string='IVA Crédito Fiscal',
        currency_field='currency_id',
        compute='_compute_vat',
        store=True,
        help='IVA de compras (a favor del contribuyente)'
    )

    vat_balance = fields.Monetary(
        string='Saldo IVA (a Pagar/Favor)',
        currency_field='currency_id',
        compute='_compute_vat',
        store=True,
        help='Positivo: a pagar | Negativo: a favor'
    )

    # ========================
    # SINCRONIZACIÓN SII
    # ========================
    sii_f29_proposal = fields.Text(
        string='Propuesta F29 (SII)',
        help='Propuesta de declaración F29 obtenida desde el SII'
    )

    sii_f29_fetched_date = fields.Datetime(
        string='Fecha Obtención F29',
        help='Última vez que se obtuvo propuesta F29 del SII'
    )

    sii_last_sync_date = fields.Datetime(
        string='Última Sincronización SII',
        help='Última vez que se sincronizó con RCV del SII'
    )

    sii_discrepancy_count = fields.Integer(
        string='# Discrepancias SII',
        compute='_compute_discrepancy_count',
        store=True,
        help='Cantidad de entradas con discrepancias vs SII'
    )

    # ========================
    # DECLARACIÓN F29
    # ========================
    tax_return_move_id = fields.Many2one(
        'account.move',
        string='Declaración F29',
        help='Asiento contable de la declaración F29'
    )

    f29_declaration_date = fields.Date(
        string='Fecha Declaración F29',
        help='Fecha en que se declaró el F29'
    )

    # ========================
    # CONSTRAINTS (Odoo 19 CE format)
    # ========================
    _unique_period = models.Constraint(
        'UNIQUE(company_id, period_date)',
        'Ya existe un período RCV para esta empresa en esta fecha.'
    )

    # ========================
    # COMPUTED FIELDS
    # ========================
    @api.depends('period_date')
    def _compute_display_name(self):
        """Genera nombre del período (Mes YYYY)"""
        for rec in self:
            if rec.period_date:
                month_names = [
                    'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
                    'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
                ]
                month_name = month_names[rec.period_date.month - 1]
                rec.display_name = f"RCV {month_name} {rec.period_date.year}"
            else:
                rec.display_name = 'Período RCV'

    @api.depends('entry_ids', 'entry_ids.amount_total', 'entry_ids.entry_type')
    def _compute_stats(self):
        """Calcula estadísticas del período"""
        for rec in self:
            sales = rec.entry_ids.filtered(lambda e: e.entry_type == 'sale')
            purchases = rec.entry_ids.filtered(lambda e: e.entry_type == 'purchase')

            rec.sale_entry_count = len(sales)
            rec.purchase_entry_count = len(purchases)
            rec.total_sales = sum(sales.mapped('amount_total'))
            rec.total_purchases = sum(purchases.mapped('amount_total'))

    @api.depends('entry_ids', 'entry_ids.amount_tax', 'entry_ids.entry_type')
    def _compute_vat(self):
        """Calcula IVA del período"""
        for rec in self:
            sales = rec.entry_ids.filtered(lambda e: e.entry_type == 'sale')
            purchases = rec.entry_ids.filtered(lambda e: e.entry_type == 'purchase')

            rec.vat_debit = sum(sales.mapped('amount_tax'))
            rec.vat_credit = sum(purchases.mapped('amount_tax'))
            rec.vat_balance = rec.vat_debit - rec.vat_credit

    @api.depends('entry_ids', 'entry_ids.sii_discrepancy')
    def _compute_discrepancy_count(self):
        """Cuenta entradas con discrepancias"""
        for rec in self:
            rec.sii_discrepancy_count = len(
                rec.entry_ids.filtered(lambda e: e.sii_discrepancy)
            )

    # ========================
    # VALIDATIONS
    # ========================
    @api.constrains('period_date')
    def _check_period_date_is_first_of_month(self):
        """Valida que period_date sea primer día del mes"""
        for rec in self:
            if rec.period_date and rec.period_date.day != 1:
                raise ValidationError(_(
                    'El campo "Período" debe ser el primer día del mes.\n'
                    'Recibido: %s\n'
                    'Esperado: %s'
                ) % (
                    rec.period_date,
                    rec.period_date.replace(day=1)
                ))

    # ========================
    # BUSINESS METHODS
    # ========================
    @api.model
    def _get_or_create_period(self, invoice_date, company_id):
        """
        Obtiene o crea período RCV para una fecha.

        Args:
            invoice_date (date): Fecha de la factura
            company_id (int): ID de la compañía

        Returns:
            l10n_cl.rcv.period: Período correspondiente
        """
        # Calcular primer día del mes
        period_date = invoice_date.replace(day=1)

        # Buscar período existente
        period = self.search([
            ('company_id', '=', company_id),
            ('period_date', '=', period_date),
        ], limit=1)

        # Crear si no existe
        if not period:
            period = self.create({
                'company_id': company_id,
                'period_date': period_date,
                'state': 'open',
            })

            _logger.info(
                "✅ RCV Period created: %s",
                period.display_name
            )

        return period

    # ========================
    # ACTIONS
    # ========================
    def action_sync_with_sii(self):
        """Sincroniza período con RCV del SII"""
        self.ensure_one()

        rcv_integration = self.env['l10n_cl.rcv.integration']

        try:
            # Ejecutar sincronización
            result = rcv_integration.sync_with_sii(
                self.period_date,
                self.company_id.id
            )

            # Actualizar fecha última sincronización
            self.write({
                'sii_last_sync_date': fields.Datetime.now(),
            })

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Sincronización con SII completada'),
                    'type': 'success',
                }
            }

        except Exception as e:
            _logger.error(
                "Error sincronizando RCV con SII: %s",
                str(e)
            )

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Error en sincronización: %s') % str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }

    def action_fetch_f29_proposal(self):
        """Obtiene propuesta F29 desde SII"""
        self.ensure_one()

        rcv_integration = self.env['l10n_cl.rcv.integration']

        try:
            proposal = rcv_integration.get_propuesta_f29(
                self.period_date,
                self.company_id.id
            )

            self.write({
                'sii_f29_proposal': proposal,
                'sii_f29_fetched_date': fields.Datetime.now(),
            })

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Propuesta F29 obtenida desde SII'),
                    'type': 'success',
                }
            }

        except Exception as e:
            _logger.error(
                "Error obteniendo propuesta F29: %s",
                str(e)
            )

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Error obteniendo F29: %s') % str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }

    def action_close_period(self):
        """Cierra el período (no permite más modificaciones)"""
        self.ensure_one()

        if self.state != 'open':
            raise ValidationError(_(
                'Solo se pueden cerrar períodos en estado "Abierto"'
            ))

        self.write({'state': 'closed'})

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': _('Período RCV cerrado'),
                'type': 'success',
            }
        }

    def action_reopen_period(self):
        """Reabre el período"""
        self.ensure_one()

        if self.state == 'declared':
            raise ValidationError(_(
                'No se puede reabrir un período ya declarado en F29'
            ))

        self.write({'state': 'open'})

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': _('Período RCV reabierto'),
                'type': 'success',
            }
        }

    def action_view_entries(self):
        """Abre lista de entradas del período"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Entradas RCV - %s') % self.display_name,
            'res_model': 'l10n_cl.rcv.entry',
            'view_mode': 'tree,form',
            'domain': [('period_id', '=', self.id)],
            'context': {'default_period_id': self.id},
        }

    def action_view_discrepancies(self):
        """Abre lista de entradas con discrepancias"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Discrepancias SII - %s') % self.display_name,
            'res_model': 'l10n_cl.rcv.entry',
            'view_mode': 'tree,form',
            'domain': [
                ('period_id', '=', self.id),
                ('sii_discrepancy', '=', True),
            ],
            'context': {'default_period_id': self.id},
        }

    def action_export_to_excel(self):
        """Exporta período a Excel para análisis"""
        self.ensure_one()

        # TODO: Implementar exportación Excel
        # Podría usar biblioteca openpyxl o xlsxwriter

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': _('Exportación a Excel: Pendiente implementación'),
                'type': 'warning',
            }
        }
