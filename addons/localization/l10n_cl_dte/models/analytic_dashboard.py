# -*- coding: utf-8 -*-
"""
Dashboard de Rentabilidad por Proyecto

Modelo para visualizar KPIs financieros en tiempo real:
- Ingresos (facturas emitidas)
- Costos (compras + facturas proveedores)
- Margen bruto y porcentual
- Presupuesto consumido

Diseñado específicamente para empresas de ingeniería y proyectos.

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-10-23
Basado en: Documentación oficial Odoo 19 CE
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
from odoo.models import Constraint

import logging
_logger = logging.getLogger(__name__)


class AnalyticDashboard(models.Model):
    """
    Dashboard de rentabilidad por cuenta analítica.

    IMPORTANTE: Este módulo usa 'account.analytic.account' (Analytic Accounting)
    que está incluido en Odoo CE base. NO depende del módulo 'project'.

    Para empresas de ingeniería, las cuentas analíticas representan proyectos,
    pero técnicamente son cuentas analíticas genéricas que permiten trazabilidad
    de costos por proyecto, departamento, centro de costo, etc.

    Calcula KPIs financieros en tiempo real consultando:
    - account.move (facturas emitidas y recibidas)
    - purchase.order (órdenes de compra)
    - Usando analytic_distribution para filtrar por cuenta analítica
    """
    _name = 'analytic.dashboard'
    _description = 'Dashboard Rentabilidad Cuentas Analíticas'
    _rec_name = 'analytic_account_id'
    _order = 'margin_percentage desc'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    analytic_account_id = fields.Many2one(
        'account.analytic.account',
        string='Cuenta Analítica',
        required=True,
        ondelete='cascade',
        index=True,
        help='Cuenta analítica para trazabilidad de costos. '
             'Puede representar un proyecto, departamento o centro de costo.'
    )

    company_id = fields.Many2one(
        'res.company',
        related='analytic_account_id.company_id',
        store=True,
        string='Compañía'
    )

    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Moneda'
    )

    # ═══════════════════════════════════════════════════════════
    # INGRESOS
    # ═══════════════════════════════════════════════════════════

    total_invoiced = fields.Monetary(
        compute='_compute_financials',
        store=True,
        string='Total Facturado',
        currency_field='currency_id',
        help='Suma de facturas emitidas (out_invoice) del proyecto'
    )

    dtes_emitted_count = fields.Integer(
        compute='_compute_financials',
        string='# DTEs Emitidos',
        help='Cantidad de DTEs 33 emitidos'
    )

    # ═══════════════════════════════════════════════════════════
    # COSTOS
    # ═══════════════════════════════════════════════════════════

    total_purchases = fields.Monetary(
        compute='_compute_financials',
        string='Total Órdenes Compra',
        currency_field='currency_id',
        help='Suma de purchase.order del proyecto'
    )

    total_vendor_invoices = fields.Monetary(
        compute='_compute_financials',
        string='Total Fact. Proveedores',
        currency_field='currency_id',
        help='Suma de facturas recibidas (in_invoice) del proyecto'
    )

    total_costs = fields.Monetary(
        compute='_compute_financials',
        store=True,
        string='Costos Totales',
        currency_field='currency_id',
        help='Suma de compras + facturas proveedores'
    )

    # ═══════════════════════════════════════════════════════════
    # RENTABILIDAD
    # ═══════════════════════════════════════════════════════════

    gross_margin = fields.Monetary(
        compute='_compute_financials',
        store=True,
        string='Margen Bruto',
        currency_field='currency_id',
        help='Facturado - Costos'
    )

    margin_percentage = fields.Float(
        compute='_compute_financials',
        store=True,
        string='% Margen',
        help='(Margen / Facturado) × 100'
    )

    # ═══════════════════════════════════════════════════════════
    # PRESUPUESTO
    # ═══════════════════════════════════════════════════════════

    budget = fields.Monetary(
        string='Presupuesto',
        currency_field='currency_id',
        help='Presupuesto total del proyecto'
    )

    budget_consumed_amount = fields.Monetary(
        compute='_compute_financials',
        string='Presupuesto Consumido',
        currency_field='currency_id'
    )

    budget_consumed_percentage = fields.Float(
        compute='_compute_financials',
        store=True,
        string='% Presupuesto Consumido'
    )

    budget_original = fields.Monetary(
        string='Presupuesto Original',
        currency_field='currency_id',
        help='Presupuesto base asignado a la cuenta analítica'
    )

    budget_remaining = fields.Monetary(
        compute='_compute_budget_status',
        string='Presupuesto Restante',
        currency_field='currency_id',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO Y CONTADORES
    # ═══════════════════════════════════════════════════════════

    analytic_status = fields.Selection([
        ('on_budget', 'On Budget'),
        ('at_risk', 'At Risk'),
        ('over_budget', 'Over Budget')
    ], string='Estado', compute='_compute_budget_status', store=True,
       help='Estado presupuestario: on_budget (<85%), at_risk (85-100%), over_budget (>100%)')

    purchases_count = fields.Integer(
        compute='_compute_financials',
        string='# Órdenes Compra',
        help='Cantidad de órdenes de compra'
    )

    vendor_invoices_count = fields.Integer(
        compute='_compute_financials',
        string='# Facturas Proveedores',
        help='Cantidad de facturas recibidas'
    )

    # ═══════════════════════════════════════════════════════════
    # METADATA
    # ═══════════════════════════════════════════════════════════

    last_update = fields.Datetime(
        string='Última Actualización',
        default=fields.Datetime.now,
        readonly=True
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════

    @api.depends('analytic_account_id')
    def _compute_financials(self):
        """
        Calcula todos los KPIs financieros de la cuenta analítica.

        Basado en:
        - analytic_distribution (campo JSON Odoo 19)
        - Formato: {"account_id": percentage} donde sum = 100
        """
        for dashboard in self:
            if not dashboard.analytic_account_id:
                # Sin proyecto, todos los campos en cero
                dashboard.total_invoiced = 0
                dashboard.dtes_emitted_count = 0
                dashboard.total_purchases = 0
                dashboard.total_vendor_invoices = 0
                dashboard.total_costs = 0
                dashboard.gross_margin = 0
                dashboard.margin_percentage = 0
                dashboard.budget_consumed_amount = 0
                dashboard.budget_consumed_percentage = 0
                continue

            analytic_id_str = str(dashboard.analytic_account_id.id)

            # ══════════════════════════════════════════════
            # INGRESOS: Facturas emitidas (out_invoice)
            # ══════════════════════════════════════════════

            invoices_out = self.env['account.move'].search([
                ('move_type', '=', 'out_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ])

            dashboard.total_invoiced = sum(invoices_out.mapped('amount_total'))
            dashboard.dtes_emitted_count = len(invoices_out)

            # ══════════════════════════════════════════════
            # COSTOS: Órdenes de compra
            # ══════════════════════════════════════════════

            purchases = self.env['purchase.order'].search([
                ('state', 'in', ['purchase', 'done']),
                ('analytic_account_id', '=', dashboard.analytic_account_id.id)
            ])

            dashboard.total_purchases = sum(purchases.mapped('amount_total'))
            dashboard.purchases_count = len(purchases)  # ⭐ NUEVO: contador

            # ══════════════════════════════════════════════
            # COSTOS: Facturas proveedores (in_invoice)
            # ══════════════════════════════════════════════

            invoices_in = self.env['account.move'].search([
                ('move_type', '=', 'in_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ])

            dashboard.total_vendor_invoices = sum(invoices_in.mapped('amount_total'))
            dashboard.vendor_invoices_count = len(invoices_in)  # ⭐ NUEVO: contador

            # ══════════════════════════════════════════════
            # TOTALES
            # ══════════════════════════════════════════════

            dashboard.total_costs = (
                dashboard.total_purchases +
                dashboard.total_vendor_invoices
            )

            dashboard.gross_margin = (
                dashboard.total_invoiced -
                dashboard.total_costs
            )

            dashboard.margin_percentage = (
                (dashboard.gross_margin / dashboard.total_invoiced * 100)
                if dashboard.total_invoiced else 0
            )

            # ══════════════════════════════════════════════
            # PRESUPUESTO
            # ══════════════════════════════════════════════

            dashboard.budget_consumed_amount = dashboard.total_costs

            dashboard.budget_consumed_percentage = (
                (dashboard.total_costs / dashboard.budget * 100)
                if dashboard.budget else 0
            )

            # ⭐ NUEVO: Actualizar timestamp
            dashboard.last_update = fields.Datetime.now()

    @api.depends('total_costs', 'budget_original')
    def _compute_budget_status(self):
        """
        Calcula estado presupuestario y presupuesto restante.

        Estados:
        - on_budget: Consumo < 85% presupuesto
        - at_risk: Consumo 85-100% presupuesto
        - over_budget: Consumo > 100% presupuesto
        """
        for dashboard in self:
            if not dashboard.budget_original or dashboard.budget_original == 0:
                dashboard.analytic_status = 'on_budget'
                dashboard.budget_remaining = 0
                continue

            consumed_pct = (dashboard.total_costs / dashboard.budget_original) * 100
            dashboard.budget_remaining = dashboard.budget_original - dashboard.total_costs

            if consumed_pct > 100:
                dashboard.analytic_status = 'over_budget'
            elif consumed_pct >= 85:
                dashboard.analytic_status = 'at_risk'
            else:
                dashboard.analytic_status = 'on_budget'

    # ═══════════════════════════════════════════════════════════
    # ACCIONES (DRILL-DOWN)
    # ═══════════════════════════════════════════════════════════

    def action_view_invoices_out(self):
        """Ver facturas emitidas del proyecto"""
        self.ensure_one()
        analytic_id_str = str(self.analytic_account_id.id)

        return {
            'type': 'ir.actions.act_window',
            'name': f'Facturas Emitidas - {self.analytic_account_id.name}',
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('move_type', '=', 'out_invoice'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ],
            'context': {'default_move_type': 'out_invoice'}
        }

    def action_view_invoices_in(self):
        """Ver facturas recibidas del proyecto"""
        self.ensure_one()
        analytic_id_str = str(self.analytic_account_id.id)

        return {
            'type': 'ir.actions.act_window',
            'name': f'Facturas Proveedores - {self.analytic_account_id.name}',
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('move_type', '=', 'in_invoice'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ],
            'context': {'default_move_type': 'in_invoice'}
        }

    def action_view_purchases(self):
        """Ver órdenes de compra del proyecto"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': f'Órdenes de Compra - {self.analytic_account_id.name}',
            'res_model': 'purchase.order',
            'view_mode': 'list,form',
            'domain': [('project_id', '=', self.analytic_account_id.id)],
            'context': {'default_analytic_account_id': self.analytic_account_id.id}
        }

    def action_view_analytic_lines(self):
        """Ver líneas analíticas del proyecto"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': f'Líneas Analíticas - {self.analytic_account_id.name}',
            'res_model': 'account.analytic.line',
            'view_mode': 'list,pivot,graph',
            'domain': [('account_id', '=', self.analytic_account_id.id)],
            'context': {'default_account_id': self.analytic_account_id.id}
        }
