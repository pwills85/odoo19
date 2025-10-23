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

import logging
_logger = logging.getLogger(__name__)


class ProjectDashboard(models.Model):
    """
    Dashboard de rentabilidad por proyecto.

    Calcula KPIs financieros en tiempo real consultando:
    - account.move (facturas emitidas y recibidas)
    - purchase.order (órdenes de compra)
    - Usando analytic_distribution para filtrar por proyecto
    """
    _name = 'project.dashboard'
    _description = 'Dashboard Rentabilidad Proyectos'
    _rec_name = 'project_id'
    _order = 'margin_percentage desc'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    project_id = fields.Many2one(
        'account.analytic.account',
        string='Proyecto',
        required=True,
        ondelete='cascade',
        index=True
    )

    company_id = fields.Many2one(
        'res.company',
        related='project_id.company_id',
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
        string='Costos Totales',
        currency_field='currency_id',
        help='Suma de compras + facturas proveedores'
    )

    # ═══════════════════════════════════════════════════════════
    # RENTABILIDAD
    # ═══════════════════════════════════════════════════════════

    gross_margin = fields.Monetary(
        compute='_compute_financials',
        string='Margen Bruto',
        currency_field='currency_id',
        help='Facturado - Costos'
    )

    margin_percentage = fields.Float(
        compute='_compute_financials',
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
        string='% Presupuesto Consumido'
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════

    @api.depends('project_id')
    def _compute_financials(self):
        """
        Calcula todos los KPIs financieros del proyecto.

        Basado en:
        - analytic_distribution (campo JSON Odoo 19)
        - Formato: {"account_id": percentage} donde sum = 100
        """
        for dashboard in self:
            if not dashboard.project_id:
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

            project_id_str = str(dashboard.project_id.id)

            # ══════════════════════════════════════════════
            # INGRESOS: Facturas emitidas (out_invoice)
            # ══════════════════════════════════════════════

            invoices_out = self.env['account.move'].search([
                ('move_type', '=', 'out_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{project_id_str}"')
            ])

            dashboard.total_invoiced = sum(invoices_out.mapped('amount_total'))
            dashboard.dtes_emitted_count = len(invoices_out)

            # ══════════════════════════════════════════════
            # COSTOS: Órdenes de compra
            # ══════════════════════════════════════════════

            purchases = self.env['purchase.order'].search([
                ('state', 'in', ['purchase', 'done']),
                ('project_id', '=', dashboard.project_id.id)
            ])

            dashboard.total_purchases = sum(purchases.mapped('amount_total'))

            # ══════════════════════════════════════════════
            # COSTOS: Facturas proveedores (in_invoice)
            # ══════════════════════════════════════════════

            invoices_in = self.env['account.move'].search([
                ('move_type', '=', 'in_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{project_id_str}"')
            ])

            dashboard.total_vendor_invoices = sum(invoices_in.mapped('amount_total'))

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

    # ═══════════════════════════════════════════════════════════
    # ACCIONES (DRILL-DOWN)
    # ═══════════════════════════════════════════════════════════

    def action_view_invoices_out(self):
        """Ver facturas emitidas del proyecto"""
        self.ensure_one()
        project_id_str = str(self.project_id.id)

        return {
            'type': 'ir.actions.act_window',
            'name': f'Facturas Emitidas - {self.project_id.name}',
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('move_type', '=', 'out_invoice'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{project_id_str}"')
            ],
            'context': {'default_move_type': 'out_invoice'}
        }

    def action_view_invoices_in(self):
        """Ver facturas recibidas del proyecto"""
        self.ensure_one()
        project_id_str = str(self.project_id.id)

        return {
            'type': 'ir.actions.act_window',
            'name': f'Facturas Proveedores - {self.project_id.name}',
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('move_type', '=', 'in_invoice'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{project_id_str}"')
            ],
            'context': {'default_move_type': 'in_invoice'}
        }

    def action_view_purchases(self):
        """Ver órdenes de compra del proyecto"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': f'Órdenes de Compra - {self.project_id.name}',
            'res_model': 'purchase.order',
            'view_mode': 'list,form',
            'domain': [('project_id', '=', self.project_id.id)],
            'context': {'default_project_id': self.project_id.id}
        }

    def action_view_analytic_lines(self):
        """Ver líneas analíticas del proyecto"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': f'Líneas Analíticas - {self.project_id.name}',
            'res_model': 'account.analytic.line',
            'view_mode': 'list,pivot,graph',
            'domain': [('account_id', '=', self.project_id.id)],
            'context': {'default_account_id': self.project_id.id}
        }
