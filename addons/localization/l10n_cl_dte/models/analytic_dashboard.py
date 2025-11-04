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
from odoo.exceptions import ValidationError, UserError
from odoo.models import Constraint

import logging
import io
import base64
from datetime import datetime

_logger = logging.getLogger(__name__)

try:
    import xlsxwriter
except ImportError:
    xlsxwriter = None
    _logger.warning("XlsxWriter not installed. Excel export will not work.")


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
    _order = 'sequence asc, margin_percentage desc'

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
        compute='_compute_financials_stored',
        compute_sudo=True,
        store=True,
        string='Total Facturado',
        currency_field='currency_id',
        help='Suma de facturas emitidas (out_invoice) del proyecto'
    )

    dtes_emitted_count = fields.Integer(
        compute='_compute_financials_counts',
        string='# DTEs Emitidos',
        help='Cantidad de DTEs 33 emitidos'
    )

    # ═══════════════════════════════════════════════════════════
    # COSTOS
    # ═══════════════════════════════════════════════════════════

    total_purchases = fields.Monetary(
        compute='_compute_financials_counts',
        string='Total Órdenes Compra',
        currency_field='currency_id',
        help='Suma de purchase.order del proyecto'
    )

    total_vendor_invoices = fields.Monetary(
        compute='_compute_financials_counts',
        string='Total Fact. Proveedores',
        currency_field='currency_id',
        help='Suma de facturas recibidas (in_invoice) del proyecto'
    )

    total_costs = fields.Monetary(
        compute='_compute_financials_stored',
        compute_sudo=True,
        store=True,
        string='Costos Totales',
        currency_field='currency_id',
        help='Suma de compras + facturas proveedores'
    )

    # ═══════════════════════════════════════════════════════════
    # RENTABILIDAD
    # ═══════════════════════════════════════════════════════════

    gross_margin = fields.Monetary(
        compute='_compute_financials_stored',
        compute_sudo=True,
        store=True,
        string='Margen Bruto',
        currency_field='currency_id',
        help='Facturado - Costos'
    )

    margin_percentage = fields.Float(
        compute='_compute_financials_stored',
        compute_sudo=True,
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
        compute='_compute_financials_counts',
        string='Presupuesto Consumido',
        currency_field='currency_id'
    )

    budget_consumed_percentage = fields.Float(
        compute='_compute_financials_stored',
        compute_sudo=True,
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
        compute='_compute_financials_counts',
        string='# Órdenes Compra',
        help='Cantidad de órdenes de compra'
    )

    vendor_invoices_count = fields.Integer(
        compute='_compute_financials_counts',
        string='# Facturas Proveedores',
        help='Cantidad de facturas recibidas'
    )

    # ═══════════════════════════════════════════════════════════
    # METADATA
    # ═══════════════════════════════════════════════════════════

    sequence = fields.Integer(
        string='Sequence',
        default=10,
        index=True,
        help='Used to order dashboards in kanban view. Supports drag & drop reordering.'
    )

    last_update = fields.Datetime(
        string='Última Actualización',
        default=fields.Datetime.now,
        readonly=True
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════

    @api.depends('analytic_account_id')
    def _compute_financials_stored(self):
        """
        Calcula KPIs financieros STORED (con sudo para acceso cross-model).

        Campos almacenados en BD para performance:
        - total_invoiced, total_costs
        - gross_margin, margin_percentage
        - budget_consumed_percentage
        """
        for dashboard in self.sudo():  # Unificar sudo para campos stored
            if not dashboard.analytic_account_id:
                dashboard.total_invoiced = 0
                dashboard.total_costs = 0
                dashboard.gross_margin = 0
                dashboard.margin_percentage = 0
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

            # ══════════════════════════════════════════════
            # COSTOS: Órdenes de compra + Facturas proveedores
            # ══════════════════════════════════════════════

            purchases = self.env['purchase.order'].search([
                ('state', 'in', ['purchase', 'done']),
                ('analytic_account_id', '=', dashboard.analytic_account_id.id)
            ])

            invoices_in = self.env['account.move'].search([
                ('move_type', '=', 'in_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ])

            total_purchases = sum(purchases.mapped('amount_total'))
            total_vendor_invoices = sum(invoices_in.mapped('amount_total'))

            dashboard.total_costs = total_purchases + total_vendor_invoices

            # ══════════════════════════════════════════════
            # RENTABILIDAD
            # ══════════════════════════════════════════════

            dashboard.gross_margin = dashboard.total_invoiced - dashboard.total_costs

            dashboard.margin_percentage = (
                (dashboard.gross_margin / dashboard.total_invoiced * 100)
                if dashboard.total_invoiced else 0
            )

            # ══════════════════════════════════════════════
            # PRESUPUESTO
            # ══════════════════════════════════════════════

            dashboard.budget_consumed_percentage = (
                (dashboard.total_costs / dashboard.budget * 100)
                if dashboard.budget else 0
            )

            # Actualizar timestamp
            dashboard.last_update = fields.Datetime.now()

    @api.depends('analytic_account_id')
    def _compute_financials_counts(self):
        """
        Calcula contadores y campos NON-STORED (sin sudo).

        Campos recalculados en tiempo real:
        - dtes_emitted_count, purchases_count, vendor_invoices_count
        - total_purchases, total_vendor_invoices
        - budget_consumed_amount
        """
        for dashboard in self:
            if not dashboard.analytic_account_id:
                dashboard.dtes_emitted_count = 0
                dashboard.total_purchases = 0
                dashboard.total_vendor_invoices = 0
                dashboard.purchases_count = 0
                dashboard.vendor_invoices_count = 0
                dashboard.budget_consumed_amount = 0
                continue

            analytic_id_str = str(dashboard.analytic_account_id.id)

            # ══════════════════════════════════════════════
            # INGRESOS: Contadores
            # ══════════════════════════════════════════════

            invoices_out = self.env['account.move'].search([
                ('move_type', '=', 'out_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ])

            dashboard.dtes_emitted_count = len(invoices_out)

            # ══════════════════════════════════════════════
            # COSTOS: Totales y contadores
            # ══════════════════════════════════════════════

            purchases = self.env['purchase.order'].search([
                ('state', 'in', ['purchase', 'done']),
                ('analytic_account_id', '=', dashboard.analytic_account_id.id)
            ])

            invoices_in = self.env['account.move'].search([
                ('move_type', '=', 'in_invoice'),
                ('state', '=', 'posted'),
                ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
            ])

            dashboard.total_purchases = sum(purchases.mapped('amount_total'))
            dashboard.purchases_count = len(purchases)

            dashboard.total_vendor_invoices = sum(invoices_in.mapped('amount_total'))
            dashboard.vendor_invoices_count = len(invoices_in)

            # ══════════════════════════════════════════════
            # PRESUPUESTO
            # ══════════════════════════════════════════════

            dashboard.budget_consumed_amount = dashboard.total_costs

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

    # ═══════════════════════════════════════════════════════════
    # EXPORTACIÓN EXCEL
    # ═══════════════════════════════════════════════════════════

    def action_export_excel(self):
        """
        Exporta dashboard a Excel profesional (sin dependencias externas).

        Genera archivo Excel con múltiples hojas:
        - Hoja 1: Resumen ejecutivo (KPIs principales)
        - Hoja 2: Facturas emitidas
        - Hoja 3: Facturas proveedores
        - Hoja 4: Órdenes de compra

        Returns:
            dict: Acción de descarga de archivo Excel
        """
        self.ensure_one()

        if not xlsxwriter:
            raise UserError(_('XlsxWriter is required for Excel export. Please install: pip install xlsxwriter'))

        # Preparar datos
        export_data = self._prepare_export_data()

        # Generar Excel (método inline - sin dependencia externa)
        result = self._generate_excel_workbook(export_data)

        # Retornar archivo para descarga
        return {
            'type': 'ir.actions.act_url',
            'url': f'data:{result["mimetype"]};base64,{result["data"]}',
            'target': 'self',
            'download': True,
            'filename': result['filename'],
        }

    def _prepare_export_data(self):
        """
        Prepara datos estructurados para exportación Excel.

        Returns:
            dict: Datos con estructura:
                - summary: KPIs principales
                - invoices_out: Facturas emitidas
                - invoices_in: Facturas proveedores
                - purchases: Órdenes de compra
        """
        self.ensure_one()

        return {
            'summary': {
                'project_name': self.analytic_account_id.name,
                'project_code': self.analytic_account_id.code or 'N/A',
                'company_name': self.company_id.name,
                'total_invoiced': self.total_invoiced,
                'total_costs': self.total_costs,
                'gross_margin': self.gross_margin,
                'margin_percentage': self.margin_percentage,
                'budget_original': self.budget_original,
                'budget_consumed_percentage': self.budget_consumed_percentage,
                'budget_remaining': self.budget_remaining,
                'analytic_status': dict(self._fields['analytic_status'].selection).get(self.analytic_status),
                'dtes_emitted_count': self.dtes_emitted_count,
                'purchases_count': self.purchases_count,
                'vendor_invoices_count': self.vendor_invoices_count,
            },
            'invoices_out': self._get_invoices_out_data(),
            'invoices_in': self._get_invoices_in_data(),
            'purchases': self._get_purchases_data(),
        }

    def _get_invoices_out_data(self):
        """
        Retorna facturas emitidas para exportación Excel.

        Returns:
            list: Lista de dicts con datos de facturas emitidas
        """
        self.ensure_one()

        analytic_id_str = str(self.analytic_account_id.id)

        invoices = self.env['account.move'].search([
            ('move_type', '=', 'out_invoice'),
            ('state', '=', 'posted'),
            ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
        ], order='invoice_date desc')

        return [
            {
                'date': inv.invoice_date,
                'number': inv.name,
                'partner': inv.partner_id.name,
                'amount': inv.amount_total,
                'currency': inv.currency_id.name,
                'state': dict(inv._fields['state'].selection).get(inv.state),
                'dte_code': getattr(inv, 'dte_code', 'N/A'),
            }
            for inv in invoices
        ]

    def _get_invoices_in_data(self):
        """
        Retorna facturas proveedores para exportación Excel.

        Returns:
            list: Lista de dicts con datos de facturas proveedores
        """
        self.ensure_one()

        analytic_id_str = str(self.analytic_account_id.id)

        invoices = self.env['account.move'].search([
            ('move_type', '=', 'in_invoice'),
            ('state', '=', 'posted'),
            ('invoice_line_ids.analytic_distribution', 'like', f'"{analytic_id_str}"')
        ], order='invoice_date desc')

        return [
            {
                'date': inv.invoice_date,
                'number': inv.ref or inv.name,
                'partner': inv.partner_id.name,
                'amount': inv.amount_total,
                'currency': inv.currency_id.name,
                'state': dict(inv._fields['state'].selection).get(inv.state),
            }
            for inv in invoices
        ]

    def _get_purchases_data(self):
        """
        Retorna órdenes de compra para exportación Excel.

        Returns:
            list: Lista de dicts con datos de órdenes de compra
        """
        self.ensure_one()

        purchases = self.env['purchase.order'].search([
            ('state', 'in', ['purchase', 'done']),
            ('analytic_account_id', '=', self.analytic_account_id.id)
        ], order='date_order desc')

        return [
            {
                'date': po.date_order,
                'number': po.name,
                'partner': po.partner_id.name,
                'amount': po.amount_total,
                'currency': po.currency_id.name,
                'state': dict(po._fields['state'].selection).get(po.state),
            }
            for po in purchases
        ]

    def _generate_excel_workbook(self, data):
        """
        Genera workbook Excel profesional con 4 hojas.

        Args:
            data: Datos preparados por _prepare_export_data()

        Returns:
            dict: {data (base64), filename, mimetype}
        """
        # Crear workbook en memoria
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})

        # ========================================
        # FORMATOS PROFESIONALES
        # ========================================

        title_format = workbook.add_format({
            'bold': True,
            'font_size': 18,
            'font_color': '#2c3e50',
            'align': 'left',
        })

        subtitle_format = workbook.add_format({
            'bold': True,
            'font_size': 12,
            'font_color': '#34495e',
            'align': 'left',
        })

        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#2c3e50',
            'font_color': 'white',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'text_wrap': True,
        })

        currency_format = workbook.add_format({
            'num_format': '$#,##0',
            'align': 'right',
        })

        percent_format = workbook.add_format({
            'num_format': '0.00%',
            'align': 'right',
        })

        date_format = workbook.add_format({
            'num_format': 'yyyy-mm-dd',
            'align': 'center',
        })

        kpi_label_format = workbook.add_format({
            'bold': True,
            'font_color': '#2c3e50',
            'align': 'left',
            'border': 1,
            'bg_color': '#ecf0f1',
        })

        kpi_value_format = workbook.add_format({
            'align': 'right',
            'border': 1,
            'num_format': '$#,##0',
        })

        # ========================================
        # HOJA 1: RESUMEN EJECUTIVO
        # ========================================

        summary_sheet = workbook.add_worksheet('Resumen Ejecutivo')

        # Título principal
        summary_sheet.merge_range('A1:D1', f"Dashboard Rentabilidad: {data['summary']['project_name']}", title_format)

        # Información del reporte
        summary_sheet.write(2, 0, 'Generado:', subtitle_format)
        summary_sheet.write(2, 1, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        summary_sheet.write(3, 0, 'Empresa:', subtitle_format)
        summary_sheet.write(3, 1, data['summary']['company_name'])
        summary_sheet.write(4, 0, 'Código Proyecto:', subtitle_format)
        summary_sheet.write(4, 1, data['summary']['project_code'])

        # Sección KPIs Financieros
        row = 6
        summary_sheet.merge_range(f'A{row+1}:B{row+1}', 'KPIs FINANCIEROS', subtitle_format)
        row += 2

        summary_sheet.write(row, 0, 'Total Facturado', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['total_invoiced'], kpi_value_format)
        summary_sheet.write(row, 2, '# DTEs Emitidos', kpi_label_format)
        summary_sheet.write(row, 3, data['summary']['dtes_emitted_count'])

        row += 1
        summary_sheet.write(row, 0, 'Costos Totales', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['total_costs'], kpi_value_format)
        summary_sheet.write(row, 2, '# Órdenes Compra', kpi_label_format)
        summary_sheet.write(row, 3, data['summary']['purchases_count'])

        row += 1
        summary_sheet.write(row, 0, 'Margen Bruto', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['gross_margin'], kpi_value_format)
        summary_sheet.write(row, 2, '# Fact. Proveedores', kpi_label_format)
        summary_sheet.write(row, 3, data['summary']['vendor_invoices_count'])

        row += 1
        percent_kpi_format = workbook.add_format({
            'align': 'right',
            'border': 1,
            'num_format': '0.00%',
        })
        summary_sheet.write(row, 0, '% Margen', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['margin_percentage'] / 100, percent_kpi_format)

        # Sección Presupuesto
        row += 2
        summary_sheet.merge_range(f'A{row+1}:B{row+1}', 'CONTROL PRESUPUESTARIO', subtitle_format)
        row += 2

        summary_sheet.write(row, 0, 'Presupuesto Original', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['budget_original'], kpi_value_format)

        row += 1
        summary_sheet.write(row, 0, '% Consumido', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['budget_consumed_percentage'] / 100, percent_kpi_format)

        row += 1
        summary_sheet.write(row, 0, 'Presupuesto Restante', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['budget_remaining'], kpi_value_format)

        row += 1
        status_format = workbook.add_format({
            'bold': True,
            'font_size': 12,
            'align': 'center',
            'border': 1,
        })
        if data['summary']['analytic_status'] == 'On Budget':
            status_format.set_bg_color('#27ae60')
            status_format.set_font_color('white')
        elif data['summary']['analytic_status'] == 'At Risk':
            status_format.set_bg_color('#f39c12')
            status_format.set_font_color('white')
        else:  # Over Budget
            status_format.set_bg_color('#e74c3c')
            status_format.set_font_color('white')

        summary_sheet.write(row, 0, 'Estado', kpi_label_format)
        summary_sheet.write(row, 1, data['summary']['analytic_status'], status_format)

        # Ajustar anchos de columnas
        summary_sheet.set_column('A:A', 25)
        summary_sheet.set_column('B:B', 18)
        summary_sheet.set_column('C:C', 20)
        summary_sheet.set_column('D:D', 15)

        # ========================================
        # HOJA 2: FACTURAS EMITIDAS
        # ========================================

        invoices_out_sheet = workbook.add_worksheet('Facturas Emitidas')

        # Título
        invoices_out_sheet.merge_range('A1:G1', 'FACTURAS EMITIDAS', title_format)

        # Headers
        headers = ['Fecha', 'Número', 'Cliente', 'Monto', 'Moneda', 'Estado', 'DTE']
        for col_idx, header in enumerate(headers):
            invoices_out_sheet.write(2, col_idx, header, header_format)

        # Datos
        for row_idx, inv in enumerate(data['invoices_out'], start=3):
            if inv['date']:
                invoices_out_sheet.write_datetime(row_idx, 0, inv['date'], date_format)
            else:
                invoices_out_sheet.write(row_idx, 0, 'N/A')
            invoices_out_sheet.write(row_idx, 1, inv['number'])
            invoices_out_sheet.write(row_idx, 2, inv['partner'])
            invoices_out_sheet.write(row_idx, 3, inv['amount'], currency_format)
            invoices_out_sheet.write(row_idx, 4, inv['currency'])
            invoices_out_sheet.write(row_idx, 5, inv['state'])
            invoices_out_sheet.write(row_idx, 6, inv['dte_code'])

        # Totales
        if data['invoices_out']:
            total_row = 3 + len(data['invoices_out'])
            total_format = workbook.add_format({
                'bold': True,
                'bg_color': '#ecf0f1',
                'border': 1,
            })
            invoices_out_sheet.write(total_row, 2, 'TOTAL', total_format)
            invoices_out_sheet.write_formula(
                total_row, 3,
                f'=SUM(D4:D{total_row})',
                workbook.add_format({'bold': True, 'num_format': '$#,##0', 'border': 1, 'bg_color': '#ecf0f1'})
            )

        # Ajustar anchos
        invoices_out_sheet.set_column('A:A', 12)
        invoices_out_sheet.set_column('B:B', 15)
        invoices_out_sheet.set_column('C:C', 35)
        invoices_out_sheet.set_column('D:D', 15)
        invoices_out_sheet.set_column('E:E', 10)
        invoices_out_sheet.set_column('F:F', 12)
        invoices_out_sheet.set_column('G:G', 10)

        # ========================================
        # HOJA 3: FACTURAS PROVEEDORES
        # ========================================

        invoices_in_sheet = workbook.add_worksheet('Facturas Proveedores')

        # Título
        invoices_in_sheet.merge_range('A1:F1', 'FACTURAS PROVEEDORES', title_format)

        # Headers
        headers_in = ['Fecha', 'Número', 'Proveedor', 'Monto', 'Moneda', 'Estado']
        for col_idx, header in enumerate(headers_in):
            invoices_in_sheet.write(2, col_idx, header, header_format)

        # Datos
        for row_idx, inv in enumerate(data['invoices_in'], start=3):
            if inv['date']:
                invoices_in_sheet.write_datetime(row_idx, 0, inv['date'], date_format)
            else:
                invoices_in_sheet.write(row_idx, 0, 'N/A')
            invoices_in_sheet.write(row_idx, 1, inv['number'])
            invoices_in_sheet.write(row_idx, 2, inv['partner'])
            invoices_in_sheet.write(row_idx, 3, inv['amount'], currency_format)
            invoices_in_sheet.write(row_idx, 4, inv['currency'])
            invoices_in_sheet.write(row_idx, 5, inv['state'])

        # Totales
        if data['invoices_in']:
            total_row = 3 + len(data['invoices_in'])
            total_format_in = workbook.add_format({
                'bold': True,
                'bg_color': '#ecf0f1',
                'border': 1,
            })
            invoices_in_sheet.write(total_row, 2, 'TOTAL', total_format_in)
            invoices_in_sheet.write_formula(
                total_row, 3,
                f'=SUM(D4:D{total_row})',
                workbook.add_format({'bold': True, 'num_format': '$#,##0', 'border': 1, 'bg_color': '#ecf0f1'})
            )

        # Ajustar anchos
        invoices_in_sheet.set_column('A:A', 12)
        invoices_in_sheet.set_column('B:B', 15)
        invoices_in_sheet.set_column('C:C', 35)
        invoices_in_sheet.set_column('D:D', 15)
        invoices_in_sheet.set_column('E:E', 10)
        invoices_in_sheet.set_column('F:F', 12)

        # ========================================
        # HOJA 4: ÓRDENES DE COMPRA
        # ========================================

        purchases_sheet = workbook.add_worksheet('Órdenes Compra')

        # Título
        purchases_sheet.merge_range('A1:F1', 'ÓRDENES DE COMPRA', title_format)

        # Headers
        headers_po = ['Fecha', 'Número', 'Proveedor', 'Monto', 'Moneda', 'Estado']
        for col_idx, header in enumerate(headers_po):
            purchases_sheet.write(2, col_idx, header, header_format)

        # Datos
        for row_idx, po in enumerate(data['purchases'], start=3):
            if po['date']:
                purchases_sheet.write_datetime(row_idx, 0, po['date'], date_format)
            else:
                purchases_sheet.write(row_idx, 0, 'N/A')
            purchases_sheet.write(row_idx, 1, po['number'])
            purchases_sheet.write(row_idx, 2, po['partner'])
            purchases_sheet.write(row_idx, 3, po['amount'], currency_format)
            purchases_sheet.write(row_idx, 4, po['currency'])
            purchases_sheet.write(row_idx, 5, po['state'])

        # Totales
        if data['purchases']:
            total_row = 3 + len(data['purchases'])
            total_format_po = workbook.add_format({
                'bold': True,
                'bg_color': '#ecf0f1',
                'border': 1,
            })
            purchases_sheet.write(total_row, 2, 'TOTAL', total_format_po)
            purchases_sheet.write_formula(
                total_row, 3,
                f'=SUM(D4:D{total_row})',
                workbook.add_format({'bold': True, 'num_format': '$#,##0', 'border': 1, 'bg_color': '#ecf0f1'})
            )

        # Ajustar anchos
        purchases_sheet.set_column('A:A', 12)
        purchases_sheet.set_column('B:B', 15)
        purchases_sheet.set_column('C:C', 35)
        purchases_sheet.set_column('D:D', 15)
        purchases_sheet.set_column('E:E', 10)
        purchases_sheet.set_column('F:F', 12)

        # Cerrar workbook y preparar output
        workbook.close()
        output.seek(0)

        return {
            'data': base64.b64encode(output.read()).decode('utf-8'),
            'filename': f"Dashboard_{data['summary']['project_name'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
            'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        }

    # ═══════════════════════════════════════════════════════════
    # OVERRIDE MÉTODOS ESTÁNDAR
    # ═══════════════════════════════════════════════════════════

    def write(self, vals):
        """
        Override write para manejar drag & drop en kanban view.

        Cuando usuario arrastra tarjeta en kanban:
        - Odoo automáticamente llama write() con nuevo valor de 'sequence'
        - Si sequence cambió, recalcular KPIs financieros

        Args:
            vals (dict): Valores a actualizar

        Returns:
            bool: True si actualización exitosa

        Technical Note:
        - Odoo drag & drop usa field 'sequence' para reordenamiento
        - NO es necesario JavaScript custom
        """
        result = super(AnalyticDashboard, self).write(vals)

        # Si cambió sequence (drag & drop), opcional recalcular financials
        # NOTA: En producción, esto podría ser costoso si hay muchos registros
        # Mejor estrategia: recalcular en cron job nocturno
        if 'sequence' in vals:
            _logger.info(
                f"Dashboard(s) {self.ids} reordered. New sequences: "
                f"{[(d.id, d.sequence) for d in self]}"
            )

        return result
