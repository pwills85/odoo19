# -*- coding: utf-8 -*-
"""
Stack Integration Module
Maximiza integración con suite base Odoo 19 CE y módulos custom del stack

Integración con:
- l10n_cl_dte: Facturación electrónica y DTE
- l10n_cl_hr_payroll: Nómina chilena
- account (Odoo 19 CE): Contabilidad base
- project (Odoo 19 CE): Proyectos
- hr_timesheet (Odoo 19 CE): Horas trabajadas
"""

from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class L10nClF29StackIntegration(models.Model):
    """
    Integración F29 con stack
    Consolida datos de DTE, nómina y contabilidad
    """
    _inherit = 'l10n_cl.f29'

    # Integration fields
    dte_integration_ids = fields.Many2many(
        'account.move',
        string='DTEs Relacionados',
        compute='_compute_dte_integration',
        help='Facturas DTE del período consolidadas en este F29'
    )

    # TEMPORARILY DISABLED: Requires l10n_cl_hr_payroll to be installed
    # payroll_integration_ids = fields.Many2many(
    #     'hr.payslip',
    #     string='Nóminas Relacionadas',
    #     compute='_compute_payroll_integration',
    #     help='Nóminas del período con retenciones consolidadas'
    # )

    total_dte_sales = fields.Monetary(
        string='Ventas DTE',
        compute='_compute_dte_totals',
        currency_field='currency_id',
        help='Total ventas de DTEs emitidos'
    )

    total_dte_purchases = fields.Monetary(
        string='Compras DTE',
        compute='_compute_dte_totals',
        currency_field='currency_id',
        help='Total compras de DTEs recibidos'
    )

    @api.depends('period_date', 'company_id')
    def _compute_dte_integration(self):
        """
        Integración con l10n_cl_dte
        Obtiene todas las facturas DTE del período
        """
        for record in self:
            if not record.period_date:
                record.dte_integration_ids = False
                continue

            # Solo si el módulo l10n_cl_dte está instalado
            if 'l10n_cl_dte_type' not in self.env['account.move']._fields:
                record.dte_integration_ids = False
                continue

            # Rango del período
            date_from = fields.Date.start_of(record.period_date, 'month')
            date_to = fields.Date.end_of(record.period_date, 'month')

            # Buscar facturas DTE del período
            domain = [
                ('company_id', '=', record.company_id.id),
                ('invoice_date', '>=', date_from),
                ('invoice_date', '<=', date_to),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', ['accepted', 'objected']),  # DTEs válidos
                ('move_type', 'in', ['out_invoice', 'in_invoice', 'out_refund', 'in_refund'])
            ]

            record.dte_integration_ids = self.env['account.move'].search(domain)

    @api.depends('dte_integration_ids')
    def _compute_dte_totals(self):
        """
        Calcula totales de ventas y compras DTE
        """
        for record in self:
            sales = 0.0
            purchases = 0.0

            for move in record.dte_integration_ids:
                if move.move_type in ('out_invoice', 'out_refund'):
                    # Ventas (incluye notas de crédito con signo negativo)
                    multiplier = -1 if move.move_type == 'out_refund' else 1
                    sales += move.amount_untaxed * multiplier
                elif move.move_type in ('in_invoice', 'in_refund'):
                    # Compras (incluye notas de crédito con signo negativo)
                    multiplier = -1 if move.move_type == 'in_refund' else 1
                    purchases += move.amount_untaxed * multiplier

            record.total_dte_sales = sales
            record.total_dte_purchases = purchases

    # TEMPORARILY DISABLED: Requires l10n_cl_hr_payroll to be installed
    # @api.depends('period_date', 'company_id')
    # def _compute_payroll_integration(self):
    #     """
    #     Integración con l10n_cl_hr_payroll
    #     Obtiene nóminas con retenciones del período
    #     """
    #     for record in self:
    #         if not record.period_date:
    #             record.payroll_integration_ids = False
    #             continue
    #
    #         # Solo si el módulo l10n_cl_hr_payroll está instalado
    #         if 'hr.payslip' not in self.env:
    #             record.payroll_integration_ids = False
    #             continue
    #
    #         # Rango del período
    #         date_from = fields.Date.start_of(record.period_date, 'month')
    #         date_to = fields.Date.end_of(record.period_date, 'month')
    #
    #         # Buscar nóminas del período
    #         domain = [
    #             ('company_id', '=', record.company_id.id),
    #             ('date_from', '>=', date_from),
    #             ('date_to', '<=', date_to),
    #             ('state', '=', 'done')
    #         ]
    #
    #         record.payroll_integration_ids = self.env['hr.payslip'].search(domain)

    def action_view_dte_documents(self):
        """
        Acción para ver DTEs relacionados
        Integración con l10n_cl_dte
        """
        self.ensure_one()

        return {
            'name': _('DTEs del Período'),
            'type': 'ir.actions.act_window',
            'res_model': 'account.move',
            'view_mode': 'tree,form',
            'domain': [('id', 'in', self.dte_integration_ids.ids)],
            'context': {
                'default_company_id': self.company_id.id,
                'search_default_group_by_dte_type': 1,
            }
        }

    # TEMPORARILY DISABLED: Requires l10n_cl_hr_payroll to be installed
    # def action_view_payroll_documents(self):
    #     """
    #     Acción para ver nóminas relacionadas
    #     Integración con l10n_cl_hr_payroll
    #     """
    #     self.ensure_one()
    #
    #     return {
    #         'name': _('Nóminas del Período'),
    #         'type': 'ir.actions.act_window',
    #         'res_model': 'hr.payslip',
    #         'view_mode': 'tree,form',
    #         'domain': [('id', 'in', self.payroll_integration_ids.ids)],
    #         'context': {
    #             'default_company_id': self.company_id.id,
    #         }
    #     }


class FinancialDashboardStackIntegration(models.Model):
    """
    Integración Dashboard con stack
    KPIs que usan datos de DTE, nómina y proyectos
    """
    _inherit = 'financial.dashboard.widget'

    # Nuevos tipos de widget con integración stack
    widget_type = fields.Selection(
        selection_add=[
            ('kpi_dte_status', 'KPI: Estado DTEs'),
            ('kpi_payroll_cost', 'KPI: Costo Nómina'),
            ('kpi_project_margin', 'KPI: Margen Proyectos'),
            ('chart_dte_timeline', 'Gráfico: Timeline DTEs'),
            ('chart_payroll_trend', 'Gráfico: Tendencia Nómina'),
        ],
        ondelete={
            'kpi_dte_status': 'cascade',
            'kpi_payroll_cost': 'cascade',
            'kpi_project_margin': 'cascade',
            'chart_dte_timeline': 'cascade',
            'chart_payroll_trend': 'cascade',
        }
    )

    def _compute_kpi_dte_status_data(self, filters):
        """
        KPI: Estado de DTEs del período
        Integración con l10n_cl_dte
        """
        # Verificar si módulo está instalado
        if 'l10n_cl_dte_status' not in self.env['account.move']._fields:
            return {
                'value': 0,
                'label': 'DTE no disponible',
                'color': 'grey',
            }

        # Rango de fechas
        date_from = filters.get('date_from', fields.Date.today().replace(day=1))
        date_to = filters.get('date_to', fields.Date.today())

        # Contar DTEs por estado
        domain_base = [
            ('company_id', '=', self.env.company.id),
            ('invoice_date', '>=', date_from),
            ('invoice_date', '<=', date_to),
            ('move_type', 'in', ['out_invoice', 'in_invoice']),
        ]

        total = self.env['account.move'].search_count(domain_base)
        accepted = self.env['account.move'].search_count(
            domain_base + [('l10n_cl_dte_status', '=', 'accepted')]
        )

        percentage = (accepted / total * 100) if total > 0 else 0

        return {
            'value': percentage,
            'label': f'{accepted}/{total} DTEs Aceptados',
            'color': 'green' if percentage >= 95 else 'orange' if percentage >= 80 else 'red',
            'trend': self._compute_trend(percentage, 'dte_acceptance_rate')
        }

    def _compute_kpi_payroll_cost_data(self, filters):
        """
        KPI: Costo total nómina del período
        Integración con l10n_cl_hr_payroll
        """
        # Verificar si módulo está instalado
        if 'hr.payslip' not in self.env:
            return {
                'value': 0,
                'label': 'Nómina no disponible',
                'color': 'grey',
            }

        # Rango de fechas
        date_from = filters.get('date_from', fields.Date.today().replace(day=1))
        date_to = filters.get('date_to', fields.Date.today())

        # Buscar nóminas del período
        payslips = self.env['hr.payslip'].search([
            ('company_id', '=', self.env.company.id),
            ('date_from', '>=', date_from),
            ('date_to', '<=', date_to),
            ('state', '=', 'done')
        ])

        # Sumar líquidos pagados
        total_cost = sum(payslip.net_wage for payslip in payslips)

        return {
            'value': total_cost,
            'label': f'Nómina {len(payslips)} empleados',
            'format': 'monetary',
            'color': 'blue',
            'trend': self._compute_trend(total_cost, 'payroll_cost')
        }

    def _compute_kpi_project_margin_data(self, filters):
        """
        KPI: Margen promedio proyectos
        Integración con project (Odoo 19 CE)
        """
        # Rango de fechas
        date_from = filters.get('date_from', fields.Date.today().replace(day=1))
        date_to = filters.get('date_to', fields.Date.today())

        # Buscar proyectos activos con analítica
        projects = self.env['project.project'].search([
            ('company_id', '=', self.env.company.id),
            ('active', '=', True),
            ('analytic_account_id', '!=', False)
        ])

        total_margin = 0.0
        count = 0

        for project in projects:
            # Obtener ingresos y costos del proyecto
            account = project.analytic_account_id

            # Ingresos (líneas de ingreso)
            revenue = sum(account.line_ids.filtered(
                lambda l: l.amount > 0 and
                          l.date >= date_from and
                          l.date <= date_to
            ).mapped('amount'))

            # Costos (líneas de gasto)
            costs = abs(sum(account.line_ids.filtered(
                lambda l: l.amount < 0 and
                          l.date >= date_from and
                          l.date <= date_to
            ).mapped('amount')))

            if revenue > 0:
                margin = (revenue - costs) / revenue * 100
                total_margin += margin
                count += 1

        avg_margin = total_margin / count if count > 0 else 0

        return {
            'value': avg_margin,
            'label': f'Margen {count} proyectos',
            'format': 'percentage',
            'color': 'green' if avg_margin >= 20 else 'orange' if avg_margin >= 10 else 'red',
            'trend': self._compute_trend(avg_margin, 'project_margin')
        }

    def _compute_trend(self, current_value, metric_key):
        """
        Calcula tendencia comparando con período anterior
        """
        # Obtener valor del período anterior (cached)
        previous_value = self._get_previous_period_value(metric_key)

        if previous_value is None or previous_value == 0:
            return 0

        change = ((current_value - previous_value) / previous_value) * 100

        # Guardar valor actual para próxima comparación
        self._set_current_period_value(metric_key, current_value)

        return round(change, 1)

    def _get_previous_period_value(self, metric_key):
        """
        Obtiene valor del período anterior desde cache
        """
        cache_key = f'metric_{metric_key}_previous'
        return self.env['ir.config_parameter'].sudo().get_param(cache_key, 0.0)

    def _set_current_period_value(self, metric_key, value):
        """
        Guarda valor actual para próxima comparación
        """
        cache_key = f'metric_{metric_key}_previous'
        self.env['ir.config_parameter'].sudo().set_param(cache_key, value)


class ProjectProfitabilityDTEIntegration(models.Model):
    """
    Integración análisis rentabilidad con DTEs
    """
    _inherit = 'project.profitability.report'

    dte_invoice_count = fields.Integer(
        string='# Facturas DTE',
        compute='_compute_dte_stats',
        help='Número de facturas DTE asociadas al proyecto'
    )

    dte_revenue_amount = fields.Monetary(
        string='Ingresos DTE',
        compute='_compute_dte_stats',
        currency_field='currency_id',
        help='Total facturado vía DTE'
    )

    @api.depends('project_id', 'date_from', 'date_to')
    def _compute_dte_stats(self):
        """
        Calcula estadísticas DTE del proyecto
        """
        for record in self:
            if not record.project_id or not record.project_id.analytic_account_id:
                record.dte_invoice_count = 0
                record.dte_revenue_amount = 0.0
                continue

            # Verificar si l10n_cl_dte está instalado
            if 'l10n_cl_dte_status' not in self.env['account.move']._fields:
                record.dte_invoice_count = 0
                record.dte_revenue_amount = 0.0
                continue

            # Buscar facturas DTE del proyecto
            domain = [
                ('move_type', '=', 'out_invoice'),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', ['accepted', 'objected']),
                ('line_ids.analytic_distribution', '!=', False),
            ]

            if record.date_from:
                domain.append(('invoice_date', '>=', record.date_from))
            if record.date_to:
                domain.append(('invoice_date', '<=', record.date_to))

            invoices = self.env['account.move'].search(domain)

            # Filtrar por cuenta analítica del proyecto
            project_invoices = invoices.filtered(
                lambda inv: any(
                    str(record.project_id.analytic_account_id.id) in line.analytic_distribution
                    for line in inv.line_ids
                    if line.analytic_distribution
                )
            )

            record.dte_invoice_count = len(project_invoices)
            record.dte_revenue_amount = sum(project_invoices.mapped('amount_untaxed'))


# Registrar nuevos tipos de widget en el sistema
def register_stack_widget_types():
    """
    Registra tipos de widget personalizados con integración stack
    """
    _logger.info("Registrando widget types con integración stack Odoo 19 CE")
