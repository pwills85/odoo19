# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError
from datetime import date, datetime
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class L10nClKpiDashboard(models.TransientModel):
    """
    Dashboard no persistente para visualización de KPIs financieros chilenos.

    Este modelo muestra indicadores clave basados en formularios F29 (IVA mensual)
    con cálculos optimizados mediante cache.

    KPIs mostrados:
    - IVA Débito Fiscal
    - IVA Crédito Fiscal
    - Ventas Netas
    - Compras Netas
    - PPM Pagado
    """

    _name = 'l10n_cl.kpi.dashboard'
    _description = 'KPI Dashboard - Financial Reports Chile'

    # ========== FILTROS ==========
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        help='Compañía para la cual mostrar KPIs'
    )

    date_from = fields.Date(
        string='Desde',
        required=True,
        default=lambda self: date.today().replace(day=1) - relativedelta(months=11),
        help='Fecha inicio del período a analizar'
    )

    date_to = fields.Date(
        string='Hasta',
        required=True,
        default=lambda self: date.today(),
        help='Fecha fin del período a analizar'
    )

    period_type = fields.Selection([
        ('month', 'Mensual'),
        ('quarter', 'Trimestral'),
        ('year', 'Anual'),
    ], string='Tipo de Período', default='month', required=True)

    # ========== KPIs COMPUTADOS ==========
    iva_debito_fiscal = fields.Monetary(
        string='IVA Débito Fiscal',
        compute='_compute_kpis',
        currency_field='currency_id',
        help='Total IVA débito generado por ventas afectas'
    )

    iva_credito_fiscal = fields.Monetary(
        string='IVA Crédito Fiscal',
        compute='_compute_kpis',
        currency_field='currency_id',
        help='Total IVA crédito por compras afectas'
    )

    ventas_netas = fields.Monetary(
        string='Ventas Netas',
        compute='_compute_kpis',
        currency_field='currency_id',
        help='Total ventas (afectas + exentas + exportación)'
    )

    compras_netas = fields.Monetary(
        string='Compras Netas',
        compute='_compute_kpis',
        currency_field='currency_id',
        help='Total compras (afectas + exentas + activo fijo)'
    )

    ppm_pagado = fields.Monetary(
        string='PPM Pagado',
        compute='_compute_kpis',
        currency_field='currency_id',
        help='Total Pagos Provisionales Mensuales'
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='company_id.currency_id',
        readonly=True
    )

    # ========== MÉTRICAS ADICIONALES ==========
    iva_neto = fields.Monetary(
        string='IVA Neto (Débito - Crédito)',
        compute='_compute_kpis',
        currency_field='currency_id',
        help='Diferencia entre IVA débito y crédito'
    )

    margen_ventas_pct = fields.Float(
        string='Margen Ventas (%)',
        compute='_compute_kpis',
        digits=(5, 2),
        help='(Ventas - Compras) / Ventas * 100'
    )

    cache_hit = fields.Boolean(
        string='Cache Hit',
        compute='_compute_kpis',
        help='Indica si los KPIs se obtuvieron desde cache'
    )

    calculation_time_ms = fields.Integer(
        string='Tiempo Cálculo (ms)',
        compute='_compute_kpis',
        help='Tiempo de cálculo en milisegundos'
    )

    @api.depends('company_id', 'date_from', 'date_to')
    def _compute_kpis(self):
        """
        Calcula los KPIs llamando al servicio de KPIs con cache.
        """
        kpi_service = self.env['account.financial.report.kpi.service']

        for dashboard in self:
            if not dashboard.company_id or not dashboard.date_from or not dashboard.date_to:
                # Sin filtros completos, retornar 0s
                dashboard.iva_debito_fiscal = 0.0
                dashboard.iva_credito_fiscal = 0.0
                dashboard.ventas_netas = 0.0
                dashboard.compras_netas = 0.0
                dashboard.ppm_pagado = 0.0
                dashboard.iva_neto = 0.0
                dashboard.margen_ventas_pct = 0.0
                dashboard.cache_hit = False
                dashboard.calculation_time_ms = 0
                continue

            try:
                # Llamar al servicio de KPIs
                kpis = kpi_service.compute_kpis(
                    company=dashboard.company_id,
                    period_start=dashboard.date_from,
                    period_end=dashboard.date_to
                )

                # Asignar valores
                dashboard.iva_debito_fiscal = kpis['iva_debito_fiscal']
                dashboard.iva_credito_fiscal = kpis['iva_credito_fiscal']
                dashboard.ventas_netas = kpis['ventas_netas']
                dashboard.compras_netas = kpis['compras_netas']
                dashboard.ppm_pagado = kpis['ppm_pagado']
                dashboard.cache_hit = kpis.get('cache_hit', False)
                dashboard.calculation_time_ms = kpis.get('calculation_time_ms', 0)

                # Calcular métricas derivadas
                dashboard.iva_neto = dashboard.iva_debito_fiscal - dashboard.iva_credito_fiscal

                if dashboard.ventas_netas > 0:
                    dashboard.margen_ventas_pct = (
                        (dashboard.ventas_netas - dashboard.compras_netas) / dashboard.ventas_netas * 100
                    )
                else:
                    dashboard.margen_ventas_pct = 0.0

            except Exception as e:
                _logger.error("Error al calcular KPIs del dashboard: %s", str(e))
                dashboard.iva_debito_fiscal = 0.0
                dashboard.iva_credito_fiscal = 0.0
                dashboard.ventas_netas = 0.0
                dashboard.compras_netas = 0.0
                dashboard.ppm_pagado = 0.0
                dashboard.iva_neto = 0.0
                dashboard.margen_ventas_pct = 0.0
                dashboard.cache_hit = False
                dashboard.calculation_time_ms = 0

    def action_refresh_kpis(self):
        """
        Acción para refrescar los KPIs invalidando el cache.
        """
        self.ensure_one()

        kpi_service = self.env['account.financial.report.kpi.service']

        # Invalidar cache
        kpi_service.invalidate_kpi_cache(
            company=self.company_id,
            period_start=self.date_from.strftime('%Y-%m-%d'),
            period_end=self.date_to.strftime('%Y-%m-%d')
        )

        # Recargar vista
        return {
            'type': 'ir.actions.client',
            'tag': 'reload',
        }

    def action_view_f29_records(self):
        """
        Acción para ver los registros F29 que componen los KPIs.
        """
        self.ensure_one()

        return {
            'name': _('Declaraciones F29 - %s') % self.company_id.name,
            'type': 'ir.actions.act_window',
            'res_model': 'l10n_cl.f29',
            'view_mode': 'tree,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('period_date', '>=', self.date_from),
                ('period_date', '<=', self.date_to),
                ('state', 'in', ['confirmed', 'sent', 'accepted']),
            ],
            'context': {'create': False},
        }

    @api.model
    def action_open_dashboard(self):
        """
        Acción para abrir el dashboard con valores por defecto.
        """
        # Crear dashboard con filtros por defecto (últimos 12 meses)
        dashboard = self.create({
            'company_id': self.env.company.id,
            'date_from': date.today().replace(day=1) - relativedelta(months=11),
            'date_to': date.today(),
        })

        return {
            'name': _('Dashboard KPIs - %s') % self.env.company.name,
            'type': 'ir.actions.act_window',
            'res_model': 'l10n_cl.kpi.dashboard',
            'view_mode': 'form,kanban,graph,pivot',
            'res_id': dashboard.id,
            'target': 'current',
        }
