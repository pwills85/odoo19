# -*- coding: utf-8 -*-
"""
Business Intelligence Dashboard Wizard
======================================

Wizard para el dashboard ejecutivo de BI con selección de fechas.

Autor: Claude AI siguiendo PROMPT_AGENT_IA.md
Fecha: 2025-07-15
"""

from odoo import api, fields, models, _
from odoo.exceptions import UserError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class BiDashboardWizard(models.TransientModel):
    """
    Wizard para configurar y mostrar el dashboard de BI.
    """
    _name = 'account.financial.bi.wizard'
    _description = 'Business Intelligence Dashboard Wizard'

    # Campos básicos
    date_from = fields.Date(
        string='Fecha Desde',
        required=True,
        default=lambda self: date.today().replace(day=1)
    )
    date_to = fields.Date(
        string='Fecha Hasta',
        required=True,
        default=lambda self: date.today()
    )
    company_ids = fields.Many2many(
        'res.company',
        string='Compañías',
        default=lambda self: self.env.company
    )

    # Campos para mostrar datos
    dashboard_data = fields.Text(
        string='Dashboard Data',
        readonly=True
    )

    @api.model
    def default_get(self, fields_list):
        """Valores por defecto del wizard."""
        res = super().default_get(fields_list)

        # Período por defecto: mes actual
        today = date.today()
        res.update({
            'date_from': today.replace(day=1),
            'date_to': today,
            'company_ids': [(6, 0, [self.env.company.id])]
        })

        return res

    def refresh_dashboard(self):
        """Refrescar datos del dashboard."""
        bi_service = self.env['account.financial.bi.service']

        # Obtener datos del dashboard
        dashboard = bi_service.get_executive_dashboard(
            date_from=self.date_from,
            date_to=self.date_to,
            company_ids=self.company_ids.ids
        )

        # Guardar datos en el wizard
        self.dashboard_data = str(dashboard)

        return {
            'type': 'ir.actions.act_window',
            'name': 'Business Intelligence Dashboard',
            'res_model': 'account.financial.bi.wizard',
            'view_mode': 'form',
            'res_id': self.id,
            'target': 'current',
            'context': self.env.context,
        }

    def export_dashboard(self):
        """Exportar dashboard a Excel."""
        try:
            # Get dashboard service
            dashboard_service = self.env['account.financial.dashboard.service']

            # Generate data for export
            export_data = dashboard_service.generate_export_data({
                'date_from': self.date_from,
                'date_to': self.date_to,
                'company_ids': self.company_ids.ids,
                'analytic_account_ids': self.analytic_account_ids.ids,
            })

            # Use export service for Excel generation
            export_service = self.env['account.financial.dashboard.export.service']

            excel_file = export_service.export_to_excel(
                export_data,
                f'Financial_Dashboard_{self.date_from}_{self.date_to}'
            )

            if excel_file:
                return {
                    'type': 'ir.actions.act_url',
                    'url': f'/web/content/{excel_file.id}?download=true',
                    'target': 'self',
                }
            else:
                raise UserError(_("Failed to generate Excel export"))

        except Exception as e:
            _logger.error(f"Dashboard export failed: {str(e)}")
            raise UserError(_("Export failed: %s") % str(e))

    def open_dashboard(self):
        """Abrir dashboard con datos iniciales."""
        return self.refresh_dashboard()

    def action_cancel(self):
        """Cancelar el wizard y cerrar la ventana."""
        return {'type': 'ir.actions.act_window_close'}

    def _get_available_widgets(self):
        """Obtener widgets disponibles para el dashboard."""
        available_widgets = [
            ('kpi', _('Key Performance Indicators')),
            ('chart', _('Charts and Graphs')),
            ('table', _('Data Tables')),
            ('ratio', _('Financial Ratios')),
            ('trend', _('Trend Analysis')),
            ('comparison', _('Period Comparison')),
        ]
        return available_widgets
