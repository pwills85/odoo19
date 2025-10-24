# -*- coding: utf-8 -*-
from odoo import models, fields, api

class BalanceEightColumnsReportWizard(models.TransientModel):
    _name = 'balance.eight.columns.report'
    _description = 'Wizard para Balance de 8 Columnas'

    company_id = fields.Many2one('res.company', string='Compañía', required=True, default=lambda self: self.env.company)
    date_from = fields.Date(string='Fecha Desde', required=True, default=fields.Date.today)
    date_to = fields.Date(string='Fecha Hasta', required=True, default=fields.Date.today)
    target_move = fields.Selection([('posted', 'Asientos Publicados'), ('all', 'Todos los Asientos')], string='Movimientos a Incluir', required=True, default='posted')

    def launch_report(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'tag': 'financial_report_viewer',
            'name': 'Balance de 8 Columnas',
            'context': {
                'active_model': self._name,
                'active_id': self.id,
            }
        }
