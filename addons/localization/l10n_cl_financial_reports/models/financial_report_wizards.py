# -*- coding: utf-8 -*-
from odoo import models, fields

class TrialBalanceReportWizard(models.TransientModel):
    _name = 'trial.balance.report'
    _description = 'Wizard para Balance de Comprobación'
    
    company_id = fields.Many2one('res.company', required=True, default=lambda self: self.env.company)
    date_from = fields.Date(required=True, default=fields.Date.today)
    date_to = fields.Date(required=True, default=fields.Date.today)

    def launch_report(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'tag': 'financial_report_viewer',
            'name': 'Balance de Comprobación',
            'context': {
                'active_model': self._name,
                'active_id': self.id,
                'report_code': 'trial_balance',
            }
        }

class GeneralLedgerReportWizard(models.TransientModel):
    _name = 'general.ledger.report'
    _description = 'Wizard para Libro Mayor'

    company_id = fields.Many2one('res.company', required=True, default=lambda self: self.env.company)
    date_from = fields.Date(required=True, default=fields.Date.today)
    date_to = fields.Date(required=True, default=fields.Date.today)

    def launch_report(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'tag': 'financial_report_viewer',
            'name': 'Libro Mayor',
            'context': {
                'active_model': self._name,
                'active_id': self.id,
                'report_code': 'general_ledger',
            }
        }
