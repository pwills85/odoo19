# -*- coding: utf-8 -*-
from odoo import models, fields, api

class HrContract(models.Model):
    _name = 'hr.contract'
    _description = 'Employee Contract (Stub)'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(string='Contract Reference', required=True)
    employee_id = fields.Many2one('hr.employee', string='Employee', required=True)
    date_start = fields.Date(string='Start Date', required=True)
    date_end = fields.Date(string='End Date')
    wage = fields.Monetary(string='Wage', required=True)
    currency_id = fields.Many2one('res.currency', string='Currency',
                                   default=lambda self: self.env.company.currency_id)
    state = fields.Selection([
        ('draft', 'New'),
        ('open', 'Running'),
        ('close', 'Expired'),
        ('cancel', 'Cancelled')
    ], string='Status', default='draft')
    company_id = fields.Many2one('res.company', string='Company',
                                  default=lambda self: self.env.company)
    active = fields.Boolean(default=True)
