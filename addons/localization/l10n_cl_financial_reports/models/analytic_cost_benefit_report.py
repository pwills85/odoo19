# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Analytic Cost/Benefit Report with Cost Weighting

Specialized report for cost/benefit analysis with cost group weighting
and percentage calculations relative to total costs and sales.
"""

import logging
from datetime import datetime, timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError
from odoo.tools import float_round

_logger = logging.getLogger(__name__)


class AnalyticCostBenefitReport(models.Model):
    """Analytic Cost/Benefit Report with Weighting."""
    _inherit = ['company.security.mixin']
    
    _name = 'analytic.cost.benefit.report'
    _description = 'Analytic Cost/Benefit Report'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_from desc, analytic_account_id'
    
    # Basic Information
    name = fields.Char(
        string='Report Name',
        compute='_compute_name',
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado name"
    )
    
    analytic_account_id = fields.Many2one(
        'account.analytic.account',
        string='Analytic Account',
        required=True
    )
    
    date_from = fields.Date(
        string='Date From',
        required=True,
        default=lambda self: fields.Date.today() - timedelta(days=30)
    )
    
    date_to = fields.Date(
        string='Date To',
        required=True,
        default=fields.Date.today
    )
    
    # Financial Totals
    total_costs = fields.Monetary(
        string='Total Costs (Net)',
        currency_field='currency_id',
        compute='_compute_financial_totals',
        store=True
    )
    
    total_revenues = fields.Monetary(
        string='Total Revenues (Net)',
        currency_field='currency_id',
        compute='_compute_financial_totals',
        store=True
    )
    
    net_benefit = fields.Monetary(
        string='Net Benefit',
        currency_field='currency_id',
        compute='_compute_financial_totals',
        store=True
    )
    
    benefit_margin_percentage = fields.Float(
        string='Benefit Margin %',
        digits=(16, 2),
        compute='_compute_financial_totals',
        store=True
    )
    
    # Cost Group Analysis
    cost_group_ids = fields.One2many(
        'analytic.cost.group.line',
        'report_id',
        string='Cost Groups Analysis'
    )
    
    # Revenue Analysis
    revenue_line_ids = fields.One2many(
        'analytic.revenue.line',
        'report_id',
        string='Revenue Analysis'
    )
    
    # Metadata
    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        default=lambda self: self.env.company.currency_id,
        required=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
        required=True
    )
    
    # Computed Fields
    @api.depends_context('date')
    @api.depends('analytic_account_id', 'date_from', 'date_to')
    def _compute_name(self):
        """Compute report name."""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        for record in self.with_context(prefetch_fields=False):
            if record.analytic_account_id and record.date_from and record.date_to:
                record.name = f"{record.analytic_account_id.name} - {record.date_from} to {record.date_to}"
            else:
                record.name = "Cost/Benefit Analysis"
    
    @api.depends('cost_group_ids.net_amount', 'revenue_line_ids.net_amount')
    def _compute_financial_totals(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_financial_totals for %d records", len(self))
        
        try:
            """Compute financial totals."""
            for record in self.with_context(prefetch_fields=False):
                record.total_costs = sum(record.cost_group_ids.mapped('net_amount'))
                record.total_revenues = sum(record.revenue_line_ids.mapped('net_amount'))
                record.net_benefit = record.total_revenues - record.total_costs
            
                if record.total_revenues > 0:
                    record.benefit_margin_percentage = (record.net_benefit / record.total_revenues) * 100
                else:
                    record.benefit_margin_percentage = 0
        except Exception as e:
            _logger.error("Error in _compute_financial_totals: %s", str(e))
            # Mantener valores por defecto en caso de error
            
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for record in self:
                record.total_costs = 0.0
                record.total_revenues = 0.0
                record.net_benefit = 0.0
                record.benefit_margin_percentage = 0.0

    # CRUD Operations
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to generate analysis data - Odoo 18 batch compatible."""
        records = super().create(vals_list)
        for record in records:
            record._generate_analysis_data()
        return records
    
    def write(self, vals):
        """Override write to regenerate if dates change."""
        result = super().write(vals)
        if any(field in vals for field in ['date_from', 'date_to', 'analytic_account_id']):
            self._generate_analysis_data()
        return result
    
    # Data Generation Methods
    def _generate_analysis_data(self):
        """Generate cost/benefit analysis data."""
        for record in self.with_context(prefetch_fields=False):
            # Clear existing lines
            record.cost_group_ids.unlink()
            record.revenue_line_ids.unlink()
            
            # Generate cost analysis
            record._generate_cost_analysis()
            
            # Generate revenue analysis
            record._generate_revenue_analysis()
    
    def _generate_cost_analysis(self):
        """Generate cost group analysis."""
        self.ensure_one()
        
        # Get analytic lines for costs
        cost_lines = self.env['account.analytic.line'].search([
            ('account_id', '=', self.analytic_account_id.id),
            ('date', '>=', self.date_from),
            ('date', '<=', self.date_to),
            ('amount', '<', 0)  # Costs are negative
        ])
        
        # Group by product category or account
        cost_groups = {}
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for line in cost_lines:
            # Determine cost group
            if line.product_id and line.product_id.categ_id:
                group_key = line.product_id.categ_id.id
                group_name = line.product_id.categ_id.name
            elif line.general_account_id:
                group_key = line.general_account_id.id
                group_name = line.general_account_id.name
            else:
                group_key = 'other'
                group_name = 'Other Costs'
            
            if group_key not in cost_groups:
                cost_groups[group_key] = {
                    'name': group_name,
                    'gross_amount': 0,
                    'net_amount': 0,
                    'line_count': 0
                }
            
            # Accumulate amounts (convert negative to positive for costs)
            gross_amount = abs(line.amount)
            net_amount = abs(line.amount)  # Assuming no tax for simplicity
            
            cost_groups[group_key]['gross_amount'] += gross_amount
            cost_groups[group_key]['net_amount'] += net_amount
            cost_groups[group_key]['line_count'] += 1
        
        # Create cost group lines using batch operation
        batch_service = self.env.service('l10n_cl.batch.operation')
        
        vals_list = []
        for group_data in cost_groups.values():
            vals_list.append({
                'report_id': self.id,
                'name': group_data['name'],
                'gross_amount': group_data['gross_amount'],
                'net_amount': group_data['net_amount'],
                'line_count': group_data['line_count'],
            })
        
        if vals_list:
            batch_service.batch_create('analytic.cost.group.line', vals_list)
    
    def _generate_revenue_analysis(self):
        """Generate revenue analysis."""
        self.ensure_one()
        
        # Get analytic lines for revenues
        revenue_lines = self.env['account.analytic.line'].search([
            ('account_id', '=', self.analytic_account_id.id),
            ('date', '>=', self.date_from),
            ('date', '<=', self.date_to),
            ('amount', '>', 0)  # Revenues are positive
        ])
        
        # Group by product or service type
        revenue_groups = {}
        
        for line in revenue_lines:
            # Determine revenue group
            if line.product_id:
                group_key = line.product_id.id
                group_name = line.product_id.name
            else:
                group_key = 'services'
                group_name = 'Services'
            
            if group_key not in revenue_groups:
                revenue_groups[group_key] = {
                    'name': group_name,
                    'gross_amount': 0,
                    'net_amount': 0,
                    'line_count': 0
                }
            
            # Accumulate amounts
            gross_amount = line.amount
            net_amount = line.amount  # Assuming no tax for simplicity
            
            revenue_groups[group_key]['gross_amount'] += gross_amount
            revenue_groups[group_key]['net_amount'] += net_amount
            revenue_groups[group_key]['line_count'] += 1
        
        # Create revenue lines using batch operation
        batch_service = self.env.service('l10n_cl.batch.operation')
        
        vals_list = []
        for group_data in revenue_groups.values():
            vals_list.append({
                'report_id': self.id,
                'name': group_data['name'],
                'gross_amount': group_data['gross_amount'],
                'net_amount': group_data['net_amount'],
                'line_count': group_data['line_count'],
            })
        
        if vals_list:
            batch_service.batch_create('analytic.revenue.line', vals_list)
    
    # Action Methods
    def action_regenerate_analysis(self):
        """Action to regenerate analysis data."""
        self._generate_analysis_data()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Success'),
                'message': _('Cost/Benefit analysis regenerated successfully'),
                'type': 'success',
            }
        }
    
    def action_export_to_excel(self):
        """Export analysis to Excel."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/cost_benefit_excel/{self.id}',
            'target': 'new',
        }
    
    def action_export_to_pdf(self):
        """Export analysis to PDF."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/cost_benefit_pdf/{self.id}',
            'target': 'new',
        }


class AnalyticCostGroupLine(models.Model):
    """Cost Group Analysis Line."""
    _inherit = ['company.security.mixin']
    
    _name = 'analytic.cost.group.line'
    _description = 'Cost Group Analysis Line'
    _order = 'net_amount desc'
    
    report_id = fields.Many2one(
        'analytic.cost.benefit.report',
        string='Report',
        required=True,
        ondelete='cascade'
    )
    
    name = fields.Char(
        string='Cost Group',
        required=True
    )
    
    gross_amount = fields.Monetary(
        string='Gross Amount',
        currency_field='currency_id'
    )
    
    net_amount = fields.Monetary(
        string='Net Amount',
        currency_field='currency_id'
    )
    
    line_count = fields.Integer(
        string='Number of Lines'
    )
    
    # Weighting Calculations
    weight_vs_total_costs = fields.Float(
        string='% vs Total Costs',
        digits=(16, 2),
        compute='_compute_weightings',
        store=True
    )
    
    weight_vs_total_sales = fields.Float(
        string='% vs Total Sales',
        digits=(16, 2),
        compute='_compute_weightings',
        store=True
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        related='report_id.currency_id',
        store=True
    )
    
    @api.depends('net_amount', 'report_id.total_costs', 'report_id.total_revenues')
    def _compute_weightings(self):
        """Método compute optimizado con manejo de errores"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        _logger.debug("Computing _compute_weightings for %d records", len(self))
        
        try:
            """Compute weighting percentages."""
            for record in self.with_context(prefetch_fields=False):
                # Weight vs Total Costs
                if record.report_id.total_costs > 0:
                    record.weight_vs_total_costs = (record.net_amount / record.report_id.total_costs) * 100
                else:
                    record.weight_vs_total_costs = 0
            
                # Weight vs Total Sales
                if record.report_id.total_revenues > 0:
                    record.weight_vs_total_sales = (record.net_amount / record.report_id.total_revenues) * 100
                else:
                    record.weight_vs_total_sales = 0
        except Exception as e:
            _logger.error("Error in _compute_weightings: %s", str(e))
            # Mantener valores por defecto en caso de error


class AnalyticRevenueLine(models.Model):
    """Revenue Analysis Line."""
    _inherit = ['company.security.mixin']
    
    _name = 'analytic.revenue.line'
    _description = 'Revenue Analysis Line'
    _order = 'net_amount desc'
    
    report_id = fields.Many2one(
        'analytic.cost.benefit.report',
        string='Report',
        required=True,
        ondelete='cascade'
    )
    
    name = fields.Char(
        string='Revenue Source',
        required=True
    )
    
    gross_amount = fields.Monetary(
        string='Gross Amount',
        currency_field='currency_id'
    )
    
    net_amount = fields.Monetary(
        string='Net Amount',
        currency_field='currency_id'
    )
    
    line_count = fields.Integer(
        string='Number of Lines'
    )
    
    # Revenue Analysis
    percentage_of_total = fields.Float(
        string='% of Total Revenue',
        digits=(16, 2),
        compute='_compute_percentage',
        store=True
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        related='report_id.currency_id',
        store=True
    )
    
    @api.depends('net_amount', 'report_id.total_revenues')
    def _compute_percentage(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_percentage for %d records", len(self))
        
        try:
            """Compute percentage of total revenue."""
            for record in self.with_context(prefetch_fields=False):
                if record.report_id.total_revenues > 0:
                    record.percentage_of_total = (record.net_amount / record.report_id.total_revenues) * 100
                else:
                    record.percentage_of_total = 0

        except Exception as e:
            _logger.error("Error in _compute_percentage: %s", str(e))
            # Mantener valores por defecto en caso de error