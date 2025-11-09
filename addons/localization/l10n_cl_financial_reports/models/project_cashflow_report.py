# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Project Cash Flow Report Model

Specialized model for cash flow analysis in engineering projects.
Integrates with milestone billing and retention management.
"""

import json
import logging
from datetime import timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class ProjectCashFlowReport(models.Model):
    """Project Cash Flow Report with Milestone Integration."""
    _inherit = ['company.security.mixin']
    
    _name = 'project.cashflow.report'
    
    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado display_name")
    _description = 'Project Cash Flow Report'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_generated desc, project_id'
    
    # Basic Information
    project_id = fields.Many2one(
        'project.project',
        string='Project',
        required=True,
        ondelete='cascade'
    )
    
    date_generated = fields.Datetime(
        string='Generated Date',
        default=fields.Datetime.now,
        required=True
    )
    
    forecast_periods = fields.Integer(
        string='Forecast Periods (Weeks)',
        default=13,
        help="Number of weeks to forecast"
    )
    
    # Cash Flow Metrics
    total_forecast_inflow = fields.Monetary(
        string='Total Forecast Inflow',
        currency_field='currency_id'
    )
    
    total_forecast_outflow = fields.Monetary(
        string='Total Forecast Outflow',
        currency_field='currency_id'
    )
    
    net_forecast = fields.Monetary(
        string='Net Forecast',
        currency_field='currency_id',
        compute='_compute_net_forecast',
        store=True
    )
    
    max_cash_gap = fields.Monetary(
        string='Maximum Cash Gap',
        currency_field='currency_id',
        help="Largest negative cash position forecasted"
    )
    
    working_capital_need = fields.Monetary(
        string='Working Capital Need',
        currency_field='currency_id',
        help="Maximum working capital required"
    )
    
    # DSO and Collections
    dso = fields.Float(
        string='Days Sales Outstanding',
        digits=(16, 1),
        help="Average days to collect payments"
    )
    
    total_retention = fields.Monetary(
        string='Total Retention Amount',
        currency_field='currency_id',
        help="Total amount held as retention"
    )
    
    # JSON Data Fields
    milestones_data = fields.Text(
        string='Milestones Data',
        help="JSON data for milestones"
    )
    
    forecast_data = fields.Text(
        string='Forecast Data',
        help="JSON data for cash flow forecast"
    )
    
    waterfall_data = fields.Text(
        string='Waterfall Data',
        help="JSON data for waterfall chart"
    )
    
    alerts_data = fields.Text(
        string='Alerts Data',
        help="JSON data for cash flow alerts"
    )
    
    # Status and Health
    cash_health_status = fields.Selection([
        ('excellent', 'Excellent - Strong Cash Position'),
        ('good', 'Good - Adequate Cash Flow'),
        ('warning', 'Warning - Monitor Cash Gaps'),
        ('critical', 'Critical - Immediate Action Required')
    ], string='Cash Health Status', compute='_compute_cash_health', store=True)
    
    has_cash_gaps = fields.Boolean(
        string='Has Cash Gaps',
        compute='_compute_cash_gaps',
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado has_cash_gaps")
    
    # Metadata
    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        related='project_id.company_id.currency_id',
        store=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        related='project_id.company_id',
        store=True
    )
    
    # Computed Fields
    @api.depends('total_forecast_inflow', 'total_forecast_outflow')
    def _compute_net_forecast(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_net_forecast for %d records", len(self))
        
        try:
            """Compute net cash flow forecast."""
            for record in self.with_context(prefetch_fields=False):
                record.net_forecast = record.total_forecast_inflow - record.total_forecast_outflow
    
        except Exception as e:
            _logger.error("Error in _compute_net_forecast: %s", str(e))
            # Mantener valores por defecto en caso de error
    def _compute_cash_health(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_cash_health for %d records", len(self))
        
        try:
            """Compute overall cash health status."""
            for record in self.with_context(prefetch_fields=False):
                if record.max_cash_gap <= 0 and record.net_forecast > 0 and record.dso <= 30:
                    record.cash_health_status = 'excellent'
                elif record.max_cash_gap <= 50000 and record.net_forecast >= 0 and record.dso <= 45:
                    record.cash_health_status = 'good'
                elif record.max_cash_gap <= 100000 or record.dso <= 60:
                    record.cash_health_status = 'warning'
                else:
                    record.cash_health_status = 'critical'
    
        except Exception as e:
            _logger.error("Error in _compute_cash_health: %s", str(e))
            # Mantener valores por defecto en caso de error
    def _compute_cash_gaps(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_cash_gaps for %d records", len(self))
        
        try:
            """Check if project has significant cash gaps."""
            for record in self.with_context(prefetch_fields=False):
                record.has_cash_gaps = record.max_cash_gap > 10000
    
        except Exception as e:
            _logger.error("Error in _compute_cash_gaps: %s", str(e))
            # Mantener valores por defecto en caso de error
    def create(self, vals):
        """Override create to generate cash flow data."""
        record = super().create(vals)
        record._generate_cashflow_data()
        return record
    
    def write(self, vals):
        """Override write to regenerate if key fields change."""
        result = super().write(vals)
        if any(field in vals for field in ['project_id', 'forecast_periods']):
            self._generate_cashflow_data()
        return result
    
    # Cash Flow Generation Methods
    def _generate_cashflow_data(self):
        """Generate all cash flow data for the report."""
        cashflow_service = self.env['project.cashflow.service']
        
        for record in self.with_context(prefetch_fields=False):
            try:
                # Get comprehensive cash flow data
                cashflow_data = cashflow_service.calculate_project_cashflow(
                    record.project_id.id,
                    record.forecast_periods
                )
                
                # Update metrics
                record.update({
                    'total_forecast_inflow': cashflow_data['metrics']['total_forecast_inflow'],
                    'total_forecast_outflow': cashflow_data['metrics']['total_forecast_outflow'],
                    'max_cash_gap': cashflow_data['metrics']['max_cash_gap'],
                    'working_capital_need': cashflow_data['metrics']['working_capital_need'],
                    'dso': cashflow_data['metrics']['dso'],
                    'total_retention': cashflow_data['metrics']['total_retention'],
                })
                
                # Store JSON data
                record.milestones_data = json.dumps(cashflow_data['milestones'])
                record.forecast_data = json.dumps(cashflow_data['forecast'])
                
                # Generate waterfall data
                waterfall_data = cashflow_service.generate_waterfall_data(record.project_id.id)
                record.waterfall_data = json.dumps(waterfall_data)
                
                # Generate alerts
                alerts = cashflow_service.get_cash_alerts(record.project_id.id)
                record.alerts_data = json.dumps(alerts)
                
            except Exception as e:
                _logger.error("Error generating cash flow data for record %s: %s", record.id, str(e))
                # Set default values on error
                record.update({
                    'total_forecast_inflow': 0.0,
                    'total_forecast_outflow': 0.0,
                    'max_cash_gap': 0.0,
                    'working_capital_need': 0.0,
                    'dso': 0.0,
                    'total_retention': 0.0,
                })
    
    # Action Methods
    def action_regenerate_data(self):
        """Action to regenerate cash flow data."""
        self._generate_cashflow_data()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Success'),
                'message': _('Cash flow data regenerated successfully'),
                'type': 'success',
            }
        }
    
    def action_view_milestones(self):
        """Action to view project milestones."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        return {
            'type': 'ir.actions.act_window',
            'name': _('Project Milestones'),
            'res_model': 'sale.order.line',
            'view_mode': 'tree,form',
            'domain': [('order_id', '=', self.project_id.sale_order_id.id)],
            'context': {'default_order_id': self.project_id.sale_order_id.id}
        }
    
    def action_view_invoices(self):
        """Action to view project invoices."""
        return {
            'type': 'ir.actions.act_window',
            'name': _('Project Invoices'),
            'res_model': 'account.move',
            'view_mode': 'tree,form',
            'domain': [('project_id', '=', self.project_id.id)],
            'context': {'default_project_id': self.project_id.id}
        }
    
    # Data Access Methods
    def get_milestones_data(self):
        """Get milestones data for visualization."""
        self.ensure_one()
        return json.loads(self.milestones_data) if self.milestones_data else []
    
    def get_forecast_data(self):
        """Get forecast data for visualization."""
        self.ensure_one()
        return json.loads(self.forecast_data) if self.forecast_data else {}
    
    def get_waterfall_data(self):
        """Get waterfall chart data."""
        self.ensure_one()
        return json.loads(self.waterfall_data) if self.waterfall_data else {}
    
    def get_alerts_data(self):
        """Get cash flow alerts."""
        self.ensure_one()
        return json.loads(self.alerts_data) if self.alerts_data else []
    
    # Report Generation Methods
    @api.model
    def generate_project_cashflow_report(self, project_id, forecast_periods=13):
        """Generate or update cash flow report for a project."""
        # Check if recent report exists (within last day)
        existing_report = self.search([
            ('project_id', '=', project_id),
            ('date_generated', '>=', fields.Datetime.now() - timedelta(days=1))
        ], limit=1)
        
        if existing_report:
            existing_report._generate_cashflow_data()
            return existing_report
        else:
            return self.create({
                'project_id': project_id,
                'forecast_periods': forecast_periods,
            })
    
    @api.model
    def generate_portfolio_cashflow_reports(self, project_ids, forecast_periods=13):
        """Generate cash flow reports for multiple projects."""
        reports = []
        for project_id in project_ids:
            report = self.generate_project_cashflow_report(project_id, forecast_periods)
            reports.append(report)
        return reports
    
    # Export Methods
    def export_to_excel(self):
        """Export cash flow report to Excel."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/cashflow_excel/{self.id}',
            'target': 'new',
        }
    
    def export_waterfall_chart(self):
        """Export waterfall chart as image."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/waterfall_chart/{self.id}',
            'target': 'new',
        }

    # Utility Methods
    # REMOVED name_get(): Odoo 19 uses display_name computed field instead
    # Logic migrated to _compute_display_name() below for better integration with Odoo 19 CE

    @api.depends_context('date')
    @api.depends('project_id', 'date_generated')  # Ajustar dependencias según el modelo
    def _compute_display_name(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_display_name for %d records", len(self))
        
        try:
            """Compute display name"""
            for record in self.with_context(prefetch_fields=False):
                # Migrar lógica de name_get aquí
                if record.project_id and record.date_generated:
                    record.display_name = f"{record.project_id.name} - Cash Flow ({record.date_generated.strftime('%Y-%m-%d')})"
                else:
                    record.display_name = "Project Cash Flow Report"
        except Exception as e:
            _logger.error("Error in _compute_display_name: %s", str(e))
            # Mantener valores por defecto en caso de error

    
    @api.model
    def _name_search(self, name='', args=None, operator='ilike', limit=100, name_get_uid=None):
        """Custom name search."""
        if name:
            project_ids = self.env['project.project']._name_search(
                name, args=[], operator=operator, limit=limit, name_get_uid=name_get_uid
            )
            if project_ids:
                args = (args or []) + [('project_id', 'in', [id for id, _ in project_ids])]
        return super()._name_search('', args, operator, limit, name_get_uid)
    
    def get_health_color(self):
        """Get color for health status."""
        self.ensure_one()
        color_map = {
            'excellent': '#28a745',  # Green
            'good': '#6c757d',       # Gray
            'warning': '#ffc107',    # Yellow
            'critical': '#dc3545',   # Red
        }
        return color_map.get(self.cash_health_status, '#6c757d')
    
    # Constraints
    @api.constrains('forecast_periods')
    def _check_forecast_periods(self):
        """Validate forecast periods."""
        for record in self.with_context(prefetch_fields=False):
            if record.forecast_periods < 1 or record.forecast_periods > 52:
                raise UserError(_("Forecast periods must be between 1 and 52 weeks"))


class ProjectCashFlowMilestone(models.Model):
    """Project Cash Flow Milestone Model."""
    _inherit = ['company.security.mixin']
    
    _name = 'project.cashflow.milestone'
    
    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado display_name")
    _description = 'Project Cash Flow Milestone'
    _order = 'planned_date, sequence'
    
    # Basic Information
    cashflow_report_id = fields.Many2one(
        'project.cashflow.report',
        string='Cash Flow Report',
        required=True,
        ondelete='cascade'
    )
    
    project_id = fields.Many2one(
        'project.project',
        string='Project',
        related='cashflow_report_id.project_id',
        store=True
    )
    
    sequence = fields.Integer(string='Sequence', default=10)
    
    name = fields.Char(string='Milestone Name', required=True)
    description = fields.Text(string='Description')
    
    # Financial Information
    amount = fields.Monetary(
        string='Milestone Amount',
        currency_field='currency_id',
        required=True
    )
    
    retention_percent = fields.Float(
        string='Retention %',
        digits=(16, 2),
        default=5.0,
        help="Percentage held as retention"
    )
    
    retention_amount = fields.Monetary(
        string='Retention Amount',
        currency_field='currency_id',
        compute='_compute_retention_amount',
        store=True
    )
    
    collectible_amount = fields.Monetary(
        string='Collectible Amount',
        currency_field='currency_id',
        compute='_compute_collectible_amount',
        store=True
    )
    
    # Dates
    planned_date = fields.Date(string='Planned Date', required=True)
    actual_date = fields.Date(string='Actual Date')
    collection_date = fields.Date(string='Collection Date')
    
    # Status
    status = fields.Selection([
        ('planned', 'Planned'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('invoiced', 'Invoiced'),
        ('paid', 'Paid')
    ], string='Status', default='planned', required=True)
    
    # References
    sale_line_id = fields.Many2one(
        'sale.order.line', 
        string='Sale Order Line',
        help='Related sale order line (requires sale module)'
    )
    invoice_id = fields.Many2one('account.move', string='Invoice')
    
    # Metadata
    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        related='project_id.company_id.currency_id',
        store=True
    )
    
    # Computed Fields
    @api.depends('amount', 'retention_percent')
    def _compute_retention_amount(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_retention_amount for %d records", len(self))
        
        try:
            """Compute retention amount."""
            for record in self.with_context(prefetch_fields=False):
                record.retention_amount = record.amount * (record.retention_percent / 100)
    
        except Exception as e:
            _logger.error("Error in _compute_retention_amount: %s", str(e))
            # Mantener valores por defecto en caso de error
    def _compute_collectible_amount(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_collectible_amount for %d records", len(self))
        
        try:
            """Compute collectible amount."""
            for record in self.with_context(prefetch_fields=False):
                record.collectible_amount = record.amount - record.retention_amount

        except Exception as e:
            _logger.error("Error in _compute_collectible_amount: %s", str(e))
            # Mantener valores por defecto en caso de error