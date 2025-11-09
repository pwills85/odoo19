# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Project Profitability Report Model

Extends account.report to provide specialized project profitability analysis
with EVM integration for engineering companies.

Compatible with Odoo 18 and OCA guidelines.
"""

import json
import logging

from odoo import api, fields, models, _
from odoo import tools
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class ProjectProfitabilityReport(models.Model):
    """
    Project Profitability Report with EVM Integration.
    
    Provides comprehensive project financial analysis including:
    - Earned Value Management metrics
    - Margin analysis
    - Cash flow projections
    - Resource utilization
    """
    
    _name = 'project.profitability.report'
    
    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado display_name")
    _description = 'Project Profitability Report'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_to desc, project_id'
    
    # ==========================================
    # FIELDS
    # ==========================================
    
    # Report identification
    project_id = fields.Many2one(
        'project.project',
        string='Project',
        required=True,
        ondelete='cascade',
        help="Project for profitability analysis"
    )
    
    date_from = fields.Date(
        string='Date From',
        required=True,
        default=lambda self: fields.Date.today().replace(day=1),
        help="Start date for analysis period"
    )
    
    date_to = fields.Date(
        string='Date To',
        required=True,
        default=fields.Date.today,
        help="End date for analysis period"
    )
    
    # EVM Core Values
    planned_value = fields.Monetary(
        string='Planned Value (PV)',
        currency_field='currency_id',
        help="Budgeted cost of work scheduled"
    )
    
    earned_value = fields.Monetary(
        string='Earned Value (EV)',
        currency_field='currency_id',
        help="Budgeted cost of work performed"
    )
    
    actual_cost = fields.Monetary(
        string='Actual Cost (AC)',
        currency_field='currency_id',
        help="Actual cost of work performed"
    )
    
    budget_at_completion = fields.Monetary(
        string='Budget at Completion (BAC)',
        currency_field='currency_id',
        help="Total project budget"
    )
    
    # Performance Indices
    cost_performance_index = fields.Float(
        string='Cost Performance Index (CPI)',
        digits=(16, 3),
        help="EV / AC - Cost efficiency indicator"
    )
    
    schedule_performance_index = fields.Float(
        string='Schedule Performance Index (SPI)',
        digits=(16, 3),
        help="EV / PV - Schedule efficiency indicator"
    )
    
    # Forecasts
    estimate_at_completion = fields.Monetary(
        string='Estimate at Completion (EAC)',
        currency_field='currency_id',
        help="Forecasted total project cost"
    )
    
    estimate_to_complete = fields.Monetary(
        string='Estimate to Complete (ETC)',
        currency_field='currency_id',
        help="Forecasted remaining cost"
    )
    
    variance_at_completion = fields.Monetary(
        string='Variance at Completion (VAC)',
        currency_field='currency_id',
        help="BAC - EAC (Budget variance)"
    )
    
    # Variances
    cost_variance = fields.Monetary(
        string='Cost Variance (CV)',
        currency_field='currency_id',
        help="EV - AC (Cost performance)"
    )
    
    schedule_variance = fields.Monetary(
        string='Schedule Variance (SV)',
        currency_field='currency_id',
        help="EV - PV (Schedule performance)"
    )
    
    # Status and Health
    percent_complete = fields.Float(
        string='Percent Complete',
        digits=(16, 2),
        help="Project completion percentage"
    )
    
    cost_status = fields.Selection([
        ('excellent', 'Excellent (CPI ≥ 1.1)'),
        ('good', 'Good (1.0 ≤ CPI < 1.1)'),
        ('warning', 'Warning (0.9 ≤ CPI < 1.0)'),
        ('critical', 'Critical (CPI < 0.9)')
    ], string='Cost Status', help="Cost performance status")
    
    schedule_status = fields.Selection([
        ('excellent', 'Excellent (SPI ≥ 1.1)'),
        ('good', 'Good (1.0 ≤ SPI < 1.1)'),
        ('warning', 'Warning (0.9 ≤ SPI < 1.0)'),
        ('critical', 'Critical (SPI < 0.9)')
    ], string='Schedule Status', help="Schedule performance status")
    
    health_score = fields.Float(
        string='Health Score',
        digits=(16, 1),
        help="Overall project health (0-100)"
    )
    
    is_over_budget = fields.Boolean(
        string='Over Budget',
        help="Project is over budget (CV < 0)"
    )
    
    is_behind_schedule = fields.Boolean(
        string='Behind Schedule',
        help="Project is behind schedule (SV < 0)"
    )
    
    # Additional Analysis
    margin_amount = fields.Monetary(
        string='Margin Amount',
        currency_field='currency_id',
        compute='_compute_margin_metrics',
        store=True,
        help="Projected profit amount"
    )
    
    margin_percent = fields.Float(
        string='Margin %',
        digits=(16, 2),
        compute='_compute_margin_metrics',
        store=True,
        help="Projected profit percentage"
    )
    
    # S-Curve Data (JSON field for chart)
    s_curve_data = fields.Text(
        string='S-Curve Data',
        help="JSON data for S-curve visualization"
    )
    
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
    
    # ==========================================
    # COMPUTED FIELDS
    # ==========================================
    @tools.ormcache('self.id', 'company_id')  # Odoo 19: Use self.env.context.get('company_id')
    
    @api.depends('budget_at_completion', 'estimate_at_completion')
    def _compute_margin_metrics(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_margin_metrics for %d records", len(self))
        
        try:
            """Compute margin amount and percentage."""
            for record in self.with_context(prefetch_fields=False):
                if record.budget_at_completion and record.estimate_at_completion:
                    # Margin = Revenue - Cost
                    record.margin_amount = record.budget_at_completion - record.estimate_at_completion
                    record.margin_percent = (record.margin_amount / record.budget_at_completion * 100) if record.budget_at_completion else 0.0
                else:
                    record.margin_amount = 0.0
                    record.margin_percent = 0.0
        except Exception as e:
            _logger.error("Error in _compute_margin_metrics: %s", str(e))
            # Mantener valores por defecto en caso de error
            
        # TODO: Refactorizar para usar search con dominio completo fuera del loop

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for record in self:
                record.margin_amount = 0.0
                record.margin_percent = 0.0

    # ==========================================
    # CRUD OPERATIONS
    # ==========================================

    @api.model_create_multi
    def create(self, vals_list):
        """Override create to auto-calculate EVM metrics - Odoo 18 batch compatible."""
        records = super().create(vals_list)
        for record in records:
            record._calculate_evm_metrics()
        return records
    
    def write(self, vals):
        """Override write to recalculate if dates change."""
        result = super().write(vals)
        if any(field in vals for field in ['project_id', 'date_from', 'date_to']):
            self._calculate_evm_metrics()
        return result
    
    # ==========================================
    # EVM CALCULATION METHODS
    # ==========================================
    
    def calculate_evm_metrics(self):
        """Public method to calculate and update EVM metrics for the record."""
        return self._calculate_evm_metrics()

    def _calculate_evm_metrics(self):
        """Calculate and update EVM metrics for the record."""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        evm_service = self.env['project.evm.service']
        
        for record in self.with_context(prefetch_fields=False):
            try:
                # Get EVM data from service
                evm_data = evm_service.calculate_project_evm(
                    record.project_id.id,
                    fields.Date.to_string(record.date_to)
                )
                
                # Update record with calculated values
                record.update({
                    'planned_value': evm_data['planned_value'],
                    'earned_value': evm_data['earned_value'],
                    'actual_cost': evm_data['actual_cost'],
                    'budget_at_completion': evm_data['budget_at_completion'],
                    'cost_performance_index': evm_data['cost_performance_index'],
                    'schedule_performance_index': evm_data['schedule_performance_index'],
                    'estimate_at_completion': evm_data['estimate_at_completion'],
                    'estimate_to_complete': evm_data['estimate_to_complete'],
                    'variance_at_completion': evm_data['variance_at_completion'],
                    'cost_variance': evm_data['cost_variance'],
                    'schedule_variance': evm_data['schedule_variance'],
                    'percent_complete': evm_data['percent_complete'],
                    'cost_status': evm_data['cost_status'],
                    'schedule_status': evm_data['schedule_status'],
                    'health_score': evm_data['health_score'],
                    'is_over_budget': evm_data['is_over_budget'],
                    'is_behind_schedule': evm_data['is_behind_schedule'],
                })
                
                # Generate S-curve data
                s_curve_data = evm_service.generate_s_curve_data(record.project_id.id)
                record.s_curve_data = json.dumps(s_curve_data)
                
            except Exception as e:
                _logger.error("Error calculating EVM for record %s: %s", record.id, str(e))
                # Set default values on error
                record.update({
                    'planned_value': 0.0,
                    'earned_value': 0.0,
                    'actual_cost': 0.0,
                    'budget_at_completion': 0.0,
                    'cost_performance_index': 1.0,
                    'schedule_performance_index': 1.0,
                    'health_score': 50.0,
                })
    
    @api.model
    def action_recalculate_evm(self):
        """Action to recalculate EVM metrics for selected records."""
        active_ids = self.env.self.env.self.env.context.get('active_ids', [])
        if active_ids:
            records = self.browse(active_ids)
            records._calculate_evm_metrics()
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Success'),
                    'message': _('EVM metrics recalculated for %d records') % len(records),
                    'type': 'success',
                }
            }
    
    # ==========================================
    # REPORT GENERATION METHODS
    # ==========================================
    
    @api.model
    def generate_project_report(self, project_id, date_from=None, date_to=None):
        """
        Generate or update profitability report for a project.
        
        Args:
            project_id (int): Project ID
            date_from (str): Start date
            date_to (str): End date
            
        Returns:
            project.profitability.report: Report record
        """
        date_from = date_from or fields.Date.today().replace(day=1)
        date_to = date_to or fields.Date.today()
        
        # Check if report already exists
        existing_report = self.search([
            ('project_id', '=', project_id),
            ('date_from', '=', date_from),
            ('date_to', '=', date_to)
        ], limit=1)
        
        if existing_report:
            # Update existing report
            existing_report._calculate_evm_metrics()
            return existing_report
        else:
            # Create new report
            return self.create({
                'project_id': project_id,
                'date_from': date_from,
                'date_to': date_to,
            })
    
    @api.model
    def generate_portfolio_report(self, project_ids, date_from=None, date_to=None):
        """
        Generate profitability reports for multiple projects.
        
        Args:
            project_ids (list): List of project IDs
            date_from (str): Start date
            date_to (str): End date
            
        Returns:
            list: List of report records
        """
        reports = []
        for project_id in project_ids:
            report = self.generate_project_report(project_id, date_from, date_to)
            reports.append(report)
        return reports
    
    # ==========================================
    # EXPORT METHODS
    # ==========================================
    
    def export_to_excel(self):
        """Export project profitability data to Excel."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/project_profitability_excel/{self.id}',
            'target': 'new',
        }
    
    def export_to_pdf(self):
        """Export project profitability data to PDF."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/project_profitability_pdf/{self.id}',
            'target': 'new',
        }
    
    def get_s_curve_data(self):
        """Get S-curve data for visualization."""
        self.ensure_one()
        if self.s_curve_data:
            return json.loads(self.s_curve_data)
        return {}
    
    # ==========================================
    # CONSTRAINTS AND VALIDATIONS
    # ==========================================
    
    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        """Validate date range."""
        for record in self:
            if record.date_from and record.date_to and record.date_from > record.date_to:
                raise UserError(_("Date From must be before Date To"))
    
    @api.constrains('project_id')
    def _check_project(self):
        """Validate project exists and is active."""
        # Prefetch project active status
        projects = self.mapped('project_id')
        project_active = {p.id: p.active for p in projects}
        
        for record in self:
            if record.project_id and not project_active.get(record.project_id.id, True):
                raise UserError(_("Cannot create report for inactive project"))
    
    # ==========================================
    # UTILITY METHODS
    # ==========================================

    # REMOVED name_get(): Odoo 19 uses display_name computed field instead
    # Logic migrated to _compute_display_name() below for better integration with Odoo 19 CE

    @api.depends_context('date')
    @api.depends('project_id', 'date_to')  # Ajustar dependencias según el modelo
    def _compute_display_name(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_display_name for %d records", len(self))
        
        try:
            """Compute display name"""
            for record in self.with_context(prefetch_fields=False):
                if record.project_id and record.date_to:
                    record.display_name = f"{record.project_id.name} - {record.date_to}"
                else:
                    record.display_name = "Project Profitability Report"
        except Exception as e:
            _logger.error("Error in _compute_display_name: %s", str(e))
            # Mantener valores por defecto en caso de error

    @api.model
    def _name_search(self, name='', args=None, operator='ilike', limit=100, name_get_uid=None):
        """Custom name search."""
        if name:
            # Search by project name
            project_ids = self.env['project.project']._name_search(
                name, args=[], operator=operator, limit=limit, name_get_uid=name_get_uid
            )
            if project_ids:
                args = (args or []) + [('project_id', 'in', [id for id, _ in project_ids])]
        return super()._name_search('', args, operator, limit, name_get_uid)
    
    def get_performance_color(self, field_name):
        """Get color code for performance indicators."""
        self.ensure_one()
        status = getattr(self, field_name, '')
        
        color_map = {
            'excellent': '#28a745',  # Green
            'good': '#6c757d',       # Gray
            'warning': '#ffc107',    # Yellow
            'critical': '#dc3545',   # Red
        }
        
        return color_map.get(status, '#6c757d')
    
    def get_health_score_color(self):
        """Get color for health score."""
        self.ensure_one()
        if self.health_score >= 80:
            return '#28a745'  # Green
        elif self.health_score >= 60:
            return '#ffc107'  # Yellow
        else:
            return '#dc3545'  # Red
