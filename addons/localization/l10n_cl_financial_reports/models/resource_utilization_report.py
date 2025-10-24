# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Resource Utilization Report Model

Specialized model for resource utilization analysis and capacity planning
in engineering companies. Tracks employee utilization, skills, and capacity.
"""

import json
import logging
from datetime import datetime, timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError
from odoo.tools import float_round

_logger = logging.getLogger(__name__)


class ResourceUtilizationReport(models.Model):
    """Resource Utilization Report for Capacity Planning."""
    _inherit = ['company.security.mixin']
    
    _name = 'resource.utilization.report'
    
    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado display_name")
    _description = 'Resource Utilization Report'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_generated desc'
    
    # Basic Information
    name = fields.Char(
        string='Report Name',
        compute='_compute_name',
        compute_sudo=True, 
        store=True,
        help="Campo computado name")
    
    date_generated = fields.Datetime(
        string='Generated Date',
        default=fields.Datetime.now,
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
    
    # Aggregate Metrics
    total_employees = fields.Integer(
        string='Total Employees',
        help="Number of employees analyzed")
    
    avg_utilization_rate = fields.Float(
        string='Average Utilization Rate',
        digits=(16, 2),
        help="Average utilization across all employees")
    
    avg_billable_rate = fields.Float(
        string='Average Billable Rate',
        digits=(16, 2),
        help="Average billable hours percentage")
    
    avg_overtime_rate = fields.Float(
        string='Average Overtime Rate',
        digits=(16, 2),
        help="Average overtime percentage")
    
    total_available_hours = fields.Float(
        string='Total Available Hours',
        digits=(16, 2),
        help="Total available working hours")
    
    total_worked_hours = fields.Float(
        string='Total Worked Hours',
        digits=(16, 2),
        help="Total hours actually worked")
    
    total_billable_hours = fields.Float(
        string='Total Billable Hours',
        digits=(16, 2),
        help="Total billable hours")
    
    overall_utilization = fields.Float(
        string='Overall Utilization',
        digits=(16, 2),
        help="Overall team utilization percentage")
    
    utilization_percentage = fields.Float(
        string='Utilization %',
        compute='_compute_utilization_percentage',
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado utilization_percentage")
    
    # Status Distribution
    employees_overutilized = fields.Integer(
        string='Overutilized Employees',
        help="Employees with >90% utilization")
    
    employees_optimal = fields.Integer(
        string='Optimally Utilized',
        help="Employees with 75-90% utilization")
    
    employees_underutilized = fields.Integer(
        string='Underutilized Employees',
        help="Employees with 50-75% utilization")
    
    employees_available = fields.Integer(
        string='Available Employees',
        help="Employees with <50% utilization")
    
    # JSON Data Fields
    employees_data = fields.Text(
        string='Employees Data',
        help="JSON data for individual employee metrics")
    
    capacity_forecast_data = fields.Text(
        string='Capacity Forecast Data',
        help="JSON data for capacity forecasting")
    
    recommendations_data = fields.Text(
        string='Recommendations Data',
        help="JSON data for resource recommendations")
    
    # Health Status
    resource_health_status = fields.Selection([
        ('excellent', 'Excellent - Balanced Utilization'),
        ('good', 'Good - Minor Adjustments Needed'),
        ('warning', 'Warning - Utilization Issues'),
        ('critical', 'Critical - Immediate Action Required')
    ], string='Resource Health Status', compute='_compute_resource_health', store=True)
    
    # Metadata
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
        required=True
    )
    
    # Computed Fields
    @api.depends_context('date')
    @api.depends('date_from', 'date_to')
    def _compute_name(self):
        """Compute report name."""
        for record in self.with_context(prefetch_fields=False):
            if record.date_from and record.date_to:
                record.name = f"Resource Utilization {record.date_from} to {record.date_to}"
            else:
                record.name = "Resource Utilization Report"
    
    @api.depends('avg_utilization_rate', 'employees_overutilized', 'employees_available')
    def _compute_resource_health(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_resource_health for %d records", len(self))
        
        try:
            """Compute overall resource health status."""
            for record in self.with_context(prefetch_fields=False):
                if not record.total_employees:
                    record.resource_health_status = 'good'
                    continue
                
                overutilized_pct = (record.employees_overutilized / record.total_employees) * 100
                available_pct = (record.employees_available / record.total_employees) * 100
            
                if overutilized_pct > 30 or record.avg_utilization_rate > 95:
                    record.resource_health_status = 'critical'
                elif overutilized_pct > 15 or available_pct > 40:
                    record.resource_health_status = 'warning'
                elif 70 <= record.avg_utilization_rate <= 85:
                    record.resource_health_status = 'excellent'
                else:
                    record.resource_health_status = 'good'
        except Exception as e:
            _logger.error("Error in _compute_resource_health: %s", str(e))
            # Mantener valores por defecto en caso de error
            for record in self:
                record.resource_health_status = 'good'

    # CRUD Operations
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to generate utilization data - Odoo 18 batch compatible."""
        records = super().create(vals_list)
        for record in records:
            record._generate_utilization_data()
        return records
    
    def write(self, vals):
        """Override write to regenerate if dates change."""
        result = super().write(vals)
        if any(field in vals for field in ['date_from', 'date_to']):
            self._generate_utilization_data()
        return result
    
    # Data Generation Methods
    def _generate_utilization_data(self):
        """Generate all utilization data for the report."""
        resource_service = self.env['resource.analytics.service']
        
        for record in self.with_context(prefetch_fields=False):
            try:
                # Get utilization data
                utilization_data = resource_service.calculate_resource_utilization(
                    employee_ids=None,
                    date_from=fields.Date.to_string(record.date_from),
                    date_to=fields.Date.to_string(record.date_to)
                )
                
                # Update aggregate metrics
                aggregate = utilization_data.get('aggregate', {})
                record.update({
                    'total_employees': aggregate.get('total_employees', 0),
                    'avg_utilization_rate': aggregate.get('avg_utilization_rate', 0),
                    'avg_billable_rate': aggregate.get('avg_billable_rate', 0),
                    'avg_overtime_rate': aggregate.get('avg_overtime_rate', 0),
                    'total_available_hours': aggregate.get('total_available_hours', 0),
                    'total_worked_hours': aggregate.get('total_worked_hours', 0),
                    'total_billable_hours': aggregate.get('total_billable_hours', 0),
                    'overall_utilization': aggregate.get('overall_utilization', 0),
                })
                
                # Update status distribution
                status_dist = aggregate.get('status_distribution', {})
                record.update({
                    'employees_overutilized': status_dist.get('overutilized', 0),
                    'employees_optimal': status_dist.get('optimal', 0),
                    'employees_underutilized': status_dist.get('underutilized', 0),
                    'employees_available': status_dist.get('available', 0),
                })
                
                # Store JSON data
                record.employees_data = json.dumps(utilization_data.get('employees', {}))
                
                # Generate capacity forecast
                forecast_data = resource_service.generate_capacity_forecast(weeks_ahead=12)
                record.capacity_forecast_data = json.dumps(forecast_data)
                
                # Generate recommendations
                recommendations = resource_service.get_resource_recommendations()
                record.recommendations_data = json.dumps(recommendations)
                
            except Exception as e:
                _logger.error("Error generating utilization data for record %s: %s", record.id, str(e))
                # Set default values on error
                record.update({
                    'total_employees': 0,
                    'avg_utilization_rate': 0,
                    'avg_billable_rate': 0,
                    'avg_overtime_rate': 0,
                })
    
    # Action Methods
    def action_regenerate_data(self):
        """Action to regenerate utilization data."""
        self._generate_utilization_data()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Success'),
                'message': _('Resource utilization data regenerated successfully'),
                'type': 'success',
            }
        }
    
    def action_view_employees(self):
        """Action to view employees in the report."""
        employee_ids = []
        if self.employees_data:
            employees_data = json.loads(self.employees_data)
            employee_ids = list(employees_data.keys())
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Employees'),
            'res_model': 'hr.employee',
            'view_mode': 'tree,form',
            'domain': [('id', 'in', employee_ids)],
        }
    
    def action_view_capacity_forecast(self):
        """Action to view capacity forecast."""
        return {
            'type': 'ir.actions.act_window',
            'name': _('Capacity Forecast'),
            'res_model': 'resource.capacity.forecast',
            'view_mode': 'tree,form',
            'context': {'default_report_id': self.id}
        }
    
    # Data Access Methods
    def get_employees_data(self):
        """Get employees data for visualization."""
        self.ensure_one()
        return json.loads(self.employees_data) if self.employees_data else {}
    
    def get_capacity_forecast_data(self):
        """Get capacity forecast data."""
        self.ensure_one()
        return json.loads(self.capacity_forecast_data) if self.capacity_forecast_data else {}
    
    def get_recommendations_data(self):
        """Get recommendations data."""
        self.ensure_one()
        return json.loads(self.recommendations_data) if self.recommendations_data else []
    
    def get_utilization_heatmap_data(self):
        """Get data for utilization heatmap visualization."""
        self.ensure_one()
        employees_data = self.get_employees_data()
        
        heatmap_data = []
        for emp_id, emp_data in employees_data.items():
            heatmap_data.append({
                'employee_id': emp_id,
                'employee_name': emp_data.get('employee_name', ''),
                'department': emp_data.get('department', ''),
                'utilization_rate': emp_data.get('utilization_rate', 0),
                'billable_rate': emp_data.get('billable_rate', 0),
                'overtime_rate': emp_data.get('overtime_rate', 0),
                'status': emp_data.get('utilization_status', 'available'),
                'color': self._get_utilization_color(emp_data.get('utilization_rate', 0))
            })
        
        return sorted(heatmap_data, key=lambda x: x['utilization_rate'], reverse=True)
    
    def _get_utilization_color(self, utilization_rate):
        """Get color for utilization rate."""
        if utilization_rate >= 90:
            return '#dc3545'  # Red - Overutilized
        elif utilization_rate >= 75:
            return '#28a745'  # Green - Optimal
        elif utilization_rate >= 50:
            return '#ffc107'  # Yellow - Underutilized
        else:
            return '#6c757d'  # Gray - Available
    
    # Report Generation Methods
    @api.model
    def generate_utilization_report(self, date_from=None, date_to=None):
        """Generate or update utilization report."""
        if not date_from:
            date_from = fields.Date.today() - timedelta(days=30)
        if not date_to:
            date_to = fields.Date.today()
        
        # Check if recent report exists
        existing_report = self.search([
            ('date_from', '=', date_from),
            ('date_to', '=', date_to),
            ('company_id', '=', self.env.company.id)
        ], limit=1)
        
        if existing_report:
            existing_report._generate_utilization_data()
            return existing_report
        else:
            return self.create({
                'date_from': date_from,
                'date_to': date_to,
            })
    
    # Export Methods
    def export_to_excel(self):
        """Export resource utilization data to Excel."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/resource_utilization_excel/{self.id}',
            'target': 'new',
        }
    
    def export_to_pdf(self):
        """Export resource utilization data to PDF."""
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/export/resource_utilization_pdf/{self.id}',
            'target': 'new',
        }
    
    # Utility Methods
    def get_health_color(self):
        """Get color for health status."""
        self.ensure_one()
        color_map = {
            'excellent': '#28a745',  # Green
            'good': '#6c757d',       # Gray
            'warning': '#ffc107',    # Yellow
            'critical': '#dc3545',   # Red
        }
        return color_map.get(self.resource_health_status, '#6c757d')
    
    # Constraints
    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        """Validate date range."""
        for record in self.with_context(prefetch_fields=False):
            if record.date_from > record.date_to:
                raise UserError(_("Date From must be before Date To"))


class ResourceCapacityForecast(models.Model):
    """Resource Capacity Forecast Model."""
    _inherit = ['company.security.mixin']
    
    _name = 'resource.capacity.forecast'
    
    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        compute_sudo=True, 
        store=True,
        index=True,
        help="Campo computado display_name")
    _description = 'Resource Capacity Forecast'
    _order = 'week_start'
    
    # Basic Information
    report_id = fields.Many2one(
        'resource.utilization.report',
        string='Utilization Report',
        ondelete='cascade'
    )
    
    week_start = fields.Date(
        string='Week Start',
        required=True
    )
    
    week_end = fields.Date(
        string='Week End',
        required=True
    )
    
    week_number = fields.Char(
        string='Week Number',
        compute='_compute_week_number',
        compute_sudo=True, 
        store=True,
        help="Campo computado week_number")
    
    # Capacity Metrics
    available_capacity_hours = fields.Float(
        string='Available Capacity (Hours)',
        digits=(16, 2)
    )
    
    planned_allocation_hours = fields.Float(
        string='Planned Allocation (Hours)',
        digits=(16, 2)
    )
    
    remaining_capacity_hours = fields.Float(
        string='Remaining Capacity (Hours)',
        digits=(16, 2)
    )
    
    utilization_forecast = fields.Float(
        string='Utilization Forecast (%)',
        digits=(16, 2)
    )
    
    # Status
    capacity_status = fields.Selection([
        ('overbooked', 'Overbooked - >95% Utilized'),
        ('high_utilization', 'High Utilization - 80-95%'),
        ('moderate_utilization', 'Moderate Utilization - 60-80%'),
        ('low_utilization', 'Low Utilization - <60%'),
        ('no_capacity', 'No Capacity Available')
    ], string='Capacity Status')
    
    # Metadata
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        related='report_id.company_id',
        store=True
    )
    
    # Computed Fields
    @api.depends('week_start')
    def _compute_week_number(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_week_number for %d records", len(self))
        
        try:
            """Compute week number."""
            for record in self.with_context(prefetch_fields=False):
                if record.week_start:
                    record.week_number = record.week_start.strftime('%Y-W%U')
                else:
                    record.week_number = ''
    
        except Exception as e:
            _logger.error("Error in _compute_week_number: %s", str(e))
            # Mantener valores por defecto en caso de error
    @api.depends('week_number', 'capacity_status')  # Ajustar dependencias según el modelo
    def _compute_display_name(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_display_name for %d records", len(self))
        
        try:
            """Compute display name"""
            for record in self.with_context(prefetch_fields=False):
                # Migrar lógica de name_get aquí
                if record.week_number:
                    record.display_name = f"Week {record.week_number} - {record.capacity_status or 'Unknown'}"
                else:
                    record.display_name = "Resource Capacity Forecast"
        except Exception as e:
            _logger.error("Error in _compute_display_name: %s", str(e))
            # Mantener valores por defecto en caso de error

    # REMOVED name_get(): Odoo 19 uses display_name computed field instead
    # Logic migrated to _compute_display_name() above
