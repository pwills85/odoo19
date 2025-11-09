# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Resource Analytics Service for Engineering Companies

Specialized service for resource utilization analysis and capacity planning
in engineering projects. Handles employee utilization, skills matrix, and
capacity forecasting for project planning.

Compatible with Odoo 18 and OCA guidelines.
"""

import logging
from datetime import timedelta
from typing import Dict, List

from odoo import api, fields, models
from odoo.tools import date_utils

_logger = logging.getLogger(__name__)


class ResourceAnalyticsService(models.AbstractModel):
    """Service for Resource Analytics and Capacity Planning."""
    
    _name = 'resource.analytics.service'
    _inherit = ['base.financial.service', 'batch.operation.mixin', 'query.optimization.mixin', 'cache.optimization.mixin']
    _description = 'Resource Analytics Service'
    
    @api.model
    def calculate_resource_utilization(self, employee_ids: List[int] = None, 
                                     date_from: str = None, date_to: str = None) -> Dict:
        """
        Calculate comprehensive resource utilization analysis.
        
        Args:
            employee_ids: List of employee IDs (None for all)
            date_from: Start date for analysis
            date_to: End date for analysis
            
        Returns:
            Dict: Complete resource utilization analysis
        """
        if not date_from:
            date_from = fields.Date.today().replace(day=1)
        if not date_to:
            date_to = date_utils.end_of(fields.Date.today(), 'month')
            
        # Get employees
        if employee_ids:
            employees = self.env['hr.employee'].browse(employee_ids)
        else:
            employees = self.env['hr.employee'].search([
                ('active', '=', True),
                ('company_id', '=', self.env.company.id)
            ])
        
        utilization_data = {}
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for employee in employees:
            employee_data = self._calculate_employee_utilization(
                employee, date_from, date_to
            )
            utilization_data[employee.id] = employee_data
        
        # Calculate aggregate metrics
        aggregate_metrics = self._calculate_aggregate_metrics(utilization_data)
        
        return {
            'date_from': date_from,
            'date_to': date_to,
            'employees': utilization_data,
            'aggregate': aggregate_metrics,
            'generated_date': fields.Datetime.now(),
        }
    
    @api.model
    def _calculate_employee_utilization(self, employee, date_from: str, date_to: str) -> Dict:
        """Calculate utilization metrics for a single employee."""
        # Optimización: usar with_context para prefetch
        t = t.with_context(prefetch_fields=False)

        
        # Get timesheet data
        timesheets = self.env['account.analytic.line'].search([
            ('employee_id', '=', employee.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('is_timesheet', '=', True)
        ])
        
        # Calculate working days in period
        working_days = self._get_working_days(employee, date_from, date_to)
        standard_hours_per_day = 8.0  # Configurable
        total_available_hours = working_days * standard_hours_per_day
        
        # Calculate actual hours
        total_hours = sum(timesheets.mapped('unit_amount'))
        billable_hours = sum(timesheets.filtered(
            lambda t: t.project_id and t.project_id.partner_id
        ).mapped('unit_amount'))
        
        # Calculate project distribution
        project_distribution = self._get_project_distribution(timesheets)
        
        # Calculate utilization rates
        utilization_rate = (total_hours / total_available_hours * 100) if total_available_hours > 0 else 0
        billable_rate = (billable_hours / total_hours * 100) if total_hours > 0 else 0
        
        # Calculate overtime
        overtime_hours = max(0, total_hours - total_available_hours)
        overtime_rate = (overtime_hours / total_available_hours * 100) if total_available_hours > 0 else 0
        
        # Get skills and certifications
        skills_data = self._get_employee_skills(employee)
        
        # Calculate productivity metrics
        productivity_metrics = self._calculate_productivity_metrics(employee, timesheets)
        
        return {
            'employee_id': employee.id,
            'employee_name': employee.name,
            'department': employee.department_id.name if employee.department_id else '',
            'job_position': employee.job_id.name if employee.job_id else '',
            
            # Time metrics
            'total_available_hours': total_available_hours,
            'total_hours': total_hours,
            'billable_hours': billable_hours,
            'overtime_hours': overtime_hours,
            'working_days': working_days,
            
            # Utilization rates
            'utilization_rate': utilization_rate,
            'billable_rate': billable_rate,
            'overtime_rate': overtime_rate,
            
            # Project distribution
            'project_distribution': project_distribution,
            
            # Skills and capabilities
            'skills': skills_data,
            
            # Productivity
            'productivity': productivity_metrics,
            
            # Status classification
            'utilization_status': self._get_utilization_status(utilization_rate),
            'availability_status': self._get_availability_status(utilization_rate, overtime_rate),
        }
    
    @api.model
    def _get_working_days(self, employee, date_from: str, date_to: str) -> int:
        """Calculate working days for employee in period."""
        start_date = fields.Date.from_string(date_from)
        end_date = fields.Date.from_string(date_to)
        
        # Get employee's calendar
        calendar = employee.resource_calendar_id or employee.company_id.resource_calendar_id
        
        if calendar:
            # Use calendar to calculate working days
            working_intervals = calendar._work_intervals_batch(
                start_date, end_date, resources=employee.resource_id
            )
            working_days = len(working_intervals[employee.resource_id.id])
        else:
            # Fallback: assume 5 working days per week
            total_days = (end_date - start_date).days + 1
            working_days = total_days * 5 / 7  # Rough estimate
        
        return int(working_days)
    
    @api.model
    def _get_project_distribution(self, timesheets) -> List[Dict]:
        """Get distribution of hours across projects."""
        # Optimización: usar with_context para prefetch
        timesheet = timesheet.with_context(prefe,
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
tch_fields=False)

        project_hours = {}
        total_hours = sum(timesheets.mapped('unit_amount'))
        
        for timesheet in timesheets:
            project_key = timesheet.project_id.id if timesheet.project_id else 'no_project'
            project_name = timesheet.project_id.name if timesheet.project_id else 'No Project'
            
            if project_key not in project_hours:
                project_hours[project_key] = {
                    'project_id': project_key,
                    'project_name': project_name,
                    'hours': 0,
                    'percentage': 0
                }
            
            project_hours[project_key]['hours'] += timesheet.unit_amount
        
        # Calculate percentages
        for project_data in project_hours.values():
            project_data['percentage'] = (
                project_data['hours'] / total_hours * 100
            ) if total_hours > 0 else 0
        
        return sorted(project_hours.values(), key=lambda x: x['hours'], reverse=True)
    
    @api.model
    def _get_employee_skills(self, employee) -> Dict:
        """Get employee skills and certifications."""
        skills_data = {
            'technical_skills': [],
            'certifications': [],
            'experience_years': 0,
            'skill_level': 'junior'
        }
        
        # If hr_skills module is available
        if 'hr.skill' in self.env:
            employee_skills = self.env['hr.employee.skill'].search([
                ('employee_id', '=', employee.id)
            ])
            
            
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for skill in employee_skills:
                skills_data['technical_skills'].append({
                    'name': skill.skill_id.name,
                    'level': skill.level_id.name if skill.level_id else 'Basic',
                    'skill_type': skill.skill_type_id.name if skill.skill_type_id else 'General'
                })
        
        # Calculate experience based on work start date
        if employee.first_contract_date:
            experience_years = (fields.Date.today() - employee.first_contract_date).days / 365.25
            skills_data['experience_years'] = round(experience_years, 1)
            
            # Classify skill level based on experience
            if experience_years < 2:
                skills_data['skill_level'] = 'junior'
            elif experience_years < 5:
                skills_data['skill_level'] = 'mid'
            else:
                skills_data['skill_level'] = 'senior'
        
        return skills_data
    
    @api.model
    def _calculate_productivity_metrics(self, employee, timesheets) -> Dict:
        """Calculate productivity metrics for employee."""
        
        # Calculate average hours per day
        unique_dates = set(timesheets.mapped('date'))
        avg_hours_per_day = (
            sum(timesheets.mapped('unit_amount')) / len(unique_dates)
        ) if unique_dates else 0
        
        # Calculate task completion rate (if tasks are linked)
        completed_tasks = 0
        total_tasks = 0
        
        for timesheet in timesheets:
            if timesheet.task_id:
                total_tasks += 1
                if timesheet.task_id.stage_id.is_closed:
                    completed_tasks += 1
        
        completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        # Calculate cost efficiency
        total_cost = sum(timesheets.mapped('amount'))
        cost_per_hour = abs(total_cost / sum(timesheets.mapped('unit_amount'))) if timesheets else 0
        
        return {
            'avg_hours_per_day': avg_hours_per_day,
            'task_completion_rate': completion_rate,
            'cost_per_hour': cost_per_hour,
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
        }
    
    @api.model
    def _get_utilization_status(self, utilization_rate: float) -> str:
        """Get utilization status classification."""
        if utilization_rate >= 90:
            return 'overutilized'
        elif utilization_rate >= 75:
            return 'optimal'
        elif utilization_rate >= 50:
            return 'underutilized'
        else:
            return 'available'
    
    @api.model
    def _get_availability_status(self, utilization_rate: float, overtime_rate: float) -> str:
        """Get availability status for capacity planning."""
        if overtime_rate > 20:
            return 'overloaded'
        elif utilization_rate >= 85:
            return 'fully_allocated'
        elif utilization_rate >= 70:
            return 'mostly_allocated'
        else:
            return 'available'
    
    @api.model
    def _calculate_aggregate_metrics(self, utilization_data: Dict) -> Dict:
        """Calculate aggregate metrics across all employees."""
        if not utilization_data:
            return {}
        
        employees_data = list(utilization_data.values())
        
        # Calculate averages
        avg_utilization = sum(emp['utilization_rate'] for emp in employees_data) / len(employees_data)
        avg_billable_rate = sum(emp['billable_rate'] for emp in employees_data) / len(employees_data)
        avg_overtime_rate = sum(emp['overtime_rate'] for emp in employees_data) / len(employees_data)
        
        # Calculate totals
        total_available_hours = sum(emp['total_available_hours'] for emp in employees_data)
        total_worked_hours = sum(emp['total_hours'] for emp in employees_data)
        total_billable_hours = sum(emp['billable_hours'] for emp in employees_data)
        
        # Count by status
        status_counts = {}
        for emp in employees_data:
            status = emp['utilization_status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_employees': len(employees_data),
            'avg_utilization_rate': avg_utilization,
            'avg_billable_rate': avg_billable_rate,
            'avg_overtime_rate': avg_overtime_rate,
            'total_available_hours': total_available_hours,
            'total_worked_hours': total_worked_hours,
            'total_billable_hours': total_billable_hours,
            'overall_utilization': (total_worked_hours / total_available_hours * 100) if total_available_hours > 0 else 0,
            'status_distribution': status_counts,
        }
    
    @api.model
    def generate_capacity_forecast(self, weeks_ahead: int = 12) -> Dict:
        """Generate capacity forecast for upcoming weeks."""
        
        # Get all active employees
        employees = self.env['hr.employee'].search([
            ('active', '=', True),
            ('company_id', '=', self.env.company.id)
        ])
        
        forecast_data = {}
        current_date = fields.Date.today()
        
        for week in range(weeks_ahead):
            week_start = current_date + timedelta(weeks=week)
            week_end = week_start + timedelta(days=6)
            week_key = week_start.strftime('%Y-W%U')
            
            # Calculate available capacity for this week
            week_capacity = self._calculate_week_capacity(employees, week_start, week_end)
            
            # Get planned allocations
            planned_allocations = self._get_planned_allocations(employees, week_start, week_end)
            
            # Calculate remaining capacity
            remaining_capacity = week_capacity['total_hours'] - planned_allocations['total_hours']
            
            forecast_data[week_key] = {
                'week_start': fields.Date.to_string(week_start),
                'week_end': fields.Date.to_string(week_end),
                'available_capacity': week_capacity,
                'planned_allocations': planned_allocations,
                'remaining_capacity': remaining_capacity,
                'utilization_forecast': (planned_allocations['total_hours'] / week_capacity['total_hours'] * 100) if week_capacity['total_hours'] > 0 else 0,
                'capacity_status': self._get_capacity_status(remaining_capacity, week_capacity['total_hours'])
            }
        
        return {
            'forecast_weeks': weeks_ahead,
            'generated_date': fields.Datetime.now(),
            'forecast_data': forecast_data,
            'summary': self._calculate_forecast_summary(forecast_data)
        }
    
    @api.model
    def _calculate_week_capacity(self, employees, week_start, week_end) -> Dict:
        """Calculate total capacity for a week."""
        total_hours = 0
        employee_capacities = []
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for employee in employees:
            # Calculate working days in week
            working_days = self._get_working_days(
                employee, 
                fields.Date.to_string(week_start), 
                fields.Date.to_string(week_end)
            )
            
            # Standard hours per day (could be from employee contract)
            hours_per_day = 8.0
            employee_hours = working_days * hours_per_day
            
            total_hours += employee_hours
            employee_capacities.append({
                'employee_id': employee.id,
                'employee_name': employee.name,
                'available_hours': employee_hours,
                'working_days': working_days
            })
        
        return {
            'total_hours': total_hours,
            'employee_count': len(employees),
            'employee_capacities': employee_capacities
        }
    
    @api.model
    def _get_planned_allocations(self, employees, week_start, week_end) -> Dict:
        """Get planned allocations for the week."""
        
        # Get project tasks scheduled for this week
        tasks = self.env['project.task'].search([
            ('user_ids', 'in', [emp.user_id.id for emp in employees if emp.user_id]),
            ('date_deadline', '>=', week_start),
            ('date_deadline', '<=', week_end),
            ('stage_id.is_closed', '=', False)
        ])
        
        total_planned_hours = 0
        allocations = []
        
        for task in tasks:
            planned_hours = task.planned_hours or 8.0  # Default if not set
            total_planned_hours += planned_hours
            
            allocations.append({
                'task_id': task.id,
                'task_name': task.name,
                'project_name': task.project_id.name,
                'planned_hours': planned_hours,
                'assigned_users': [user.name for user in task.user_ids]
            })
        
        return {
            'total_hours': total_planned_hours,
            'task_count': len(tasks),
            'allocations': allocations
        }
    
    @api.model
    def _get_capacity_status(self, remaining_capacity: float, total_capacity: float) -> str:
        """Get capacity status for the week."""
        if total_capacity <= 0:
            return 'no_capacity'
        
        utilization_rate = ((total_capacity - remaining_capacity) / total_capacity) * 100
        
        if utilization_rate >= 95:
            return 'overbooked'
        elif utilization_rate >= 80:
            return 'high_utilization'
        elif utilization_rate >= 60:
            return 'moderate_utilization'
        else:
            return 'low_utilization'
    
    @api.model
    def _calculate_forecast_summary(self, forecast_data: Dict) -> Dict:
        """Calculate summary metrics for the forecast."""
        weeks_data = list(forecast_data.values())
        
        if not weeks_data:
            return {}
        
        avg_utilization = sum(week['utilization_forecast'] for week in weeks_data) / len(weeks_data)
        total_capacity = sum(week['available_capacity']['total_hours'] for week in weeks_data)
        total_planned = sum(week['planned_allocations']['total_hours'] for week in weeks_data)
        
        # Count weeks by status
        status_counts = {}
        for week in weeks_data:
            status = week['capacity_status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'avg_utilization_forecast': avg_utilization,
            'total_capacity_hours': total_capacity,
            'total_planned_hours': total_planned,
            'overall_utilization_forecast': (total_planned / total_capacity * 100) if total_capacity > 0 else 0,
            'capacity_status_distribution': status_counts,
            'weeks_overbooked': status_counts.get('overbooked', 0),
            'weeks_available': status_counts.get('low_utilization', 0) + status_counts.get('moderate_utilization', 0)
        }
    
    @api.model
    def get_resource_recommendations(self, project_id: int = None) -> List[Dict]:
        """Get resource allocation recommendations."""
        recommendations = []
        
        # Get current utilization data
        utilization_data = self.calculate_resource_utilization()
        
        # Analyze for recommendations
        for emp_id, emp_data in utilization_data['employees'].items():
            
            # Overutilized employees
            if emp_data['utilization_status'] == 'overutilized':
                recommendations.append({
                    'type': 'warning',
                    'priority': 'high',
                    'employee_id': emp_id,
                    'employee_name': emp_data['employee_name'],
                    'title': 'Employee Overutilized',
                    'message': f"{emp_data['employee_name']} is at {emp_data['utilization_rate']:.1f}% utilization",
                    'suggestion': 'Consider redistributing workload or hiring additional resources',
                    'utilization_rate': emp_data['utilization_rate']
                })
            
            # Available employees
            elif emp_data['utilization_status'] == 'available':
                recommendations.append({
                    'type': 'info',
                    'priority': 'medium',
                    'employee_id': emp_id,
                    'employee_name': emp_data['employee_name'],
                    'title': 'Available Capacity',
                    'message': f"{emp_data['employee_name']} has available capacity ({emp_data['utilization_rate']:.1f}% utilized)",
                    'suggestion': 'Consider allocating additional tasks or projects',
                    'utilization_rate': emp_data['utilization_rate']
                })
            
            # High overtime
            if emp_data['overtime_rate'] > 15:
                recommendations.append({
                    'type': 'warning',
                    'priority': 'high',
                    'employee_id': emp_id,
                    'employee_name': emp_data['employee_name'],
                    'title': 'High Overtime',
                    'message': f"{emp_data['employee_name']} is working {emp_data['overtime_rate']:.1f}% overtime",
                    'suggestion': 'Review workload distribution and consider additional resources',
                    'overtime_rate': emp_data['overtime_rate']
                })
        
        return sorted(recommendations, key=lambda x: {'high': 3, 'medium': 2, 'low': 1}[x['priority']], reverse=True)