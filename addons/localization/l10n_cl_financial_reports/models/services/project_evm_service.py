# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Project Earned Value Management (EVM) Service

Implements standard PMI EVM calculations for project profitability analysis:
- Planned Value (PV)
- Earned Value (EV) 
- Actual Cost (AC)
- Cost Performance Index (CPI)
- Schedule Performance Index (SPI)
- Estimate at Completion (EAC)
- Variance at Completion (VAC)

Compatible with Odoo 18 and OCA guidelines.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from odoo import api, fields, models, _
from odoo.exceptions import UserError, ValidationError
from odoo.tools import float_round, float_compare

_logger = logging.getLogger(__name__)


class ProjectEVMService(models.AbstractModel):
    """
    Service for Earned Value Management calculations.
    
    This service provides enterprise-grade EVM analytics for engineering projects,
    following PMI standards and integrated with Odoo 18 project management.
    """
    
    _name = 'project.evm.service'
    _inherit = ['base.financial.service', 'batch.operation.mixin', 'query.optimization.mixin', 'cache.optimization.mixin']
    _description = 'Project EVM Service'
    
    # ==========================================
    # CORE EVM CALCULATIONS
    # ==========================================
    
    @api.model
    def calculate_project_evm(self, project_id: int, date_to: Optional[str] = None) -> Dict:
        """
        Calculate complete EVM metrics for a project.
        
        Args:
            project_id (int): Project ID
            date_to (str, optional): Cut-off date (YYYY-MM-DD)
            
        Returns:
            Dict: Complete EVM metrics
            
        Raises:
            UserError: If project not found or invalid data
        """
        # Optimización: usar with_context para prefetch
        project = project.with_context(prefetch_fields=False)

        try:
            project = self.env['project.project'].browse(project_id)
            if not project.exists():
                raise UserError(_("Project with ID %s not found") % project_id)
                
            date_to = date_to or fields.Date.today()
            
            # Get base values
            pv = self._calculate_planned_value(project, date_to)
            ev = self._calculate_earned_value(project, date_to)
            ac = self._calculate_actual_cost(project, date_to)
            bac = self._get_budget_at_completion(project)
            
            # Calculate performance indices
            cpi = self._calculate_cpi(ev, ac)
            spi = self._calculate_spi(ev, pv)
            
            # Calculate forecasts
            eac = self._calculate_eac(bac, cpi, ac)
            etc = eac - ac  # Estimate to Complete
            vac = bac - eac  # Variance at Completion
            
            # Calculate variances
            cv = ev - ac  # Cost Variance
            sv = ev - pv  # Schedule Variance
            
            # Calculate percentage complete
            percent_complete = (ev / bac * 100) if bac > 0 else 0
            
            # Performance status
            cost_status = self._get_performance_status(cpi)
            schedule_status = self._get_performance_status(spi)
            
            return {
                'project_id': project_id,
                'project_name': project.name,
                'date_to': date_to,
                'currency_id': project.company_id.currency_id.id,
                
                # Base Values
                'planned_value': pv,
                'earned_value': ev,
                'actual_cost': ac,
                'budget_at_completion': bac,
                
                # Performance Indices
                'cost_performance_index': cpi,
                'schedule_performance_index': spi,
                
                # Forecasts
                'estimate_at_completion': eac,
                'estimate_to_complete': etc,
                'variance_at_completion': vac,
                
                # Variances
                'cost_variance': cv,
                'schedule_variance': sv,
                
                # Status
                'percent_complete': percent_complete,
                'cost_status': cost_status,
                'schedule_status': schedule_status,
                
                # Health indicators
                'is_over_budget': cv < 0,
                'is_behind_schedule': sv < 0,
                'health_score': self._calculate_health_score(cpi, spi),
            }
            
        except Exception as e:
            _logger.error("Error calculating EVM for project %s: %s", project_id, str(e))
            raise UserError(_("Error calculating EVM: %s") % str(e))
    
    @api.model
    def _calculate_planned_value(self, project, date_to: str) -> float:
        """
        Calculate Planned Value (PV) - budgeted cost of work scheduled.
        
        Based on project timeline and budget distribution.
        """
        if not project.date_start or not project.date_end:
            return 0.0
            
        total_budget = self._get_budget_at_completion(project)
        if total_budget <= 0:
            return 0.0
            
        # Calculate progress based on time
        project_start = fields.Date.from_string(project.date_start)
        project_end = fields.Date.from_string(project.date_end)
        current_date = fields.Date.from_string(date_to)
        
        if current_date <= project_start:
            return 0.0
        elif current_date >= project_end:
            return total_budget
        else:
            # Linear distribution (can be enhanced with S-curve)
            total_days = (project_end - project_start).days
            elapsed_days = (current_date - project_start).days
            progress_ratio = elapsed_days / total_days if total_days > 0 else 0
            
            return float_round(total_budget * progress_ratio, precision_digits=2)
    
    @api.model
    def _calculate_earned_value(self, project, date_to: str) -> float:
        """
        Calculate Earned Value (EV) - budgeted cost of work performed.
        
        Based on actual task completion and milestones achieved.
        """
        total_budget = self._get_budget_at_completion(project)
        if total_budget <= 0:
            return 0.0
            
        # Method 1: Based on task completion
        tasks = project.task_ids.filtered(lambda t: not t.date_deadline or t.date_deadline <= date_to)
        if not tasks:
            return 0.0
            
        total_planned_hours = sum(tasks.mapped('planned_hours'))
        if total_planned_hours <= 0:
            return 0.0
            
        # Calculate weighted completion
        earned_hours = 0.0
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for task in tasks:
            if task.planned_hours > 0:
                task_completion = min(task.progress / 100.0, 1.0) if task.progress else 0.0
                earned_hours += task.planned_hours * task_completion
                
        completion_ratio = earned_hours / total_planned_hours
        return float_round(total_budget * completion_ratio, precision_digits=2)
    
    @api.model
    def _calculate_actual_cost(self, project, date_to: str) -> float:
        """
        Calculate Actual Cost (AC) - actual cost of work performed.
        
        Based on timesheets, expenses, and material costs.
        """
        domain = [
            ('project_id', '=', project.id),
            ('date', '<=', date_to),
        ]
        
        # Timesheet costs
        timesheet_lines = self.env['account.analytic.line'].search(domain + [
            ('is_timesheet', '=', True)
        ])
        timesheet_cost = sum(timesheet_lines.mapped('amount'))
        
        # Expense costs (if hr_expense module is installed)
        expense_cost = 0.0
        if 'hr.expense' in self.env:
            expense_lines = self.env['account.analytic.line'].search(domain + [
                ('is_timesheet', '=', False),
                ('amount', '<', 0)  # Expenses are negative
            ])
            expense_cost = abs(sum(expense_lines.mapped('amount')))
        
        # Material costs from purchase orders
        material_cost = self._get_material_costs(project, date_to)
        
        total_cost = abs(timesheet_cost) + expense_cost + material_cost
        return float_round(total_cost, precision_digits=2)
    
    @api.model
    def _get_budget_at_completion(self, project) -> float:
        """Get total project budget (BAC)."""
        # Optimización: usar with_context para prefetch
        project = project.with_context(prefetch_fields=False)

        # Try to get from sale order first
        if project.sale_order_id:
            return project.sale_order_id.amount_total
            
        # Fallback to project budget or planned hours * rate
        if hasattr(project, 'budget_amount') and project.budget_amount:
            return project.budget_amount
            
        # Calculate from planned hours and standard rate
        total_planned_hours = sum(project.task_ids.mapped('planned_hours'))
        if total_planned_hours > 0:
            # Use company's standard hourly rate or default
            standard_rate = project.company_id.standard_hourly_rate or 50.0
            return total_planned_hours * standard_rate
            
        return 0.0
    
    @api.model
    def _get_material_costs(self, project, date_to: str) -> float:
        """Calculate material costs from purchase orders."""
        if not hasattr(self.env, 'purchase.order'):
            return 0.0
            
        # Find POs linked to project
        po_lines = self.env['purchase.order.line'].search([
            ('account_analytic_id', '=', project.analytic_account_id.id),
            ('order_id.date_order', '<=', date_to),
            ('order_id.state', 'in', ['purchase', 'done'])
        ])
        
        return sum(po_lines.mapped('price_subtotal'))
    
    # ==========================================
    # PERFORMANCE CALCULATIONS
    # ==========================================
    
    @api.model
    def _calculate_cpi(self, earned_value: float, actual_cost: float) -> float:
        """Calculate Cost Performance Index (CPI = EV / AC)."""
        if actual_cost <= 0:
            return 1.0
        return float_round(earned_value / actual_cost, precision_digits=3)
    
    @api.model
    def _calculate_spi(self, earned_value: float, planned_value: float) -> float:
        """Calculate Schedule Performance Index (SPI = EV / PV)."""
        if planned_value <= 0:
            return 1.0
        return float_round(earned_value / planned_value, precision_digits=3)
    
    @api.model
    def _calculate_eac(self, bac: float, cpi: float, actual_cost: float) -> float:
        """
        Calculate Estimate at Completion (EAC).
        
        Uses typical EAC formula: EAC = AC + (BAC - EV) / CPI
        """
        if cpi <= 0:
            return bac  # Fallback to original budget
            
        return float_round(bac / cpi, precision_digits=2)
    
    @api.model
    def _get_performance_status(self, index: float) -> str:
        """Get performance status based on index value."""
        if index >= 1.1:
            return 'excellent'
        elif index >= 1.0:
            return 'good'
        elif index >= 0.9:
            return 'warning'
        else:
            return 'critical'
    
    @api.model
    def _calculate_health_score(self, cpi: float, spi: float) -> float:
        """
        Calculate overall project health score (0-100).
        
        Weighted combination of CPI and SPI.
        """
        # Weight: 60% cost, 40% schedule
        cost_weight = 0.6
        schedule_weight = 0.4
        
        # Normalize indices to 0-100 scale
        cost_score = min(cpi * 100, 100)
        schedule_score = min(spi * 100, 100)
        
        health_score = (cost_score * cost_weight) + (schedule_score * schedule_weight)
        return float_round(health_score, precision_digits=1)
    
    # ==========================================
    # S-CURVE DATA GENERATION
    # ==========================================
    
    @api.model
    def generate_s_curve_data(self, project_id: int, periods: int = 12) -> Dict:
        """
        Generate S-curve data for project visualization.
        
        Args:
            project_id (int): Project ID
            periods (int): Number of periods to generate
            
        Returns:
            Dict: S-curve data with dates and values
        """
        project = self.env['project.project'].browse(project_id)
        if not project.exists():
            raise UserError(_("Project not found"))
            
        if not project.date_start or not project.date_end:
            return {'dates': [], 'planned': [], 'earned': [], 'actual': []}
            
        # Generate date range
        start_date = fields.Date.from_string(project.date_start)
        end_date = fields.Date.from_string(project.date_end)
        
        dates = []
        planned_values = []
        earned_values = []
        actual_costs = []
        
        # Calculate interval
        total_days = (end_date - start_date).days
        interval_days = max(total_days // periods, 1)
        
        current_date = start_date
        while current_date <= end_date:
            date_str = fields.Date.to_string(current_date)
            dates.append(date_str)
            
            # Calculate values for this date
            pv = self._calculate_planned_value(project, date_str)
            ev = self._calculate_earned_value(project, date_str)
            ac = self._calculate_actual_cost(project, date_str)
            
            planned_values.append(pv)
            earned_values.append(ev)
            actual_costs.append(ac)
            
            current_date += timedelta(days=interval_days)
        
        return {
            'dates': dates,
            'planned': planned_values,
            'earned': earned_values,
            'actual': actual_costs,
            'project_name': project.name,
            'currency': project.company_id.currency_id.symbol,
        }
    
    # ==========================================
    # BATCH CALCULATIONS
    # ==========================================
    
    @api.model
    def calculate_portfolio_evm(self, project_ids: List[int], date_to: Optional[str] = None) -> Dict:
        """
        Calculate EVM metrics for multiple projects (portfolio view).
        
        Args:
            project_ids (List[int]): List of project IDs
            date_to (str, optional): Cut-off date
            
        Returns:
            Dict: Portfolio EVM summary
        """
        if not project_ids:
            return {}
            
        date_to = date_to or fields.Date.today()
        portfolio_data = []
        
        # Calculate totals
        total_pv = total_ev = total_ac = total_bac = 0.0
        
        for project_id in project_ids:
            try:
                project_evm = self.calculate_project_evm(project_id, date_to)
                portfolio_data.append(project_evm)
                
                total_pv += project_evm['planned_value']
                total_ev += project_evm['earned_value']
                total_ac += project_evm['actual_cost']
                total_bac += project_evm['budget_at_completion']
                
            except Exception as e:
                _logger.warning("Failed to calculate EVM for project %s: %s", project_id, str(e))
                continue
        
        # Calculate portfolio indices
        portfolio_cpi = self._calculate_cpi(total_ev, total_ac)
        portfolio_spi = self._calculate_spi(total_ev, total_pv)
        
        return {
            'date_to': date_to,
            'project_count': len(portfolio_data),
            'projects': portfolio_data,
            
            # Portfolio totals
            'total_planned_value': total_pv,
            'total_earned_value': total_ev,
            'total_actual_cost': total_ac,
            'total_budget': total_bac,
            
            # Portfolio performance
            'portfolio_cpi': portfolio_cpi,
            'portfolio_spi': portfolio_spi,
            'portfolio_health_score': self._calculate_health_score(portfolio_cpi, portfolio_spi),
            
            # Summary stats
            'projects_over_budget': len([p for p in portfolio_data if p['is_over_budget']]),
            'projects_behind_schedule': len([p for p in portfolio_data if p['is_behind_schedule']]),
        }
