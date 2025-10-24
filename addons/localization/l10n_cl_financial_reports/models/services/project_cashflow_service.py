# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Project Cash Flow Service for Engineering Companies

Specialized service for cash flow analysis in engineering projects with milestones.
Handles milestone-based billing, retention management, and cash flow forecasting.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dateutil.relativedelta import relativedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError
from odoo.tools import float_round, date_utils

_logger = logging.getLogger(__name__)


class ProjectCashFlowService(models.AbstractModel):
    """Service for Project Cash Flow Analysis with Milestones."""
    
    _name = 'project.cashflow.service'
    _inherit = ['base.financial.service']
    _description = 'Project Cash Flow Service'
    
    @api.model
    def calculate_project_cashflow(self, project_id: int, periods: int = 13) -> Dict:
        """
        Calculate comprehensive cash flow analysis for a project.
        
        Args:
            project_id: Project ID
            periods: Number of weeks to forecast (default 13)
            
        Returns:
            Dict: Complete cash flow analysis
        """
        # Optimización: usar with_context para prefetch
        project = project.with_context(prefetch_fields=False)

        project = self.env['project.project'].browse(project_id)
        if not project.exists():
            raise UserError(_("Project not found"))
            
        # Get milestone data
        milestones = self._get_project_milestones(project)
        
        # Calculate historical cash flow
        historical_data = self._get_historical_cashflow(project)
        
        # Generate forecast
        forecast_data = self._generate_cashflow_forecast(project, milestones, periods)
        
        # Calculate key metrics
        metrics = self._calculate_cashflow_metrics(project, historical_data, forecast_data)
        
        return {
            'project_id': project_id,
            'project_name': project.name,
            'currency_id': project.company_id.currency_id.id,
            'milestones': milestones,
            'historical': historical_data,
            'forecast': forecast_data,
            'metrics': metrics,
            'generated_date': fields.Datetime.now(),
        }
    
    @api.model
    def _get_project_milestones(self, project) -> List[Dict]:
        """Get project milestones from sale order lines or tasks."""
        milestones = []
        
        if project.sale_order_id:
            # Get milestones from sale order lines
            for line in project.sale_order_id.order_line:
                if line.product_id.type == 'service':
                    milestone = {
                        'id': line.id,
                        'name': line.name,
                        'amount': line.price_subtotal,
                        'planned_date': self._estimate_milestone_date(project, line),
                        'status': 'planned',
                        'retention_percent': 0.05,  # 5% default retention
                        'type': 'milestone'
                    }
                    milestones.append(milestone)
        
        # Add invoiced milestones
        invoiced_milestones = self._get_invoiced_milestones(project)
        milestones.extend(invoiced_milestones)
        
        return sorted(milestones, key=lambda x: x['planned_date'])
    
    @api.model
    def _get_invoiced_milestones(self, project) -> List[Dict]:
        """Get already invoiced milestones."""
        invoices = self.env['account.move'].search([
            ('project_id', '=', project.id),
            ('move_type', '=', 'out_invoice'),
            ('state', 'in', ['posted', 'paid'])
        ])
        
        milestones = []
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for invoice in invoices:
            milestone = {
                'id': f"inv_{invoice.id}",
                'name': f"Invoice {invoice.name}",
                'amount': invoice.amount_total,
                'planned_date': invoice.invoice_date,
                'actual_date': invoice.invoice_date,
                'status': 'invoiced' if invoice.state == 'posted' else 'paid',
                'retention_percent': 0.05,
                'type': 'invoice',
                'invoice_id': invoice.id
            }
            milestones.append(milestone)
        
        return milestones
    
    @api.model
    def _estimate_milestone_date(self, project, line) -> str:
        """Estimate milestone date based on project timeline."""
        # Optimización: usar with_context para prefetch
        project = project.with_context(prefetch_fields=False)

        if not project.date_start or not project.date_end:
            return fields.Date.today()
            
        # Simple linear distribution based on order
        total_lines = len(project.sale_order_id.order_line)
        line_index = list(project.sale_order_id.order_line).index(line)
        
        project_duration = (project.date_end - project.date_start).days
        milestone_offset = (project_duration / total_lines) * (line_index + 1)
        
        milestone_date = project.date_start + timedelta(days=int(milestone_offset))
        return fields.Date.to_string(milestone_date)
    
    @api.model
    def _get_historical_cashflow(self, project) -> Dict:
        """Get historical cash flow data."""
        # Get payments received
        payments = self.env['account.payment'].search([
            ('partner_id', '=', project.partner_id.id),
            ('state', '=', 'posted'),
            ('payment_type', '=', 'inbound')
        ])
        
        # Get costs (timesheets, expenses, materials)
        costs = self.env['account.analytic.line'].search([
            ('project_id', '=', project.id),
            ('amount', '<', 0)  # Costs are negative
        ])
        
        # Organize by month
        monthly_data = {}
        
        # Process payments (inflows)
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for payment in payments:
            month_key = payment.date.strftime('%Y-%m')
            if month_key not in monthly_data:
                monthly_data[month_key] = {'inflow': 0, 'outflow': 0, 'net': 0}
            monthly_data[month_key]['inflow'] += payment.amount
        
        # Process costs (outflows)
        for cost in costs:
            month_key = cost.date.strftime('%Y-%m')
            if month_key not in monthly_data:
                monthly_data[month_key] = {'inflow': 0, 'outflow': 0, 'net': 0}
            monthly_data[month_key]['outflow'] += abs(cost.amount)
        
        # Calculate net flow
        for month_data in monthly_data.values():
            month_data['net'] = month_data['inflow'] - month_data['outflow']
        
        return monthly_data
    
    @api.model
    def _generate_cashflow_forecast(self, project, milestones, periods) -> Dict:
        """Generate cash flow forecast for next periods."""
        forecast = {}
        current_date = fields.Date.today()
        
        for week in range(periods):
            week_start = current_date + timedelta(weeks=week)
            week_end = week_start + timedelta(days=6)
            week_key = week_start.strftime('%Y-W%U')
            
            forecast[week_key] = {
                'date_start': fields.Date.to_string(week_start),
                'date_end': fields.Date.to_string(week_end),
                'expected_inflow': 0,
                'expected_outflow': 0,
                'net_flow': 0,
                'cumulative': 0,
                'milestones': []
            }
            
            # Check for milestones in this week
            for milestone in milestones:
                milestone_date = fields.Date.from_string(milestone['planned_date'])
                if week_start <= milestone_date <= week_end:
                    # Calculate expected collection (considering retention)
                    retention_amount = milestone['amount'] * milestone['retention_percent']
                    collectible_amount = milestone['amount'] - retention_amount
                    
                    forecast[week_key]['expected_inflow'] += collectible_amount
                    forecast[week_key]['milestones'].append({
                        'name': milestone['name'],
                        'amount': milestone['amount'],
                        'collectible': collectible_amount,
                        'retention': retention_amount
                    })
            
            # Estimate weekly costs based on project burn rate
            weekly_cost = self._estimate_weekly_cost(project)
            forecast[week_key]['expected_outflow'] = weekly_cost
            forecast[week_key]['net_flow'] = (
                forecast[week_key]['expected_inflow'] - 
                forecast[week_key]['expected_outflow']
            )
        
        # Calculate cumulative cash flow
        cumulative = 0
        for week_data in forecast.values():
            cumulative += week_data['net_flow']
            week_data['cumulative'] = cumulative
        
        return forecast
    
    @api.model
    def _estimate_weekly_cost(self, project) -> float:
        """Estimate weekly project cost based on historical data."""
        # Get recent timesheet data
        recent_timesheets = self.env['account.analytic.line'].search([
            ('project_id', '=', project.id),
            ('is_timesheet', '=', True),
            ('date', '>=', fields.Date.today() - timedelta(days=30))
        ])
        
        if not recent_timesheets:
            return 0.0
        
        # Calculate average weekly cost
        total_cost = sum(abs(ts.amount) for ts in recent_timesheets)
        weeks_of_data = 4  # 30 days / 7 days
        
        return total_cost / weeks_of_data if weeks_of_data > 0 else 0.0
    
    @api.model
    def _calculate_cashflow_metrics(self, project, historical, forecast) -> Dict:
        """Calculate key cash flow metrics."""
        # Calculate working capital needs
        total_forecast_outflow = sum(
            week['expected_outflow'] for week in forecast.values()
        )
        total_forecast_inflow = sum(
            week['expected_inflow'] for week in forecast.values()
        )
        
        # Find cash gaps
        cash_gaps = []
        for week_key, week_data in forecast.items():
            if week_data['cumulative'] < 0:
                cash_gaps.append({
                    'week': week_key,
                    'date': week_data['date_start'],
                    'gap_amount': abs(week_data['cumulative'])
                })
        
        # Calculate DSO (Days Sales Outstanding)
        dso = self._calculate_dso(project)
        
        # Calculate retention amounts
        total_retention = sum(
            milestone['amount'] * milestone['retention_percent']
            for milestone in self._get_project_milestones(project)
        )
        
        return {
            'total_forecast_inflow': total_forecast_inflow,
            'total_forecast_outflow': total_forecast_outflow,
            'net_forecast': total_forecast_inflow - total_forecast_outflow,
            'cash_gaps': cash_gaps,
            'max_cash_gap': max([gap['gap_amount'] for gap in cash_gaps], default=0),
            'dso': dso,
            'total_retention': total_retention,
            'working_capital_need': max([abs(week['cumulative']) for week in forecast.values()], default=0)
        }
    
    @api.model
    def _calculate_dso(self, project) -> float:
        """Calculate Days Sales Outstanding for the project."""
        invoices = self.env['account.move'].search([
            ('project_id', '=', project.id),
            ('move_type', '=', 'out_invoice'),
            ('state', '=', 'posted')
        ])
        
        if not invoices:
            return 0.0
        
        total_days = 0
        total_amount = 0
        
        for invoice in invoices:
            if invoice.payment_state == 'paid':
                # Find payment date
                payments = invoice._get_reconciled_payments()
                if payments:
                    payment_date = max(payments.mapped('date'))
                    days_to_pay = (payment_date - invoice.invoice_date).days
                    total_days += days_to_pay * invoice.amount_total
                    total_amount += invoice.amount_total
        
        return total_days / total_amount if total_amount > 0 else 0.0
    
    @api.model
    def generate_waterfall_data(self, project_id: int) -> Dict:
        """Generate data for waterfall chart visualization."""
        cashflow_data = self.calculate_project_cashflow(project_id)
        
        waterfall_items = []
        cumulative = 0
        
        # Starting balance
        waterfall_items.append({
            'label': 'Starting Balance',
            'value': 0,
            'cumulative': 0,
            'type': 'start'
        })
        
        # Add milestone inflows
        for milestone in cashflow_data['milestones']:
            if milestone['status'] in ['invoiced', 'paid']:
                retention = milestone['amount'] * milestone['retention_percent']
                collectible = milestone['amount'] - retention
                
                cumulative += collectible
                waterfall_items.append({
                    'label': milestone['name'],
                    'value': collectible,
                    'cumulative': cumulative,
                    'type': 'inflow',
                    'retention': retention
                })
        
        # Add projected costs
        total_projected_cost = sum(
            week['expected_outflow'] 
            for week in cashflow_data['forecast'].values()
        )
        
        cumulative -= total_projected_cost
        waterfall_items.append({
            'label': 'Projected Costs',
            'value': -total_projected_cost,
            'cumulative': cumulative,
            'type': 'outflow'
        })
        
        # Final balance
        waterfall_items.append({
            'label': 'Projected Balance',
            'value': cumulative,
            'cumulative': cumulative,
            'type': 'end'
        })
        
        return {
            'project_name': cashflow_data['project_name'],
            'currency': self.env['res.currency'].browse(cashflow_data['currency_id']).symbol,
            'items': waterfall_items
        }
    
    @api.model
    def get_cash_alerts(self, project_id: int) -> List[Dict]:
        """Get cash flow alerts for a project."""
        cashflow_data = self.calculate_project_cashflow(project_id)
        alerts = []
        
        # Check for cash gaps
        for gap in cashflow_data['metrics']['cash_gaps']:
            if gap['gap_amount'] > 10000:  # Configurable threshold
                alerts.append({
                    'type': 'warning',
                    'title': 'Cash Gap Alert',
                    'message': f"Projected cash gap of ${gap['gap_amount']:,.2f} on {gap['date']}",
                    'date': gap['date'],
                    'amount': gap['gap_amount']
                })
        
        # Check DSO
        if cashflow_data['metrics']['dso'] > 45:  # More than 45 days
            alerts.append({
                'type': 'info',
                'title': 'High DSO',
                'message': f"Days Sales Outstanding is {cashflow_data['metrics']['dso']:.1f} days",
                'dso': cashflow_data['metrics']['dso']
            })
        
        # Check retention amounts
        if cashflow_data['metrics']['total_retention'] > 50000:
            alerts.append({
                'type': 'info',
                'title': 'High Retention',
                'message': f"Total retention amount: ${cashflow_data['metrics']['total_retention']:,.2f}",
                'amount': cashflow_data['metrics']['total_retention']
            })
        
        return alerts
