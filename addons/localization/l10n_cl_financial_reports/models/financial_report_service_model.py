# -*- coding: utf-8 -*-
# Copyright 2024 ACSONE SA/NV
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class FinancialReportService(models.Model):
    """
    Service layer for financial report calculations using native Odoo 18 APIs.
    This service provides comprehensive financial analysis capabilities including
    balance sheet, profit & loss, cash flow, and ratio analysis.
    """
    _inherit = ['company.security.mixin']
    _name = 'account.financial.report.service'
    _description = 'Financial Report Service'
    _order = 'create_date desc'

    # Core fields
    name = fields.Char(string='Report Name', required=True)
    company_id = fields.Many2one(
        'res.company', 
        string='Company', 
        required=True, 
        default=lambda self: self.env.company
    )
    date_from = fields.Date(string='Date From', required=True)
    date_to = fields.Date(string='Date To', required=True)
    report_type = fields.Selection([
        ('balance_sheet', 'Balance Sheet'),
        ('profit_loss', 'Profit & Loss'),
        ('cash_flow', 'Cash Flow'),
        ('trial_balance', 'Trial Balance'),
        ('general_ledger', 'General Ledger'),
        ('aged_receivables', 'Aged Receivables'),
        ('aged_payables', 'Aged Payables'),
    ], string='Report Type', required=True)
    
    # Configuration
    show_zero_balance = fields.Boolean(string='Show Zero Balance', default=False)
    show_hierarchy = fields.Boolean(string='Show Account Hierarchy', default=True)
    currency_id = fields.Many2one(
        'res.currency', 
        string='Currency', 
        default=lambda self: self.env.company.currency_id
    )
    
    # Results storage
    report_data = fields.Json(string='Report Data')
    summary_data = fields.Json(string='Summary Data')
    
    # Status
    state = fields.Selection([
        ('draft', 'Draft'),
        ('computed', 'Computed'),
        ('error', 'Error'),
    ], string='State', default='draft')
    
    error_message = fields.Text(string='Error Message')

    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        """Validate date range."""
        for record in self.with_context(prefetch_fields=False):
            if record.date_from > record.date_to:
                raise ValidationError(_('Date From must be before Date To'))

    def compute_report(self):
        """Main method to compute financial reports."""
        self.ensure_one()
        try:
            self.state = 'draft'
            self.error_message = False
            
            # Dispatch to specific computation method
            method_name = f'_compute_{self.report_type}'
            if hasattr(self, method_name):
                result = getattr(self, method_name)()
                self.report_data = result.get('data', {})
                self.summary_data = result.get('summary', {})
                self.state = 'computed'
                _logger.info(f"Financial report {self.report_type} computed successfully for {self.name}")
            else:
                raise ValidationError(_('Report type %s is not implemented') % self.report_type)
                
        except Exception as e:
            self.state = 'error'
            self.error_message = str(e)
            _logger.error(f"Error computing financial report: {str(e)}")
            raise

    def _compute_balance_sheet(self):
        """Compute Balance Sheet using native Odoo 18 account.report APIs."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        # Get account data using native APIs
        domain = [
            ('company_id', '=', self.company_id.id),
            ('date', '<=', self.date_to),
        ]
        
        # Assets
        assets = self._get_account_balances(['asset_receivable', 'asset_cash', 'asset_current', 'asset_non_current', 'asset_prepayments', 'asset_fixed'])
        
        # Liabilities
        liabilities = self._get_account_balances(['liability_payable', 'liability_credit_card', 'liability_current', 'liability_non_current'])
        
        # Equity
        equity = self._get_account_balances(['equity', 'equity_unaffected'])
        
        # Calculate totals
        total_assets = sum(assets.values())
        total_liabilities = sum(liabilities.values())
        total_equity = sum(equity.values())
        
        return {
            'data': {
                'assets': assets,
                'liabilities': liabilities,
                'equity': equity,
                'currency_symbol': self.currency_id.symbol,
                'company_name': self.company_id.name,
                'date_to': self.date_to.strftime('%Y-%m-%d'),
            },
            'summary': {
                'total_assets': total_assets,
                'total_liabilities': total_liabilities,
                'total_equity': total_equity,
                'balance_check': abs(total_assets - (total_liabilities + total_equity)) < 0.01,
            }
        }

    def _compute_profit_loss(self):
        """Compute Profit & Loss using native Odoo 18 APIs."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        # Income
        income = self._get_account_balances(['income', 'income_other'], date_range=True)
        
        # Expenses
        expenses = self._get_account_balances(['expense', 'expense_depreciation', 'expense_direct_cost'], date_range=True)
        
        # Calculate totals
        total_income = sum(income.values())
        total_expenses = sum(expenses.values())
        net_profit = total_income - total_expenses
        
        return {
            'data': {
                'income': income,
                'expenses': expenses,
                'currency_symbol': self.currency_id.symbol,
                'company_name': self.company_id.name,
                'date_from': self.date_from.strftime('%Y-%m-%d'),
                'date_to': self.date_to.strftime('%Y-%m-%d'),
            },
            'summary': {
                'total_income': total_income,
                'total_expenses': total_expenses,
                'net_profit': net_profit,
                'profit_margin': (net_profit / total_income * 100) if total_income else 0,
            }
        }

    def _compute_cash_flow(self):
        """Compute Cash Flow Statement using native Odoo 18 APIs."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        # Operating activities
        operating_cash = self._get_cash_flow_operating()
        
        # Investing activities
        investing_cash = self._get_cash_flow_investing()
        
        # Financing activities
        financing_cash = self._get_cash_flow_financing()
        
        # Net cash flow
        net_cash_flow = operating_cash + investing_cash + financing_cash
        
        return {
            'data': {
                'operating_activities': operating_cash,
                'investing_activities': investing_cash,
                'financing_activities': financing_cash,
                'currency_symbol': self.currency_id.symbol,
                'company_name': self.company_id.name,
                'date_from': self.date_from.strftime('%Y-%m-%d'),
                'date_to': self.date_to.strftime('%Y-%m-%d'),
            },
            'summary': {
                'net_cash_flow': net_cash_flow,
                'operating_cash_flow': operating_cash,
                'investing_cash_flow': investing_cash,
                'financing_cash_flow': financing_cash,
            }
        }

    def _compute_trial_balance(self):
        """Compute Trial Balance using native Odoo 18 APIs."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        accounts_data = {}
        
        # Get all accounts with movements
        accounts = self.env['account.account'].search([
        
        # TODO: Refactorizar para usar browse en batch fuera del loop
    ('company_id', '=', self.company_id.id),
            ('deprecated', '=', False),
        ])
        
        for account in accounts:
            balance = self._get_account_balance_single(account.id)
            if balance != 0 or self.show_zero_balance:
                accounts_data[account.code] = {
                    'name': account.name,
                    'code': account.code,
                    'account_type': account.account_type,
                    'balance': balance,
                    'debit': max(balance, 0),
                    'credit': max(-balance, 0),
                }
        
        total_debit = sum(acc['debit'] for acc in accounts_data.values())
        total_credit = sum(acc['credit'] for acc in accounts_data.values())
        
        return {
            'data': {
                'accounts': accounts_data,
                'currency_symbol': self.currency_id.symbol,
                'company_name': self.company_id.name,
                'date_to': self.date_to.strftime('%Y-%m-%d'),
            },
            'summary': {
                'total_debit': total_debit,
                'total_credit': total_credit,
                'balance_check': abs(total_debit - total_credit) < 0.01,
                'accounts_count': len(accounts_data),
            }
        }

    def _get_account_balances(self, account_types, date_range=False):
        """Get account balances by account types using native Odoo 18 APIs."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        domain = [
            ('account_id.account_type', 'in', account_types),
            ('company_id', '=', self.company_id.id),
            ('parent_state', '=', 'posted'),
        ]
        
        if date_range:
            domain.extend([
                ('date', '>=', self.date_from),
                ('date', '<=', self.date_to),
            ])
        else:
            domain.append(('date', '<=', self.date_to))
        
        # Use native Odoo _read_group for performance
        result = self.env['account.move.line']._read_group(
            domain,
            ['account_id'],
            ['balance:sum'])
        
        balances = {}
        for account_id, balance in result:
            account = self.env['account.account'].browse(account_id)
            balances[f"{account.code} - {account.name}"] = balance or 0.0
        
        return balances

    def _get_account_balance_single(self, account_id):
        """Get balance for a single account."""
        domain = [
            ('account_id', '=', account_id),
            ('company_id', '=', self.company_id.id),
            ('parent_state', '=', 'posted'),
            ('date', '<=', self.date_to),
        ]
        
        result = self.env['account.move.line']._read_group(
            domain,
            [],
            ['balance:sum'])
        
        return result[0][0] if result else 0.0

    def _get_cash_flow_operating(self):
        """Calculate operating cash flow using indirect method."""
        # This is a simplified implementation
        # In practice, you would need more sophisticated logic
        income_types = ['income', 'income_other']
        expense_types = ['expense', 'expense_depreciation', 'expense_direct_cost']
        
        income = sum(self._get_account_balances(income_types, date_range=True).values())
        expenses = sum(self._get_account_balances(expense_types, date_range=True).values())
        
        return income - expenses

    def _get_cash_flow_investing(self):
        """Calculate investing cash flow."""
        # Simplified implementation for asset purchases/sales
        asset_types = ['asset_fixed']
        return -sum(self._get_account_balances(asset_types, date_range=True).values())

    def _get_cash_flow_financing(self):
        """Calculate financing cash flow."""
        # Simplified implementation for debt and equity changes
        liability_types = ['liability_non_current']
        equity_types = ['equity']
        
        debt_changes = sum(self._get_account_balances(liability_types, date_range=True).values())
        equity_changes = sum(self._get_account_balances(equity_types, date_range=True).values())
        
        return debt_changes + equity_changes

    def export_to_excel(self):
        """Export report data to Excel format."""
        # This would implement Excel export functionality
        # For now, return a placeholder
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Export'),
                'message': _('Excel export functionality will be implemented'),
                'type': 'info',
            }
        }

    def export_to_pdf(self):
        """Export report data to PDF format."""
        # This would implement PDF export functionality
        return {
            'type': 'ir.actions.report',
            'report_name': 'l10n_cl_financial_reports.financial_report_pdf',
            'report_type': 'qweb-pdf',
            'data': {'report_data': self.report_data},
            'context': self.env.context,
        }

    @api.model
    def create_quick_report(self, report_type, date_from=None, date_to=None, company_id=None):
        """Create and compute a quick financial report."""
        if not date_to:
            date_to = fields.Date.today()
        if not date_from:
            date_from = fields.Date.today().replace(month=1, day=1)
        if not company_id:
            company_id = self.env.company.id
            
        report = self.create({
            'name': f'{report_type.replace("_", " ").title()} - {date_to}',
            'report_type': report_type,
            'date_from': date_from,
            'date_to': date_to,
            'company_id': company_id,
        })
        
        report.compute_report()
        return report

    def get_comparative_analysis(self, previous_period_months=12):
        """Get comparative analysis with previous period."""
        # Calculate previous period dates
        from dateutil.relativedelta import relativedelta
        prev_date_to = self.date_from - relativedelta(days=1)
        prev_date_from = prev_date_to - relativedelta(months=previous_period_months)
        
        # Create previous period report
        prev_report = self.create({
            'name': f'{self.name} - Previous Period',
            'report_type': self.report_type,
            'date_from': prev_date_from,
            'date_to': prev_date_to,
            'company_id': self.company_id.id,
        })
        prev_report.compute_report()
        
        # Calculate variances
        current_summary = self.summary_data or {}
        previous_summary = prev_report.summary_data or {}
        
        variances = {}
        for key in current_summary:
            if key in previous_summary:
                current_val = current_summary[key]
                previous_val = previous_summary[key]
                if isinstance(current_val, (int, float)) and isinstance(previous_val, (int, float)):
                    variance = current_val - previous_val
                    variance_pct = (variance / previous_val * 100) if previous_val != 0 else 0
                    variances[key] = {
                        'current': current_val,
                        'previous': previous_val,
                        'variance': variance,
                        'variance_pct': variance_pct,
                    }
        
        return {
            'current_period': self,
            'previous_period': prev_report,
            'variances': variances,
        }
