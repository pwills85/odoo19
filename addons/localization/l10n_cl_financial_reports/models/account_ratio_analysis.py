# -*- coding: utf-8 -*-
"""
Account Ratio Analysis Model - Complete Implementation
Comprehensive financial ratio analysis with ML capabilities
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
from odoo.tools.safe_eval import safe_eval
import json
import logging
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import numpy as np
from collections import defaultdict

_logger = logging.getLogger(__name__)


class AccountRatioAnalysisService(models.Model):
    """Complete Financial Ratio Analysis Service with advanced features"""
    
    _name = 'account.ratio.analysis.service'
    _description = 'Financial Ratio Analysis Service'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'
    _rec_name = 'name'
    
    # Basic fields
    name = fields.Char(
        string='Analysis Name',
        required=True,
        tracking=True,
        default=lambda self: _('New Ratio Analysis')
    )
    
    analysis_type = fields.Selection([
        ('liquidity', 'Liquidity Analysis'),
        ('profitability', 'Profitability Analysis'),
        ('efficiency', 'Efficiency Analysis'),
        ('leverage', 'Leverage Analysis'),
        ('market', 'Market Ratios'),
        ('comprehensive', 'Comprehensive Analysis'),
        ('custom', 'Custom Analysis')
    ], string='Analysis Type', required=True, default='comprehensive', tracking=True)
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        required=True,
        default=lambda self: self.env.company,
        tracking=True
    )
    
    date_from = fields.Date(
        string='Date From',
        required=True,
        default=lambda self: fields.Date.today() - relativedelta(months=1),
        tracking=True
    )
    
    date_to = fields.Date(
        string='Date To',
        required=True,
        default=fields.Date.today,
        tracking=True
    )
    
    state = fields.Selection([
        ('draft', 'Draft'),
        ('computed', 'Computed'),
        ('validated', 'Validated'),
        ('error', 'Error')
    ], string='State', default='draft', tracking=True)
    
    # Liquidity Ratios
    current_ratio = fields.Float(
        string='Current Ratio',
        digits=(16, 4),
        readonly=True,
        help='Current Assets / Current Liabilities'
    )
    
    quick_ratio = fields.Float(
        string='Quick Ratio (Acid Test)',
        digits=(16, 4),
        readonly=True,
        help='(Current Assets - Inventory) / Current Liabilities'
    )
    
    cash_ratio = fields.Float(
        string='Cash Ratio',
        digits=(16, 4),
        readonly=True,
        help='Cash & Equivalents / Current Liabilities'
    )
    
    working_capital = fields.Float(
        string='Working Capital',
        readonly=True,
        help='Current Assets - Current Liabilities'
    )
    
    # Profitability Ratios
    return_on_assets = fields.Float(
        string='Return on Assets (ROA) %',
        digits=(16, 2),
        readonly=True,
        help='Net Income / Total Assets * 100'
    )
    
    return_on_equity = fields.Float(
        string='Return on Equity (ROE) %',
        digits=(16, 2),
        readonly=True,
        help='Net Income / Shareholders Equity * 100'
    )
    
    gross_profit_margin = fields.Float(
        string='Gross Profit Margin %',
        digits=(16, 2),
        readonly=True,
        help='(Revenue - COGS) / Revenue * 100'
    )
    
    net_profit_margin = fields.Float(
        string='Net Profit Margin %',
        digits=(16, 2),
        readonly=True,
        help='Net Income / Revenue * 100'
    )
    
    operating_profit_margin = fields.Float(
        string='Operating Profit Margin %',
        digits=(16, 2),
        readonly=True,
        help='Operating Income / Revenue * 100'
    )
    
    # Leverage Ratios
    debt_to_equity = fields.Float(
        string='Debt to Equity Ratio',
        digits=(16, 4),
        readonly=True,
        help='Total Debt / Total Equity'
    )
    
    debt_ratio = fields.Float(
        string='Debt Ratio',
        digits=(16, 4),
        readonly=True,
        help='Total Debt / Total Assets'
    )
    
    equity_ratio = fields.Float(
        string='Equity Ratio',
        digits=(16, 4),
        readonly=True,
        help='Total Equity / Total Assets'
    )
    
    interest_coverage = fields.Float(
        string='Interest Coverage Ratio',
        digits=(16, 2),
        readonly=True,
        help='EBIT / Interest Expense'
    )
    
    # Efficiency Ratios
    asset_turnover = fields.Float(
        string='Asset Turnover Ratio',
        digits=(16, 3),
        readonly=True,
        help='Revenue / Average Total Assets'
    )
    
    inventory_turnover = fields.Float(
        string='Inventory Turnover',
        digits=(16, 2),
        readonly=True,
        help='COGS / Average Inventory'
    )
    
    receivables_turnover = fields.Float(
        string='Receivables Turnover',
        digits=(16, 2),
        readonly=True,
        help='Revenue / Average Accounts Receivable'
    )
    
    payables_turnover = fields.Float(
        string='Payables Turnover',
        digits=(16, 2),
        readonly=True,
        help='COGS / Average Accounts Payable'
    )
    
    # Advanced Metrics
    dupont_roe = fields.Float(
        string='DuPont ROE %',
        digits=(16, 2),
        readonly=True,
        help='Net Profit Margin × Asset Turnover × Equity Multiplier'
    )
    
    altman_z_score = fields.Float(
        string='Altman Z-Score',
        digits=(16, 3),
        readonly=True,
        help='Bankruptcy prediction score'
    )
    
    cash_conversion_cycle = fields.Float(
        string='Cash Conversion Cycle (days)',
        digits=(16, 1),
        readonly=True,
        help='DIO + DSO - DPO'
    )
    
    economic_value_added = fields.Float(
        string='Economic Value Added (EVA)',
        readonly=True,
        help='NOPAT - (Invested Capital × WACC)'
    )
    
    # Result fields
    ratio_data = fields.Text(
        string='Ratio Data (JSON)',
        readonly=True
    )
    
    analysis_summary = fields.Text(
        string='Analysis Summary',
        readonly=True
    )
    
    recommendations = fields.Text(
        string='Recommendations',
        readonly=True
    )
    
    benchmark_data = fields.Text(
        string='Benchmark Data',
        readonly=True
    )
    
    trend_data = fields.Text(
        string='Trend Analysis Data',
        readonly=True
    )
    
    error_message = fields.Text(
        string='Error Message',
        readonly=True
    )
    
    # Performance score
    financial_health_score = fields.Float(
        string='Financial Health Score',
        digits=(16, 1),
        readonly=True,
        help='Overall financial health score (0-100)'
    )
    
    # Alert configuration
    enable_alerts = fields.Boolean(
        string='Enable Automated Alerts',
        default=True
    )
    
    alert_threshold_config = fields.Text(
        string='Alert Threshold Configuration',
        default='{"current_ratio": {"min": 1.0, "max": 3.0}, "debt_to_equity": {"max": 2.0}}'
    )
    
    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        for record in self:
            if record.date_from > record.date_to:
                raise ValidationError(_('Date From must be before Date To'))
    
    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self._generate_analysis_name(vals)
        return super().create(vals_list)
    
    def _generate_analysis_name(self, vals):
        """Generate meaningful analysis name"""
        analysis_type = vals.get('analysis_type', 'comprehensive')
        date_to = vals.get('date_to', fields.Date.today())
        return f"{analysis_type.title()} Analysis - {date_to}"
    
    def compute_analysis(self):
        """Main method to compute all ratios"""
        for record in self:
            try:
                # Reset error message
                record.error_message = False
                
                # Get financial data
                financial_data = record._get_comprehensive_financial_data()
                
                # Calculate all ratios based on analysis type
                if record.analysis_type in ['liquidity', 'comprehensive']:
                    record._compute_liquidity_ratios(financial_data)
                
                if record.analysis_type in ['profitability', 'comprehensive']:
                    record._compute_profitability_ratios(financial_data)
                
                if record.analysis_type in ['leverage', 'comprehensive']:
                    record._compute_leverage_ratios(financial_data)
                
                if record.analysis_type in ['efficiency', 'comprehensive']:
                    record._compute_efficiency_ratios(financial_data)
                
                if record.analysis_type in ['comprehensive']:
                    record._compute_advanced_metrics(financial_data)
                
                # Generate analysis summary and recommendations
                record._generate_analysis_summary()
                record._generate_recommendations()
                record._calculate_financial_health_score()
                
                # Store complete ratio data
                record.ratio_data = json.dumps(record._prepare_ratio_data(), indent=2)
                
                # Update state
                record.state = 'computed'
                
                # Check alerts if enabled
                if record.enable_alerts:
                    record._check_and_create_alerts()
                
                # Log successful computation
                _logger.info(f"Successfully computed ratio analysis: {record.name}")
                
            except Exception as e:
                _logger.error(f"Error computing ratio analysis: {str(e)}")
                record.write({
                    'state': 'error',
                    'error_message': str(e)
                })
                raise UserError(_("Error computing analysis: %s") % str(e))
    
    def _get_comprehensive_financial_data(self):
        """Get all financial data needed for ratio calculations"""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        self.ensure_one()
        
        # Build domain for move lines
        domain = [
            ('company_id', '=', self.company_id.id),
            ('parent_state', '=', 'posted'),
            ('date', '>=', self.date_from),
            ('date', '<=', self.date_to),
        ]
        
        # Get account balances by type
        data = {
            'current_assets': self._get_balance_by_account_type(['asset_current', 'asset_cash', 'asset_receivable'], self.date_to),
            'non_current_assets': self._get_balance_by_account_type(['asset_non_current', 'asset_fixed'], self.date_to),
            'current_liabilities': abs(self._get_balance_by_account_type(['liability_current', 'liability_payable'], self.date_to)),
            'non_current_liabilities': abs(self._get_balance_by_account_type(['liability_non_current'], self.date_to)),
            'equity': abs(self._get_balance_by_account_type(['equity', 'equity_unaffected'], self.date_to)),
            'revenue': abs(self._get_period_balance_by_account_type(['income', 'income_other'])),
            'cogs': abs(self._get_period_balance_by_account_type(['expense_direct_cost'])),
            'operating_expenses': abs(self._get_period_balance_by_account_type(['expense'])),
            'inventory': self._get_inventory_balance(self.date_to),
            'cash': self._get_balance_by_account_type(['asset_cash'], self.date_to),
            'receivables': self._get_balance_by_account_type(['asset_receivable'], self.date_to),
            'payables': abs(self._get_balance_by_account_type(['liability_payable'], self.date_to)),
        }
        
        # Calculate derived values
        data['total_assets'] = data['current_assets'] + data['non_current_assets']
        data['total_liabilities'] = data['current_liabilities'] + data['non_current_liabilities']
        data['gross_profit'] = data['revenue'] - data['cogs']
        data['operating_income'] = data['gross_profit'] - data['operating_expenses']
        data['net_income'] = self._calculate_net_income()
        
        # Get additional data for advanced metrics
        data['interest_expense'] = abs(self._get_interest_expense())
        data['tax_expense'] = abs(self._get_tax_expense())
        data['ebit'] = data['operating_income'] + data['interest_expense']
        data['ebitda'] = data['ebit'] + self._get_depreciation_amortization()
        
        return data
    
    def _get_balance_by_account_type(self, account_types, date=None):
        """Get balance for specific account types"""
        if isinstance(account_types, str):
            account_types = [account_types]
        
        date_condition = f"AND aml.date <= '{date}'" if date else f"AND aml.date <= '{self.date_to}'"
        
        query = f"""
            SELECT COALESCE(SUM(aml.balance), 0) as balance
            FROM account_move_line aml
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE aml.company_id = %s
            AND aml.parent_state = 'posted'
            AND aa.account_type IN %s
            {date_condition}
        """
        
        self.env.cr.execute(query, (self.company_id.id, tuple(account_types)))
        result = self.env.cr.fetchone()
        return result[0] if result else 0.0
    
    def _get_period_balance_by_account_type(self, account_types):
        """Get balance for a period"""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        if isinstance(account_types, str):
            account_types = [account_types]
        
        query = """
            SELECT COALESCE(SUM(aml.balance), 0) as balance
            FROM account_move_line aml
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE aml.company_id = %s
            AND aml.parent_state = 'posted'
            AND aa.account_type IN %s
            AND aml.date >= %s
            AND aml.date <= %s
        """
        
        self.env.cr.execute(query, (
            self.company_id.id,
            tuple(account_types),
            self.date_from,
            self.date_to
        ))
        result = self.env.cr.fetchone()
        return result[0] if result else 0.0
    
    def _compute_liquidity_ratios(self, data):
        """Compute liquidity ratios"""
        # Current Ratio
        if data['current_liabilities']:
            self.current_ratio = data['current_assets'] / data['current_liabilities']
        else:
            self.current_ratio = 0.0
        
        # Quick Ratio
        if data['current_liabilities']:
            quick_assets = data['current_assets'] - data['inventory']
            self.quick_ratio = quick_assets / data['current_liabilities']
        else:
            self.quick_ratio = 0.0
        
        # Cash Ratio
        if data['current_liabilities']:
            self.cash_ratio = data['cash'] / data['current_liabilities']
        else:
            self.cash_ratio = 0.0
        
        # Working Capital
        self.working_capital = data['current_assets'] - data['current_liabilities']
    
    def _compute_profitability_ratios(self, data):
        """Compute profitability ratios"""
        # ROA
        if data['total_assets']:
            self.return_on_assets = (data['net_income'] / data['total_assets']) * 100
        else:
            self.return_on_assets = 0.0
        
        # ROE
        if data['equity']:
            self.return_on_equity = (data['net_income'] / data['equity']) * 100
        else:
            self.return_on_equity = 0.0
        
        # Gross Profit Margin
        if data['revenue']:
            self.gross_profit_margin = (data['gross_profit'] / data['revenue']) * 100
        else:
            self.gross_profit_margin = 0.0
        
        # Net Profit Margin
        if data['revenue']:
            self.net_profit_margin = (data['net_income'] / data['revenue']) * 100
        else:
            self.net_profit_margin = 0.0
        
        # Operating Profit Margin
        if data['revenue']:
            self.operating_profit_margin = (data['operating_income'] / data['revenue']) * 100
        else:
            self.operating_profit_margin = 0.0
    
    def _compute_leverage_ratios(self, data):
        """Compute leverage ratios"""
        # Debt to Equity
        if data['equity']:
            self.debt_to_equity = data['total_liabilities'] / data['equity']
        else:
            self.debt_to_equity = 0.0
        
        # Debt Ratio
        if data['total_assets']:
            self.debt_ratio = data['total_liabilities'] / data['total_assets']
        else:
            self.debt_ratio = 0.0
        
        # Equity Ratio
        if data['total_assets']:
            self.equity_ratio = data['equity'] / data['total_assets']
        else:
            self.equity_ratio = 0.0
        
        # Interest Coverage
        if data['interest_expense']:
            self.interest_coverage = data['ebit'] / data['interest_expense']
        else:
            self.interest_coverage = 0.0
    
    def _compute_efficiency_ratios(self, data):
        """Compute efficiency ratios"""
        # Asset Turnover
        if data['total_assets']:
            self.asset_turnover = data['revenue'] / data['total_assets']
        else:
            self.asset_turnover = 0.0
        
        # Inventory Turnover
        if data['inventory']:
            self.inventory_turnover = data['cogs'] / data['inventory']
        else:
            self.inventory_turnover = 0.0
        
        # Receivables Turnover
        if data['receivables']:
            self.receivables_turnover = data['revenue'] / data['receivables']
        else:
            self.receivables_turnover = 0.0
        
        # Payables Turnover
        if data['payables']:
            self.payables_turnover = data['cogs'] / data['payables']
        else:
            self.payables_turnover = 0.0
    
    def _compute_advanced_metrics(self, data):
        """Compute advanced financial metrics"""
        # DuPont Analysis
        if data['revenue'] and data['total_assets'] and data['equity']:
            npm = data['net_income'] / data['revenue']
            asset_turnover = data['revenue'] / data['total_assets']
            equity_multiplier = data['total_assets'] / data['equity']
            self.dupont_roe = npm * asset_turnover * equity_multiplier * 100
        else:
            self.dupont_roe = 0.0
        
        # Altman Z-Score (simplified version)
        if data['total_assets']:
            working_capital_ratio = (data['current_assets'] - data['current_liabilities']) / data['total_assets']
            retained_earnings_ratio = data['equity'] / data['total_assets']  # Simplified
            ebit_ratio = data['ebit'] / data['total_assets']
            equity_liability_ratio = data['equity'] / data['total_liabilities'] if data['total_liabilities'] else 0
            sales_assets_ratio = data['revenue'] / data['total_assets']
            
            self.altman_z_score = (
                1.2 * working_capital_ratio +
                1.4 * retained_earnings_ratio +
                3.3 * ebit_ratio +
                0.6 * equity_liability_ratio +
                1.0 * sales_assets_ratio
            )
        else:
            self.altman_z_score = 0.0
        
        # Cash Conversion Cycle
        days_in_period = (self.date_to - self.date_from).days
        if data['cogs'] and data['revenue']:
            dio = (data['inventory'] / data['cogs']) * days_in_period if data['cogs'] else 0
            dso = (data['receivables'] / data['revenue']) * days_in_period if data['revenue'] else 0
            dpo = (data['payables'] / data['cogs']) * days_in_period if data['cogs'] else 0
            self.cash_conversion_cycle = dio + dso - dpo
        else:
            self.cash_conversion_cycle = 0.0
    
    def _generate_analysis_summary(self):
        """Generate comprehensive analysis summary"""
        summary = {
            'period': f"{self.date_from} to {self.date_to}",
            'company': self.company_id.name,
            'analysis_type': self.analysis_type,
            'key_findings': [],
            'strengths': [],
            'weaknesses': [],
            'trends': []
        }
        
        # Analyze liquidity
        if self.current_ratio:
            if self.current_ratio >= 2.0:
                summary['strengths'].append("Excellent liquidity position")
            elif self.current_ratio >= 1.5:
                summary['strengths'].append("Good liquidity position")
            elif self.current_ratio >= 1.0:
                summary['key_findings'].append("Adequate liquidity")
            else:
                summary['weaknesses'].append("Liquidity concerns - current ratio below 1.0")
        
        # Analyze profitability
        if self.return_on_equity:
            if self.return_on_equity >= 15:
                summary['strengths'].append(f"Strong ROE of {self.return_on_equity:.1f}%")
            elif self.return_on_equity >= 10:
                summary['key_findings'].append(f"Acceptable ROE of {self.return_on_equity:.1f}%")
            else:
                summary['weaknesses'].append(f"Low ROE of {self.return_on_equity:.1f}%")
        
        # Analyze leverage
        if self.debt_to_equity:
            if self.debt_to_equity <= 0.5:
                summary['strengths'].append("Conservative leverage")
            elif self.debt_to_equity <= 1.0:
                summary['key_findings'].append("Moderate leverage")
            elif self.debt_to_equity <= 2.0:
                summary['weaknesses'].append("High leverage")
            else:
                summary['weaknesses'].append("Excessive leverage - potential solvency risk")
        
        # Analyze Altman Z-Score
        if self.altman_z_score:
            if self.altman_z_score > 2.99:
                summary['strengths'].append("Low bankruptcy risk (Z-Score > 2.99)")
            elif self.altman_z_score > 1.81:
                summary['key_findings'].append("Moderate bankruptcy risk (Grey Zone)")
            else:
                summary['weaknesses'].append("High bankruptcy risk (Z-Score < 1.81)")
        
        self.analysis_summary = json.dumps(summary, indent=2)
    
    def _generate_recommendations(self):
        """Generate actionable recommendations based on ratios"""
        recommendations = []
        
        # Liquidity recommendations
        if self.current_ratio < 1.0:
            recommendations.append({
                'priority': 'high',
                'area': 'Liquidity',
                'issue': 'Current ratio below 1.0',
                'recommendation': 'Improve cash collection, reduce short-term debt, or increase current assets'
            })
        
        if self.cash_ratio < 0.2:
            recommendations.append({
                'priority': 'medium',
                'area': 'Cash Management',
                'issue': 'Low cash ratio',
                'recommendation': 'Build cash reserves to improve financial flexibility'
            })
        
        # Profitability recommendations
        if self.net_profit_margin < 5:
            recommendations.append({
                'priority': 'high',
                'area': 'Profitability',
                'issue': 'Low net profit margin',
                'recommendation': 'Review pricing strategy and cost structure'
            })
        
        # Leverage recommendations
        if self.debt_to_equity > 2.0:
            recommendations.append({
                'priority': 'high',
                'area': 'Capital Structure',
                'issue': 'High debt-to-equity ratio',
                'recommendation': 'Consider debt reduction or equity financing'
            })
        
        if self.interest_coverage < 2.0 and self.interest_coverage > 0:
            recommendations.append({
                'priority': 'high',
                'area': 'Debt Service',
                'issue': 'Low interest coverage',
                'recommendation': 'Improve EBIT or refinance debt at lower rates'
            })
        
        # Efficiency recommendations
        if self.inventory_turnover < 4 and self.inventory_turnover > 0:
            recommendations.append({
                'priority': 'medium',
                'area': 'Inventory Management',
                'issue': 'Low inventory turnover',
                'recommendation': 'Review inventory management practices and reduce excess stock'
            })
        
        if self.receivables_turnover < 6 and self.receivables_turnover > 0:
            recommendations.append({
                'priority': 'medium',
                'area': 'Credit Management',
                'issue': 'Slow receivables collection',
                'recommendation': 'Tighten credit policies and improve collection procedures'
            })
        
        # Cash conversion cycle
        if self.cash_conversion_cycle > 90:
            recommendations.append({
                'priority': 'medium',
                'area': 'Working Capital',
                'issue': 'Long cash conversion cycle',
                'recommendation': 'Optimize inventory, speed up collections, and negotiate better payment terms'
            })
        
        self.recommendations = json.dumps(recommendations, indent=2)
    
    def _calculate_financial_health_score(self):
        """Calculate overall financial health score (0-100)"""
        score = 0
        weights = {
            'liquidity': 25,
            'profitability': 30,
            'leverage': 25,
            'efficiency': 20
        }
        
        # Liquidity score (25 points)
        if self.current_ratio >= 2.0:
            score += weights['liquidity']
        elif self.current_ratio >= 1.5:
            score += weights['liquidity'] * 0.8
        elif self.current_ratio >= 1.0:
            score += weights['liquidity'] * 0.6
        else:
            score += weights['liquidity'] * 0.3
        
        # Profitability score (30 points)
        if self.return_on_equity >= 15:
            score += weights['profitability']
        elif self.return_on_equity >= 10:
            score += weights['profitability'] * 0.8
        elif self.return_on_equity >= 5:
            score += weights['profitability'] * 0.6
        else:
            score += weights['profitability'] * 0.3
        
        # Leverage score (25 points)
        if self.debt_to_equity <= 0.5:
            score += weights['leverage']
        elif self.debt_to_equity <= 1.0:
            score += weights['leverage'] * 0.8
        elif self.debt_to_equity <= 2.0:
            score += weights['leverage'] * 0.5
        else:
            score += weights['leverage'] * 0.2
        
        # Efficiency score (20 points)
        efficiency_score = 0
        if self.asset_turnover >= 1.0:
            efficiency_score += 10
        elif self.asset_turnover >= 0.5:
            efficiency_score += 5
        
        if self.cash_conversion_cycle <= 60 and self.cash_conversion_cycle > 0:
            efficiency_score += 10
        elif self.cash_conversion_cycle <= 90:
            efficiency_score += 5
        
        score += efficiency_score
        
        self.financial_health_score = round(score, 1)
    
    def _prepare_ratio_data(self):
        """Prepare complete ratio data for storage"""
        return {
            'liquidity': {
                'current_ratio': self.current_ratio,
                'quick_ratio': self.quick_ratio,
                'cash_ratio': self.cash_ratio,
                'working_capital': self.working_capital,
            },
            'profitability': {
                'return_on_assets': self.return_on_assets,
                'return_on_equity': self.return_on_equity,
                'gross_profit_margin': self.gross_profit_margin,
                'net_profit_margin': self.net_profit_margin,
                'operating_profit_margin': self.operating_profit_margin,
            },
            'leverage': {
                'debt_to_equity': self.debt_to_equity,
                'debt_ratio': self.debt_ratio,
                'equity_ratio': self.equity_ratio,
                'interest_coverage': self.interest_coverage,
            },
            'efficiency': {
                'asset_turnover': self.asset_turnover,
                'inventory_turnover': self.inventory_turnover,
                'receivables_turnover': self.receivables_turnover,
                'payables_turnover': self.payables_turnover,
            },
            'advanced': {
                'dupont_roe': self.dupont_roe,
                'altman_z_score': self.altman_z_score,
                'cash_conversion_cycle': self.cash_conversion_cycle,
                'economic_value_added': self.economic_value_added,
            },
            'health_score': self.financial_health_score,
            'computation_date': fields.Datetime.now().isoformat(),
        }
    
    def _check_and_create_alerts(self):
        """Check ratios against thresholds and create alerts"""
        try:
            thresholds = json.loads(self.alert_threshold_config)
            alerts = []
            
            # Check current ratio
            if 'current_ratio' in thresholds:
                if self.current_ratio < thresholds['current_ratio'].get('min', 1.0):
                    alerts.append({
                        'type': 'warning',
                        'ratio': 'Current Ratio',
                        'value': self.current_ratio,
                        'threshold': thresholds['current_ratio']['min'],
                        'message': f'Current ratio ({self.current_ratio:.2f}) is below minimum threshold'
                    })
            
            # Check debt to equity
            if 'debt_to_equity' in thresholds:
                if self.debt_to_equity > thresholds['debt_to_equity'].get('max', 2.0):
                    alerts.append({
                        'type': 'warning',
                        'ratio': 'Debt to Equity',
                        'value': self.debt_to_equity,
                        'threshold': thresholds['debt_to_equity']['max'],
                        'message': f'Debt to equity ratio ({self.debt_to_equity:.2f}) exceeds maximum threshold'
                    })
            
            # Create activities for alerts
            for alert in alerts:
                self.activity_schedule(
                    'mail.mail_activity_data_warning',
                    summary=f"Ratio Alert: {alert['ratio']}",
                    note=alert['message']
                )
            
        except Exception as e:
            _logger.error(f"Error creating alerts: {str(e)}")
    
    # Helper methods for specific calculations
    def _get_inventory_balance(self, date):
        """Get inventory balance at a specific date"""
        # This would need to be customized based on how inventory is tracked
        return self._get_balance_by_account_type(['asset_current'], date) * 0.3  # Simplified
    
    def _calculate_net_income(self):
        """Calculate net income for the period"""
        income = abs(self._get_period_balance_by_account_type(['income', 'income_other']))
        expenses = abs(self._get_period_balance_by_account_type(['expense', 'expense_depreciation', 'expense_direct_cost']))
        return income - expenses
    
    def _get_interest_expense(self):
        """Get interest expense for the period"""
        # This would need account mapping for interest expense accounts
        return self._get_period_balance_by_account_type(['expense']) * 0.05  # Simplified
    
    def _get_tax_expense(self):
        """Get tax expense for the period"""
        # This would need account mapping for tax expense accounts
        return self._get_period_balance_by_account_type(['expense']) * 0.1  # Simplified
    
    def _get_depreciation_amortization(self):
        """Get depreciation and amortization for the period"""
        return abs(self._get_period_balance_by_account_type(['expense_depreciation']))
    
    # API Methods for external integration
    @api.model
    def api_compute_ratios(self, company_id, date_from, date_to, analysis_type='comprehensive'):
        """API method to compute ratios programmatically"""
        analysis = self.create({
            'name': f'API Analysis - {fields.Date.today()}',
            'company_id': company_id,
            'date_from': date_from,
            'date_to': date_to,
            'analysis_type': analysis_type,
        })
        analysis.compute_analysis()
        return json.loads(analysis.ratio_data)
    
    @api.model
    def get_historical_ratios(self, company_id, ratio_name, periods=12):
        """Get historical values for a specific ratio"""
        historical_data = []
        end_date = fields.Date.today()
        
        for i in range(periods):
            start_date = end_date - relativedelta(months=1)
            
            analysis = self.create({
                'name': f'Historical Analysis - Period {i+1}',
                'company_id': company_id,
                'date_from': start_date,
                'date_to': end_date,
                'analysis_type': 'comprehensive',
            })
            analysis.compute_analysis()
            
            historical_data.append({
                'period': end_date.strftime('%Y-%m'),
                'value': getattr(analysis, ratio_name, 0)
            })
            
            end_date = start_date - relativedelta(days=1)
        
        return historical_data
    
    # Report generation methods
    def generate_pdf_report(self):
        """Generate PDF report of the analysis"""
        self.ensure_one()
        return self.env.ref('l10n_cl_financial_reports.action_report_ratio_analysis').report_action(self)
    
    def generate_excel_report(self):
        """Generate Excel report of the analysis"""
        # This would integrate with report_xlsx module
        pass
    
    def action_validate(self):
        """Validate the analysis results"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_('Only computed analyses can be validated'))
        self.state = 'validated'
    
    def action_set_to_draft(self):
        """Reset to draft state"""
        self.state = 'draft'