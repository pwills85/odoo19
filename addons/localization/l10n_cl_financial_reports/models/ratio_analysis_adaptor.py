# -*- coding: utf-8 -*-
"""
Ratio Analysis Odoo Adaptor
Bridges pure Python service with Odoo ORM
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging
from datetime import datetime, timedelta

# Import pure Python service
try:
    from odoo.addons.l10n_cl_financial_reports.models.services.ratio_analysis_service_pure import RatioAnalysisService
except ImportError:
    from ..services.ratio_analysis_service_pure import RatioAnalysisService

_logger = logging.getLogger(__name__)


class RatioAnalysisAdaptor(models.AbstractModel):
    """Odoo adaptor for ratio analysis service."""

    _name = 'ratio.analysis.adaptor'
    _description = 'Ratio Analysis Service Adaptor'

    def _get_service(self):
        """Get service instance (cached per request)."""
        # Use context to cache service instance per request
        if not hasattr(self.env.context, '_ratio_analysis_service'):
            self.env.context._ratio_analysis_service = RatioAnalysisService()
        return self.env.context._ratio_analysis_service

    @api.model
    def calculate_dupont_analysis(self, company_id, date_from, date_to):
        """
        Perform DuPont analysis using Odoo data.

        Args:
            company_id: Company record
            date_from: Start date
            date_to: End date

        Returns:
            Dictionary with DuPont analysis components
        """
        try:
            # Get financial data from Odoo
            net_income = self._get_net_income(company_id, date_from, date_to)
            revenue = self._get_revenue(company_id, date_from, date_to)
            total_assets = self._get_total_assets(company_id, date_to)
            total_equity = self._get_total_equity(company_id, date_to)

            # Use pure service for calculations
            return self._get_service().calculate_dupont_analysis(
                net_income=net_income,
                revenue=revenue,
                total_assets=total_assets,
                total_equity=total_equity
            )

        except Exception as e:
            _logger.error(f"Error in DuPont analysis: {str(e)}")
            raise UserError(_("Error calculating DuPont analysis: %s") % str(e))

    @api.model
    def calculate_liquidity_ratios(self, company_id, date):
        """Calculate liquidity ratios using Odoo data."""
        try:
            # Get data from Odoo
            current_assets = self._get_current_assets(company_id, date)
            current_liabilities = self._get_current_liabilities(company_id, date)
            cash = self._get_cash_balance(company_id, date)
            marketable_securities = self._get_marketable_securities(company_id, date)
            receivables = self._get_receivables(company_id, date)
            inventory = self._get_inventory(company_id, date)

            # Use pure service
            return self._get_service().calculate_liquidity_ratios(
                current_assets=current_assets,
                current_liabilities=current_liabilities,
                cash=cash,
                marketable_securities=marketable_securities,
                receivables=receivables,
                inventory=inventory
            )

        except Exception as e:
            _logger.error(f"Error calculating liquidity ratios: {str(e)}")
            raise UserError(_("Error calculating liquidity ratios: %s") % str(e))

    @api.model
    def perform_comprehensive_analysis(self, company_id, date_from, date_to):
        """Perform comprehensive financial analysis."""
        try:
            # Collect all financial data
            financial_data = self._collect_financial_data(company_id, date_from, date_to)

            # Use pure service for analysis
            results = self._get_service().perform_comprehensive_analysis(financial_data)

            # Add Odoo-specific metadata
            results['company_id'] = company_id.id
            results['company_name'] = company_id.name
            results['period'] = f"{date_from} to {date_to}"
            results['currency'] = company_id.currency_id.name

            return results

        except Exception as e:
            _logger.error(f"Error in comprehensive analysis: {str(e)}")
            raise UserError(_("Error performing comprehensive analysis: %s") % str(e))

    # ========== Data Extraction Methods ==========

    def _get_net_income(self, company_id, date_from, date_to):
        """Extract net income from account moves."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('parent_state', '=', 'posted')
        ]

        # Get P&L accounts
        pl_accounts = self.env['account.account'].search([
            ('company_id', '=', company_id.id),
            ('account_type', 'in', ['income', 'income_other', 'expense', 'expense_depreciation'])
        ])

        if pl_accounts:
            domain.append(('account_id', 'in', pl_accounts.ids))

        move_lines = self.env['account.move.line'].search(domain)
        return sum(move_lines.mapped('balance'))

    def _get_revenue(self, company_id, date_from, date_to):
        """Extract revenue from account moves."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', 'in', ['income', 'income_other'])
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_total_assets(self, company_id, date):
        """Extract total assets at a specific date."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', 'in', [
                'asset_receivable', 'asset_cash', 'asset_current',
                'asset_non_current', 'asset_prepayments', 'asset_fixed'
            ])
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_total_equity(self, company_id, date):
        """Extract total equity at a specific date."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', '=', 'equity')
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_current_assets(self, company_id, date):
        """Extract current assets."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', 'in', [
                'asset_receivable', 'asset_cash', 'asset_current'
            ])
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_current_liabilities(self, company_id, date):
        """Extract current liabilities."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', 'in', [
                'liability_payable', 'liability_current'
            ])
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_cash_balance(self, company_id, date):
        """Extract cash and cash equivalents."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', '=', 'asset_cash')
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_marketable_securities(self, company_id, date):
        """Extract marketable securities (if tracked)."""
        # This would need custom account configuration
        # For now, return 0
        return 0.0

    def _get_receivables(self, company_id, date):
        """Extract accounts receivable."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', '=', 'asset_receivable')
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_inventory(self, company_id, date):
        """Extract inventory value."""
        # Get from stock valuation if available
        stock_valuation = self.env['stock.valuation.layer'].search([
            ('company_id', '=', company_id.id),
            ('create_date', '<=', date)
        ])

        if stock_valuation:
            return sum(stock_valuation.mapped('value'))
        return 0.0

    def _collect_financial_data(self, company_id, date_from, date_to):
        """Collect all financial data for comprehensive analysis."""
        # Period end date for balance sheet items
        period_end = date_to

        # Calculate COGS
        cogs_domain = [
            ('company_id', '=', company_id.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', '=', 'expense_direct_cost')
        ]
        cogs_lines = self.env['account.move.line'].search(cogs_domain)
        cogs = abs(sum(cogs_lines.mapped('balance')))

        # Calculate EBIT (Operating Profit)
        revenue = self._get_revenue(company_id, date_from, date_to)
        operating_expenses = self._get_operating_expenses(company_id, date_from, date_to)
        ebit = revenue - cogs - operating_expenses

        # Calculate Gross Profit
        gross_profit = revenue - cogs

        # Get interest expense
        interest_expense = self._get_interest_expense(company_id, date_from, date_to)

        # Calculate total debt
        total_debt = self._get_total_debt(company_id, period_end)

        # Calculate averages for efficiency ratios
        avg_receivables = self._get_average_balance(
            company_id, date_from, date_to, 'asset_receivable'
        )
        avg_inventory = self._get_average_inventory(company_id, date_from, date_to)
        avg_payables = self._get_average_balance(
            company_id, date_from, date_to, 'liability_payable'
        )

        return {
            'revenue': revenue,
            'net_income': self._get_net_income(company_id, date_from, date_to),
            'total_assets': self._get_total_assets(company_id, period_end),
            'total_equity': self._get_total_equity(company_id, period_end),
            'current_assets': self._get_current_assets(company_id, period_end),
            'current_liabilities': self._get_current_liabilities(company_id, period_end),
            'cash': self._get_cash_balance(company_id, period_end),
            'marketable_securities': self._get_marketable_securities(company_id, period_end),
            'receivables': self._get_receivables(company_id, period_end),
            'inventory': self._get_inventory(company_id, period_end),
            'cogs': cogs,
            'ebit': ebit,
            'gross_profit': gross_profit,
            'operating_profit': ebit,
            'total_debt': total_debt,
            'interest_expense': interest_expense,
            'average_receivables': avg_receivables,
            'average_inventory': avg_inventory,
            'average_payables': avg_payables,
            'days_in_period': (fields.Date.from_string(date_to) -
                              fields.Date.from_string(date_from)).days
        }

    def _get_operating_expenses(self, company_id, date_from, date_to):
        """Get operating expenses excluding COGS and interest."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', 'in', ['expense', 'expense_depreciation'])
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_interest_expense(self, company_id, date_from, date_to):
        """Get interest expense."""
        # This would need specific account configuration
        # Look for accounts with 'interest' in name as fallback
        interest_accounts = self.env['account.account'].search([
            ('company_id', '=', company_id.id),
            ('name', 'ilike', 'interest'),
            ('account_type', '=', 'expense')
        ])

        if interest_accounts:
            domain = [
                ('company_id', '=', company_id.id),
                ('date', '>=', date_from),
                ('date', '<=', date_to),
                ('parent_state', '=', 'posted'),
                ('account_id', 'in', interest_accounts.ids)
            ]
            move_lines = self.env['account.move.line'].search(domain)
            return abs(sum(move_lines.mapped('balance')))
        return 0.0

    def _get_total_debt(self, company_id, date):
        """Get total debt (current + non-current liabilities)."""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', 'in', [
                'liability_payable', 'liability_current', 'liability_non_current'
            ])
        ]

        move_lines = self.env['account.move.line'].search(domain)
        return abs(sum(move_lines.mapped('balance')))

    def _get_average_balance(self, company_id, date_from, date_to, account_type):
        """Calculate average balance for an account type over a period."""
        # Get beginning balance
        begin_domain = [
            ('company_id', '=', company_id.id),
            ('date', '<', date_from),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', '=', account_type)
        ]
        begin_lines = self.env['account.move.line'].search(begin_domain)
        begin_balance = abs(sum(begin_lines.mapped('balance')))

        # Get ending balance
        end_domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date_to),
            ('parent_state', '=', 'posted'),
            ('account_id.account_type', '=', account_type)
        ]
        end_lines = self.env['account.move.line'].search(end_domain)
        end_balance = abs(sum(end_lines.mapped('balance')))

        return (begin_balance + end_balance) / 2

    def _get_average_inventory(self, company_id, date_from, date_to):
        """Calculate average inventory over a period."""
        # Try stock valuation first
        begin_valuation = self.env['stock.valuation.layer'].search([
            ('company_id', '=', company_id.id),
            ('create_date', '<', date_from)
        ])
        begin_inventory = sum(begin_valuation.mapped('value')) if begin_valuation else 0

        end_valuation = self.env['stock.valuation.layer'].search([
            ('company_id', '=', company_id.id),
            ('create_date', '<=', date_to)
        ])
        end_inventory = sum(end_valuation.mapped('value')) if end_valuation else 0

        if begin_inventory or end_inventory:
            return (begin_inventory + end_inventory) / 2

        # Fallback to account balance
        return self._get_average_balance(company_id, date_from, date_to, 'asset_current')
