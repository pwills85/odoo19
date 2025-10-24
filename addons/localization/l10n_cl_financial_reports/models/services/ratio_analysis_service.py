# -*- coding: utf-8 -*-
"""
Financial Ratio Analysis Service
Provides advanced financial ratio calculations and analysis
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class RatioAnalysisService(models.AbstractModel):
    """Service for advanced financial ratio analysis"""
    _name = 'ratio.analysis.service'
    _description = 'Financial Ratio Analysis Service'
    
    @api.model
    def calculate_dupont_analysis(self, company_id, date_from, date_to):
        """
        Perform DuPont analysis (ROE decomposition)
        ROE = Net Profit Margin × Asset Turnover × Equity Multiplier
        
        :param company_id: Company record
        :param date_from: Start date
        :param date_to: End date
        :return: Dictionary with DuPont analysis components
        """
        try:
            # Get financial data
            net_income = self._get_net_income(company_id, date_from, date_to)
            revenue = self._get_revenue(company_id, date_from, date_to)
            total_assets = self._get_total_assets(company_id, date_to)
            total_equity = self._get_total_equity(company_id, date_to)
            
            # Calculate components
            net_profit_margin = (net_income / revenue * 100) if revenue else 0
            asset_turnover = revenue / total_assets if total_assets else 0
            equity_multiplier = total_assets / total_equity if total_equity else 0
            roe = net_profit_margin * asset_turnover * equity_multiplier / 100
            
            return {
                'net_income': net_income,
                'revenue': revenue,
                'total_assets': total_assets,
                'total_equity': total_equity,
                'net_profit_margin': round(net_profit_margin, 2),
                'asset_turnover': round(asset_turnover, 2),
                'equity_multiplier': round(equity_multiplier, 2),
                'roe': round(roe, 2),
                'analysis_date': fields.Date.today(),
            }
            
        except Exception as e:
            _logger.error(f"Error in DuPont analysis: {e}")
            raise UserError(_("Error calculating DuPont analysis: %s") % str(e))
    
    @api.model
    def calculate_altman_z_score(self, company_id, date):
        """
        Calculate Altman Z-Score for bankruptcy prediction
        Z = 1.2A + 1.4B + 3.3C + 0.6D + 1.0E
        
        :param company_id: Company record
        :param date: Analysis date
        :return: Dictionary with Z-Score components
        """
        try:
            # Get financial data
            working_capital = self._get_working_capital(company_id, date)
            total_assets = self._get_total_assets(company_id, date)
            retained_earnings = self._get_retained_earnings(company_id, date)
            ebit = self._get_ebit(company_id, date)
            market_value_equity = self._get_market_value_equity(company_id, date)
            total_liabilities = self._get_total_liabilities(company_id, date)
            sales = self._get_annual_sales(company_id, date)
            
            # Calculate ratios
            a = working_capital / total_assets if total_assets else 0
            b = retained_earnings / total_assets if total_assets else 0
            c = ebit / total_assets if total_assets else 0
            d = market_value_equity / total_liabilities if total_liabilities else 0
            e = sales / total_assets if total_assets else 0
            
            # Calculate Z-Score
            z_score = 1.2 * a + 1.4 * b + 3.3 * c + 0.6 * d + 1.0 * e
            
            # Interpret score
            if z_score > 2.99:
                interpretation = 'Safe Zone'
                risk_level = 'low'
            elif z_score > 1.81:
                interpretation = 'Grey Zone'
                risk_level = 'medium'
            else:
                interpretation = 'Distress Zone'
                risk_level = 'high'
            
            return {
                'z_score': round(z_score, 2),
                'working_capital_ratio': round(a, 3),
                'retained_earnings_ratio': round(b, 3),
                'ebit_ratio': round(c, 3),
                'equity_liability_ratio': round(d, 3),
                'sales_assets_ratio': round(e, 3),
                'interpretation': interpretation,
                'risk_level': risk_level,
                'analysis_date': date,
            }
            
        except Exception as e:
            _logger.error(f"Error calculating Altman Z-Score: {e}")
            raise UserError(_("Error calculating Altman Z-Score: %s") % str(e))
    
    @api.model
    def calculate_cash_conversion_cycle(self, company_id, date_from, date_to):
        """
        Calculate Cash Conversion Cycle
        CCC = DIO + DSO - DPO
        
        :param company_id: Company record
        :param date_from: Start date
        :param date_to: End date
        :return: Dictionary with CCC components
        """
        try:
            # Days Inventory Outstanding
            avg_inventory = self._get_average_inventory(company_id, date_from, date_to)
            cogs = self._get_cogs(company_id, date_from, date_to)
            days = (date_to - date_from).days
            dio = (avg_inventory / cogs * days) if cogs else 0
            
            # Days Sales Outstanding
            avg_receivables = self._get_average_receivables(company_id, date_from, date_to)
            revenue = self._get_revenue(company_id, date_from, date_to)
            dso = (avg_receivables / revenue * days) if revenue else 0
            
            # Days Payables Outstanding
            avg_payables = self._get_average_payables(company_id, date_from, date_to)
            dpo = (avg_payables / cogs * days) if cogs else 0
            
            # Cash Conversion Cycle
            ccc = dio + dso - dpo
            
            return {
                'dio': round(dio, 1),
                'dso': round(dso, 1),
                'dpo': round(dpo, 1),
                'ccc': round(ccc, 1),
                'avg_inventory': avg_inventory,
                'avg_receivables': avg_receivables,
                'avg_payables': avg_payables,
                'period_days': days,
            }
            
        except Exception as e:
            _logger.error(f"Error calculating Cash Conversion Cycle: {e}")
            raise UserError(_("Error calculating Cash Conversion Cycle: %s") % str(e))
    
    @api.model
    def calculate_economic_value_added(self, company_id, date_from, date_to):
        """
        Calculate Economic Value Added (EVA)
        EVA = NOPAT - (Invested Capital × WACC)
        
        :param company_id: Company record
        :param date_from: Start date
        :param date_to: End date
        :return: Dictionary with EVA calculation
        """
        try:
            # Get NOPAT (Net Operating Profit After Tax)
            ebit = self._get_ebit_period(company_id, date_from, date_to)
            tax_rate = self._get_effective_tax_rate(company_id, date_from, date_to)
            nopat = ebit * (1 - tax_rate)
            
            # Get Invested Capital
            invested_capital = self._get_invested_capital(company_id, date_to)
            
            # Get WACC (simplified - would need more data in practice)
            wacc = self._estimate_wacc(company_id, date_to)
            
            # Calculate EVA
            capital_charge = invested_capital * wacc
            eva = nopat - capital_charge
            
            return {
                'eva': round(eva, 2),
                'nopat': round(nopat, 2),
                'invested_capital': round(invested_capital, 2),
                'wacc': round(wacc * 100, 2),  # As percentage
                'capital_charge': round(capital_charge, 2),
                'value_created': eva > 0,
            }
            
        except Exception as e:
            _logger.error(f"Error calculating EVA: {e}")
            raise UserError(_("Error calculating EVA: %s") % str(e))
    
    # Helper methods for data retrieval
    @api.model
    def _get_net_income(self, company_id, date_from, date_to):
        """Get net income for period"""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('account_id.account_type', 'in', ['income', 'expense']),
            ('parent_state', '=', 'posted'),
        ]
        
        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['balance'],
            []
        )
        
        return -read_group_res[0]['balance'] if read_group_res and read_group_res[0]['balance'] else 0
    
    @api.model
    def _get_revenue(self, company_id, date_from, date_to):
        """Get total revenue for period"""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('account_id.account_type', '=', 'income'),
            ('parent_state', '=', 'posted'),
        ]
        
        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['balance'],
            []
        )
        
        return -read_group_res[0]['balance'] if read_group_res and read_group_res[0]['balance'] else 0
    
    @api.model
    def _get_total_assets(self, company_id, date):
        """Get total assets at date"""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('account_id.account_type', 'in', ['asset_receivable', 'asset_cash', 
                               'asset_current', 'asset_non_current', 'asset_fixed']),
            ('parent_state', '=', 'posted'),
        ]
        
        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['balance'],
            []
        )
        
        return read_group_res[0]['balance'] if read_group_res and read_group_res[0]['balance'] else 0
    
    @api.model
    def _get_total_equity(self, company_id, date):
        """Get total equity at date"""
        domain = [
            ('company_id', '=', company_id.id),
            ('date', '<=', date),
            ('account_id.account_type', '=', 'equity'),
            ('parent_state', '=', 'posted'),
        ]
        
        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['balance'],
            []
        )
        
        return -read_group_res[0]['balance'] if read_group_res and read_group_res[0]['balance'] else 0
    
    # Additional helper methods would be implemented similarly...
    # _get_working_capital, _get_retained_earnings, _get_ebit, etc.
