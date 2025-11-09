# -*- coding: utf-8 -*-
"""
Financial Ratio Analysis Service - Pure Python Implementation
Provides advanced financial ratio calculations and analysis
Compatible with Odoo 18 CE
"""

import logging
from datetime import datetime
from typing import Dict, Any

_logger = logging.getLogger(__name__)


class RatioAnalysisService:
    """Pure Python service for advanced financial ratio analysis."""
    
    def __init__(self):
        """Initialize the service."""
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def calculate_dupont_analysis(
        self, 
        net_income: float,
        revenue: float,
        total_assets: float,
        total_equity: float
    ) -> Dict[str, float]:
        """
        Perform DuPont analysis (ROE decomposition).
        
        ROE = Net Profit Margin × Asset Turnover × Equity Multiplier
        
        Args:
            net_income: Net income for the period
            revenue: Total revenue for the period
            total_assets: Total assets at period end
            total_equity: Total equity at period end
            
        Returns:
            Dictionary with DuPont analysis components
        """
        try:
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
                'analysis_type': 'dupont',
                'calculated_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error calculating DuPont analysis: {str(e)}")
            raise
    
    def calculate_liquidity_ratios(
        self,
        current_assets: float,
        current_liabilities: float,
        cash: float,
        marketable_securities: float,
        receivables: float,
        inventory: float
    ) -> Dict[str, float]:
        """
        Calculate liquidity ratios.
        
        Args:
            current_assets: Total current assets
            current_liabilities: Total current liabilities
            cash: Cash and cash equivalents
            marketable_securities: Marketable securities
            receivables: Accounts receivable
            inventory: Inventory value
            
        Returns:
            Dictionary with liquidity ratios
        """
        try:
            # Current Ratio
            current_ratio = current_assets / current_liabilities if current_liabilities else 0
            
            # Quick Ratio (Acid Test)
            quick_assets = current_assets - inventory
            quick_ratio = quick_assets / current_liabilities if current_liabilities else 0
            
            # Cash Ratio
            cash_and_securities = cash + marketable_securities
            cash_ratio = cash_and_securities / current_liabilities if current_liabilities else 0
            
            return {
                'current_ratio': round(current_ratio, 2),
                'quick_ratio': round(quick_ratio, 2),
                'cash_ratio': round(cash_ratio, 2),
                'working_capital': round(current_assets - current_liabilities, 2),
                'analysis_type': 'liquidity',
                'calculated_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error calculating liquidity ratios: {str(e)}")
            raise
    
    def calculate_efficiency_ratios(
        self,
        revenue: float,
        average_receivables: float,
        cogs: float,
        average_inventory: float,
        average_payables: float,
        days_in_period: int = 365
    ) -> Dict[str, float]:
        """
        Calculate efficiency/activity ratios.
        
        Args:
            revenue: Total revenue for the period
            average_receivables: Average accounts receivable
            cogs: Cost of goods sold
            average_inventory: Average inventory
            average_payables: Average accounts payable
            days_in_period: Number of days in the period (default 365)
            
        Returns:
            Dictionary with efficiency ratios
        """
        try:
            # Receivables Turnover
            receivables_turnover = revenue / average_receivables if average_receivables else 0
            days_sales_outstanding = days_in_period / receivables_turnover if receivables_turnover else 0
            
            # Inventory Turnover
            inventory_turnover = cogs / average_inventory if average_inventory else 0
            days_inventory_outstanding = days_in_period / inventory_turnover if inventory_turnover else 0
            
            # Payables Turnover
            payables_turnover = cogs / average_payables if average_payables else 0
            days_payables_outstanding = days_in_period / payables_turnover if payables_turnover else 0
            
            # Cash Conversion Cycle
            cash_conversion_cycle = (days_sales_outstanding + 
                                   days_inventory_outstanding - 
                                   days_payables_outstanding)
            
            return {
                'receivables_turnover': round(receivables_turnover, 2),
                'days_sales_outstanding': round(days_sales_outstanding, 1),
                'inventory_turnover': round(inventory_turnover, 2),
                'days_inventory_outstanding': round(days_inventory_outstanding, 1),
                'payables_turnover': round(payables_turnover, 2),
                'days_payables_outstanding': round(days_payables_outstanding, 1),
                'cash_conversion_cycle': round(cash_conversion_cycle, 1),
                'analysis_type': 'efficiency',
                'calculated_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error calculating efficiency ratios: {str(e)}")
            raise
    
    def calculate_leverage_ratios(
        self,
        total_debt: float,
        total_equity: float,
        total_assets: float,
        ebit: float,
        interest_expense: float
    ) -> Dict[str, float]:
        """
        Calculate leverage/solvency ratios.
        
        Args:
            total_debt: Total debt
            total_equity: Total equity
            total_assets: Total assets
            ebit: Earnings before interest and taxes
            interest_expense: Interest expense
            
        Returns:
            Dictionary with leverage ratios
        """
        try:
            # Debt to Equity Ratio
            debt_to_equity = total_debt / total_equity if total_equity else 0
            
            # Debt Ratio
            debt_ratio = total_debt / total_assets if total_assets else 0
            
            # Equity Ratio
            equity_ratio = total_equity / total_assets if total_assets else 0
            
            # Interest Coverage Ratio
            interest_coverage = ebit / interest_expense if interest_expense else 0
            
            return {
                'debt_to_equity': round(debt_to_equity, 2),
                'debt_ratio': round(debt_ratio, 2),
                'equity_ratio': round(equity_ratio, 2),
                'interest_coverage': round(interest_coverage, 2),
                'analysis_type': 'leverage',
                'calculated_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error calculating leverage ratios: {str(e)}")
            raise
    
    def calculate_profitability_ratios(
        self,
        gross_profit: float,
        operating_profit: float,
        net_income: float,
        revenue: float,
        total_assets: float,
        total_equity: float
    ) -> Dict[str, float]:
        """
        Calculate profitability ratios.
        
        Args:
            gross_profit: Gross profit
            operating_profit: Operating profit (EBIT)
            net_income: Net income
            revenue: Total revenue
            total_assets: Total assets
            total_equity: Total equity
            
        Returns:
            Dictionary with profitability ratios
        """
        try:
            # Margin Ratios
            gross_margin = (gross_profit / revenue * 100) if revenue else 0
            operating_margin = (operating_profit / revenue * 100) if revenue else 0
            net_margin = (net_income / revenue * 100) if revenue else 0
            
            # Return Ratios
            roa = (net_income / total_assets * 100) if total_assets else 0
            roe = (net_income / total_equity * 100) if total_equity else 0
            
            return {
                'gross_margin': round(gross_margin, 2),
                'operating_margin': round(operating_margin, 2),
                'net_margin': round(net_margin, 2),
                'return_on_assets': round(roa, 2),
                'return_on_equity': round(roe, 2),
                'analysis_type': 'profitability',
                'calculated_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error calculating profitability ratios: {str(e)}")
            raise
    
    def perform_comprehensive_analysis(self, financial_data: Dict[str, float]) -> Dict[str, Any]:
        """
        Perform comprehensive financial ratio analysis.
        
        Args:
            financial_data: Dictionary containing all required financial data
            
        Returns:
            Dictionary with all ratio categories
        """
        try:
            results = {
                'dupont': self.calculate_dupont_analysis(
                    financial_data.get('net_income', 0),
                    financial_data.get('revenue', 0),
                    financial_data.get('total_assets', 0),
                    financial_data.get('total_equity', 0)
                ),
                'liquidity': self.calculate_liquidity_ratios(
                    financial_data.get('current_assets', 0),
                    financial_data.get('current_liabilities', 0),
                    financial_data.get('cash', 0),
                    financial_data.get('marketable_securities', 0),
                    financial_data.get('receivables', 0),
                    financial_data.get('inventory', 0)
                ),
                'efficiency': self.calculate_efficiency_ratios(
                    financial_data.get('revenue', 0),
                    financial_data.get('average_receivables', 0),
                    financial_data.get('cogs', 0),
                    financial_data.get('average_inventory', 0),
                    financial_data.get('average_payables', 0),
                    financial_data.get('days_in_period', 365)
                ),
                'leverage': self.calculate_leverage_ratios(
                    financial_data.get('total_debt', 0),
                    financial_data.get('total_equity', 0),
                    financial_data.get('total_assets', 0),
                    financial_data.get('ebit', 0),
                    financial_data.get('interest_expense', 0)
                ),
                'profitability': self.calculate_profitability_ratios(
                    financial_data.get('gross_profit', 0),
                    financial_data.get('operating_profit', 0),
                    financial_data.get('net_income', 0),
                    financial_data.get('revenue', 0),
                    financial_data.get('total_assets', 0),
                    financial_data.get('total_equity', 0)
                ),
                'analysis_date': datetime.now().isoformat(),
                'data_completeness': self._calculate_data_completeness(financial_data)
            }
            
            # Add health score
            results['financial_health_score'] = self._calculate_financial_health_score(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error performing comprehensive analysis: {str(e)}")
            raise
    
    def _calculate_data_completeness(self, financial_data: Dict[str, float]) -> float:
        """Calculate percentage of financial data provided."""
        required_fields = [
            'revenue', 'net_income', 'total_assets', 'total_equity',
            'current_assets', 'current_liabilities', 'cash', 'inventory',
            'cogs', 'ebit', 'gross_profit', 'operating_profit'
        ]
        
        provided = sum(1 for field in required_fields if financial_data.get(field, 0) != 0)
        return round(provided / len(required_fields) * 100, 1)
    
    def _calculate_financial_health_score(self, ratios: Dict[str, Any]) -> float:
        """
        Calculate overall financial health score (0-100).
        
        This is a simplified scoring model that can be customized.
        """
        score = 0
        max_score = 100
        
        # Liquidity score (25 points)
        current_ratio = ratios['liquidity']['current_ratio']
        if 1.5 <= current_ratio <= 3:
            score += 25
        elif 1 <= current_ratio < 1.5 or 3 < current_ratio <= 4:
            score += 15
        elif 0.5 <= current_ratio < 1 or 4 < current_ratio <= 5:
            score += 5
        
        # Profitability score (25 points)
        roe = ratios['dupont']['roe']
        if roe >= 15:
            score += 25
        elif 10 <= roe < 15:
            score += 20
        elif 5 <= roe < 10:
            score += 10
        elif 0 < roe < 5:
            score += 5
        
        # Leverage score (25 points)
        debt_to_equity = ratios['leverage']['debt_to_equity']
        if 0.3 <= debt_to_equity <= 0.5:
            score += 25
        elif 0.1 <= debt_to_equity < 0.3 or 0.5 < debt_to_equity <= 0.7:
            score += 20
        elif 0 <= debt_to_equity < 0.1 or 0.7 < debt_to_equity <= 1:
            score += 10
        elif 1 < debt_to_equity <= 1.5:
            score += 5
        
        # Efficiency score (25 points)
        cash_conversion = ratios['efficiency']['cash_conversion_cycle']
        if 0 <= cash_conversion <= 30:
            score += 25
        elif 30 < cash_conversion <= 60:
            score += 20
        elif 60 < cash_conversion <= 90:
            score += 10
        elif 90 < cash_conversion <= 120:
            score += 5
        
        return round(score, 1)


# Factory function
def create_ratio_analysis_service() -> RatioAnalysisService:
    """Factory function to create service instance."""
    return RatioAnalysisService()