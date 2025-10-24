# -*- coding: utf-8 -*-
"""
Financial Report Service - Pure Python Implementation
Provides core financial reporting calculations
Compatible with Odoo 18 CE
"""

import logging
from datetime import datetime, date
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

_logger = logging.getLogger(__name__)


class FinancialReportService:
    """Pure Python service for financial report generation."""
    
    def __init__(self):
        """Initialize the service."""
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def classify_eight_column_balances(
        self,
        account_data: List[Dict[str, Any]]
    ) -> Tuple[List[Dict], Dict[str, float]]:
        """
        Classify account balances into 8-column format.
        
        Args:
            account_data: List of account data with initial and period balances
            
        Returns:
            Tuple of (classified_lines, totals)
        """
        classified_lines = []
        totals = defaultdict(float)
        
        for account in account_data:
            line = self._classify_single_account(account)
            classified_lines.append(line)
            
            # Accumulate totals
            for col in ['debit_initial', 'credit_initial', 'debit_period', 
                       'credit_period', 'debit_balance', 'credit_balance',
                       'debit_inventory', 'credit_inventory']:
                totals[col] += line.get(col, 0.0)
        
        return classified_lines, dict(totals)
    
    def _classify_single_account(self, account: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a single account into 8 columns.
        
        The 8 columns are:
        1. Initial Debit
        2. Initial Credit  
        3. Period Debit
        4. Period Credit
        5. Balance Debit
        6. Balance Credit
        7. Inventory Debit
        8. Inventory Credit
        """
        # Extract values
        initial_debit = account.get('initial_debit', 0.0)
        initial_credit = account.get('initial_credit', 0.0)
        period_debit = account.get('period_debit', 0.0)
        period_credit = account.get('period_credit', 0.0)
        
        # Calculate net balances
        initial_balance = initial_debit - initial_credit
        period_movement = period_debit - period_credit
        final_balance = initial_balance + period_movement
        
        # Classify final balance
        balance_debit = final_balance if final_balance > 0 else 0.0
        balance_credit = -final_balance if final_balance < 0 else 0.0
        
        # Inventory columns (for balance sheet accounts)
        is_balance_sheet = account.get('account_type') in [
            'asset_receivable', 'asset_cash', 'asset_current',
            'asset_non_current', 'asset_prepayments', 'asset_fixed',
            'liability_payable', 'liability_current', 'liability_non_current',
            'equity', 'equity_unaffected'
        ]
        
        inventory_debit = balance_debit if is_balance_sheet else 0.0
        inventory_credit = balance_credit if is_balance_sheet else 0.0
        
        return {
            'account_id': account.get('account_id'),
            'account_code': account.get('account_code'),
            'account_name': account.get('account_name'),
            'account_type': account.get('account_type'),
            'debit_initial': round(initial_debit, 2),
            'credit_initial': round(initial_credit, 2),
            'debit_period': round(period_debit, 2),
            'credit_period': round(period_credit, 2),
            'debit_balance': round(balance_debit, 2),
            'credit_balance': round(balance_credit, 2),
            'debit_inventory': round(inventory_debit, 2),
            'credit_inventory': round(inventory_credit, 2),
            'is_balance_sheet': is_balance_sheet
        }
    
    def generate_general_ledger(
        self,
        move_lines: List[Dict[str, Any]],
        group_by_account: bool = True,
        include_initial_balance: bool = True
    ) -> Dict[str, Any]:
        """
        Generate general ledger report data.
        
        Args:
            move_lines: List of account move lines
            group_by_account: Whether to group by account
            include_initial_balance: Whether to include initial balances
            
        Returns:
            Dictionary with ledger data
        """
        if group_by_account:
            return self._generate_grouped_ledger(move_lines, include_initial_balance)
        else:
            return self._generate_detailed_ledger(move_lines)
    
    def _generate_grouped_ledger(
        self,
        move_lines: List[Dict[str, Any]],
        include_initial_balance: bool
    ) -> Dict[str, Any]:
        """Generate ledger grouped by account."""
        accounts = defaultdict(lambda: {
            'move_lines': [],
            'initial_balance': 0.0,
            'total_debit': 0.0,
            'total_credit': 0.0,
            'final_balance': 0.0
        })
        
        for line in move_lines:
            account_id = line.get('account_id')
            if line.get('is_initial_balance') and include_initial_balance:
                accounts[account_id]['initial_balance'] += line.get('balance', 0.0)
            else:
                accounts[account_id]['move_lines'].append(line)
                accounts[account_id]['total_debit'] += line.get('debit', 0.0)
                accounts[account_id]['total_credit'] += line.get('credit', 0.0)
        
        # Calculate final balances
        for account_id, data in accounts.items():
            data['final_balance'] = (
                data['initial_balance'] + 
                data['total_debit'] - 
                data['total_credit']
            )
        
        return dict(accounts)
    
    def _generate_detailed_ledger(
        self,
        move_lines: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate detailed ledger without grouping."""
        # Sort by date and move name
        sorted_lines = sorted(
            move_lines,
            key=lambda x: (x.get('date', ''), x.get('move_name', ''))
        )
        
        # Calculate running balance
        running_balance = 0.0
        for line in sorted_lines:
            running_balance += line.get('debit', 0.0) - line.get('credit', 0.0)
            line['running_balance'] = round(running_balance, 2)
        
        return {
            'lines': sorted_lines,
            'total_debit': sum(line.get('debit', 0.0) for line in sorted_lines),
            'total_credit': sum(line.get('credit', 0.0) for line in sorted_lines),
            'final_balance': running_balance
        }
    
    def calculate_trial_balance(
        self,
        account_balances: List[Dict[str, Any]],
        show_zero_balance: bool = False
    ) -> Dict[str, Any]:
        """
        Calculate trial balance from account balances.
        
        Args:
            account_balances: List of account balances
            show_zero_balance: Whether to include zero balance accounts
            
        Returns:
            Dictionary with trial balance data
        """
        trial_balance_lines = []
        totals = {
            'initial_debit': 0.0,
            'initial_credit': 0.0,
            'period_debit': 0.0,
            'period_credit': 0.0,
            'final_debit': 0.0,
            'final_credit': 0.0
        }
        
        for account in account_balances:
            # Skip zero balance accounts if requested
            if not show_zero_balance and all(
                account.get(field, 0.0) == 0.0 
                for field in ['initial_balance', 'period_debit', 'period_credit']
            ):
                continue
            
            # Process account
            line = self._process_trial_balance_line(account)
            trial_balance_lines.append(line)
            
            # Update totals
            for field in totals:
                totals[field] += line.get(field, 0.0)
        
        return {
            'lines': trial_balance_lines,
            'totals': totals,
            'is_balanced': abs(totals['final_debit'] - totals['final_credit']) < 0.01
        }
    
    def _process_trial_balance_line(self, account: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single trial balance line."""
        initial_balance = account.get('initial_balance', 0.0)
        period_debit = account.get('period_debit', 0.0)
        period_credit = account.get('period_credit', 0.0)
        
        # Calculate final balance
        final_balance = initial_balance + period_debit - period_credit
        
        # Classify initial and final balances
        initial_debit = initial_balance if initial_balance > 0 else 0.0
        initial_credit = -initial_balance if initial_balance < 0 else 0.0
        final_debit = final_balance if final_balance > 0 else 0.0
        final_credit = -final_balance if final_balance < 0 else 0.0
        
        return {
            'account_id': account.get('account_id'),
            'account_code': account.get('account_code'),
            'account_name': account.get('account_name'),
            'initial_debit': round(initial_debit, 2),
            'initial_credit': round(initial_credit, 2),
            'period_debit': round(period_debit, 2),
            'period_credit': round(period_credit, 2),
            'final_debit': round(final_debit, 2),
            'final_credit': round(final_credit, 2),
            'final_balance': round(final_balance, 2)
        }
    
    def generate_balance_sheet(
        self,
        account_balances: List[Dict[str, Any]],
        report_date: str
    ) -> Dict[str, Any]:
        """
        Generate balance sheet data.
        
        Args:
            account_balances: List of account balances
            report_date: Date of the report
            
        Returns:
            Dictionary with balance sheet structure
        """
        # Initialize structure
        balance_sheet = {
            'assets': {
                'current': defaultdict(float),
                'non_current': defaultdict(float),
                'total': 0.0
            },
            'liabilities': {
                'current': defaultdict(float),
                'non_current': defaultdict(float),
                'total': 0.0
            },
            'equity': {
                'items': defaultdict(float),
                'total': 0.0
            },
            'report_date': report_date,
            'is_balanced': False
        }
        
        # Classify accounts
        for account in account_balances:
            balance = account.get('balance', 0.0)
            if balance == 0:
                continue
                
            account_type = account.get('account_type')
            
            # Assets
            if account_type in ['asset_receivable', 'asset_cash', 'asset_current']:
                balance_sheet['assets']['current'][account_type] += balance
            elif account_type in ['asset_non_current', 'asset_fixed', 'asset_prepayments']:
                balance_sheet['assets']['non_current'][account_type] += balance
            
            # Liabilities
            elif account_type in ['liability_payable', 'liability_current']:
                balance_sheet['liabilities']['current'][account_type] += abs(balance)
            elif account_type == 'liability_non_current':
                balance_sheet['liabilities']['non_current'][account_type] += abs(balance)
            
            # Equity
            elif account_type in ['equity', 'equity_unaffected']:
                balance_sheet['equity']['items'][account_type] += abs(balance)
        
        # Calculate totals
        balance_sheet['assets']['total'] = (
            sum(balance_sheet['assets']['current'].values()) +
            sum(balance_sheet['assets']['non_current'].values())
        )
        
        balance_sheet['liabilities']['total'] = (
            sum(balance_sheet['liabilities']['current'].values()) +
            sum(balance_sheet['liabilities']['non_current'].values())
        )
        
        balance_sheet['equity']['total'] = sum(balance_sheet['equity']['items'].values())
        
        # Check if balanced
        total_liabilities_equity = (
            balance_sheet['liabilities']['total'] + 
            balance_sheet['equity']['total']
        )
        
        balance_sheet['is_balanced'] = abs(
            balance_sheet['assets']['total'] - total_liabilities_equity
        ) < 0.01
        
        # Convert defaultdicts to regular dicts
        balance_sheet['assets']['current'] = dict(balance_sheet['assets']['current'])
        balance_sheet['assets']['non_current'] = dict(balance_sheet['assets']['non_current'])
        balance_sheet['liabilities']['current'] = dict(balance_sheet['liabilities']['current'])
        balance_sheet['liabilities']['non_current'] = dict(balance_sheet['liabilities']['non_current'])
        balance_sheet['equity']['items'] = dict(balance_sheet['equity']['items'])
        
        return balance_sheet
    
    def generate_profit_loss(
        self,
        move_lines: List[Dict[str, Any]],
        start_date: str,
        end_date: str
    ) -> Dict[str, Any]:
        """
        Generate profit & loss statement.
        
        Args:
            move_lines: List of P&L account move lines
            start_date: Start date of the period
            end_date: End date of the period
            
        Returns:
            Dictionary with P&L structure
        """
        pl_structure = {
            'revenue': defaultdict(float),
            'cost_of_sales': defaultdict(float),
            'operating_expenses': defaultdict(float),
            'other_income': defaultdict(float),
            'other_expenses': defaultdict(float),
            'period': f"{start_date} to {end_date}",
            'totals': {}
        }
        
        # Classify move lines
        for line in move_lines:
            account_type = line.get('account_type')
            balance = line.get('balance', 0.0)
            
            if account_type == 'income':
                pl_structure['revenue']['sales'] += abs(balance)
            elif account_type == 'income_other':
                pl_structure['other_income']['other'] += abs(balance)
            elif account_type == 'expense_direct_cost':
                pl_structure['cost_of_sales']['direct_costs'] += balance
            elif account_type in ['expense', 'expense_depreciation']:
                pl_structure['operating_expenses']['operating'] += balance
            elif account_type == 'expense_other':
                pl_structure['other_expenses']['other'] += balance
        
        # Calculate totals
        total_revenue = sum(pl_structure['revenue'].values())
        total_cogs = sum(pl_structure['cost_of_sales'].values())
        gross_profit = total_revenue - total_cogs
        
        total_operating_exp = sum(pl_structure['operating_expenses'].values())
        operating_profit = gross_profit - total_operating_exp
        
        total_other_income = sum(pl_structure['other_income'].values())
        total_other_expenses = sum(pl_structure['other_expenses'].values())
        
        net_profit = operating_profit + total_other_income - total_other_expenses
        
        pl_structure['totals'] = {
            'revenue': round(total_revenue, 2),
            'cost_of_sales': round(total_cogs, 2),
            'gross_profit': round(gross_profit, 2),
            'gross_margin': round(gross_profit / total_revenue * 100, 2) if total_revenue else 0,
            'operating_expenses': round(total_operating_exp, 2),
            'operating_profit': round(operating_profit, 2),
            'operating_margin': round(operating_profit / total_revenue * 100, 2) if total_revenue else 0,
            'other_income': round(total_other_income, 2),
            'other_expenses': round(total_other_expenses, 2),
            'net_profit': round(net_profit, 2),
            'net_margin': round(net_profit / total_revenue * 100, 2) if total_revenue else 0
        }
        
        # Convert defaultdicts to regular dicts
        pl_structure['revenue'] = dict(pl_structure['revenue'])
        pl_structure['cost_of_sales'] = dict(pl_structure['cost_of_sales'])
        pl_structure['operating_expenses'] = dict(pl_structure['operating_expenses'])
        pl_structure['other_income'] = dict(pl_structure['other_income'])
        pl_structure['other_expenses'] = dict(pl_structure['other_expenses'])
        
        return pl_structure
    
    def calculate_period_comparison(
        self,
        current_period: Dict[str, Any],
        previous_period: Dict[str, Any],
        comparison_type: str = 'absolute'
    ) -> Dict[str, Any]:
        """
        Calculate period-over-period comparison.
        
        Args:
            current_period: Current period data
            previous_period: Previous period data
            comparison_type: 'absolute' or 'percentage'
            
        Returns:
            Dictionary with comparison data
        """
        comparison = {}
        
        # Get all keys from both periods
        all_keys = set(current_period.keys()) | set(previous_period.keys())
        
        for key in all_keys:
            current_val = current_period.get(key, 0.0)
            previous_val = previous_period.get(key, 0.0)
            
            if comparison_type == 'absolute':
                comparison[key] = {
                    'current': current_val,
                    'previous': previous_val,
                    'change': round(current_val - previous_val, 2)
                }
            else:  # percentage
                change_pct = 0.0
                if previous_val != 0:
                    change_pct = ((current_val - previous_val) / previous_val) * 100
                
                comparison[key] = {
                    'current': current_val,
                    'previous': previous_val,
                    'change_amount': round(current_val - previous_val, 2),
                    'change_percentage': round(change_pct, 2)
                }
        
        return comparison


# Factory function
def create_financial_report_service() -> FinancialReportService:
    """Factory function to create service instance."""
    return FinancialReportService()