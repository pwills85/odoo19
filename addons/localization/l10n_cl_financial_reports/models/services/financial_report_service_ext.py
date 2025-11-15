# -*- coding: utf-8 -*-
"""
Extensión del servicio de reportes financieros con métodos de datos reales
"""
from odoo import api, models
from datetime import datetime, timedelta
import logging

_logger = logging.getLogger(__name__)


class FinancialReportServiceExt(models.AbstractModel):
    """Extensión con métodos de datos reales para gráficos y períodos"""
    _inherit = 'financial.report.service'
    
    @api.model
    def _generate_comparison_periods(self, date_from, date_to, comparison_type):
        """
        Genera períodos para comparación según el tipo
        
        Args:
            date_from: Fecha inicio (string)
            date_to: Fecha fin (string)
            comparison_type: 'month', 'quarter', 'year'
            
        Returns:
            list: Lista de diccionarios con períodos
        """
        periods = []
        date_from_dt = datetime.strptime(date_from, '%Y-%m-%d')
        date_to_dt = datetime.strptime(date_to, '%Y-%m-%d')
        
        if comparison_type == 'month':
            # Generar períodos mensuales
            current = date_from_dt.replace(day=1)
            while current <= date_to_dt:
                period_start = current
                # Último día del mes
                if current.month == 12:
                    period_end = current.replace(year=current.year + 1, month=1, day=1) - timedelta(days=1)
                else:
                    period_end = current.replace(month=current.month + 1, day=1) - timedelta(days=1)
                
                if period_end > date_to_dt:
                    period_end = date_to_dt
                    
                periods.append({
                    'label': current.strftime('%B %Y'),
                    'date_from': period_start.strftime('%Y-%m-%d'),
                    'date_to': period_end.strftime('%Y-%m-%d'),
                })
                
                # Siguiente mes
                if current.month == 12:
                    current = current.replace(year=current.year + 1, month=1)
                else:
                    current = current.replace(month=current.month + 1)
                    
        elif comparison_type == 'quarter':
            # Generar períodos trimestrales
            current = date_from_dt
            while current <= date_to_dt:
                quarter = (current.month - 1) // 3 + 1
                quarter_start = datetime(current.year, (quarter - 1) * 3 + 1, 1)
                quarter_end = datetime(current.year, quarter * 3, 1)
                
                if quarter == 4:
                    quarter_end = datetime(current.year + 1, 1, 1)
                    
                quarter_end = quarter_end - timedelta(days=1)
                
                if quarter_start < date_from_dt:
                    quarter_start = date_from_dt
                if quarter_end > date_to_dt:
                    quarter_end = date_to_dt
                    
                periods.append({
                    'label': f'Q{quarter} {current.year}',
                    'date_from': quarter_start.strftime('%Y-%m-%d'),
                    'date_to': quarter_end.strftime('%Y-%m-%d'),
                })
                
                # Siguiente trimestre
                current = quarter_end + timedelta(days=1)
                
        else:  # year
            # Generar períodos anuales
            current_year = date_from_dt.year
            end_year = date_to_dt.year
            
            while current_year <= end_year:
                year_start = datetime(current_year, 1, 1)
                year_end = datetime(current_year, 12, 31)
                
                if year_start < date_from_dt:
                    year_start = date_from_dt
                if year_end > date_to_dt:
                    year_end = date_to_dt
                    
                periods.append({
                    'label': str(current_year),
                    'date_from': year_start.strftime('%Y-%m-%d'),
                    'date_to': year_end.strftime('%Y-%m-%d'),
                })
                
                current_year += 1
                
        return periods
    
    @api.model
    def _get_revenue_chart_data(self, company_id, periods):
        """
        Obtiene datos de ingresos para gráfico
        
        Returns:
            dict: Datos formateados para Chart.js
        """
        labels = []
        revenue_data = []
        profit_data = []
        
        for period in periods:
            labels.append(period['label'])
            
            # Obtener datos del período
            income_data = self._get_income_statement_data(
                company_id, 
                period['date_from'], 
                period['date_to']
            )
            
            revenue_data.append(income_data.get('total_revenue', 0))
            profit_data.append(income_data.get('net_profit', 0))
        
        return {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Ingresos',
                    'data': revenue_data,
                    'backgroundColor': 'rgba(75, 192, 192, 0.2)',
                    'borderColor': 'rgba(75, 192, 192, 1)',
                    'borderWidth': 2,
                    'tension': 0.4
                },
                {
                    'label': 'Utilidad Neta',
                    'data': profit_data,
                    'backgroundColor': 'rgba(54, 162, 235, 0.2)',
                    'borderColor': 'rgba(54, 162, 235, 1)',
                    'borderWidth': 2,
                    'tension': 0.4
                }
            ]
        }
    
    @api.model
    def _get_expenses_chart_data(self, company_id, periods):
        """
        Obtiene datos de gastos para gráfico
        
        Returns:
            dict: Datos formateados para Chart.js
        """
        labels = []
        categories = {
            'cost_of_goods': [],
            'operating': [],
            'depreciation': [],
            'other': []
        }
        
        for period in periods:
            labels.append(period['label'])
            
            # Consulta SQL para obtener gastos por categoría
            query = """
                SELECT 
                    CASE 
                        WHEN aa.account_type = 'expense_direct_cost' THEN 'cost_of_goods'
                        WHEN aa.account_type = 'expense_depreciation' THEN 'depreciation'
                        WHEN aa.account_type = 'expense' AND aa.code LIKE '6%%' THEN 'operating'
                        ELSE 'other'
                    END as category,
                    SUM(ABS(aml.balance)) as amount
                FROM account_move_line aml
                JOIN account_account aa ON aml.account_id = aa.id
                JOIN account_move am ON aml.move_id = am.id
                WHERE 
                    aml.company_id = %s
                    AND aml.date >= %s
                    AND aml.date <= %s
                    AND am.state = 'posted'
                    AND aa.account_type IN ('expense', 'expense_depreciation', 'expense_direct_cost')
                GROUP BY category
            """
            
            self.env.cr.execute(query, (company_id, period['date_from'], period['date_to']))
            results = dict(self.env.cr.fetchall())
            
            categories['cost_of_goods'].append(results.get('cost_of_goods', 0))
            categories['operating'].append(results.get('operating', 0))
            categories['depreciation'].append(results.get('depreciation', 0))
            categories['other'].append(results.get('other', 0))
        
        return {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Costo de Ventas',
                    'data': categories['cost_of_goods'],
                    'backgroundColor': 'rgba(255, 99, 132, 0.5)',
                    'stack': 'expenses'
                },
                {
                    'label': 'Gastos Operacionales',
                    'data': categories['operating'],
                    'backgroundColor': 'rgba(54, 162, 235, 0.5)',
                    'stack': 'expenses'
                },
                {
                    'label': 'Depreciación',
                    'data': categories['depreciation'],
                    'backgroundColor': 'rgba(255, 206, 86, 0.5)',
                    'stack': 'expenses'
                },
                {
                    'label': 'Otros Gastos',
                    'data': categories['other'],
                    'backgroundColor': 'rgba(75, 192, 192, 0.5)',
                    'stack': 'expenses'
                }
            ]
        }
    
    @api.model
    def _get_cash_flow_chart_data(self, company_id, periods):
        """
        Obtiene datos de flujo de caja para gráfico
        
        Returns:
            dict: Datos formateados para Chart.js
        """
        labels = []
        operating_data = []
        investing_data = []
        financing_data = []
        net_cash_data = []
        
        for period in periods:
            labels.append(period['label'])
            
            # Consulta para flujo de caja operacional
            operating_query = """
                SELECT 
                    SUM(CASE 
                        WHEN aa.account_type IN ('income', 'income_other') THEN -aml.balance
                        WHEN aa.account_type IN ('expense', 'expense_depreciation', 'expense_direct_cost') THEN aml.balance
                        ELSE 0
                    END) as operating_cash
                FROM account_move_line aml
                JOIN account_account aa ON aml.account_id = aa.id
                JOIN account_move am ON aml.move_id = am.id
                WHERE 
                    aml.company_id = %s
                    AND aml.date >= %s
                    AND aml.date <= %s
                    AND am.state = 'posted'
                    AND aa.account_type IN ('income', 'income_other', 'expense', 'expense_depreciation', 'expense_direct_cost')
            """
            
            self.env.cr.execute(operating_query, (company_id, period['date_from'], period['date_to']))
            operating = self.env.cr.fetchone()[0] or 0
            
            # Flujo de inversión (simplificado - activos fijos)
            investing_query = """
                SELECT 
                    SUM(aml.balance) as investing_cash
                FROM account_move_line aml
                JOIN account_account aa ON aml.account_id = aa.id
                JOIN account_move am ON aml.move_id = am.id
                WHERE 
                    aml.company_id = %s
                    AND aml.date >= %s
                    AND aml.date <= %s
                    AND am.state = 'posted'
                    AND aa.account_type = 'asset_fixed'
            """
            
            self.env.cr.execute(investing_query, (company_id, period['date_from'], period['date_to']))
            investing = self.env.cr.fetchone()[0] or 0
            
            # Flujo de financiamiento (simplificado - pasivos no corrientes y patrimonio)
            financing_query = """
                SELECT 
                    SUM(-aml.balance) as financing_cash
                FROM account_move_line aml
                JOIN account_account aa ON aml.account_id = aa.id
                JOIN account_move am ON aml.move_id = am.id
                WHERE 
                    aml.company_id = %s
                    AND aml.date >= %s
                    AND aml.date <= %s
                    AND am.state = 'posted'
                    AND aa.account_type IN ('liability_non_current', 'equity')
            """
            
            self.env.cr.execute(financing_query, (company_id, period['date_from'], period['date_to']))
            financing = self.env.cr.fetchone()[0] or 0
            
            operating_data.append(operating)
            investing_data.append(investing)
            financing_data.append(financing)
            net_cash_data.append(operating + investing + financing)
        
        return {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Flujo Operacional',
                    'data': operating_data,
                    'backgroundColor': 'rgba(75, 192, 192, 0.5)',
                },
                {
                    'label': 'Flujo de Inversión',
                    'data': investing_data,
                    'backgroundColor': 'rgba(255, 206, 86, 0.5)',
                },
                {
                    'label': 'Flujo de Financiamiento',
                    'data': financing_data,
                    'backgroundColor': 'rgba(54, 162, 235, 0.5)',
                },
                {
                    'label': 'Flujo Neto',
                    'data': net_cash_data,
                    'type': 'line',
                    'borderColor': 'rgba(255, 99, 132, 1)',
                    'borderWidth': 3,
                    'fill': False,
                    'tension': 0.4
                }
            ]
        }
    
    @api.model
    def _get_ratios_chart_data(self, company_id, periods):
        """
        Obtiene evolución de ratios financieros para gráfico
        
        Returns:
            dict: Datos formateados para Chart.js
        """
        labels = []
        current_ratio_data = []
        debt_to_equity_data = []
        roe_data = []
        
        for period in periods:
            labels.append(period['label'])
            
            # Obtener datos del período
            balance_data = self._get_balance_sheet_data(
                company_id, 
                period['date_from'], 
                period['date_to']
            )
            income_data = self._get_income_statement_data(
                company_id, 
                period['date_from'], 
                period['date_to']
            )
            
            # Calcular ratios
            current_ratio = self._calculate_current_ratio(balance_data)
            debt_to_equity = self._calculate_debt_to_equity(balance_data)
            roe = self._calculate_roe(income_data, balance_data)
            
            current_ratio_data.append(current_ratio)
            debt_to_equity_data.append(debt_to_equity)
            roe_data.append(roe)
        
        return {
            'labels': labels,
            'datasets': [
                {
                    'label': 'Ratio de Liquidez',
                    'data': current_ratio_data,
                    'borderColor': 'rgba(75, 192, 192, 1)',
                    'backgroundColor': 'rgba(75, 192, 192, 0.2)',
                    'yAxisID': 'y',
                    'tension': 0.4
                },
                {
                    'label': 'Deuda/Patrimonio',
                    'data': debt_to_equity_data,
                    'borderColor': 'rgba(255, 206, 86, 1)',
                    'backgroundColor': 'rgba(255, 206, 86, 0.2)',
                    'yAxisID': 'y',
                    'tension': 0.4
                },
                {
                    'label': 'ROE (%)',
                    'data': roe_data,
                    'borderColor': 'rgba(54, 162, 235, 1)',
                    'backgroundColor': 'rgba(54, 162, 235, 0.2)',
                    'yAxisID': 'y1',
                    'tension': 0.4
                }
            ],
            'options': {
                'scales': {
                    'y': {
                        'type': 'linear',
                        'display': True,
                        'position': 'left',
                        'title': {
                            'display': True,
                            'text': 'Ratio'
                        }
                    },
                    'y1': {
                        'type': 'linear',
                        'display': True,
                        'position': 'right',
                        'title': {
                            'display': True,
                            'text': 'Porcentaje (%)'
                        },
                        'grid': {
                            'drawOnChartArea': False
                        }
                    }
                }
            }
        }
