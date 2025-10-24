# -*- coding: utf-8 -*-
"""
Business Intelligence Dashboard Service
======================================

Servicio completo de BI para dashboard ejecutivo con KPIs principales,
análisis predictivo y visualizaciones interactivas.

Autor: Claude AI siguiendo PROMPT_AGENT_IA.md
Fecha: 2025-07-13
"""

import logging
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
import json
from collections import defaultdict

from odoo import api, models, fields, _
from odoo.exceptions import UserError, ValidationError
from odoo.tools import float_round, float_compare
from odoo.tools.misc import format_amount

_logger = logging.getLogger(__name__)


class BiDashboardService(models.AbstractModel):
    """
    Servicio de Business Intelligence para dashboards ejecutivos.
    Proporciona KPIs, métricas y análisis predictivo.
    """
    _name = 'account.financial.bi.service'
    _description = 'Business Intelligence Dashboard Service'
    
    # Cache timeouts
    CACHE_TIMEOUT_FAST = 300      # 5 minutos para datos dinámicos
    CACHE_TIMEOUT_MEDIUM = 3600   # 1 hora para cálculos pesados
    CACHE_TIMEOUT_SLOW = 86400    # 24 horas para datos históricos
    
    # ========================================================================
    # MÉTODOS PRINCIPALES - DASHBOARD EJECUTIVO
    # ========================================================================
    
    @api.model
    def get_executive_dashboard(self, date_from, date_to, company_ids=None):
        """
        Dashboard ejecutivo con KPIs principales.
        
        Args:
            date_from: datetime.date fecha inicio
            date_to: datetime.date fecha fin
            company_ids: list de IDs de compañías (opcional)
            
        Returns:
            dict: Dashboard completo con todas las métricas
        """
        if not company_ids:
            company_ids = [self.env.company.id]
            
        # Cache check
        cache_key = f"bi_dashboard_{date_from}_{date_to}_{','.join(map(str, company_ids))}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached
            
        try:
            dashboard = {
                'period': {
                    'from': date_from.isoformat(),
                    'to': date_to.isoformat(),
                    'days': (date_to - date_from).days + 1
                },
                'kpis': self._get_main_kpis(date_from, date_to, company_ids),
                'revenue_metrics': self._get_revenue_metrics(date_from, date_to, company_ids),
                'expense_analysis': self._get_expense_analysis(date_from, date_to, company_ids),
                'cashflow_projection': self._get_cashflow_projection(company_ids),
                'tax_compliance': self._get_tax_compliance_status(date_from, date_to, company_ids),
                'trends': self._get_financial_trends(date_from, date_to, company_ids),
                'alerts': self._get_financial_alerts(company_ids),
                'comparisons': self._get_period_comparisons(date_from, date_to, company_ids),
                'projections': self._get_financial_projections(date_from, date_to, company_ids),
            }
            
            # Save to cache
            self._save_to_cache(cache_key, dashboard, self.CACHE_TIMEOUT_FAST)
            
            return dashboard
            
        except Exception as e:
            _logger.error(f"Error generando dashboard ejecutivo: {str(e)}")
            raise UserError(_("Error al generar dashboard: %s") % str(e))
    
    # ========================================================================
    # KPIs PRINCIPALES
    # ========================================================================
    
    def _get_main_kpis(self, date_from, date_to, company_ids):
        """Obtiene KPIs principales del negocio."""
        
        # Obtener moneda de la compañía principal
        company = self.env['res.company'].browse(company_ids[0])
        currency = company.currency_id
        
        # Queries optimizadas para KPIs
        query_revenue = """
            SELECT 
                COALESCE(SUM(aml.credit - aml.debit), 0) as total
            FROM account_move_line aml
            JOIN account_move am ON aml.move_id = am.id
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE am.state = 'posted'
                AND am.date BETWEEN %s AND %s
                AND am.company_id IN %s
                AND aa.account_type IN ('income', 'income_other')
        """
        
        query_expenses = """
            SELECT 
                COALESCE(SUM(aml.debit - aml.credit), 0) as total
            FROM account_move_line aml
            JOIN account_move am ON aml.move_id = am.id
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE am.state = 'posted'
                AND am.date BETWEEN %s AND %s
                AND am.company_id IN %s
                AND aa.account_type IN ('expense', 'expense_depreciation', 'expense_direct_cost')
        """
        
        query_cash = """
            SELECT 
                COALESCE(SUM(aml.balance), 0) as total
            FROM account_move_line aml
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE aml.date <= %s
                AND aml.company_id IN %s
                AND aa.account_type IN ('asset_cash', 'asset_bank')
                AND aml.parent_state = 'posted'
        """
        
        # Ejecutar queries
        self.env.self.env.cr.execute(query_revenue, (date_from, date_to, tuple(company_ids)))
        revenue = self.env.cr.fetchone()[0]
        
        self.env.self.env.cr.execute(query_expenses, (date_from, date_to, tuple(company_ids)))
        expenses = self.env.cr.fetchone()[0]
        
        self.env.self.env.cr.execute(query_cash, (date_to, tuple(company_ids)))
        cash_balance = self.env.cr.fetchone()[0]
        
        # Calcular métricas derivadas
        profit = revenue - expenses
        margin = (profit / revenue * 100) if revenue else 0
        
        # Comparar con período anterior
        days_diff = (date_to - date_from).days + 1
        prev_date_from = date_from - timedelta(days=days_diff)
        prev_date_to = date_from - timedelta(days=1)
        
        self.env.self.env.cr.execute(query_revenue, (prev_date_from, prev_date_to, tuple(company_ids)))
        prev_revenue = self.env.cr.fetchone()[0]
        
        revenue_growth = ((revenue - prev_revenue) / prev_revenue * 100) if prev_revenue else 0
        
        return {
            'revenue': {
                'value': revenue,
                'formatted': format_amount(self.env, revenue, currency),
                'growth': round(revenue_growth, 1),
                'trend': 'up' if revenue_growth > 0 else 'down' if revenue_growth < 0 else 'stable'
            },
            'expenses': {
                'value': expenses,
                'formatted': format_amount(self.env, expenses, currency),
                'percentage_of_revenue': round((expenses / revenue * 100) if revenue else 0, 1)
            },
            'profit': {
                'value': profit,
                'formatted': format_amount(self.env, profit, currency),
                'margin': round(margin, 1),
                'status': 'profit' if profit > 0 else 'loss' if profit < 0 else 'breakeven'
            },
            'cash_balance': {
                'value': cash_balance,
                'formatted': format_amount(self.env, cash_balance, currency),
                'days_of_expenses': round((cash_balance / (expenses / days_diff)) if expenses else 0, 1)
            }
        }
    
    # ========================================================================
    # ANÁLISIS DE INGRESOS
    # ========================================================================
    
    def _get_revenue_metrics(self, date_from, date_to, company_ids):
        """Métricas detalladas de ingresos con análisis predictivo."""
        
        query = """
            WITH monthly_revenue AS (
                SELECT 
                    DATE_TRUNC('month', am.date) as period,
                    aa.code as account_code,
                    aa.name as account_name,
                    SUM(aml.credit - aml.debit) as revenue,
                    COUNT(DISTINCT am.partner_id) as customers,
                    COUNT(DISTINCT am.id) as transactions,
                    AVG(aml.credit - aml.debit) as avg_transaction
                FROM account_move_line aml
                JOIN account_move am ON aml.move_id = am.id
                JOIN account_account aa ON aml.account_id = aa.id
                WHERE am.state = 'posted'
                    AND am.date BETWEEN %s AND %s
                    AND am.company_id IN %s
                    AND aa.account_type IN ('income', 'income_other')
                GROUP BY DATE_TRUNC('month', am.date), aa.code, aa.name
            ),
            customer_analysis AS (
                SELECT 
                    am.partner_id,
                    rp.name as customer_name,
                    SUM(aml.credit - aml.debit) as total_revenue,
                    COUNT(DISTINCT am.id) as transaction_count,
                    MAX(am.date) as last_transaction
                FROM account_move_line aml
                JOIN account_move am ON aml.move_id = am.id
                JOIN res_partner rp ON am.partner_id = rp.id
                JOIN account_account aa ON aml.account_id = aa.id
                WHERE am.state = 'posted'
                    AND am.date BETWEEN %s AND %s
                    AND am.company_id IN %s
                    AND aa.account_type IN ('income', 'income_other')
                GROUP BY am.partner_id, rp.name
                ORDER BY total_revenue DESC
                LIMIT 10
            )
            SELECT 
                (SELECT json_agg(row_to_json(mr)) FROM monthly_revenue mr) as monthly_data,
                (SELECT json_agg(row_to_json(ca)) FROM customer_analysis ca) as top_customers
        """
        
        self.env.self.env.cr.execute(query, (
            date_from, date_to, tuple(company_ids),
            date_from, date_to, tuple(company_ids)
        ))
        
        result = self.env.cr.fetchone()
        monthly_data = json.loads(result[0] or '[]')
        top_customers = json.loads(result[1] or '[]')
        
        # Análisis de tendencias
        revenue_trend = self._analyze_trend([m['revenue'] for m in monthly_data])
        
        # Predicción simple usando promedio móvil
        if len(monthly_data) >= 3:
            last_3_months = [m['revenue'] for m in monthly_data[-3:]]
            predicted_next = sum(last_3_months) / 3 * 1.05  # Factor de crecimiento 5%
        else:
            predicted_next = 0
            
        return {
            'summary': {
                'total_revenue': sum(m['revenue'] for m in monthly_data),
                'avg_monthly': sum(m['revenue'] for m in monthly_data) / len(monthly_data) if monthly_data else 0,
                'total_customers': len(set(c['partner_id'] for c in top_customers)),
                'avg_customer_value': sum(c['total_revenue'] for c in top_customers) / len(top_customers) if top_customers else 0
            },
            'monthly_breakdown': monthly_data,
            'top_customers': top_customers,
            'trend_analysis': revenue_trend,
            'prediction': {
                'next_month': predicted_next,
                'confidence': 'medium' if len(monthly_data) >= 6 else 'low'
            },
            'by_category': self._get_revenue_by_category(date_from, date_to, company_ids)
        }
    
    # ========================================================================
    # ANÁLISIS DE GASTOS
    # ========================================================================
    
    def _get_expense_analysis(self, date_from, date_to, company_ids):
        """Análisis detallado de gastos con categorización."""
        
        query = """
            SELECT 
                CASE 
                    WHEN aa.code LIKE '6%' THEN 'operational'
                    WHEN aa.code LIKE '7%' THEN 'administrative'
                    WHEN aa.code LIKE '8%' THEN 'financial'
                    ELSE 'other'
                END as category,
                aa.name as account_name,
                SUM(aml.debit - aml.credit) as amount,
                COUNT(DISTINCT am.id) as transaction_count,
                json_agg(DISTINCT at.name) as tags
            FROM account_move_line aml
            JOIN account_move am ON aml.move_id = am.id
            JOIN account_account aa ON aml.account_id = aa.id
            LEFT JOIN account_account_tag_account_move_line_rel aatml ON aatml.account_move_line_id = aml.id
            LEFT JOIN account_account_tag at ON aatml.account_account_tag_id = at.id
            WHERE am.state = 'posted'
                AND am.date BETWEEN %s AND %s
                AND am.company_id IN %s
                AND aa.account_type IN ('expense', 'expense_depreciation', 'expense_direct_cost')
            GROUP BY category, aa.name
            ORDER BY amount DESC
        """
        
        self.env.self.env.cr.execute(query, (date_from, date_to, tuple(company_ids)))
        expenses = self.env.cr.dictfetchall()
        
        # Agrupar por categoría
        by_category = defaultdict(lambda: {'total': 0, 'accounts': []})
        total_expenses = 0
        
        for expense in expenses:
            category = expense['category']
            amount = expense['amount']
            by_category[category]['total'] += amount
            by_category[category]['accounts'].append({
                'name': expense['account_name'],
                'amount': amount,
                'transactions': expense['transaction_count'],
                'tags': json.loads(expense['tags'] or '[]')
            })
            total_expenses += amount
            
        # Calcular porcentajes
        for category, data in by_category.items():
            data['percentage'] = round((data['total'] / total_expenses * 100) if total_expenses else 0, 1)
            data['accounts'].sort(key=lambda x: x['amount'], reverse=True)
            data['accounts'] = data['accounts'][:5]  # Top 5 por categoría
            
        # Análisis de variación
        variation_analysis = self._analyze_expense_variation(date_from, date_to, company_ids)
        
        return {
            'total': total_expenses,
            'by_category': dict(by_category),
            'variation_analysis': variation_analysis,
            'cost_reduction_opportunities': self._identify_cost_reduction(expenses, total_expenses),
            'budget_comparison': self._compare_with_budget(date_from, date_to, company_ids)
        }
    
    # ========================================================================
    # PROYECCIÓN DE FLUJO DE CAJA
    # ========================================================================
    
    def _get_cashflow_projection(self, company_ids):
        """Proyección de flujo de caja para los próximos 3 meses."""
        
        today = fields.Date.today()
        projections = []
        
        for i in range(3):  # Próximos 3 meses
            month_start = today + relativedelta(months=i, day=1)
            month_end = today + relativedelta(months=i+1, day=1) - timedelta(days=1)
            
            # Ingresos proyectados (basados en promedio histórico)
            projected_income = self._project_monthly_income(month_start, company_ids)
            
            # Gastos proyectados
            projected_expenses = self._project_monthly_expenses(month_start, company_ids)
            
            # Cobros pendientes
            pending_collections = self._get_pending_collections(month_start, month_end, company_ids)
            
            # Pagos pendientes
            pending_payments = self._get_pending_payments(month_start, month_end, company_ids)
            
            net_cashflow = projected_income + pending_collections - projected_expenses - pending_payments
            
            projections.append({
                'period': month_start.strftime('%Y-%m'),
                'projected_income': projected_income,
                'projected_expenses': projected_expenses,
                'pending_collections': pending_collections,
                'pending_payments': pending_payments,
                'net_cashflow': net_cashflow,
                'accumulated': sum(p['net_cashflow'] for p in projections) + net_cashflow
            })
            
        # Análisis de liquidez
        current_cash = self._get_current_cash_balance(company_ids)
        
        return {
            'current_balance': current_cash,
            'projections': projections,
            'liquidity_analysis': {
                'months_of_cash': self._calculate_months_of_cash(current_cash, projections),
                'minimum_cash_date': self._find_minimum_cash_date(current_cash, projections),
                'requires_financing': any(current_cash + p['accumulated'] < 0 for p in projections)
            },
            'recommendations': self._generate_cashflow_recommendations(current_cash, projections)
        }
    
    # ========================================================================
    # CUMPLIMIENTO TRIBUTARIO
    # ========================================================================
    
    def _get_tax_compliance_status(self, date_from, date_to, company_ids):
        """Estado de cumplimiento tributario."""
        
        status = {
            'f29_status': self._check_f29_compliance(date_from, date_to, company_ids),
            'f22_status': self._check_f22_compliance(company_ids),
            'dte_status': self._check_dte_compliance(date_from, date_to, company_ids),
            'rcv_status': self._check_rcv_compliance(date_from, date_to, company_ids),
            'pending_declarations': [],
            'upcoming_deadlines': [],
            'compliance_score': 100
        }
        
        # Verificar declaraciones pendientes
        today = fields.Date.today()
        
        # F29 del mes anterior
        if today.day > 20:  # Después del día 20, verificar F29 del mes actual
            f29_period = today.strftime('%Y-%m')
            f29_exists = self.env['l10n_cl.f29'].search([
                ('period_date', '=', today.replace(day=1)),
                ('company_id', 'in', company_ids),
                ('state', 'in', ['validated', 'sent', 'accepted'])
            ], limit=1)
            
            if not f29_exists:
                status['pending_declarations'].append({
                    'type': 'F29',
                    'period': f29_period,
                    'deadline': (today + relativedelta(months=1, day=1) - timedelta(days=1)).isoformat(),
                    'priority': 'high'
                })
                status['compliance_score'] -= 20
                
        # Próximos vencimientos
        next_month = today + relativedelta(months=1)
        status['upcoming_deadlines'] = [
            {
                'type': 'F29',
                'period': next_month.strftime('%Y-%m'),
                'deadline': (next_month + relativedelta(day=20)).isoformat()
            }
        ]
        
        if today.month == 3:  # Marzo - declaración F22
            status['upcoming_deadlines'].append({
                'type': 'F22',
                'period': str(today.year - 1),
                'deadline': f"{today.year}-04-30"
            })
            
        return status
    
    # ========================================================================
    # ANÁLISIS DE TENDENCIAS
    # ========================================================================
    
    def _get_financial_trends(self, date_from, date_to, company_ids):
        """Análisis de tendencias financieras."""
        
        # Obtener datos históricos (últimos 12 meses)
        historical_start = date_from - relativedelta(months=12)
        
        query = """
            SELECT 
                DATE_TRUNC('month', am.date) as period,
                SUM(CASE WHEN aa.account_type IN ('income', 'income_other') 
                    THEN aml.credit - aml.debit ELSE 0 END) as revenue,
                SUM(CASE WHEN aa.account_type IN ('expense', 'expense_depreciation', 'expense_direct_cost') 
                    THEN aml.debit - aml.credit ELSE 0 END) as expenses,
                COUNT(DISTINCT CASE WHEN am.move_type IN ('out_invoice', 'out_refund') 
                    THEN am.partner_id END) as customers,
                AVG(CASE WHEN am.move_type = 'out_invoice' 
                    THEN am.amount_total END) as avg_invoice_value
            FROM account_move_line aml
            JOIN account_move am ON aml.move_id = am.id
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE am.state = 'posted'
                AND am.date BETWEEN %s AND %s
                AND am.company_id IN %s
            GROUP BY DATE_TRUNC('month', am.date)
            ORDER BY period
        """
        
        self.env.self.env.cr.execute(query, (historical_start, date_to, tuple(company_ids)))
        monthly_data = self.env.cr.dictfetchall()
        
        if len(monthly_data) < 3:
            return {'status': 'insufficient_data'}
            
        # Calcular tendencias
        revenue_trend = self._calculate_trend_metrics([m['revenue'] for m in monthly_data])
        expense_trend = self._calculate_trend_metrics([m['expenses'] for m in monthly_data])
        margin_trend = self._calculate_trend_metrics([
            (m['revenue'] - m['expenses']) / m['revenue'] * 100 if m['revenue'] else 0 
            for m in monthly_data
        ])
        
        # Estacionalidad
        seasonality = self._analyze_seasonality(monthly_data)
        
        return {
            'revenue_trend': revenue_trend,
            'expense_trend': expense_trend,
            'margin_trend': margin_trend,
            'seasonality': seasonality,
            'growth_indicators': {
                'revenue_growth_rate': revenue_trend['growth_rate'],
                'expense_growth_rate': expense_trend['growth_rate'],
                'customer_growth': self._calculate_customer_growth(monthly_data),
                'avg_transaction_growth': self._calculate_transaction_value_growth(monthly_data)
            },
            'projections': {
                'next_3_months': self._project_next_months(monthly_data, 3),
                'confidence': self._calculate_projection_confidence(monthly_data)
            }
        }
    
    # ========================================================================
    # ALERTAS FINANCIERAS
    # ========================================================================
    
    def _get_financial_alerts(self, company_ids):
        """Genera alertas financieras basadas en umbrales y tendencias."""
        
        alerts = []
        today = fields.Date.today()
        
        # 1. Alertas de liquidez
        cash_balance = self._get_current_cash_balance(company_ids)
        monthly_expenses = self._get_average_monthly_expenses(company_ids)
        
        if cash_balance < monthly_expenses * 2:
            alerts.append({
                'type': 'liquidity',
                'severity': 'high' if cash_balance < monthly_expenses else 'medium',
                'message': _('Liquidez baja: %.1f meses de gastos en caja') % (cash_balance / monthly_expenses if monthly_expenses else 0),
                'recommendation': _('Considerar acelerar cobros o línea de crédito'),
                'metrics': {
                    'cash_balance': cash_balance,
                    'monthly_expenses': monthly_expenses
                }
            })
            
        # 2. Alertas de cobros
        overdue_receivables = self._get_overdue_receivables(company_ids)
        if overdue_receivables > 0:
            alerts.append({
                'type': 'receivables',
                'severity': 'medium',
                'message': _('Cobros vencidos: %s') % format_amount(self.env, overdue_receivables, self.env.company.currency_id),
                'recommendation': _('Revisar gestión de cobranza'),
                'metrics': {
                    'overdue_amount': overdue_receivables,
                    'overdue_invoices': self._count_overdue_invoices(company_ids)
                }
            })
            
        # 3. Alertas de margen
        current_margin = self._get_current_margin(today - timedelta(days=30), today, company_ids)
        if current_margin < 10:  # Margen menor a 10%
            alerts.append({
                'type': 'profitability',
                'severity': 'high',
                'message': _('Margen bajo: %.1f%%') % current_margin,
                'recommendation': _('Revisar estructura de costos'),
                'metrics': {
                    'current_margin': current_margin,
                    'target_margin': 15
                }
            })
            
        # 4. Alertas tributarias
        tax_alerts = self._get_tax_alerts(company_ids)
        alerts.extend(tax_alerts)
        
        # 5. Alertas de tendencia
        trend_alerts = self._get_trend_alerts(company_ids)
        alerts.extend(trend_alerts)
        
        # Ordenar por severidad
        severity_order = {'high': 0, 'medium': 1, 'low': 2}
        alerts.sort(key=lambda x: severity_order.get(x['severity'], 3))
        
        return alerts
    
    # ========================================================================
    # COMPARACIONES DE PERÍODO
    # ========================================================================
    
    def _get_period_comparisons(self, date_from, date_to, company_ids):
        """Compara el período actual con períodos anteriores."""
        
        # Calcular duración del período
        days = (date_to - date_from).days + 1
        
        # Período anterior inmediato
        prev_date_to = date_from - timedelta(days=1)
        prev_date_from = prev_date_to - timedelta(days=days-1)
        
        # Mismo período año anterior
        year_ago_from = date_from - relativedelta(years=1)
        year_ago_to = date_to - relativedelta(years=1)
        
        # Obtener métricas para cada período
        current = self._get_period_metrics(date_from, date_to, company_ids)
        previous = self._get_period_metrics(prev_date_from, prev_date_to, company_ids)
        year_ago = self._get_period_metrics(year_ago_from, year_ago_to, company_ids)
        
        # Calcular variaciones
        comparisons = {
            'vs_previous_period': {
                'revenue': self._calculate_variation(current['revenue'], previous['revenue']),
                'expenses': self._calculate_variation(current['expenses'], previous['expenses']),
                'profit': self._calculate_variation(current['profit'], previous['profit']),
                'margin': self._calculate_variation(current['margin'], previous['margin']),
                'customers': self._calculate_variation(current['customers'], previous['customers'])
            },
            'vs_year_ago': {
                'revenue': self._calculate_variation(current['revenue'], year_ago['revenue']),
                'expenses': self._calculate_variation(current['expenses'], year_ago['expenses']),
                'profit': self._calculate_variation(current['profit'], year_ago['profit']),
                'margin': self._calculate_variation(current['margin'], year_ago['margin']),
                'customers': self._calculate_variation(current['customers'], year_ago['customers'])
            },
            'performance_index': self._calculate_performance_index(current, previous, year_ago),
            'best_performing_areas': self._identify_best_performers(current, previous),
            'areas_of_concern': self._identify_concerns(current, previous)
        }
        
        return comparisons
    
    # ========================================================================
    # PROYECCIONES FINANCIERAS
    # ========================================================================
    
    def _get_financial_projections(self, date_from, date_to, company_ids):
        """Genera proyecciones financieras usando análisis predictivo."""
        
        # Usar ML si está disponible
        ml_available = self._check_ml_availability()
        
        if ml_available:
            projections = self._get_ml_projections(date_from, date_to, company_ids)
        else:
            projections = self._get_statistical_projections(date_from, date_to, company_ids)
            
        # Agregar análisis de escenarios
        projections['scenarios'] = {
            'optimistic': self._apply_scenario(projections['base'], 1.15),  # +15%
            'base': projections['base'],
            'pessimistic': self._apply_scenario(projections['base'], 0.85)  # -15%
        }
        
        # Análisis de sensibilidad
        projections['sensitivity'] = self._sensitivity_analysis(projections['base'])
        
        # Recomendaciones
        projections['recommendations'] = self._generate_projection_recommendations(projections)
        
        return projections
    
    # ========================================================================
    # MÉTODOS AUXILIARES - CÁLCULOS
    # ========================================================================
    
    def _analyze_trend(self, values):
        """Analiza tendencia de una serie de valores."""
        if len(values) < 2:
            return {'direction': 'stable', 'strength': 0}
            
        # Calcular pendiente simple
        n = len(values)
        if n == 0:
            return {'direction': 'stable', 'strength': 0}
            
        x_mean = sum(range(n)) / n
        y_mean = sum(values) / n
        
        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return {'direction': 'stable', 'strength': 0}
            
        slope = numerator / denominator
        
        # Determinar dirección y fuerza
        if abs(slope) < 0.01:
            direction = 'stable'
        elif slope > 0:
            direction = 'up'
        else:
            direction = 'down'
            
        # Fuerza de la tendencia (0-100)
        strength = min(100, abs(slope) * 10)
        
        return {
            'direction': direction,
            'strength': round(strength, 1),
            'slope': round(slope, 4)
        }
    
    def _calculate_trend_metrics(self, values):
        """Calcula métricas de tendencia detalladas."""
        if len(values) < 2:
            return {'status': 'insufficient_data'}
            
        trend = self._analyze_trend(values)
        
        # Calcular tasa de crecimiento
        if values[0] != 0:
            growth_rate = ((values[-1] - values[0]) / values[0]) * 100
        else:
            growth_rate = 0
            
        # Volatilidad (desviación estándar)
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        volatility = variance ** 0.5
        
        return {
            'direction': trend['direction'],
            'strength': trend['strength'],
            'growth_rate': round(growth_rate, 1),
            'volatility': round(volatility, 2),
            'coefficient_variation': round((volatility / mean * 100) if mean else 0, 1)
        }
    
    def _get_revenue_by_category(self, date_from, date_to, company_ids):
        """Obtiene ingresos agrupados por categoría."""
        query = """
            SELECT 
                COALESCE(pc.name, 'Sin categoría') as category,
                SUM(aml.credit - aml.debit) as amount,
                COUNT(DISTINCT am.partner_id) as customers
            FROM account_move_line aml
            JOIN account_move am ON aml.move_id = am.id
            JOIN account_account aa ON aml.account_id = aa.id
            LEFT JOIN res_partner rp ON am.partner_id = rp.id
            LEFT JOIN res_partner_category_rel pcr ON pcr.partner_id = rp.id
            LEFT JOIN res_partner_category pc ON pcr.category_id = pc.id
            WHERE am.state = 'posted'
                AND am.date BETWEEN %s AND %s
                AND am.company_id IN %s
                AND aa.account_type IN ('income', 'income_other')
            GROUP BY pc.name
            ORDER BY amount DESC
        """
        
        self.env.self.env.cr.execute(query, (date_from, date_to, tuple(company_ids)))
        return self.env.cr.dictfetchall()
    
    def _get_period_metrics(self, date_from, date_to, company_ids):
        """Obtiene métricas básicas de un período."""
        query = """
            SELECT 
                SUM(CASE WHEN aa.account_type IN ('income', 'income_other') 
                    THEN aml.credit - aml.debit ELSE 0 END) as revenue,
                SUM(CASE WHEN aa.account_type IN ('expense', 'expense_depreciation', 'expense_direct_cost') 
                    THEN aml.debit - aml.credit ELSE 0 END) as expenses,
                COUNT(DISTINCT CASE WHEN am.move_type IN ('out_invoice', 'out_refund') 
                    THEN am.partner_id END) as customers
            FROM account_move_line aml
            JOIN account_move am ON aml.move_id = am.id
            JOIN account_account aa ON aml.account_id = aa.id
            WHERE am.state = 'posted'
                AND am.date BETWEEN %s AND %s
                AND am.company_id IN %s
        """
        
        self.env.self.env.cr.execute(query, (date_from, date_to, tuple(company_ids)))
        result = self.env.cr.fetchone()
        
        revenue = result[0] or 0
        expenses = result[1] or 0
        profit = revenue - expenses
        margin = (profit / revenue * 100) if revenue else 0
        
        return {
            'revenue': revenue,
            'expenses': expenses,
            'profit': profit,
            'margin': margin,
            'customers': result[2] or 0
        }
    
    def _calculate_variation(self, current, previous):
        """Calcula variación porcentual entre dos valores."""
        if previous == 0:
            return {'value': 0, 'percentage': 0, 'trend': 'stable'}
            
        variation = current - previous
        percentage = (variation / previous) * 100
        
        if abs(percentage) < 1:
            trend = 'stable'
        elif percentage > 0:
            trend = 'up'
        else:
            trend = 'down'
            
        return {
            'value': round(variation, 2),
            'percentage': round(percentage, 1),
            'trend': trend
        }
    
    # ========================================================================
    # MÉTODOS DE CACHE
    # ========================================================================
    
    def _get_from_cache(self, key):
        """
        Obtiene valor del cache si existe.

        Note: Cache delegado a @tools.ormcache en métodos específicos.
        Este método se mantiene por compatibilidad pero retorna None.
        Usar decorador @tools.ormcache en métodos compute_* para cache real.
        """
        # Cache architecture: usar @tools.ormcache en métodos compute
        # Ver docs/architecture/ARQUITECTURA_CACHE.md
        return None

    def _save_to_cache(self, key, value, timeout=None):
        """
        Guarda valor en cache.

        Note: Cache delegado a @tools.ormcache en métodos específicos.
        Este método se mantiene por compatibilidad pero no hace nada.
        Usar decorador @tools.ormcache en métodos compute_* para cache real.
        """
        # Cache architecture: usar @tools.ormcache en métodos compute
        # Ver docs/architecture/ARQUITECTURA_CACHE.md
        pass
    
    # ========================================================================
    # MÉTODOS PÚBLICOS ADICIONALES
    # ========================================================================
    
    @api.model
    def get_dashboard_widgets(self, widget_ids=None):
        """Obtiene datos para widgets específicos del dashboard."""
        if not widget_ids:
            widget_ids = ['revenue', 'expenses', 'cashflow', 'kpis']
            
        widgets = {}
        today = fields.Date.today()
        month_start = today.replace(day=1)
        
        for widget_id in widget_ids:
            if widget_id == 'revenue':
                widgets[widget_id] = self._get_revenue_widget(month_start, today)
            elif widget_id == 'expenses':
                widgets[widget_id] = self._get_expense_widget(month_start, today)
            elif widget_id == 'cashflow':
                widgets[widget_id] = self._get_cashflow_widget()
            elif widget_id == 'kpis':
                widgets[widget_id] = self._get_kpi_widget()
                
        return widgets
    
    @api.model
    def export_dashboard_data(self, date_from, date_to, format='xlsx'):
        """Exporta datos del dashboard en formato solicitado."""
        data = self.get_executive_dashboard(date_from, date_to)
        
        if format == 'xlsx':
            return self._export_to_excel(data)
        elif format == 'pdf':
            return self._export_to_pdf(data)
        elif format == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            raise ValidationError(_("Formato no soportado: %s") % format)