# -*- coding: utf-8 -*-
"""
Executive Dashboard Service for Chilean Business Intelligence
Provides comprehensive business intelligence metrics and KPIs
"""

from odoo import api, fields, models, _
from odoo.exceptions import UserError
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class ExecutiveDashboardService(models.AbstractModel):
    """
    Service for consolidated executive metrics across Chilean modules.
    Provides a 360° view of business operations integrating DTE, payroll,
    and financial data.
    
    This service follows the Single Responsibility Principle and leverages
    existing services from l10n_cl_base for consistency.
    """
    _name = 'l10n_cl_financial_reports.executive_dashboard_service'
    _description = 'Executive Dashboard Service for Chile'
    
    # ========================================================================
    # CONSOLIDATED METRICS
    # ========================================================================
    
    @api.model
    def get_executive_summary(self, company_id=None, date_from=None, date_to=None):
        """
        Get comprehensive executive summary with key business metrics.
        
        Args:
            company_id: Company ID (default: current company)
            date_from: Start date (default: first day of current month)
            date_to: End date (default: today)
            
        Returns:
            dict: Executive summary with financial, operational, and HR metrics
        """
        if not company_id:
            company_id = self.env.company.id
        
        if not date_from:
            date_from = fields.Date.today().replace(day=1)
        if not date_to:
            date_to = fields.Date.today()
            
        # Note: Cache eliminado - usar @tools.ormcache en métodos _get_*_metrics
        # para cache granular. Ver docs/architecture/ARQUITECTURA_CACHE.md

        try:
            summary = {
                'financial': self._get_financial_metrics(company_id, date_from, date_to),
                'operational': self._get_operational_metrics(company_id, date_from, date_to),
                'hr': self._get_hr_metrics(company_id, date_from, date_to),
                'compliance': self._get_compliance_metrics(company_id, date_from, date_to),
                'alerts': self._get_active_alerts(company_id),
                'generated_at': fields.Datetime.now(),
            }
            
            return summary
            
        except Exception as e:
            _logger.error(f"Error generating executive summary: {str(e)}")
            raise UserError(_("Error generating executive summary: %s") % str(e))
    
    # ========================================================================
    # FINANCIAL METRICS
    # ========================================================================
    
    def _get_financial_metrics(self, company_id, date_from, date_to):
        """Get consolidated financial metrics."""
        self.env.self.env.cr.execute("""
            WITH revenue_data AS (
                SELECT 
                    COALESCE(SUM(amount_total_signed), 0) as total_revenue,
                    COALESCE(AVG(amount_total_signed), 0) as avg_invoice_amount,
                    COUNT(*) as invoice_count
                FROM account_move
                WHERE company_id = %s
                    AND move_type IN ('out_invoice', 'out_refund')
                    AND state = 'posted'
                    AND invoice_date BETWEEN %s AND %s
            ),
            expense_data AS (
                SELECT 
                    COALESCE(SUM(amount_total_signed), 0) as total_expenses
                FROM account_move
                WHERE company_id = %s
                    AND move_type IN ('in_invoice', 'in_refund')
                    AND state = 'posted'
                    AND invoice_date BETWEEN %s AND %s
            ),
            cash_flow AS (
                SELECT 
                    COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as cash_inflow,
                    COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as cash_outflow
                FROM account_bank_statement_line
                WHERE company_id = %s
                    AND date BETWEEN %s AND %s
            )
            SELECT 
                r.total_revenue,
                r.avg_invoice_amount,
                r.invoice_count,
                e.total_expenses,
                c.cash_inflow,
                c.cash_outflow,
                r.total_revenue - e.total_expenses as gross_profit,
                CASE 
                    WHEN r.total_revenue > 0 
                    THEN ((r.total_revenue - e.total_expenses) / r.total_revenue) * 100 
                    ELSE 0 
                END as profit_margin
            FROM revenue_data r, expense_data e, cash_flow c
        """, (company_id, date_from, date_to, company_id, date_from, date_to, company_id, date_from, date_to))
        
        result = self.env.cr.dictfetchone()
        
        # Get previous period for comparison
        prev_date_from = date_from - relativedelta(months=1)
        prev_date_to = date_to - relativedelta(months=1)
        
        prev_metrics = self._get_previous_financial_metrics(company_id, prev_date_from, prev_date_to)
        
        return {
            'revenue': {
                'total': result['total_revenue'],
                'average_invoice': result['avg_invoice_amount'],
                'invoice_count': result['invoice_count'],
                'growth': self._calculate_growth(result['total_revenue'], prev_metrics.get('total_revenue', 0)),
            },
            'expenses': {
                'total': result['total_expenses'],
                'growth': self._calculate_growth(result['total_expenses'], prev_metrics.get('total_expenses', 0)),
            },
            'profitability': {
                'gross_profit': result['gross_profit'],
                'margin': result['profit_margin'],
                'margin_change': result['profit_margin'] - prev_metrics.get('profit_margin', 0),
            },
            'cash_flow': {
                'inflow': result['cash_inflow'],
                'outflow': result['cash_outflow'],
                'net': result['cash_inflow'] - result['cash_outflow'],
            }
        }
    
    # ========================================================================
    # OPERATIONAL METRICS
    # ========================================================================
    
    def _get_operational_metrics(self, company_id, date_from, date_to):
        """Get operational metrics focused on DTE and compliance."""
        # DTE metrics
        dte_metrics = self._get_dte_metrics(company_id, date_from, date_to)
        
        # Collection metrics
        collection_metrics = self._get_collection_metrics(company_id, date_to)
        
        # CAF availability
        caf_status = self._get_caf_availability(company_id)
        
        return {
            'dte': dte_metrics,
            'collections': collection_metrics,
            'caf_status': caf_status,
        }
    
    def _get_dte_metrics(self, company_id, date_from, date_to):
        """Get DTE processing metrics."""
        self.env.self.env.cr.execute("""
            SELECT 
                COUNT(*) as total_dte,
                COUNT(CASE WHEN l10n_cl_dte_status = 'accepted' THEN 1 END) as accepted,
                COUNT(CASE WHEN l10n_cl_dte_status = 'rejected' THEN 1 END) as rejected,
                COUNT(CASE WHEN l10n_cl_dte_status = 'sent' THEN 1 END) as pending,
                CASE 
                    WHEN COUNT(*) > 0 
                    THEN (COUNT(CASE WHEN l10n_cl_dte_status = 'accepted' THEN 1 END) * 100.0 / COUNT(*))
                    ELSE 0 
                END as acceptance_rate
            FROM account_move
            WHERE company_id = %s
                AND move_type IN ('out_invoice', 'out_refund', 'in_invoice', 'in_refund')
                AND l10n_cl_dte_status IS NOT NULL
                AND invoice_date BETWEEN %s AND %s
        """, (company_id, date_from, date_to))
        
        return self.env.cr.dictfetchone()
    
    def _get_caf_availability(self, company_id):
        """Get CAF (folio) availability status."""
        caf_alerts = []
        
        # Check CAF availability for main document types
        doc_types = ['33', '34', '61', '56', '52', '39', '41']  # Main Chilean document types
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for doc_type in doc_types:
            self.env.self.env.cr.execute("""
                SELECT 
                    dt.name as document_type,
                    COALESCE(SUM(c.folios_available), 0) as available,
                    MIN(c.fecha_limite) as next_expiry
                FROM l10n_cl_dte_caf c
                JOIN l10n_latam_document_type dt ON c.l10n_latam_document_type_id = dt.id
                WHERE c.company_id = %s
                    AND dt.code = %s
                    AND c.state = 'in_use'
                    AND c.folios_available > 0
                GROUP BY dt.name
            """, (company_id, doc_type))
            
            result = self.env.cr.dictfetchone()
            if result and result['available'] < 100:
                caf_alerts.append({
                    'type': result['document_type'],
                    'available': result['available'],
                    'expiry': result['next_expiry'],
                    'severity': 'critical' if result['available'] < 50 else 'warning'
                })
        
        return caf_alerts
    
    # ========================================================================
    # HR METRICS
    # ========================================================================
    
    def _get_hr_metrics(self, company_id, date_from, date_to):
        """Get human resources metrics if payroll module is installed."""
        if not self.env['ir.module.module'].search([('name', '=', 'l10n_cl_payroll'), ('state', '=', 'installed')]):
            return {'available': False}
            
        self.env.self.env.cr.execute("""
            SELECT 
                COUNT(DISTINCT e.id) as headcount,
                COUNT(DISTINCT CASE WHEN e.contract_id IS NOT NULL THEN e.id END) as active_contracts,
                COALESCE(SUM(p.net_wage), 0) as total_payroll,
                COALESCE(AVG(p.net_wage), 0) as avg_salary
            FROM hr_employee e
            LEFT JOIN hr_payslip p ON p.employee_id = e.id 
                AND p.state = 'done'
                AND p.date_from >= %s
                AND p.date_to <= %s
            WHERE e.company_id = %s
                AND e.active = true
        """, (date_from, date_to, company_id))
        
        hr_data = self.env.cr.dictfetchone()
        
        return {
            'available': True,
            'headcount': hr_data['headcount'],
            'active_contracts': hr_data['active_contracts'],
            'payroll': {
                'total': hr_data['total_payroll'],
                'average': hr_data['avg_salary'],
            }
        }
    
    # ========================================================================
    # COMPLIANCE METRICS
    # ========================================================================
    
    def _get_compliance_metrics(self, company_id, date_from, date_to):
        """Get tax compliance and regulatory metrics."""
        # F29 status
        f29_status = self._get_f29_compliance_status(company_id)
        
        # Withholding taxes
        withholding_status = self._get_withholding_status(company_id, date_from, date_to)
        
        return {
            'f29': f29_status,
            'withholdings': withholding_status,
            'next_deadlines': self._get_compliance_deadlines(company_id),
        }
    
    def _get_f29_compliance_status(self, company_id):
        """Check F29 tax form compliance."""
        current_period = fields.Date.today().strftime('%Y-%m')
        
        self.env.self.env.cr.execute("""
            SELECT 
                period,
                state,
                total_iva_debito,
                total_iva_credito,
                saldo_a_favor
            FROM l10n_cl_f29
            WHERE company_id = %s
                AND period = %s
            ORDER BY create_date DESC
            LIMIT 1
        """, (company_id, current_period))
        
        f29 = self.env.cr.dictfetchone()
        
        return {
            'current_period': current_period,
            'status': f29['state'] if f29 else 'pending',
            'iva_debito': f29['total_iva_debito'] if f29 else 0,
            'iva_credito': f29['total_iva_credito'] if f29 else 0,
            'balance': f29['saldo_a_favor'] if f29 else 0,
        }
    
    # ========================================================================
    # ALERTS SYSTEM
    # ========================================================================
    
    def _get_active_alerts(self, company_id):
        """Get all active business alerts."""
        alerts = []
        
        # CAF low availability
        caf_alerts = self._get_caf_availability(company_id)
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for caf in caf_alerts:
            if caf['severity'] == 'critical':
                alerts.append({
                    'type': 'caf_critical',
                    'message': f"CAF {caf['type']}: Solo {caf['available']} folios disponibles",
                    'severity': 'critical',
                    'action': 'upload_caf'
                })
        
        # Overdue invoices
        self.env.self.env.cr.execute("""
            SELECT COUNT(*) as overdue_count, SUM(amount_residual) as overdue_amount
            FROM account_move
            WHERE company_id = %s
                AND move_type = 'out_invoice'
                AND payment_state NOT IN ('paid', 'in_payment')
                AND invoice_date_due < %s
        """, (company_id, fields.Date.today()))
        
        overdue = self.env.cr.dictfetchone()
        if overdue['overdue_count'] > 0:
            alerts.append({
                'type': 'overdue_invoices',
                'message': f"{overdue['overdue_count']} facturas vencidas por ${overdue['overdue_amount']:,.0f}",
                'severity': 'warning',
                'action': 'review_collections'
            })
        
        return alerts
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _calculate_growth(self, current, previous):
        """Calculate percentage growth."""
        if previous == 0:
            return 100 if current > 0 else 0
        return ((current - previous) / previous) * 100
    
    def _get_previous_financial_metrics(self, company_id, date_from, date_to):
        """Get financial metrics for previous period (simplified)."""
        self.env.self.env.cr.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN move_type IN ('out_invoice', 'out_refund') THEN amount_total_signed ELSE 0 END), 0) as total_revenue,
                COALESCE(SUM(CASE WHEN move_type IN ('in_invoice', 'in_refund') THEN amount_total_signed ELSE 0 END), 0) as total_expenses
            FROM account_move
            WHERE company_id = %s
                AND state = 'posted'
                AND invoice_date BETWEEN %s AND %s
        """, (company_id, date_from, date_to))
        
        result = self.env.cr.dictfetchone()
        profit_margin = 0
        if result['total_revenue'] > 0:
            profit_margin = ((result['total_revenue'] - result['total_expenses']) / result['total_revenue']) * 100
            
        result['profit_margin'] = profit_margin
        return result
    
    def _get_withholding_status(self, company_id, date_from, date_to):
        """Get withholding tax status."""
        self.env.self.env.cr.execute("""
            SELECT 
                COUNT(*) as total_withholdings,
                SUM(amount_total) as total_amount
            FROM account_move
            WHERE company_id = %s
                AND move_type = 'in_invoice'
                AND l10n_cl_journal_point_of_sale_type = 'boleta_honorarios'
                AND invoice_date BETWEEN %s AND %s
                AND state = 'posted'
        """, (company_id, date_from, date_to))
        
        return self.env.cr.dictfetchone()
    
    def _get_compliance_deadlines(self, company_id):
        """Get upcoming compliance deadlines."""
        today = fields.Date.today()
        deadlines = []
        
        # F29 deadline (20th of next month)
        f29_deadline = (today + relativedelta(months=1)).replace(day=20)
        deadlines.append({
            'type': 'F29',
            'date': f29_deadline,
            'days_remaining': (f29_deadline - today).days,
        })
        
        # Previred deadline (10th of next month)
        if self.env['ir.module.module'].search([('name', '=', 'l10n_cl_payroll'), ('state', '=', 'installed')]):
            previred_deadline = (today + relativedelta(months=1)).replace(day=10)
            deadlines.append({
                'type': 'Previred',
                'date': previred_deadline,
                'days_remaining': (previred_deadline - today).days,
            })
        
        return sorted(deadlines, key=lambda x: x['date'])