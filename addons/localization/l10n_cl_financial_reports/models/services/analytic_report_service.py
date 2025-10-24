# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
import logging
from collections import defaultdict

_logger = logging.getLogger(__name__)


class AnalyticReportService(models.Model):
    """Servicio para reportes de contabilidad analítica avanzados"""
    
    _name = 'analytic.report.service'
    _description = 'Servicio de Reportes Analíticos'
    
    @api.model
    def get_analytic_report_data(self, analytic_account_ids, date_from, date_to, 
                                 include_timesheet=True, group_by_account=True,
                                 include_child_accounts=True):
        """
        Obtiene datos detallados de cuentas analíticas con apertura por cuentas contables
        
        :param analytic_account_ids: Lista de IDs de cuentas analíticas
        :param date_from: Fecha inicio
        :param date_to: Fecha fin
        :param include_timesheet: Incluir costos de HH desde timesheet
        :param group_by_account: Agrupar por cuenta contable
        :param include_child_accounts: Incluir cuentas hijas
        :return: Diccionario con datos del reporte
        """
        try:
            # Expandir para incluir cuentas hijas si es necesario
            if include_child_accounts:
                analytic_account_ids = self._get_analytic_accounts_with_children(analytic_account_ids)
            
            # Obtener movimientos analíticos
            analytic_lines = self._get_analytic_lines(
                analytic_account_ids, date_from, date_to
            )
            
            # Obtener costos de timesheet si está habilitado
            timesheet_costs = {}
            if include_timesheet:
                timesheet_costs = self._get_timesheet_costs(
                    analytic_account_ids, date_from, date_to
                )
            
            # Procesar y agrupar datos
            report_data = self._process_analytic_data(
                analytic_lines, timesheet_costs, group_by_account
            )
            
            # Calcular totales y KPIs
            totals = self._calculate_totals_and_kpis(report_data)
            
            return {
                'success': True,
                'data': report_data,
                'totals': totals,
                'filters': {
                    'date_from': date_from,
                    'date_to': date_to,
                    'analytic_accounts': self._get_analytic_accounts_info(analytic_account_ids),
                    'include_timesheet': include_timesheet,
                    'group_by_account': group_by_account
                }
            }
            
        except Exception as e:
            _logger.error(f"Error generando reporte analítico: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_analytic_accounts_with_children(self, account_ids):
        """Obtiene cuentas analíticas incluyendo sus hijas"""
        accounts = self.env['account.analytic.account'].browse(account_ids)
        all_accounts = accounts
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for account in accounts:
            # Buscar todas las cuentas hijas
            children = self.env['account.analytic.account'].search([
                ('id', 'child_of', account.id),
                ('id', '!=', account.id)
            ])
            all_accounts |= children
        
        return all_accounts.ids
    
    def _get_analytic_lines(self, analytic_account_ids, date_from, date_to):
        """Obtiene líneas analíticas con información detallada"""
        query = """
            SELECT 
                aal.id,
                aal.account_id as analytic_account_id,
                aal.general_account_id as account_id,
                aal.name as description,
                aal.date,
                aal.amount,
                aal.unit_amount,
                aal.product_uom_id,
                aal.partner_id,
                aal.move_id,
                aa.name as analytic_account_name,
                aa.code as analytic_account_code,
                ac.code as account_code,
                ac.name as account_name,
                COALESCE(rp.name, '') as partner_name,
                am.name as move_name,
                aat.name as tag_name
            FROM account_analytic_line aal
            JOIN account_analytic_account aa ON aal.account_id = aa.id
            LEFT JOIN account_account ac ON aal.general_account_id = ac.id
            LEFT JOIN res_partner rp ON aal.partner_id = rp.id
            LEFT JOIN account_move am ON aal.move_id = am.id
            LEFT JOIN account_analytic_line_tag_rel aaltr ON aal.id = aaltr.line_id
            LEFT JOIN account_analytic_tag aat ON aaltr.tag_id = aat.id
            WHERE aal.account_id IN %s
                AND aal.date >= %s
                AND aal.date <= %s
            ORDER BY aa.code, ac.code, aal.date
        """
        
        self.env.self.env.self.env.cr.execute(query, (tuple(analytic_account_ids), date_from, date_to))
        return self.env.cr.dictfetchall()
    
    def _get_timesheet_costs(self, analytic_account_ids, date_from, date_to):
        """Obtiene costos de HH desde timesheet"""
        query = """
            SELECT 
                aal.account_id as analytic_account_id,
                aal.employee_id,
                he.name as employee_name,
                SUM(aal.unit_amount) as total_hours,
                AVG(he.timesheet_cost) as hourly_cost,
                SUM(aal.unit_amount * he.timesheet_cost) as total_cost,
                COUNT(DISTINCT aal.date) as days_worked,
                MIN(aal.date) as first_date,
                MAX(aal.date) as last_date
            FROM account_analytic_line aal
            JOIN hr_employee he ON aal.employee_id = he.id
            WHERE aal.account_id IN %s
                AND aal.date >= %s
                AND aal.date <= %s
                AND aal.project_id IS NOT NULL
            GROUP BY aal.account_id, aal.employee_id, he.name, he.timesheet_cost
        """
        
        self.env.self.env.self.env.cr.execute(query, (tuple(analytic_account_ids), date_from, date_to))
        
        # Organizar por cuenta analítica
        timesheet_by_account = defaultdict(list)
        for row in self.env.cr.dictfetchall():
            timesheet_by_account[row['analytic_account_id']].append(row)
        
        return dict(timesheet_by_account)
    
    def _process_analytic_data(self, analytic_lines, timesheet_costs, group_by_account):
        """Procesa y agrupa datos analíticos"""
        data = defaultdict(lambda: {
            'lines': [],
            'accounts': defaultdict(lambda: {
                'debit': 0.0,
                'credit': 0.0,
                'balance': 0.0,
                'lines': []
            }),
            'timesheet': {
                'total_hours': 0.0,
                'total_cost': 0.0,
                'employees': []
            },
            'totals': {
                'debit': 0.0,
                'credit': 0.0,
                'balance': 0.0
            }
        })
        
        # Procesar líneas analíticas
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for line in analytic_lines:
            analytic_id = line['analytic_account_id']
            account_code = line['account_code'] or 'SIN_CUENTA'
            
            # Determinar débito/crédito
            amount = line['amount'] or 0.0
            debit = amount if amount > 0 else 0.0
            credit = -amount if amount < 0 else 0.0
            
            line_data = {
                'id': line['id'],
                'date': line['date'],
                'description': line['description'],
                'partner': line['partner_name'],
                'move': line['move_name'],
                'debit': debit,
                'credit': credit,
                'balance': amount,
                'account_code': account_code,
                'account_name': line['account_name'],
                'tag': line['tag_name']
            }
            
            # Agregar a la estructura de datos
            data[analytic_id]['analytic_account_name'] = line['analytic_account_name']
            data[analytic_id]['analytic_account_code'] = line['analytic_account_code']
            data[analytic_id]['lines'].append(line_data)
            
            if group_by_account:
                data[analytic_id]['accounts'][account_code]['debit'] += debit
                data[analytic_id]['accounts'][account_code]['credit'] += credit
                data[analytic_id]['accounts'][account_code]['balance'] += amount
                data[analytic_id]['accounts'][account_code]['name'] = line['account_name']
                data[analytic_id]['accounts'][account_code]['lines'].append(line_data)
            
            # Actualizar totales
            data[analytic_id]['totals']['debit'] += debit
            data[analytic_id]['totals']['credit'] += credit
            data[analytic_id]['totals']['balance'] += amount
        
        # Agregar costos de timesheet
        for analytic_id, timesheet_list in timesheet_costs.items():
            if analytic_id in data:
                total_hours = sum(t['total_hours'] for t in timesheet_list)
                total_cost = sum(t['total_cost'] for t in timesheet_list)
                
                data[analytic_id]['timesheet'] = {
                    'total_hours': total_hours,
                    'total_cost': total_cost,
                    'employees': timesheet_list,
                    'average_hourly_cost': total_cost / total_hours if total_hours > 0 else 0
                }
        
        return dict(data)
    
    def _calculate_totals_and_kpis(self, report_data):
        """Calcula totales generales y KPIs del proyecto"""
        totals = {
            'total_debit': 0.0,
            'total_credit': 0.0,
            'total_balance': 0.0,
            'total_timesheet_hours': 0.0,
            'total_timesheet_cost': 0.0,
            'project_count': len(report_data),
            'kpis': {}
        }
        
        for analytic_id, data in report_data.items():
            totals['total_debit'] += data['totals']['debit']
            totals['total_credit'] += data['totals']['credit']
            totals['total_balance'] += data['totals']['balance']
            totals['total_timesheet_hours'] += data['timesheet']['total_hours']
            totals['total_timesheet_cost'] += data['timesheet']['total_cost']
        
        # Calcular KPIs
        if totals['total_timesheet_hours'] > 0:
            totals['kpis']['average_hourly_cost'] = (
                totals['total_timesheet_cost'] / totals['total_timesheet_hours']
            )
        
        if totals['total_credit'] > 0:
            totals['kpis']['profit_margin'] = (
                (totals['total_credit'] - totals['total_debit']) / totals['total_credit'] * 100
            )
        
        totals['kpis']['cost_per_project'] = (
            totals['total_debit'] / totals['project_count'] 
            if totals['project_count'] > 0 else 0
        )
        
        return totals
    
    def _get_analytic_accounts_info(self, account_ids):
        """Obtiene información de las cuentas analíticas"""
        # Optimización: usar with_context para prefetch
        acc = acc.with_context(prefetch_fields=False)

        accounts = self.env['account.analytic.account'].browse(account_ids)
        return [{
            'id': acc.id,
            'name': acc.name,
            'code': acc.code,
            'partner_id': acc.partner_id.id if acc.partner_id else False,
            'partner_name': acc.partner_id.name if acc.partner_id else ''
        } for acc in accounts]
    
    @api.model
    def get_project_dashboard_data(self, analytic_account_ids=None, months=6):
        """
        Obtiene datos para dashboard de proyectos
        
        :param analytic_account_ids: IDs de cuentas analíticas (None = todas)
        :param months: Número de meses hacia atrás
        :return: Datos para dashboard
        """
        date_to = fields.Date.today()
        date_from = date_to - relativedelta(months=months)
        
        if not analytic_account_ids:
            # Obtener proyectos activos
            analytic_account_ids = self.env['account.analytic.account'].search([
                ('active', '=', True)
            ]).ids
        
        # Obtener datos del reporte
        report_data = self.get_analytic_report_data(
            analytic_account_ids, 
            date_from.strftime('%Y-%m-%d'),
            date_to.strftime('%Y-%m-%d'),
            include_timesheet=True,
            group_by_account=True
        )
        
        if not report_data['success']:
            return report_data
        
        # Procesar para dashboard
        dashboard_data = {
            'project_summary': self._get_project_summary(report_data['data']),
            'monthly_evolution': self._get_monthly_evolution(analytic_account_ids, months),
            'cost_breakdown': self._get_cost_breakdown(report_data['data']),
            'efficiency_metrics': self._get_efficiency_metrics(report_data['data']),
            'top_projects': self._get_top_projects(report_data['data'], limit=10)
        }
        
        return {
            'success': True,
            'data': dashboard_data,
            'totals': report_data['totals']
        }
    
    def _get_project_summary(self, data):
        """Resumen de proyectos para dashboard"""
        summary = []
        
        for analytic_id, project_data in data.items():
            revenue = project_data['totals']['credit']
            costs = project_data['totals']['debit']
            margin = revenue - costs
            margin_percent = (margin / revenue * 100) if revenue > 0 else 0
            
            summary.append({
                'id': analytic_id,
                'name': project_data['analytic_account_name'],
                'code': project_data['analytic_account_code'],
                'revenue': revenue,
                'costs': costs,
                'margin': margin,
                'margin_percent': margin_percent,
                'hours': project_data['timesheet']['total_hours'],
                'timesheet_cost': project_data['timesheet']['total_cost'],
                'status': 'profitable' if margin > 0 else 'loss'
            })
        
        # Ordenar por margen
        summary.sort(key=lambda x: x['margin'], reverse=True)
        
        return summary
    
    def _get_monthly_evolution(self, analytic_account_ids, months):
        """Evolución mensual de costos e ingresos"""
        evolution = []
        date_to = fields.Date.today()
        
        for i in range(months):
            month_end = date_to - relativedelta(months=i)
            month_start = month_end.replace(day=1)
            
            # Consulta para obtener totales del mes
            query = """
                SELECT 
                    COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as revenue,
                    COALESCE(SUM(CASE WHEN amount < 0 THEN -amount ELSE 0 END), 0) as costs
                FROM account_analytic_line
                WHERE account_id IN %s
                    AND date >= %s
                    AND date <= %s
            """
            
            self.env.self.env.self.env.cr.execute(query, (
                tuple(analytic_account_ids),
                month_start,
                month_end
            ))
            
            result = self.env.cr.dictfetchone()
            
            evolution.append({
                'month': month_start.strftime('%B %Y'),
                'revenue': result['revenue'],
                'costs': result['costs'],
                'margin': result['revenue'] - result['costs']
            })
        
        evolution.reverse()  # Orden cronológico
        return evolution
    
    def _get_cost_breakdown(self, data):
        """Desglose de costos por categoría"""
        breakdown = defaultdict(float)
        
        for project_data in data.values():
            for account_code, account_data in project_data['accounts'].items():
                if account_data['debit'] > 0:
                    account_name = account_data.get('name', account_code)
                    breakdown[account_name] += account_data['debit']
        
        # Convertir a lista y ordenar
        breakdown_list = [
            {'category': k, 'amount': v} 
            for k, v in breakdown.items()
        ]
        breakdown_list.sort(key=lambda x: x['amount'], reverse=True)
        
        # Tomar top 10 y agrupar el resto
        if len(breakdown_list) > 10:
            top_10 = breakdown_list[:10]
            others_amount = sum(item['amount'] for item in breakdown_list[10:])
            if others_amount > 0:
                top_10.append({'category': 'Otros', 'amount': others_amount})
            return top_10
        
        return breakdown_list
    
    def _get_efficiency_metrics(self, data):
        """Métricas de eficiencia del proyecto"""
        total_projects = len(data)
        profitable_projects = sum(
            1 for p in data.values() 
            if p['totals']['balance'] < 0  # Balance negativo = ganancia
        )
        
        total_hours = sum(p['timesheet']['total_hours'] for p in data.values())
        total_revenue = sum(p['totals']['credit'] for p in data.values())
        
        return {
            'total_projects': total_projects,
            'profitable_projects': profitable_projects,
            'profitability_rate': (profitable_projects / total_projects * 100) if total_projects > 0 else 0,
            'revenue_per_hour': (total_revenue / total_hours) if total_hours > 0 else 0,
            'average_project_duration': total_hours / total_projects if total_projects > 0 else 0
        }
    
    def _get_top_projects(self, data, limit=10):
        """Top proyectos por margen"""
        projects = []
        
        for analytic_id, project_data in data.items():
            revenue = project_data['totals']['credit']
            costs = project_data['totals']['debit']
            margin = revenue - costs
            
            projects.append({
                'id': analytic_id,
                'name': project_data['analytic_account_name'],
                'code': project_data['analytic_account_code'],
                'revenue': revenue,
                'costs': costs,
                'margin': margin,
                'hours': project_data['timesheet']['total_hours']
            })
        
        # Ordenar por margen y tomar los mejores
        projects.sort(key=lambda x: x['margin'], reverse=True)
        return projects[:limit]
