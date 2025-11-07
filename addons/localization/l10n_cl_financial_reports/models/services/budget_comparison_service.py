# -*- coding: utf-8 -*-
from odoo import _
from odoo.exceptions import UserError
from datetime import datetime
import logging
import base64
import io

_logger = logging.getLogger(__name__)


class BudgetComparisonService:
    """
    Servicio para cálculo y análisis de comparación presupuestaria.
    Integra con el módulo account_budget de Odoo.
    """
    
    def __init__(self, env):
        self.env = env
        self._cache = {}
        
    def compute_budget_comparison(self, report):
        """
        Calcula la comparación entre presupuesto y real según configuración.
        
        Returns:
            dict: Datos de comparación con líneas y recomendaciones
        """
        try:
            lines_data = []
            
            # Ejecutar según tipo de análisis
            if report.analysis_type == 'by_account':
                lines_data = self._analyze_by_account(report)
            elif report.analysis_type == 'by_budget_post':
                lines_data = self._analyze_by_budget_post(report)
            elif report.analysis_type == 'by_analytic':
                lines_data = self._analyze_by_analytic(report)
            elif report.analysis_type == 'by_department':
                lines_data = self._analyze_by_department(report)
            else:  # consolidated
                lines_data = self._analyze_consolidated(report)
            
            # Generar recomendaciones basadas en el análisis
            recommendations = self._generate_recommendations(lines_data, report)
            
            return {
                'lines': lines_data,
                'recommendations': recommendations
            }
            
        except Exception as e:
            _logger.error(f"Error computing budget comparison: {str(e)}")
            raise UserError(_(
                "Error al calcular la comparación presupuestaria: %s"
            ) % str(e))
    
    def _analyze_by_account(self, report):
        """Análisis por cuenta contable"""
        # Optimización: usar with_context para prefetch
        report = report.with_context(prefetch_fields=False)

        lines = []
        
        # Obtener cuentas con presupuesto
        domain = [('company_id', '=', report.company_id.id)]
        if report.account_ids:
            domain.append(('id', 'in', report.account_ids.ids))
        
        accounts = self.env['account.account'].search(domain, order='code')
        
        # Filtrar solo cuentas que tienen presupuesto asignado
        budget_posts = self.env['account.budget.post'].search([
            ('company_id', '=', report.company_id.id)
        ])
        
        budgeted_accounts = set()
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for post in budget_posts:
            budgeted_accounts.update(post.account_ids.ids)
        
        accounts = accounts.filtered(lambda a: a.id in budgeted_accounts)
        
        # Analizar cada cuenta
        for account in accounts:
            # Obtener presupuesto
            budget_data = self._get_account_budget(
                account.id, report.date_from, report.date_to,
                report.crossovered_budget_id
            )
            
            if not budget_data['budget_amount'] and not report.show_details:
                continue  # Skip si no hay presupuesto y no se muestran detalles
            
            # Obtener real
            actual_amount = self._get_account_actual(
                account.id, report.date_from, report.date_to
            )
            
            # Obtener comprometido si aplica
            committed_amount = 0
            if report.include_committed:
                committed_amount = self._get_account_committed(
                    account.id, report.date_from, report.date_to
                )
            
            # Calcular variaciones
            variance_amount = actual_amount - budget_data['budget_amount']
            variance_percentage = 0
            achievement_percentage = 0
            
            if budget_data['budget_amount'] != 0:
                variance_percentage = (variance_amount / budget_data['budget_amount']) * 100
                achievement_percentage = (actual_amount / budget_data['budget_amount']) * 100
            
            # Calcular disponible
            available_amount = budget_data['budget_amount'] - actual_amount - committed_amount
            
            # Proyección simple basada en tendencia
            projection_amount = self._calculate_projection(
                actual_amount, report.date_from, report.date_to, datetime.now().date()
            )
            
            # Determinar tipo de alerta
            alert_type = self._determine_alert_type(
                variance_percentage, report.deviation_threshold
            )
            
            lines.append({
                'name': account.display_name,
                'code': account.code,
                'account_id': account.id,
                'hierarchy_level': 1,
                'is_total_line': False,
                'budget_amount': budget_data['budget_amount'],
                'actual_amount': actual_amount,
                'committed_amount': committed_amount,
                'variance_amount': variance_amount,
                'variance_percentage': variance_percentage,
                'achievement_percentage': achievement_percentage,
                'available_amount': available_amount,
                'projection_amount': projection_amount,
                'alert_type': alert_type,
                'notes': budget_data.get('notes', ''),
            })
        
        # Agregar totales si hay líneas
        if lines:
            lines.append(self._create_total_line(lines, "TOTAL GENERAL"))
        
        return lines
    
    def _analyze_by_budget_post(self, report):
        """Análisis por posición presupuestaria"""
        # Optimización: usar with_context para prefetch
        report = report.with_context(prefetch_fields=False)

        lines = []
        
        # Obtener posiciones presupuestarias
        domain = [('company_id', '=', report.company_id.id)]
        if report.budget_id:
            domain.append(('id', '=', report.budget_id.id))
        
        budget_posts = self.env['account.budget.post'].search(domain, order='name')
        
        for post in budget_posts:
            # Obtener líneas presupuestarias
            budget_lines = self._get_budget_lines(
                post.id, report.date_from, report.date_to,
                report.crossovered_budget_id
            )
            
            if not budget_lines and not report.show_details:
                continue
            
            # Calcular totales del post
            post_budget = sum(l['planned_amount'] for l in budget_lines)
            post_actual = 0
            post_committed = 0
            
            # Obtener real para todas las cuentas del post
            for account in post.account_ids:
                post_actual += self._get_account_actual(
                    account.id, report.date_from, report.date_to
                )
                
                if report.include_committed:
                    post_committed += self._get_account_committed(
                        account.id, report.date_from, report.date_to
                    )
            
            # Calcular métricas
            variance_amount = post_actual - post_budget
            variance_percentage = (variance_amount / post_budget * 100) if post_budget else 0
            achievement_percentage = (post_actual / post_budget * 100) if post_budget else 0
            available_amount = post_budget - post_actual - post_committed
            
            projection_amount = self._calculate_projection(
                post_actual, report.date_from, report.date_to, datetime.now().date()
            )
            
            alert_type = self._determine_alert_type(
                variance_percentage, report.deviation_threshold
            )
            
            # Línea principal del post
            post_line = {
                'name': post.name,
                'code': post.code or '',
                'budget_post_id': post.id,
                'hierarchy_level': 1,
                'is_total_line': True,
                'budget_amount': post_budget,
                'actual_amount': post_actual,
                'committed_amount': post_committed,
                'variance_amount': variance_amount,
                'variance_percentage': variance_percentage,
                'achievement_percentage': achievement_percentage,
                'available_amount': available_amount,
                'projection_amount': projection_amount,
                'alert_type': alert_type,
                'notes': '',
            }
            
            lines.append(post_line)
            
            # Agregar detalle por cuenta si se solicita
            if report.show_details:
                for account in post.account_ids:
                    account_budget = sum(
                        l['planned_amount'] for l in budget_lines 
                        if account.id in l.get('account_ids', [])
                    )
                    
                    account_actual = self._get_account_actual(
                        account.id, report.date_from, report.date_to
                    )
                    
                    if account_budget == 0 and account_actual == 0:
                        continue
                    
                    account_variance = account_actual - account_budget
                    account_var_percent = (account_variance / account_budget * 100) if account_budget else 0
                    
                    lines.append({
                        'name': f"  {account.display_name}",
                        'code': account.code,
                        'account_id': account.id,
                        'budget_post_id': post.id,
                        'hierarchy_level': 2,
                        'is_total_line': False,
                        'budget_amount': account_budget,
                        'actual_amount': account_actual,
                        'committed_amount': 0,
                        'variance_amount': account_variance,
                        'variance_percentage': account_var_percent,
                        'achievement_percentage': (account_actual / account_budget * 100) if account_budget else 0,
                        'available_amount': account_budget - account_actual,
                        'projection_amount': 0,
                        'alert_type': 'none',
                        'notes': '',
                    })
        
        # Total general
        if lines:
            main_lines = [l for l in lines if l['hierarchy_level'] == 1]
            lines.append(self._create_total_line(main_lines, "TOTAL PRESUPUESTO"))
        
        return lines
    
    def _analyze_by_analytic(self, report):
        """Análisis por cuenta analítica"""
        # Optimización: usar with_context para prefetch
        report = report.with_context(prefetch_fields=False)

        lines = []
        
        # Obtener cuentas analíticas
        domain = [('company_id', '=', report.company_id.id)]
        if report.analytic_account_ids:
            domain.append(('id', 'in', report.analytic_account_ids.ids))
        
        analytic_accounts = self.env['account.analytic.account'].search(domain, order='name')
        
        for analytic in analytic_accounts:
            # Obtener presupuesto analítico
            budget_data = self._get_analytic_budget(
                analytic.id, report.date_from, report.date_to,
                report.crossovered_budget_id
            )
            
            if not budget_data['budget_amount'] and not report.show_details:
                continue
            
            # Obtener real
            actual_amount = self._get_analytic_actual(
                analytic.id, report.date_from, report.date_to
            )
            
            # Calcular métricas
            variance_amount = actual_amount - budget_data['budget_amount']
            variance_percentage = (variance_amount / budget_data['budget_amount'] * 100) if budget_data['budget_amount'] else 0
            achievement_percentage = (actual_amount / budget_data['budget_amount'] * 100) if budget_data['budget_amount'] else 0
            
            alert_type = self._determine_alert_type(
                variance_percentage, report.deviation_threshold
            )
            
            lines.append({
                'name': analytic.name,
                'code': analytic.code or '',
                'analytic_account_id': analytic.id,
                'hierarchy_level': 1,
                'is_total_line': False,
                'budget_amount': budget_data['budget_amount'],
                'actual_amount': actual_amount,
                'committed_amount': 0,
                'variance_amount': variance_amount,
                'variance_percentage': variance_percentage,
                'achievement_percentage': achievement_percentage,
                'available_amount': budget_data['budget_amount'] - actual_amount,
                'projection_amount': self._calculate_projection(
                    actual_amount, report.date_from, report.date_to, datetime.now().date()
                ),
                'alert_type': alert_type,
                'notes': '',
            })
        
        # Total
        if lines:
            lines.append(self._create_total_line(lines, "TOTAL ANALÍTICO"))
        
        return lines
    
    def _analyze_by_department(self, report):
        """Análisis por departamento"""
        lines = []
        
        # Verificar si HR está instalado
        if not self.env['ir.module.module'].search([
            ('name', '=', 'hr'),
            ('state', '=', 'installed')
        ]):
            raise UserError(_("El módulo de Recursos Humanos (hr) no está instalado."))
        
        # Obtener departamentos
        domain = []
        if report.department_ids:
            domain.append(('id', 'in', report.department_ids.ids))
        
        departments = self.env['hr.department'].search(domain, order='name')
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for dept in departments:
            # Buscar cuentas analíticas del departamento
            # Esto asume que hay una relación entre departamentos y cuentas analíticas
            analytic_accounts = self.env['account.analytic.account'].search([
                ('name', 'ilike', dept.name)  # Búsqueda simple por nombre
            ])
            
            if not analytic_accounts:
                continue
            
            dept_budget = 0
            dept_actual = 0
            
            # TODO: Refactorizar para usar search con dominio completo fuera del loop
            for analytic in analytic_accounts:
                budget_data = self._get_analytic_budget(
                    analytic.id, report.date_from, report.date_to,
                    report.crossovered_budget_id
                )
                dept_budget += budget_data['budget_amount']
                
                dept_actual += self._get_analytic_actual(
                    analytic.id, report.date_from, report.date_to
                )
            
            if dept_budget == 0 and dept_actual == 0:
                continue
            
            variance_amount = dept_actual - dept_budget
            variance_percentage = (variance_amount / dept_budget * 100) if dept_budget else 0
            achievement_percentage = (dept_actual / dept_budget * 100) if dept_budget else 0
            
            lines.append({
                'name': dept.name,
                'code': '',
                'hierarchy_level': 1,
                'is_total_line': False,
                'budget_amount': dept_budget,
                'actual_amount': dept_actual,
                'committed_amount': 0,
                'variance_amount': variance_amount,
                'variance_percentage': variance_percentage,
                'achievement_percentage': achievement_percentage,
                'available_amount': dept_budget - dept_actual,
                'projection_amount': self._calculate_projection(
                    dept_actual, report.date_from, report.date_to, datetime.now().date()
                ),
                'alert_type': self._determine_alert_type(
                    variance_percentage, report.deviation_threshold
                ),
                'notes': f"Incluye {len(analytic_accounts)} cuentas analíticas",
            })
        
        # Total
        if lines:
            lines.append(self._create_total_line(lines, "TOTAL DEPARTAMENTOS"))
        
        return lines
    
    def _analyze_consolidated(self, report):
        """Análisis consolidado general"""
        lines = []
        
        # Categorías principales a consolidar
        categories = [
            ('income', 'INGRESOS', ['income', 'income_other']),
            ('expense', 'GASTOS', ['expense', 'expense_direct_cost', 'expense_depreciation']),
            ('assets', 'ACTIVOS', ['asset_receivable', 'asset_cash', 'asset_current', 'asset_non_current']),
            ('liabilities', 'PASIVOS', ['liability_payable', 'liability_current', 'liability_non_current']),
        ]
        
        for cat_code, cat_name, account_types in categories:
            # Obtener cuentas de la categoría
            accounts = self.env['account.account'].search([
                ('account_type', 'in', account_types),
                ('company_id', '=', report.company_id.id)
            ])
            
            cat_budget = 0
            cat_actual = 0
            cat_committed = 0
            
            # TODO: Refactorizar para usar search con dominio completo fuera del loop
            for account in accounts:
                budget_data = self._get_account_budget(
                    account.id, report.date_from, report.date_to,
                    report.crossovered_budget_id
                )
                cat_budget += budget_data['budget_amount']
                
                cat_actual += self._get_account_actual(
                    account.id, report.date_from, report.date_to
                )
                
                if report.include_committed:
                    cat_committed += self._get_account_committed(
                        account.id, report.date_from, report.date_to
                    )
            
            if cat_budget == 0 and cat_actual == 0:
                continue
            
            # Para ingresos y gastos, usar valores absolutos para presentación
            if cat_code in ['income', 'expense']:
                cat_actual = abs(cat_actual)
                cat_budget = abs(cat_budget)
            
            variance_amount = cat_actual - cat_budget
            variance_percentage = (variance_amount / cat_budget * 100) if cat_budget else 0
            achievement_percentage = (cat_actual / cat_budget * 100) if cat_budget else 0
            
            lines.append({
                'name': cat_name,
                'code': cat_code.upper(),
                'hierarchy_level': 1,
                'is_total_line': True,
                'budget_amount': cat_budget,
                'actual_amount': cat_actual,
                'committed_amount': cat_committed,
                'variance_amount': variance_amount,
                'variance_percentage': variance_percentage,
                'achievement_percentage': achievement_percentage,
                'available_amount': cat_budget - cat_actual - cat_committed,
                'projection_amount': self._calculate_projection(
                    cat_actual, report.date_from, report.date_to, datetime.now().date()
                ),
                'alert_type': self._determine_alert_type(
                    variance_percentage, report.deviation_threshold
                ),
                'notes': f"Incluye {len(accounts)} cuentas",
            })
        
        return lines
    
    def _get_account_budget(self, account_id, date_from, date_to, budget_id=None):
        """Obtiene el presupuesto de una cuenta"""
        # Buscar posiciones presupuestarias que incluyan esta cuenta
        posts = self.env['account.budget.post'].search([
            ('account_ids', 'in', account_id)
        ])
        
        total_budget = 0
        notes = []
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for post in posts:
            # Buscar líneas presupuestarias
            domain = [
                ('general_budget_id', '=', post.id),
                ('date_from', '<=', date_to),
                ('date_to', '>=', date_from),
            ]
            
            if budget_id:
                domain.append(('crossovered_budget_id', '=', budget_id.id))
            
            budget_lines = self.env['crossovered.budget.lines'].search(domain)
            
            for line in budget_lines:
                # Prorratear si es necesario
                line_from = max(line.date_from, date_from)
                line_to = min(line.date_to, date_to)
                
                if line_from <= line_to:
                    total_days = (line.date_to - line.date_from).days + 1
                    period_days = (line_to - line_from).days + 1
                    
                    # Prorratear el presupuesto
                    prorated_amount = line.planned_amount * (period_days / total_days)
                    
                    # Si el post tiene múltiples cuentas, dividir equitativamente
                    account_count = len(post.account_ids)
                    if account_count > 1:
                        prorated_amount = prorated_amount / account_count
                    
                    total_budget += prorated_amount
                    
                    if line.notes:
                        notes.append(line.notes)
        
        return {
            'budget_amount': total_budget,
            'notes': '\n'.join(notes)
        }
    
    def _get_account_actual(self, account_id, date_from, date_to):
        """Obtiene el monto real de una cuenta"""
        # Para cuentas de balance, obtener el saldo
        account = self.env['account.account'].browse(account_id)
        
        if account.account_type in ['asset_receivable', 'asset_cash', 'asset_current', 
                                   'asset_non_current', 'asset_fixed', 'liability_payable',
                                   'liability_current', 'liability_non_current', 
                                   'equity', 'equity_unaffected']:
            # Balance - usar saldo a la fecha
            domain = [
                ('account_id', '=', account_id),
                ('date', '<=', date_to),
                ('parent_state', '=', 'posted')
            ]
            balance = sum(self.env['account.move.line'].search(domain).mapped('balance'))
            return balance
        else:
            # P&L - usar movimiento del período
            domain = [
                ('account_id', '=', account_id),
                ('date', '>=', date_from),
                ('date', '<=', date_to),
                ('parent_state', '=', 'posted')
            ]
            movement = sum(self.env['account.move.line'].search(domain).mapped('balance'))
            return movement
    
    def _get_account_committed(self, account_id, date_from, date_to):
        """Obtiene montos comprometidos (órdenes de compra, etc.)"""
        committed = 0
        
        # Verificar si el módulo de compras está instalado
        if self.env['ir.module.module'].search([
            ('name', '=', 'purchase'),
            ('state', '=', 'installed')
        ]):
            # Buscar órdenes de compra confirmadas pero no facturadas
            domain = [
                ('account_id', '=', account_id),
                ('order_id.state', 'in', ['purchase', 'done']),
                ('order_id.date_order', '>=', date_from),
                ('order_id.date_order', '<=', date_to),
                ('qty_invoiced', '<', 'product_qty')
            ]
            
            po_lines = self.env['purchase.order.line'].search(domain)
            
            for line in po_lines:
                # Calcular monto pendiente de facturar
                pending_qty = line.product_qty - line.qty_invoiced
                committed += pending_qty * line.price_unit
        
        return committed
    
    def _get_budget_lines(self, budget_post_id, date_from, date_to, budget_id=None):
        """Obtiene líneas presupuestarias de un post"""
        domain = [
            ('general_budget_id', '=', budget_post_id),
            ('date_from', '<=', date_to),
            ('date_to', '>=', date_from),
        ]
        
        if budget_id:
            domain.append(('crossovered_budget_id', '=', budget_id.id))
        
        lines = self.env['crossovered.budget.lines'].search(domain)
        
        result = []
        for line in lines:
            # Prorratear si es necesario
            line_from = max(line.date_from, date_from)
            line_to = min(line.date_to, date_to)
            
            if line_from <= line_to:
                total_days = (line.date_to - line.date_from).days + 1
                period_days = (line_to - line_from).days + 1
                prorated_amount = line.planned_amount * (period_days / total_days)
                
                result.append({
                    'planned_amount': prorated_amount,
                    'practical_amount': line.practical_amount,
                    'theoretical_amount': line.theoretical_amount,
                    'percentage': line.percentage,
                    'account_ids': line.general_budget_id.account_ids.ids,
                })
        
        return result
    
    def _get_analytic_budget(self, analytic_id, date_from, date_to, budget_id=None):
        """Obtiene presupuesto de cuenta analítica"""
        domain = [
            ('analytic_account_id', '=', analytic_id),
            ('date_from', '<=', date_to),
            ('date_to', '>=', date_from),
        ]
        
        if budget_id:
            domain.append(('crossovered_budget_id', '=', budget_id.id))
        
        budget_lines = self.env['crossovered.budget.lines'].search(domain)
        
        total_budget = 0
        for line in budget_lines:
            # Prorratear
            line_from = max(line.date_from, date_from)
            line_to = min(line.date_to, date_to)
            
            if line_from <= line_to:
                total_days = (line.date_to - line.date_from).days + 1
                period_days = (line_to - line_from).days + 1
                total_budget += line.planned_amount * (period_days / total_days)
        
        return {'budget_amount': total_budget}
    
    def _get_analytic_actual(self, analytic_id, date_from, date_to):
        """Obtiene monto real de cuenta analítica"""
        domain = [
            ('analytic_account_id', '=', analytic_id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('parent_state', '=', 'posted')
        ]
        
        lines = self.env['account.move.line'].search(domain)
        return sum(lines.mapped('balance'))
    
    def _calculate_projection(self, actual_amount, date_from, date_to, current_date):
        """Calcula proyección simple basada en tendencia"""
        if current_date < date_from:
            return 0
        
        if current_date >= date_to:
            return actual_amount
        
        # Días transcurridos y totales
        total_days = (date_to - date_from).days + 1
        elapsed_days = (current_date - date_from).days + 1
        
        if elapsed_days <= 0:
            return 0
        
        # Proyección lineal simple
        daily_rate = actual_amount / elapsed_days
        projection = daily_rate * total_days
        
        return projection
    
    def _determine_alert_type(self, variance_percentage, threshold):
        """Determina el tipo de alerta según la variación"""
        abs_variance = abs(variance_percentage)
        
        if abs_variance <= threshold:
            return 'none'
        elif abs_variance <= threshold * 1.5:
            return 'warning'
        elif abs_variance <= threshold * 2:
            return 'danger'
        else:
            return 'danger'
    
    def _create_total_line(self, lines, name):
        """Crea una línea de total"""
        return {
            'name': name,
            'code': 'TOTAL',
            'hierarchy_level': 0,
            'is_total_line': True,
            'budget_amount': sum(l['budget_amount'] for l in lines),
            'actual_amount': sum(l['actual_amount'] for l in lines),
            'committed_amount': sum(l['committed_amount'] for l in lines),
            'variance_amount': sum(l['variance_amount'] for l in lines),
            'variance_percentage': 0,  # Se calcula después
            'achievement_percentage': 0,  # Se calcula después
            'available_amount': sum(l['available_amount'] for l in lines),
            'projection_amount': sum(l['projection_amount'] for l in lines),
            'alert_type': 'none',
            'notes': '',
        }
    
    def _generate_recommendations(self, lines_data, report):
        """Genera recomendaciones basadas en el análisis"""
        # Optimización: usar with_context para prefetch
        report = report.with_context(prefetch_fields=False)

        recommendations = []
        
        # Analizar desviaciones significativas
        significant_deviations = [
            l for l in lines_data 
            if not l['is_total_line'] and abs(l['variance_percentage']) > report.deviation_threshold
        ]
        
        if significant_deviations:
            recommendations.append(
                f"📊 Se detectaron {len(significant_deviations)} partidas con "
                f"desviaciones superiores al {report.deviation_threshold}%"
            )
        
        # Analizar sobregastos
        overruns = [
            l for l in lines_data 
            if not l['is_total_line'] and l['variance_amount'] > 0
        ]
        
        if overruns:
            total_overrun = sum(l['variance_amount'] for l in overruns)
            recommendations.append(
                f"⚠️ Sobregasto total detectado: {report.currency_id.symbol} {total_overrun:,.0f} "
                f"en {len(overruns)} partidas"
            )
        
        # Analizar subejecución
        underruns = [
            l for l in lines_data 
            if not l['is_total_line'] and l['achievement_percentage'] < 80
        ]
        
        if underruns:
            recommendations.append(
                f"💡 {len(underruns)} partidas tienen una ejecución inferior al 80%, "
                "considerar reasignación de recursos"
            )
        
        # Proyecciones críticas
        critical_projections = [
            l for l in lines_data
            if not l['is_total_line'] and l['projection_amount'] > 0 and
            l['projection_amount'] > l['budget_amount'] * 1.1
        ]
        
        if critical_projections:
            recommendations.append(
                f"🎯 {len(critical_projections)} partidas proyectan exceder el presupuesto "
                "en más del 10% al final del período"
            )
        
        # Disponibilidad crítica
        low_availability = [
            l for l in lines_data
            if not l['is_total_line'] and l['available_amount'] < l['budget_amount'] * 0.1
        ]
        
        if low_availability:
            recommendations.append(
                f"🔴 {len(low_availability)} partidas tienen menos del 10% de presupuesto disponible"
            )
        
        # Recomendaciones específicas por tipo de análisis
        if report.analysis_type == 'by_department' and lines_data:
            # Identificar departamento con mejor y peor desempeño
            dept_lines = [l for l in lines_data if not l['is_total_line']]
            if dept_lines:
                best = min(dept_lines, key=lambda x: abs(x['variance_percentage']))
                worst = max(dept_lines, key=lambda x: abs(x['variance_percentage']))
                
                recommendations.append(
                    f"🏆 Mejor control presupuestario: {best['name']} "
                    f"(desviación {best['variance_percentage']:.1f}%)"
                )
                recommendations.append(
                    f"📉 Mayor desviación: {worst['name']} "
                    f"(desviación {worst['variance_percentage']:.1f}%)"
                )
        
        return '\n\n'.join(recommendations)
    
    def export_to_excel(self, report):
        """
        Exporta el reporte de comparación presupuestaria a Excel
        """
        try:
            from xlsxwriter import Workbook
            output = io.BytesIO()
            workbook = Workbook(output, {'in_memory': True})
            
            # Hoja principal
            self._create_comparison_sheet(workbook, report)
            
            # Hoja de análisis
            if report.show_variance_analysis:
                self._create_variance_analysis_sheet(workbook, report)
            
            # Hoja de gráficos
            self._create_charts_sheet(workbook, report)
            
            workbook.close()
            output.seek(0)
            
            # Crear attachment
            filename = f"Comparacion_Presupuestaria_{report.company_id.name}_{report.date_to}.xlsx"
            attachment = self.env['ir.attachment'].create({
                'name': filename,
                'type': 'binary',
                'datas': base64.b64encode(output.read()),
                'res_model': report._name,
                'res_id': report.id,
                'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            })
            
            return {
                'type': 'ir.actions.act_url',
                'url': f'/web/content/{attachment.id}/{filename}?download=true',
                'target': 'self',
            }
            
        except ImportError:
            raise UserError(_(
                "La librería xlsxwriter no está instalada. "
                "Por favor, instálela con: pip install xlsxwriter"
            ))
    
    def _create_comparison_sheet(self, workbook, report):
        """Crea hoja principal de comparación"""
        worksheet = workbook.add_worksheet('Comparación Presupuestaria')
        
        # Formatos
        formats = self._get_excel_formats(workbook)
        
        # Header
        worksheet.merge_range(0, 0, 0, 10, 
                            f"COMPARACIÓN PRESUPUESTARIA - {report.company_id.name}", 
                            formats['header'])
        
        worksheet.merge_range(1, 0, 1, 10, 
                            f"Período: {report.date_from.strftime('%d/%m/%Y')} - {report.date_to.strftime('%d/%m/%Y')}", 
                            formats['subheader'])
        
        # Column headers
        headers = [
            ('Código', 15),
            ('Descripción', 40),
            ('Presupuesto', 15),
            ('Real', 15),
            ('Comprometido', 15),
            ('Disponible', 15),
            ('Variación', 15),
            ('Var %', 10),
            ('Cumpl %', 10),
            ('Proyección', 15),
            ('Alerta', 10)
        ]
        
        row = 3
        col = 0
        for header, width in headers:
            worksheet.write(row, col, header, formats['column_header'])
            worksheet.set_column(col, col, width)
            col += 1
        
        # Data
        row = 4
        for line in report.line_ids:
            # Determinar formato
            if line.is_total_line:
                line_format = formats['total_line']
                number_format = formats['total_number']
            elif line.hierarchy_level > 1:
                line_format = formats['subtotal_line']
                number_format = formats['number']
            else:
                line_format = formats['normal_line']
                number_format = formats['number']
            
            # Escribir datos
            worksheet.write(row, 0, line.code, line_format)
            worksheet.write(row, 1, line.name, line_format)
            worksheet.write(row, 2, line.budget_amount, number_format)
            worksheet.write(row, 3, line.actual_amount, number_format)
            worksheet.write(row, 4, line.committed_amount, number_format)
            worksheet.write(row, 5, line.available_amount, number_format)
            
            # Variación con color
            var_format = formats['positive_var'] if line.variance_amount >= 0 else formats['negative_var']
            worksheet.write(row, 6, line.variance_amount, var_format)
            
            # Porcentajes
            worksheet.write(row, 7, line.variance_percentage / 100, formats['percent'])
            worksheet.write(row, 8, line.achievement_percentage / 100, formats['percent'])
            
            # Proyección
            worksheet.write(row, 9, line.projection_amount, number_format)
            
            # Alerta
            alert_format = {
                'none': formats['normal_line'],
                'warning': formats['warning'],
                'danger': formats['danger'],
                'info': formats['info']
            }.get(line.alert_type, formats['normal_line'])
            
            worksheet.write(row, 10, line.alert_type.upper(), alert_format)
            
            row += 1
        
        # Resumen al final
        row += 2
        worksheet.write(row, 0, "RESUMEN EJECUTIVO", formats['header'])
        row += 1
        worksheet.write_string(row, 0, report.recommendations or "Sin recomendaciones")
    
    def _create_variance_analysis_sheet(self, workbook, report):
        """Crea hoja de análisis de variaciones"""
        worksheet = workbook.add_worksheet('Análisis de Variaciones')
        
        formats = self._get_excel_formats(workbook)
        
        # Top 10 mayores desviaciones
        deviations = report.line_ids.filtered(
            lambda l: not l.is_total_line
        ).sorted('variance_amount', reverse=True)
        
        worksheet.write(0, 0, "TOP 10 MAYORES DESVIACIONES", formats['header'])
        
        row = 2
        for line in deviations[:10]:
            worksheet.write(row, 0, line.name, formats['normal_line'])
            worksheet.write(row, 1, line.variance_amount, formats['number'])
            worksheet.write(row, 2, line.variance_percentage / 100, formats['percent'])
            row += 1
    
    def _create_charts_sheet(self, workbook, report):
        """Crea hoja con gráficos"""
        worksheet = workbook.add_worksheet('Gráficos')
        
        # Gráfico de comparación presupuesto vs real
        chart = workbook.add_chart({'type': 'column'})
        chart.set_title({'name': 'Presupuesto vs Real'})
        
        # Configurar series (simplificado)
        chart.add_series({
            'name': 'Presupuesto',
            'categories': ['Comparación Presupuestaria', 4, 1, 8, 1],
            'values': ['Comparación Presupuestaria', 4, 2, 8, 2],
        })
        
        chart.add_series({
            'name': 'Real',
            'categories': ['Comparación Presupuestaria', 4, 1, 8, 1],
            'values': ['Comparación Presupuestaria', 4, 3, 8, 3],
        })
        
        worksheet.insert_chart('B2', chart)
    
    def _get_excel_formats(self, workbook):
        """Define formatos para Excel"""
        return {
            'header': workbook.add_format({
                'bold': True,
                'font_size': 16,
                'align': 'center',
                'bg_color': '#2C3E50',
                'font_color': 'white'
            }),
            'subheader': workbook.add_format({
                'bold': True,
                'font_size': 12,
                'align': 'center',
                'bg_color': '#34495E',
                'font_color': 'white'
            }),
            'column_header': workbook.add_format({
                'bold': True,
                'align': 'center',
                'bg_color': '#3498DB',
                'font_color': 'white',
                'border': 1
            }),
            'normal_line': workbook.add_format({
                'border': 1
            }),
            'total_line': workbook.add_format({
                'bold': True,
                'bg_color': '#ECF0F1',
                'border': 2
            }),
            'subtotal_line': workbook.add_format({
                'bg_color': '#F8F9FA',
                'border': 1
            }),
            'number': workbook.add_format({
                'num_format': '#,##0.00',
                'border': 1
            }),
            'total_number': workbook.add_format({
                'bold': True,
                'num_format': '#,##0.00',
                'bg_color': '#ECF0F1',
                'border': 2
            }),
            'percent': workbook.add_format({
                'num_format': '0.00%',
                'border': 1
            }),
            'positive_var': workbook.add_format({
                'num_format': '#,##0.00',
                'font_color': '#E74C3C',
                'border': 1
            }),
            'negative_var': workbook.add_format({
                'num_format': '#,##0.00',
                'font_color': '#27AE60',
                'border': 1
            }),
            'warning': workbook.add_format({
                'bg_color': '#F39C12',
                'font_color': 'white',
                'border': 1
            }),
            'danger': workbook.add_format({
                'bg_color': '#E74C3C',
                'font_color': 'white',
                'border': 1
            }),
            'info': workbook.add_format({
                'bg_color': '#3498DB',
                'font_color': 'white',
                'border': 1
            })
        }