# -*- coding: utf-8 -*-
from odoo import fields, _
from odoo.exceptions import UserError
import logging
import base64
import io
from collections import defaultdict
import statistics
import numpy as np
from scipy import stats

_logger = logging.getLogger(__name__)


class MultiPeriodComparisonService:
    """
    Servicio para cálculo y análisis de comparaciones multi-período.
    Incluye análisis de tendencias, proyecciones y generación de insights.
    """
    
    def __init__(self, env):
        self.env = env
        self._cache = {}
        
    def compute_comparison(self, comparison):
        """
        Calcula la comparación multi-período según configuración.
        
        Returns:
            dict: Datos de comparación con líneas, tendencias e insights
        """
        try:
            # Obtener datos según tipo de reporte
            if comparison.report_type == 'balance_sheet':
                lines_data = self._compute_balance_sheet_comparison(comparison)
            elif comparison.report_type == 'profit_loss':
                lines_data = self._compute_profit_loss_comparison(comparison)
            elif comparison.report_type == 'cash_flow':
                lines_data = self._compute_cash_flow_comparison(comparison)
            elif comparison.report_type == 'ratios':
                lines_data = self._compute_ratios_comparison(comparison)
            else:  # custom_accounts
                lines_data = self._compute_custom_accounts_comparison(comparison)
            
            # Aplicar método de comparación
            lines_data = self._apply_comparison_method(lines_data, comparison)
            
            # Análisis de tendencias si está habilitado
            trend_analysis = ""
            if comparison.show_trends:
                trend_analysis = self._analyze_trends(lines_data, comparison)
            
            # Generar insights clave
            key_insights = self._generate_key_insights(lines_data, comparison)
            
            return {
                'lines': lines_data,
                'trend_analysis': trend_analysis,
                'key_insights': key_insights
            }
            
        except Exception as e:
            _logger.error(f"Error computing multi-period comparison: {str(e)}")
            raise UserError(_(
                "Error al calcular la comparación multi-período: %s"
            ) % str(e))
    
    def _compute_balance_sheet_comparison(self, comparison):
        """Calcula comparación para Balance General"""
        # Optimización: usar with_context para prefetch
        comparison = comparison.with_context(prefetch_fields=False)

        lines = []
        
        # Definir estructura del balance
        balance_structure = [
            ('1', 'ACTIVOS', ['asset_receivable', 'asset_cash', 'asset_current', 'asset_non_current', 'asset_fixed']),
            ('2', 'PASIVOS', ['liability_payable', 'liability_current', 'liability_non_current']),
            ('3', 'PATRIMONIO', ['equity', 'equity_unaffected']),
        ]
        
        for group_code, group_name, account_types in balance_structure:
            # Línea de grupo
            group_line = {
                'account_code': group_code,
                'account_name': group_name,
                'is_total_line': True,
                'hierarchy_level': 1,
                'periods': []
            }
            
            # Calcular por período
            for period in comparison.period_ids.sorted('sequence'):
                amount = self._get_balance_by_type(
                    account_types, period.date_from, period.date_to,
                    comparison.company_id.id, comparison.target_move
                )
                
                group_line['periods'].append({
                    'period_id': period.id,
                    'amount': amount
                })
            
            lines.append(group_line)
            
            # Agregar cuentas detalladas
            detail_lines = self._get_account_details(
                account_types, comparison
            )
            lines.extend(detail_lines)
        
        return lines
    
    def _compute_profit_loss_comparison(self, comparison):
        """Calcula comparación para Estado de Resultados"""
        lines = []
        
        # Estructura P&L
        pl_structure = [
            ('4', 'INGRESOS', ['income', 'income_other']),
            ('5', 'COSTOS', ['expense_direct_cost']),
            ('6', 'GASTOS', ['expense', 'expense_depreciation']),
        ]
        
        period_totals = defaultdict(lambda: {
            'income': 0, 'costs': 0, 'expenses': 0
        })
        
        for group_code, group_name, account_types in pl_structure:
            group_line = {
                'account_code': group_code,
                'account_name': group_name,
                'is_total_line': True,
                'hierarchy_level': 1,
                'periods': []
            }
            
            for period in comparison.period_ids.sorted('sequence'):
                # Para P&L, necesitamos el movimiento del período, no el saldo
                amount = self._get_period_movement(
                    account_types, period.date_from, period.date_to,
                    comparison.company_id.id, comparison.target_move
                )
                
                group_line['periods'].append({
                    'period_id': period.id,
                    'amount': abs(amount)  # Mostrar positivo
                })
                
                # Acumular para totales
                if group_code == '4':
                    period_totals[period.id]['income'] = abs(amount)
                elif group_code == '5':
                    period_totals[period.id]['costs'] = abs(amount)
                else:
                    period_totals[period.id]['expenses'] = abs(amount)
            
            lines.append(group_line)
            
            # Detalles
            detail_lines = self._get_account_movement_details(
                account_types, comparison
            )
            lines.extend(detail_lines)
        
        # Agregar líneas de resultados
        # Utilidad Bruta
        gross_profit_line = {
            'account_code': 'GP',
            'account_name': 'UTILIDAD BRUTA',
            'is_total_line': True,
            'hierarchy_level': 1,
            'periods': []
        }
        
        for period in comparison.period_ids.sorted('sequence'):
            gross_profit = period_totals[period.id]['income'] - period_totals[period.id]['costs']
            gross_profit_line['periods'].append({
                'period_id': period.id,
                'amount': gross_profit
            })
        
        lines.append(gross_profit_line)
        
        # Utilidad Operacional
        operating_profit_line = {
            'account_code': 'OP',
            'account_name': 'UTILIDAD OPERACIONAL',
            'is_total_line': True,
            'hierarchy_level': 1,
            'periods': []
        }
        
        for period in comparison.period_ids.sorted('sequence'):
            operating_profit = (period_totals[period.id]['income'] - 
                              period_totals[period.id]['costs'] - 
                              period_totals[period.id]['expenses'])
            operating_profit_line['periods'].append({
                'period_id': period.id,
                'amount': operating_profit
            })
        
        lines.append(operating_profit_line)
        
        return lines
    
    def _compute_ratios_comparison(self, comparison):
        """Calcula comparación de ratios financieros"""
        # Optimización: usar with_context para prefetch
        comparison = comparison.with_context(prefetch_fields=False)

        lines = []
        
        # Ratios a calcular
        ratios = [
            ('LIQ_CUR', 'Liquidez Corriente', self._calculate_current_ratio),
            ('LIQ_ACI', 'Prueba Ácida', self._calculate_acid_ratio),
            ('END_TOT', 'Endeudamiento Total', self._calculate_debt_ratio),
            ('ROE', 'Retorno sobre Patrimonio', self._calculate_roe),
            ('ROA', 'Retorno sobre Activos', self._calculate_roa),
            ('MAR_BRUT', 'Margen Bruto', self._calculate_gross_margin),
            ('MAR_OPER', 'Margen Operacional', self._calculate_operating_margin),
            ('ROT_ACT', 'Rotación de Activos', self._calculate_asset_turnover),
        ]
        
        for ratio_code, ratio_name, calc_func in ratios:
            ratio_line = {
                'account_code': ratio_code,
                'account_name': ratio_name,
                'is_total_line': False,
                'hierarchy_level': 1,
                'periods': []
            }
            
            for period in comparison.period_ids.sorted('sequence'):
                value = calc_func(
                    period.date_from, period.date_to,
                    comparison.company_id.id, comparison.target_move
                )
                
                ratio_line['periods'].append({
                    'period_id': period.id,
                    'amount': value,
                    'percentage': value  # Los ratios ya son porcentajes
                })
            
            lines.append(ratio_line)
        
        return lines
    
    def _compute_custom_accounts_comparison(self, comparison):
        """Calcula comparación para cuentas específicas"""
        # Optimización: usar with_context para prefetch
        comparison = comparison.with_context(prefetch_fields=False)

        lines = []
        
        if not comparison.account_ids:
            raise UserError(_("Debe seleccionar al menos una cuenta para comparar."))
        
        for account in comparison.account_ids.sorted('code'):
            account_line = {
                'account_id': account.id,
                'account_code': account.code,
                'account_name': account.name,
                'account_type': account.account_type,
                'is_total_line': False,
                'hierarchy_level': 1,
                'periods': []
            }
            
            for period in comparison.period_ids.sorted('sequence'):
                # Determinar si es cuenta de balance o P&L
                if account.account_type in ['asset_receivable', 'asset_cash', 'asset_current', 
                                          'asset_non_current', 'asset_fixed', 'liability_payable',
                                          'liability_current', 'liability_non_current', 
                                          'equity', 'equity_unaffected']:
                    # Balance - usar saldo
                    amount = self._get_account_balance(
                        account.id, period.date_to,
                        comparison.company_id.id, comparison.target_move
                    )
                else:
                    # P&L - usar movimiento del período
                    amount = self._get_account_movement(
                        account.id, period.date_from, period.date_to,
                        comparison.company_id.id, comparison.target_move
                    )
                
                account_line['periods'].append({
                    'period_id': period.id,
                    'amount': amount
                })
            
            lines.append(account_line)
        
        return lines
    
    def _get_balance_by_type(self, account_types, date_from, date_to, company_id, target_move):
        """Obtiene balance por tipos de cuenta"""
        domain = [
            ('account_type', 'in', account_types),
            ('company_id', '=', company_id),
            ('date', '<=', date_to)
        ]
        
        if target_move == 'posted':
            domain.append(('parent_state', '=', 'posted'))
        
        query = """
            SELECT SUM(aml.balance) as balance
            FROM account_move_line aml
            INNER JOIN account_account aa ON aml.account_id = aa.id
            WHERE aa.account_type = ANY(%(account_types)s)
            AND aml.company_id = %(company_id)s
            AND aml.date <= %(date_to)s
            {move_filter}
        """
        
        move_filter = "AND aml.parent_state = 'posted'" if target_move == 'posted' else ""
        query = query.format(move_filter=move_filter)
        
        self.env.self.env.cr.execute(query, {
            'account_types': account_types,
            'company_id': company_id,
            'date_to': date_to
        })
        
        result = self.env.cr.fetchone()
        return result[0] if result and result[0] else 0.0
    
    def _get_period_movement(self, account_types, date_from, date_to, company_id, target_move):
        """Obtiene movimiento del período para tipos de cuenta"""
        domain = [
            ('account_type', 'in', account_types),
            ('company_id', '=', company_id),
            ('date', '>=', date_from),
            ('date', '<=', date_to)
        ]
        
        if target_move == 'posted':
            domain.append(('parent_state', '=', 'posted'))
        
        query = """
            SELECT SUM(aml.balance) as movement
            FROM account_move_line aml
            INNER JOIN account_account aa ON aml.account_id = aa.id
            WHERE aa.account_type = ANY(%(account_types)s)
            AND aml.company_id = %(company_id)s
            AND aml.date >= %(date_from)s
            AND aml.date <= %(date_to)s
            {move_filter}
        """
        
        move_filter = "AND aml.parent_state = 'posted'" if target_move == 'posted' else ""
        query = query.format(move_filter=move_filter)
        
        self.env.self.env.cr.execute(query, {
            'account_types': account_types,
            'company_id': company_id,
            'date_from': date_from,
            'date_to': date_to
        })
        
        result = self.env.cr.fetchone()
        return result[0] if result and result[0] else 0.0
    
    def _get_account_balance(self, account_id, date, company_id, target_move):
        """Obtiene saldo de una cuenta específica"""
        Account = self.env['account.account']
        account = Account.browse(account_id)
        
        domain = [
            ('account_id', '=', account_id),
            ('company_id', '=', company_id),
            ('date', '<=', date)
        ]
        
        if target_move == 'posted':
            domain.append(('parent_state', '=', 'posted'))
        
        balance = sum(self.env['account.move.line'].search(domain).mapped('balance'))
        return balance
    
    def _get_account_movement(self, account_id, date_from, date_to, company_id, target_move):
        """Obtiene movimiento de una cuenta en el período"""
        domain = [
            ('account_id', '=', account_id),
            ('company_id', '=', company_id),
            ('date', '>=', date_from),
            ('date', '<=', date_to)
        ]
        
        if target_move == 'posted':
            domain.append(('parent_state', '=', 'posted'))
        
        movement = sum(self.env['account.move.line'].search(domain).mapped('balance'))
        return movement
    
    def _get_account_details(self, account_types, comparison):
        """Obtiene detalles de cuentas para balance"""
        # Optimización: usar with_context para prefetch
        comparison = comparison.with_context(prefetch_fields=False)

        lines = []
        
        # Buscar cuentas activas
        accounts = self.env['account.account'].search([
            ('account_type', 'in', account_types),
            ('company_id', '=', comparison.company_id.id)
        ], order='code')
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        
        for account in accounts:
            has_movement = False
            account_line = {
                'account_id': account.id,
                'account_code': account.code,
                'account_name': account.name,
                'account_type': account.account_type,
                'is_total_line': False,
                'hierarchy_level': 2,
                'periods': []
            }
            
            for period in comparison.period_ids.sorted('sequence'):
                amount = self._get_account_balance(
                    account.id, period.date_to,
                    comparison.company_id.id, comparison.target_move
                )
                
                if amount != 0:
                    has_movement = True
                
                account_line['periods'].append({
                    'period_id': period.id,
                    'amount': amount
                })
            
            # Solo agregar si tiene movimiento en algún período
            if has_movement:
                lines.append(account_line)
        
        return lines
    
    def _get_account_movement_details(self, account_types, comparison):
        """Obtiene detalles de movimientos para P&L"""
        # Optimización: usar with_context para prefetch
        comparison = comparison.with_context(prefetch_fields=False)

        lines = []
        
        accounts = self.env['account.account'].search([
            ('account_type', 'in', account_types),
            ('company_id', '=', comparison.company_id.id)
        ], order='code')
        
        for account in accounts:
            has_movement = False
            account_line = {
                'account_id': account.id,
                'account_code': account.code,
                'account_name': account.name,
                'account_type': account.account_type,
                'is_total_line': False,
                'hierarchy_level': 2,
                'periods': []
            }
            
            for period in comparison.period_ids.sorted('sequence'):
                amount = self._get_account_movement(
                    account.id, period.date_from, period.date_to,
                    comparison.company_id.id, comparison.target_move
                )
                
                if amount != 0:
                    has_movement = True
                
                account_line['periods'].append({
                    'period_id': period.id,
                    'amount': abs(amount)  # Mostrar positivo
                })
            
            if has_movement:
                lines.append(account_line)
        
        return lines
    
    def _apply_comparison_method(self, lines_data, comparison):
        """Aplica el método de comparación seleccionado"""
        if comparison.comparison_method == 'absolute':
            # Ya está en valores absolutos
            return lines_data
        
        elif comparison.comparison_method == 'percentage':
            # Análisis vertical - porcentaje sobre total
            return self._apply_vertical_analysis(lines_data, comparison)
        
        elif comparison.comparison_method == 'base_100':
            # Índice base 100
            return self._apply_base_index(lines_data, comparison)
        
        elif comparison.comparison_method == 'growth_rate':
            # Tasa de crecimiento
            return self._apply_growth_rate(lines_data, comparison)
        
        return lines_data
    
    def _apply_vertical_analysis(self, lines_data, comparison):
        """Aplica análisis vertical (porcentaje sobre total)"""
        # Calcular totales por período
        period_totals = {}
        
        # Para balance, el total es activos totales
        # Para P&L, el total es ingresos totales
        if comparison.report_type == 'balance_sheet':
            # Buscar línea de activos totales
            for line in lines_data:
                if line['account_code'] == '1':  # ACTIVOS
                    for period_data in line['periods']:
                        period_totals[period_data['period_id']] = abs(period_data['amount'])
        
        elif comparison.report_type == 'profit_loss':
            # Buscar línea de ingresos totales
            for line in lines_data:
                if line['account_code'] == '4':  # INGRESOS
                    for period_data in line['periods']:
                        period_totals[period_data['period_id']] = abs(period_data['amount'])
        
        # Aplicar porcentajes
        for line in lines_data:
            for period_data in line['periods']:
                total = period_totals.get(period_data['period_id'], 1)
                if total != 0:
                    period_data['percentage'] = (period_data['amount'] / total) * 100
                else:
                    period_data['percentage'] = 0
                
                # Cambiar amount a porcentaje para visualización
                period_data['amount'] = period_data['percentage']
        
        return lines_data
    
    def _apply_base_index(self, lines_data, comparison):
        """Aplica índice base 100 al primer período"""
        for line in lines_data:
            # Obtener valor del período base
            base_value = None
            for period_data in line['periods']:
                period = comparison.period_ids.filtered(lambda p: p.id == period_data['period_id'])
                if period.is_base_period:
                    base_value = period_data['amount']
                    break
            
            # Calcular índices
            if base_value and base_value != 0:
                for period_data in line['periods']:
                    period_data['base_index'] = (period_data['amount'] / base_value) * 100
                    period_data['amount'] = period_data['base_index']
            else:
                for period_data in line['periods']:
                    period_data['base_index'] = 100
                    period_data['amount'] = 100
        
        return lines_data
    
    def _apply_growth_rate(self, lines_data, comparison):
        """Aplica tasa de crecimiento período a período"""
        for line in lines_data:
            previous_amount = None
            
            for i, period_data in enumerate(line['periods']):
                if i == 0:
                    period_data['growth_rate'] = 0
                    period_data['amount'] = 0
                else:
                    if previous_amount and previous_amount != 0:
                        growth = ((period_data['amount'] - previous_amount) / abs(previous_amount)) * 100
                        period_data['growth_rate'] = growth
                        period_data['amount'] = growth
                    else:
                        period_data['growth_rate'] = 0
                        period_data['amount'] = 0
                
                previous_amount = period_data.get('amount', 0)
        
        return lines_data
    
    def _analyze_trends(self, lines_data, comparison):
        """Analiza tendencias y genera insights"""
        analysis = []
        
        # Analizar líneas principales
        main_lines = [l for l in lines_data if l.get('is_total_line')]
        
        for line in main_lines:
            amounts = [p['amount'] for p in line['periods']]
            
            if len(amounts) >= 3:
                # Análisis de tendencia
                trend = self._calculate_trend(amounts)
                
                # Proyección simple
                projection = self._project_next_period(amounts)
                
                analysis.append({
                    'account': line['account_name'],
                    'trend': trend,
                    'projection': projection,
                    'volatility': statistics.stdev(amounts) if len(amounts) > 1 else 0
                })
        
        # Generar texto de análisis
        trend_text = "📊 ANÁLISIS DE TENDENCIAS\n\n"
        
        for item in analysis:
            trend_icon = {
                'up': '📈',
                'down': '📉',
                'stable': '➡️',
                'volatile': '📊'
            }.get(item['trend']['direction'], '❓')
            
            trend_text += f"{trend_icon} **{item['account']}**:\n"
            trend_text += f"   - Tendencia: {item['trend']['description']}\n"
            trend_text += f"   - Proyección próximo período: {item['projection']:,.2f}\n"
            if item['volatility'] > 0:
                trend_text += f"   - Volatilidad: {item['volatility']:,.2f}\n"
            trend_text += "\n"
        
        return trend_text
    
    def _calculate_trend(self, values):
        """Calcula la tendencia de una serie de valores"""
        if len(values) < 2:
            return {'direction': 'stable', 'description': 'Datos insuficientes'}
        
        # Calcular pendiente con regresión lineal
        x = list(range(len(values)))
        slope, intercept, r_value, p_value, std_err = stats.linregress(x, values)
        
        # Determinar dirección
        avg = statistics.mean(values)
        relative_slope = (slope / abs(avg)) * 100 if avg != 0 else 0
        
        if abs(relative_slope) < 5:
            direction = 'stable'
            description = 'Tendencia estable'
        elif relative_slope > 5:
            direction = 'up'
            description = f'Tendencia creciente ({relative_slope:.1f}% por período)'
        else:
            direction = 'down'
            description = f'Tendencia decreciente ({relative_slope:.1f}% por período)'
        
        # Check volatility
        cv = statistics.stdev(values) / abs(avg) if avg != 0 else 0
        if cv > 0.3:
            direction = 'volatile'
            description += ' con alta volatilidad'
        
        return {
            'direction': direction,
            'description': description,
            'slope': slope,
            'r_squared': r_value ** 2
        }
    
    def _project_next_period(self, values):
        """Proyecta el valor del siguiente período"""
        if len(values) < 2:
            return values[-1] if values else 0
        
        # Usar regresión lineal simple
        x = list(range(len(values)))
        slope, intercept = np.polyfit(x, values, 1)
        
        # Proyectar siguiente valor
        next_x = len(values)
        projection = slope * next_x + intercept
        
        return projection
    
    def _generate_key_insights(self, lines_data, comparison):
        """Genera insights clave automáticos"""
        insights = []
        
        # 1. Mayor variación absoluta
        max_variation = {'line': None, 'amount': 0, 'percent': 0}
        
        for line in lines_data:
            if not line.get('is_total_line'):
                continue
                
            periods = line['periods']
            if len(periods) >= 2:
                first = periods[0]['amount']
                last = periods[-1]['amount']
                variation = last - first
                percent = (variation / abs(first)) * 100 if first != 0 else 0
                
                if abs(variation) > abs(max_variation['amount']):
                    max_variation = {
                        'line': line['account_name'],
                        'amount': variation,
                        'percent': percent
                    }
        
        if max_variation['line']:
            direction = "aumentó" if max_variation['amount'] > 0 else "disminuyó"
            insights.append(
                f"💡 {max_variation['line']} {direction} "
                f"{abs(max_variation['percent']):.1f}% "
                f"({max_variation['amount']:,.0f})"
            )
        
        # 2. Cambios en estructura (para análisis vertical)
        if comparison.comparison_method == 'percentage':
            structure_changes = self._analyze_structure_changes(lines_data)
            insights.extend(structure_changes)
        
        # 3. Alertas de ratios (si aplica)
        if comparison.report_type == 'ratios':
            ratio_alerts = self._generate_ratio_alerts(lines_data)
            insights.extend(ratio_alerts)
        
        # 4. Estacionalidad detectada
        seasonality = self._detect_seasonality(lines_data, comparison)
        if seasonality:
            insights.append(f"📅 {seasonality}")
        
        # Formatear insights
        insights_text = "🔍 INSIGHTS CLAVE\n\n"
        for i, insight in enumerate(insights[:10], 1):  # Top 10 insights
            insights_text += f"{i}. {insight}\n"
        
        return insights_text
    
    def _analyze_structure_changes(self, lines_data):
        """Analiza cambios en la estructura porcentual"""
        changes = []
        
        for line in lines_data:
            if line.get('is_total_line') or not line['periods']:
                continue
            
            first_percent = line['periods'][0].get('percentage', 0)
            last_percent = line['periods'][-1].get('percentage', 0)
            
            change = last_percent - first_percent
            if abs(change) > 5:  # Cambio significativo > 5%
                direction = "aumentó" if change > 0 else "disminuyó"
                changes.append((
                    abs(change),
                    f"📊 {line['account_name']} {direction} su participación "
                    f"en {abs(change):.1f} puntos porcentuales"
                ))
        
        # Ordenar por magnitud y retornar top 3
        changes.sort(reverse=True)
        return [msg for _, msg in changes[:3]]
    
    def _generate_ratio_alerts(self, lines_data):
        """Genera alertas para ratios críticos"""
        alerts = []
        
        ratio_thresholds = {
            'LIQ_CUR': (1.5, 2.5, 'Liquidez Corriente'),
            'LIQ_ACI': (1.0, 1.5, 'Prueba Ácida'),
            'END_TOT': (0, 0.6, 'Endeudamiento'),
            'ROE': (0.15, 0.30, 'ROE'),
            'MAR_OPER': (0.10, 0.25, 'Margen Operacional')
        }
        
        for line in lines_data:
            if line['account_code'] in ratio_thresholds:
                min_val, max_val, name = ratio_thresholds[line['account_code']]
                
                # Verificar último valor
                if line['periods']:
                    last_value = line['periods'][-1]['amount']
                    
                    if last_value < min_val:
                        alerts.append(
                            f"⚠️ {name} bajo el mínimo recomendado "
                            f"({last_value:.2f} < {min_val})"
                        )
                    elif last_value > max_val:
                        alerts.append(
                            f"⚠️ {name} sobre el máximo recomendado "
                            f"({last_value:.2f} > {max_val})"
                        )
        
        return alerts
    
    def _detect_seasonality(self, lines_data, comparison):
        """Detecta patrones de estacionalidad"""
        if comparison.comparison_type != 'monthly' or len(comparison.period_ids) < 12:
            return None
        
        # Buscar línea de ingresos
        for line in lines_data:
            if line['account_code'] == '4':  # INGRESOS
                values = [p['amount'] for p in line['periods']]
                
                # Análisis simple de estacionalidad
                if len(values) >= 12:
                    monthly_avg = [0] * 12
                    monthly_count = [0] * 12
                    
                    for i, period in enumerate(comparison.period_ids):
                        month = period.date_from.month - 1
                        monthly_avg[month] += values[i]
                        monthly_count[month] += 1
                    
                    # Calcular promedios
                    for i in range(12):
                        if monthly_count[i] > 0:
                            monthly_avg[i] /= monthly_count[i]
                    
                    # Encontrar mes pico
                    max_month = monthly_avg.index(max(monthly_avg))
                    min_month = monthly_avg.index(min(monthly_avg))
                    
                    months = ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
                             'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre']
                    
                    return (f"Estacionalidad detectada: Peak en {months[max_month]}, "
                           f"mínimo en {months[min_month]}")
        
        return None
    
    # Métodos de cálculo de ratios
    def _calculate_current_ratio(self, date_from, date_to, company_id, target_move):
        """Calcula ratio de liquidez corriente"""
        current_assets = self._get_balance_by_type(
            ['asset_current', 'asset_receivable', 'asset_cash'],
            date_from, date_to, company_id, target_move
        )
        
        current_liabilities = self._get_balance_by_type(
            ['liability_current', 'liability_payable'],
            date_from, date_to, company_id, target_move
        )
        
        if current_liabilities != 0:
            return current_assets / abs(current_liabilities)
        return 0
    
    def _calculate_acid_ratio(self, date_from, date_to, company_id, target_move):
        """Calcula prueba ácida"""
        # Similar a current ratio pero sin inventarios
        liquid_assets = self._get_balance_by_type(
            ['asset_receivable', 'asset_cash'],
            date_from, date_to, company_id, target_move
        )
        
        current_liabilities = self._get_balance_by_type(
            ['liability_current', 'liability_payable'],
            date_from, date_to, company_id, target_move
        )
        
        if current_liabilities != 0:
            return liquid_assets / abs(current_liabilities)
        return 0
    
    def _calculate_debt_ratio(self, date_from, date_to, company_id, target_move):
        """Calcula ratio de endeudamiento"""
        total_liabilities = self._get_balance_by_type(
            ['liability_current', 'liability_non_current', 'liability_payable'],
            date_from, date_to, company_id, target_move
        )
        
        total_assets = self._get_balance_by_type(
            ['asset_receivable', 'asset_cash', 'asset_current', 
             'asset_non_current', 'asset_fixed'],
            date_from, date_to, company_id, target_move
        )
        
        if total_assets != 0:
            return abs(total_liabilities) / total_assets
        return 0
    
    def _calculate_roe(self, date_from, date_to, company_id, target_move):
        """Calcula retorno sobre patrimonio"""
        net_income = self._get_period_movement(
            ['income', 'income_other', 'expense', 'expense_direct_cost', 'expense_depreciation'],
            date_from, date_to, company_id, target_move
        )
        
        equity = self._get_balance_by_type(
            ['equity', 'equity_unaffected'],
            date_from, date_to, company_id, target_move
        )
        
        if equity != 0:
            return (net_income / abs(equity)) * 100
        return 0
    
    def _calculate_roa(self, date_from, date_to, company_id, target_move):
        """Calcula retorno sobre activos"""
        net_income = self._get_period_movement(
            ['income', 'income_other', 'expense', 'expense_direct_cost', 'expense_depreciation'],
            date_from, date_to, company_id, target_move
        )
        
        total_assets = self._get_balance_by_type(
            ['asset_receivable', 'asset_cash', 'asset_current', 
             'asset_non_current', 'asset_fixed'],
            date_from, date_to, company_id, target_move
        )
        
        if total_assets != 0:
            return (net_income / total_assets) * 100
        return 0
    
    def _calculate_gross_margin(self, date_from, date_to, company_id, target_move):
        """Calcula margen bruto"""
        revenue = abs(self._get_period_movement(
            ['income', 'income_other'],
            date_from, date_to, company_id, target_move
        ))
        
        cogs = abs(self._get_period_movement(
            ['expense_direct_cost'],
            date_from, date_to, company_id, target_move
        ))
        
        if revenue != 0:
            return ((revenue - cogs) / revenue) * 100
        return 0
    
    def _calculate_operating_margin(self, date_from, date_to, company_id, target_move):
        """Calcula margen operacional"""
        revenue = abs(self._get_period_movement(
            ['income', 'income_other'],
            date_from, date_to, company_id, target_move
        ))
        
        operating_expenses = abs(self._get_period_movement(
            ['expense', 'expense_direct_cost', 'expense_depreciation'],
            date_from, date_to, company_id, target_move
        ))
        
        if revenue != 0:
            return ((revenue - operating_expenses) / revenue) * 100
        return 0
    
    def _calculate_asset_turnover(self, date_from, date_to, company_id, target_move):
        """Calcula rotación de activos"""
        revenue = abs(self._get_period_movement(
            ['income', 'income_other'],
            date_from, date_to, company_id, target_move
        ))
        
        total_assets = self._get_balance_by_type(
            ['asset_receivable', 'asset_cash', 'asset_current', 
             'asset_non_current', 'asset_fixed'],
            date_from, date_to, company_id, target_move
        )
        
        if total_assets != 0:
            return revenue / total_assets
        return 0
    
    def export_to_excel(self, comparison):
        """
        Exporta la comparación multi-período a Excel con gráficos
        """
        try:
            from xlsxwriter import Workbook
            output = io.BytesIO()
            workbook = Workbook(output, {'in_memory': True})
            
            # Crear hojas
            self._create_comparison_sheet(workbook, comparison)
            self._create_chart_sheet(workbook, comparison)
            if comparison.show_trends:
                self._create_trends_sheet(workbook, comparison)
            
            workbook.close()
            output.seek(0)
            
            # Crear attachment
            filename = f"Comparacion_{comparison.comparison_type}_{comparison.company_id.name}_{fields.Date.today()}.xlsx"
            attachment = self.env['ir.attachment'].create({
                'name': filename,
                'type': 'binary',
                'datas': base64.b64encode(output.read()),
                'res_model': comparison._name,
                'res_id': comparison.id,
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
    
    def _create_comparison_sheet(self, workbook, comparison):
        """Crea hoja principal de comparación"""
        worksheet = workbook.add_worksheet('Comparación')
        
        # Formatos
        formats = self._get_excel_formats(workbook)
        
        # Header
        worksheet.merge_range(0, 0, 0, len(comparison.period_ids) + 1,
                            f"{comparison.name}", formats['header'])
        
        # Column headers
        row = 2
        worksheet.write(row, 0, "Cuenta", formats['column_header'])
        
        col = 1
        for period in comparison.period_ids.sorted('sequence'):
            worksheet.write(row, col, period.name, formats['column_header'])
            col += 1
        
        # Data
        row = 3
        for line in comparison.line_ids:
            if line.is_total_line:
                line_format = formats['total_line']
            else:
                line_format = formats['account_line']
            
            worksheet.write(row, 0, line.account_name, line_format)
            
            col = 1
            for period in comparison.period_ids.sorted('sequence'):
                value = line.value_ids.filtered(lambda v: v.period_id == period)
                amount = value.amount if value else 0
                worksheet.write(row, col, amount, line_format)
                col += 1
            
            row += 1
    
    def _create_chart_sheet(self, workbook, comparison):
        """Crea hoja con gráficos"""
        worksheet = workbook.add_worksheet('Gráficos')
        
        # Crear gráfico de líneas
        chart = workbook.add_chart({'type': 'line'})
        chart.set_title({'name': 'Evolución Multi-período'})
        chart.set_size({'width': 720, 'height': 480})
        
        # Agregar series principales
        data_row = 3
        for line in comparison.line_ids.filtered(lambda l: l.is_total_line)[:5]:
            chart.add_series({
                'name': line.account_name,
                'categories': ['Comparación', 2, 1, 2, len(comparison.period_ids)],
                'values': ['Comparación', data_row, 1, data_row, len(comparison.period_ids)],
            })
            data_row += 1
        
        worksheet.insert_chart('B2', chart)
    
    def _create_trends_sheet(self, workbook, comparison):
        """Crea hoja de análisis de tendencias"""
        worksheet = workbook.add_worksheet('Tendencias')
        
        formats = self._get_excel_formats(workbook)
        
        worksheet.write(0, 0, "ANÁLISIS DE TENDENCIAS", formats['header'])
        worksheet.write_string(2, 0, comparison.trend_analysis or "Sin análisis disponible")
        
        worksheet.write(10, 0, "INSIGHTS CLAVE", formats['header'])
        worksheet.write_string(12, 0, comparison.key_insights or "Sin insights disponibles")
    
    def _get_excel_formats(self, workbook):
        """Define formatos para Excel"""
        return {
            'header': workbook.add_format({
                'bold': True,
                'font_size': 16,
                'align': 'center',
                'bg_color': '#1B5E8C',
                'font_color': 'white'
            }),
            'column_header': workbook.add_format({
                'bold': True,
                'align': 'center',
                'bg_color': '#4A90E2',
                'font_color': 'white',
                'border': 1
            }),
            'account_line': workbook.add_format({
                'border': 1,
                'num_format': '#,##0.00'
            }),
            'total_line': workbook.add_format({
                'bold': True,
                'bg_color': '#FFE599',
                'border': 2,
                'num_format': '#,##0.00'
            })
        }