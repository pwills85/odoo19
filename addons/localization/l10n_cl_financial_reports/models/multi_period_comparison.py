# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import UserError
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
import json
import logging

_logger = logging.getLogger(__name__)


class MultiPeriodComparison(models.Model):
    """
    Comparación Multi-período para análisis de tendencias financieras.
    Permite comparar hasta 12 períodos con visualización gráfica.
    """
    _name = 'account.multi.period.comparison'
    _description = 'Comparación Financiera Multi-período'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'
    
    # Override del campo name
    name = fields.Char(
        string='Nombre del Reporte',
        compute='_compute_name',
        store=True
    )
    
    # Tipo de comparación
    comparison_type = fields.Selection([
        ('monthly', 'Comparación Mensual'),
        ('quarterly', 'Comparación Trimestral'),
        ('yearly', 'Comparación Anual'),
        ('custom', 'Períodos Personalizados')
    ], string='Tipo de Comparación', required=True, default='monthly')
    
    # Configuración de períodos
    period_count = fields.Integer(
        string='Número de Períodos',
        default=6,
        required=True,
        help='Número de períodos a comparar (máximo 12)'
    )
    
    base_date = fields.Date(
        string='Fecha Base',
        required=True,
        default=fields.Date.context_today,
        help='Fecha de referencia para calcular los períodos'
    )
    
    # Opciones de reporte
    report_type = fields.Selection([
        ('balance_sheet', 'Balance General'),
        ('profit_loss', 'Estado de Resultados'),
        ('cash_flow', 'Flujo de Efectivo'),
        ('ratios', 'Ratios Financieros'),
        ('custom_accounts', 'Cuentas Específicas')
    ], string='Tipo de Reporte', required=True, default='profit_loss')
    
    # Filtros adicionales
    account_ids = fields.Many2many(
        'account.account',
        string='Cuentas Específicas',
        help='Solo para tipo "Cuentas Específicas"'
    )
    
    analytic_account_ids = fields.Many2many(
        'account.analytic.account',
        string='Cuentas Analíticas'
    )
    
    target_move = fields.Selection([
        ('posted', 'Asientos Publicados'),
        ('all', 'Todos los Asientos')
    ], string='Movimientos Objetivo', required=True, default='posted')
    
    # Opciones de visualización
    show_percentage = fields.Boolean(
        string='Mostrar Porcentajes',
        default=True,
        help='Mostrar variación porcentual entre períodos'
    )
    
    show_accumulated = fields.Boolean(
        string='Mostrar Acumulados',
        default=False,
        help='Mostrar valores acumulados además de los del período'
    )
    
    show_trends = fields.Boolean(
        string='Mostrar Tendencias',
        default=True,
        help='Incluir análisis de tendencias y proyecciones'
    )
    
    comparison_method = fields.Selection([
        ('absolute', 'Valores Absolutos'),
        ('percentage', 'Análisis Vertical (%)'),
        ('base_100', 'Base 100 (Índice)'),
        ('growth_rate', 'Tasa de Crecimiento')
    ], string='Método de Comparación', default='absolute', required=True)
    
    # Estado y resultados
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('computing', 'Calculando'),
        ('computed', 'Calculado'),
        ('error', 'Error')
    ], string='Estado', default='draft', required=True)
    
    validation_errors = fields.Text(
        string='Errores de Validación',
        readonly=True,
        help='Mensajes de error encontrados durante la generación del reporte'
    )
    
    # Líneas de comparación
    line_ids = fields.One2many(
        'account.multi.period.comparison.line',
        'comparison_id',
        string='Líneas de Comparación'
    )
    
    # Períodos calculados
    period_ids = fields.One2many(
        'account.multi.period.comparison.period',
        'comparison_id',
        string='Períodos'
    )
    
    # Datos para gráficos (JSON)
    chart_data = fields.Text(
        string='Datos del Gráfico',
        compute='_compute_chart_data'
    )
    
    # Análisis de tendencias
    trend_analysis = fields.Text(
        string='Análisis de Tendencias'
    )
    
    # KPIs destacados
    key_insights = fields.Text(
        string='Insights Clave'
    )
    
    # Cache
    last_compute = fields.Datetime(string='Última Actualización')
    
    # Campos de compañía y moneda
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='company_id.currency_id',
        store=True
    )
    
    @api.depends_context('company')
    @api.depends('comparison_type', 'period_count', 'report_type', 'company_id')
    def _compute_name(self):
        for record in self:
            type_name = dict(record._fields['comparison_type'].selection).get(record.comparison_type, '')
            report_name = dict(record._fields['report_type'].selection).get(record.report_type, '')
            record.name = f"{report_name} - {type_name} ({record.period_count} períodos) - {record.company_id.name}"
    
    @api.constrains('period_count')
    def _check_period_count(self):
        for record in self:
            if record.period_count < 2 or record.period_count > 12:
                raise UserError(_("El número de períodos debe estar entre 2 y 12."))
    
    @api.onchange('comparison_type', 'base_date', 'period_count')
    def _onchange_periods(self):
        """Calcula y muestra preview de los períodos que se compararán"""
        if self.comparison_type and self.base_date and self.period_count:
            self._calculate_periods()
    
    def _calculate_periods(self):
        """Calcula los períodos según el tipo de comparación"""
        self.period_ids.unlink()
        
        periods = []
        for i in range(self.period_count):
            if self.comparison_type == 'monthly':
                # Períodos mensuales hacia atrás
                date_to = self.base_date - relativedelta(months=i)
                date_from = date_to.replace(day=1)
                date_to = date_to + relativedelta(day=31)  # Último día del mes
                
            elif self.comparison_type == 'quarterly':
                # Trimestres hacia atrás
                date_to = self.base_date - relativedelta(months=i*3)
                # Ajustar al final del trimestre
                quarter = (date_to.month - 1) // 3
                date_to = date(date_to.year, quarter * 3 + 3, 1) + relativedelta(day=31)
                date_from = date_to - relativedelta(months=2, day=1)
                
            elif self.comparison_type == 'yearly':
                # Años completos hacia atrás
                date_to = self.base_date - relativedelta(years=i)
                date_from = date(date_to.year, 1, 1)
                date_to = date(date_to.year, 12, 31)
                
            else:  # custom
                # Por defecto, períodos mensuales
                date_to = self.base_date - relativedelta(months=i)
                date_from = date_to.replace(day=1)
                date_to = date_to + relativedelta(day=31)
            
            period_name = self._get_period_name(date_from, date_to, self.comparison_type)
            
            self.env['account.multi.period.comparison.period'].create({
                'comparison_id': self.id,
                'sequence': i + 1,
                'name': period_name,
                'date_from': date_from,
                'date_to': date_to,
                'is_base_period': i == 0
            })
    
    def _get_period_name(self, date_from, date_to, comparison_type):
        """Genera nombre descriptivo para el período"""
        if comparison_type == 'monthly':
            return date_from.strftime('%B %Y')
        elif comparison_type == 'quarterly':
            quarter = (date_from.month - 1) // 3 + 1
            return f"Q{quarter} {date_from.year}"
        elif comparison_type == 'yearly':
            return str(date_from.year)
        else:
            return f"{date_from.strftime('%d/%m/%Y')} - {date_to.strftime('%d/%m/%Y')}"
    
    def action_compute_comparison(self):
        """
        Acción principal para calcular la comparación multi-período
        """
        self.ensure_one()
        
        try:
            # Cambiar estado
            self.write({'state': 'computing', 'last_compute': fields.Datetime.now()})
            
            # Limpiar datos anteriores
            self.line_ids.unlink()
            
            # Calcular períodos si no existen
            if not self.period_ids:
                self._calculate_periods()
            
            # Obtener servicio
            from ..services.multi_period_comparison_service import MultiPeriodComparisonService
            service = MultiPeriodComparisonService(self.env)
            
            # Ejecutar comparación
            result = service.compute_comparison(self)
            
            # Crear líneas de resultado
            self._create_comparison_lines(result['lines'])
            
            # Guardar análisis
            self.write({
                'state': 'computed',
                'trend_analysis': result.get('trend_analysis', ''),
                'key_insights': result.get('key_insights', '')
            })
            
            # Retornar acción para mostrar resultados
            return {
                'type': 'ir.actions.client',
                'tag': 'multi_period_comparison_report',
                'context': {
                    'active_id': self.id,
                    'active_model': self._name,
                }
            }
            
        except Exception as e:
            _logger.error(f"Error computing multi-period comparison: {str(e)}")
            self.write({
                'state': 'error',
                'validation_errors': str(e)
            })
            raise UserError(_("Error al calcular la comparación: %s") % str(e))
    
    def _create_comparison_lines(self, lines_data):
        """Crea las líneas de comparación desde los datos calculados"""
        batch_service = self.env.service('l10n_cl.batch.operation')
        
        # Preparar datos para creación batch de líneas
        lines_vals_list = []
        line_to_periods_map = []
        
        for sequence, line_data in enumerate(lines_data, 1):
            # Preparar valores de línea principal
            line_vals = {
                'comparison_id': self.id,
                'sequence': sequence,
                'account_id': line_data.get('account_id'),
                'account_code': line_data.get('account_code', ''),
                'account_name': line_data.get('account_name', ''),
                'account_type': line_data.get('account_type', ''),
                'is_total_line': line_data.get('is_total_line', False),
                'hierarchy_level': line_data.get('hierarchy_level', 0),
            }
            lines_vals_list.append(line_vals)
            
            # Guardar datos de períodos para procesamiento posterior
            line_to_periods_map.append(line_data.get('periods', []))
        
        # Crear todas las líneas principales en batch
        if lines_vals_list:
            created_lines = batch_service.batch_create(
                'account.multi.period.comparison.line', 
                lines_vals_list
            )
            
            # Preparar valores por período para creación batch
            period_vals_list = []
            for line, periods_data in zip(created_lines, line_to_periods_map):
                for period_data in periods_data:
                    period_vals_list.append({
                        'line_id': line.id,
                        'period_id': period_data['period_id'],
                        'amount': period_data['amount'],
                        'percentage': period_data.get('percentage', 0.0),
                        'accumulated': period_data.get('accumulated', 0.0),
                        'growth_rate': period_data.get('growth_rate', 0.0),
                    })
            
            # Crear todos los valores de período en batch
            if period_vals_list:
                batch_service.batch_create(
                    'account.multi.period.comparison.value',
                    period_vals_list
                )
    
    @api.depends('line_ids', 'line_ids.value_ids', 'show_trends')
    def _compute_chart_data(self):
        """Prepara datos para visualización en gráficos"""
        for record in self:
            if record.state != 'computed':
                record.chart_data = '{}'
                continue
            
            # Preparar estructura de datos para Chart.js
            chart_data = {
                'labels': [],
                'datasets': [],
                'trend_lines': [],
                'annotations': []
            }
            
            # Obtener etiquetas de períodos
            chart_data['labels'] = [p.name for p in record.period_ids.sorted('sequence')]
            
            # Preparar datasets principales (top 10 cuentas por variación)
            main_lines = record.line_ids.filtered(
                lambda l: not l.is_total_line and l.account_id
            ).sorted(key=lambda l: abs(sum(v.amount for v in l.value_ids)), reverse=True)[:10]
            
            for line in main_lines:
                values = []
                for period in record.period_ids.sorted('sequence'):
                    value = line.value_ids.filtered(lambda v: v.period_id == period)
                    values.append(value.amount if value else 0)
                
                chart_data['datasets'].append({
                    'label': line.account_name,
                    'data': values,
                    'borderColor': self._get_chart_color(len(chart_data['datasets'])),
                    'fill': False,
                    'tension': 0.1
                })
            
            # Agregar línea de tendencia si está habilitada
            if record.show_trends and main_lines:
                # Calcular tendencia promedio
                trend_values = []
                for i, period in enumerate(record.period_ids.sorted('sequence')):
                    total = sum(
                        line.value_ids.filtered(lambda v: v.period_id == period).amount
                        for line in main_lines
                    )
                    trend_values.append(total / len(main_lines) if main_lines else 0)
                
                chart_data['trend_lines'].append({
                    'label': 'Tendencia Promedio',
                    'data': trend_values,
                    'borderColor': '#FF6B6B',
                    'borderDash': [5, 5],
                    'fill': False
                })
            
            record.chart_data = json.dumps(chart_data)
    
    def _get_chart_color(self, index):
        """Retorna color para gráfico según índice"""
        colors = [
            '#4A90E2', '#7ED321', '#F5A623', '#BD10E0',
            '#50E3C2', '#F8E71C', '#B8E986', '#FF6B6B',
            '#4A4A4A', '#9013FE'
        ]
        return colors[index % len(colors)]
    
    def action_export_excel(self):
        """Exporta la comparación a Excel con gráficos"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular la comparación antes de exportar."))
        
        from ..services.multi_period_comparison_service import MultiPeriodComparisonService
        service = MultiPeriodComparisonService(self.env)
        return service.export_to_excel(self)
    
    def action_export_pdf(self):
        """Exporta la comparación a PDF con gráficos"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular la comparación antes de exportar."))
        
        return self.env.ref('l10n_cl_financial_reports.action_report_multi_period_comparison').report_action(self)
    
    def action_refresh(self):
        """Recalcula la comparación"""
        return self.action_compute_comparison()
    
    def action_open_dashboard(self):
        """Abre dashboard interactivo con gráficos"""
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'tag': 'multi_period_comparison_dashboard',
            'context': {
                'active_id': self.id,
                'comparison_data': self.chart_data,
            }
        }


class MultiPeriodComparisonPeriod(models.Model):
    """Períodos individuales en la comparación"""
    _name = 'account.multi.period.comparison.period'
    _description = 'Período de Comparación'
    _order = 'sequence'
    
    comparison_id = fields.Many2one(
        'account.multi.period.comparison',
        string='Comparación',
        required=True,
        ondelete='cascade'
    )
    
    sequence = fields.Integer(string='Secuencia', default=1)
    name = fields.Char(string='Nombre del Período', required=True)
    date_from = fields.Date(string='Fecha Desde', required=True)
    date_to = fields.Date(string='Fecha Hasta', required=True)
    is_base_period = fields.Boolean(string='Período Base', default=False)
    
    # Totales del período (calculados)
    total_debit = fields.Monetary(
        string='Total Débitos',
        currency_field='currency_id'
    )
    total_credit = fields.Monetary(
        string='Total Créditos',
        currency_field='currency_id'
    )
    total_balance = fields.Monetary(
        string='Balance Total',
        currency_field='currency_id'
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        related='comparison_id.currency_id'
    )


class MultiPeriodComparisonLine(models.Model):
    """Líneas de comparación (cuentas o grupos)"""
    _name = 'account.multi.period.comparison.line'
    _description = 'Línea de Comparación Multi-período'
    _order = 'sequence, account_code'
    
    comparison_id = fields.Many2one(
        'account.multi.period.comparison',
        string='Comparación',
        required=True,
        ondelete='cascade'
    )
    
    sequence = fields.Integer(string='Secuencia', default=10)
    
    # Datos de la cuenta
    account_id = fields.Many2one('account.account', string='Cuenta')
    account_code = fields.Char(string='Código', required=True)
    account_name = fields.Char(string='Nombre', required=True)
    account_type = fields.Char(string='Tipo')
    
    # Jerarquía
    hierarchy_level = fields.Integer(string='Nivel', default=0)
    is_total_line = fields.Boolean(string='Es Línea de Total', default=False)
    
    # Valores por período
    value_ids = fields.One2many(
        'account.multi.period.comparison.value',
        'line_id',
        string='Valores'
    )
    
    # Análisis calculados
    average_amount = fields.Monetary(
        string='Promedio',
        compute='_compute_statistics',
        currency_field='currency_id'
    )
    standard_deviation = fields.Float(
        string='Desviación Estándar',
        compute='_compute_statistics'
    )
    trend_direction = fields.Selection([
        ('up', 'Creciente'),
        ('down', 'Decreciente'),
        ('stable', 'Estable'),
        ('volatile', 'Volátil')
    ], string='Tendencia', compute='_compute_statistics')
    
    currency_id = fields.Many2one(
        'res.currency',
        related='comparison_id.currency_id'
    )
    
    @api.depends('value_ids.amount')
    def _compute_statistics(self):
        """Calcula estadísticas de la línea"""
        import statistics
        
        for line in self:
            amounts = [v.amount for v in line.value_ids.sorted('period_id.sequence')]
            
            if not amounts:
                line.average_amount = 0
                line.standard_deviation = 0
                line.trend_direction = 'stable'
                continue
            
            # Promedio
            line.average_amount = statistics.mean(amounts)
            
            # Desviación estándar
            if len(amounts) > 1:
                line.standard_deviation = statistics.stdev(amounts)
            else:
                line.standard_deviation = 0
            
            # Determinar tendencia
            if len(amounts) >= 3:
                # Calcular pendiente de regresión lineal simple
                x_values = list(range(len(amounts)))
                x_mean = statistics.mean(x_values)
                y_mean = statistics.mean(amounts)
                
                numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, amounts))
                denominator = sum((x - x_mean) ** 2 for x in x_values)
                
                if denominator != 0:
                    slope = numerator / denominator
                    
                    # Determinar dirección basada en pendiente y volatilidad
                    cv = line.standard_deviation / abs(line.average_amount) if line.average_amount != 0 else 0
                    
                    if cv > 0.5:  # Alta volatilidad
                        line.trend_direction = 'volatile'
                    elif abs(slope) < (line.average_amount * 0.05):  # Cambio menor al 5%
                        line.trend_direction = 'stable'
                    elif slope > 0:
                        line.trend_direction = 'up'
                    else:
                        line.trend_direction = 'down'
                else:
                    line.trend_direction = 'stable'
            else:
                line.trend_direction = 'stable'


class MultiPeriodComparisonValue(models.Model):
    """Valores específicos por período y línea"""
    _name = 'account.multi.period.comparison.value'
    _description = 'Valor de Comparación'
    
    line_id = fields.Many2one(
        'account.multi.period.comparison.line',
        string='Línea',
        required=True,
        ondelete='cascade'
    )
    
    period_id = fields.Many2one(
        'account.multi.period.comparison.period',
        string='Período',
        required=True,
        ondelete='cascade'
    )
    
    # Valores
    amount = fields.Monetary(
        string='Monto',
        currency_field='currency_id'
    )
    percentage = fields.Float(
        string='Porcentaje',
        digits=(16, 2),
        help='Porcentaje respecto al total del período'
    )
    accumulated = fields.Monetary(
        string='Acumulado',
        currency_field='currency_id',
        help='Valor acumulado hasta este período'
    )
    growth_rate = fields.Float(
        string='Tasa de Crecimiento',
        digits=(16, 2),
        help='Tasa de crecimiento respecto al período anterior'
    )
    
    # Comparación con período base
    base_index = fields.Float(
        string='Índice Base 100',
        digits=(16, 2),
        help='Índice respecto al período base (base = 100)'
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        related='line_id.currency_id'
    )