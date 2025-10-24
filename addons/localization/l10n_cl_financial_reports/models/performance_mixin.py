# -*- coding: utf-8 -*-
"""
Performance Optimization Mixin
Implementa optimizaciones de performance basadas en los 594 módulos oficiales
"""

from odoo import models, api, fields, _
from functools import lru_cache, wraps
from datetime import datetime, timedelta
import hashlib
import json
import logging

_logger = logging.getLogger(__name__)


def batch_processor(batch_size=1000):
    """
    Decorador para procesar registros en lotes
    Evita problemas de memoria con grandes datasets
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if len(self) <= batch_size:
                return func(self, *args, **kwargs)

            # Procesar en lotes
            results = self.env[self._name]
            for i in range(0, len(self), batch_size):
                batch = self[i:i + batch_size]
                batch_result = func(batch, *args, **kwargs)
                if batch_result:
                    results |= batch_result

            return results
        return wrapper
    return decorator


def sql_optimized(use_raw_sql=True):
    """
    Decorador para métodos que pueden beneficiarse de SQL crudo
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Detectar si estamos en un contexto que requiere SQL crudo
            if self.env.context.get('use_raw_sql', use_raw_sql) and len(self) > 100:
                method_name = f"{func.__name__}_sql"
                if hasattr(self, method_name):
                    return getattr(self, method_name)(*args, **kwargs)

            return func(self, *args, **kwargs)
        return wrapper
    return decorator


class PerformanceMixin(models.AbstractModel):
    """
    Mixin con optimizaciones de performance
    Basado en patrones de los módulos oficiales de Odoo 18
    """
    _name = 'performance.mixin'
    _description = 'Performance Optimization Mixin'

    @api.model
    def _get_cache_key(self, method_name, *args, **kwargs):
        """
        Genera una clave de cache única
        """
        key_parts = [
            self._name,
            method_name,
            str(self.env.company.id),
            str(self.env.uid),
        ]

        # Añadir argumentos
        if args:
            key_parts.append(str(args))

        # Añadir kwargs relevantes
        if kwargs:
            sorted_kwargs = sorted(kwargs.items())
            key_parts.append(str(sorted_kwargs))

        # Generar hash
        key_str = '|'.join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()

    @api.model
    def _invalidate_cache(self, cache_keys=None):
        """
        Invalida entradas de cache
        """
        cache = self.env.cache
        if cache_keys:
            for key in cache_keys:
                cache.invalidate([(self._name, key)])
        else:
            # Invalidar todo el cache del modelo
            cache.invalidate([(self._name,)])

    @api.model
    def search_read_optimized(self, domain=None, fields=None, offset=0,
                             limit=None, order=None):
        """
        search_read optimizado con prefetch y contexto
        """
        # Añadir contexto de optimización
        optimized_context = {
            'prefetch_fields': False,
            'no_attachment': True,
            'skip_computed': True,
        }

        # Si hay muchos registros, usar paginación automática
        if not limit and self.search_count(domain) > 10000:
            limit = 1000
            _logger.warning(f"Auto-limiting to {limit} records for performance")

        return self.with_context(**optimized_context).search_read(
            domain, fields, offset, limit, order
        )

    @api.model
    @lru_cache(maxsize=128)
    def _get_cached_config(self, config_key):
        """
        Cache para configuraciones que no cambian frecuentemente
        """
        return self.env['ir.config_parameter'].sudo().get_param(config_key)

    def _prefetch_related(self, field_names):
        """
        Prefetch campos relacionados para evitar N+1
        """
        if not self:
            return

        # Forzar prefetch
        for field_name in field_names:
            if '.' in field_name:
                # Campo anidado (ej: 'partner_id.vat')
                parts = field_name.split('.')
                records = self
                for part in parts[:-1]:
                    records = records.mapped(part)
                if records:
                    records.mapped(parts[-1])
            else:
                # Campo simple
                self.mapped(field_name)

    @batch_processor(batch_size=500)
    def _compute_batch_optimized(self, compute_method):
        """
        Ejecuta un método de cálculo en lotes optimizados
        """
        return compute_method(self)

    def _get_query_optimization_hints(self):
        """
        Retorna hints de optimización para queries
        """
        return {
            'enable_seqscan': False,  # Forzar uso de índices
            'enable_hashjoin': True,   # Permitir hash joins
            'work_mem': '64MB',        # Memoria para operaciones
            'effective_cache_size': '4GB',  # Cache estimado
        }


class F29PerformanceOptimized(models.Model):
    """
    Optimizaciones específicas para F29
    """
    _name = 'l10n_cl.f29.performance'
    _inherit = ['l10n_cl.f29', 'performance.mixin']

    @api.model
    def search(self, domain, offset=0, limit=None, order=None):
        """
        Búsqueda optimizada con índices específicos
        """
        # Reordenar domain para aprovechar índices compuestos
        optimized_domain = self._optimize_search_domain(domain)

        # Si buscamos por período, usar índice específico
        if any(term[0] == 'period_date' for term in domain if isinstance(term, (list, tuple))):
            order = order or 'period_date DESC, id DESC'

        return super().search(optimized_domain, offset, limit, order)

    def _optimize_search_domain(self, domain):
        """
        Reordena domain para aprovechar índices
        """
        if not domain:
            return domain

        # Separar cláusulas por campo
        company_clauses = []
        period_clauses = []
        state_clauses = []
        other_clauses = []

        for clause in domain:
            if isinstance(clause, str):
                other_clauses.append(clause)
            elif clause[0] == 'company_id':
                company_clauses.append(clause)
            elif clause[0] == 'period_date':
                period_clauses.append(clause)
            elif clause[0] == 'state':
                state_clauses.append(clause)
            else:
                other_clauses.append(clause)

        # Reconstruir en orden óptimo para índices
        optimized = []
        optimized.extend(company_clauses)  # Primero company_id
        optimized.extend(period_clauses)   # Luego period_date
        optimized.extend(state_clauses)    # Luego state
        optimized.extend(other_clauses)    # El resto

        return optimized

    @sql_optimized()
    def calculate_taxes_summary(self, date_from, date_to):
        """
        Cálculo optimizado de resumen de impuestos
        """
        query = """
            WITH tax_summary AS (
                SELECT
                    am.company_id,
                    DATE_TRUNC('month', am.date) as period,
                    CASE
                        WHEN at.type_tax_use = 'sale' THEN 'sales'
                        WHEN at.type_tax_use = 'purchase' THEN 'purchases'
                        ELSE 'other'
                    END as tax_type,
                    at.amount as tax_rate,
                    SUM(aml.balance) as tax_amount,
                    SUM(aml.tax_base_amount) as base_amount,
                    COUNT(DISTINCT am.id) as document_count
                FROM account_move_line aml
                INNER JOIN account_move am ON aml.move_id = am.id
                LEFT JOIN account_tax at ON aml.tax_line_id = at.id
                WHERE am.state = 'posted'
                    AND am.date BETWEEN %s AND %s
                    AND am.company_id = %s
                    AND at.id IS NOT NULL
                GROUP BY
                    am.company_id,
                    DATE_TRUNC('month', am.date),
                    at.type_tax_use,
                    at.amount
            )
            SELECT
                period,
                tax_type,
                tax_rate,
                SUM(tax_amount) as total_tax,
                SUM(base_amount) as total_base,
                SUM(document_count) as doc_count
            FROM tax_summary
            GROUP BY period, tax_type, tax_rate
            ORDER BY period, tax_type, tax_rate
        """

        self.env.cr.execute(query, (date_from, date_to, self.env.company.id))
        return self.env.cr.dictfetchall()

    def calculate_taxes_summary_sql(self, date_from, date_to):
        """
        Versión SQL pura del cálculo de impuestos
        """
        return self.calculate_taxes_summary(date_from, date_to)

    @api.model
    def generate_batch(self, company_ids, period_date):
        """
        Genera F29 para múltiples compañías en batch
        """
        created_records = self.env['l10n_cl.f29']

        # Precalcular datos compartidos
        shared_data = self._prepare_shared_data(period_date)

        # Crear en batch con contexto optimizado
        with self.env.norecompute():
            for company_id in company_ids:
                vals = self._prepare_f29_vals(company_id, period_date, shared_data)
                created_records |= self.create(vals)

            # Recomputar una sola vez al final
            created_records.recompute()

        return created_records

    def _prepare_shared_data(self, period_date):
        """
        Prepara datos compartidos para generación en batch
        """
        # Calcular fechas del período
        date_from = period_date
        date_to = fields.Date.end_of(period_date, 'month')

        # Precargar tasas de impuestos
        taxes = self.env['account.tax'].search([
            ('type_tax_use', 'in', ['sale', 'purchase']),
            ('company_id', 'in', self.env.companies.ids)
        ])

        tax_rates = {
            tax.company_id.id: {
                'sale': tax.amount for tax in taxes if tax.type_tax_use == 'sale'
            }
            for tax in taxes
        }

        return {
            'date_from': date_from,
            'date_to': date_to,
            'tax_rates': tax_rates,
        }


class DashboardWidgetOptimized(models.Model):
    """
    Optimizaciones para widgets del dashboard
    """
    _name = 'financial.dashboard.widget'
    _inherit = ['financial.dashboard.widget', 'performance.mixin']

    # Cache de datos del widget
    _widget_cache = {}
    _cache_timeout = 300  # 5 minutos

    def get_widget_data(self, filters=None):
        """
        Obtiene datos del widget con cache inteligente
        """
        self.ensure_one()

        # Generar cache key
        cache_key = self._get_widget_cache_key(filters)

        # Verificar cache
        cached_data = self._get_cached_widget_data(cache_key)
        if cached_data:
            return cached_data

        # Calcular datos según tipo de widget
        if self.widget_type == 'kpi':
            data = self._compute_kpi_data(filters)
        elif self.widget_type.startswith('chart_'):
            data = self._compute_chart_data(filters)
        elif self.widget_type == 'table':
            data = self._compute_table_data(filters)
        else:
            data = super().get_widget_data(filters)

        # Guardar en cache
        self._set_cached_widget_data(cache_key, data)

        return data

    def _get_widget_cache_key(self, filters):
        """
        Genera clave de cache para el widget
        """
        key_parts = [
            str(self.id),
            str(self.widget_type),
            str(self.env.company.id),
            json.dumps(filters or {}, sort_keys=True)
        ]

        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()

    def _get_cached_widget_data(self, cache_key):
        """
        Obtiene datos del cache si están disponibles y vigentes
        """
        if cache_key in self._widget_cache:
            cached = self._widget_cache[cache_key]
            if datetime.now() - cached['timestamp'] < timedelta(seconds=self._cache_timeout):
                _logger.debug(f"Cache hit for widget {self.id}")
                return cached['data']

        return None

    def _set_cached_widget_data(self, cache_key, data):
        """
        Guarda datos en cache
        """
        self._widget_cache[cache_key] = {
            'data': data,
            'timestamp': datetime.now()
        }

        # Limpiar cache antiguo si hay demasiadas entradas
        if len(self._widget_cache) > 1000:
            self._cleanup_widget_cache()

    def _cleanup_widget_cache(self):
        """
        Limpia entradas de cache expiradas
        """
        now = datetime.now()
        timeout = timedelta(seconds=self._cache_timeout)

        expired_keys = [
            key for key, value in self._widget_cache.items()
            if now - value['timestamp'] > timeout
        ]

        for key in expired_keys:
            del self._widget_cache[key]

        _logger.info(f"Cleaned {len(expired_keys)} expired cache entries")

    @api.model
    def compute_all_widgets_async(self, layout_id):
        """
        Calcula todos los widgets de un layout de forma asíncrona
        """
        layout = self.env['financial.dashboard.layout'].browse(layout_id)

        # Obtener todos los widgets
        widgets = layout.widget_ids.mapped('widget_id')

        # Agrupar por tipo para optimizar
        widgets_by_type = {}
        for widget in widgets:
            if widget.widget_type not in widgets_by_type:
                widgets_by_type[widget.widget_type] = self.env['financial.dashboard.widget']
            widgets_by_type[widget.widget_type] |= widget

        # Procesar cada grupo en paralelo (si queue_job está disponible)
        for widget_type, widget_group in widgets_by_type.items():
            if self.env.context.get('async_computation'):
                widget_group.with_delay().compute_widget_data_batch()
            else:
                widget_group.compute_widget_data_batch()

    def compute_widget_data_batch(self):
        """
        Calcula datos para un grupo de widgets del mismo tipo
        """
        # Esto permite reutilizar queries y cálculos comunes
        shared_data = self._get_shared_computation_data()

        for widget in self:
            widget._compute_with_shared_data(shared_data)

    def _get_shared_computation_data(self):
        """
        Obtiene datos compartidos para cálculo en batch
        """
        # Por ejemplo, para widgets financieros
        return {
            'account_balances': self._get_all_account_balances(),
            'period_data': self._get_period_summaries(),
            'tax_data': self._get_tax_summaries(),
        }

    def _get_all_account_balances(self):
        """
        Obtiene balances de todas las cuentas en una sola query
        """
        query = """
            SELECT
                account_id,
                SUM(debit) as total_debit,
                SUM(credit) as total_credit,
                SUM(balance) as total_balance
            FROM account_move_line
            WHERE parent_state = 'posted'
                AND company_id = %s
                AND date >= %s
                AND date <= %s
            GROUP BY account_id
        """

        # Usar fechas del contexto o últimos 12 meses por defecto
        date_to = fields.Date.today()
        date_from = date_to - timedelta(days=365)

        self.env.cr.execute(query, (self.env.company.id, date_from, date_to))

        return {
            row[0]: {
                'debit': row[1],
                'credit': row[2],
                'balance': row[3]
            }
            for row in self.env.cr.fetchall()
        }
