# -*- coding: utf-8 -*-
"""
Financial Dashboard Service Optimized
Servicio optimizado con caché y lazy loading
Siguiendo PROMPT_AGENT_IA.md y arquitectura de l10n_cl_base
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging
from functools import wraps
import hashlib

_logger = logging.getLogger(__name__)


def cached_method(ttl_key='financial_report'):
    """
    Decorador para métodos que usan caché.
    Integrado con l10n_cl.cache.service.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Generar clave de caché
            cache_key = self._generate_cache_key(func.__name__, *args, **kwargs)

            # Intentar obtener del caché
            cache_service = self.env['l10n_cl.cache.service']
            cached_value = cache_service.get(cache_key)

            if cached_value is not None:
                _logger.debug(f"Cache hit for {func.__name__}: {cache_key}")
                return cached_value

            # Ejecutar método y cachear resultado
            result = func(self, *args, **kwargs)

            # Determinar TTL
            ttl = cache_service.CACHE_TTL.get(ttl_key, 300)  # Default 5 min
            cache_service.set(cache_key, result, ttl=ttl)

            return result
        return wrapper
    return decorator


class FinancialDashboardServiceOptimized(models.AbstractModel):
    """
    Servicio optimizado de dashboard financiero.
    Hereda los mixins de performance y usa caché agresivamente.
    """
    _name = 'financial.dashboard.service.optimized'
# _inherit - Not inheriting any mixins for now to avoid dependencies
    _description = 'Financial Dashboard Service Optimized'

    @api.model
    def _generate_cache_key(self, method_name, *args, **kwargs):
        """
        Genera clave única de caché incluyendo contexto relevante.
        """
        # Datos base
        key_parts = [
            self._name,
            method_name,
            str(self.env.company.id),
            str(self.env.user.id),
            self.env.lang or 'en_US'
        ]

        # Añadir argumentos
        if args:
            key_parts.append(str(args))

        # Añadir kwargs relevantes (filtros)
        if kwargs:
            # Ordenar para consistencia
            sorted_kwargs = sorted(kwargs.items())
            key_parts.append(str(sorted_kwargs))

        # Generar hash para evitar claves muy largas
        key_str = '|'.join(key_parts)
        key_hash = hashlib.md5(key_str.encode()).hexdigest()

        return f"dashboard:{method_name}:{key_hash}"

    @api.model
    @cached_method('financial_report')
    def get_dashboard_data(self, layout_id, filters=None, options=None):
        """
        Obtiene todos los datos del dashboard con optimizaciones.
        """
        # Data structure initialization

        try:
            layout = self.env['financial.dashboard.layout'].browse(layout_id)
            if not layout.exists():
                raise UserError(_('Dashboard layout not found'))

            # Preparar respuesta con estructura para lazy loading
            dashboard_data = {
                'layout': self._get_layout_info(layout),
                'widgets': [],
                'metadata': {
                    'generated_at': fields.Datetime.now(),
                    'filters': filters or {},
                    'cache_enabled': True
                }
            }

            # Obtener widgets con lazy loading
            if options and options.get('lazy_load'):
                # Solo enviar estructura, datos se cargan por demanda
                for widget_user in layout.widget_ids:
                    dashboard_data['widgets'].append({
                        'id': widget_user.widget_id.id,
                        'user_widget_id': widget_user.id,
                        'widget_type': widget_user.widget_id.widget_type,
                        'name': widget_user.widget_id.name,
                        'grid_data': widget_user.grid_data,
                        'lazy_load': True,
                        'data': None  # Se cargará por demanda
                    })
            else:
                # Cargar todos los datos (modo tradicional)
                dashboard_data['widgets'] = self._load_all_widgets_optimized(
                    layout.widget_ids, filters
                )

            return dashboard_data
        except Exception as e:
            _logger.error(f"Error getting dashboard data: {str(e)}")
            return {'error': str(e), 'widgets': [], 'metadata': {}}

    @api.model
    def _get_layout_info(self, layout):
        """
        Obtiene información básica del layout.
        """
        return {
            'id': layout.id,
            'name': layout.name,
            'grid_config': layout.grid_config,
            'last_update': layout.last_update,
            'is_default': layout.is_default
        }

    @api.model
    def _load_all_widgets_optimized(self, widget_users, filters):
        """
        Carga todos los widgets de forma optimizada.
        """
        widgets_data = []

        # Precargar relaciones para evitar N+1
        widget_users = widget_users.with_prefetch(['widget_id'])

        # Agrupar por tipo para optimizar queries
        widgets_by_type = {}

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for wu in widget_users:
            widget_type = wu.widget_id.widget_type
            if widget_type not in widgets_by_type:
                widgets_by_type[widget_type] = []
            widgets_by_type[widget_type].append(wu)

        # Procesar por tipo (permite optimizaciones específicas)
        for widget_type, widget_list in widgets_by_type.items():
            if widget_type == 'table':
                widgets_data.extend(self._load_table_widgets_batch(widget_list, filters))
            elif widget_type.startswith('chart_'):
                widgets_data.extend(self._load_chart_widgets_batch(widget_list, filters))
            else:
                # Default: cargar uno por uno
                for wu in widget_list:
                    widgets_data.append(self._load_single_widget(wu, filters))

        return widgets_data

    @api.model
    def _load_table_widgets_batch(self, widget_users, filters):
        """
        Carga widgets de tabla en batch para optimizar queries.
        """
        results = []

        # Si todos usan el mismo servicio, hacer una sola query
        service_groups = {}
        for wu in widget_users:
            key = (wu.widget_id.data_service_model, wu.widget_id.data_service_method)
            if key not in service_groups:
                service_groups[key] = []
            service_groups[key].append(wu)

        for (model, method), widgets in service_groups.items():
            # Ejecutar una vez y distribuir resultados
            service = self.env[model]
            if hasattr(service, f"{method}_batch"):
                # Si existe versión batch del método
                batch_data = getattr(service, f"{method}_batch")(
                    widget_ids=[w.widget_id.id for w in widgets],
                    filters=filters
                )

                for wu in widgets:
                    widget_data = batch_data.get(wu.widget_id.id, {})
                    results.append(self._format_widget_data(wu, widget_data))
            else:
                # Fallback: cargar individualmente
                for wu in widgets:
                    results.append(self._load_single_widget(wu, filters))

        return results

    @api.model
    def _load_chart_widgets_batch(self, widget_users, filters):
        """
        Carga widgets de gráficos optimizando queries compartidas.
        """
        results = []

        # Muchos gráficos comparten datos base (ej: ventas por período)
        # Podemos cachear y reutilizar
        base_data_cache = {}

        for wu in widget_users:
            cache_key = f"{wu.widget_id.data_service_model}:{filters}"

            if cache_key not in base_data_cache:
                # Primera vez: obtener datos base
                service = self.env[wu.widget_id.data_service_model]
                if hasattr(service, 'get_base_data'):
                    base_data_cache[cache_key] = service.get_base_data(filters)

            # Aplicar transformación específica del widget
            widget_data = self._transform_chart_data(
                wu.widget_id,
                base_data_cache.get(cache_key, {}),
                filters
            )

            results.append(self._format_widget_data(wu, widget_data))

        return results

    @api.model
    @cached_method('financial_report')
    def get_widget_data_lazy(self, widget_id, filters=None):
        """
        Obtiene datos de un widget individual (para lazy loading).
        """
        widget = self.env['financial.dashboard.widget'].browse(widget_id)
        if not widget.exists():
            return {'error': 'Widget not found'}

        # Usar caché agresivo para widgets individuales
        try:
            data = widget.get_widget_data(filters)
            return {
                'success': True,
                'data': data,
                'cached': True,
                'timestamp': fields.Datetime.now()
            }
        except Exception as e:
            _logger.error(f"Error loading widget {widget_id}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'cached': False
            }

    @api.model
    def _load_single_widget(self, widget_user, filters):
        """
        Carga un widget individual.
        """
        # Optimización: usar with_context para prefetch
        widget_user = widget_user.with_context(prefetch_fields=False)

        try:
            widget_filters = filters or {}
            if widget_user.custom_filters:
                widget_filters.update(widget_user.custom_filters)

            data = widget_user.widget_id.get_widget_data(widget_filters)
            return self._format_widget_data(widget_user, data)

        except Exception as e:
            _logger.error(f"Error loading widget {widget_user.widget_id.name}: {str(e)}")
            return self._format_widget_data(widget_user, {'error': str(e)})

    @api.model
    def _format_widget_data(self, widget_user, data):
        """
        Formatea datos del widget para respuesta.
        """
        # Optimización: usar with_context para prefetch
        widget_user = widget_user.with_context(prefetch_fields=False)

        return {
            'id': widget_user.widget_id.id,
            'user_widget_id': widget_user.id,
            'widget_type': widget_user.widget_id.widget_type,
            'name': widget_user.widget_id.name,
            'grid_data': widget_user.grid_data,
            'custom_config': widget_user.custom_config,
            'data': data,
            'last_update': fields.Datetime.now()
        }

    @api.model
    def _transform_chart_data(self, widget, base_data, filters):
        """
        Transforma datos base según el tipo de gráfico.
        """
        widget_type = widget.widget_type

        if widget_type == 'chart_line':
            return self._transform_to_line_chart(base_data, widget.chart_config)
        elif widget_type == 'chart_bar':
            return self._transform_to_bar_chart(base_data, widget.chart_config)
        elif widget_type == 'chart_pie':
            return self._transform_to_pie_chart(base_data, widget.chart_config)
        else:
            return base_data

    @api.model
    def _transform_to_line_chart(self, data, config):
        """Transforma datos para gráfico de líneas."""
        # Implementación específica según estructura de datos
        return data

    @api.model
    def _transform_to_bar_chart(self, data, config):
        """Transforma datos para gráfico de barras."""
        return data

    @api.model
    def _transform_to_pie_chart(self, data, config):
        """Transforma datos para gráfico de torta."""
        return data

    @api.model
    def invalidate_dashboard_cache(self, layout_id=None, widget_ids=None):
        """
        Invalida caché del dashboard.
        Llamar cuando se actualizan datos subyacentes.
        """
        cache_service = self.env['l10n_cl.cache.service']

        if layout_id:
            # Invalidar todo el dashboard
            pattern = f"dashboard:*:{layout_id}:*"
            cache_service.clear_pattern(pattern)

        if widget_ids:
            # Invalidar widgets específicos
            for widget_id in widget_ids:
                pattern = f"dashboard:*widget*{widget_id}*"
                cache_service.clear_pattern(pattern)

        _logger.info(f"Cache invalidated for layout={layout_id}, widgets={widget_ids}")

    @api.model
    def get_performance_metrics(self):
        """
        Obtiene métricas de performance del dashboard.
        """
        cache_service = self.env['l10n_cl.cache.service']

        # Obtener estadísticas de caché
        cache_stats = cache_service.get_statistics()

        # Queries más lentas (si están siendo monitoreadas)
        slow_queries = self._get_slow_queries_log()

        return {
            'cache_stats': cache_stats,
            'slow_queries': slow_queries,
            'recommendations': self._get_performance_recommendations()
        }

    @api.model
    def _get_slow_queries_log(self):
        """
        Obtiene log de queries lentas del dashboard.
        """
        # En producción, esto leería de pg_stat_statements o similar
        return []

    @api.model
    def _get_performance_recommendations(self):
        """
        Genera recomendaciones de optimización.
        """
        recommendations = []

        # Verificar índices
        missing_indexes = self._check_missing_indexes()
        if missing_indexes:
            recommendations.append({
                'type': 'index',
                'severity': 'high',
                'message': f'Missing indexes on: {", ".join(missing_indexes)}'
            })

        # Verificar tamaño de tablas
        large_tables = self._check_large_tables()
        if large_tables:
            recommendations.append({
                'type': 'archiving',
                'severity': 'medium',
                'message': f'Consider archiving old data in: {", ".join(large_tables)}'
            })

        return recommendations

    @api.model
    def _check_missing_indexes(self):
        """
        Verifica índices faltantes en tablas críticas.
        """
        # Lista de índices recomendados
        recommended_indexes = [
            ('account_move', 'date'),
            ('account_move', 'company_id'),
            ('account_move_line', 'account_id'),
            ('account_move_line', 'date'),
        ]

        missing = []
        for table, column in recommended_indexes:
            if not self._index_exists(table, column):
                missing.append(f"{table}.{column}")

        return missing

    @api.model
    def _index_exists(self, table, column):
        """
        Verifica si existe un índice en una columna.
        """
        query = """
            SELECT 1
            FROM pg_indexes
            WHERE tablename = %s
            AND indexdef LIKE %s
            LIMIT 1
        """
        self._cr.execute(query, [table, f'%{column}%'])
        return bool(self._cr.fetchone())

    @api.model
    def _check_large_tables(self):
        """
        Identifica tablas grandes que podrían necesitar archivado.
        """
        query = """
            SELECT
                schemaname,
                tablename,
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                n_live_tup as row_count
            FROM pg_stat_user_tables
            WHERE n_live_tup > 1000000
            ORDER BY n_live_tup DESC
        """

        self._cr.execute(query)
        large_tables = []

        for row in self._cr.fetchall():
            if row[1] in ['account_move', 'account_move_line']:
                large_tables.append(f"{row[1]} ({row[3]:,} rows)")

        return large_tables


class DashboardWebSocketService:
    '''WebSocket service for real-time dashboard updates'''

    @api.model
    def send_update(self, channel, data):
        '''Send real-time update to dashboard'''
        self.env['bus.bus']._sendone(channel, 'dashboard_update', data)

    def get_dashboard_data_stream(self, dashboard_id):
        '''Stream dashboard data with WebSocket'''
        dashboard = self.env['financial.dashboard'].browse(dashboard_id)

        # Initial data load
        initial_data = self._get_dashboard_data_optimized(dashboard)

        # Setup change listener
        channel = f'dashboard_{dashboard_id}'

        # Send initial data
        self.send_update(channel, initial_data)

        # Return channel for subscription
        return channel

    def _get_dashboard_data_optimized(self, dashboard):
        '''Get dashboard data with optimizations'''
        # Use lazy loading for widgets
        widget_data = []

        for widget in dashboard.widget_ids:
            # Load only visible widgets first
            if widget.is_visible:
                widget_data.append({
                    'id': widget.id,
                    'type': widget.widget_type,
                    'position': {'x': widget.position_x, 'y': widget.position_y},
                    'size': {'width': widget.width, 'height': widget.height},
                    'data': None,  # Lazy load data
                    'lazy_load': True
                })

        return {
            'dashboard_id': dashboard.id,
            'widgets': widget_data,
            'timestamp': time.time()
        }
