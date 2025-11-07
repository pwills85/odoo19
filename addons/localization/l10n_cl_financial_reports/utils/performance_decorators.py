# -*- coding: utf-8 -*-
"""
Decoradores de rendimiento para monitorear performance de métodos.

Proporciona decoradores para:
- Medir tiempo de ejecución
- Contar queries SQL
- Logging estructurado JSON
"""

import time
import json
import logging
import functools
from odoo import sql_db

_logger = logging.getLogger(__name__)


def measure_sql_performance(func):
    """
    Decorador que mide el rendimiento de un método:
    - Tiempo de ejecución (ms)
    - Número de queries SQL ejecutadas
    - Logging estructurado JSON

    Usage:
        @measure_sql_performance
        def my_expensive_method(self):
            # ...expensive operations...
            return result

    Logs JSON format:
        {
            "module": "l10n_cl_financial_reports",
            "method": "ClassName.method_name",
            "duration_ms": 1234,
            "query_count": 15,
            "timestamp": "2024-01-15T10:30:45",
            "status": "success"
        }
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Obtener nombre del método y clase
        if args and hasattr(args[0], '__class__'):
            class_name = args[0].__class__.__name__
            method_name = f"{class_name}.{func.__name__}"
        else:
            method_name = func.__name__

        # Obtener cursor para contar queries
        cr = None
        if args and hasattr(args[0], 'env') and hasattr(args[0].env, 'cr'):
            cr = args[0].env.cr

        # Contar queries antes de ejecutar
        query_count_before = 0
        if cr and hasattr(cr, 'sql_log'):
            query_count_before = len(cr.sql_log)
        elif cr and hasattr(cr, '_obj'):
            # Fallback: contar usando internal counter si sql_log no está disponible
            query_count_before = getattr(cr._obj, 'query_count', 0)

        # Medir tiempo de ejecución
        start_time = time.time()
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')

        try:
            # Ejecutar método
            result = func(*args, **kwargs)

            # Calcular duración
            duration_ms = int((time.time() - start_time) * 1000)

            # Contar queries después de ejecutar
            query_count_after = 0
            if cr and hasattr(cr, 'sql_log'):
                query_count_after = len(cr.sql_log)
            elif cr and hasattr(cr, '_obj'):
                query_count_after = getattr(cr._obj, 'query_count', 0)

            query_count = query_count_after - query_count_before

            # Logging estructurado JSON
            log_data = {
                "module": "l10n_cl_financial_reports",
                "method": method_name,
                "duration_ms": duration_ms,
                "query_count": query_count,
                "timestamp": timestamp,
                "status": "success"
            }

            _logger.info(json.dumps(log_data))

            return result

        except Exception as e:
            # Calcular duración incluso en error
            duration_ms = int((time.time() - start_time) * 1000)

            # Logging de error estructurado
            log_data = {
                "module": "l10n_cl_financial_reports",
                "method": method_name,
                "duration_ms": duration_ms,
                "timestamp": timestamp,
                "status": "error",
                "error": str(e)
            }

            _logger.error(json.dumps(log_data))

            # Re-raise la excepción
            raise

    return wrapper


def measure_performance(log_queries=True, log_result_size=False):
    """
    Decorador paramétrico para medir rendimiento con opciones configurables.

    Args:
        log_queries (bool): Si True, incluye query_count en log
        log_result_size (bool): Si True, incluye tamaño del resultado en log

    Usage:
        @measure_performance(log_queries=True, log_result_size=True)
        def my_method(self):
            return [1, 2, 3, ...]

    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Obtener nombre del método
            if args and hasattr(args[0], '__class__'):
                class_name = args[0].__class__.__name__
                method_name = f"{class_name}.{func.__name__}"
            else:
                method_name = func.__name__

            # Obtener cursor
            cr = None
            if args and hasattr(args[0], 'env') and hasattr(args[0].env, 'cr'):
                cr = args[0].env.cr

            # Query counting
            query_count_before = 0
            if log_queries and cr and hasattr(cr, 'sql_log'):
                query_count_before = len(cr.sql_log)

            # Timing
            start_time = time.time()
            timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')

            try:
                result = func(*args, **kwargs)

                duration_ms = int((time.time() - start_time) * 1000)

                # Build log data
                log_data = {
                    "module": "l10n_cl_financial_reports",
                    "method": method_name,
                    "duration_ms": duration_ms,
                    "timestamp": timestamp,
                    "status": "success"
                }

                # Add query count if requested
                if log_queries and cr and hasattr(cr, 'sql_log'):
                    query_count_after = len(cr.sql_log)
                    log_data["query_count"] = query_count_after - query_count_before

                # Add result size if requested
                if log_result_size:
                    if hasattr(result, '__len__'):
                        log_data["result_size"] = len(result)
                    elif hasattr(result, 'ids'):
                        log_data["result_size"] = len(result.ids)

                _logger.info(json.dumps(log_data))

                return result

            except Exception as e:
                duration_ms = int((time.time() - start_time) * 1000)

                log_data = {
                    "module": "l10n_cl_financial_reports",
                    "method": method_name,
                    "duration_ms": duration_ms,
                    "timestamp": timestamp,
                    "status": "error",
                    "error": str(e)
                }

                _logger.error(json.dumps(log_data))
                raise

        return wrapper
    return decorator
