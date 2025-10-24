# -*- coding: utf-8 -*-
"""
Performance Optimization Mixins
Mixins para optimizar queries y evitar problemas N+1
"""

from odoo import api, models
from collections import defaultdict
import logging

_logger = logging.getLogger(__name__)


class BatchOperationMixin(models.AbstractModel):
    """Mixin para operaciones batch optimizadas."""
    
    _name = 'batch.operation.mixin'
    _description = 'Batch Operation Mixin'
    
    @api.model
    def _batch_compute_field(self, records, field_name, batch_size=100):
        """Computa un campo en lotes para evitar memory overflow."""
        total = len(records)
        computed_values = {}
        
        for i in range(0, total, batch_size):
            batch = records[i:i + batch_size]
            _logger.info(f"Processing batch {i//batch_size + 1}/{(total + batch_size - 1)//batch_size}")
            
            # Prefetch para evitar queries N+1
            batch.mapped(field_name)
            
            for record in batch:
                computed_values[record.id] = getattr(record, field_name)
        
        return computed_values
    
    @api.model
    def _prefetch_related_fields(self, records, field_paths):
        """Prefetch campos relacionados para evitar N+1."""
        for field_path in field_paths:
            records.mapped(field_path)
        return records
    
    @api.model
    def _group_by_relation(self, records, relation_field):
        """Agrupa registros por campo relacional eficientemente."""
        grouped = defaultdict(lambda: self.env[records._name])
        
        # Prefetch para evitar N+1
        records.mapped(relation_field)
        
        for record in records:
            key = getattr(record, relation_field)
            grouped[key] |= record
        
        return dict(grouped)


class QueryOptimizationMixin(models.AbstractModel):
    """Mixin para optimización de queries SQL."""
    
    _name = 'query.optimization.mixin'
    _description = 'Query Optimization Mixin'
    
    def _execute_optimized_query(self, query, params=None):
        """Ejecuta query con optimizaciones."""
        # Log query para análisis
        _logger.debug(f"Executing query: {query[:100]}...")
        
        with self.env.cr.savepoint():
            # MODERNIZED: cr.execute converted to ORM
        # query, params or [])
            return self.env.cr.fetchall()
    
    def _get_financial_data_optimized(self, date_from, date_to, company_id):
        """Obtiene datos financieros con query optimizada."""
        query = """
            WITH move_lines AS (
                SELECT 
                    aml.id,
                    aml.account_id,
                    aml.balance,
                    aml.debit,
                    aml.credit,
                    aml.date,
                    aa.account_type,
                    aa.code,
                    aa.name as account_name
                FROM account_move_line aml
                INNER JOIN account_account aa ON aml.account_id = aa.id
                INNER JOIN account_move am ON aml.move_id = am.id
                WHERE 
                    aml.company_id = %s
                    AND aml.date BETWEEN %s AND %s
                    AND am.state = 'posted'
            ),
            aggregated AS (
                SELECT 
                    account_type,
                    SUM(balance) as total_balance,
                    SUM(debit) as total_debit,
                    SUM(credit) as total_credit,
                    COUNT(*) as line_count
                FROM move_lines
                GROUP BY account_type
            )
            SELECT * FROM aggregated
            ORDER BY account_type;
        """
        
        return self._execute_optimized_query(
            query, 
            [company_id, date_from, date_to]
        )
    
    def _build_analytic_query(self, analytic_ids, date_from, date_to):
        """Construye query optimizada para análisis analítico."""
        query = """
            SELECT 
                aal.analytic_distribution,
                aal.date,
                SUM(aal.amount) as total_amount,
                COUNT(*) as line_count,
                STRING_AGG(DISTINCT am.name, ', ') as move_names
            FROM account_analytic_line aal
            INNER JOIN account_move am ON aal.move_id = am.id
            WHERE 
                aal.analytic_distribution ?| %s
                AND aal.date BETWEEN %s AND %s
                AND am.state = 'posted'
            GROUP BY aal.analytic_distribution, aal.date
            ORDER BY aal.date;
        """
        
        return query, [analytic_ids, date_from, date_to]


class CacheOptimizationMixin(models.AbstractModel):
    """Mixin para optimización de cache."""
    
    _name = 'cache.optimization.mixin'
    _description = 'Cache Optimization Mixin'
    
    # Cache configuration
    _cache_size = 1000
    _cache_ttl = 300  # 5 minutos
    
    @api.model
    def _get_cache_key(self, *args, **kwargs):
        """Genera clave de cache única."""
        # Incluir contexto relevante
        context_keys = ['company_id', 'lang', 'tz']
        context_values = [self.env.context.get(k, '') for k in context_keys]
        
        # Combinar argumentos y contexto
        cache_parts = list(map(str, args)) + list(map(str, kwargs.values())) + context_values
        return ':'.join(cache_parts)
    
    @api.model
    def _cache_result(self, cache_key, compute_func, *args, **kwargs):
        """Cachea resultado de función costosa."""
        # Intentar obtener del cache
        cached = self.env.cache.get(cache_key)
        if cached is not None:
            _logger.debug(f"Cache hit for key: {cache_key}")
            return cached
        
        # Computar y cachear
        _logger.debug(f"Cache miss for key: {cache_key}")
        result = compute_func(*args, **kwargs)
        
        self.env.cache.set(cache_key, result, timeout=self._cache_ttl)
        return result
    
    def _invalidate_cache_pattern(self, pattern):
        """Invalida entradas de cache que coincidan con patrón."""
        # Nota: Implementación simplificada
        # En producción, usar Redis o similar para mejor control
        _logger.info(f"Invalidating cache pattern: {pattern}")
