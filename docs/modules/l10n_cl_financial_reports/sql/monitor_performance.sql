-- =============================================================================
-- SCRIPT DE MONITOREO DE PERFORMANCE
-- Módulo: account_financial_report
-- Versión: 18.0.6.0.0
-- Fecha: 2025-01-07
-- =============================================================================
-- 
-- PROPÓSITO: Monitorear el impacto de los índices en performance
-- USO: Ejecutar periódicamente para validar mejoras
-- 
-- =============================================================================

-- =============================================================================
-- 1. QUERIES MÁS LENTAS (Requiere pg_stat_statements)
-- =============================================================================

-- Habilitar extensión si no existe
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Top 10 queries más lentas relacionadas con reportes financieros
SELECT 
    substring(query, 1, 80) as query_preview,
    calls,
    ROUND(total_exec_time::numeric, 2) as total_time_ms,
    ROUND(mean_exec_time::numeric, 2) as avg_time_ms,
    ROUND(stddev_exec_time::numeric, 2) as stddev_ms,
    rows as rows_returned
FROM pg_stat_statements
WHERE query LIKE '%account_move%'
   OR query LIKE '%l10n_cl_f%'
   OR query LIKE '%financial%'
ORDER BY mean_exec_time DESC
LIMIT 10;

-- =============================================================================
-- 2. USO DE ÍNDICES CRÍTICOS
-- =============================================================================

-- Estadísticas de uso de índices financieros
SELECT 
    indexrelname as index_name,
    idx_scan as times_used,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
    CASE 
        WHEN idx_scan > 0 THEN 
            ROUND((idx_tup_fetch::numeric / idx_scan), 2)
        ELSE 0 
    END as avg_tuples_per_scan
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
  AND indexrelname LIKE 'idx_%'
  AND tablename IN ('account_move_line', 'account_move', 'account_account', 'account_tax')
ORDER BY idx_scan DESC;

-- =============================================================================
-- 3. TAMAÑO Y BLOAT DE ÍNDICES
-- =============================================================================

-- Análisis de fragmentación de índices
WITH index_bloat AS (
    SELECT 
        schemaname,
        tablename,
        indexname,
        pg_relation_size(indexrelid) as index_size,
        CASE WHEN indisunique THEN 'UNIQUE' ELSE 'REGULAR' END as index_type
    FROM pg_stat_user_indexes
    JOIN pg_index ON indexrelid = indexrelid
    WHERE schemaname = 'public'
      AND indexname LIKE 'idx_%'
)
SELECT 
    tablename,
    indexname,
    pg_size_pretty(index_size) as size,
    index_type
FROM index_bloat
WHERE tablename IN ('account_move_line', 'account_move', 'account_account')
ORDER BY index_size DESC;

-- =============================================================================
-- 4. CACHE HIT RATIO
-- =============================================================================

-- Ratio de cache hits (debe ser > 95% idealmente)
SELECT 
    'account_move_line' as table_name,
    heap_blks_read,
    heap_blks_hit,
    CASE 
        WHEN heap_blks_read + heap_blks_hit > 0 THEN
            ROUND(100.0 * heap_blks_hit / (heap_blks_read + heap_blks_hit), 2)
        ELSE 0
    END as cache_hit_ratio
FROM pg_statio_user_tables
WHERE tablename = 'account_move_line'
UNION ALL
SELECT 
    'account_move' as table_name,
    heap_blks_read,
    heap_blks_hit,
    CASE 
        WHEN heap_blks_read + heap_blks_hit > 0 THEN
            ROUND(100.0 * heap_blks_hit / (heap_blks_read + heap_blks_hit), 2)
        ELSE 0
    END as cache_hit_ratio
FROM pg_statio_user_tables
WHERE tablename = 'account_move';

-- =============================================================================
-- 5. QUERIES SIN ÍNDICES (Table Scans)
-- =============================================================================

-- Detectar tablas con muchos sequential scans
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    CASE 
        WHEN seq_scan + idx_scan > 0 THEN
            ROUND(100.0 * seq_scan / (seq_scan + idx_scan), 2)
        ELSE 0
    END as seq_scan_ratio
FROM pg_stat_user_tables
WHERE schemaname = 'public'
  AND tablename IN ('account_move_line', 'account_move', 'account_account')
  AND seq_scan > 100
ORDER BY seq_scan DESC;

-- =============================================================================
-- 6. TIEMPO DE RESPUESTA F29 (Benchmark)
-- =============================================================================

-- Benchmark query F29
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT 
    DATE_TRUNC('month', aml.date) as period,
    at.type_tax_use,
    SUM(aml.balance) as total_iva
FROM account_move_line aml
INNER JOIN account_move am ON aml.move_id = am.id
INNER JOIN account_tax at ON aml.tax_line_id = at.id
WHERE am.state = 'posted'
    AND am.company_id = (SELECT id FROM res_company LIMIT 1)
    AND aml.date >= CURRENT_DATE - INTERVAL '12 months'
    AND at.amount = 19.0
GROUP BY DATE_TRUNC('month', aml.date), at.type_tax_use
ORDER BY period DESC;

-- =============================================================================
-- 7. TIEMPO DE RESPUESTA F22 (Benchmark)
-- =============================================================================

-- Benchmark query F22
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT 
    CASE 
        WHEN aa.code LIKE '4%' THEN 'ingresos_operacionales'
        WHEN aa.code LIKE '5%' THEN 'costos_directos'
        WHEN aa.code LIKE '6%' THEN 'gastos_operacionales'
        ELSE 'otros'
    END as categoria,
    SUM(aml.credit - aml.debit) as saldo
FROM account_move_line aml
INNER JOIN account_account aa ON aml.account_id = aa.id
INNER JOIN account_move am ON aml.move_id = am.id
WHERE am.company_id = (SELECT id FROM res_company LIMIT 1)
  AND am.state = 'posted'
  AND aml.date >= CURRENT_DATE - INTERVAL '12 months'
  AND (aa.code LIKE '4%' OR aa.code LIKE '5%' OR aa.code LIKE '6%')
GROUP BY categoria
HAVING ABS(SUM(aml.credit - aml.debit)) > 0.01;

-- =============================================================================
-- 8. ÍNDICES NO UTILIZADOS (Candidatos a eliminar)
-- =============================================================================

-- Índices que nunca se han usado
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
  AND idx_scan = 0
  AND indexrelname LIKE 'idx_%'
ORDER BY pg_relation_size(indexrelid) DESC;

-- =============================================================================
-- 9. RESUMEN DE PERFORMANCE
-- =============================================================================

-- Vista consolidada de métricas clave
WITH performance_metrics AS (
    SELECT 
        'Total Queries' as metric,
        COUNT(*)::text as value
    FROM pg_stat_statements
    WHERE query LIKE '%account_%'
    
    UNION ALL
    
    SELECT 
        'Avg Query Time (ms)',
        ROUND(AVG(mean_exec_time), 2)::text
    FROM pg_stat_statements
    WHERE query LIKE '%account_%'
    
    UNION ALL
    
    SELECT 
        'Cache Hit Ratio (%)',
        ROUND(100.0 * SUM(heap_blks_hit) / NULLIF(SUM(heap_blks_hit + heap_blks_read), 0), 2)::text
    FROM pg_statio_user_tables
    WHERE tablename IN ('account_move_line', 'account_move')
    
    UNION ALL
    
    SELECT 
        'Active Indexes',
        COUNT(DISTINCT indexname)::text
    FROM pg_stat_user_indexes
    WHERE idx_scan > 0
      AND indexrelname LIKE 'idx_%'
)
SELECT * FROM performance_metrics;

-- =============================================================================
-- 10. RECOMENDACIONES AUTOMÁTICAS
-- =============================================================================

-- Generar recomendaciones basadas en estadísticas
WITH recommendations AS (
    -- Recomendar VACUUM
    SELECT 
        'VACUUM NEEDED' as recommendation_type,
        tablename as object_name,
        'Table has ' || n_dead_tup || ' dead tuples' as reason
    FROM pg_stat_user_tables
    WHERE n_dead_tup > 10000
      AND tablename IN ('account_move_line', 'account_move')
    
    UNION ALL
    
    -- Recomendar ANALYZE
    SELECT 
        'ANALYZE NEEDED',
        tablename,
        'Last analyzed: ' || COALESCE(last_analyze::text, 'NEVER')
    FROM pg_stat_user_tables
    WHERE (last_analyze IS NULL OR last_analyze < CURRENT_DATE - INTERVAL '7 days')
      AND tablename IN ('account_move_line', 'account_move')
    
    UNION ALL
    
    -- Recomendar nuevos índices
    SELECT 
        'INDEX CANDIDATE',
        tablename,
        'High sequential scan ratio: ' || 
        ROUND(100.0 * seq_scan / NULLIF(seq_scan + idx_scan, 0), 2) || '%'
    FROM pg_stat_user_tables
    WHERE seq_scan > idx_scan
      AND seq_scan > 1000
      AND tablename IN ('account_move_line', 'account_move')
)
SELECT * FROM recommendations
ORDER BY recommendation_type, object_name;

-- =============================================================================
-- NOTAS DE USO
-- =============================================================================
-- 
-- 1. EJECUCIÓN PERIÓDICA:
--    - Ejecutar semanalmente para monitoreo continuo
--    - Guardar resultados para análisis de tendencias
--    - Comparar métricas antes/después de cambios
--
-- 2. INTERPRETACIÓN DE RESULTADOS:
--    - Cache hit ratio < 90%: Aumentar shared_buffers
--    - Queries > 1000ms: Revisar índices y optimizar
--    - Sequential scans altos: Crear índices adicionales
--    - Dead tuples > 20%: Ejecutar VACUUM
--
-- 3. ACCIONES RECOMENDADAS:
--    - Documentar cambios de performance
--    - Alertar si métricas degradan
--    - Planificar mantenimiento preventivo
--
-- =============================================================================