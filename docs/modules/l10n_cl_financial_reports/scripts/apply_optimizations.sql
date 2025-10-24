-- ============================================================================
-- SCRIPT DE OPTIMIZACIÓN DE PERFORMANCE - account_financial_report
-- Odoo 18 CE - Elite Performance Optimizer
-- ============================================================================
-- Ejecutar este script en la base de datos PostgreSQL de Odoo
-- IMPORTANTE: Hacer backup antes de ejecutar en producción
-- ============================================================================

-- Configurar parámetros de sesión para optimización
SET work_mem = '64MB';
SET maintenance_work_mem = '256MB';

-- ============================================================================
-- PARTE 1: ÍNDICES CRÍTICOS PARA TABLAS PRINCIPALES
-- ============================================================================

-- Índices para l10n_cl_f29 (Formulario 29)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f29_company_period_state
ON l10n_cl_f29 (company_id, period_date, state)
WHERE state != 'replaced';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f29_period_date
ON l10n_cl_f29 (period_date DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f29_ventas_total
ON l10n_cl_f29 (ventas_total)
WHERE state = 'accepted';

-- Índices para l10n_cl_f22 (Formulario 22)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f22_company_year_state
ON l10n_cl_f22 (company_id, year, state);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f22_year_desc
ON l10n_cl_f22 (year DESC);

-- Índices críticos para account_move_line
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_account_date_company
ON account_move_line (account_id, date, company_id)
WHERE parent_state = 'posted';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_tax_calculations
ON account_move_line (tax_line_id, tax_base_amount, balance)
WHERE tax_line_id IS NOT NULL;

-- Índice con columnas INCLUDE para reportes (PostgreSQL 11+)
DO $$
BEGIN
    IF (SELECT current_setting('server_version_num')::int >= 110000) THEN
        EXECUTE 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_analytic_reporting
        ON account_move_line (company_id, date)
        INCLUDE (account_id, partner_id, debit, credit)
        WHERE parent_state = ''posted''';
    END IF;
END $$;

-- Índices para account_move
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_move_type_state_date
ON account_move (move_type, state, date DESC)
WHERE state = 'posted';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_move_partner_date
ON account_move (partner_id, date DESC)
WHERE state = 'posted' AND partner_id IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_move_company_date
ON account_move (company_id, date DESC)
WHERE state IN ('posted', 'draft');

-- Índices para dashboard widgets
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dashboard_widget_active
ON financial_dashboard_widget (active, sequence)
WHERE active = true;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dashboard_widget_type
ON financial_dashboard_widget (widget_type);

-- Índices para KPIs financieros
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_kpi_company_date
ON financial_report_kpi (company_id, date_from, date_to);

-- Índice para account_analytic_line
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytic_line_date_account
ON account_analytic_line (date DESC, account_id)
WHERE amount != 0;

-- ============================================================================
-- PARTE 2: VISTAS MATERIALIZADAS PARA REPORTES PESADOS
-- ============================================================================

-- Vista materializada para resumen F29
DROP MATERIALIZED VIEW IF EXISTS mv_f29_summary CASCADE;
CREATE MATERIALIZED VIEW mv_f29_summary AS
SELECT 
    f.id,
    f.company_id,
    f.period_date,
    f.state,
    f.ventas_gravadas,
    f.ventas_exentas,
    f.iva_debito,
    f.iva_credito,
    f.saldo_a_favor,
    f.total_a_pagar,
    COUNT(DISTINCT am.id) as move_count,
    SUM(CASE WHEN am.move_type IN ('out_invoice', 'out_refund') THEN 1 ELSE 0 END) as sales_count,
    SUM(CASE WHEN am.move_type IN ('in_invoice', 'in_refund') THEN 1 ELSE 0 END) as purchase_count
FROM l10n_cl_f29 f
LEFT JOIN account_move am ON 
    am.date >= f.period_date 
    AND am.date < (f.period_date + interval '1 month')
    AND am.company_id = f.company_id
    AND am.state = 'posted'
WHERE f.state != 'replaced'
GROUP BY f.id;

CREATE INDEX idx_mv_f29_company_period ON mv_f29_summary(company_id, period_date);
CREATE INDEX idx_mv_f29_state ON mv_f29_summary(state);

-- Vista materializada para KPIs financieros
DROP MATERIALIZED VIEW IF EXISTS mv_financial_kpis CASCADE;
CREATE MATERIALIZED VIEW mv_financial_kpis AS
SELECT 
    company_id,
    DATE_TRUNC('month', date) as period,
    account_id,
    partner_id,
    journal_id,
    SUM(debit) as total_debit,
    SUM(credit) as total_credit,
    SUM(balance) as total_balance,
    COUNT(*) as transaction_count,
    AVG(balance) as avg_balance
FROM account_move_line
WHERE parent_state = 'posted'
GROUP BY 
    company_id, 
    DATE_TRUNC('month', date), 
    account_id,
    partner_id,
    journal_id;

CREATE INDEX idx_mv_kpis_company_period ON mv_financial_kpis(company_id, period);
CREATE INDEX idx_mv_kpis_account ON mv_financial_kpis(account_id);
CREATE INDEX idx_mv_kpis_partner ON mv_financial_kpis(partner_id);

-- Vista materializada para resumen de impuestos
DROP MATERIALIZED VIEW IF EXISTS mv_tax_summary CASCADE;
CREATE MATERIALIZED VIEW mv_tax_summary AS
SELECT 
    am.company_id,
    DATE_TRUNC('month', am.date) as period,
    at.type_tax_use,
    at.amount as tax_rate,
    at.id as tax_id,
    at.name as tax_name,
    COUNT(DISTINCT am.id) as document_count,
    SUM(aml.balance) as tax_amount,
    SUM(aml.tax_base_amount) as base_amount
FROM account_move_line aml
INNER JOIN account_move am ON aml.move_id = am.id
INNER JOIN account_tax at ON aml.tax_line_id = at.id
WHERE am.state = 'posted'
GROUP BY 
    am.company_id,
    DATE_TRUNC('month', am.date),
    at.type_tax_use,
    at.amount,
    at.id,
    at.name;

CREATE INDEX idx_mv_tax_company_period ON mv_tax_summary(company_id, period);
CREATE INDEX idx_mv_tax_type ON mv_tax_summary(type_tax_use);

-- ============================================================================
-- PARTE 3: OPTIMIZACIÓN DE TABLAS Y ESTADÍSTICAS
-- ============================================================================

-- Actualizar estadísticas de tablas críticas
ANALYZE account_move;
ANALYZE account_move_line;
ANALYZE l10n_cl_f29;
ANALYZE l10n_cl_f22;
ANALYZE financial_dashboard_widget;
ANALYZE financial_report_kpi;

-- Configurar autovacuum más agresivo para tablas críticas
ALTER TABLE account_move_line SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_cost_limit = 1000
);

ALTER TABLE account_move SET (
    autovacuum_vacuum_scale_factor = 0.1,
    autovacuum_analyze_scale_factor = 0.05
);

-- ============================================================================
-- PARTE 4: FUNCIONES AUXILIARES PARA PERFORMANCE
-- ============================================================================

-- Función para calcular resumen de impuestos optimizada
CREATE OR REPLACE FUNCTION calculate_tax_summary(
    p_company_id INTEGER,
    p_date_from DATE,
    p_date_to DATE
)
RETURNS TABLE (
    tax_type VARCHAR,
    tax_rate NUMERIC,
    total_base NUMERIC,
    total_tax NUMERIC,
    document_count INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH tax_data AS (
        SELECT 
            CASE 
                WHEN at.type_tax_use = 'sale' THEN 'sales'
                WHEN at.type_tax_use = 'purchase' THEN 'purchases'
                ELSE 'other'
            END as tax_type,
            at.amount as tax_rate,
            SUM(aml.tax_base_amount) as base_amount,
            SUM(aml.balance) as tax_amount,
            COUNT(DISTINCT am.id) as doc_count
        FROM account_move_line aml
        INNER JOIN account_move am ON aml.move_id = am.id
        INNER JOIN account_tax at ON aml.tax_line_id = at.id
        WHERE am.state = 'posted'
            AND am.company_id = p_company_id
            AND am.date BETWEEN p_date_from AND p_date_to
        GROUP BY at.type_tax_use, at.amount
    )
    SELECT 
        tax_type::VARCHAR,
        tax_rate,
        COALESCE(base_amount, 0),
        COALESCE(tax_amount, 0),
        doc_count
    FROM tax_data
    ORDER BY tax_type, tax_rate;
END;
$$;

-- Función para obtener balance de cuentas optimizada
CREATE OR REPLACE FUNCTION get_account_balances(
    p_company_id INTEGER,
    p_date_from DATE,
    p_date_to DATE,
    p_account_ids INTEGER[] DEFAULT NULL
)
RETURNS TABLE (
    account_id INTEGER,
    debit NUMERIC,
    credit NUMERIC,
    balance NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        aml.account_id,
        COALESCE(SUM(aml.debit), 0) as debit,
        COALESCE(SUM(aml.credit), 0) as credit,
        COALESCE(SUM(aml.balance), 0) as balance
    FROM account_move_line aml
    INNER JOIN account_move am ON aml.move_id = am.id
    WHERE am.state = 'posted'
        AND am.company_id = p_company_id
        AND am.date BETWEEN p_date_from AND p_date_to
        AND (p_account_ids IS NULL OR aml.account_id = ANY(p_account_ids))
    GROUP BY aml.account_id;
END;
$$;

-- ============================================================================
-- PARTE 5: CONFIGURACIÓN DE PARÁMETROS DE POSTGRESQL
-- ============================================================================

-- NOTA: Estos comandos requieren permisos de superusuario
-- Ejecutar como usuario postgres o con permisos adecuados

-- ALTER SYSTEM SET work_mem = '64MB';
-- ALTER SYSTEM SET maintenance_work_mem = '256MB';
-- ALTER SYSTEM SET effective_cache_size = '4GB';
-- ALTER SYSTEM SET random_page_cost = 1.1;  -- Para SSD
-- ALTER SYSTEM SET effective_io_concurrency = 200;  -- Para SSD
-- ALTER SYSTEM SET max_parallel_workers_per_gather = 4;
-- ALTER SYSTEM SET max_parallel_workers = 8;
-- ALTER SYSTEM SET max_parallel_maintenance_workers = 4;

-- Después de ejecutar ALTER SYSTEM, recargar configuración:
-- SELECT pg_reload_conf();

-- ============================================================================
-- PARTE 6: SCRIPTS DE MANTENIMIENTO REGULAR
-- ============================================================================

-- Script para ejecutar diariamente (programar en cron)
/*
-- daily_maintenance.sql
VACUUM ANALYZE account_move_line;
VACUUM ANALYZE account_move;
VACUUM ANALYZE l10n_cl_f29;
VACUUM ANALYZE l10n_cl_f22;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_f29_summary;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_financial_kpis;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_tax_summary;
*/

-- Script para ejecutar semanalmente
/*
-- weekly_maintenance.sql
REINDEX TABLE CONCURRENTLY account_move_line;
REINDEX TABLE CONCURRENTLY account_move;
CLUSTER account_move_line USING account_move_line_account_id_partner_id_index;
VACUUM FULL ANALYZE account_move_line;
*/

-- ============================================================================
-- PARTE 7: VERIFICACIÓN DE OPTIMIZACIONES
-- ============================================================================

-- Verificar índices creados
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_indexes
JOIN pg_stat_user_indexes ON indexrelname = indexname
WHERE schemaname = 'public'
    AND tablename IN ('account_move', 'account_move_line', 'l10n_cl_f29', 'l10n_cl_f22')
ORDER BY tablename, indexname;

-- Verificar vistas materializadas
SELECT 
    schemaname,
    matviewname,
    pg_size_pretty(pg_total_relation_size(matviewname::regclass)) as size,
    last_refresh.last_refresh
FROM pg_matviews
LEFT JOIN LATERAL (
    SELECT MAX(modification_time) as last_refresh
    FROM pg_stat_user_tables
    WHERE tablename = matviewname
) last_refresh ON true
WHERE schemaname = 'public';

-- Verificar estadísticas de cache
SELECT 
    schemaname,
    tablename,
    heap_blks_read,
    heap_blks_hit,
    CASE 
        WHEN heap_blks_hit + heap_blks_read > 0 THEN
            ROUND(100.0 * heap_blks_hit / (heap_blks_hit + heap_blks_read), 2)
        ELSE 0
    END as cache_hit_ratio
FROM pg_statio_user_tables
WHERE schemaname = 'public'
    AND tablename IN ('account_move', 'account_move_line', 'l10n_cl_f29', 'l10n_cl_f22')
ORDER BY tablename;

-- ============================================================================
-- FIN DEL SCRIPT DE OPTIMIZACIÓN
-- ============================================================================

-- Mensaje de confirmación
DO $$
BEGIN
    RAISE NOTICE 'Optimizaciones aplicadas exitosamente.';
    RAISE NOTICE 'Recuerde:';
    RAISE NOTICE '1. Refrescar las vistas materializadas regularmente';
    RAISE NOTICE '2. Ejecutar VACUUM ANALYZE periódicamente';
    RAISE NOTICE '3. Monitorear el performance con pg_stat_statements';
    RAISE NOTICE '4. Ajustar parámetros de PostgreSQL según hardware disponible';
END $$;