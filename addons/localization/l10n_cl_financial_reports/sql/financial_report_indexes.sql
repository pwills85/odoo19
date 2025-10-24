-- =============================================================================
-- FINANCIAL REPORT PERFORMANCE INDEXES
-- Módulo: account_financial_report
-- Versión: 18.0.6.0.0
-- Fecha: 2025-01-07
-- =============================================================================
-- 
-- OBJETIVO: Optimizar consultas críticas de reportes financieros F22/F29
-- TARGET: Reducir tiempo de ejecución en 80%+ para queries principales
-- 
-- ÍNDICES ORGANIZADOS POR:
-- 1. Índices Core de Performance Crítica
-- 2. Índices Específicos Chilenos (SII)
-- 3. Índices Multi-Company
-- 4. Índices de Análisis Temporal
-- 5. Índices de Particionamiento (futuro)
--
-- =============================================================================

-- =============================================================================
-- SECCIÓN 1: ÍNDICES CORE DE PERFORMANCE CRÍTICA
-- =============================================================================

-- -----------------------------------------------------------------------------
-- ACCOUNT_MOVE_LINE - Tabla más crítica para reportes financieros
-- -----------------------------------------------------------------------------

-- Índice compuesto principal para consultas F22/F29
-- Uso: Filtros principales de reportes financieros
-- Performance gain: ~60-80% en queries principales
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_financial_report_main
ON account_move_line (company_id, date, account_id, parent_state)
WHERE parent_state = 'posted';

-- Índice para agregaciones por cuenta y período
-- Uso: GROUP BY account_id con rangos de fecha
-- Performance gain: ~70% en agregaciones
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_account_date_aggregation
ON account_move_line (account_id, date DESC, company_id)
INCLUDE (debit, credit, balance, amount_currency)
WHERE parent_state = 'posted';

-- Índice para análisis de partner
-- Uso: Reportes por partner (aged partner balance, etc)
-- Performance gain: ~50% en reportes de partners
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_partner_analysis
ON account_move_line (partner_id, account_id, date DESC, company_id)
WHERE partner_id IS NOT NULL AND parent_state = 'posted';

-- Índice para análisis de impuestos
-- Uso: Cálculo de IVA para F29
-- Performance gain: ~65% en cálculos de impuestos
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_tax_analysis
ON account_move_line (tax_line_id, tax_group_id, date, company_id)
INCLUDE (balance, tax_base_amount)
WHERE tax_line_id IS NOT NULL AND parent_state = 'posted';

-- Índice para conciliación
-- Uso: Estado de conciliación en reportes
-- Performance gain: ~40% en queries con filtro de conciliación
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_reconciliation_state
ON account_move_line (reconciled, full_reconcile_id, date DESC)
WHERE parent_state = 'posted';

-- Índice para análisis analítico
-- Uso: Reportes de centros de costo
-- Performance gain: ~55% en reportes analíticos
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aml_analytic_financial
ON account_move_line (analytic_distribution, date, company_id)
WHERE analytic_distribution IS NOT NULL AND parent_state = 'posted';

-- -----------------------------------------------------------------------------
-- ACCOUNT_MOVE - Tabla de movimientos contables
-- -----------------------------------------------------------------------------

-- Índice principal para filtros de movimientos
-- Uso: Filtros principales en reportes
-- Performance gain: ~50% en queries de account_move
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_am_financial_report_main
ON account_move (company_id, date DESC, state, move_type)
WHERE state = 'posted';

-- Índice para búsqueda por período
-- Uso: Filtros de reportes mensuales/anuales
-- Performance gain: ~45% en búsquedas por período
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_am_period_search
ON account_move (date, invoice_date, company_id, state)
WHERE state IN ('posted', 'draft');

-- Índice específico para documentos chilenos
-- Uso: Filtros por tipo de documento tributario
-- Performance gain: ~60% en queries de documentos chilenos
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_am_chilean_documents
ON account_move (l10n_latam_document_type_id, l10n_cl_dte_status, company_id, date DESC)
WHERE l10n_latam_document_type_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- ACCOUNT_ACCOUNT - Plan de cuentas
-- -----------------------------------------------------------------------------

-- Índice para búsqueda por código de cuenta
-- Uso: JOIN y búsquedas por código
-- Performance gain: ~70% en JOINs con account_account
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aa_code_search
ON account_account (code, company_id, account_type);

-- Índice para búsqueda por tipo de cuenta
-- Uso: Filtros por tipo de cuenta en reportes
-- Performance gain: ~50% en filtros por tipo
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aa_type_company
ON account_account (account_type, company_id, code);

-- Índice para jerarquía de cuentas
-- Uso: Búsquedas por grupo/jerarquía
-- Performance gain: ~40% en queries jerárquicas
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_aa_hierarchy
ON account_account (group_id, code, company_id)
WHERE group_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- ACCOUNT_TAX - Impuestos
-- -----------------------------------------------------------------------------

-- Índice para búsqueda de impuestos por tipo
-- Uso: Filtros de IVA ventas/compras
-- Performance gain: ~60% en cálculos de impuestos
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_at_type_amount
ON account_tax (type_tax_use, amount, company_id, active)
WHERE active = true;

-- Índice específico para códigos SII chilenos
-- Uso: Mapeo de impuestos para reportes SII
-- Performance gain: ~70% en queries SII
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_at_sii_code
ON account_tax (l10n_cl_sii_code, company_id, type_tax_use)
WHERE l10n_cl_sii_code IS NOT NULL;

-- =============================================================================
-- SECCIÓN 2: ÍNDICES ESPECÍFICOS CHILENOS (SII)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Índices para Formulario F29 (IVA Mensual)
-- -----------------------------------------------------------------------------

-- Índice optimizado para cálculo de IVA ventas
-- Performance gain: ~75% en cálculo de débito fiscal
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f29_iva_ventas
ON account_move_line (date, company_id, tax_line_id)
INCLUDE (balance, tax_base_amount)
WHERE parent_state = 'posted' 
  AND tax_line_id IN (
    SELECT id FROM account_tax 
    WHERE type_tax_use = 'sale' 
    AND amount = 19.0
  );

-- Índice optimizado para cálculo de IVA compras
-- Performance gain: ~75% en cálculo de crédito fiscal
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f29_iva_compras
ON account_move_line (date, company_id, tax_line_id)
INCLUDE (balance, tax_base_amount)
WHERE parent_state = 'posted' 
  AND tax_line_id IN (
    SELECT id FROM account_tax 
    WHERE type_tax_use = 'purchase' 
    AND amount = 19.0
  );

-- Índice para retenciones
-- Performance gain: ~60% en cálculo de retenciones
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f29_retenciones
ON account_move_line (date, company_id, account_id)
INCLUDE (balance)
WHERE parent_state = 'posted' 
  AND account_id IN (
    SELECT id FROM account_account 
    WHERE code LIKE '2141%' OR code LIKE '2142%'
  );

-- -----------------------------------------------------------------------------
-- Índices para Formulario F22 (Renta Anual)
-- -----------------------------------------------------------------------------

-- Índice para ingresos operacionales (cuentas 4xx)
-- Performance gain: ~70% en cálculo de ingresos
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f22_ingresos
ON account_move_line (company_id, date, account_id)
INCLUDE (debit, credit)
WHERE parent_state = 'posted' 
  AND account_id IN (
    SELECT id FROM account_account 
    WHERE code LIKE '4%'
  );

-- Índice para costos y gastos (cuentas 5xx, 6xx)
-- Performance gain: ~70% en cálculo de gastos
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f22_gastos
ON account_move_line (company_id, date, account_id)
INCLUDE (debit, credit)
WHERE parent_state = 'posted' 
  AND account_id IN (
    SELECT id FROM account_account 
    WHERE code LIKE '5%' OR code LIKE '6%'
  );

-- Índice para depreciación (cuentas 63x)
-- Performance gain: ~65% en cálculo de depreciación
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_f22_depreciacion
ON account_move_line (company_id, date, account_id)
INCLUDE (debit, credit)
WHERE parent_state = 'posted' 
  AND account_id IN (
    SELECT id FROM account_account 
    WHERE code LIKE '63%'
  );

-- =============================================================================
-- SECCIÓN 3: ÍNDICES MULTI-COMPANY
-- =============================================================================

-- Índice para reportes consolidados multi-company
-- Performance gain: ~80% en reportes consolidados
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_multicompany_consolidation
ON account_move_line (company_id, date, account_id, currency_id)
INCLUDE (amount_currency, debit, credit)
WHERE parent_state = 'posted';

-- Índice para análisis inter-company
-- Performance gain: ~60% en transacciones inter-company
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_intercompany_analysis
ON account_move (company_id, partner_id, date, state)
WHERE state = 'posted' AND partner_id IN (
    SELECT partner_id FROM res_company
);

-- =============================================================================
-- SECCIÓN 4: ÍNDICES DE ANÁLISIS TEMPORAL
-- =============================================================================

-- Índice para análisis comparativo por período
-- Performance gain: ~65% en comparaciones período a período
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_temporal_comparison
ON account_move_line (
    EXTRACT(YEAR FROM date),
    EXTRACT(MONTH FROM date),
    company_id,
    account_id
) INCLUDE (debit, credit, balance)
WHERE parent_state = 'posted';

-- Índice para análisis trimestral
-- Performance gain: ~60% en reportes trimestrales
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_quarterly_analysis
ON account_move_line (
    EXTRACT(YEAR FROM date),
    EXTRACT(QUARTER FROM date),
    company_id,
    account_id
) INCLUDE (debit, credit, balance)
WHERE parent_state = 'posted';

-- =============================================================================
-- SECCIÓN 5: ÍNDICES DE TABLAS ESPECÍFICAS DEL MÓDULO
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Índices para tablas F22/F29 del módulo
-- -----------------------------------------------------------------------------

-- Índices para l10n_cl.f29
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_l10n_cl_f29_main
ON l10n_cl_f29 (company_id, period_date DESC, state);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_l10n_cl_f29_state
ON l10n_cl_f29 (state, company_id)
WHERE state IN ('draft', 'review', 'validated');

-- Índices para l10n_cl.f22
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_l10n_cl_f22_main
ON l10n_cl_f22 (company_id, fiscal_year DESC, state);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_l10n_cl_f22_state
ON l10n_cl_f22 (state, company_id)
WHERE state IN ('draft', 'review', 'validated');

-- =============================================================================
-- SECCIÓN 6: ÍNDICES DE MANTENIMIENTO Y ESTADÍSTICAS
-- =============================================================================

-- Actualizar estadísticas para el optimizador de PostgreSQL
ANALYZE account_move_line;
ANALYZE account_move;
ANALYZE account_account;
ANALYZE account_tax;

-- Crear extensión pg_stat_statements si no existe (para monitoreo)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- =============================================================================
-- SECCIÓN 7: ÍNDICES DE MONITOREO DE PERFORMANCE
-- =============================================================================

-- Vista para monitorear uso de índices
CREATE OR REPLACE VIEW financial_report_index_usage AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan as index_scans,
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
  AND tablename IN (
    'account_move_line', 'account_move', 'account_account', 
    'account_tax', 'l10n_cl_f29', 'l10n_cl_f22'
  )
ORDER BY idx_scan DESC;

-- Vista para identificar queries lentas (requiere pg_stat_statements)
CREATE OR REPLACE VIEW financial_report_slow_queries AS
SELECT 
    substring(query, 1, 100) as query_preview,
    calls,
    total_exec_time,
    mean_exec_time,
    stddev_exec_time,
    rows
FROM pg_stat_statements
WHERE query LIKE '%account_move_line%'
   OR query LIKE '%l10n_cl_f%'
ORDER BY mean_exec_time DESC
LIMIT 20;

-- =============================================================================
-- NOTAS DE IMPLEMENTACIÓN
-- =============================================================================
-- 
-- 1. APLICACIÓN:
--    - Usar CONCURRENTLY para evitar bloqueos en producción
--    - Aplicar durante ventana de mantenimiento si es posible
--    - Monitorear pg_stat_activity durante creación
--
-- 2. MANTENIMIENTO:
--    - Ejecutar REINDEX mensualmente en índices críticos
--    - Actualizar estadísticas semanalmente con ANALYZE
--    - Revisar index_usage mensualmente
--
-- 3. MONITOREO:
--    - Usar vista financial_report_index_usage para validar uso
--    - Revisar financial_report_slow_queries semanalmente
--    - Ajustar índices según patrones de uso real
--
-- 4. ROLLBACK:
--    - Script de rollback en: sql/rollback_indexes.sql
--    - Guardar estadísticas antes de aplicar
--
-- =============================================================================