-- =============================================================================
-- ROLLBACK SCRIPT - FINANCIAL REPORT INDEXES
-- Módulo: account_financial_report
-- Versión: 18.0.6.0.0
-- Fecha: 2025-01-07
-- =============================================================================
-- 
-- PROPÓSITO: Eliminar índices creados por financial_report_indexes.sql
-- USO: Ejecutar solo en caso de problemas de performance o conflictos
-- 
-- =============================================================================

-- =============================================================================
-- ELIMINAR ÍNDICES DE ACCOUNT_MOVE_LINE
-- =============================================================================

DROP INDEX IF EXISTS idx_aml_financial_report_main;
DROP INDEX IF EXISTS idx_aml_account_date_aggregation;
DROP INDEX IF EXISTS idx_aml_partner_analysis;
DROP INDEX IF EXISTS idx_aml_tax_analysis;
DROP INDEX IF EXISTS idx_aml_reconciliation_state;
DROP INDEX IF EXISTS idx_aml_analytic_financial;

-- =============================================================================
-- ELIMINAR ÍNDICES DE ACCOUNT_MOVE
-- =============================================================================

DROP INDEX IF EXISTS idx_am_financial_report_main;
DROP INDEX IF EXISTS idx_am_period_search;
DROP INDEX IF EXISTS idx_am_chilean_documents;

-- =============================================================================
-- ELIMINAR ÍNDICES DE ACCOUNT_ACCOUNT
-- =============================================================================

DROP INDEX IF EXISTS idx_aa_code_search;
DROP INDEX IF EXISTS idx_aa_type_company;
DROP INDEX IF EXISTS idx_aa_hierarchy;

-- =============================================================================
-- ELIMINAR ÍNDICES DE ACCOUNT_TAX
-- =============================================================================

DROP INDEX IF EXISTS idx_at_type_amount;
DROP INDEX IF EXISTS idx_at_sii_code;

-- =============================================================================
-- ELIMINAR ÍNDICES ESPECÍFICOS CHILENOS
-- =============================================================================

DROP INDEX IF EXISTS idx_f29_iva_ventas;
DROP INDEX IF EXISTS idx_f29_iva_compras;
DROP INDEX IF EXISTS idx_f29_retenciones;
DROP INDEX IF EXISTS idx_f22_ingresos;
DROP INDEX IF EXISTS idx_f22_gastos;
DROP INDEX IF EXISTS idx_f22_depreciacion;

-- =============================================================================
-- ELIMINAR ÍNDICES MULTI-COMPANY
-- =============================================================================

DROP INDEX IF EXISTS idx_multicompany_consolidation;
DROP INDEX IF EXISTS idx_intercompany_analysis;

-- =============================================================================
-- ELIMINAR ÍNDICES TEMPORALES
-- =============================================================================

DROP INDEX IF EXISTS idx_temporal_comparison;
DROP INDEX IF EXISTS idx_quarterly_analysis;

-- =============================================================================
-- ELIMINAR ÍNDICES DE TABLAS ESPECÍFICAS DEL MÓDULO
-- =============================================================================

DROP INDEX IF EXISTS idx_l10n_cl_f29_main;
DROP INDEX IF EXISTS idx_l10n_cl_f29_state;
DROP INDEX IF EXISTS idx_l10n_cl_f22_main;
DROP INDEX IF EXISTS idx_l10n_cl_f22_state;

-- =============================================================================
-- ELIMINAR VISTAS DE MONITOREO
-- =============================================================================

DROP VIEW IF EXISTS financial_report_index_usage;
DROP VIEW IF EXISTS financial_report_slow_queries;

-- =============================================================================
-- ACTUALIZAR ESTADÍSTICAS DESPUÉS DEL ROLLBACK
-- =============================================================================

ANALYZE account_move_line;
ANALYZE account_move;
ANALYZE account_account;
ANALYZE account_tax;

-- =============================================================================
-- NOTAS DE ROLLBACK
-- =============================================================================
-- 
-- 1. ANTES DE EJECUTAR:
--    - Verificar que no hay queries activas usando los índices
--    - Hacer backup de estadísticas de performance actual
--    - Notificar a usuarios sobre posible degradación temporal
--
-- 2. DESPUÉS DE EJECUTAR:
--    - Monitorear performance por 24 horas
--    - Recolectar métricas de queries afectadas
--    - Considerar recrear índices selectivamente si es necesario
--
-- =============================================================================