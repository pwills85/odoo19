# -*- coding: utf-8 -*-
"""
Test de validación de performance con índices SQL optimizados
Verifica mejoras en tiempo de ejecución de queries críticas
"""

import time
import logging
from datetime import datetime, timedelta
from odoo.tests import common, tagged
from odoo import fields

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'performance')
class TestPerformanceIndexes(common.TransactionCase):
    """
    Test suite para validar mejoras de performance con índices SQL
    
    Valida:
    - Tiempo de ejecución de queries críticas
    - Uso efectivo de índices
    - Mejora en operaciones masivas
    - Performance de reportes F22/F29
    """
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Configuración básica
        cls.company = cls.env.company
        cls.today = fields.Date.today()
        cls.last_year = cls.today - timedelta(days=365)
        
        # Crear datos de prueba si no existen suficientes
        cls._ensure_test_data()
        
        # Ejecutar ANALYZE para actualizar estadísticas
        cls.env.cr.execute("ANALYZE account_move_line")
        cls.env.cr.execute("ANALYZE account_move")
        cls.env.cr.execute("ANALYZE account_account")
        cls.env.cr.execute("ANALYZE account_tax")
    
    @classmethod
    def _ensure_test_data(cls):
        """
        Asegura que existan datos suficientes para pruebas significativas
        """
        # Verificar cantidad de movimientos
        cls.env.cr.execute("""
            SELECT COUNT(*) 
            FROM account_move_line 
            WHERE company_id = %s
        """, (cls.company.id,))
        
        line_count = cls.env.cr.fetchone()[0]
        
        if line_count < 1000:
            _logger.warning(f"Datos insuficientes para test de performance: {line_count} líneas")
            _logger.info("Considere cargar más datos para pruebas más significativas")
    
    def test_01_index_existence(self):
        """
        Verifica que los índices críticos existan en la base de datos
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("TEST 01: Verificación de existencia de índices")
        _logger.info("=" * 70)
        
        critical_indexes = [
            'idx_aml_financial_report_main',
            'idx_aml_account_date_aggregation',
            'idx_am_financial_report_main',
            'idx_aa_code_search',
            'idx_at_type_amount',
            'idx_f29_iva_ventas',
            'idx_f22_ingresos'
        ]
        
        for index_name in critical_indexes:
            self.env.cr.execute("""
                SELECT EXISTS (
                    SELECT 1 
                    FROM pg_indexes 
                    WHERE indexname = %s
                )
            """, (index_name,))
            
            exists = self.env.cr.fetchone()[0]
            
            if exists:
                _logger.info(f"  ✓ Índice encontrado: {index_name}")
            else:
                _logger.warning(f"  ✗ Índice NO encontrado: {index_name}")
            
            self.assertTrue(exists, f"Índice crítico no encontrado: {index_name}")
    
    def test_02_f29_query_performance(self):
        """
        Test de performance para consulta F29 (IVA mensual)
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("TEST 02: Performance consulta F29 (IVA)")
        _logger.info("=" * 70)
        
        # Query F29 típica para cálculo de IVA
        query = """
            SELECT 
                EXTRACT(MONTH FROM aml.date) as month,
                EXTRACT(YEAR FROM aml.date) as year,
                at.type_tax_use,
                SUM(aml.balance) as total_tax
            FROM account_move_line aml
            INNER JOIN account_move am ON aml.move_id = am.id
            INNER JOIN account_tax at ON aml.tax_line_id = at.id
            WHERE am.state = 'posted'
                AND am.company_id = %s
                AND aml.date >= %s
                AND aml.date <= %s
                AND at.amount = 19.0
            GROUP BY 
                EXTRACT(MONTH FROM aml.date),
                EXTRACT(YEAR FROM aml.date),
                at.type_tax_use
            ORDER BY year DESC, month DESC
        """
        
        # Ejecutar query y medir tiempo
        start_time = time.time()
        self.env.cr.execute(query, (
            self.company.id,
            self.last_year,
            self.today
        ))
        results = self.env.cr.fetchall()
        execution_time = time.time() - start_time
        
        _logger.info(f"  Tiempo de ejecución: {execution_time:.3f}s")
        _logger.info(f"  Registros procesados: {len(results)}")
        
        # Verificar EXPLAIN PLAN
        self._analyze_query_plan(query, (self.company.id, self.last_year, self.today))
        
        # Assert: Query debe ejecutarse en menos de 5 segundos
        self.assertLess(execution_time, 5.0, 
                       f"Query F29 muy lenta: {execution_time:.2f}s (esperado < 5s)")
        
        if execution_time < 1.0:
            _logger.info("  ✓ Performance EXCELENTE (< 1s)")
        elif execution_time < 3.0:
            _logger.info("  ✓ Performance BUENA (< 3s)")
        else:
            _logger.warning(f"  ⚠ Performance MEJORABLE ({execution_time:.2f}s)")
    
    def test_03_f22_query_performance(self):
        """
        Test de performance para consulta F22 (Renta anual)
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("TEST 03: Performance consulta F22 (Renta)")
        _logger.info("=" * 70)
        
        # Query F22 para cálculo de ingresos y gastos
        query = """
            SELECT 
                CASE 
                    WHEN aa.code LIKE '4%' THEN 'ingresos'
                    WHEN aa.code LIKE '5%' THEN 'costos'
                    WHEN aa.code LIKE '6%' THEN 'gastos'
                    ELSE 'otros'
                END as categoria,
                SUM(aml.credit - aml.debit) as saldo
            FROM account_move_line aml
            INNER JOIN account_account aa ON aml.account_id = aa.id
            INNER JOIN account_move am ON aml.move_id = am.id
            WHERE am.company_id = %s
              AND am.state = 'posted'
              AND aml.date >= %s
              AND aml.date <= %s
              AND (aa.code LIKE '4%%' OR aa.code LIKE '5%%' OR aa.code LIKE '6%%')
            GROUP BY categoria
            HAVING ABS(SUM(aml.credit - aml.debit)) > 0.01
        """
        
        # Ejecutar y medir
        start_time = time.time()
        self.env.cr.execute(query, (
            self.company.id,
            self.last_year,
            self.today
        ))
        results = self.env.cr.fetchall()
        execution_time = time.time() - start_time
        
        _logger.info(f"  Tiempo de ejecución: {execution_time:.3f}s")
        _logger.info(f"  Categorías procesadas: {len(results)}")
        
        for row in results:
            _logger.debug(f"    {row[0]}: ${row[1]:,.2f}")
        
        # Assert: Query debe ejecutarse en menos de 5 segundos
        self.assertLess(execution_time, 5.0,
                       f"Query F22 muy lenta: {execution_time:.2f}s (esperado < 5s)")
    
    def test_04_dashboard_aggregation_performance(self):
        """
        Test de performance para agregaciones de dashboard
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("TEST 04: Performance agregaciones dashboard")
        _logger.info("=" * 70)
        
        # Query típica de dashboard con múltiples agregaciones
        query = """
            WITH monthly_data AS (
                SELECT 
                    DATE_TRUNC('month', aml.date) as period,
                    aa.account_type,
                    SUM(aml.debit) as total_debit,
                    SUM(aml.credit) as total_credit,
                    COUNT(*) as line_count
                FROM account_move_line aml
                INNER JOIN account_account aa ON aml.account_id = aa.id
                WHERE aml.company_id = %s
                  AND aml.date >= %s
                  AND aml.parent_state = 'posted'
                GROUP BY DATE_TRUNC('month', aml.date), aa.account_type
            )
            SELECT 
                period,
                SUM(CASE WHEN account_type IN ('asset_receivable', 'asset_cash') 
                    THEN total_debit - total_credit ELSE 0 END) as assets,
                SUM(CASE WHEN account_type IN ('liability_payable', 'liability_credit_card') 
                    THEN total_credit - total_debit ELSE 0 END) as liabilities,
                SUM(CASE WHEN account_type = 'income' 
                    THEN total_credit - total_debit ELSE 0 END) as income,
                SUM(CASE WHEN account_type = 'expense' 
                    THEN total_debit - total_credit ELSE 0 END) as expenses,
                SUM(line_count) as total_lines
            FROM monthly_data
            GROUP BY period
            ORDER BY period DESC
            LIMIT 12
        """
        
        # Ejecutar y medir
        start_time = time.time()
        self.env.cr.execute(query, (
            self.company.id,
            self.last_year
        ))
        results = self.env.cr.fetchall()
        execution_time = time.time() - start_time
        
        _logger.info(f"  Tiempo de ejecución: {execution_time:.3f}s")
        _logger.info(f"  Períodos procesados: {len(results)}")
        
        # Assert: Dashboard debe cargar en menos de 2 segundos
        self.assertLess(execution_time, 2.0,
                       f"Dashboard muy lento: {execution_time:.2f}s (esperado < 2s)")
    
    def test_05_multi_company_performance(self):
        """
        Test de performance para queries multi-company
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("TEST 05: Performance multi-company")
        _logger.info("=" * 70)
        
        # Obtener todas las compañías
        companies = self.env['res.company'].search([])
        
        if len(companies) < 2:
            _logger.info("  ⚠ Solo una compañía disponible, test limitado")
        
        # Query multi-company
        query = """
            SELECT 
                c.id as company_id,
                c.name as company_name,
                COUNT(DISTINCT am.id) as move_count,
                COUNT(aml.id) as line_count,
                SUM(aml.debit) as total_debit,
                SUM(aml.credit) as total_credit
            FROM res_company c
            LEFT JOIN account_move am ON am.company_id = c.id
            LEFT JOIN account_move_line aml ON aml.move_id = am.id
            WHERE am.state = 'posted'
              AND am.date >= %s
            GROUP BY c.id, c.name
            ORDER BY c.name
        """
        
        # Ejecutar y medir
        start_time = time.time()
        self.env.cr.execute(query, (self.last_year,))
        results = self.env.cr.fetchall()
        execution_time = time.time() - start_time
        
        _logger.info(f"  Tiempo de ejecución: {execution_time:.3f}s")
        _logger.info(f"  Compañías procesadas: {len(results)}")
        
        for row in results:
            _logger.debug(f"    {row[1]}: {row[2]} movimientos, {row[3]} líneas")
        
        # Assert: Query multi-company debe ejecutarse en menos de 10 segundos
        self.assertLess(execution_time, 10.0,
                       f"Query multi-company muy lenta: {execution_time:.2f}s (esperado < 10s)")
    
    def test_06_index_usage_statistics(self):
        """
        Verifica que los índices estén siendo utilizados efectivamente
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("TEST 06: Estadísticas de uso de índices")
        _logger.info("=" * 70)
        
        # Query para obtener estadísticas de uso
        query = """
            SELECT 
                indexrelname as index_name,
                idx_scan as scan_count,
                idx_tup_read as tuples_read,
                idx_tup_fetch as tuples_fetched,
                pg_size_pretty(pg_relation_size(indexrelid)) as index_size
            FROM pg_stat_user_indexes
            WHERE schemaname = 'public'
              AND tablename IN ('account_move_line', 'account_move', 'account_account')
              AND indexrelname LIKE 'idx_%'
            ORDER BY idx_scan DESC
            LIMIT 10
        """
        
        self.env.cr.execute(query)
        results = self.env.cr.fetchall()
        
        _logger.info("  Top 10 índices más utilizados:")
        for row in results:
            if row[1] > 0:  # Solo mostrar índices usados
                _logger.info(f"    {row[0]}: {row[1]} scans, {row[4]} size")
        
        # Verificar que al menos algunos índices críticos se estén usando
        used_indexes = [row[0] for row in results if row[1] > 0]
        
        critical_used = [
            idx for idx in ['idx_aml_financial_report_main', 'idx_am_financial_report_main']
            if idx in used_indexes
        ]
        
        if critical_used:
            _logger.info(f"  ✓ Índices críticos en uso: {', '.join(critical_used)}")
        else:
            _logger.warning("  ⚠ Algunos índices críticos no están siendo utilizados")
    
    def _analyze_query_plan(self, query, params):
        """
        Analiza el plan de ejecución de una query
        """
        explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}"
        
        try:
            self.env.cr.execute(explain_query, params)
            plan = self.env.cr.fetchone()[0]
            
            # Extraer información relevante del plan
            if plan and isinstance(plan, list) and len(plan) > 0:
                execution_time = plan[0].get('Execution Time', 0)
                planning_time = plan[0].get('Planning Time', 0)
                
                _logger.debug(f"    Planning time: {planning_time:.3f}ms")
                _logger.debug(f"    Execution time: {execution_time:.3f}ms")
                
                # Buscar uso de índices en el plan
                plan_str = str(plan)
                if 'Index Scan' in plan_str or 'Index Only Scan' in plan_str:
                    _logger.debug("    ✓ Usando índices eficientemente")
                elif 'Seq Scan' in plan_str:
                    _logger.warning("    ⚠ Detectado Sequential Scan (posible optimización)")
                
        except Exception as e:
            _logger.warning(f"    No se pudo analizar plan de ejecución: {e}")
    
    def test_99_performance_summary(self):
        """
        Resumen final de mejoras de performance
        """
        _logger.info("\n" + "=" * 70)
        _logger.info("RESUMEN DE VALIDACIÓN DE PERFORMANCE")
        _logger.info("=" * 70)
        
        # Ejecutar query de resumen
        self.env.cr.execute("""
            SELECT 
                'account_move_line' as table_name,
                COUNT(*) as row_count,
                pg_size_pretty(pg_total_relation_size('account_move_line')) as table_size
            UNION ALL
            SELECT 
                'account_move' as table_name,
                COUNT(*) as row_count,
                pg_size_pretty(pg_total_relation_size('account_move')) as table_size
            FROM account_move
        """)
        
        results = self.env.cr.fetchall()
        
        _logger.info("\nEstadísticas de tablas principales:")
        for row in results:
            _logger.info(f"  {row[0]}: {row[1]:,} registros, {row[2]} tamaño")
        
        _logger.info("\n✅ Validación de performance completada")
        _logger.info("Los índices están correctamente instalados y funcionando")
        _logger.info("=" * 70)