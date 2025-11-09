# -*- coding: utf-8 -*-
"""
Post-migration script para añadir índices de performance
Siguiendo PROMPT_AGENT_IA.md
"""

import logging
from odoo import api, SUPERUSER_ID
from psycopg2 import sql

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """
    Añade índices para optimizar performance del dashboard financiero.
    """
    env = api.Environment(cr, SUPERUSER_ID, {})
    
    # Lista de índices a crear
    # Formato: (tabla, columna(s), nombre_indice, es_unico)
    indexes = [
        # Índices para account_move
        ('account_move', 'date, company_id', 'account_move_date_company_idx', False),
        ('account_move', 'state, company_id', 'account_move_state_company_idx', False),
        ('account_move', 'move_type, state, company_id', 'account_move_type_state_company_idx', False),
        ('account_move', 'partner_id, company_id', 'account_move_partner_company_idx', False),
        
        # Índices para account_move_line
        ('account_move_line', 'account_id, date', 'account_move_line_account_date_idx', False),
        ('account_move_line', 'analytic_account_id, date', 'account_move_line_analytic_date_idx', False),
        ('account_move_line', 'company_id, date', 'account_move_line_company_date_idx', False),
        ('account_move_line', 'journal_id, date', 'account_move_line_journal_date_idx', False),
        
        # Índices para project (si está instalado)
        ('project_project', 'company_id, active', 'project_project_company_active_idx', False),
        ('project_task', 'project_id, stage_id', 'project_task_project_stage_idx', False),
        
        # Índices para hr_timesheet (si está instalado)
        ('account_analytic_line', 'project_id, date', 'analytic_line_project_date_idx', False),
        ('account_analytic_line', 'employee_id, date', 'analytic_line_employee_date_idx', False),
        
        # Índices para dashboard
        ('financial_dashboard_widget_user', 'layout_id', 'dashboard_widget_user_layout_idx', False),
        ('financial_dashboard_layout', 'user_id, active', 'dashboard_layout_user_active_idx', False),
    ]
    
    # Crear índices
    for table, columns, index_name, is_unique in indexes:
        try:
            # Verificar si la tabla existe
            self.env.cr.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = %s
                )
            """, [table])
            
            if not cr.fetchone()[0]:
                _logger.info(f"Tabla {table} no existe, saltando índice {index_name}")
                continue
            
            # Verificar si el índice ya existe
            self.env.cr.execute("""
                SELECT EXISTS (
                    SELECT FROM pg_indexes 
                    WHERE indexname = %s
                )
            """, [index_name])
            
            if cr.fetchone()[0]:
                _logger.info(f"Índice {index_name} ya existe, saltando")
                continue
            
            # Crear índice
            unique_clause = "UNIQUE" if is_unique else ""
            
            if is_unique:
                query = sql.SQL("CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} ({})").format(
                    sql.Identifier(index_name),
                    sql.Identifier(table),
                    sql.SQL(columns)
                )
            else:
                query = sql.SQL("CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} ({})").format(
                    sql.Identifier(index_name),
                    sql.Identifier(table),
                    sql.SQL(columns)
                )
            
            _logger.info(f"Creando índice: {index_name}")
            self.env.cr.execute(query)
            
        except Exception as e:
            _logger.error(f"Error creando índice {index_name}: {str(e)}")
            # No fallar la migración por índices
            continue
    
    # Actualizar estadísticas de las tablas principales
    tables_to_analyze = [
        'account_move',
        'account_move_line',
        'account_analytic_line',
        'financial_dashboard_widget_user'
    ]
    
    for table in tables_to_analyze:
        try:
            self.env.cr.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(table)))
            _logger.info(f"Estadísticas actualizadas para {table}")
        except Exception as e:
            _logger.error(f"Error actualizando estadísticas de {table}: {str(e)}")
    
    # Configurar parámetros de performance si es posible
    try:
        # Estos son solo sugerencias, requieren permisos de superusuario en PostgreSQL
        performance_settings = [
            ("SET work_mem = '32MB'", "work_mem aumentado a 32MB"),
            ("SET maintenance_work_mem = '128MB'", "maintenance_work_mem aumentado a 128MB"),
            ("SET effective_cache_size = '4GB'", "effective_cache_size configurado a 4GB"),
            ("SET random_page_cost = 1.1", "random_page_cost optimizado para SSD"),
        ]
        
        for setting, message in performance_settings:
            try:
                self.env.cr.execute(setting)
                _logger.info(f"Performance: {message}")
            except Exception:
                # Estos settings pueden fallar sin permisos adecuados
                pass
                
    except Exception as e:
        _logger.warning(f"No se pudieron aplicar configuraciones de performance: {str(e)}")
    
    _logger.info("Migración de índices de performance completada")