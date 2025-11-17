#!/usr/bin/env python3
"""
MCP Server para consultas seguras a base de datos Odoo
Proporciona acceso controlado a datos de Odoo sin comprometer seguridad
"""

import os
import sys
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from mcp.server import Server
import mcp.types as types
from typing import Any, Sequence
import configparser
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OdooDatabaseMCPServer(Server):
    """Servidor MCP para consultas seguras a base de datos Odoo"""

    def __init__(self, config_path: str):
        super().__init__("odoo-database-tools", "1.0.0")
        self.config_path = config_path
        self.db_config = self._load_db_config()
        self.connection = None

        # Registrar herramientas disponibles
        self.add_tool(self.get_model_structure)
        self.add_tool(self.get_dte_records)
        self.add_tool(self.get_payroll_data)
        self.add_tool(self.validate_rut_in_db)
        self.add_tool(self.get_company_config)

    def _load_db_config(self) -> dict:
        """Cargar configuración de base de datos desde odoo.conf"""
        config = configparser.ConfigParser()
        config.read(self.config_path)

        return {
            'host': os.getenv('ODOO_DB_HOST', config.get('options', 'db_host', fallback='localhost')),
            'port': int(os.getenv('ODOO_DB_PORT', config.get('options', 'db_port', fallback='5432'))),
            'database': os.getenv('ODOO_DB_NAME', config.get('options', 'db_name', fallback='odoo19_dev')),
            'user': os.getenv('ODOO_DB_USER', config.get('options', 'db_user', fallback='odoo')),
            'password': os.getenv('ODOO_DB_PASSWORD', config.get('options', 'db_password', fallback='')),
        }

    def _get_connection(self):
        """Obtener conexión a base de datos con cache"""
        if self.connection is None or self.connection.closed:
            try:
                self.connection = psycopg2.connect(**self.db_config, cursor_factory=RealDictCursor)
                logger.info("Conexión a base de datos Odoo establecida")
            except Exception as e:
                logger.error(f"Error conectando a base de datos: {e}")
                raise
        return self.connection

    @types.tool(
        name="get_model_structure",
        description="Obtiene la estructura de un modelo Odoo (campos, tipos, relaciones)",
        parameters={
            "model_name": {
                "type": "string",
                "description": "Nombre del modelo Odoo (ej: account.move, hr.payslip)"
            }
        }
    )
    async def get_model_structure(self, model_name: str) -> dict:
        """Obtener estructura de un modelo Odoo"""
        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                # Obtener información de campos desde ir.model.fields
                cursor.execute("""
                    SELECT f.name, f.field_description, f.ttype, f.relation, f.required,
                           f.store, f.index, f.translate
                    FROM ir_model_fields f
                    JOIN ir_model m ON f.model_id = m.id
                    WHERE m.model = %s AND f.name NOT LIKE '__%%'
                    ORDER BY f.name
                """, (model_name,))

                fields = cursor.fetchall()

                # Obtener información del modelo
                cursor.execute("""
                    SELECT name, model, info, transient, inherited_model_ids
                    FROM ir_model
                    WHERE model = %s
                """, (model_name,))

                model_info = cursor.fetchone()

                return {
                    "model": dict(model_info) if model_info else None,
                    "fields": [dict(field) for field in fields],
                    "field_count": len(fields)
                }

        except Exception as e:
            logger.error(f"Error obteniendo estructura del modelo {model_name}: {e}")
            return {"error": str(e), "model": model_name}

    @types.tool(
        name="get_dte_records",
        description="Obtiene registros DTE con filtros de seguridad",
        parameters={
            "limit": {
                "type": "integer",
                "description": "Número máximo de registros a retornar",
                "default": 50
            },
            "company_id": {
                "type": "integer",
                "description": "ID de la compañía (obligatorio por seguridad)"
            },
            "dte_type": {
                "type": "string",
                "description": "Tipo de DTE (33, 34, 52, 56, 61)",
                "enum": ["33", "34", "52", "56", "61"]
            }
        }
    )
    async def get_dte_records(self, limit: int = 50, company_id: int = None,
                            dte_type: str = None) -> dict:
        """Obtener registros DTE con control de acceso"""
        if not company_id:
            return {"error": "company_id es obligatorio por seguridad"}

        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                query = """
                    SELECT am.id, am.name, am.move_type, am.state,
                           am.amount_total, am.currency_id,
                           am.l10n_cl_dte_type_id, am.l10n_cl_dte_status,
                           am.l10n_cl_dte_partner_id, am.invoice_date
                    FROM account_move am
                    WHERE am.company_id = %s
                """
                params = [company_id]

                if dte_type:
                    query += " AND am.l10n_cl_dte_type_id = %s"
                    params.append(dte_type)

                query += f" ORDER BY am.id DESC LIMIT {min(limit, 100)}"

                cursor.execute(query, params)
                records = cursor.fetchall()

                return {
                    "records": [dict(record) for record in records],
                    "count": len(records),
                    "company_id": company_id,
                    "filters": {"dte_type": dte_type}
                }

        except Exception as e:
            logger.error(f"Error obteniendo registros DTE: {e}")
            return {"error": str(e)}

    @types.tool(
        name="get_payroll_data",
        description="Obtiene datos de nómina con filtros de seguridad",
        parameters={
            "employee_id": {
                "type": "integer",
                "description": "ID del empleado (opcional)"
            },
            "company_id": {
                "type": "integer",
                "description": "ID de la compañía (obligatorio por seguridad)"
            },
            "period_start": {
                "type": "string",
                "description": "Fecha inicio período (YYYY-MM-DD)"
            },
            "period_end": {
                "type": "string",
                "description": "Fecha fin período (YYYY-MM-DD)"
            },
            "limit": {
                "type": "integer",
                "description": "Número máximo de registros",
                "default": 50
            }
        }
    )
    async def get_payroll_data(self, employee_id: int = None, company_id: int = None,
                             period_start: str = None, period_end: str = None,
                             limit: int = 50) -> dict:
        """Obtener datos de nómina con control de acceso"""
        if not company_id:
            return {"error": "company_id es obligatorio por seguridad"}

        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                query = """
                    SELECT hp.id, hp.name, hp.employee_id, hp.state,
                           hp.date_from, hp.date_to, hp.net_wage,
                           hp.l10n_cl_total_imponible, hp.l10n_cl_afp_amount,
                           hp.l10n_cl_isapre_amount, he.name as employee_name
                    FROM hr_payslip hp
                    JOIN hr_employee he ON hp.employee_id = he.id
                    WHERE hp.company_id = %s
                """
                params = [company_id]

                if employee_id:
                    query += " AND hp.employee_id = %s"
                    params.append(employee_id)

                if period_start:
                    query += " AND hp.date_from >= %s"
                    params.append(period_start)

                if period_end:
                    query += " AND hp.date_to <= %s"
                    params.append(period_end)

                query += f" ORDER BY hp.id DESC LIMIT {min(limit, 100)}"

                cursor.execute(query, params)
                records = cursor.fetchall()

                return {
                    "records": [dict(record) for record in records],
                    "count": len(records),
                    "company_id": company_id,
                    "filters": {
                        "employee_id": employee_id,
                        "period_start": period_start,
                        "period_end": period_end
                    }
                }

        except Exception as e:
            logger.error(f"Error obteniendo datos de nómina: {e}")
            return {"error": str(e)}

    @types.tool(
        name="validate_rut_in_db",
        description="Valida si un RUT existe en la base de datos y obtiene información asociada",
        parameters={
            "vat": {
                "type": "string",
                "description": "RUT a validar (con o sin formato)"
            },
            "company_id": {
                "type": "integer",
                "description": "ID de la compañía para filtrar resultados"
            }
        }
    )
    async def validate_rut_in_db(self, vat: str, company_id: int = None) -> dict:
        """Validar RUT contra base de datos"""
        try:
            # Normalizar RUT
            vat_clean = ''.join(filter(str.isdigit, vat))
            if len(vat_clean) > 1:
                vat_clean = vat_clean[:-1] + '-' + vat_clean[-1]

            conn = self._get_connection()
            with conn.cursor() as cursor:
                query = """
                    SELECT p.id, p.name, p.vat, p.is_company,
                           p.l10n_cl_activity_description, p.email,
                           CASE WHEN p.is_company THEN 'Empresa' ELSE 'Persona' END as type_desc
                    FROM res_partner p
                    WHERE p.vat = %s
                """
                params = [vat_clean]

                if company_id:
                    query += " AND (p.company_id = %s OR p.company_id IS NULL)"
                    params.append(company_id)

                cursor.execute(query, params)
                partners = cursor.fetchall()

                return {
                    "rut_input": vat,
                    "rut_normalized": vat_clean,
                    "partners_found": len(partners),
                    "partners": [dict(partner) for partner in partners],
                    "validation": "found" if partners else "not_found"
                }

        except Exception as e:
            logger.error(f"Error validando RUT {vat}: {e}")
            return {"error": str(e), "rut_input": vat}

    @types.tool(
        name="get_company_config",
        description="Obtiene configuración específica de compañía para localización chilena",
        parameters={
            "company_id": {
                "type": "integer",
                "description": "ID de la compañía"
            }
        }
    )
    async def get_company_config(self, company_id: int) -> dict:
        """Obtener configuración de compañía chilena"""
        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                # Configuración general de compañía
                cursor.execute("""
                    SELECT c.id, c.name, c.vat, c.country_id,
                           c.l10n_cl_company_activity_id, c.l10n_cl_sii_regional_office,
                           c.l10n_cl_dte_resolution_number, c.l10n_cl_dte_resolution_date
                    FROM res_company c
                    WHERE c.id = %s
                """, (company_id,))

                company = cursor.fetchone()

                if not company:
                    return {"error": "Compañía no encontrada", "company_id": company_id}

                # Configuración DTE
                cursor.execute("""
                    SELECT dt.id, dt.name, dt.code, dt.active
                    FROM l10n_cl_dte_type dt
                    WHERE dt.company_id = %s OR dt.company_id IS NULL
                    ORDER BY dt.code
                """, (company_id,))

                dte_types = cursor.fetchall()

                # Indicadores económicos
                cursor.execute("""
                    SELECT ei.id, ei.name, ei.type, ei.value, ei.date
                    FROM hr_economic_indicators ei
                    WHERE ei.company_id = %s OR ei.company_id IS NULL
                    ORDER BY ei.date DESC
                    LIMIT 10
                """, (company_id,))

                indicators = cursor.fetchall()

                return {
                    "company": dict(company),
                    "dte_types": [dict(dt) for dt in dte_types],
                    "economic_indicators": [dict(ei) for ei in indicators],
                    "config_complete": bool(company and dte_types)
                }

        except Exception as e:
            logger.error(f"Error obteniendo configuración de compañía {company_id}: {e}")
            return {"error": str(e), "company_id": company_id}

def main():
    """Función principal del servidor MCP"""
    import argparse

    parser = argparse.ArgumentParser(description="MCP Server para base de datos Odoo")
    parser.add_argument("--config", required=True, help="Ruta al archivo odoo.conf")
    args = parser.parse_args()

    # Inicializar servidor
    server = OdooDatabaseMCPServer(args.config)

    # Ejecutar servidor
    import asyncio
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
