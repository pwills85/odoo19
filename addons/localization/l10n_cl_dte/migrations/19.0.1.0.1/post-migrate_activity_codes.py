# -*- coding: utf-8 -*-
"""
Migración: Convertir l10n_cl_activity_code (Char) a l10n_cl_activity_ids (Many2many)

CONTEXTO:
Antes: Campo Char que permitía solo UN código de actividad económica
Ahora: Campo Many2many que permite MÚLTIPLES códigos del catálogo SII

ACCIÓN:
- Buscar empresas con código en l10n_cl_activity_code (legacy)
- Buscar registro correspondiente en sii.activity.code
- Agregar a l10n_cl_activity_ids (nuevo campo)
"""
import logging

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Migrar códigos de actividad económica de Char a Many2many"""

    _logger.info("═" * 70)
    _logger.info("MIGRACIÓN: l10n_cl_activity_code → l10n_cl_activity_ids")
    _logger.info("═" * 70)

    # Verificar si existe tabla sii_activity_code
    cr.execute("""
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = 'sii_activity_code'
        )
    """)

    if not cr.fetchone()[0]:
        _logger.warning("Tabla sii_activity_code no existe aún. Saltando migración.")
        return

    # Buscar empresas con código de actividad en formato antiguo
    cr.execute("""
        SELECT
            id,
            name,
            l10n_cl_activity_code
        FROM res_company
        WHERE l10n_cl_activity_code IS NOT NULL
          AND l10n_cl_activity_code != ''
    """)

    companies = cr.fetchall()
    migrated_count = 0
    not_found_count = 0

    for company_id, company_name, activity_code in companies:
        # Buscar código en catálogo
        cr.execute("""
            SELECT id
            FROM sii_activity_code
            WHERE code = %s
              AND active = TRUE
        """, (activity_code,))

        result = cr.fetchone()

        if result:
            activity_id = result[0]

            # Verificar si ya está asignado
            cr.execute("""
                SELECT 1
                FROM res_company_sii_activity_rel
                WHERE company_id = %s
                  AND activity_id = %s
            """, (company_id, activity_id))

            if not cr.fetchone():
                # Agregar relación Many2many
                cr.execute("""
                    INSERT INTO res_company_sii_activity_rel (company_id, activity_id)
                    VALUES (%s, %s)
                """, (company_id, activity_id))

                _logger.info(
                    f"✅ Migrado: {company_name} → [{activity_code}] "
                    f"(company_id={company_id}, activity_id={activity_id})"
                )
                migrated_count += 1
            else:
                _logger.info(
                    f"⏭️  Ya migrado: {company_name} → [{activity_code}]"
                )
        else:
            _logger.warning(
                f"⚠️  Código NO encontrado en catálogo: {activity_code} "
                f"(empresa: {company_name}, id={company_id})\n"
                f"   ACCIÓN: Crear manualmente registro en sii.activity.code"
            )
            not_found_count += 1

    _logger.info("═" * 70)
    _logger.info("MIGRACIÓN COMPLETADA:")
    _logger.info(f"  ✅ Migrados: {migrated_count}")
    _logger.info(f"  ⚠️  No encontrados: {not_found_count}")
    _logger.info("═" * 70)
