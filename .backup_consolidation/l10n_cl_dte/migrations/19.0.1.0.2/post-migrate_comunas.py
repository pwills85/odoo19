# -*- coding: utf-8 -*-
"""
Migración 19.0.1.0.2: Campo l10n_cl_comuna (Char) → l10n_cl_comuna_id (Many2one)

CAMBIOS:
- Nuevo modelo: l10n.cl.comuna (catálogo 347 comunas oficiales SII)
- res.partner: l10n_cl_comuna_id Many2one (nuevo)
- res.partner: l10n_cl_comuna Char → Computed (deprecated)

MIGRACIÓN:
- Migrar datos existentes en l10n_cl_comuna (texto) → l10n_cl_comuna_id (Many2one)
- Matching inteligente por nombre y región
"""
import logging
from odoo import SUPERUSER_ID, api

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """
    Migrar campo comuna de texto a Many2one

    Args:
        cr: Database cursor
        version (str): Versión del módulo antes de la migración
    """
    _logger.info("=" * 70)
    _logger.info("INICIANDO MIGRACIÓN: l10n_cl_comuna → l10n_cl_comuna_id")
    _logger.info("=" * 70)

    # Usar SUPERUSER_ID para acceso completo durante migración
    env = api.Environment(cr, SUPERUSER_ID, {})

    # ═══════════════════════════════════════════════════════════
    # PASO 1: Verificar que el catálogo de comunas existe
    # ═══════════════════════════════════════════════════════════

    total_comunas = env['l10n.cl.comuna'].search_count([])
    _logger.info(f"✓ Catálogo de comunas cargado: {total_comunas} comunas")

    if total_comunas == 0:
        _logger.warning(
            "⚠️ ADVERTENCIA: No se encontraron comunas en el catálogo. "
            "La migración no podrá asignar Many2one. "
            "Asegúrese de que el archivo data/l10n_cl_comunas_data.xml se haya cargado."
        )
        return

    # ═══════════════════════════════════════════════════════════
    # PASO 2: Buscar partners con comuna (texto) pero sin Many2one
    # ═══════════════════════════════════════════════════════════

    # SQL directo para performance (evitar computed fields)
    cr.execute("""
        SELECT id, l10n_cl_comuna, state_id, city
        FROM res_partner
        WHERE l10n_cl_comuna IS NOT NULL
          AND l10n_cl_comuna != ''
          AND l10n_cl_comuna_id IS NULL
          AND country_id = (SELECT id FROM res_country WHERE code = 'CL')
    """)

    partners_to_migrate = cr.fetchall()
    total_to_migrate = len(partners_to_migrate)

    _logger.info(f"✓ Partners chilenos con comuna (texto): {total_to_migrate}")

    if total_to_migrate == 0:
        _logger.info("✓ No hay datos para migrar. Migración completada.")
        return

    # ═══════════════════════════════════════════════════════════
    # PASO 3: Migrar cada partner
    # ═══════════════════════════════════════════════════════════

    stats = {
        'migrated': 0,
        'not_found': 0,
        'errors': 0,
    }

    not_found_comunas = {}  # Para reporte

    for partner_id, comuna_text, state_id, city in partners_to_migrate:
        try:
            # Normalizar nombre (eliminar espacios extra, title case)
            comuna_normalized = ' '.join(comuna_text.split()).strip()

            # Intentar match exacto por nombre
            comuna_obj = env['l10n.cl.comuna'].search([
                ('name', '=ilike', comuna_normalized)
            ], limit=1)

            # Si no hay match exacto, intentar match aproximado
            if not comuna_obj and state_id:
                comuna_obj = env['l10n.cl.comuna'].search([
                    ('name', 'ilike', comuna_normalized),
                    ('state_id', '=', state_id)
                ], limit=1)

            # Si aún no hay match, intentar con ciudad
            if not comuna_obj and city and state_id:
                comuna_obj = env['l10n.cl.comuna'].search([
                    ('name', 'ilike', city),
                    ('state_id', '=', state_id)
                ], limit=1)

            if comuna_obj:
                # MATCH ENCONTRADO: Actualizar Many2one
                cr.execute("""
                    UPDATE res_partner
                    SET l10n_cl_comuna_id = %s
                    WHERE id = %s
                """, (comuna_obj.id, partner_id))

                stats['migrated'] += 1

                _logger.debug(
                    f"✓ Partner {partner_id}: '{comuna_text}' → "
                    f"[{comuna_obj.code}] {comuna_obj.name}"
                )
            else:
                # NO SE ENCONTRÓ MATCH
                stats['not_found'] += 1

                # Registrar para reporte
                key = (comuna_normalized, state_id)
                not_found_comunas[key] = not_found_comunas.get(key, 0) + 1

                _logger.warning(
                    f"⚠️ Partner {partner_id}: No se encontró comuna '{comuna_text}' "
                    f"(región: {state_id}, ciudad: {city})"
                )

        except Exception as e:
            stats['errors'] += 1
            _logger.error(
                f"❌ Error migrando partner {partner_id}: {str(e)}"
            )

    # ═══════════════════════════════════════════════════════════
    # PASO 4: Reporte final
    # ═══════════════════════════════════════════════════════════

    _logger.info("=" * 70)
    _logger.info("MIGRACIÓN COMPLETADA")
    _logger.info("=" * 70)
    _logger.info(f"Total partners procesados: {total_to_migrate}")
    _logger.info(f"✓ Migrados exitosamente:   {stats['migrated']}")
    _logger.info(f"⚠️ Sin match en catálogo:   {stats['not_found']}")
    _logger.info(f"❌ Errores:                 {stats['errors']}")

    if stats['not_found'] > 0:
        _logger.warning("-" * 70)
        _logger.warning("COMUNAS NO ENCONTRADAS (requieren revisión manual):")
        _logger.warning("-" * 70)

        for (comuna_text, state_id), count in sorted(
            not_found_comunas.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            state_name = "Sin región"
            if state_id:
                cr.execute(
                    "SELECT name FROM res_country_state WHERE id = %s",
                    (state_id,)
                )
                result = cr.fetchone()
                if result:
                    state_name = result[0]

            _logger.warning(
                f"  • '{comuna_text}' en {state_name}: {count} registros"
            )

        _logger.warning("")
        _logger.warning(
            "ACCIÓN REQUERIDA:"
        )
        _logger.warning(
            "  1. Revisar logs y corregir nombres de comunas manualmente"
        )
        _logger.warning(
            "  2. O corregir directamente en Odoo: Contactos → Editar → Comuna"
        )

    _logger.info("=" * 70)
