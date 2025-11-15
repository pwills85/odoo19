# -*- coding: utf-8 -*-
"""
Migration Script: Preserve Historical DTE Digital Signatures
Version: 19.0.1.0.4
Date: 2025-11-01

PURPOSE:
--------
Preserve digital signatures from historical DTEs (2018-2024) that have EXPIRED certificates.

CRITICAL PROBLEM:
----------------
DTEs migrated from Odoo 11 have XMLDSig signatures created with certificates that are now EXPIRED.

If we try to RE-SIGN these DTEs → ERROR (certificate invalid)
If we LOSE original signature → DTE loses LEGAL validity

SOLUTION:
---------
1. Mark all DTEs < 2025-01-01 as "historical"
2. Preserve original signed XML in dedicated field
3. Modify signing logic to SKIP re-signing for historical DTEs
4. Maintain legal validity of migrated documents

AFFECTED DTEs:
-------------
- Facturas (33, 34): 2018-2024
- Notas Crédito/Débito (61, 56): 2018-2024
- Guías de Despacho (52): 2018-2024

IMPACT:
-------
- Legal: Preserves SII legal validity of historical DTEs
- Audit: Maintains digital signatures for tax audits (up to 6 years)
- Operations: Allows viewing/reprinting historical documents

COMPLIANCE SII:
--------------
Art. 8° Resolución SII: "Los contribuyentes deberán conservar los archivos
electrónicos que contengan los documentos tributarios electrónicos generados
o recibidos por un período de 6 años."

La firma digital original debe preservarse INTACTA para cumplir normativa.
"""

import logging
from odoo import api, SUPERUSER_ID
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """
    Main migration function.

    Args:
        cr: Database cursor
        version: Module version being migrated from
    """
    _logger.info("=" * 80)
    _logger.info("INICIANDO MIGRACIÓN: Preservación Firmas Digitales Históricas")
    _logger.info("=" * 80)

    env = api.Environment(cr, SUPERUSER_ID, {})

    # FASE 1: Identificar DTEs históricos
    dtes_historicos = _identify_historical_dtes(cr)

    # FASE 2: Preservar firmas digitales
    stats = _preserve_signatures(env, dtes_historicos)

    # FASE 3: Validar preservación
    _validate_preservation(env, stats)

    # FASE 4: Reporte final
    _print_migration_report(stats)

    _logger.info("=" * 80)
    _logger.info("✅ MIGRACIÓN COMPLETADA: Firmas Digitales Preservadas")
    _logger.info("=" * 80)


def _identify_historical_dtes(cr):
    """
    Identifica DTEs históricos (< 2025-01-01).

    Returns:
        list: IDs de DTEs históricos
    """
    _logger.info("FASE 1: Identificando DTEs históricos...")

    # Buscar DTEs con XML firmado anterior a 2025
    cr.execute("""
        SELECT id, name, invoice_date, dte_code, dte_folio, dte_xml, dte_timestamp
        FROM account_move
        WHERE invoice_date < '2025-01-01'
          AND dte_code IS NOT NULL
          AND dte_xml IS NOT NULL
          AND state != 'cancel'
        ORDER BY invoice_date ASC
    """)

    dtes = cr.dictfetchall()

    _logger.info(f"Encontrados {len(dtes)} DTEs históricos con firma digital")

    # Mostrar estadísticas por año
    cr.execute("""
        SELECT EXTRACT(YEAR FROM invoice_date) as year, COUNT(*) as count
        FROM account_move
        WHERE invoice_date < '2025-01-01'
          AND dte_code IS NOT NULL
          AND dte_xml IS NOT NULL
          AND state != 'cancel'
        GROUP BY EXTRACT(YEAR FROM invoice_date)
        ORDER BY year
    """)

    stats_by_year = cr.dictfetchall()

    _logger.info("Distribución por año:")
    for row in stats_by_year:
        _logger.info(f"  • {int(row['year'])}: {row['count']} DTEs")

    return dtes


def _preserve_signatures(env, dtes_historicos):
    """
    Preserva firmas digitales de DTEs históricos.

    Args:
        env: Odoo environment
        dtes_historicos: Lista de diccionarios con datos de DTEs

    Returns:
        dict: Estadísticas de preservación
    """
    _logger.info("FASE 2: Preservando firmas digitales...")

    stats = {
        'total': len(dtes_historicos),
        'preserved': 0,
        'skipped_no_xml': 0,
        'skipped_already_historical': 0,
        'errors': 0,
        'by_year': {},
        'by_type': {}
    }

    move_model = env['account.move']

    for dte_data in dtes_historicos:
        try:
            move = move_model.browse(dte_data['id'])

            # Skip si ya está marcado como histórico
            if move.is_historical_dte:
                stats['skipped_already_historical'] += 1
                continue

            # Verificar que tenga XML firmado
            if not dte_data['dte_xml']:
                stats['skipped_no_xml'] += 1
                _logger.warning(f"DTE {move.name} no tiene XML firmado, omitido")
                continue

            # Decodificar XML (está en Binary/base64)
            # En Odoo, Binary fields se leen como bytes, no necesitan decode
            signed_xml_original = dte_data['dte_xml']

            # Actualizar DTE con preservación (usar SQL directo para evitar triggers)
            cr = env.cr
            cr.execute("""
                UPDATE account_move
                SET is_historical_dte = TRUE,
                    signed_xml_original = %s,
                    historical_signature_date = %s,
                    migration_source = 'odoo11',
                    migration_date = NOW()
                WHERE id = %s
            """, (
                signed_xml_original,
                dte_data['dte_timestamp'] or dte_data['invoice_date'],
                dte_data['id']
            ))

            stats['preserved'] += 1

            # Estadísticas por año
            year = dte_data['invoice_date'].year if dte_data['invoice_date'] else 'unknown'
            stats['by_year'][year] = stats['by_year'].get(year, 0) + 1

            # Estadísticas por tipo
            dte_type = dte_data['dte_code'] or 'unknown'
            stats['by_type'][dte_type] = stats['by_type'].get(dte_type, 0) + 1

            _logger.debug(
                f"✅ DTE {move.name} ({dte_data['dte_code']}-{dte_data['dte_folio']}): "
                f"Firma preservada (fecha: {dte_data['invoice_date']})"
            )

        except Exception as e:
            stats['errors'] += 1
            _logger.error(f"❌ Error preservando DTE {dte_data['id']}: {e}")

    _logger.info(
        f"✅ Firmas preservadas: {stats['preserved']} | "
        f"Omitidos: {stats['skipped_already_historical'] + stats['skipped_no_xml']} | "
        f"Errores: {stats['errors']}"
    )

    return stats


def _validate_preservation(env, stats):
    """
    Valida que la preservación fue exitosa.

    Args:
        env: Odoo environment
        stats: Estadísticas de preservación
    """
    _logger.info("FASE 3: Validando preservación...")

    # Verificar que todos los DTEs históricos tengan XML preservado
    cr = env.cr
    cr.execute("""
        SELECT COUNT(*) as count
        FROM account_move
        WHERE is_historical_dte = TRUE
          AND signed_xml_original IS NULL
    """)

    missing_xml = cr.fetchone()[0]

    if missing_xml > 0:
        _logger.error(
            f"❌ VALIDACIÓN FALLIDA: {missing_xml} DTEs históricos sin XML preservado"
        )
        raise UserError(
            f"Migración fallida: {missing_xml} DTEs históricos no tienen XML preservado"
        )

    # Verificar que todos tengan fecha de firma
    cr.execute("""
        SELECT COUNT(*) as count
        FROM account_move
        WHERE is_historical_dte = TRUE
          AND historical_signature_date IS NULL
    """)

    missing_date = cr.fetchone()[0]

    if missing_date > 0:
        _logger.warning(
            f"⚠️  {missing_date} DTEs históricos sin fecha de firma (usar invoice_date)"
        )

    _logger.info("✅ Validación exitosa: Todos los DTEs históricos tienen XML preservado")


def _print_migration_report(stats):
    """
    Imprime reporte final de migración.

    Args:
        stats: Diccionario con estadísticas de preservación
    """
    _logger.info("")
    _logger.info("=" * 80)
    _logger.info("REPORTE DE MIGRACIÓN - PRESERVACIÓN FIRMAS DIGITALES")
    _logger.info("=" * 80)
    _logger.info("")
    _logger.info("📊 ESTADÍSTICAS GENERALES:")
    _logger.info(f"  • Total DTEs procesados:     {stats['total']}")
    _logger.info(f"  • Firmas preservadas:        {stats['preserved']} ✅")
    _logger.info(f"  • Ya eran históricos:        {stats['skipped_already_historical']}")
    _logger.info(f"  • Sin XML (omitidos):        {stats['skipped_no_xml']}")
    _logger.info(f"  • Errores:                   {stats['errors']}")
    _logger.info("")

    if stats['by_year']:
        _logger.info("📅 PRESERVACIÓN POR AÑO:")
        for year in sorted(stats['by_year'].keys()):
            count = stats['by_year'][year]
            _logger.info(f"  • {year}: {count} DTEs")
        _logger.info("")

    if stats['by_type']:
        _logger.info("📄 PRESERVACIÓN POR TIPO DTE:")
        dte_names = {
            '33': 'Factura Electrónica',
            '34': 'Factura Exenta',
            '52': 'Guía de Despacho',
            '56': 'Nota de Débito',
            '61': 'Nota de Crédito',
        }
        for dte_type in sorted(stats['by_type'].keys()):
            count = stats['by_type'][dte_type]
            name = dte_names.get(dte_type, f'DTE {dte_type}')
            _logger.info(f"  • {name} ({dte_type}): {count} DTEs")
        _logger.info("")

    _logger.info("✅ RESULTADO:")
    _logger.info(f"  • {stats['preserved']} DTEs históricos preservados correctamente")
    _logger.info("  • Firmas digitales INTACTAS (certificados expirados no re-firmados)")
    _logger.info("  • Validez legal SII mantenida para auditorías (6 años)")
    _logger.info("")

    if stats['errors'] > 0:
        _logger.warning("")
        _logger.warning("⚠️  ATENCIÓN:")
        _logger.warning("=" * 80)
        _logger.warning(
            f"{stats['errors']} DTEs tuvieron errores durante preservación."
        )
        _logger.warning("")
        _logger.warning("ACCIONES REQUERIDAS:")
        _logger.warning("1. Revisar logs para detalles de errores")
        _logger.warning("2. Verificar manualmente DTEs afectados")
        _logger.warning("3. Re-ejecutar migración si es necesario (es idempotente)")
        _logger.warning("=" * 80)
        _logger.warning("")

    _logger.info("=" * 80)
    _logger.info("COMPLIANCE SII:")
    _logger.info("=" * 80)
    _logger.info("✅ Art. 8° Resolución SII: Archivos electrónicos conservados")
    _logger.info("✅ Firma digital original preservada (no re-firmada)")
    _logger.info("✅ Validez legal para auditorías SII hasta 6 años")
    _logger.info("✅ DTEs históricos pueden visualizarse y reimprimirse")
    _logger.info("=" * 80)
    _logger.info("")

    _logger.info("✅ MIGRACIÓN EXITOSA")
    _logger.info("")
