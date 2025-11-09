# -*- coding: utf-8 -*-
"""
Migration Script: Recalcular Retenciones Históricas BHE
Version: 19.0.1.0.3
Date: 2025-11-01

PURPOSE:
--------
Recalcula las retenciones de BHE históricas (2018-2024) usando las tasas
correctas según el año de emisión.

PROBLEMA A RESOLVER:
-------------------
Las BHE migradas desde Odoo 11 pueden tener tasas incorrectas:
- 2018: debería ser 10.0%, no 14.5%
- 2019: debería ser 10.0%, no 14.5%
- 2020: debería ser 10.0%, no 14.5%
- 2021: debería ser 11.5%, no 14.5%
- 2022: debería ser 12.25%, no 14.5%
- 2023: debería ser 13.0%, no 14.5%
- 2024: debería ser 13.75%, no 14.5%

PROCESO:
--------
1. Cargar tasas históricas en tabla l10n_cl.bhe.retention.rate
2. Para cada BHE histórica:
   a. Obtener tasa correcta según fecha emisión
   b. Recalcular monto retención
   c. Recalcular monto neto
   d. Actualizar registro
3. Recalcular libros BHE históricos (totales)
4. Generar reporte de correcciones

CRITICAL FOR:
------------
- Empresas de ingeniería con alto volumen de BHE (50-100/mes)
- Migración desde Odoo 11 (datos desde 2018)
- Compliance SII (declaración F29 correcta)

IMPACT:
-------
- Corrección financiera: hasta 45% error (10% vs 14.5%)
- Afecta declaración F29 histórica
- Puede requerir declaración rectificatoria si ya se declaró
"""

import logging
from odoo import api, SUPERUSER_ID
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """
    Main migration function.

    Args:
        cr: Database cursor
        version: Module version being migrated from
    """
    _logger.info("=" * 80)
    _logger.info("INICIANDO MIGRACIÓN: Recálculo Retenciones Históricas BHE")
    _logger.info("=" * 80)

    env = api.Environment(cr, SUPERUSER_ID, {})

    # FASE 1: Cargar tasas históricas
    _load_historical_rates(env)

    # FASE 2: Recalcular BHE históricas
    stats = _recalculate_historical_bhes(env)

    # FASE 3: Recalcular libros BHE
    _recalculate_bhe_books(env)

    # FASE 4: Reporte final
    _print_migration_report(stats)

    _logger.info("=" * 80)
    _logger.info("✅ MIGRACIÓN COMPLETADA: Retenciones BHE Recalculadas")
    _logger.info("=" * 80)


def _load_historical_rates(env):
    """
    Carga tasas históricas en tabla l10n_cl.bhe.retention.rate.

    Esta función es idempotente: si las tasas ya existen, no las duplica.
    """
    _logger.info("FASE 1: Cargando tasas históricas...")

    rate_model = env['l10n_cl.bhe.retention.rate']

    # Llamar al método de carga del modelo
    try:
        rate_model._load_historical_rates()
        _logger.info("✅ Tasas históricas cargadas")
    except Exception as e:
        _logger.error(f"❌ Error cargando tasas históricas: {e}")
        raise


def _recalculate_historical_bhes(env):
    """
    Recalcula retenciones de BHE históricas (2018-2024).

    Returns:
        dict: Estadísticas de migración
    """
    _logger.info("FASE 2: Recalculando BHE históricas...")

    bhe_model = env['l10n_cl.bhe']
    rate_model = env['l10n_cl.bhe.retention.rate']

    # Buscar BHE históricas (antes de 2025)
    historical_bhes = bhe_model.search([
        ('date', '<', '2025-01-01'),
        ('state', 'in', ['posted', 'accepted', 'declared'])
    ], order='date asc')

    _logger.info(f"Encontradas {len(historical_bhes)} BHE históricas para recalcular")

    stats = {
        'total': len(historical_bhes),
        'corrected': 0,
        'no_change': 0,
        'errors': 0,
        'corrections_by_year': {},
        'total_diff_retention': 0.0
    }

    for bhe in historical_bhes:
        try:
            # Obtener tasa correcta para la fecha
            correct_rate = rate_model.get_rate_for_date(bhe.date)

            # Calcular nueva retención
            new_retention = bhe.amount_gross * (correct_rate / 100)
            new_net = bhe.amount_gross - new_retention

            # Solo actualizar si hay diferencia significativa (> $1)
            if abs(new_retention - bhe.amount_retention) > 1:
                year = bhe.date.year

                # Registrar diferencia
                diff = new_retention - bhe.amount_retention
                stats['total_diff_retention'] += diff

                # Actualizar BHE (usar SQL directo para evitar recomputes)
                cr = env.cr
                cr.execute("""
                    UPDATE l10n_cl_bhe
                    SET retention_rate = %s,
                        amount_retention = %s,
                        amount_net = %s
                    WHERE id = %s
                """, (correct_rate, new_retention, new_net, bhe.id))

                stats['corrected'] += 1
                if year not in stats['corrections_by_year']:
                    stats['corrections_by_year'][year] = 0
                stats['corrections_by_year'][year] += 1

                _logger.debug(
                    f"BHE {bhe.number} ({bhe.date}): "
                    f"Tasa {bhe.retention_rate}% → {correct_rate}% | "
                    f"Retención ${bhe.amount_retention:,.0f} → ${new_retention:,.0f} "
                    f"(diff: ${diff:,.0f})"
                )
            else:
                stats['no_change'] += 1

        except ValidationError as e:
            stats['errors'] += 1
            _logger.error(f"❌ Error procesando BHE {bhe.id}: {e}")
        except Exception as e:
            stats['errors'] += 1
            _logger.error(f"❌ Error inesperado procesando BHE {bhe.id}: {e}")

    _logger.info(f"✅ BHE recalculadas: {stats['corrected']} corregidas, "
                 f"{stats['no_change']} sin cambios, {stats['errors']} errores")

    return stats


def _recalculate_bhe_books(env):
    """
    Recalcula totales de libros BHE históricos.

    Como las líneas del libro tienen campos required, necesitamos actualizar
    también las líneas del libro para que coincidan con las BHE corregidas.
    """
    _logger.info("FASE 3: Recalculando libros BHE históricos...")

    book_model = env['l10n_cl.bhe.book']
    line_model = env['l10n_cl.bhe.book.line']

    # Buscar libros históricos (antes de 2025)
    historical_books = book_model.search([
        ('period_year', '<', 2025),
        ('state', 'in', ['posted', 'declared'])
    ])

    _logger.info(f"Encontrados {len(historical_books)} libros históricos")

    books_updated = 0
    for book in historical_books:
        try:
            # Actualizar líneas del libro con tasas correctas de BHE
            for line in book.line_ids:
                if line.bhe_id:
                    # Usar SQL directo
                    cr = env.cr
                    cr.execute("""
                        UPDATE l10n_cl_bhe_book_line
                        SET retention_rate = %s,
                            amount_retention = %s,
                            amount_net = %s
                        WHERE id = %s
                    """, (
                        line.bhe_id.retention_rate,
                        line.bhe_id.amount_retention,
                        line.bhe_id.amount_net,
                        line.id
                    ))

            # Recomputar totales del libro (forzar usando _compute_totals)
            book._compute_totals()

            books_updated += 1

            _logger.debug(
                f"Libro {book.name}: Total retenciones = ${book.total_retention:,.0f}"
            )

        except Exception as e:
            _logger.error(f"❌ Error recalculando libro {book.id}: {e}")

    _logger.info(f"✅ Libros BHE actualizados: {books_updated}")


def _print_migration_report(stats):
    """
    Imprime reporte final de migración.

    Args:
        stats: Diccionario con estadísticas de migración
    """
    _logger.info("")
    _logger.info("=" * 80)
    _logger.info("REPORTE DE MIGRACIÓN - RETENCIONES BHE HISTÓRICAS")
    _logger.info("=" * 80)
    _logger.info("")
    _logger.info(f"📊 ESTADÍSTICAS GENERALES:")
    _logger.info(f"  • Total BHE procesadas: {stats['total']}")
    _logger.info(f"  • BHE corregidas:       {stats['corrected']}")
    _logger.info(f"  • BHE sin cambios:      {stats['no_change']}")
    _logger.info(f"  • Errores:              {stats['errors']}")
    _logger.info("")

    if stats['corrections_by_year']:
        _logger.info(f"📅 CORRECCIONES POR AÑO:")
        for year in sorted(stats['corrections_by_year'].keys()):
            count = stats['corrections_by_year'][year]
            _logger.info(f"  • {year}: {count} BHE corregidas")
        _logger.info("")

    _logger.info(f"💰 IMPACTO FINANCIERO:")
    _logger.info(f"  • Diferencia total retenciones: ${stats['total_diff_retention']:,.0f}")
    _logger.info("")

    if stats['total_diff_retention'] != 0:
        _logger.warning("")
        _logger.warning("⚠️  ATENCIÓN CONTADOR:")
        _logger.warning("=" * 80)
        _logger.warning(
            f"Las retenciones históricas fueron ajustadas en ${stats['total_diff_retention']:,.0f}."
        )
        _logger.warning("")
        _logger.warning("ACCIONES REQUERIDAS:")
        _logger.warning("1. Revisar declaraciones F29 históricas (2018-2024)")
        _logger.warning("2. Evaluar si se requiere declaración rectificatoria")
        _logger.warning("3. Validar saldos contables de cuenta retención honorarios")
        _logger.warning("4. Documentar ajuste para auditoría interna")
        _logger.warning("=" * 80)
        _logger.warning("")

    _logger.info("✅ MIGRACIÓN EXITOSA")
    _logger.info("")
