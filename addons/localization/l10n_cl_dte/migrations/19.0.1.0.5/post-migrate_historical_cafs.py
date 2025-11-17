# -*- coding: utf-8 -*-
"""
Migration Script: Mark Historical CAFs
Version: 19.0.1.0.5
Date: 2025-11-01

PURPOSE:
--------
Mark historical CAFs (< 2025) to prevent folio duplication.

CRITICAL PROBLEM:
----------------
CAFs from Odoo 11 (2018-2024) are EXHAUSTED.
If used for new DTEs → FOLIO DUPLICATION → SII rejection

SOLUTION:
---------
1. Mark all CAFs with fecha_autorizacion < 2025-01-01 as historical
2. Mark all EXHAUSTED CAFs as historical
3. Modify search logic to EXCLUDE historical CAFs

IMPACT:
-------
- Prevents folio duplication
- Maintains audit trail (CAFs preserved)
- New DTEs use only current CAFs
"""

import logging
from odoo import api, SUPERUSER_ID

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Main migration function."""
    _logger.info("=" * 80)
    _logger.info("MIGRACIÓN: Marcar CAFs Históricos")
    _logger.info("=" * 80)

    api.Environment(cr, SUPERUSER_ID, {})

    # FASE 1: Marcar CAFs históricos por fecha
    stats = _mark_historical_by_date(cr)

    # FASE 2: Marcar CAFs agotados
    stats.update(_mark_historical_exhausted(cr))

    # FASE 3: Reporte
    _print_report(stats)

    _logger.info("=" * 80)
    _logger.info("✅ MIGRACIÓN COMPLETADA")
    _logger.info("=" * 80)


def _mark_historical_by_date(cr):
    """Mark CAFs with fecha_autorizacion < 2025 as historical."""
    _logger.info("FASE 1: Marcando CAFs por fecha...")

    cr.execute("""
        UPDATE dte_caf
        SET is_historical = TRUE
        WHERE fecha_autorizacion < '2025-01-01'
          AND is_historical = FALSE
    """)

    count = cr.rowcount
    _logger.info(f"✅ {count} CAFs marcados como históricos (fecha < 2025)")

    return {'by_date': count}


def _mark_historical_exhausted(cr):
    """Mark EXHAUSTED CAFs as historical."""
    _logger.info("FASE 2: Marcando CAFs agotados...")

    cr.execute("""
        UPDATE dte_caf
        SET is_historical = TRUE
        WHERE state = 'exhausted'
          AND is_historical = FALSE
    """)

    count = cr.rowcount
    _logger.info(f"✅ {count} CAFs agotados marcados como históricos")

    return {'exhausted': count}


def _print_report(stats):
    """Print migration report."""
    _logger.info("")
    _logger.info("=" * 80)
    _logger.info("REPORTE MIGRACIÓN - CAFs HISTÓRICOS")
    _logger.info("=" * 80)
    _logger.info(f"CAFs marcados por fecha: {stats.get('by_date', 0)}")
    _logger.info(f"CAFs marcados agotados: {stats.get('exhausted', 0)}")
    _logger.info(f"TOTAL: {stats.get('by_date', 0) + stats.get('exhausted', 0)}")
    _logger.info("=" * 80)
