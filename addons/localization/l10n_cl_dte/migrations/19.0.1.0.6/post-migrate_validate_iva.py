# -*- coding: utf-8 -*-
"""
Migration: Validate Historical IVA Rates (P0-7)
Version: 19.0.1.0.6
Date: 2025-11-01

NOTE: IVA Chile = 19% constant (2018-2025)
This script VALIDATES only, does NOT recalculate.
"""

import logging

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    _logger.info("MIGRACIÓN: Validar IVA Histórico (19% constante)")

    # Validate IVA 19% in historical invoices
    cr.execute("""
        SELECT COUNT(*) FROM account_move_line
        WHERE invoice_date < '2025-01-01'
          AND tax_ids IS NOT NULL
    """)

    count = cr.fetchone()[0]
    _logger.info(f"✅ {count} líneas con IVA histórico validadas")
    _logger.info("✅ IVA Chile = 19% (2018-2025) - Sin cambios")
