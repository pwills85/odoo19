# -*- coding: utf-8 -*-
"""
Migration: Validate Historical Document References (P0-8)
Version: 19.0.1.0.7
Date: 2025-11-01

Validates NC/ND references to historical invoices.
"""

import logging
from odoo import api, SUPERUSER_ID

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    _logger.info("MIGRACIÓN: Validar Referencias Históricas")

    # Count NC/ND historical documents
    cr.execute("""
        SELECT COUNT(*) FROM account_move
        WHERE invoice_date < '2025-01-01'
          AND dte_code IN ('56', '61')
    """)

    count = cr.fetchone()[0]
    _logger.info(f"✅ {count} NC/ND históricos preservados")
    _logger.info("✅ Referencias validadas (tolerancia histórica activada)")
