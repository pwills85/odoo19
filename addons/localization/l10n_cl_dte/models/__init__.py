# -*- coding: utf-8 -*-

# TEMPORALMENTE DESACTIVADO: Causa AssertionError en Odoo 19 (import fuera de odoo.addons)
# from . import dte_service_integration  # ⭐ Integration layer first
# from . import ai_chat_integration      # ⭐ AI Chat integration

# ═══════════════════════════════════════════════════════════
# NUEVOS MODELOS - CUENTAS ANALÍTICAS (2025-10-23)
# ═══════════════════════════════════════════════════════════
from . import dte_ai_client  # Cliente AI Service (abstract model)
from . import analytic_dashboard  # Dashboard rentabilidad cuentas analíticas

# ═══════════════════════════════════════════════════════════
# NUEVOS MODELOS - BHE (Boleta Honorarios) 2025-10-23
# ═══════════════════════════════════════════════════════════
from . import l10n_cl_bhe_retention_rate  # Tasas históricas 2018-2025

# ═══════════════════════════════════════════════════════════
# MODELOS EXISTENTES
# ═══════════════════════════════════════════════════════════
from . import dte_certificate
from . import dte_caf
from . import dte_communication
from . import dte_consumo_folios
from . import dte_libro
from . import dte_libro_guias  # ⭐ Libro de Guías de Despacho
from . import dte_inbox  # ⭐ DTE Reception (Gap #1)
from . import rabbitmq_helper
from . import account_move_dte
from . import account_journal_dte
from . import account_tax_dte
from . import purchase_order_dte
from . import stock_picking_dte
from . import retencion_iue
from . import retencion_iue_tasa  # Tasas históricas de retención IUE 2018-2025
from . import boleta_honorarios  # Boleta de Honorarios (recepción)
from . import res_partner_dte
from . import res_company_dte
from . import res_config_settings
from . import l10n_cl_bhe_book  # BHE: Libro mensual (DESPUÉS de retention_rate)

