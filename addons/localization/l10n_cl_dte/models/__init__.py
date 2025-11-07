# -*- coding: utf-8 -*-

# TEMPORALMENTE DESACTIVADO: Causa AssertionError en Odoo 19 (import fuera de odoo.addons)
# from . import dte_service_integration  # ⭐ Integration layer first
# from . import ai_chat_integration      # ⭐ AI Chat integration

# ═══════════════════════════════════════════════════════════
# NUEVOS MODELOS - CUENTAS ANALÍTICAS (2025-10-23)
# ═══════════════════════════════════════════════════════════
from . import dte_ai_client  # Cliente AI Service (abstract model)
from . import analytic_dashboard  # Dashboard rentabilidad cuentas analíticas
from . import dte_dashboard  # ⭐ NEW (Fase 2.1 - 2025-11-07): Dashboard Central DTEs - Monitoreo SII

# ═══════════════════════════════════════════════════════════
# AI INTEGRATION - PHASE 2 (2025-10-24)
# ═══════════════════════════════════════════════════════════
from . import ai_agent_selector  # 🆕 RBAC-aware plugin selector

# ═══════════════════════════════════════════════════════════
# NUEVOS MODELOS - BHE (Boleta Honorarios) 2025-10-23
# ═══════════════════════════════════════════════════════════
from . import l10n_cl_bhe_retention_rate  # Tasas históricas 2018-2025

# ═══════════════════════════════════════════════════════════
# DISASTER RECOVERY - NATIVE IMPLEMENTATION (2025-10-24)
# ═══════════════════════════════════════════════════════════
from . import dte_backup  # ⭐ NEW: DTE backup storage (PostgreSQL + ir.attachment)
from . import dte_failed_queue  # ⭐ NEW: Failed DTEs retry queue (exponential backoff)

# ═══════════════════════════════════════════════════════════
# CONTINGENCY MODE - NATIVE IMPLEMENTATION (Sprint 3 - 2025-10-24)
# ═══════════════════════════════════════════════════════════
from . import dte_contingency  # ⭐ NEW: Contingency mode (OBLIGATORIO normativa SII)

# ═══════════════════════════════════════════════════════════
# RCV - REGISTRO DE COMPRAS Y VENTAS (Sprint 1 - 2025-11-01)
# Resolución SII 61/2017, 68/2017 - OBLIGATORIO
# ═══════════════════════════════════════════════════════════
from . import l10n_cl_rcv_entry  # ⭐ NEW: Entradas RCV individuales
from . import l10n_cl_rcv_period  # ⭐ NEW: Períodos mensuales RCV
from . import l10n_cl_rcv_integration  # ⭐ NEW: Sincronización con SII

# ═══════════════════════════════════════════════════════════
# CATÁLOGOS SII (2025-10-24)
# ═══════════════════════════════════════════════════════════
from . import sii_activity_code  # ⭐ NEW: Catálogo CIIU Rev. 4 CL (códigos actividad económica)
from . import l10n_cl_comuna  # ⭐ NEW: Catálogo oficial 345 comunas de Chile

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
# P2.2 GAP CLOSURE: RabbitMQ removed - standardized on ir.cron
# from . import rabbitmq_helper  # REMOVED
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

# ═══════════════════════════════════════════════════════════
# ENHANCED FEATURES (v19.0.6.0.0 - ex-l10n_cl_dte_enhanced)
# ═══════════════════════════════════════════════════════════
from . import account_move_enhanced  # Contact, forma_pago, cedible, reference_ids
from . import account_move_reference  # SII document references (NC/ND mandatory)
from . import res_company_bank_info  # Bank information management
from . import report_helper  # PDF report helper utilities

