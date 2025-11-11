# -*- coding: utf-8 -*-

# P0 Critical Tests (Auditoría 2025-11-07)
from . import test_hr_contract_stub_ce  # SPRINT 1 - CE compatibility stub
from . import test_company_currency_id_fields  # SPRINT 1 - Monetary fields fix
from . import test_p0_afp_cap_2025
from . import test_p0_multi_company
from . import test_p0_reforma_2025
from . import test_ley21735_reforma_pensiones  # Corrección profesional Ley 21.735
from . import test_previred_integration
from . import test_payslip_validations

# GAP-001: Proporcionalidad Asignación Familiar (2025-11-09)
from . import test_asignacion_familiar_proporcional  # DFL 150 proporcionalidad

# GAP-002: Eliminar hardcoded AFP cap (2025-11-09)
from . import test_gap002_legal_caps_integration  # HR-GAP-002: Legal caps integration

# GAP-003: Reforma Previsional 2025 - Gradualidad Aporte Empleador (2025-11-09)
from . import test_gap003_reforma_gradual  # Reforma Ley 21.735 - Gradualidad 1.0%-8.5%

# P1 FIXES: Cierre Brechas Sprint 1 (2025-11-11)
from . import test_sis_rate_fix  # HIGH-004: Corrección SIS 1.53% → 1.57%

# Existing tests
from . import test_naming_integrity
from . import test_tax_brackets
from . import test_apv_calculation
from . import test_indicator_automation
from . import test_sopa_categories
from . import test_payslip_totals
from . import test_calculations_sprint32
from . import test_payroll_calculation_p1
from . import test_lre_generation
