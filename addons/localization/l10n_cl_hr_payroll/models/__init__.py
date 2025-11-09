# -*- coding: utf-8 -*-

# Maestros (primero)
from . import hr_afp
from . import hr_isapre
from . import hr_apv
from . import l10n_cl_apv_institution
from . import l10n_cl_legal_caps
from . import hr_economic_indicators
from . import hr_tax_bracket
from . import hr_salary_rule_category
from . import hr_payroll_structure
from . import hr_salary_rule

# CE Compatibility (debe cargarse ANTES de hr_contract_cl)
from . import hr_contract_stub_ce  # CE stub - replaces hr_contract Enterprise dependency

# Modelos base extendidos
from . import hr_contract_cl

# Modelos principales
from . import hr_payslip
from . import hr_payslip_line
from . import hr_payslip_input
from . import hr_payslip_run

# Reglas salariales críticas (Sprint 4.1 - 2025-10-23)
from . import hr_salary_rule_gratificacion
from . import hr_salary_rule_asignacion_familiar
from . import hr_salary_rule_aportes_empleador
