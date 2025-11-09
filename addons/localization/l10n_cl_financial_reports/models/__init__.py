# -*- coding: utf-8 -*-

# Base models

# Core models - Registro de servicios y arquitectura modular
from . import core

# Services - Servicios de negocio y integración SII
from . import services

# Report models

# Imports automáticos generados por Claude Code
from . import base_financial_service
from . import company_security_mixin
from . import performance_optimization_mixins
from . import account_financial_bi_wizard
from . import account_move_line
from . import account_ratio_analysis
from . import account_report_extension
from . import account_report
from . import analytic_cost_benefit_report
from . import balance_eight_columns_report
from . import balance_eight_columns
# from . import budget_comparison_report  # DISABLED: Requires Enterprise account.budget.post model
from . import date_helper
from . import financial_dashboard_add_widget_wizard
from . import financial_dashboard_layout
from . import financial_dashboard_template
from . import financial_dashboard_widget
from . import financial_report_kpi
from . import financial_report_service_model
from . import financial_report_wizards
from . import general_ledger
from . import l10n_cl_f22_report
from . import l10n_cl_f22
from . import l10n_cl_f29_report
from . import l10n_cl_f29  # Base model MUST be imported before stack_integration
from . import l10n_cl_kpi_dashboard
from . import project_profitability_report  # MUST be before stack_integration (line 366 inherits from it)

# Stack Integration (Odoo 19 CE + Custom Modules) - AFTER base models
from . import stack_integration
from . import l10n_cl_kpi_alert
from . import performance_mixin
from . import l10n_cl_ppm
from . import multi_period_comparison
# from . import project_cashflow_report  # DISABLED: Requires sale module (sale.order.line)
from . import ratio_analysis_adaptor
from . import ratio_analysis_service_model
from . import ratio_prediction_ml
from . import res_config_settings
from . import resource_utilization_report
from . import tax_balance_report
from . import trial_balance
