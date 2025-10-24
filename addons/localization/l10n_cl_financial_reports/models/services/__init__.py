# -*- coding: utf-8 -*-
# Pure Python Services
from . import ratio_analysis_service_pure
from . import financial_report_service_pure

# Odoo-dependent Services (to be refactored)
from . import kpi_service
from . import dashboard_export_service
from . import financial_dashboard_service_optimized
from . import bi_dashboard_service
from . import executive_dashboard_service

# SII Integration Services - Real implementations
from . import financial_report_sii_service
