# -*- coding: utf-8 -*-
# Author: Damien Crier
# Author: Julien Coux
# Copyright 2016 Camptocamp SA
# Copyright 2020 ForgeFlow S.L. (https://www.forgeflow.com)
# Copyright 2021 Tecnativa - João Marques
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).
{
    "name": "Chile - Financial Reports",
    "version": "19.0.1.0.0",
    "category": "Localization/Chile",
    "summary": "Reportes financieros avanzados | Advanced financial reports",
    "description": """
Advanced Financial Reports for Chile - Enterprise Edition
========================================================

**OCA Compliant Module - Odoo 19 Native**

Complete financial reporting system designed specifically for Chilean companies,
featuring advanced analytics and executive dashboards with real-time KPIs.

Key Features
------------
* **Chilean Balance Sheet**: Adapted to SII standards and local accounting practices
* **Profit & Loss Statement**: Chilean chart of accounts classification
* **Executive Dashboard**: Interactive panel with real-time KPIs and Chart.js visualizations
* **Financial Ratios Analysis**: Liquidity, leverage, profitability and efficiency metrics
* **SII Integration**: Tax compliance tools and automated reporting
* **Advanced Export**: Professional Excel and PDF formats with custom templates

Dashboard Components
-------------------
* Customizable KPI indicators with trend analysis
* Interactive charts (Chart.js integration)
* Multi-period comparison capabilities
* Automated alerts and notifications
* 360° executive view with drill-down functionality
* Mobile-responsive design

Technical Architecture
---------------------
* **Native Odoo 19 Engine**: Leverages enhanced reporting framework (3x faster)
* **Service Layer Pattern**: Clean separation of business logic
* **Optimized Performance**: Efficient SQL queries with intelligent caching
* **REST API**: External system integration endpoints
* **Multi-company Support**: Complete support for business groups
* **OWL Framework**: Modern component architecture

Specialized Reports
------------------
* Projected cash flow analysis
* Project profitability analysis with EVM (Earned Value Management)
* Budget control and variance analysis
* Statement of changes in equity
* Notes to financial statements
* Resource utilization and capacity planning

Business Benefits
----------------
* Data-driven decision making with real-time insights
* Guaranteed regulatory compliance (SII standards)
* 80% reduction in report generation time
* Instant executive visibility with automated dashboards
* Early detection of financial deviations
* Professional presentation for stakeholders

Odoo 19 Optimizations
--------------------
* OWL Framework for modern UI components
* New asset management system
* Enhanced performance (3x faster backend, 2.7x faster frontend)
* Reinforced security with role-based access control
* PostgreSQL 15+ optimizations
* AI-ready architecture for future integrations

Support & Updates
----------------
Continuously evolving module with regular updates to maintain compatibility
with Chilean regulatory changes and new Odoo versions.

Installation
-----------
1. Install dependencies: account, date_range, report_xlsx, project, hr_timesheet
2. Update module list
3. Install 'Advanced Financial Reports Chile'
4. Configure company settings and chart of accounts
5. Access via Accounting > Reporting > Financial Reports

Configuration
------------
* Set up company fiscal information
* Configure chart of accounts mapping
* Define KPI thresholds and alerts
* Customize dashboard layout
* Set up automated report scheduling

Screenshots
----------
.. image:: static/description/images/dashboard_financial.svg
   :alt: Financial Dashboard
   :width: 100%

Technical Support
----------------
For technical support and customizations, contact EERGYGROUP.
    """,
    "author": "EERGYGROUP - Ing. Pedro Troncoso Willz",
    "website": "https://github.com/pwills85",
    "license": "AGPL-3",
    "category": "Accounting/Reporting",
    "maintainers": ["pwills85"],
    "support": "support@eergygroup.cl",
    "contributors": [
        "Damien Crier",
        "Julien Coux",
        "Camptocamp SA",
        "ForgeFlow S.L.",
        "Tecnativa - João Marques"
    ],
    "images": [
        "static/description/images/dashboard_financial.svg",
    ],
    # Dependencias organizadas por prioridad
    "depends": [
        # Core Odoo modules
        "account",
        "base",

        # Reporting modules
        "date_range",
        "report_xlsx",

        # Project management
        "project",
        "hr_timesheet",
        "account_budget",

        # Localization
        "l10n_cl_base",  # Chilean localization services
    ],
    "data": [
        # Security files first
        "security/security.xml",
        "security/ir.model.access.csv",
        "data/account_report_balance_sheet_cl_simple.xml",
        "data/account_report_profit_loss_cl_data.xml",
        "data/account_report_f29_cl_data.xml",
        "data/account_report_f22_cl_data.xml",  # F22 SII - Declaración Anual de Renta
        "data/financial_dashboard_widget_data.xml",
        "data/sample_dashboard_widgets.xml",  # Sample widget templates for dashboard
        "data/l10n_cl_tax_forms_cron.xml",  # Fixed: referencias corregidas a modelos F29 y F22

        # Views with actions and forms first
        "views/account_report_view.xml",
        "views/financial_report_kpi_view.xml",
        "views/project_profitability_views.xml",  # Corregido: HTML entities
        "views/resource_utilization_views.xml",  # Corregido: Vista válida
        "views/financial_report_service_views.xml",  # Corregido: Vista válida
        "views/ratio_analysis_service_views.xml",
        "views/analytic_cost_benefit_views.xml",
        "views/balance_eight_columns_views.xml",
        "views/general_ledger_views.xml",
        "views/tax_balance_report_views.xml",
        "views/trial_balance_views.xml",
        "views/multi_period_comparison_views.xml",
        "views/budget_comparison_views.xml",
        "views/ratio_prediction_ml_views.xml",
        "views/executive_dashboard_views.xml",
        "views/bi_dashboard_views.xml",
        "views/financial_dashboard_layout_views.xml",  # Dashboard management views

        # Wizard views - Now enabled with complete implementation
        "wizards/financial_dashboard_add_widget_wizard_view.xml",
        # Chilean Tax Forms
        "views/l10n_cl_f29_views.xml",
        "views/l10n_cl_f22_views.xml",
        "views/l10n_cl_tax_forms_menu.xml",
        "views/res_config_settings_views.xml",  # Fixed: XPath corregido para Odoo 18
        "views/res_config_settings_performance_views.xml",  # Fixed: Implementación completa con monitoreo

        # All menu items after views that define actions
        "views/menu_items.xml",
        "views/menu_items_sub.xml",  # Sub-menu items that reference parent menus
        "views/financial_services_menu.xml",
        "views/financial_dashboard_menu.xml",
        "views/analytic_report_menu.xml",
    ],
    'assets': {
        'web.assets_backend': [
            # GridStack library for draggable dashboard
            'l10n_cl_financial_reports/static/lib/gridstack/gridstack.min.css',
            'l10n_cl_financial_reports/static/lib/gridstack/gridstack-all.js',

            # New widget components
            'l10n_cl_financial_reports/static/src/components/widgets/chart_widget/chart_widget.scss',
            'l10n_cl_financial_reports/static/src/components/widgets/chart_widget/chart_widget.js',
            'l10n_cl_financial_reports/static/src/components/widgets/chart_widget/chart_widget.xml',
            'l10n_cl_financial_reports/static/src/components/widgets/table_widget/table_widget.scss',
            'l10n_cl_financial_reports/static/src/components/widgets/table_widget/table_widget.js',
            'l10n_cl_financial_reports/static/src/components/widgets/table_widget/table_widget.xml',
            'l10n_cl_financial_reports/static/src/components/widgets/gauge_widget/gauge_widget.scss',
            'l10n_cl_financial_reports/static/src/components/widgets/gauge_widget/gauge_widget.js',
            'l10n_cl_financial_reports/static/src/components/widgets/gauge_widget/gauge_widget.xml',

            # Filter Panel component
            'l10n_cl_financial_reports/static/src/components/filter_panel/filter_panel.scss',
            'l10n_cl_financial_reports/static/src/components/filter_panel/filter_panel.js',
            'l10n_cl_financial_reports/static/src/components/filter_panel/filter_panel.xml',

            # WebSocket service for real-time updates
            'l10n_cl_financial_reports/static/src/services/dashboard_websocket_service.js',

            # Lazy loading component
            'l10n_cl_financial_reports/static/src/components/lazy_widget_loader/lazy_widget_loader.scss',
            'l10n_cl_financial_reports/static/src/components/lazy_widget_loader/lazy_widget_loader.js',
            'l10n_cl_financial_reports/static/src/components/lazy_widget_loader/lazy_widget_loader.xml',

            # Mobile components
            'l10n_cl_financial_reports/static/src/components/mobile_dashboard_wrapper/mobile_dashboard_wrapper.scss',
            'l10n_cl_financial_reports/static/src/components/mobile_dashboard_wrapper/mobile_dashboard_wrapper.js',
            'l10n_cl_financial_reports/static/src/components/mobile_dashboard_wrapper/mobile_dashboard_wrapper.xml',
            'l10n_cl_financial_reports/static/src/components/mobile_filter_panel/mobile_filter_panel.scss',
            'l10n_cl_financial_reports/static/src/components/mobile_filter_panel/mobile_filter_panel.js',
            'l10n_cl_financial_reports/static/src/components/mobile_filter_panel/mobile_filter_panel.xml',

            # Mobile services
            'l10n_cl_financial_reports/static/src/services/touch_gesture_service.js',
            'l10n_cl_financial_reports/static/src/services/mobile_performance_service.js',

            # Responsive styles
            'l10n_cl_financial_reports/static/src/scss/responsive_widgets.scss',

            # Enhanced dashboard components
            'l10n_cl_financial_reports/static/src/components/financial_dashboard/financial_dashboard.scss',
            'l10n_cl_financial_reports/static/src/components/financial_dashboard/financial_dashboard.js',
            'l10n_cl_financial_reports/static/src/components/financial_dashboard/financial_dashboard.xml',

            # Executive dashboard
            'l10n_cl_financial_reports/static/src/js/executive_dashboard.js',

            # BI Dashboard
            'l10n_cl_financial_reports/static/src/js/bi_dashboard.js',
            'l10n_cl_financial_reports/static/src/xml/bi_dashboard.xml',

            # Existing components
            'l10n_cl_financial_reports/static/src/components/financial_report_viewer/financial_report_viewer.css',
            'l10n_cl_financial_reports/static/src/components/financial_report_viewer/financial_report_viewer.js',
            'l10n_cl_financial_reports/static/src/components/financial_report_viewer/financial_report_viewer.xml',
            'l10n_cl_financial_reports/static/src/components/ratio_dashboard/ratio_dashboard.css',
            'l10n_cl_financial_reports/static/src/components/ratio_dashboard/ratio_dashboard.js',
            'l10n_cl_financial_reports/static/src/components/ratio_dashboard/ratio_dashboard.xml',
        ],
    },
    "demo": [],
    "installable": True,
    "application": False,
    "auto_install": False,
    "post_init_hook": "post_init_hook",
    "uninstall_hook": "uninstall_hook",
    "external_dependencies": {
        "python": [
            "xlsxwriter",         # Excel report generation
            "python-dateutil",    # Date calculations with relativedelta
            "numpy",              # Numerical computations for ML
            "scikit-learn",       # Machine learning for ratio predictions
            "joblib",             # ML model serialization
            "PyJWT",              # JWT authentication for API (correct package name)
            # Removed: requests (imported but not actually used)
        ]
    }
}
