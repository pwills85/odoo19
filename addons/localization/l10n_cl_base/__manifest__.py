# -*- coding: utf-8 -*-
{
    "name": "Chile - Base Localization Services",
    "version": "19.0.1.0.0",
    "category": "Localization/Chile",
    "summary": "Servicios base para localización chilena",
    "description": """
Chile - Base Localization Services
===================================

Módulo base que proporciona servicios comunes para la localización chilena:
- Cache service para optimización de consultas
- Utilidades comunes para módulos de localización
- Servicios compartidos entre módulos chilenos

Este módulo es requerido por:
- l10n_cl_dte (Facturación Electrónica)
- l10n_cl_hr_payroll (Nóminas Chile)
- l10n_cl_financial_reports (Reportes Financieros)
    """,
    "author": "EERGYGROUP - Ing. Pedro Troncoso Willz",
    "website": "https://github.com/pwills85",
    "license": "LGPL-3",
    "depends": [
        "base",
    ],
    "data": [],
    "installable": True,
    "application": False,
    "auto_install": False,
}
