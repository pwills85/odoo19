# -*- coding: utf-8 -*-
{
    "name": "Chile - Base Localization Services",
    "version": "19.0.1.0.0",
    "category": "Localization/Chile",
    "summary": "Utilidades base para localización chilena (RUT)",
    "description": """
Chile - Base Localization Utilities
====================================

Módulo base que proporciona utilidades esenciales para la localización chilena:

**RUT Utilities:**
- format_rut(): Formatea RUT a XX.XXX.XXX-X
- validate_rut(): Valida dígito verificador
- clean_rut(): Limpia formato (solo números + K)

**Arquitectura:**
- AbstractModel (cl.utils) - Helper methods, sin persistencia
- Alto rendimiento (pure functions, sin I/O)
- Usado por: l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports

**Cache Strategy:**
Este módulo NO incluye cache service. Para caching:
- Odoo models: Use @tools.cache decorator (Odoo 19 CE nativo)
- Microservices: Use Redis directo (ver ai-service/utils/cache.py)
- Performance: Redis ~0.5-2ms vs PostgreSQL ~50-100ms
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
