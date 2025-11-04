# -*- coding: utf-8 -*-
{
    'name': 'EERGYGROUP - Corporate Branding',
    'version': '19.0.2.0.0',  # UPDATED: Now depends on l10n_cl_dte (consolidated module)
    'category': 'Customizations',
    'summary': 'EERGYGROUP SpA corporate visual identity and branding',
    'description': """
EERGYGROUP Corporate Branding
==============================

Complete visual customization for EERGYGROUP SpA corporate identity.

This module is SPECIFIC to EERGYGROUP SpA. It provides AESTHETICS only.
For DTE functionality, install l10n_cl_dte module (v19.0.6.0.0+).

Features
--------

**EERGYGROUP Colors:**
- Primary: #E97300 (EERGYGROUP Orange)
- Secondary: #1A1A1A (Dark gray for text/headers)
- Accent: #FF9933 (Light orange for highlights)

**Logos:**
- Header logo for PDF reports
- Footer logo (optional)
- Watermark for backgrounds (optional)

**Footer Branding:**
- Custom footer text: "Gracias por Preferirnos"
- Company websites: www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl

**Typography:**
- Font family: Helvetica, Arial, sans-serif (professional)

**PDF Templates:**
- Fully branded DTE invoices (Week 2)
- Custom QWeb report templates

**Backend UI:**
- Customized Odoo backend with EERGYGROUP colors (Week 2)
- CSS assets for consistent branding

Separation of Concerns
----------------------

This module follows enterprise architecture principles:

**eergygroup_branding (this module):**
- AESTHETICS: Colors, logos, templates
- SPECIFIC: EERGYGROUP SpA only

**l10n_cl_dte (base module v19.0.6.0.0+):**
- FUNCTIONALITY: DTE/SII features (consolidated)
- GENERIC: Reusable by any Chilean company

Other Companies in EERGYGROUP
------------------------------

For other companies in the group, create similar modules:

- **eergymas_branding**: EERGYMAS visual identity
  - Primary color: Different from EERGYGROUP
  - Different logos and websites
  - Same architecture

- **eergyhaus_branding**: EERGYHAUS visual identity
  - Primary color: Different from EERGYGROUP
  - Different logos and websites
  - Same architecture

Installation
------------

**Installation:**
```bash
# Base DTE functionality + EERGYGROUP branding
odoo-bin -i l10n_cl_dte,eergygroup_branding

# Note: l10n_cl_dte v19.0.6.0.0+ includes all enhanced features
```

Post-Install Hook
-----------------

On installation, EERGYGROUP defaults are automatically applied to all companies:
- Colors: #E97300 (primary), #1A1A1A (secondary)
- Footer: "Gracias por Preferirnos"
- Websites: EERGYGROUP group websites

Only applied if company doesn't have custom branding already.

Dependencies
------------

- **base** (Odoo core)
- **web** (for CSS/assets customization)
- **l10n_cl_dte** (for DTE functionality - v19.0.6.0.0+)

Author
------

EERGYGROUP - Ing. Pedro Troncoso Willz

- Email: contacto@eergygroup.cl
- Website: https://www.eergygroup.cl
- Phone: +56 9 XXXX XXXX

License
-------

LGPL-3 (GNU Lesser General Public License v3.0)

Compatible with Odoo Community Edition

Support
-------

- Email: contacto@eergygroup.cl
- Website: https://www.eergygroup.cl
- GitHub: https://github.com/eergygroup
    """,
    'author': 'EERGYGROUP',
    'maintainer': 'EERGYGROUP',
    'contributors': [
        'Ing. Pedro Troncoso Willz <contacto@eergygroup.cl>',
    ],
    'website': 'https://www.eergygroup.cl',
    'support': 'contacto@eergygroup.cl',
    'license': 'LGPL-3',

    # Dependencies
    'depends': [
        'base',
        'web',
        'l10n_cl_dte',  # Functional module (v19.0.6.0.0+ with consolidated enhanced features)
    ],

    # Data files
    'data': [
        'data/eergygroup_branding_defaults.xml',

        # Week 2: Views and Reports (FASE 2)
        # 'views/res_company_views.xml',
        'report/report_invoice_eergygroup.xml',
    ],

    # Assets (CSS/JS)
    'assets': {
        'web.assets_backend': [
            'eergygroup_branding/static/src/css/eergygroup_branding.css',
        ],
    },

    # Demo data
    'demo': [],

    # Technical
    'installable': True,
    'application': False,
    'auto_install': False,
    'post_init_hook': 'post_init_hook',

    # Images
    'images': ['static/description/icon.png'],

    # Version info
    'sequence': 200,  # Install after l10n_cl_dte
}
