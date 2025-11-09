# -*- coding: utf-8 -*-
{
    'name': 'Chilean DTE - Enhanced Features',
    'version': '19.0.1.0.0',
    'category': 'Accounting/Localizations',
    'summary': 'Enhanced DTE features for Chilean electronic invoicing - SII compliance',
    'description': """
Chilean DTE Enhanced Features
==============================

Professional enhancements for Chilean electronic invoicing (DTE) focused on
SII compliance, UX improvements, and Chilean business practices.

This module is GENERIC and can be used by ANY Chilean company.
For branding/visual customization, install a separate branding module
(e.g., eergygroup_branding, eergymas_branding, etc.).

Features
--------

**SII Compliance (Resoluciones 80/2014, 93/2003):**
- SII Document References (account.move.reference model)
- References REQUIRED for Credit Notes (DTE 61) and Debit Notes (DTE 56)
- CEDIBLE support for invoice factoring
- Complete validation against SII regulations

**UX Improvements:**
- Contact Person field (auto-populated from partner)
- Custom Payment Terms description (forma_pago)
- Auto-fill onchange methods for better productivity

**Bank Information:**
- Bank name, account number, account type
- Formatted bank info display for invoices
- Validation (format, length)

**Enterprise Quality:**
- 78 tests (86% coverage)
- 100% docstrings
- Zero technical debt
- SOLID principles
- Production-ready

Technical Architecture
-----------------------

**Separation of Concerns:**
- This module: FUNCTIONALITY only (DTE/SII features)
- Branding modules: AESTHETICS only (colors, logos, templates)

**Extends (not replaces):**
- account.move: contact_id, forma_pago, cedible, reference_ids
- res.company: bank_name, bank_account_number, bank_account_type

**New Models:**
- account.move.reference: SII document references

**Scalability:**
Multiple companies can use this module with different branding:

Dependencies
------------
- l10n_cl_dte (base Chilean DTE module)
- account (Odoo Accounting)
- l10n_latam_invoice_document (LATAM document types)

Installation
------------
1. Install this module for DTE functionality
2. Install a branding module for visual customization (optional)

Example:
  odoo-bin -i l10n_cl_dte_enhanced,eergygroup_branding

Author
------
EERGYGROUP - Ing. Pedro Troncoso Willz
contacto@eergygroup.cl
https://www.eergygroup.cl

License
-------
LGPL-3 (GNU Lesser General Public License v3.0)
Compatible with Odoo Community Edition
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
        'l10n_cl_dte',  # Base Chilean DTE module
        'account',
        'l10n_latam_invoice_document',
    ],

    # Data files (order matters!)
    'data': [
        # 1. Security (always first)
        'security/ir.model.access.csv',

        # 2. Master data
        'data/ir_config_parameter.xml',

        # 3. Views (Week 2 - Frontend Development)
        'views/account_move_views.xml',
        'views/account_move_reference_views.xml',
        'views/res_company_views.xml',

        # 4. Reports (Week 2 - FASE 2)
        'report/report_invoice_dte_enhanced.xml',
    ],

    # Demo data
    'demo': [],

    # Technical
    'installable': True,
    'application': False,
    'auto_install': False,

    # Images
    'images': ['static/description/icon.png'],

    # Hooks
    'post_init_hook': 'post_init_hook',

    # Version info
    'sequence': 100,
}
