# -*- coding: utf-8 -*-
"""
EERGYGROUP DTE Customizations
==============================

Professional customizations for Chilean electronic invoicing (DTE)
tailored for EERGYGROUP operations.

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
"""

from . import models


def post_init_hook(env):
    """
    Post-installation hook.

    Executed after module installation to:
    1. Apply default company configuration
    2. Log installation

    Args:
        env: Odoo environment
    """
    # Apply default configuration to all companies
    companies = env['res.company'].search([])
    for company in companies:
        # Solo aplicar si no tiene configuración previa
        if not company.bank_name:
            company.write({
                'report_primary_color': '#E97300',
                'report_footer_websites': 'www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',
            })

    # Log installation
    env['ir.logging'].sudo().create({
        'name': 'l10n_cl_dte_eergygroup',
        'type': 'server',
        'level': 'INFO',
        'message': 'EERGYGROUP DTE module installed successfully',
        'path': __file__,
        'func': 'post_init_hook',
    })
