# -*- coding: utf-8 -*-
"""
EERGYGROUP Corporate Branding
==============================

Visual identity and branding for EERGYGROUP SpA.

This module applies EERGYGROUP colors, logos, and visual identity
to all reports and documents.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

from . import models

import logging
_logger = logging.getLogger(__name__)


def post_init_hook(env):
    """
    Apply EERGYGROUP branding defaults to all companies.

    This ensures EERGYGROUP visual identity is applied automatically
    when the module is installed.

    Executed once after module installation.
    """
    _logger.info("╔══════════════════════════════════════════════════════════╗")
    _logger.info("║   EERGYGROUP Branding - Applying Defaults               ║")
    _logger.info("╚══════════════════════════════════════════════════════════╝")

    companies = env['res.company'].search([])

    for company in companies:
        # Only apply if not already configured (respect user customization)
        # Check if primary color is still default Odoo purple or not set
        if not company.report_primary_color or company.report_primary_color == '#875A7B':
            _logger.info(f"Applying EERGYGROUP branding to company: {company.name}")

            company.write({
                # EERGYGROUP Color Palette
                'report_primary_color': '#E97300',  # EERGYGROUP Orange
                'report_secondary_color': '#1A1A1A',  # Dark gray
                'report_accent_color': '#FF9933',  # Light orange

                # EERGYGROUP Footer
                'report_footer_text': 'Gracias por Preferirnos',
                'report_footer_websites': 'www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',

                # Typography
                'report_font_family': 'Helvetica, Arial, sans-serif',
            })

            _logger.info(f"✅ EERGYGROUP branding applied to: {company.name}")
        else:
            _logger.info(f"ℹ️  Skipping {company.name} (already customized)")

    _logger.info("✅ EERGYGROUP Branding defaults applied successfully.")
