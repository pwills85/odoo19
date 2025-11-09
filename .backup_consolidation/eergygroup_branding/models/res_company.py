# -*- coding: utf-8 -*-
"""
res.company Extension - EERGYGROUP Branding
============================================

Extends res.company with EERGYGROUP specific branding fields.

This module contains ONLY aesthetic/branding fields:
- Colors (primary, secondary)
- Logos (header, footer)
- Footer text and websites

For functional fields (bank info, etc.), see l10n_cl_dte_enhanced module.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import re
import logging

_logger = logging.getLogger(__name__)


class ResCompany(models.Model):
    """
    Extension of res.company with EERGYGROUP branding fields.

    BRANDING ONLY - Functional fields are in l10n_cl_dte_enhanced.
    """
    _inherit = 'res.company'

    # ═══════════════════════════════════════════════════════════════════════
    # BRANDING FIELDS - EERGYGROUP VISUAL IDENTITY
    # ═══════════════════════════════════════════════════════════════════════

    report_primary_color = fields.Char(
        string='Primary Brand Color',
        default='#E97300',  # EERGYGROUP Orange
        help='Primary color for reports and documents (hex format: #RRGGBB). '
             'Default: #E97300 (EERGYGROUP orange).'
    )

    report_secondary_color = fields.Char(
        string='Secondary Brand Color',
        default='#1A1A1A',  # Dark gray
        help='Secondary color for reports and documents (hex format: #RRGGBB). '
             'Default: #1A1A1A (dark gray for text/headers).'
    )

    report_accent_color = fields.Char(
        string='Accent Color',
        default='#FF9933',  # Light orange
        help='Accent color for highlights and call-to-actions (hex format: #RRGGBB).'
    )

    report_footer_text = fields.Text(
        string='Report Footer Text',
        default='Gracias por Preferirnos',
        translate=True,
        help='Custom footer text displayed at the bottom of all PDF reports. '
             'Default: "Gracias por Preferirnos" (EERGYGROUP standard).'
    )

    report_footer_websites = fields.Char(
        string='Footer Websites',
        default='www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',
        help="Company websites displayed in footer (separated by ' | '). "
             "Maximum 5 websites. Default: EERGYGROUP websites."
    )

    # Logo variants for different contexts
    report_header_logo = fields.Binary(
        string='Report Header Logo',
        attachment=True,
        help='Logo displayed in PDF report headers. '
             'Recommended size: 200x80px (transparent PNG).'
    )

    report_footer_logo = fields.Binary(
        string='Report Footer Logo',
        attachment=True,
        help='Logo displayed in PDF report footers (optional). '
             'Recommended size: 150x60px (transparent PNG).'
    )

    report_watermark_logo = fields.Binary(
        string='Report Watermark',
        attachment=True,
        help='Watermark logo for PDF backgrounds (optional). '
             'Recommended: Light/transparent version of logo.'
    )

    # Typography
    report_font_family = fields.Char(
        string='Font Family',
        default='Helvetica, Arial, sans-serif',
        help='Font family for PDF reports. '
             'Default: Helvetica (professional, widely supported).'
    )

    # ═══════════════════════════════════════════════════════════════════════
    # CONSTRAINT METHODS - Branding Validation
    # ═══════════════════════════════════════════════════════════════════════

    @api.constrains('report_primary_color', 'report_secondary_color', 'report_accent_color')
    def _check_color_format(self):
        """
        Validate hex color format #RRGGBB.

        Ensures all colors are valid 6-digit hex codes.
        """
        for company in self:
            for field_name in ['report_primary_color', 'report_secondary_color', 'report_accent_color']:
                color = company[field_name]
                if color and not re.match(r'^#[0-9A-Fa-f]{6}$', color):
                    raise ValidationError(_(
                        "Color must be in hex format: #RRGGBB (e.g., #E97300). "
                        "Current value for %s: %s"
                    ) % (company._fields[field_name].string, color))

    @api.constrains('report_footer_websites')
    def _check_footer_websites(self):
        """
        Validate footer websites format.

        Rules:
        - Separated by ' | ' (space-pipe-space)
        - Maximum 5 websites
        - Each website min 5 characters
        """
        for company in self:
            if company.report_footer_websites:
                websites = [w.strip() for w in company.report_footer_websites.split('|')]

                # Check: maximum 5 websites
                if len(websites) > 5:
                    raise ValidationError(_(
                        "Footer websites: Maximum 5 websites allowed. "
                        "Current count: %d websites."
                    ) % len(websites))

                # Check: each website minimum length
                for website in websites:
                    if len(website) < 5:
                        raise ValidationError(_(
                            "Footer websites: Each website must be at least 5 characters. "
                            "Invalid website: '%s'"
                        ) % website)

    # ═══════════════════════════════════════════════════════════════════════
    # BUSINESS METHODS - Branding Utilities
    # ═══════════════════════════════════════════════════════════════════════

    def get_brand_colors(self):
        """
        Get EERGYGROUP brand colors as dict.

        Returns:
            dict: {
                'primary': '#E97300',
                'secondary': '#1A1A1A',
                'accent': '#FF9933',
            }
        """
        self.ensure_one()
        return {
            'primary': self.report_primary_color or '#E97300',
            'secondary': self.report_secondary_color or '#1A1A1A',
            'accent': self.report_accent_color or '#FF9933',
        }

    def action_reset_eergygroup_branding(self):
        """
        Reset all branding fields to EERGYGROUP defaults.

        Useful after customization to restore original EERGYGROUP identity.
        """
        self.ensure_one()
        self.write({
            'report_primary_color': '#E97300',
            'report_secondary_color': '#1A1A1A',
            'report_accent_color': '#FF9933',
            'report_footer_text': 'Gracias por Preferirnos',
            'report_footer_websites': 'www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',
            'report_font_family': 'Helvetica, Arial, sans-serif',
        })
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': _('EERGYGROUP branding restored to defaults.'),
                'type': 'success',
                'sticky': False,
            }
        }
