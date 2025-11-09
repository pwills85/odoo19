# -*- coding: utf-8 -*-

from odoo import models, fields, _
import logging

_logger = logging.getLogger(__name__)


class ResCompanyDTE(models.Model):
    """
    Extensión de res.company para configuración DTE
    
    ESTRATEGIA: EXTENDER res.company
    - l10n_cl YA provee: datos tributarios, actividad económica, RUT
    - SOLO agregamos campos específicos para DTE electrónico
    """
    _inherit = 'res.company'
    
    # ═══════════════════════════════════════════════════════════
    # NOTA: Campos que YA EXISTEN en l10n_cl (NO duplicar):
    # - l10n_cl_sii_taxpayer_type (tipo de contribuyente)
    # - l10n_cl_activity_description (giro/actividad)
    # - l10n_cl_activity_code (código actividad SII)
    # - vat (RUT, ya validado)
    # ═══════════════════════════════════════════════════════════
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS ESPECÍFICOS DTE ELECTRÓNICO
    # ═══════════════════════════════════════════════════════════
    
    dte_email = fields.Char(
        string='Email DTE',
        help='Email para notificaciones de DTEs electrónicos'
    )
    
    dte_resolution_number = fields.Char(
        string='Número Resolución SII',
        help='Número de resolución de autorización de DTEs del SII'
    )
    
    dte_resolution_date = fields.Date(
        string='Fecha Resolución DTE',
        help='Fecha de la resolución de autorización de DTEs'
    )
    
    # ═══════════════════════════════════════════════════════════
    # NOTA: Validación RUT YA ESTÁ en l10n_cl
    # No duplicamos validaciones
    # ═══════════════════════════════════════════════════════════

