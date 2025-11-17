# -*- coding: utf-8 -*-

from odoo import models, fields


class AccountTaxDTE(models.Model):
    """
    Extensión de account.tax para códigos SII
    
    NOTA: l10n_cl ya provee configuración de impuestos Chile
    Solo agregamos campos específicos para DTEs electrónicos
    """
    _inherit = 'account.tax'
    
    # ═══════════════════════════════════════════════════════════
    # CÓDIGOS SII PARA DTEs
    # ═══════════════════════════════════════════════════════════
    
    sii_code = fields.Integer(
        string='Código SII',
        help='Código del impuesto según clasificación SII para DTEs'
    )
    
    sii_type = fields.Selection([
        ('1', 'IVA'),
        ('2', 'Impuesto Específico'),
        ('3', 'Impuesto Adicional'),
    ], string='Tipo Impuesto SII',
       help='Clasificación del impuesto según SII')

