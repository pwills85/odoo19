# -*- coding: utf-8 -*-
from odoo import models, fields, api

class AccountReport(models.Model):
    """Extensión básica para reportes chilenos"""
    _inherit = 'account.report'
    
    # Campos específicos para localización chilena
    is_chilean_report = fields.Boolean(
        string='Reporte Chileno',
        default=False,
        help='Indica si es un reporte específico para Chile'
    )
    
    sii_compliance = fields.Boolean(
        string='Cumplimiento SII',
        default=False,
        help='Indica si el reporte cumple con normativas SII'
    )
    
    @api.model
    def get_chilean_reports(self):
        """Obtener reportes específicos para Chile"""
        return self.search([('is_chilean_report', '=', True)])
