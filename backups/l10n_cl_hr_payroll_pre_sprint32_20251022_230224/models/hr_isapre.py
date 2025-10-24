# -*- coding: utf-8 -*-

from odoo import models, fields


class HrIsapre(models.Model):
    """
    Instituciones de Salud Previsional (ISAPRE) Chile
    
    Modelo maestro con las ISAPREs vigentes en Chile.
    """
    _name = 'hr.isapre'
    _description = 'ISAPRE Chile'
    _order = 'name'
    
    name = fields.Char(
        string='Nombre ISAPRE',
        required=True,
        help='Nombre completo de la ISAPRE'
    )
    code = fields.Char(
        string='Código',
        required=True,
        help='Código único de la ISAPRE (para Previred)'
    )
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    _sql_constraints = [
        ('code_unique', 'UNIQUE(code)', 'El código de la ISAPRE debe ser único'),
    ]
