# -*- coding: utf-8 -*-

from odoo import models, fields


class HrAPV(models.Model):
    """
    Ahorro Previsional Voluntario (APV) Chile
    
    Instituciones autorizadas para APV.
    """
    _name = 'hr.apv'
    _description = 'APV Chile'
    _order = 'name'
    
    name = fields.Char(
        string='Nombre Institución',
        required=True
    )
    code = fields.Char(
        string='Código',
        required=True
    )
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    _sql_constraints = [
        ('code_unique', 'UNIQUE(code)', 'El código de la institución APV debe ser único'),
    ]
