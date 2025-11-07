# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class L10nClApvInstitution(models.Model):
    """
    Instituciones APV (Ahorro Previsional Voluntario) Chile
    
    Entidades autorizadas para recibir aportes de APV:
    - AFPs
    - Compañías de Seguros
    - Bancos
    - Administradoras de Fondos Mutuos
    
    Fuente: Superintendencia de Pensiones
    """
    _name = 'l10n_cl.apv.institution'
    _description = 'APV Institution Chile'
    _order = 'name'
    
    name = fields.Char(
        string='Institution Name',
        required=True,
        help='Nombre de la institución APV'
    )
    
    code = fields.Char(
        string='Code',
        required=True,
        help='Código oficial de la institución'
    )
    
    institution_type = fields.Selection([
        ('afp', 'AFP'),
        ('insurance', 'Compañía de Seguros'),
        ('bank', 'Banco'),
        ('mutual_fund', 'Administradora de Fondos Mutuos')
    ], string='Type', required=True, default='afp')
    
    active = fields.Boolean(
        string='Active',
        default=True
    )
    
    _sql_constraints = [
        ('code_unique', 'UNIQUE(code)', 'El código de la institución APV debe ser único'),
    ]
