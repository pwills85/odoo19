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

    @api.constrains('code')
    def _check_code_unique(self):
        """Validar que el código sea único (migrado desde _sql_constraints en Odoo 19)"""
        for institution in self:
            if institution.code:
                existing = self.search_count([
                    ('code', '=', institution.code),
                    ('id', '!=', institution.id)
                ])
                if existing:
                    raise ValidationError(_('El código de la institución APV debe ser único'))
