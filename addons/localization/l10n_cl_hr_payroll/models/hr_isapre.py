# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


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

    @api.constrains('code')
    def _check_code_unique(self):
        """Validar que el código sea único (migrado desde _sql_constraints en Odoo 19)"""
        for isapre in self:
            if isapre.code:
                existing = self.search_count([
                    ('code', '=', isapre.code),
                    ('id', '!=', isapre.id)
                ])
                if existing:
                    raise ValidationError(_('El código de la ISAPRE debe ser único'))
