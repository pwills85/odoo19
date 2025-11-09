# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


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

    @api.constrains('code')
    def _check_code_unique(self):
        """Validar que el código sea único (migrado desde _sql_constraints en Odoo 19)"""
        for apv in self:
            if apv.code:
                existing = self.search_count([
                    ('code', '=', apv.code),
                    ('id', '!=', apv.id)
                ])
                if existing:
                    raise ValidationError(_('El código de la institución APV debe ser único'))
