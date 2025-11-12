# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class HrAFP(models.Model):
    """
    Administradoras de Fondos de Pensiones (AFP) Chile
    
    Modelo maestro con las 10 AFPs vigentes en Chile.
    Tasas actualizadas según normativa 2025.
    """
    _name = 'hr.afp'
    _description = 'AFP Chile'
    _order = 'name'
    
    name = fields.Char(
        string='Nombre AFP',
        required=True,
        help='Nombre completo de la AFP'
    )
    code = fields.Char(
        string='Código',
        required=True,
        index=True,  # AUDIT A-1: Agregar índice para búsquedas frecuentes
        help='Código único de la AFP (para Previred)'
    )
    rate = fields.Float(
        string='Tasa AFP (%)',
        digits=(5, 4),
        required=True,
        help='Tasa de cotización AFP (10.49% - 11.54%)'
    )
    sis_rate = fields.Float(
        string='Tasa SIS (%)',
        digits=(5, 4),
        default=0.0157,
        help='Tasa Seguro de Invalidez y Sobrevivencia (1.57%)'
    )
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    _sql_constraints = [
        ('code_unique', 'UNIQUE(code)', 'El código de la AFP debe ser único'),
    ]
    
    @api.constrains('rate', 'sis_rate')
    def _check_rates(self):
        """Validar que las tasas estén en rangos válidos"""
        for afp in self:
            if afp.rate < 0 or afp.rate > 20:
                raise ValidationError(_('La tasa AFP debe estar entre 0% y 20%'))
            if afp.sis_rate < 0 or afp.sis_rate > 5:
                raise ValidationError(_('La tasa SIS debe estar entre 0% y 5%'))
    
    def name_get(self):
        """Mostrar nombre con tasa"""
        result = []
        for afp in self:
            name = f"{afp.name} ({afp.rate:.2f}%)"
            result.append((afp.id, name))
        return result
