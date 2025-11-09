# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class HrSalaryRuleCategory(models.Model):
    """
    Categoría de Regla Salarial - SOPA 2025
    
    Migrado desde Odoo 11 CE con técnicas Odoo 19 CE.
    Soporta jerarquía y flags para cálculos chilenos.
    """
    _name = 'hr.salary.rule.category'
    _description = 'Categoría de Concepto Salarial'
    _order = 'sequence, id'
    _parent_store = True
    _parent_name = 'parent_id'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        required=True,
        translate=True
    )
    
    code = fields.Char(
        string='Código',
        required=True,
        help='Código único de la categoría (ej: IMPO, NOIMPO, BASE_SOPA)'
    )
    
    sequence = fields.Integer(
        string='Secuencia',
        default=10,
        help='Orden de visualización y cálculo'
    )
    
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # JERARQUÍA (SOPA 2025) - Odoo 19 CE Style
    # ═══════════════════════════════════════════════════════════
    
    parent_id = fields.Many2one(
        'hr.salary.rule.category',
        string='Categoría Padre',
        ondelete='cascade',
        index=True,
        help='Categoría padre en la jerarquía'
    )
    
    parent_path = fields.Char(
        index=True,
        unaccent=False,
        help='Ruta completa en la jerarquía (auto-calculado por _parent_store)'
    )
    
    child_ids = fields.One2many(
        'hr.salary.rule.category',
        'parent_id',
        string='Sub-Categorías'
    )
    
    # ═══════════════════════════════════════════════════════════
    # FLAGS SOPA 2025 (CRÍTICOS PARA CHILE)
    # ═══════════════════════════════════════════════════════════
    
    tipo = fields.Selection(
        selection=[
            ('haber', 'Haber'),
            ('descuento', 'Descuento'),
            ('aporte', 'Aporte Empleador'),
            ('totalizador', 'Totalizador')
        ],
        string='Tipo',
        required=True,
        default='haber',
        help='Tipo de concepto para agrupación'
    )
    
    imponible = fields.Boolean(
        string='Imponible AFP/Salud',
        default=False,
        help='Si True, afecta cálculo de AFP y Salud (base imponible)'
    )
    
    tributable = fields.Boolean(
        string='Tributable Impuesto',
        default=False,
        help='Si True, afecta cálculo de Impuesto Único (base tributable)'
    )
    
    afecta_gratificacion = fields.Boolean(
        string='Afecta Gratificación',
        default=False,
        help='Si True, se considera para cálculo de gratificación legal'
    )
    
    signo = fields.Selection(
        selection=[
            ('positivo', 'Positivo (+)'),
            ('negativo', 'Negativo (-)')
        ],
        string='Signo',
        default='positivo',
        help='Signo del concepto en la liquidación'
    )
    
    # ═══════════════════════════════════════════════════════════
    # INFORMACIÓN ADICIONAL
    # ═══════════════════════════════════════════════════════════
    
    note = fields.Text(
        string='Descripción',
        help='Descripción detallada de la categoría'
    )
    
    color = fields.Integer(
        string='Color',
        help='Color para visualización en reportes'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════
    
    _sql_constraints = [
        ('code_unique', 'UNIQUE(code)', 'El código debe ser único'),
    ]
    
    @api.constrains('parent_id')
    def _check_parent_recursion(self):
        """Evitar recursión infinita en jerarquía - Odoo 19 CE"""
        if self._has_cycle():
            raise ValidationError(_(
                'Error: No puede crear una jerarquía recursiva de categorías.'
            ))
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS - Odoo 19 CE Style (sin @api.multi)
    # ═══════════════════════════════════════════════════════════
    
    def name_get(self):
        """Mostrar jerarquía en el nombre"""
        result = []
        for category in self:
            if category.parent_id:
                name = f"{category.parent_id.name} / {category.name}"
            else:
                name = category.name
            result.append((category.id, name))
        return result
    
    @api.model
    def _name_search(self, name, domain=None, operator='ilike', limit=None, order=None):
        """Búsqueda por código o nombre - Odoo 19 CE"""
        domain = domain or []
        if name:
            domain = [
                '|',
                ('code', operator, name),
                ('name', operator, name)
            ] + domain
        return self._search(domain, limit=limit, order=order)
