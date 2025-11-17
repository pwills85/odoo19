# -*- coding: utf-8 -*-

"""
Estructura Salarial Chile

Define las estructuras de nómina que agrupan reglas salariales.
Compatible 100% con Odoo 19 CE.
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class HrPayrollStructure(models.Model):
    """
    Estructura Salarial (Payroll Structure)
    
    Técnica Odoo 19 CE:
    - Model estándar con _name y _description
    - Relaciones Many2one/One2many
    - Validaciones con @api.constrains
    - Métodos compute con @api.depends
    """
    _name = 'hr.payroll.structure'
    _description = 'Estructura Salarial'
    _order = 'name'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        required=True,
        help='Nombre de la estructura salarial'
    )
    
    code = fields.Char(
        string='Código',
        required=True,
        help='Código único de la estructura'
    )
    
    active = fields.Boolean(
        default=True,
        help='Si está inactiva, no se puede usar en contratos'
    )
    
    note = fields.Text(
        string='Notas',
        help='Descripción o notas adicionales'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════
    
    parent_id = fields.Many2one(
        'hr.payroll.structure',
        string='Estructura Padre',
        help='Estructura padre (hereda reglas)'
    )
    
    children_ids = fields.One2many(
        'hr.payroll.structure',
        'parent_id',
        string='Estructuras Hijas'
    )
    
    rule_ids = fields.One2many(
        'hr.salary.rule',
        'struct_id',
        string='Reglas Salariales',
        help='Reglas de cálculo de esta estructura'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    rule_count = fields.Integer(
        string='Número de Reglas',
        compute='_compute_rule_count',
        store=True
    )
    
    @api.depends('rule_ids')
    def _compute_rule_count(self):
        """
        Contar reglas salariales
        
        Técnica Odoo 19 CE:
        - @api.depends para cache
        - len() para contar
        """
        for structure in self:
            structure.rule_count = len(structure.rule_ids)
    
    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('code')
    def _check_code_unique(self):
        """
        Validar código único
        
        Técnica Odoo 19 CE:
        - @api.constrains para validación
        - search_count para verificar duplicados
        """
        for structure in self:
            count = self.search_count([
                ('code', '=', structure.code),
                ('id', '!=', structure.id)
            ])
            if count > 0:
                raise ValidationError(_(
                    'Ya existe una estructura con el código "%s"'
                ) % structure.code)
    
    @api.constrains('parent_id')
    def _check_parent_recursion(self):
        """
        Validar recursión en jerarquía

        Técnica Odoo 19 CE:
        - _has_cycle() method (replaces deprecated _check_recursion)
        """
        if self._has_cycle():
            raise ValidationError(_(
                'No puede crear estructuras recursivas (padre → hijo → padre)'
            ))
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PÚBLICOS
    # ═══════════════════════════════════════════════════════════
    
    def get_all_rules(self):
        """
        Obtener todas las reglas (propias + heredadas)
        
        Técnica Odoo 19 CE:
        - Método público sin decorador
        - Itera con while para jerarquía
        - Retorna recordset
        """
        self.ensure_one()
        
        all_rules = self.rule_ids
        parent = self.parent_id
        
        # Subir por la jerarquía
        while parent:
            all_rules |= parent.rule_ids
            parent = parent.parent_id
        
        # Ordenar por sequence
        return all_rules.sorted('sequence')
    
    def action_view_rules(self):
        """
        Acción para ver reglas en vista tree
        
        Técnica Odoo 19 CE:
        - Retorna ir.actions.act_window dict
        - domain para filtrar
        """
        self.ensure_one()
        
        return {
            'name': _('Reglas Salariales'),
            'type': 'ir.actions.act_window',
            'res_model': 'hr.salary.rule',
            'view_mode': 'tree,form',
            'domain': [('struct_id', '=', self.id)],
            'context': {'default_struct_id': self.id},
        }
    
    # ═══════════════════════════════════════════════════════════
    # CRUD OVERRIDES
    # ═══════════════════════════════════════════════════════════
    
    @api.model
    def _name_search(self, name, args=None, operator='ilike', limit=100, name_get_uid=None):
        """
        Búsqueda por nombre o código
        
        Técnica Odoo 19 CE:
        - Override _name_search
        - Usa | (OR) en domain
        """
        args = args or []
        domain = []
        
        if name:
            domain = ['|', ('name', operator, name), ('code', operator, name)]
        
        return self._search(domain + args, limit=limit, access_rights_uid=name_get_uid)
