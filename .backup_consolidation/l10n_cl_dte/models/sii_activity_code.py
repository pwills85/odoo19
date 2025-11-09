# -*- coding: utf-8 -*-
"""
Modelo: sii.activity.code
Catálogo de Códigos de Actividad Económica SII (CIIU Rev. 4 CL)

Referencias:
- SII: https://www.sii.cl/destacados/codigos_actividades/
- CIIU Rev. 4 CL 2012 (Clasificación Industrial Internacional Uniforme)
"""
from odoo import api, fields, models
from odoo.exceptions import ValidationError


class SIIActivityCode(models.Model):
    """Catálogo de Códigos de Actividad Económica SII (Acteco)

    Según clasificación CIIU Rev. 4 CL 2012 del SII.
    Una empresa puede tener múltiples actividades económicas.
    """
    _name = 'sii.activity.code'
    _description = 'Código Actividad Económica SII (Acteco)'
    _order = 'code'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS
    # ═══════════════════════════════════════════════════════════

    code = fields.Char(
        string='Código',
        required=True,
        size=6,
        index=True,
        help='Código de 6 dígitos según CIIU Rev. 4 CL 2012'
    )

    name = fields.Char(
        string='Descripción',
        required=True,
        translate=False,
        help='Descripción oficial de la actividad económica según SII'
    )

    parent_id = fields.Many2one(
        comodel_name='sii.activity.code',
        string='Categoría Padre',
        ondelete='restrict',
        help='Categoría padre en jerarquía CIIU (Sección → División → Grupo → Clase)'
    )

    child_ids = fields.One2many(
        comodel_name='sii.activity.code',
        inverse_name='parent_id',
        string='Subcategorías'
    )

    active = fields.Boolean(
        default=True,
        help='Códigos inactivos son obsoletos o dados de baja por SII'
    )

    company_count = fields.Integer(
        string='Empresas',
        compute='_compute_company_count',
        help='Número de empresas con esta actividad'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends()  # Inverse relation - computed on-demand
    def _compute_company_count(self):
        """
        Contar empresas que usan esta actividad.

        US-1.4: Added @api.depends() for inverse relation counter.
        No dependencies tracked (computed from res.company pointing here).
        """
        for record in self:
            record.company_count = self.env['res.company'].search_count([
                ('l10n_cl_activity_ids', 'in', record.id)
            ])

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('code')
    def _check_code_format(self):
        """Validar formato código: 6 dígitos y unicidad"""
        for record in self:
            if record.code:
                code = record.code.strip()

                if not code.isdigit():
                    raise ValidationError(
                        f'Código "{code}" debe contener solo dígitos.\n'
                        f'Ejemplo: 421000'
                    )

                if len(code) != 6:
                    raise ValidationError(
                        f'Código "{code}" debe tener exactamente 6 dígitos.\n'
                        f'Ejemplo: 421000'
                    )

                # Validar unicidad
                duplicate = self.search([
                    ('code', '=', code),
                    ('id', '!=', record.id)
                ], limit=1)
                if duplicate:
                    raise ValidationError(
                        f'Código "{code}" ya existe.\n'
                        f'Cada código de actividad económica debe ser único.'
                    )

    # ═══════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════

    def name_get(self):
        """Personalizar cómo se muestra el registro: [421000] Construcción de carreteras"""
        result = []
        for record in self:
            if record.code and record.name:
                name = f"[{record.code}] {record.name}"
            else:
                name = record.name or record.code or f'ID {record.id}'
            result.append((record.id, name))
        return result

    @api.model
    def name_search(self, name='', args=None, operator='ilike', limit=100):
        """Búsqueda por código o descripción"""
        args = args or []

        if name:
            # Buscar por código o descripción
            records = self.search([
                '|',
                ('code', operator, name),
                ('name', operator, name)
            ] + args, limit=limit)
        else:
            records = self.search(args, limit=limit)

        return records.name_get()

    def action_view_companies(self):
        """Abrir lista de empresas con esta actividad"""
        self.ensure_one()

        return {
            'name': f'Empresas - {self.display_name}',
            'type': 'ir.actions.act_window',
            'res_model': 'res.company',
            'view_mode': 'tree,form',
            'domain': [('l10n_cl_activity_ids', 'in', self.id)],
            'context': {'default_l10n_cl_activity_ids': [(6, 0, [self.id])]},
        }
