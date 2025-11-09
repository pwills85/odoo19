# -*- coding: utf-8 -*-
"""
Modelo: l10n.cl.comuna
Catálogo Oficial de Comunas de Chile según SII

Referencias:
- SII Tabla Comunas: https://zeus.sii.cl/avalu_cgi/br/brch10.sh
- 345 comunas oficiales
- Códigos formato RRPPP (5 dígitos): Región + Provincia + Comuna
"""
from odoo import api, fields, models
from odoo.exceptions import ValidationError


class L10nClComuna(models.Model):
    """Catálogo Oficial de Comunas de Chile (SII)

    Según tabla oficial del Servicio de Impuestos Internos (SII).
    Cada comuna pertenece a una región y tiene un código único de 5 dígitos.
    """
    _name = 'l10n.cl.comuna'
    _description = 'Comuna de Chile'
    _order = 'code'
    _rec_name = 'name'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS
    # ═══════════════════════════════════════════════════════════

    code = fields.Char(
        string='Código SII',
        required=True,
        size=5,
        index=True,
        help='Código SII de 5 dígitos (formato RRPPP)\n'
             'Ejemplo: 09201 = Región 09 + Comuna 201 (Temuco)'
    )

    name = fields.Char(
        string='Comuna',
        required=True,
        index=True,
        translate=False,
        help='Nombre oficial de la comuna según SII'
    )

    treasury_code = fields.Char(
        string='Código Tesorería',
        size=3,
        index=True,
        help='Código de 3 dígitos usado por Tesorería General de la República'
    )

    state_id = fields.Many2one(
        comodel_name='res.country.state',
        string='Región',
        required=True,
        ondelete='restrict',
        domain="[('country_id.code', '=', 'CL')]",
        index=True,
        help='Región administrativa a la que pertenece la comuna'
    )

    active = fields.Boolean(
        default=True,
        help='Desactivar comunas obsoletas o dadas de baja'
    )

    partner_count = fields.Integer(
        string='Contactos',
        compute='_compute_partner_count',
        help='Número de contactos/empresas en esta comuna'
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends()  # Inverse relation - computed on-demand
    def _compute_partner_count(self):
        """
        Contar contactos que usan esta comuna.

        US-1.4: Added @api.depends() for inverse relation counter.
        No dependencies tracked (computed from res.partner pointing here).
        """
        for record in self:
            record.partner_count = self.env['res.partner'].search_count([
                ('l10n_cl_comuna_id', '=', record.id)
            ])

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('code')
    def _check_code_format(self):
        """Validar formato código: 5 dígitos y unicidad"""
        for record in self:
            if record.code:
                code = record.code.strip()

                # Validar que sea numérico
                if not code.isdigit():
                    raise ValidationError(
                        f'Código "{code}" debe contener solo dígitos.\n'
                        f'Formato: RRPPP (5 dígitos)\n'
                        f'Ejemplo: 09201 (Temuco)'
                    )

                # Validar longitud
                if len(code) != 5:
                    raise ValidationError(
                        f'Código "{code}" debe tener exactamente 5 dígitos.\n'
                        f'Formato: RRPPP\n'
                        f'Ejemplo: 09201 (Temuco)'
                    )

                # Validar unicidad
                duplicate = self.search([
                    ('code', '=', code),
                    ('id', '!=', record.id)
                ], limit=1)
                if duplicate:
                    raise ValidationError(
                        f'Código SII "{code}" ya existe en la comuna: {duplicate.name}.\n'
                        f'Cada código debe ser único.'
                    )

    @api.constrains('name', 'state_id')
    def _check_name_state_unique(self):
        """Validar que no haya comunas con mismo nombre en la misma región"""
        for record in self:
            if record.name and record.state_id:
                duplicate = self.search([
                    ('name', '=', record.name),
                    ('state_id', '=', record.state_id.id),
                    ('id', '!=', record.id)
                ], limit=1)
                if duplicate:
                    raise ValidationError(
                        f'Ya existe la comuna "{record.name}" en la región {record.state_id.name}.\n'
                        f'Código existente: {duplicate.code}'
                    )

    # ═══════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════

    def name_get(self):
        """Personalizar visualización: [09201] Temuco"""
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
        """Búsqueda inteligente por código o nombre"""
        args = args or []

        if name:
            # Buscar por código o nombre
            records = self.search([
                '|',
                ('code', operator, name),
                ('name', operator, name)
            ] + args, limit=limit)
        else:
            records = self.search(args, limit=limit)

        return records.name_get()

    def action_view_partners(self):
        """Abrir lista de contactos en esta comuna"""
        self.ensure_one()

        return {
            'name': f'Contactos en {self.name}',
            'type': 'ir.actions.act_window',
            'res_model': 'res.partner',
            'view_mode': 'tree,form',
            'domain': [('l10n_cl_comuna_id', '=', self.id)],
            'context': {
                'default_l10n_cl_comuna_id': self.id,
                'default_state_id': self.state_id.id,
            },
        }

    @api.model
    def get_comuna_by_code(self, code):
        """Helper: Obtener comuna por código SII

        Args:
            code (str): Código SII de 5 dígitos

        Returns:
            l10n.cl.comuna: Registro de la comuna o False
        """
        if not code:
            return False

        return self.search([('code', '=', str(code).strip())], limit=1)

    @api.model
    def get_comuna_by_name(self, name, state_id=None):
        """Helper: Obtener comuna por nombre

        Args:
            name (str): Nombre de la comuna
            state_id (int, optional): ID de la región para filtrar

        Returns:
            l10n.cl.comuna: Registro de la comuna o False
        """
        if not name:
            return False

        domain = [('name', 'ilike', name.strip())]
        if state_id:
            domain.append(('state_id', '=', state_id))

        return self.search(domain, limit=1)
