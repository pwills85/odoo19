
# -*- coding: utf-8 -*-

from odoo import api, fields, models

class DynamicStatesMixin(models.AbstractModel):
    """Mixin para reemplazar 'states' con computed fields dinámicos"""

    _name = 'dynamic.states.mixin'
    _description = 'Dynamic States Alternative to deprecated states parameter'

    # Computed readonly field
    is_readonly = fields.Boolean(
        string='Is Readonly',
        compute='_compute_is_readonly',
        help="Computed field to replace states readonly logic"
    )

    # Computed required field
    is_required = fields.Boolean(
        string='Is Required',
        compute='_compute_is_required',
        help="Computed field to replace states required logic"
    )

    @api.depends('state')
    def _compute_is_readonly(self):
        """Override in each model to define readonly logic"""
        for record in self:
            # Default: readonly if not in draft state
            record.is_readonly = record.state != 'draft' if hasattr(record, 'state') else False

    @api.depends('state')
    def _compute_is_required(self):
        """Override in each model to define required logic"""
        for record in self:
            # Default: required if in confirmed state
            record.is_required = record.state == 'confirmed' if hasattr(record, 'state') else False

    def get_dynamic_attrs(self, field_name):
        """Get dynamic attributes for field based on state"""
        attrs = {}

        if hasattr(self, 'state'):
            # Common patterns
            if self.state == 'draft':
                attrs['readonly'] = False
            elif self.state in ['confirmed', 'done', 'posted']:
                attrs['readonly'] = True

            if self.state in ['confirmed', 'done']:
                attrs['required'] = True

        return attrs

    @api.model
    def fields_view_get(self, view_id=None, view_type='form', toolbar=False, submenu=False):
        """Override to inject dynamic attrs"""
        result = super().fields_view_get(view_id, view_type, toolbar, submenu)

        if view_type == 'form' and hasattr(self, 'state'):
            # Inject dynamic attrs into form view
            self._inject_dynamic_attrs(result)

        return result

    def _inject_dynamic_attrs(self, view_result):
        """Inject dynamic attributes into view"""
        try:
            import xml.etree.ElementTree as ET

            # Parse the view
            arch = ET.fromstring(view_result['arch'])

            # Find fields that need dynamic attrs
            for field_elem in arch.xpath('.//field'):
                field_name = field_elem.get('name')

                if field_name and field_name in self._fields:
                    # Add dynamic attrs based on state
                    attrs = self.get_dynamic_attrs(field_name)

                    if attrs:
                        attrs_str = str(attrs).replace("'", '"')
                        field_elem.set('attrs', attrs_str)

            # Convert back to string
            view_result['arch'] = ET.tostring(arch, encoding='unicode')

        except Exception as e:
            # If injection fails, continue without modification
            pass
