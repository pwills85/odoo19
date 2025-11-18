
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
    def get_view(self, view_id=None, view_type='form', **options):
        """
        Override get_view to inject dynamic attrs based on record state.
        
        This mixin replaces deprecated 'states' parameter in field definitions
        with computed fields (is_readonly, is_required) and dynamic view manipulation.
        
        Migrated from fields_view_get() (Odoo 19 CE compliance - 2025-11-17).
        
        Args:
            view_id (int|None): View ID to load (None = default view for view_type)
            view_type (str): Type of view ('form', 'tree', 'pivot', 'graph', 'search')
            **options (dict): Additional options
                - toolbar (bool): Include toolbar actions
                - submenu (bool): Include submenu actions
                - context (dict): Execution context
        
        Returns:
            dict: View definition with keys:
                - arch (str): XML architecture of the view
                - fields (dict): Field definitions
                - toolbar (dict): Available actions (if requested)
                - name (str): View name
                - type (str): View type
        
        Example:
            >>> model = env['account.balance.sheet']
            >>> view = model.get_view(view_type='form')
            >>> print(view.keys())
            dict_keys(['arch', 'fields', 'toolbar', 'name', 'type'])
        """
        # Call new Odoo 19 API (not deprecated fields_view_get)
        result = super().get_view(view_id, view_type, **options)

        # Inject dynamic attrs only for form views with state field
        if view_type == 'form' and hasattr(self, 'state'):
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

        except Exception:
            # If injection fails, continue without modification
            pass
