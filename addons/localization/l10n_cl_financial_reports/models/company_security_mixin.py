# -*- coding: utf-8 -*-
"""
Company Security Mixin
Proporciona validación automática de seguridad multi-company
"""

from odoo import api, models
from odoo.exceptions import AccessError


class CompanySecurityMixin(models.AbstractModel):
    """Mixin para asegurar acceso correcto multi-company."""
    
    _name = 'company.security.mixin'
    _description = 'Company Security Mixin'
    
    @api.model
    def check_company_access(self, company_id=None):
        """Verifica que el usuario tenga acceso a la company."""
        if not company_id:
            company_id = self.env.company.id
            
        if company_id not in self.env.user.company_ids.ids:
            raise AccessError(
                "No tiene permisos para acceder a los datos de esta compañía."
            )
        return True
    
    @api.model
    def search(self, args, offset=0, limit=None, order=None, count=False):
        """Override search para filtrar por company automáticamente."""
        # Solo aplicar si el modelo tiene campo company_id
        if 'company_id' in self._fields:
            # Verificar si ya hay filtro de company
            has_company_filter = any(
                arg[0] == 'company_id' for arg in args if isinstance(arg, (list, tuple))
            )
            
            # Agregar filtro si no existe
            if not has_company_filter and not self.env.context.get('bypass_company_check'):
                args = [('company_id', 'in', self.env.companies.ids)] + list(args)
        
        if count:
            return super().search(args, offset=offset, limit=limit, order=order, count=count)
        else:
            return super().search(args, offset=offset, limit=limit, order=order)
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para asignar company automáticamente."""
        if 'company_id' in self._fields:
            for vals in vals_list:
                if 'company_id' not in vals:
                    vals['company_id'] = self.env.company.id
                else:
                    # Verificar acceso a la company especificada
                    self.check_company_access(vals['company_id'])
                    
        return super().create(vals_list)
    
    def write(self, vals):
        """Override write para verificar permisos de company."""
        if 'company_id' in vals:
            self.check_company_access(vals['company_id'])
            
        return super().write(vals)
