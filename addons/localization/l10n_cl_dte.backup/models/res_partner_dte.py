# -*- coding: utf-8 -*-

from odoo import models, api, _
from odoo.exceptions import ValidationError
from odoo.addons.l10n_cl_dte.tools.rut_validator import validate_rut, format_rut
import logging

_logger = logging.getLogger(__name__)


class ResPartnerDTE(models.Model):
    """
    Extensión de res.partner para DTEs
    
    ESTRATEGIA: EXTENDER res.partner
    - l10n_cl YA provee: l10n_cl_sii_taxpayer_type, validación RUT
    - l10n_latam_base YA provee: l10n_latam_identification_type_id
    - SOLO agregamos campos específicos para DTE electrónico
    """
    _inherit = 'res.partner'
    
    # ═══════════════════════════════════════════════════════════
    # NOTA: Campos que YA EXISTEN en l10n_cl (NO duplicar):
    # - l10n_cl_sii_taxpayer_type (tipo de contribuyente)
    # - l10n_cl_activity_description (giro)
    # - vat (RUT, ya validado por l10n_latam_base + l10n_cl)
    # ═══════════════════════════════════════════════════════════
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS ADICIONALES SOLO PARA DTE
    # ═══════════════════════════════════════════════════════════
    
    def _format_rut_for_dte(self):
        """
        Retorna el RUT en formato para DTE (sin puntos, con guión).
        
        Returns:
            str: RUT en formato 12345678-9
        """
        self.ensure_one()
        
        if not self.vat:
            return ''
        
        # Remover puntos pero mantener guión
        rut = self.vat.replace('.', '').replace(' ', '')
        
        # Asegurar que tenga guión
        if '-' not in rut:
            # Si no tiene guión, agregarlo antes del último caracter
            rut = rut[:-1] + '-' + rut[-1]
        
        return rut.upper()
    
    # ═══════════════════════════════════════════════════════════
    # NOTA: Validación RUT YA ESTÁ en l10n_cl
    # Solo agregamos validación adicional si es necesaria para DTE
    # ═══════════════════════════════════════════════════════════

