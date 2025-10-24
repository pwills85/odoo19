# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
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
    # CAMPO ESPECÍFICO DTE: COMUNA
    # XSD SII: Campo OPCIONAL (minOccurs="0") pero RECOMENDADO
    # Para Santiago/Valparaíso: especificar comuna exacta
    # ═══════════════════════════════════════════════════════════

    l10n_cl_comuna = fields.Char(
        string='Comuna',
        help='Comuna chilena según DTE.\n\n'
             'IMPORTANTE para Santiago y Valparaíso:\n'
             '  - NO usar "Santiago" genérico → especificar comuna exacta\n'
             '  - Ejemplos: Santiago Centro, Las Condes, Providencia, etc.\n'
             '  - Para otras ciudades: usar nombre de ciudad\n\n'
             'Campo OPCIONAL en XML DTE pero RECOMENDADO para precisión.'
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS ADICIONALES SOLO PARA DTE
    # ═══════════════════════════════════════════════════════════

    @api.onchange('city')
    def _onchange_city_set_comuna(self):
        """Auto-fill comuna based on city for non-ambiguous cities"""
        if self.city and not self.l10n_cl_comuna:
            city_lower = self.city.lower()

            # Para ciudades únicas, auto-fill comuna
            # Santiago y Valparaíso se dejan en blanco para que usuario especifique comuna
            ambiguous_cities = ['santiago', 'valparaíso', 'valparaiso']

            if city_lower not in ambiguous_cities:
                self.l10n_cl_comuna = self.city
            else:
                # Para ciudades ambiguas, mostrar advertencia en log
                _logger.info(
                    f"Ciudad '{self.city}' requiere especificar comuna exacta. "
                    f"Por favor, complete el campo 'Comuna' manualmente."
                )
    
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

