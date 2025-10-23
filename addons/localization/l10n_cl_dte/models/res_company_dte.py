# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class ResCompanyDTE(models.Model):
    """
    Extensión de res.company para configuración DTE
    
    ESTRATEGIA: EXTENDER res.company
    - l10n_cl YA provee: datos tributarios, actividad económica, RUT
    - SOLO agregamos campos específicos para DTE electrónico
    """
    _inherit = 'res.company'
    
    # ═══════════════════════════════════════════════════════════
    # NOTA: Campos que YA EXISTEN en l10n_cl (NO duplicar):
    # - l10n_cl_sii_taxpayer_type (tipo de contribuyente)
    # - l10n_cl_activity_description (giro/actividad)
    # - l10n_cl_activity_code (código actividad SII)
    # - vat (RUT, ya validado)
    # ═══════════════════════════════════════════════════════════
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS ESPECÍFICOS DTE ELECTRÓNICO
    # ═══════════════════════════════════════════════════════════
    
    dte_email = fields.Char(
        string='Email DTE',
        help='Email para notificaciones de DTEs electrónicos'
    )
    
    dte_resolution_number = fields.Char(
        string='Número Resolución SII',
        help='Número de resolución de autorización de DTEs del SII'
    )
    
    dte_resolution_date = fields.Date(
        string='Fecha Resolución DTE',
        help='Fecha de la resolución de autorización de DTEs'
    )

    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN PROYECTOS (EMPRESAS DE INGENIERÍA)
    # ═══════════════════════════════════════════════════════════

    dte_require_analytic_on_purchases = fields.Boolean(
        string='Requerir Proyecto en Compras',
        default=False,
        help='Si está activo, todas las líneas de compra deben tener proyecto asignado.\n\n'
             'Recomendado para:\n'
             '• Empresas de ingeniería\n'
             '• Empresas de construcción\n'
             '• Empresas de consultoría\n'
             '• Cualquier empresa que gestione proyectos de inversión\n\n'
             'Garantiza 100% trazabilidad de costos por proyecto.'
    )

    # ═══════════════════════════════════════════════════════════
    # CAMPO CRÍTICO SII: Código Actividad Económica (Acteco)
    # XSD SII: Campo OBLIGATORIO (minOccurs default=1)
    # Formato: 6 dígitos según clasificador CIIU4.CL 2012
    # ═══════════════════════════════════════════════════════════

    l10n_cl_activity_code = fields.Char(
        string='Código Actividad Económica (Acteco)',
        size=6,
        help='Código SII de 6 dígitos según clasificador CIIU4.CL 2012.\n'
             'Campo OBLIGATORIO en XML DTE (elemento <Acteco>).\n\n'
             'Ejemplos:\n'
             '  421000 - Construcción de carreteras y líneas de ferrocarril\n'
             '  433000 - Terminación y acabado de edificios\n'
             '  620100 - Actividades de programación informática\n\n'
             'Ver catálogo completo:\n'
             'https://www.sii.cl/destacados/codigos_actividades/'
    )

    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════

    @api.constrains('l10n_cl_activity_code')
    def _check_activity_code(self):
        """Validar código actividad según estándar SII"""
        for company in self:
            if company.l10n_cl_activity_code:
                code = company.l10n_cl_activity_code.strip()

                # Validar solo dígitos
                if not code.isdigit():
                    raise ValidationError(
                        'Código de actividad económica debe contener solo dígitos.\n'
                        'Ejemplo: 421000'
                    )

                # Validar longitud exacta 6 dígitos
                if len(code) != 6:
                    raise ValidationError(
                        'Código de actividad económica debe tener exactamente 6 dígitos.\n'
                        f'Recibido: {len(code)} dígitos'
                    )

                # Validar rango válido (100000-999999)
                code_int = int(code)
                if not (100000 <= code_int <= 999999):
                    raise ValidationError(
                        'Código de actividad económica debe estar entre 100000 y 999999.\n'
                        f'Recibido: {code_int}'
                    )

    # ═══════════════════════════════════════════════════════════
    # NOTA: Validación RUT YA ESTÁ en l10n_cl
    # No duplicamos validaciones
    # ═══════════════════════════════════════════════════════════

