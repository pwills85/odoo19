# -*- coding: utf-8 -*-

from odoo import models, fields, api
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
    # NOTA IMPORTANTE: Campo l10n_cl_activity_description (Giro)
    # ═══════════════════════════════════════════════════════════
    # Este campo YA está definido en el módulo oficial l10n_cl como:
    #   l10n_cl_activity_description = fields.Char(
    #       related='partner_id.l10n_cl_activity_description',
    #       readonly=False
    #   )
    #
    # NO redefinimos este campo aquí para respetar la arquitectura
    # del módulo base y evitar conflictos de herencia.
    #
    # El campo se usa en XML DTE como <GiroEmis> (OBLIGATORIO).
    # Almacenamiento: res.partner (Single Source of Truth)
    # ═══════════════════════════════════════════════════════════

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

    l10n_cl_activity_ids = fields.Many2many(
        comodel_name='sii.activity.code',
        relation='res_company_sii_activity_rel',
        column1='company_id',
        column2='activity_id',
        string='Actividades Económicas',
        help='Códigos de Actividad Económica SII (CIIU Rev. 4 CL 2012).\n\n'
             'IMPORTANTE:\n'
             '• Una empresa puede tener MÚLTIPLES actividades económicas\n'
             '• Al menos UNA actividad es OBLIGATORIA para emisión de DTEs\n'
             '• La primera actividad se usa en XML DTE (elemento <Acteco>)\n\n'
             'Ejemplos:\n'
             '  421000 - Construcción de carreteras y líneas de ferrocarril\n'
             '  433000 - Terminación y acabado de edificios\n'
             '  620100 - Actividades de programación informática\n\n'
             'Ver catálogo completo:\n'
             'https://www.sii.cl/destacados/codigos_actividades/'
    )

    l10n_cl_activity_code = fields.Char(
        string='Código Actividad Principal (DEPRECADO)',
        size=6,
        compute='_compute_activity_code',
        store=False,
        help='Campo DEPRECADO: Ahora use l10n_cl_activity_ids (selección múltiple).\n\n'
             'Este campo existe solo por compatibilidad con código legacy.\n'
             'Retorna el código de la primera actividad seleccionada.'
    )

    @api.depends('l10n_cl_activity_ids')
    def _compute_activity_code(self):
        """Campo legacy: retorna código de primera actividad"""
        for company in self:
            if company.l10n_cl_activity_ids:
                company.l10n_cl_activity_code = company.l10n_cl_activity_ids[0].code
            else:
                company.l10n_cl_activity_code = False

    # ═══════════════════════════════════════════════════════════
    # UBICACIÓN TRIBUTARIA (Related fields from partner_id)
    # Expone datos de ubicación del partner para uso en DTEs
    # ═══════════════════════════════════════════════════════════

    l10n_cl_state_id = fields.Many2one(
        related='partner_id.state_id',
        string='Región',
        readonly=False,  # ✅ Editable: se sincroniza automáticamente con partner
        store=False,
        help='Región donde opera la empresa (campo relacionado desde partner).\n\n'
             'IMPORTANTE:\n'
             '• Se usa en XML DTE como región de origen\n'
             '• Los cambios aquí se sincronizan automáticamente con el partner\n'
             '• Campo editable directamente desde la ficha de la empresa'
    )

    l10n_cl_comuna_id = fields.Many2one(
        related='partner_id.l10n_cl_comuna_id',
        string='Comuna SII',
        readonly=False,  # ✅ Editable: se sincroniza automáticamente con partner
        store=False,
        help='Comuna según catálogo oficial SII (campo relacionado desde partner).\n\n'
             'IMPORTANTE:\n'
             '• Campo <CmnaOrigen> en XML DTE (OBLIGATORIO)\n'
             '• Código oficial del catálogo 347 comunas SII\n'
             '• Los cambios aquí se sincronizan automáticamente con el partner\n'
             '• Las comunas se filtran automáticamente según la región seleccionada'
    )

    l10n_cl_city = fields.Char(
        related='partner_id.city',
        string='Ciudad',
        readonly=False,  # ✅ Editable: se sincroniza automáticamente con partner
        store=False,
        help='Ciudad donde opera la empresa (campo relacionado desde partner).\n\n'
             'Los cambios aquí se sincronizan automáticamente con el partner.\n'
             'Campo editable directamente desde la ficha de la empresa.'
    )

    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════

    @api.constrains('l10n_cl_activity_ids')
    def _check_activity_ids(self):
        """Validar que al menos una actividad económica esté seleccionada"""
        for company in self:
            # OPCIONAL: Comentar esta validación si se permite empresa sin actividad
            # (útil durante setup inicial)
            if not company.l10n_cl_activity_ids:
                _logger.warning(
                    f'Compañía "{company.name}" no tiene actividades económicas configuradas. '
                    f'Requerido para emisión de DTEs.'
                )
                # Descomentar para hacer OBLIGATORIO:
                # raise ValidationError(
                #     'Debe seleccionar al menos una Actividad Económica.\n\n'
                #     'Es OBLIGATORIO para emisión de DTEs según normativa SII.'
                # )

    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN BHE (Boleta Honorarios Electrónica)
    # Según SII - Res. Ex. N° 34 del 2019
    # ═══════════════════════════════════════════════════════════

    l10n_cl_bhe_journal_id = fields.Many2one(
        'account.journal',
        string='Diario BHE',
        domain="[('type', '=', 'general'), ('company_id', '=', id)]",
        help='Diario contable para registrar BHE recibidas.\n\n'
             'Recomendado: Crear diario específico "BHE" tipo General.\n'
             'Ejemplo: Código "BHE", Nombre "Boletas de Honorarios"'
    )

    l10n_cl_bhe_expense_account_id = fields.Many2one(
        'account.account',
        string='Cuenta Gasto Honorarios',
        domain="[('account_type', 'in', ['expense', 'expense_depreciation']), ('company_id', '=', id)]",
        help='Cuenta contable para registrar el gasto de honorarios.\n\n'
             'Plan de cuentas chileno:\n'
             '  6301010 - Honorarios por Servicios Profesionales\n\n'
             'Débito: Esta cuenta (monto bruto)'
    )

    l10n_cl_bhe_retention_account_id = fields.Many2one(
        'account.account',
        string='Cuenta Retención Honorarios',
        domain="[('account_type', '=', 'liability_current'), ('company_id', '=', id)]",
        help='Cuenta contable para registrar la retención de honorarios.\n\n'
             'Plan de cuentas chileno:\n'
             '  2105020 - Retención Honorarios (Impuesto a la Renta Art. 42 N°2)\n\n'
             'Crédito: Esta cuenta (monto retención 14.5%)\n\n'
             'IMPORTANTE:\n'
             '• Se declara mensualmente en F29 línea 150\n'
             '• Se paga al SII al declarar F29\n'
             '• Tasa variable según año: 10% (2018-2020) a 14.5% (2025+)'
    )

    # ═══════════════════════════════════════════════════════════
    # NOTA: Validación RUT YA ESTÁ en l10n_cl
    # No duplicamos validaciones
    # ═══════════════════════════════════════════════════════════

