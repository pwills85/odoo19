# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class L10nClF22ConfigWizard(models.TransientModel):
    """
    Wizard para configuración inicial del F22 (Declaración Anual Renta).

    Permite al usuario mapear cuentas contables a las líneas principales del F22:
    - Cuenta de gasto impuesto primera categoría
    - Cuenta de impuesto por pagar

    La configuración se guarda en ir.config_parameter para uso posterior.
    """

    _name = 'l10n_cl_f22.config.wizard'
    _description = 'Wizard de Configuración F22'

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        help='Compañía para la cual se configura el F22'
    )

    cuenta_gasto_impuesto = fields.Many2one(
        'account.account',
        string='Cuenta Gasto Impuesto Primera Categoría',
        help='Cuenta contable para registrar el gasto de impuesto primera categoría (ej: 5105 - Impuesto a la Renta)',
        required=True
    )

    cuenta_impuesto_por_pagar = fields.Many2one(
        'account.account',
        string='Cuenta Impuesto por Pagar',
        help='Cuenta contable para el impuesto por pagar al SII (ej: 2103 - Impuesto Renta por Pagar)',
        required=True
    )

    # Dominios dinámicos (Odoo 19 compatible)
    cuenta_gasto_impuesto_domain = fields.Char(
        compute='_compute_account_domains',
        readonly=True,
        store=False
    )

    cuenta_impuesto_por_pagar_domain = fields.Char(
        compute='_compute_account_domains',
        readonly=True,
        store=False
    )

    @api.depends('company_id')
    def _compute_account_domains(self):
        """Computa los dominios dinámicos para las cuentas basándose en company_id"""
        for wizard in self:
            company_id = wizard.company_id.id if wizard.company_id else False

            wizard.cuenta_gasto_impuesto_domain = str([
                ('company_id', '=', company_id),
                ('account_type', 'in', ['expense', 'expense_direct_cost'])
            ]) if company_id else '[]'

            wizard.cuenta_impuesto_por_pagar_domain = str([
                ('company_id', '=', company_id),
                ('account_type', '=', 'liability_current')
            ]) if company_id else '[]'

    # ========== INFORMACIÓN ACTUAL ==========
    config_existente = fields.Boolean(
        string='¿Configuración Existente?',
        compute='_compute_config_existente',
        help='Indica si ya existe configuración previa para esta compañía'
    )

    cuenta_gasto_actual = fields.Char(
        string='Cuenta Gasto Actual',
        compute='_compute_config_existente',
        help='Cuenta de gasto configurada actualmente'
    )

    cuenta_impuesto_actual = fields.Char(
        string='Cuenta Impuesto Actual',
        compute='_compute_config_existente',
        help='Cuenta de impuesto por pagar configurada actualmente'
    )

    @api.depends('company_id')
    def _compute_config_existente(self):
        """Computa si existe configuración previa y muestra las cuentas actuales"""
        IrConfigParameter = self.env['ir.config_parameter'].sudo()

        for wizard in self:
            company_id = wizard.company_id.id

            # Claves de configuración con namespace por compañía
            key_gasto = f'l10n_cl_f22.cuenta_gasto_impuesto.{company_id}'
            key_impuesto = f'l10n_cl_f22.cuenta_impuesto_por_pagar.{company_id}'

            # Obtener configuración actual
            cuenta_gasto_id = IrConfigParameter.get_param(key_gasto)
            cuenta_impuesto_id = IrConfigParameter.get_param(key_impuesto)

            # Verificar si existe configuración
            wizard.config_existente = bool(cuenta_gasto_id or cuenta_impuesto_id)

            # Mostrar cuentas actuales
            if cuenta_gasto_id:
                cuenta = self.env['account.account'].sudo().browse(int(cuenta_gasto_id))
                wizard.cuenta_gasto_actual = f"{cuenta.code} - {cuenta.name}" if cuenta.exists() else 'No encontrada'
            else:
                wizard.cuenta_gasto_actual = 'No configurada'

            if cuenta_impuesto_id:
                cuenta = self.env['account.account'].sudo().browse(int(cuenta_impuesto_id))
                wizard.cuenta_impuesto_actual = f"{cuenta.code} - {cuenta.name}" if cuenta.exists() else 'No encontrada'
            else:
                wizard.cuenta_impuesto_actual = 'No configurada'

    @api.constrains('cuenta_gasto_impuesto', 'cuenta_impuesto_por_pagar')
    def _check_cuentas_diferentes(self):
        """Valida que las cuentas de gasto e impuesto por pagar sean diferentes"""
        for wizard in self:
            if wizard.cuenta_gasto_impuesto == wizard.cuenta_impuesto_por_pagar:
                raise ValidationError(
                    _('La cuenta de gasto y la cuenta de impuesto por pagar deben ser diferentes.\n\n'
                      'Por favor, seleccione cuentas contables distintas.')
                )

    @api.constrains('cuenta_gasto_impuesto', 'cuenta_impuesto_por_pagar', 'company_id')
    def _check_cuentas_compania(self):
        """Valida que las cuentas pertenezcan a la compañía seleccionada"""
        for wizard in self:
            if wizard.cuenta_gasto_impuesto.company_id != wizard.company_id:
                raise ValidationError(
                    _('La cuenta de gasto impuesto "%s" no pertenece a la compañía "%s".\n\n'
                      'Por favor, seleccione una cuenta de la compañía correcta.') %
                    (wizard.cuenta_gasto_impuesto.display_name, wizard.company_id.name)
                )

            if wizard.cuenta_impuesto_por_pagar.company_id != wizard.company_id:
                raise ValidationError(
                    _('La cuenta de impuesto por pagar "%s" no pertenece a la compañía "%s".\n\n'
                      'Por favor, seleccione una cuenta de la compañía correcta.') %
                    (wizard.cuenta_impuesto_por_pagar.display_name, wizard.company_id.name)
                )

    def action_apply_configuration(self):
        """
        Guarda la configuración del F22 en ir.config_parameter.

        Las claves utilizadas son:
        - l10n_cl_f22.cuenta_gasto_impuesto.<company_id>
        - l10n_cl_f22.cuenta_impuesto_por_pagar.<company_id>

        Returns:
            dict: Acción para cerrar el wizard y mostrar notificación
        """
        self.ensure_one()

        IrConfigParameter = self.env['ir.config_parameter'].sudo()
        company_id = self.company_id.id

        # Claves de configuración con namespace por compañía
        key_gasto = f'l10n_cl_f22.cuenta_gasto_impuesto.{company_id}'
        key_impuesto = f'l10n_cl_f22.cuenta_impuesto_por_pagar.{company_id}'

        # Guardar configuración
        IrConfigParameter.set_param(key_gasto, str(self.cuenta_gasto_impuesto.id))
        IrConfigParameter.set_param(key_impuesto, str(self.cuenta_impuesto_por_pagar.id))

        _logger.info(
            "Configuración F22 guardada para compañía %s: "
            "cuenta_gasto=%s, cuenta_impuesto=%s",
            self.company_id.name,
            self.cuenta_gasto_impuesto.display_name,
            self.cuenta_impuesto_por_pagar.display_name
        )

        # Retornar notificación de éxito
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Configuración Guardada'),
                'message': _(
                    'La configuración del F22 ha sido guardada exitosamente para %s.\n\n'
                    'Cuenta Gasto: %s\n'
                    'Cuenta Impuesto por Pagar: %s'
                ) % (
                    self.company_id.name,
                    self.cuenta_gasto_impuesto.display_name,
                    self.cuenta_impuesto_por_pagar.display_name
                ),
                'type': 'success',
                'sticky': False,
            }
        }

    def action_cancel(self):
        """Cierra el wizard sin guardar cambios"""
        return {'type': 'ir.actions.act_window_close'}

    @api.model
    def get_f22_config(self, company_id):
        """
        Método de utilidad para obtener la configuración F22 de una compañía.

        Args:
            company_id (int): ID de la compañía

        Returns:
            dict: Diccionario con las cuentas configuradas:
                  {'cuenta_gasto_impuesto': account.account, 'cuenta_impuesto_por_pagar': account.account}
                  o None si no hay configuración

        Example:
            >>> wizard_model = env['l10n_cl_f22.config.wizard']
            >>> config = wizard_model.get_f22_config(env.company.id)
            >>> if config:
            ...     print(config['cuenta_gasto_impuesto'].code)
        """
        IrConfigParameter = self.env['ir.config_parameter'].sudo()

        # Claves de configuración
        key_gasto = f'l10n_cl_f22.cuenta_gasto_impuesto.{company_id}'
        key_impuesto = f'l10n_cl_f22.cuenta_impuesto_por_pagar.{company_id}'

        # Obtener IDs de cuentas
        cuenta_gasto_id = IrConfigParameter.get_param(key_gasto)
        cuenta_impuesto_id = IrConfigParameter.get_param(key_impuesto)

        if not cuenta_gasto_id or not cuenta_impuesto_id:
            return None

        # Obtener registros de cuentas
        cuenta_gasto = self.env['account.account'].sudo().browse(int(cuenta_gasto_id))
        cuenta_impuesto = self.env['account.account'].sudo().browse(int(cuenta_impuesto_id))

        if not cuenta_gasto.exists() or not cuenta_impuesto.exists():
            _logger.warning(
                "Configuración F22 incompleta para compañía %s: "
                "cuentas no encontradas",
                company_id
            )
            return None

        return {
            'cuenta_gasto_impuesto': cuenta_gasto,
            'cuenta_impuesto_por_pagar': cuenta_impuesto,
        }
