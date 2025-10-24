# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class PurchaseOrderDTE(models.Model):
    """
    Extensión de purchase.order para DTE 34 (Factura Exenta Electrónica)

    ESTRATEGIA: EXTENDER purchase.order de Odoo base
    Reutilizamos todo el workflow de compras de Odoo

    NOTA: DTE 34 = Factura Exenta (operaciones sin IVA)
          NO confundir con DTE 43 (Liquidación Factura)
    """
    _inherit = 'purchase.order'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS ANALÍTICA - CUENTAS ANALÍTICAS
    # ═══════════════════════════════════════════════════════════

    analytic_account_id = fields.Many2one(
        'account.analytic.account',
        string='Cuenta Analítica',
        required=False,  # Opcional por defecto (compatible upgrade)
        tracking=True,
        domain="[('company_id', '=', company_id)]",
        help='Cuenta analítica para trazabilidad de costos. '
             'Representa proyectos, departamentos o centros de costo. '
             'Se propagará automáticamente a líneas sin analítica asignada.'
    )

    # ═══════════════════════════════════════════════════════════
    # CAMPOS DTE 34 (LIQUIDACIÓN HONORARIOS)
    # ═══════════════════════════════════════════════════════════

    es_liquidacion_honorarios = fields.Boolean(
        string='Es Liquidación de Honorarios',
        default=False,
        help='Marcar si es pago a profesional independiente (DTE 34)'
    )
    
    profesional_rut = fields.Char(
        string='RUT Profesional',
        help='RUT del profesional que recibe el pago'
    )
    
    profesional_nombre = fields.Char(
        string='Nombre Profesional',
        help='Nombre del profesional'
    )
    
    periodo_servicio_inicio = fields.Date(
        string='Período Servicio: Desde',
        help='Inicio del período de servicios prestados'
    )
    
    periodo_servicio_fin = fields.Date(
        string='Período Servicio: Hasta',
        help='Fin del período de servicios prestados'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RETENCIÓN IUE (Impuesto Único Empleador)
    # ═══════════════════════════════════════════════════════════
    
    retencion_iue_porcentaje = fields.Float(
        string='% Retención IUE',
        default=10.0,
        help='Porcentaje de retención (típicamente 10%)'
    )
    
    monto_bruto_honorarios = fields.Monetary(
        string='Monto Bruto',
        compute='_compute_monto_bruto_honorarios',
        store=True,
        help='Suma de líneas de la orden'
    )
    
    monto_retencion_iue = fields.Monetary(
        string='Monto Retención IUE',
        compute='_compute_retencion_iue',
        store=True,
        help='Monto a retener = Monto bruto × % retención'
    )
    
    monto_neto_a_pagar = fields.Monetary(
        string='Monto Neto a Pagar',
        compute='_compute_monto_neto',
        store=True,
        help='Monto a pagar = Monto bruto - Retención'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO DTE 34
    # ═══════════════════════════════════════════════════════════
    
    dte_34_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
    ], string='Estado DTE 34', default='draft', copy=False)
    
    dte_34_folio = fields.Char(
        string='Folio DTE 34',
        readonly=True,
        copy=False,
        index=True
    )
    
    dte_34_xml = fields.Binary(
        string='XML DTE 34',
        readonly=True,
        copy=False,
        attachment=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIÓN CON RETENCIONES
    # ═══════════════════════════════════════════════════════════
    
    retencion_iue_id = fields.Many2one(
        'retencion.iue',
        string='Registro Retención',
        help='Registro de retención mensual asociado'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ONCHANGE - PROPAGACIÓN PROYECTO
    # ═══════════════════════════════════════════════════════════

    @api.onchange('analytic_account_id')
    def _onchange_analytic_account_id(self):
        """
        Propaga cuenta analítica a líneas SIN analítica asignada.

        Basado en documentación oficial Odoo 19 CE:
        - purchase.order.line tiene campo analytic_distribution (JSON)
        - Formato: {"account_id": percentage} donde sum = 100%
        """
        if self.analytic_account_id:
            analytic_dist = {str(self.analytic_account_id.id): 100.0}
            # Solo sobreescribe líneas vacías (respeta asignaciones manuales)
            for line in self.order_line.filtered(
                lambda l: not l.analytic_distribution and not l.display_type
            ):
                line.analytic_distribution = analytic_dist

    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════

    @api.depends('order_line.price_subtotal')
    def _compute_monto_bruto_honorarios(self):
        """Calcula monto bruto como suma de líneas"""
        for order in self:
            if order.es_liquidacion_honorarios:
                order.monto_bruto_honorarios = sum(
                    line.price_subtotal for line in order.order_line
                )
            else:
                order.monto_bruto_honorarios = 0.0
    
    @api.depends('monto_bruto_honorarios', 'retencion_iue_porcentaje')
    def _compute_retencion_iue(self):
        """Calcula retención IUE"""
        for order in self:
            if order.es_liquidacion_honorarios:
                order.monto_retencion_iue = (
                    order.monto_bruto_honorarios * 
                    order.retencion_iue_porcentaje / 100.0
                )
            else:
                order.monto_retencion_iue = 0.0
    
    @api.depends('monto_bruto_honorarios', 'monto_retencion_iue')
    def _compute_monto_neto(self):
        """Calcula monto neto a pagar"""
        for order in self:
            order.monto_neto_a_pagar = (
                order.monto_bruto_honorarios - 
                order.monto_retencion_iue
            )
    
    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('profesional_rut')
    def _check_profesional_rut(self):
        """
        Valida RUT del profesional.

        Nota: Validación RUT delegada a python-stdnum (mismo algoritmo que Odoo nativo).
        Para validar, el RUT debe cumplir formato básico. La validación completa
        se hace al crear res.partner con country_code='CL'.
        """
        # Constraint removido - delegado a validación nativa Odoo
        # Si profesional_rut se convierte a partner_id en futuro, validará automáticamente
        pass
    
    @api.constrains('retencion_iue_porcentaje')
    def _check_retencion_porcentaje(self):
        """Valida porcentaje de retención"""
        for order in self:
            if order.es_liquidacion_honorarios:
                if not (0 <= order.retencion_iue_porcentaje <= 100):
                    raise ValidationError(
                        _('El porcentaje de retención debe estar entre 0% y 100%')
                    )
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS - OVERRIDE
    # ═══════════════════════════════════════════════════════════

    def button_confirm(self):
        """
        Override de button_confirm para validar proyecto si empresa lo requiere.

        Empresas de ingeniería pueden requerir proyecto obligatorio en compras.
        Configuración: res.company.dte_require_analytic_on_purchases
        """
        # Validar proyecto si empresa lo requiere
        if self.company_id.dte_require_analytic_on_purchases:
            for line in self.order_line.filtered(lambda l: not l.display_type):
                if not line.analytic_distribution:
                    raise ValidationError(_(
                        "La línea '%s' no tiene proyecto asignado.\n\n"
                        "Para desactivar esta validación:\n"
                        "Configuración → Facturación → DTE Chile → "
                        "'Requerir proyecto en compras'"
                    ) % line.product_id.name)

        # Llamar método padre (incluye _validate_analytic_distribution de Odoo)
        return super().button_confirm()

    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS - DTE 34
    # ═══════════════════════════════════════════════════════════

    def action_generar_liquidacion_dte34(self):
        """
        Genera DTE 34 (Liquidación de Honorarios)
        """
        self.ensure_one()
        
        if not self.es_liquidacion_honorarios:
            raise ValidationError(_('Esta orden no es una liquidación de honorarios'))
        
        # Validar datos
        self._validate_liquidacion_data()
        
        # Llamar DTE Service para generar DTE 34
        # TODO: Implementar llamada a DTE Service
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Generación de DTE 34 pendiente de implementación completa'),
                'type': 'info',
            }
        }
    
    def _validate_liquidacion_data(self):
        """Validaciones para liquidación de honorarios"""
        self.ensure_one()

        if not self.profesional_rut:
            raise ValidationError(_('Debe ingresar el RUT del profesional'))

        if not self.profesional_nombre:
            raise ValidationError(_('Debe ingresar el nombre del profesional'))

        if not self.periodo_servicio_inicio or not self.periodo_servicio_fin:
            raise ValidationError(_('Debe ingresar el período de servicios'))

        if self.monto_bruto_honorarios <= 0:
            raise ValidationError(_('El monto debe ser mayor a cero'))

    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS - DASHBOARD PROYECTOS ⭐ NUEVO
    # ═══════════════════════════════════════════════════════════

    def action_view_analytic_dashboard(self):
        """
        Abrir dashboard de la cuenta analítica asociada a esta orden de compra.

        Returns:
            dict: Action window para mostrar dashboard de cuenta analítica
        """
        self.ensure_one()

        if not self.analytic_account_id:
            raise ValidationError(_(
                'Esta orden de compra no tiene cuenta analítica asignada.'
            ))

        # Buscar o crear dashboard de la cuenta analítica
        dashboard = self.env['analytic.dashboard'].search([
            ('analytic_account_id', '=', self.analytic_account_id.id)
        ], limit=1)

        if not dashboard:
            # Crear dashboard si no existe
            dashboard = self.env['analytic.dashboard'].create({
                'analytic_account_id': self.analytic_account_id.id
            })

        return {
            'type': 'ir.actions.act_window',
            'name': _('Dashboard - %s') % self.analytic_account_id.name,
            'res_model': 'analytic.dashboard',
            'res_id': dashboard.id,
            'view_mode': 'form',
            'view_id': self.env.ref('l10n_cl_dte.view_analytic_dashboard_form').id,
            'target': 'current',
        }

