# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import logging

_logger = logging.getLogger(__name__)


class L10nClPpm(models.Model):
    """
    Pagos Provisionales Mensuales (PPM) - Art. 84 LIR
    Sistema automático para cálculo y control de PPM según normativa chilena

    🔗 REFERENCIAS TÉCNICAS:
    - Art. 84 Ley de Impuesto a la Renta (LIR)
    - Circular SII N° 55: Instrucciones PPM
    - Sprint 2 Requirements: PPM Implementation Completa

    CARACTERÍSTICAS PRINCIPALES:
    - Cálculo automático basado en renta líquida imponible año anterior
    - Tasa PPM: 0.25% sobre renta mensual (empresas Primera Categoría)
    - Integración automática con F29 mensual
    - Proyección anual y ajustes por variación de renta
    - Crédito fiscal aplicación automática contra F22
    - Manejo de excepciones: empresas nuevas, pérdidas tributarias
    """
    _name = 'l10n_cl.ppm'
    _description = 'Pagos Provisionales Mensuales - Art. 84 LIR'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _rec_name = 'display_name'
    _order = 'fiscal_year desc, period desc, id desc'

    # ========== CAMPOS DE IDENTIFICACIÓN ==========
    display_name = fields.Char(
        string='Nombre',
        compute='_compute_display_name',
        store=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        readonly=lambda self: self.state != 'draft'
    )

    fiscal_year = fields.Integer(
        string='Año Tributario',
        required=True,
        help='Año para el cual se calculan los PPM',
        readonly=lambda self: self.state != 'draft'
    )

    period = fields.Integer(
        string='Mes',
        required=True,
        help='Mes del PPM (1-12)',
        readonly=lambda self: self.state != 'draft'
    )

    period_date = fields.Date(
        string='Fecha Período',
        compute='_compute_period_date',
        store=True,
        help='Primer día del mes para el PPM'
    )

    # ========== CONFIGURACIÓN BASE ==========
    base_year = fields.Integer(
        string='Año Base',
        compute='_compute_base_year',
        store=True,
        help='Año de la renta base para el cálculo (fiscal_year - 1)'
    )

    renta_liquida_base = fields.Monetary(
        string='Renta Líquida Base (Año Anterior)',
        currency_field='currency_id',
        readonly=True,
        tracking=True,
        help='Renta líquida imponible del año anterior'
    )

    renta_mensual_base = fields.Monetary(
        string='Renta Mensual Base',
        compute='_compute_monthly_amounts',
        store=True,
        currency_field='currency_id',
        help='Renta líquida base / 12'
    )

    # ========== CÁLCULO PPM ==========
    ppm_rate = fields.Float(
        string='Tasa PPM (%)',
        default=0.25,
        help='Tasa de PPM según normativa (0.25%)',
        readonly=lambda self: self.state != 'draft'
    )

    ppm_amount_calculated = fields.Monetary(
        string='PPM Calculado',
        compute='_compute_monthly_amounts',
        store=True,
        currency_field='currency_id',
        help='PPM = Renta Mensual Base * Tasa PPM'
    )

    # ========== AJUSTES Y EXCEPCIONES ==========
    is_new_company = fields.Boolean(
        string='Empresa Nueva',
        help='Empresa sin renta año anterior',
        readonly=lambda self: self.state != 'draft'
    )

    has_previous_losses = fields.Boolean(
        string='Pérdidas Tributarias Anteriores',
        help='Empresa con pérdidas arrastrables',
        readonly=lambda self: self.state != 'draft'
    )

    is_suspended = fields.Boolean(
        string='PPM Suspendido',
        compute='_compute_suspension_status',
        store=True,
        help='PPM suspendido por empresa nueva o pérdidas'
    )

    manual_adjustment = fields.Monetary(
        string='Ajuste Manual',
        currency_field='currency_id',
        help='Ajuste manual al PPM calculado',
        readonly=lambda self: self.state != 'draft'
    )

    adjustment_reason = fields.Text(
        string='Motivo del Ajuste',
        readonly=lambda self: self.state != 'draft'
    )

    # ========== MONTOS FINALES ==========
    ppm_amount_final = fields.Monetary(
        string='PPM Final a Pagar',
        compute='_compute_final_amounts',
        store=True,
        currency_field='currency_id',
        tracking=True,
        help='PPM calculado + ajustes (o 0 si suspendido)'
    )

    accumulated_ppm = fields.Monetary(
        string='PPM Acumulado Año',
        compute='_compute_accumulated_amounts',
        store=True,
        currency_field='currency_id',
        help='PPM pagado acumulado en el año'
    )

    projected_annual_ppm = fields.Monetary(
        string='PPM Proyectado Anual',
        compute='_compute_projected_amounts',
        store=True,
        currency_field='currency_id',
        help='PPM total estimado para el año'
    )

    # ========== ESTADOS Y CONTROL ==========
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('calculated', 'Calculado'),
        ('validated', 'Validado'),
        # ('integrated_f29', 'Integrado F29'),  # TODO: Rehabilitar
        ('paid', 'Pagado'),
        ('suspended', 'Suspendido'),
        ('cancelled', 'Cancelado')
    ], string='Estado', default='draft', required=True, readonly=True,
       tracking=True, copy=False)

    # ========== INTEGRACIÓN F29 (DESHABILITADO TEMPORALMENTE) ==========
    # TODO: Rehabilitar después de instalar módulos base
    # f29_id = fields.Many2one(
    #     'l10n_cl.f29',
    #     string='F29 Asociado',
    #     readonly=True,
    #     copy=False,
    #     help='F29 donde se incluye este PPM'
    # )

    # auto_integrate_f29 = fields.Boolean(
    #     string='Integración Automática F29',
    #     default=True,
    #     readonly=lambda self: self.state != 'draft',
    #     help='Integrar automáticamente con F29 mensual'
    # )

    # ========== ASIENTOS CONTABLES ==========
    provision_move_id = fields.Many2one(
        'account.move',
        string='Asiento Provisión PPM',
        readonly=True,
        copy=False,
        help='Asiento contable de provisión del PPM'
    )

    payment_move_id = fields.Many2one(
        'account.move',
        string='Asiento Pago PPM',
        readonly=True,
        copy=False,
        help='Asiento contable del pago del PPM'
    )

    # ========== CAMPOS TÉCNICOS ==========
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        store=True,
        readonly=True
    )

    # ========== CAMPOS COMPUTADOS ==========
    @api.depends('company_id', 'fiscal_year', 'period')
    def _compute_display_name(self):
        """Genera nombre descriptivo del PPM"""
        for record in self:
            if record.company_id and record.fiscal_year and record.period:
                month_name = fields.Date(record.fiscal_year, record.period, 1).strftime('%B')
                record.display_name = f"PPM {record.company_id.name} - {month_name} {record.fiscal_year}"
            else:
                record.display_name = "PPM Borrador"

    @api.depends('fiscal_year', 'period')
    def _compute_period_date(self):
        """Calcula fecha del período"""
        for record in self:
            if record.fiscal_year and record.period:
                try:
                    record.period_date = fields.Date(record.fiscal_year, record.period, 1)
                except ValueError:
                    record.period_date = False
            else:
                record.period_date = False

    @api.depends('fiscal_year')
    def _compute_base_year(self):
        """Calcula año base para renta líquida"""
        for record in self:
            record.base_year = record.fiscal_year - 1 if record.fiscal_year else False

    @api.depends('renta_liquida_base', 'ppm_rate')
    def _compute_monthly_amounts(self):
        """Calcula montos mensuales base y PPM"""
        for record in self:
            if record.renta_liquida_base and record.renta_liquida_base > 0:
                record.renta_mensual_base = record.renta_liquida_base / 12
                record.ppm_amount_calculated = record.renta_mensual_base * (record.ppm_rate / 100)
            else:
                record.renta_mensual_base = 0.0
                record.ppm_amount_calculated = 0.0

    @api.depends('is_new_company', 'has_previous_losses', 'renta_liquida_base')
    def _compute_suspension_status(self):
        """Determina si el PPM debe ser suspendido"""
        for record in self:
            record.is_suspended = (
                record.is_new_company or
                record.has_previous_losses or
                record.renta_liquida_base <= 0
            )

    @api.depends('ppm_amount_calculated', 'manual_adjustment', 'is_suspended')
    def _compute_final_amounts(self):
        """Calcula monto final del PPM"""
        for record in self:
            if record.is_suspended:
                record.ppm_amount_final = 0.0
            else:
                record.ppm_amount_final = record.ppm_amount_calculated + record.manual_adjustment

    @api.depends('company_id', 'fiscal_year', 'period')
    def _compute_accumulated_amounts(self):
        """Calcula PPM acumulado en el año"""
        for record in self:
            if record.company_id and record.fiscal_year and record.period:
                # Buscar todos los PPM del año hasta el mes actual
                domain = [
                    ('company_id', '=', record.company_id.id),
                    ('fiscal_year', '=', record.fiscal_year),
                    ('period', '<=', record.period),
                    ('state', 'in', ['validated', 'integrated_f29', 'paid']),
                    ('id', '!=', record.id)  # Excluir el registro actual
                ]
                previous_ppms = self.search(domain)
                record.accumulated_ppm = sum(previous_ppms.mapped('ppm_amount_final'))
            else:
                record.accumulated_ppm = 0.0

    @api.depends('ppm_amount_final')
    def _compute_projected_amounts(self):
        """Calcula PPM proyectado anual"""
        for record in self:
            record.projected_annual_ppm = record.ppm_amount_final * 12

    # ========== CONSTRAINTS ==========
    @api.constrains('fiscal_year', 'period', 'company_id')
    def _check_unique_period(self):
        """Verifica que no exista otro PPM para el mismo período"""
        for record in self:
            domain = [
                ('company_id', '=', record.company_id.id),
                ('fiscal_year', '=', record.fiscal_year),
                ('period', '=', record.period),
                ('id', '!=', record.id),
                ('state', '!=', 'cancelled')
            ]
            if self.search_count(domain) > 0:
                raise ValidationError(
                    _('Ya existe un PPM para %s/%s en esta compañía') %
                    (record.period, record.fiscal_year)
                )

    @api.constrains('period')
    def _check_period_range(self):
        """Verifica que el período esté en rango válido"""
        for record in self:
            if record.period and not (1 <= record.period <= 12):
                raise ValidationError(_('El período debe estar entre 1 y 12'))

    @api.constrains('ppm_rate')
    def _check_ppm_rate(self):
        """Verifica que la tasa PPM sea válida"""
        for record in self:
            if record.ppm_rate and (record.ppm_rate < 0 or record.ppm_rate > 100):
                raise ValidationError(_('La tasa PPM debe estar entre 0% y 100%'))

    # ========== BUSINESS METHODS ==========
    def action_calculate_base_income(self):
        """
        Calcula la renta líquida base desde el F22 del año anterior
        """
        self.ensure_one()

        if self.state not in ['draft']:
            raise UserError(_('Solo se puede calcular la renta base en estado Borrador'))

        # Buscar F22 del año base
        f22_base = self.env['l10n_cl.f22'].search([
            ('company_id', '=', self.company_id.id),
            ('fiscal_year', '=', self.base_year),
            ('state', 'in', ['validated', 'sent', 'accepted'])
        ], limit=1)

        if f22_base:
            self.write({
                'renta_liquida_base': f22_base.renta_liquida_imponible,
                'is_new_company': False,
            })

            self.message_post(
                body=_('Renta base calculada desde F22 %s: %s %s') %
                     (self.base_year, f22_base.renta_liquida_imponible, self.currency_id.symbol),
                message_type='notification'
            )
        else:
            # Empresa nueva o sin F22 anterior
            self.write({
                'renta_liquida_base': 0.0,
                'is_new_company': True,
            })

            self.message_post(
                body=_('No se encontró F22 para el año %s. Marcado como empresa nueva.') % self.base_year,
                message_type='notification'
            )

    def action_calculate_ppm(self):
        """
        Calcula el PPM basado en la renta líquida base
        """
        self.ensure_one()

        if self.state not in ['draft', 'calculated']:
            raise UserError(_('Solo se puede calcular PPM en estado Borrador o Calculado'))

        # Primero calcular renta base si no existe
        if not self.renta_liquida_base and not self.is_new_company:
            self.action_calculate_base_income()

        # Verificar pérdidas tributarias
        self._check_previous_losses()

        # El cálculo se hace automáticamente por computed fields
        self.write({
            'state': 'calculated'
        })

        if self.is_suspended:
            message = _('PPM suspendido. Motivo: %s') % self._get_suspension_reason()
        else:
            message = _('PPM calculado: %s %s (%.2f%% sobre %s mensual)') % (
                self.ppm_amount_final,
                self.currency_id.symbol,
                self.ppm_rate,
                self.renta_mensual_base
            )

        self.message_post(
            body=message,
            message_type='notification'
        )

    def _check_previous_losses(self):
        """Verifica si existen pérdidas tributarias anteriores"""
        # Buscar F22 anteriores con pérdidas
        previous_f22s = self.env['l10n_cl.f22'].search([
            ('company_id', '=', self.company_id.id),
            ('fiscal_year', '<', self.fiscal_year),
            ('renta_liquida_imponible', '<=', 0),
            ('state', 'in', ['validated', 'sent', 'accepted'])
        ])

        if previous_f22s:
            self.has_previous_losses = True

    def _get_suspension_reason(self):
        """Obtiene la razón de suspensión del PPM"""
        reasons = []
        if self.is_new_company:
            reasons.append('Empresa nueva')
        if self.has_previous_losses:
            reasons.append('Pérdidas tributarias anteriores')
        if self.renta_liquida_base <= 0:
            reasons.append('Sin renta base')

        return ', '.join(reasons)

    def action_validate(self):
        """
        Valida el PPM y crea efectos contables
        """
        self.ensure_one()

        if self.state not in ['calculated']:
            raise UserError(_('Solo se pueden validar PPM calculados'))

        # Crear asiento de provisión si hay PPM a pagar
        if self.ppm_amount_final > 0:
            self._create_provision_move()

        # Cambiar estado
        self.write({
            'state': 'validated'
        })

        # TODO: Rehabilitar integración F29
        # if self.auto_integrate_f29:
        #     self._integrate_with_f29()

        message = _('PPM validado: %s %s') % (self.ppm_amount_final, self.currency_id.symbol)
        self.message_post(
            body=message,
            message_type='notification'
        )

    def _create_provision_move(self):
        """
        Crea asiento contable de provisión del PPM
        """
        self.ensure_one()

        # Obtener cuentas desde configuración
        ppm_por_pagar_account = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl.account_ppm_por_pagar_id'
        )
        if not ppm_por_pagar_account:
            raise UserError(_('No se ha configurado la cuenta de PPM por pagar'))

        gasto_ppm_account = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl.account_gasto_ppm_id'
        )
        if not gasto_ppm_account:
            raise UserError(_('No se ha configurado la cuenta de Gasto PPM'))

        # Crear asiento
        move_vals = {
            'journal_id': self.env['account.journal'].search([
                ('type', '=', 'general'),
                ('company_id', '=', self.company_id.id)
            ], limit=1).id,
            'date': self.period_date,
            'ref': f'Provisión PPM {self.period:02d}/{self.fiscal_year}',
            'company_id': self.company_id.id,
            'line_ids': [
                (0, 0, {
                    'name': f'Gasto PPM {self.period:02d}/{self.fiscal_year}',
                    'account_id': int(gasto_ppm_account),
                    'debit': self.ppm_amount_final,
                    'credit': 0.0,
                }),
                (0, 0, {
                    'name': f'PPM por Pagar {self.period:02d}/{self.fiscal_year}',
                    'account_id': int(ppm_por_pagar_account),
                    'debit': 0.0,
                    'credit': self.ppm_amount_final,
                }),
            ]
        }

        move = self.env['account.move'].create(move_vals)
        move.action_post()

        self.provision_move_id = move

    # TODO: Método deshabilitado temporalmente
    # def _integrate_with_f29(self):
    #     """
    #     Integra el PPM con el F29 mensual correspondiente
    #     """
    #     self.ensure_one()

    #     # Buscar o crear F29 del mismo período
    #     period_date = self.period_date
    #     f29 = self.env['l10n_cl.f29'].search([
    #         ('company_id', '=', self.company_id.id),
    #         ('period_date', '=', period_date)
    #     ], limit=1)

    #     if not f29:
    #         # Crear F29 si no existe
    #         f29 = self.env['l10n_cl.f29'].create({
    #             'company_id': self.company_id.id,
    #             'period_date': period_date,
    #         })

    #     # Vincular PPM con F29
    #     self.write({
    #         'f29_id': f29.id,
    #         'state': 'integrated_f29'
    #     })

    #     # Actualizar F29 con el PPM
    #     f29._integrate_ppm(self)

    #     self.message_post(
    #         body=_('PPM integrado con F29: %s') % f29.display_name,
    #         message_type='notification'
    #     )

    def action_mark_as_paid(self):
        """
        Marca el PPM como pagado
        """
        self.ensure_one()

        if self.state not in ['validated']:  # TODO: Rehabilitar 'integrated_f29'
            raise UserError(_('Solo se pueden marcar como pagados PPM validados'))

        if not self.provision_move_id:
            raise UserError(_('No existe asiento de provisión para este PPM'))

        # Crear asiento de pago (reversa de la provisión + pago real)
        self._create_payment_move()

        self.write({
            'state': 'paid'
        })

        self.message_post(
            body=_('PPM marcado como pagado'),
            message_type='notification'
        )

    def _create_payment_move(self):
        """
        Crea asiento contable de pago del PPM
        """
        self.ensure_one()

        # Obtener cuentas
        ppm_por_pagar_account = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl.account_ppm_por_pagar_id'
        )
        banco_account = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl.account_banco_principal_id'
        )

        if not banco_account:
            raise UserError(_('No se ha configurado la cuenta de banco principal'))

        # Crear asiento
        move_vals = {
            'journal_id': self.env['account.journal'].search([
                ('type', '=', 'bank'),
                ('company_id', '=', self.company_id.id)
            ], limit=1).id,
            'date': fields.Date.today(),
            'ref': f'Pago PPM {self.period:02d}/{self.fiscal_year}',
            'company_id': self.company_id.id,
            'line_ids': [
                (0, 0, {
                    'name': f'Pago PPM {self.period:02d}/{self.fiscal_year}',
                    'account_id': int(ppm_por_pagar_account),
                    'debit': self.ppm_amount_final,
                    'credit': 0.0,
                }),
                (0, 0, {
                    'name': f'Pago PPM {self.period:02d}/{self.fiscal_year}',
                    'account_id': int(banco_account),
                    'debit': 0.0,
                    'credit': self.ppm_amount_final,
                }),
            ]
        }

        move = self.env['account.move'].create(move_vals)
        move.action_post()

        self.payment_move_id = move

    def action_suspend(self):
        """
        Suspende el PPM manualmente
        """
        self.ensure_one()

        if self.state not in ['draft', 'calculated']:
            raise UserError(_('Solo se pueden suspender PPM en borrador o calculados'))

        self.write({
            'state': 'suspended',
            'is_suspended': True
        })

        self.message_post(
            body=_('PPM suspendido manualmente'),
            message_type='notification'
        )

    def action_cancel(self):
        """
        Cancela el PPM
        """
        self.ensure_one()

        if self.state in ['paid']:
            raise UserError(_('No se puede cancelar un PPM pagado'))

        # Reversas de asientos si existen
        if self.provision_move_id:
            self.provision_move_id.button_cancel()

        if self.payment_move_id:
            self.payment_move_id.button_cancel()

        self.write({
            'state': 'cancelled'
        })

        self.message_post(
            body=_('PPM cancelado'),
            message_type='notification'
        )

    @api.model
    def create_monthly_ppm(self):
        """
        Cron job para crear PPM mensualmente
        Se ejecuta el día 12 de cada mes para el mes actual
        """
        # Calcular período actual
        today = fields.Date.today()
        current_year = today.year
        current_month = today.month

        # Para cada compañía activa con PPM habilitado
        companies = self.env['res.company'].search([
            ('l10n_cl_ppm_enabled', '=', True)
        ])

        for company in companies:
            # Verificar si ya existe PPM para este período
            existing = self.search([
                ('company_id', '=', company.id),
                ('fiscal_year', '=', current_year),
                ('period', '=', current_month),
                ('state', '!=', 'cancelled')
            ], limit=1)

            if not existing:
                # Crear nuevo PPM
                ppm = self.create({
                    'company_id': company.id,
                    'fiscal_year': current_year,
                    'period': current_month,
                })

                try:
                    # Calcular automáticamente
                    ppm.action_calculate_ppm()

                    _logger.info(f"PPM creado automáticamente: {ppm.display_name}")

                except Exception as e:
                    _logger.error(f"Error creando PPM automático para {company.name}: {str(e)}")

    def action_view_related_documents(self):
        """
        Abre documentos relacionados (F29, F22, asientos)
        """
        self.ensure_one()

        actions = []

        # TODO: Rehabilitar F29 relacionado
        # if self.f29_id:
        #     actions.append({
        #         'name': _('F29 Relacionado'),
        #         'type': 'ir.actions.act_window',
        #         'res_model': 'l10n_cl.f29',
        #         'res_id': self.f29_id.id,
        #         'view_mode': 'form',
        #         'target': 'new',
        #     })

        # F22 base
        f22_base = self.env['l10n_cl.f22'].search([
            ('company_id', '=', self.company_id.id),
            ('fiscal_year', '=', self.base_year)
        ], limit=1)

        if f22_base:
            actions.append({
                'name': _('F22 Base'),
                'type': 'ir.actions.act_window',
                'res_model': 'l10n_cl.f22',
                'res_id': f22_base.id,
                'view_mode': 'form',
                'target': 'new',
            })

        # Asientos contables
        moves = (self.provision_move_id + self.payment_move_id).filtered(lambda x: x)
        if moves:
            actions.append({
                'name': _('Asientos Contables'),
                'type': 'ir.actions.act_window',
                'res_model': 'account.move',
                'domain': [('id', 'in', moves.ids)],
                'view_mode': 'tree,form',
                'target': 'current',
            })

        if len(actions) == 1:
            return actions[0]
        elif len(actions) > 1:
            # Retornar menú de selección
            return {
                'name': _('Documentos Relacionados'),
                'type': 'ir.actions.act_window',
                'res_model': 'ir.actions.act_window',
                'view_mode': 'tree',
                'target': 'new',
            }
        else:
            raise UserError(_('No hay documentos relacionados para mostrar'))

