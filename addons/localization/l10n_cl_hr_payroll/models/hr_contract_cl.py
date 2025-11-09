# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class HrContractCL(models.Model):
    """
    Extensión de hr.contract para Chile
    
    ESTRATEGIA: EXTENDER, NO DUPLICAR
    - Reutilizamos campos de hr.contract (wage, date_start, etc.)
    - Solo agregamos campos específicos Chile
    - Heredamos workflow de Odoo
    """
    _inherit = 'hr.contract'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS CHILE ESPECÍFICOS
    # ═══════════════════════════════════════════════════════════
    
    # AFP
    afp_id = fields.Many2one(
        'hr.afp',
        string='AFP',
        help='Administradora de Fondos de Pensiones'
    )
    afp_rate = fields.Float(
        string='Tasa AFP (%)',
        related='afp_id.rate',
        store=True,
        readonly=True,
        help='Tasa de cotización AFP (10.49% - 11.54%)'
    )
    
    # Salud
    health_system = fields.Selection([
        ('fonasa', 'FONASA'),
        ('isapre', 'ISAPRE')
    ], string='Sistema de Salud', default='fonasa', required=True)
    
    isapre_id = fields.Many2one(
        'hr.isapre',
        string='ISAPRE',
        help='Institución de Salud Previsional'
    )
    isapre_plan_uf = fields.Float(
        string='Plan ISAPRE (UF)',
        digits=(6, 4),
        help='Cotización pactada en UF'
    )
    isapre_fun = fields.Char(
        string='N° FUN',
        help='Número de Formulario Único de Notificación'
    )
    
    # Computed
    is_fonasa = fields.Boolean(
        string='Es FONASA',
        compute='_compute_is_fonasa',
        store=True
    )
    
    @api.depends('health_system')
    def _compute_is_fonasa(self):
        for contract in self:
            contract.is_fonasa = (contract.health_system == 'fonasa')
    
    # APV (Ahorro Previsional Voluntario)
    l10n_cl_apv_institution_id = fields.Many2one(
        'l10n_cl.apv.institution',
        string='APV Institution',
        help='Institución receptora del APV'
    )
    l10n_cl_apv_regime = fields.Selection([
        ('A', 'Régimen A (Rebaja tributaria)'),
        ('B', 'Régimen B (Sin rebaja)')
    ], string='APV Regime', help='Régimen tributario del APV')
    
    l10n_cl_apv_amount = fields.Monetary(
        string='APV Amount',
        currency_field='currency_id',
        help='Monto del aporte APV'
    )
    l10n_cl_apv_amount_type = fields.Selection([
        ('fixed', 'Monto Fijo CLP'),
        ('percent', 'Porcentaje RLI'),
        ('uf', 'Monto en UF')
    ], string='APV Amount Type', default='fixed',
       help='Tipo de cotización APV')
    
    # Asignaciones Art. 41 CT
    colacion = fields.Monetary(
        string='Colación',
        currency_field='currency_id',
        help='Asignación de colación (Art. 41 CT). Exento hasta 5 UTM conjunto con movilización'
    )
    movilizacion = fields.Monetary(
        string='Movilización',
        currency_field='currency_id',
        help='Asignación de movilización (Art. 41 CT). Exento hasta 5 UTM conjunto con colación'
    )
    
    # Cargas familiares
    family_allowance_simple = fields.Integer(
        string='Cargas Simples',
        default=0,
        help='Número de cargas familiares simples'
    )
    family_allowance_maternal = fields.Integer(
        string='Cargas Maternales',
        default=0,
        help='Número de cargas familiares maternales'
    )
    family_allowance_invalid = fields.Integer(
        string='Cargas Inválidas',
        default=0,
        help='Número de cargas familiares inválidas'
    )
    
    # Gratificación
    gratification_type = fields.Selection([
        ('legal', 'Legal (25% utilidades)'),
        ('monthly', 'Mensual (1/12)'),
        ('none', 'Sin gratificación')
    ], string='Tipo Gratificación', default='legal')
    
    # Jornada
    weekly_hours = fields.Integer(
        string='Jornada Semanal (horas)',
        default=44,
        help='Jornada laboral semanal pactada. Estándar: 44 horas (desde abril 2024)'
    )
    
    # Zona extrema
    extreme_zone = fields.Boolean(
        string='Zona Extrema',
        help='Trabajador en zona extrema (rebaja 50% impuesto único)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('isapre_plan_uf')
    def _check_isapre_plan(self):
        for contract in self:
            if contract.health_system == 'isapre':
                if not contract.isapre_id:
                    raise ValidationError(_("Debe seleccionar una ISAPRE"))
                if contract.isapre_plan_uf <= 0:
                    raise ValidationError(_("El plan ISAPRE debe ser mayor a 0 UF"))
    
    @api.constrains('weekly_hours')
    def _check_weekly_hours(self):
        for contract in self:
            if contract.weekly_hours < 1 or contract.weekly_hours > 45:
                raise ValidationError(_("La jornada semanal debe estar entre 1 y 45 horas"))
    
    @api.constrains('family_allowance_simple', 'family_allowance_maternal', 'family_allowance_invalid')
    def _check_family_allowances(self):
        for contract in self:
            if contract.family_allowance_simple < 0:
                raise ValidationError(_("Las cargas simples no pueden ser negativas"))
            if contract.family_allowance_maternal < 0:
                raise ValidationError(_("Las cargas maternales no pueden ser negativas"))
            if contract.family_allowance_invalid < 0:
                raise ValidationError(_("Las cargas inválidas no pueden ser negativas"))
