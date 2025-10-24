# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import UserError
from datetime import datetime
import json
import logging

_logger = logging.getLogger(__name__)


class TrialBalance(models.Model):
    """
    Balance de Comprobación y Saldos (Trial Balance)
    Muestra el resumen de todas las cuentas con sus saldos deudor/acreedor
    """
    _name = 'account.trial.balance'
    _description = 'Balance de Comprobación y Saldos'
    _inherit = []
    _order = 'create_date desc'
    
    # Override del campo name para computado
    name = fields.Char(
        string='Nombre del Reporte',
        compute='_compute_name',
        store=True
    )
    
    # Campos de Configuración
    date_from = fields.Date(
        string='Fecha Desde',
        required=True,
        default=lambda self: fields.Date.today(self).replace(day=1)
    )
    date_to = fields.Date(
        string='Fecha Hasta',
        required=True,
        default=fields.Date.context_today
    )
    
    # Opciones de visualización
    target_move = fields.Selection([
        ('posted', 'Asientos Publicados'),
        ('all', 'Todos los Asientos')
    ], string='Movimientos Objetivo', required=True, default='posted')
    
    hide_zero_balance = fields.Boolean(
        string='Ocultar Saldos en Cero',
        default=True,
        help='No mostrar cuentas sin movimientos o con saldo cero'
    )
    
    show_initial_balance = fields.Boolean(
        string='Incluir Saldo Inicial',
        default=True,
        help='Mostrar columna con saldo inicial del período'
    )
    
    hierarchy_level = fields.Selection([
        ('all', 'Todas las Cuentas'),
        ('1', 'Nivel 1 - Grupos Principales'),
        ('2', 'Nivel 2 - Subgrupos'),
        ('3', 'Nivel 3 - Cuentas'),
        ('detail', 'Solo Cuentas de Detalle')
    ], string='Nivel de Jerarquía', default='all', required=True)
    
    # Comparación de períodos
    comparison_enabled = fields.Boolean(
        string='Comparar con Período Anterior',
        default=False
    )
    previous_date_from = fields.Date(
        string='Fecha Desde Anterior'
    )
    previous_date_to = fields.Date(
        string='Fecha Hasta Anterior'
    )
    
    # Estado del reporte
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('computing', 'Calculando'),
        ('computed', 'Calculado'),
        ('error', 'Error')
    ], string='Estado', default='draft', required=True)
    
    # Líneas del Balance
    line_ids = fields.One2many(
        'account.trial.balance.line',
        'balance_id',
        string='Líneas del Balance'
    )
    
    # Totales
    total_initial_debit = fields.Monetary(
        string='Total Débito Inicial',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_initial_credit = fields.Monetary(
        string='Total Crédito Inicial',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_period_debit = fields.Monetary(
        string='Total Débitos Período',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_period_credit = fields.Monetary(
        string='Total Créditos Período',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_ending_debit = fields.Monetary(
        string='Total Débito Final',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_ending_credit = fields.Monetary(
        string='Total Crédito Final',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    
    # Validación
    is_balanced = fields.Boolean(
        string='Balance Cuadrado',
        compute='_compute_validation',
        store=True
    )
    balance_difference = fields.Monetary(
        string='Diferencia',
        compute='_compute_validation',
        store=True,
        currency_field='currency_id'
    )
    
    # Cache y Performance
    cache_key = fields.Char(string='Cache Key', compute='_compute_cache_key')
    last_compute = fields.Datetime(string='Última Actualización')
    
    # Compañía
    company_id = fields.Many2one('res.company', string='Compañía', required=True, default=lambda self: self.env.company)
    
    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Moneda'
    )
    
    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'company_id')
    def _compute_name(self):
        for record in self:
            if record.date_from and record.date_to:
                record.name = f"Balance de Comprobación - {record.company_id.name}: {record.date_from} al {record.date_to}"
            else:
                record.name = f"Balance de Comprobación - {record.company_id.name}"
    
    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'company_id', 'target_move', 'hide_zero_balance')
    def _compute_cache_key(self):
        for record in self:
            key_data = {
                'date_from': str(record.date_from),
                'date_to': str(record.date_to),
                'company_id': record.company_id.id,
                'target_move': record.target_move,
                'hide_zero': record.hide_zero_balance,
                'hierarchy': record.hierarchy_level
            }
            record.cache_key = json.dumps(key_data, sort_keys=True)
    
    @api.depends('line_ids.initial_debit', 'line_ids.initial_credit',
                 'line_ids.period_debit', 'line_ids.period_credit',
                 'line_ids.ending_debit', 'line_ids.ending_credit')
    def _compute_totals(self):
        """Calcula los totales del balance"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        d = d.with_context(prefetch_fields=False)

        for record in self:
            # Filtrar solo líneas de cuentas (no grupos)
            account_lines = record.line_ids.filtered(lambda l: not l.is_group_line)
            
            record.total_initial_debit = sum(account_lines.mapped('initial_debit'))
            record.total_initial_credit = sum(account_lines.mapped('initial_credit'))
            record.total_period_debit = sum(account_lines.mapped('period_debit'))
            record.total_period_credit = sum(account_lines.mapped('period_credit'))
            record.total_ending_debit = sum(account_lines.mapped('ending_debit'))
            record.total_ending_credit = sum(account_lines.mapped('ending_credit'))
    
    @api.depends('total_ending_debit', 'total_ending_credit')
    def _compute_validation(self):
        """Valida que el balance cuadre"""
        for record in self:
            difference = abs(record.total_ending_debit - record.total_ending_credit)
            record.balance_difference = difference
            record.is_balanced = difference < 0.01
    
    def action_compute_balance(self):
        """
        Acción principal para calcular el balance de comprobación.
        """
        self.ensure_one()
        
        try:
            # Cambiar estado a computing
            self.write({'state': 'computing', 'last_compute': fields.Datetime.now()})
            
            # Limpiar líneas anteriores
            self.line_ids.unlink()
            
            # Obtener el servicio
            from ..services.trial_balance_service import TrialBalanceService
            service = TrialBalanceService(self.env)
            
            # Calcular el balance
            result = service.compute_trial_balance(
                date_from=self.date_from,
                date_to=self.date_to,
                company_id=self.company_id.id,
                target_move=self.target_move,
                hide_zero_balance=self.hide_zero_balance,
                show_initial_balance=self.show_initial_balance,
                hierarchy_level=self.hierarchy_level,
                comparison_enabled=self.comparison_enabled,
                previous_date_from=self.previous_date_from,
                previous_date_to=self.previous_date_to
            )
            
            # Crear las líneas
            sequence = 1
            for line_data in result['lines']:
                self.env['account.trial.balance.line'].create({
                    'balance_id': self.id,
                    'sequence': sequence,
                    'account_id': line_data.get('account_id'),
                    'account_code': line_data['account_code'],
                    'account_name': line_data['account_name'],
                    'account_type': line_data.get('account_type', ''),
                    'hierarchy_level': line_data.get('hierarchy_level', 0),
                    'is_group_line': line_data.get('is_group_line', False),
                    'initial_debit': line_data.get('initial_debit', 0.0),
                    'initial_credit': line_data.get('initial_credit', 0.0),
                    'initial_balance': line_data.get('initial_balance', 0.0),
                    'period_debit': line_data['period_debit'],
                    'period_credit': line_data['period_credit'],
                    'period_balance': line_data['period_balance'],
                    'ending_debit': line_data['ending_debit'],
                    'ending_credit': line_data['ending_credit'],
                    'ending_balance': line_data['ending_balance'],
                    # Comparación
                    'previous_ending_balance': line_data.get('previous_ending_balance', 0.0),
                    'variation_amount': line_data.get('variation_amount', 0.0),
                    'variation_percent': line_data.get('variation_percent', 0.0),
                })
                sequence += 1
            
            # Actualizar estado
            self.write({'state': 'computed'})
            
            # Retornar acción para mostrar el reporte
            return {
                'type': 'ir.actions.client',
                'tag': 'trial_balance_report',
                'context': {
                    'active_id': self.id,
                    'active_model': self._name,
                }
            }
            
        except Exception as e:
            _logger.error(f"Error computing trial balance: {str(e)}")
            self.write({
                'state': 'error',
                'validation_errors': str(e)
            })
            raise UserError(_("Error al calcular el balance de comprobación: %s") % str(e))
    
    def action_export_excel(self):
        """Exporta el balance a Excel con formato profesional"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el balance antes de exportar."))
        
        from ..services.trial_balance_service import TrialBalanceService
        service = TrialBalanceService(self.env)
        return service.export_to_excel(self)
    
    def action_export_pdf(self):
        """Exporta el balance a PDF"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el balance antes de exportar."))
        
        return self.env.ref('l10n_cl_financial_reports.action_report_trial_balance').report_action(self)
    
    def action_refresh(self):
        """Recalcula el balance"""
        return self.action_compute_balance()
    
    def action_drill_down(self):
        """Abre el mayor analítico con los mismos filtros"""
        self.ensure_one()
        
        # Crear mayor analítico con mismos parámetros
        ledger = self.env['account.general.ledger'].create({
            'company_id': self.company_id.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
            'include_unposted': self.target_move == 'all',
        })
        
        # Abrir en vista form
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'account.general.ledger',
            'res_id': ledger.id,
            'view_mode': 'form',
            'target': 'current',
        }
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para establecer valores por defecto en batch"""
        for vals in vals_list:
            if 'company_id' not in vals:
                vals['company_id'] = self.env.company.id
            
            # Si se habilita comparación, calcular fechas anteriores
            if vals.get('comparison_enabled') and vals.get('date_from') and vals.get('date_to'):
                from dateutil.relativedelta import relativedelta
                date_from = fields.Date.from_string(vals['date_from'])
                date_to = fields.Date.from_string(vals['date_to'])
                
                # Calcular período anterior (mismo rango, año anterior)
                vals['previous_date_from'] = date_from - relativedelta(years=1)
                vals['previous_date_to'] = date_to - relativedelta(years=1)
                
        return super().create(vals_list)


class TrialBalanceLine(models.Model):
    """Líneas del Balance de Comprobación"""
    _name = 'account.trial.balance.line'
    _description = 'Línea de Balance de Comprobación'
    _order = 'sequence, account_code'
    
    balance_id = fields.Many2one(
        'account.trial.balance',
        string='Balance',
        required=True,
        ondelete='cascade'
    )
    
    sequence = fields.Integer(
        string='Secuencia',
        default=10
    )
    
    # Datos de la cuenta
    account_id = fields.Many2one(
        'account.account',
        string='Cuenta'
    )
    account_code = fields.Char(
        string='Código',
        required=True
    )
    account_name = fields.Char(
        string='Nombre',
        required=True
    )
    account_type = fields.Char(
        string='Tipo de Cuenta'
    )
    
    # Jerarquía
    hierarchy_level = fields.Integer(
        string='Nivel',
        default=0
    )
    is_group_line = fields.Boolean(
        string='Es Línea de Grupo',
        default=False,
        help='Indica si es una línea de agrupación/subtotal'
    )
    
    # Saldos iniciales
    initial_debit = fields.Monetary(
        string='Débito Inicial',
        currency_field='currency_id'
    )
    initial_credit = fields.Monetary(
        string='Crédito Inicial',
        currency_field='currency_id'
    )
    initial_balance = fields.Monetary(
        string='Saldo Inicial',
        currency_field='currency_id'
    )
    
    # Movimientos del período
    period_debit = fields.Monetary(
        string='Débitos Período',
        currency_field='currency_id'
    )
    period_credit = fields.Monetary(
        string='Créditos Período',
        currency_field='currency_id'
    )
    period_balance = fields.Monetary(
        string='Balance Período',
        currency_field='currency_id'
    )
    
    # Saldos finales
    ending_debit = fields.Monetary(
        string='Débito Final',
        currency_field='currency_id'
    )
    ending_credit = fields.Monetary(
        string='Crédito Final',
        currency_field='currency_id'
    )
    ending_balance = fields.Monetary(
        string='Saldo Final',
        currency_field='currency_id'
    )
    
    # Comparación con período anterior
    previous_ending_balance = fields.Monetary(
        string='Saldo Final Anterior',
        currency_field='currency_id'
    )
    variation_amount = fields.Monetary(
        string='Variación',
        currency_field='currency_id'
    )
    variation_percent = fields.Float(
        string='Variación %',
        digits=(16, 2)
    )
    
    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='balance_id.currency_id',
        string='Moneda'
    )
    
    def action_open_account_moves(self):
        """Abre los movimientos de la cuenta en el período"""
        self.ensure_one()
        if not self.account_id:
            return False
        
        domain = [
            ('account_id', '=', self.account_id.id),
            ('date', '>=', self.balance_id.date_from),
            ('date', '<=', self.balance_id.date_to),
            ('company_id', '=', self.balance_id.company_id.id)
        ]
        
        if self.balance_id.target_move == 'posted':
            domain.append(('parent_state', '=', 'posted'))
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Movimientos de %s') % self.account_name,
            'res_model': 'account.move.line',
            'domain': domain,
            'view_mode': 'tree,form',
            'context': {
                'search_default_group_by_move': 1,
            },
            'target': 'current',
        }