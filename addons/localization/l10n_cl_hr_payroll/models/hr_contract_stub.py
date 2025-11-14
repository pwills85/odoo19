# -*- coding: utf-8 -*-
"""
HR Contract Stub for Odoo 19 CE
================================

PROPÓSITO: Proveer modelo hr.contract mínimo para Odoo 19 CE
    (hr_contract es Enterprise-only desde Odoo 17+)

ESTRATEGIA:
    - Define modelo base hr.contract con campos esenciales
    - Compatible con extensiones chilenas (hr_contract_cl.py)
    - Workflow simplificado (draft → running → close)

IMPORTANTE:
    - Si migras a Odoo Enterprise, desactiva este módulo
    - Este stub NO replica todas las funciones de hr_contract Enterprise
    - Solo provee funcionalidad básica para contratos en CE

Created: 2025-11-14
Author: SuperClaude AI (Claude Code)
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import date


class HrContractType(models.Model):
    """
    Tipo de Contrato (stub)

    Permite clasificar contratos por tipo (plazo fijo, indefinido, etc.)
    """
    _name = 'hr.contract.type'
    _description = 'Contract Type (CE Stub)'
    _order = 'sequence, name'

    name = fields.Char(
        string='Contract Type',
        required=True,
        translate=True,
        help='Name of the contract type'
    )

    sequence = fields.Integer(
        string='Sequence',
        default=10,
        help='Determines the display order'
    )

    active = fields.Boolean(
        string='Active',
        default=True
    )


class HrContract(models.Model):
    """
    Modelo stub de contrato laboral para Odoo 19 CE

    Provee funcionalidad básica de contratos de trabajo sin depender
    del módulo Enterprise hr_contract.
    """
    _name = 'hr.contract'
    _description = 'Employee Contract (CE Stub)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_start desc, id desc'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string='Contract Reference',
        required=True,
        help='Contract name or reference number'
    )

    active = fields.Boolean(
        string='Active',
        default=True,
        help='Set active to false to hide the contract without removing it'
    )

    employee_id = fields.Many2one(
        'hr.employee',
        string='Employee',
        required=True,
        tracking=True,
        ondelete='restrict',
        help='Employee linked to this contract'
    )

    # ═══════════════════════════════════════════════════════════
    # FECHAS Y PERÍODO
    # ═══════════════════════════════════════════════════════════

    date_start = fields.Date(
        string='Start Date',
        required=True,
        default=fields.Date.today,
        tracking=True,
        help='Start date of the contract'
    )

    date_end = fields.Date(
        string='End Date',
        tracking=True,
        help='End date of the contract (if a fixed-term contract)'
    )

    # ═══════════════════════════════════════════════════════════
    # INFORMACIÓN SALARIAL
    # ═══════════════════════════════════════════════════════════

    wage = fields.Monetary(
        string='Wage',
        required=True,
        tracking=True,
        help="Employee's monthly gross wage",
        aggregator="avg"
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        required=True,
        default=lambda self: self.env.company.currency_id,
        help='Currency of the wage'
    )

    # ═══════════════════════════════════════════════════════════
    # TIPO DE CONTRATO
    # ═══════════════════════════════════════════════════════════

    contract_type_id = fields.Many2one(
        'hr.contract.type',
        string='Contract Type',
        tracking=True,
        help='Type of employment contract (e.g., Indefinido, Plazo Fijo)'
    )

    contract_type = fields.Selection([
        ('permanent', 'Permanent'),
        ('fixed_term', 'Fixed Term'),
        ('temporary', 'Temporary')
    ], string='Contract Type (Legacy)', default='permanent',
       tracking=True,
       help='Type of employment contract (deprecated, use contract_type_id)')

    # ═══════════════════════════════════════════════════════════
    # ESTADO Y WORKFLOW
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'New'),
        ('open', 'Running'),
        ('close', 'Expired'),
        ('cancel', 'Cancelled')
    ], string='Status', default='draft', required=True,
       tracking=True,
       help='Status of the contract')

    # ═══════════════════════════════════════════════════════════
    # INFORMACIÓN ADICIONAL
    # ═══════════════════════════════════════════════════════════

    job_id = fields.Many2one(
        'hr.job',
        string='Job Position',
        help="Employee's job position"
    )

    department_id = fields.Many2one(
        'hr.department',
        string='Department',
        help="Employee's department"
    )

    company_id = fields.Many2one(
        'res.company',
        string='Company',
        required=True,
        default=lambda self: self.env.company,
        help='Company of the contract'
    )

    notes = fields.Text(
        string='Notes',
        help='Additional information about the contract'
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS COMPUTE
    # ═══════════════════════════════════════════════════════════

    @api.constrains('date_start', 'date_end')
    def _check_dates(self):
        """Valida que fecha fin sea posterior a fecha inicio"""
        for contract in self:
            if contract.date_end and contract.date_start:
                if contract.date_end < contract.date_start:
                    raise ValidationError(
                        _('Contract end date must be greater than start date.')
                    )

    @api.constrains('wage')
    def _check_wage(self):
        """Valida que el salario sea positivo"""
        for contract in self:
            if contract.wage < 0:
                raise ValidationError(
                    _('Wage must be a positive value.')
                )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS DE WORKFLOW
    # ═══════════════════════════════════════════════════════════

    def action_start_contract(self):
        """Inicia el contrato (draft → open)"""
        self.ensure_one()
        if self.state != 'draft':
            raise ValidationError(_('Only draft contracts can be started.'))
        self.write({'state': 'open'})
        return True

    def action_close_contract(self):
        """Cierra el contrato (open → close)"""
        self.ensure_one()
        if self.state != 'open':
            raise ValidationError(_('Only running contracts can be closed.'))
        self.write({
            'state': 'close',
            'date_end': date.today() if not self.date_end else self.date_end
        })
        return True

    def action_cancel_contract(self):
        """Cancela el contrato"""
        self.write({'state': 'cancel'})
        return True

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS AUXILIARES
    # ═══════════════════════════════════════════════════════════

    @api.model
    def create(self, vals):
        """Override create para auto-iniciar contratos según configuración"""
        contract = super().create(vals)
        # Auto-start si fecha inicio es hoy o pasada
        if contract.date_start <= date.today() and contract.state == 'draft':
            contract.action_start_contract()
        return contract

    def write(self, vals):
        """Override write para tracking de cambios críticos"""
        # Auto-cerrar contratos vencidos
        if 'date_end' in vals:
            for contract in self:
                if vals.get('date_end') and contract.state == 'open':
                    if vals['date_end'] < date.today():
                        vals['state'] = 'close'
        return super().write(vals)

    @api.model
    def _cron_expire_contracts(self):
        """
        Cron job: Cierra automáticamente contratos vencidos
        Ejecutar diariamente
        """
        today = date.today()
        expired = self.search([
            ('state', '=', 'open'),
            ('date_end', '!=', False),
            ('date_end', '<', today)
        ])
        if expired:
            expired.action_close_contract()
        return True
