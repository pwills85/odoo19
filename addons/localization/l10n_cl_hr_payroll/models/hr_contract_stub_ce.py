# -*- coding: utf-8 -*-
"""
hr.contract Stub for Odoo 19 Community Edition
==============================================

Stub mínimo de hr.contract para compatibilidad CE.

En Odoo Enterprise, hr_contract es módulo separado.
En CE, este stub provee funcionalidad básica requerida por nómina chilena.

IMPORTANTE: Solo campos mínimos para l10n_cl_hr_payroll.
            Para funcionalidad completa, usar Odoo Enterprise.

Author: EERGYGROUP
License: LGPL-3
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class HrContractType(models.Model):
    """
    Tipo de Contrato Laboral (CE Stub).

    En Enterprise, este modelo viene con hr_contract.
    En CE, creamos stub básico.
    """
    _name = 'hr.contract.type'
    _description = 'Tipo de Contrato (CE Stub)'
    _order = 'sequence, name'

    name = fields.Char(
        string='Nombre Tipo Contrato',
        required=True,
        translate=True,
        help='Ej: Indefinido, Plazo Fijo, Por Obra'
    )

    sequence = fields.Integer(
        string='Secuencia',
        default=10,
        help='Orden de visualización'
    )

    active = fields.Boolean(
        string='Activo',
        default=True
    )


class HrContract(models.Model):
    """
    Stub básico hr.contract para Odoo 19 CE.

    Provee campos mínimos requeridos por nómina chilena.
    Compatible con l10n_cl_hr_payroll.
    """
    _name = 'hr.contract'
    _description = 'Contrato Laboral (CE Stub)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_start desc, id desc'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string='Nombre Contrato',
        required=True,
        tracking=True,
        help='Referencia del contrato (ej: "Contrato Ingeniero Civil 2025")'
    )

    active = fields.Boolean(
        string='Activo',
        default=True,
        help='Desactivar para archivar contrato sin eliminar'
    )

    employee_id = fields.Many2one(
        'hr.employee',
        string='Empleado',
        required=True,
        tracking=True,
        ondelete='restrict',
        index=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        tracking=True,
        index=True
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        required=True,
        default=lambda self: self.env.company.currency_id,
        tracking=True
    )

    # ═══════════════════════════════════════════════════════════
    # DATOS SALARIALES
    # ═══════════════════════════════════════════════════════════

    wage = fields.Monetary(
        string='Sueldo Base',
        required=True,
        currency_field='currency_id',
        tracking=True,
        help='Remuneración mensual bruta (base cálculo nómina)'
    )

    # ═══════════════════════════════════════════════════════════
    # PERÍODO CONTRACTUAL
    # ═══════════════════════════════════════════════════════════

    date_start = fields.Date(
        string='Fecha Inicio',
        required=True,
        tracking=True,
        default=fields.Date.today,
        index=True
    )

    date_end = fields.Date(
        string='Fecha Término',
        tracking=True,
        help='Dejar vacío para contrato indefinido',
        index=True
    )

    # ═══════════════════════════════════════════════════════════
    # TIPO DE CONTRATO
    # ═══════════════════════════════════════════════════════════

    contract_type_id = fields.Many2one(
        'hr.contract.type',
        string='Tipo Contrato',
        help='Tipo de contrato laboral (indefinido, plazo fijo, etc.)',
        tracking=True
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('open', 'Vigente'),
        ('pending', 'Pendiente'),
        ('close', 'Cerrado'),
        ('cancel', 'Cancelado'),
    ], string='Estado', default='draft', tracking=True, required=True, index=True)

    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════

    payslip_ids = fields.One2many(
        'hr.payslip',
        'contract_id',
        string='Liquidaciones',
        readonly=True
    )

    payslip_count = fields.Integer(
        string='N° Liquidaciones',
        compute='_compute_payslip_count',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTES
    # ═══════════════════════════════════════════════════════════

    @api.depends('payslip_ids')
    def _compute_payslip_count(self):
        """Contar liquidaciones del contrato"""
        for contract in self:
            contract.payslip_count = len(contract.payslip_ids)

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('date_start', 'date_end')
    def _check_dates(self):
        """Validar coherencia de fechas"""
        for contract in self:
            if contract.date_end and contract.date_start:
                if contract.date_end < contract.date_start:
                    raise ValidationError(
                        _('La fecha de término debe ser posterior a la fecha de inicio.')
                    )

    @api.constrains('wage')
    def _check_wage_positive(self):
        """Validar sueldo positivo"""
        for contract in self:
            if contract.wage <= 0:
                raise ValidationError(
                    _('El sueldo base debe ser mayor a cero.')
                )

    @api.constrains('employee_id', 'date_start', 'date_end', 'state')
    def _check_overlap_contracts(self):
        """Validar que no haya contratos vigentes superpuestos para mismo empleado"""
        for contract in self:
            if contract.state not in ('open', 'pending'):
                continue

            domain = [
                ('employee_id', '=', contract.employee_id.id),
                ('state', 'in', ('open', 'pending')),
                ('id', '!=', contract.id),
            ]

            # Verificar superposición de fechas
            if contract.date_end:
                domain += [
                    '|',
                    '&',
                    ('date_start', '<=', contract.date_end),
                    '|',
                    ('date_end', '>=', contract.date_start),
                    ('date_end', '=', False),
                    '&',
                    ('date_start', '>=', contract.date_start),
                    ('date_start', '<=', contract.date_end),
                ]
            else:
                domain += [
                    '|',
                    ('date_end', '>=', contract.date_start),
                    ('date_end', '=', False),
                ]

            overlapping = self.search(domain, limit=1)
            if overlapping:
                raise ValidationError(_(
                    'Ya existe un contrato vigente para el empleado %s '
                    'en el período %s - %s que se superpone con este contrato.'
                ) % (
                    contract.employee_id.name,
                    contract.date_start,
                    contract.date_end or 'Indefinido'
                ))

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS NEGOCIO
    # ═══════════════════════════════════════════════════════════

    def action_open(self):
        """Activar contrato"""
        self.ensure_one()
        self.write({'state': 'open'})
        _logger.info(f"Contrato {self.name} activado para empleado {self.employee_id.name}")
        return True

    def action_close(self):
        """Cerrar contrato"""
        self.ensure_one()
        self.write({
            'state': 'close',
            'date_end': fields.Date.today() if not self.date_end else self.date_end
        })
        _logger.info(f"Contrato {self.name} cerrado para empleado {self.employee_id.name}")
        return True

    def action_set_running(self):
        """Activar contrato (alias para action_open)"""
        self.ensure_one()
        self.write({'state': 'running'})
        _logger.info(f"Contrato {self.name} activado (running) para empleado {self.employee_id.name}")
        return True

    def action_set_close(self):
        """Cerrar contrato (alias para action_close)"""
        return self.action_close()

    def action_set_draft(self):
        """Volver contrato a borrador"""
        self.ensure_one()
        self.write({'state': 'draft'})
        _logger.info(f"Contrato {self.name} vuelto a borrador para empleado {self.employee_id.name}")
        return True

    @api.model_create_multi
    def create(self, vals_list):
        """Log creación contratos"""
        contracts = super(HrContract, self).create(vals_list)
        for contract in contracts:
            _logger.info(
                f"Contrato CE creado: {contract.name} "
                f"para empleado {contract.employee_id.name} "
                f"({contract.date_start} - {contract.date_end or 'Indefinido'})"
            )
        return contracts

    def write(self, vals):
        """Log modificaciones importantes"""
        result = super(HrContract, self).write(vals)
        if 'state' in vals or 'wage' in vals or 'date_end' in vals:
            for contract in self:
                _logger.info(
                    f"Contrato CE modificado: {contract.name} "
                    f"(Estado: {contract.state}, Sueldo: {contract.wage})"
                )
        return result
