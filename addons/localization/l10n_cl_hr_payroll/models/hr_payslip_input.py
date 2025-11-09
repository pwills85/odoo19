# -*- coding: utf-8 -*-

from odoo import models, fields


class HrPayslipInput(models.Model):
    """
    Input de Liquidación
    
    Inputs adicionales para la liquidación (horas extra, bonos, etc.)
    """
    _name = 'hr.payslip.input'
    _description = 'Input de Liquidación'
    _order = 'payslip_id, sequence'
    
    payslip_id = fields.Many2one(
        'hr.payslip',
        string='Liquidación',
        required=True,
        ondelete='cascade'
    )
    
    sequence = fields.Integer(
        string='Secuencia',
        default=10
    )
    
    code = fields.Char(
        string='Código',
        required=True,
        help='Código del input (ej: HEX, BONO)'
    )
    
    name = fields.Char(
        string='Descripción',
        required=True
    )
    
    amount = fields.Float(
        string='Monto',
        digits='Payroll',
        help='Monto del input'
    )
    
    contract_id = fields.Many2one(
        'hr.contract',
        string='Contrato',
        related='payslip_id.contract_id',
        store=True,
        readonly=True
    )
