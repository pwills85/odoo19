# -*- coding: utf-8 -*-

from odoo import models, fields, api


class HrPayslipLine(models.Model):
    """
    Línea de Liquidación de Sueldo
    
    Representa cada concepto (haber o descuento) en una liquidación.
    """
    _name = 'hr.payslip.line'
    _description = 'Línea de Liquidación'
    _order = 'slip_id, sequence, id'
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════
    
    slip_id = fields.Many2one(
        'hr.payslip',
        string='Liquidación',
        required=True,
        ondelete='cascade',
        index=True
    )
    
    category_id = fields.Many2one(
        'hr.salary.rule.category',
        string='Categoría',
        required=True,
        help='Categoría del concepto (Haber, Descuento, etc.)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # IDENTIFICACIÓN
    # ═══════════════════════════════════════════════════════════
    
    code = fields.Char(
        string='Código',
        required=True,
        help='Código único del concepto (ej: SUELDO, AFP, FONASA)'
    )
    
    name = fields.Char(
        string='Descripción',
        required=True
    )
    
    sequence = fields.Integer(
        string='Secuencia',
        default=100,
        help='Orden de visualización'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CÁLCULO
    # ═══════════════════════════════════════════════════════════
    
    amount = fields.Float(
        string='Monto Base',
        digits='Payroll',
        help='Monto sobre el cual se aplica el cálculo'
    )
    
    quantity = fields.Float(
        string='Cantidad',
        default=1.0,
        digits='Payroll Rate',
        help='Cantidad (ej: días, horas)'
    )
    
    rate = fields.Float(
        string='Tasa (%)',
        default=100.0,
        digits='Payroll Rate',
        help='Porcentaje a aplicar'
    )
    
    total = fields.Float(
        string='Total',
        digits='Payroll',
        required=True,
        help='Monto final (positivo=haber, negativo=descuento)'
    )
    
    # ═══════════════════════════════════════════════════════════
    # INFORMACIÓN ADICIONAL
    # ═══════════════════════════════════════════════════════════
    
    note = fields.Text(
        string='Nota'
    )
    
    # Campos relacionados para búsquedas
    employee_id = fields.Many2one(
        'hr.employee',
        string='Empleado',
        related='slip_id.employee_id',
        store=True,
        readonly=True
    )
    
    contract_id = fields.Many2one(
        'hr.contract',
        string='Contrato',
        related='slip_id.contract_id',
        store=True,
        readonly=True
    )
    
    date_from = fields.Date(
        string='Fecha Desde',
        related='slip_id.date_from',
        store=True,
        readonly=True
    )
    
    date_to = fields.Date(
        string='Fecha Hasta',
        related='slip_id.date_to',
        store=True,
        readonly=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        related='slip_id.company_id',
        store=True,
        readonly=True
    )
