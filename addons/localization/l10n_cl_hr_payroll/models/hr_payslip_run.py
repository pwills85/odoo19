# -*- coding: utf-8 -*-

"""
Lote de Nóminas (Payslip Run / Batch)

Permite generar liquidaciones masivas para un período.
Compatible 100% con Odoo 19 CE.
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import logging

_logger = logging.getLogger(__name__)


class HrPayslipRun(models.Model):
    """
    Lote de Nóminas (Payslip Run)
    
    Técnica Odoo 19 CE:
    - Workflow con states
    - Generación masiva con batch
    - Progress tracking
    """
    _name = 'hr.payslip.run'
    _description = 'Lote de Nóminas'
    _order = 'date_start desc, id desc'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        required=True,
        tracking=True,
        help='Nombre del lote (ej: "Nómina Octubre 2025")'
    )
    
    date_start = fields.Date(
        string='Fecha Inicio',
        required=True,
        tracking=True,
        help='Primer día del período'
    )
    
    date_end = fields.Date(
        string='Fecha Fin',
        required=True,
        tracking=True,
        help='Último día del período'
    )
    
    date_payment = fields.Date(
        string='Fecha de Pago',
        tracking=True,
        help='Fecha en que se realizará el pago'
    )
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('processing', 'Procesando'),
        ('done', 'Completado'),
        ('cancel', 'Cancelado')
    ], string='Estado', default='draft', required=True, tracking=True)
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        default=lambda self: self.env.company,
        required=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════
    
    slip_ids = fields.One2many(
        'hr.payslip',
        'payslip_run_id',
        string='Liquidaciones',
        help='Liquidaciones de este lote'
    )
    
    struct_id = fields.Many2one(
        'hr.payroll.structure',
        string='Estructura Salarial',
        help='Estructura a usar para generar liquidaciones'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    slip_count = fields.Integer(
        string='Número de Liquidaciones',
        compute='_compute_slip_stats',
        store=True
    )
    
    slip_draft_count = fields.Integer(
        string='Borradores',
        compute='_compute_slip_stats',
        store=True
    )
    
    slip_done_count = fields.Integer(
        string='Completadas',
        compute='_compute_slip_stats',
        store=True
    )
    
    slip_error_count = fields.Integer(
        string='Con Errores',
        compute='_compute_slip_stats',
        store=True
    )
    
    total_gross = fields.Monetary(
        string='Total Bruto',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    
    total_net = fields.Monetary(
        string='Total Líquido',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Moneda'
    )
    
    @api.depends('slip_ids', 'slip_ids.state')
    def _compute_slip_stats(self):
        """Computar estadísticas de liquidaciones"""
        for run in self:
            run.slip_count = len(run.slip_ids)
            run.slip_draft_count = len(run.slip_ids.filtered(lambda s: s.state == 'draft'))
            run.slip_done_count = len(run.slip_ids.filtered(lambda s: s.state == 'done'))
            run.slip_error_count = len(run.slip_ids.filtered(lambda s: s.state == 'cancel'))
    
    @api.depends('slip_ids', 'slip_ids.gross_wage', 'slip_ids.net_wage')
    def _compute_totals(self):
        """Computar totales monetarios"""
        for run in self:
            done_slips = run.slip_ids.filtered(lambda s: s.state == 'done')
            run.total_gross = sum(done_slips.mapped('gross_wage'))
            run.total_net = sum(done_slips.mapped('net_wage'))
    
    # ═══════════════════════════════════════════════════════════
    # VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('date_start', 'date_end')
    def _check_dates(self):
        """Validar que fecha fin sea mayor a fecha inicio"""
        for run in self:
            if run.date_start and run.date_end and run.date_start > run.date_end:
                raise ValidationError(_(
                    'La fecha de fin debe ser posterior a la fecha de inicio'
                ))
    
    # ═══════════════════════════════════════════════════════════
    # GENERACIÓN MASIVA
    # ═══════════════════════════════════════════════════════════
    
    def action_generate_payslips(self):
        """
        Generar liquidaciones para todos los empleados activos
        
        Técnica Odoo 19 CE:
        - Search con domain filtrado
        - Create batch con list comprehension
        - Progress tracking con message_post
        """
        self.ensure_one()
        
        if self.state != 'draft':
            raise UserError(_('Solo puede generar liquidaciones desde estado Borrador'))
        
        # Buscar empleados activos con contrato abierto
        contracts = self.env['hr.contract'].search([
            ('state', '=', 'open'),
            ('company_id', '=', self.company_id.id),
            # Filtrar contratos que estén vigentes en el período
            '|',
            ('date_end', '=', False),
            ('date_end', '>=', self.date_start),
        ])
        
        if not contracts:
            raise UserError(_('No se encontraron contratos activos para generar liquidaciones'))
        
        _logger.info("Generando %d liquidaciones para período %s - %s",
                    len(contracts), self.date_start, self.date_end)
        
        # Generar liquidaciones
        payslips_created = 0
        payslips_skipped = 0
        
        for contract in contracts:
            # Verificar si ya existe liquidación para este empleado
            existing = self.env['hr.payslip'].search([
                ('payslip_run_id', '=', self.id),
                ('employee_id', '=', contract.employee_id.id),
            ], limit=1)
            
            if existing:
                payslips_skipped += 1
                continue
            
            # Crear liquidación
            try:
                self.env['hr.payslip'].create({
                    'employee_id': contract.employee_id.id,
                    'contract_id': contract.id,
                    'struct_id': self.struct_id.id if self.struct_id else False,
                    'date_from': self.date_start,
                    'date_to': self.date_end,
                    'payslip_run_id': self.id,
                    'name': f"{contract.employee_id.name} - {self.name}",
                    'company_id': self.company_id.id,
                })
                payslips_created += 1
                
            except Exception as e:
                _logger.error("Error creando liquidación para %s: %s",
                            contract.employee_id.name, e)
        
        # Cambiar estado
        self.state = 'processing'
        
        # Log actividad
        self.message_post(body=_(
            "✅ Generadas <b>%d liquidaciones</b> (omitidas: %d)"
        ) % (payslips_created, payslips_skipped))
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Liquidaciones Generadas'),
                'message': _('Se generaron %d liquidaciones exitosamente') % payslips_created,
                'type': 'success',
                'sticky': False,
            }
        }
    
    def action_compute_all(self):
        """
        Calcular todas las liquidaciones del lote
        
        Técnica Odoo 19 CE:
        - Batch processing
        - Try/except para manejo errores
        - Progress tracking
        """
        self.ensure_one()
        
        draft_slips = self.slip_ids.filtered(lambda s: s.state == 'draft')
        
        if not draft_slips:
            raise UserError(_('No hay liquidaciones en borrador para calcular'))
        
        _logger.info("Calculando %d liquidaciones del lote %s", 
                    len(draft_slips), self.name)
        
        success_count = 0
        error_count = 0
        errors = []
        
        for slip in draft_slips:
            try:
                slip.action_compute_sheet()
                success_count += 1
            except Exception as e:
                error_count += 1
                errors.append(f"{slip.employee_id.name}: {str(e)}")
                _logger.error("Error calculando liquidación %s: %s", slip.name, e)
        
        # Log resultado
        if error_count == 0:
            self.message_post(body=_(
                "✅ Calculadas <b>%d liquidaciones</b> exitosamente"
            ) % success_count)
        else:
            error_msg = "\n".join(errors[:10])  # Primeros 10 errores
            self.message_post(body=_(
                "⚠️ Calculadas <b>%d liquidaciones</b> con <b>%d errores</b>:\n%s"
            ) % (success_count, error_count, error_msg))
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Cálculo Completado'),
                'message': _('Éxito: %d | Errores: %d') % (success_count, error_count),
                'type': 'success' if error_count == 0 else 'warning',
                'sticky': True,
            }
        }
    
    def action_confirm_all(self):
        """Confirmar todas las liquidaciones calculadas"""
        self.ensure_one()
        
        computed_slips = self.slip_ids.filtered(lambda s: s.state == 'verify')
        
        for slip in computed_slips:
            slip.action_payslip_done()
        
        self.state = 'done'
        
        self.message_post(body=_(
            "✅ Confirmadas <b>%d liquidaciones</b>"
        ) % len(computed_slips))
    
    # ═══════════════════════════════════════════════════════════
    # ACCIONES DE VISTA
    # ═══════════════════════════════════════════════════════════
    
    def action_view_payslips(self):
        """Ver liquidaciones del lote"""
        self.ensure_one()
        
        return {
            'name': _('Liquidaciones'),
            'type': 'ir.actions.act_window',
            'res_model': 'hr.payslip',
            'view_mode': 'tree,form',
            'domain': [('payslip_run_id', '=', self.id)],
            'context': {
                'default_payslip_run_id': self.id,
                'default_date_from': self.date_start,
                'default_date_to': self.date_end,
            },
        }
    
    def action_draft(self):
        """Volver a borrador"""
        self.write({'state': 'draft'})
    
    def action_cancel(self):
        """Cancelar lote"""
        self.write({'state': 'cancel'})
    
    def action_export_previred(self):
        """Exportar a Previred"""
        self.ensure_one()
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'previred.export.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_payslip_run_id': self.id,
                'default_year': self.date_start.year,
                'default_month': self.date_start.month,
            },
        }
