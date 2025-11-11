# -*- coding: utf-8 -*-

from odoo import models, fields, api, _

class PayrollAIValidationWizard(models.TransientModel):
    """
    Wizard Advertencias Validación IA
    
    Mostrado cuando la validación IA recomienda revisión manual
    debido a confianza baja (<70%) o advertencias encontradas.
    """
    _name = 'payroll.ai.validation.wizard'
    _description = 'Wizard Advertencias Validación IA'
    
    payslip_id = fields.Many2one(
        'hr.payslip',
        string='Liquidación',
        required=True,
        readonly=True
    )
    
    confidence = fields.Float(
        string='Confianza IA (%)',
        readonly=True,
        help='Nivel de confianza de la validación IA (0-100)'
    )
    
    warnings = fields.Text(
        string='Advertencias Detectadas',
        readonly=True,
        help='Lista de advertencias encontradas por IA'
    )
    
    recommendation = fields.Selection([
        ('approve', 'Aprobar'),
        ('review', 'Revisar'),
        ('reject', 'Rechazar')
    ], string='Recomendación IA', readonly=True)
    
    def action_confirm_anyway(self):
        """
        Confirmar liquidación ignorando advertencias IA
        
        Registra en el chatter que el usuario decidió ignorar
        las advertencias de IA y confirmó manualmente.
        """
        self.ensure_one()
        
        # Mensaje en chatter
        self.payslip_id.message_post(
            body=f"⚠️ <b>Liquidación confirmada manualmente</b><br/>"
                 f"Usuario ignoró advertencias IA (Confianza: {self.confidence:.1f}%)<br/>"
                 f"<b>Advertencias omitidas:</b><br/>"
                 f"<pre>{self.warnings}</pre>",
            message_type='notification',
            subtype_xmlid='mail.mt_note'
        )
        
        # Confirmar con context para omitir validación IA
        return self.payslip_id.with_context(skip_ai_validation=True).action_done()
    
    def action_cancel(self):
        """Cancelar confirmación y volver a revisar liquidación"""
        return {'type': 'ir.actions.act_window_close'}
