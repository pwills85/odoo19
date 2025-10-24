# -*- coding: utf-8 -*-

from odoo import models, fields, _


class GenerateConsumoFoliosWizard(models.TransientModel):
    """Wizard para generar reporte de consumo de folios"""
    _name = 'generate.consumo.folios.wizard'
    _description = 'Generar Consumo de Folios'
    
    period_start = fields.Date(string='Período Desde', required=True)
    period_end = fields.Date(string='Período Hasta', required=True)
    journal_id = fields.Many2one('account.journal', string='Diario', 
                                   domain=[('is_dte_journal', '=', True)])
    
    def action_generate(self):
        """Generar reporte de consumo de folios"""
        self.ensure_one()
        
        # TODO: Implementar en fase posterior
        # Por ahora, solo placeholder
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Generación de consumo de folios pendiente de implementación'),
                'type': 'info',
            }
        }

