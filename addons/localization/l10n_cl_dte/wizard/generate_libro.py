# -*- coding: utf-8 -*-

from odoo import models, fields, _


class GenerateLibroWizard(models.TransientModel):
    """Wizard para generar libro de compra/venta"""
    _name = 'generate.libro.wizard'
    _description = 'Generar Libro Compra/Venta'
    
    period_start = fields.Date(string='Período Desde', required=True)
    period_end = fields.Date(string='Período Hasta', required=True)
    tipo_libro = fields.Selection([
        ('venta', 'Libro de Ventas'),
        ('compra', 'Libro de Compras'),
    ], string='Tipo de Libro', required=True, default='venta')
    
    def action_generate(self):
        """Generar libro electrónico"""
        self.ensure_one()
        
        # TODO: Implementar en fase posterior
        # Por ahora, solo placeholder
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('En Desarrollo'),
                'message': _('Generación de libro electrónico pendiente de implementación'),
                'type': 'info',
            }
        }

