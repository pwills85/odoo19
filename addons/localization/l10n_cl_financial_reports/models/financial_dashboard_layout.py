# -*- coding: utf-8 -*-
from odoo import models, fields, api

import json
import logging

_logger = logging.getLogger(__name__)

class FinancialDashboardLayout(models.Model):
    _name = 'financial.dashboard.layout'
    _description = 'Almacena la disposición personalizada del Dashboard Financiero por usuario'

    name = fields.Char(
        string='Nombre del Dashboard',
        required=True,
        help="Nombre descriptivo del dashboard"
    )
    user_id = fields.Many2one(
        'res.users',
        string='Usuario',
        required=True,
        ondelete='cascade',
        default=lambda self: self.env.user,
        help="Usuario al que pertenece esta configuración de layout."
    )
    widget_identifier = fields.Char(
        string='Identificador del Widget',
        help="Un identificador único para el widget, ej: 'kpi_total_sales'."
    )
    widget_template_id = fields.Many2one(
        'financial.dashboard.widget',
        string='Plantilla de Widget',
        ondelete='cascade',
        help="La plantilla que define el contenido y la apariencia de este widget."
    )
    pos_x = fields.Integer(string='Posición X', default=0)
    pos_y = fields.Integer(string='Posición Y', default=0)
    size_w = fields.Integer(string='Ancho', default=4)
    size_h = fields.Integer(string='Alto', default=2)

    # New fields for enhanced dashboard management
    layout_config = fields.Text(
        string='Configuración del Layout',
        help="Configuración completa del dashboard en formato JSON"
    )
    is_default = fields.Boolean(
        string='Dashboard por Defecto',
        default=False,
        help="Marcar como dashboard predeterminado para el usuario"
    )
    description = fields.Text(
        string='Descripción',
        help="Descripción del propósito del dashboard"
    )

    _sql_constraints = [
        ('user_widget_unique', 'unique(user_id, widget_identifier)',
         'La disposición para cada widget debe ser única por usuario.')
    ]

    @api.model
    def get_layout_for_user(self):
        """
        Devuelve la configuración del layout para el usuario actual,
        incluyendo la información de la plantilla.
        """
        # Optimización: usar with_context para prefetch
        layout = layout.with_context(prefetch_fields=False)

        user_layouts = self.search([('user_id', '=', self.env.uid)])
        return [{
            'id': layout.widget_identifier,
            'x': layout.pos_x,
            'y': layout.pos_y,
            'w': layout.size_w,
            'h': layout.size_h,
            'name': layout.widget_template_id.name,
            'service_model': layout.widget_template_id.data_service_model,
            'service_method': layout.widget_template_id.data_service_method,
        } for layout in user_layouts]

    @api.model
    def save_layout_for_user(self, layout_items):
        """
        Guarda la nueva configuración de layout para el usuario actual.
        """
        user_id = self.env.uid

        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for item in layout_items:
            identifier = item.get('id')
            if not identifier:
                continue

            existing_layout = self.search([
                ('user_id', '=', user_id),
                ('widget_identifier', '=', identifier)
            ])

            vals = {
                'user_id': user_id,
                'widget_identifier': identifier,
                'pos_x': item.get('x'),
                'pos_y': item.get('y'),
                'size_w': item.get('w'),
                'size_h': item.get('h'),
            }
            if existing_layout:
                existing_layout.write(vals)
            else:
                self.create(vals)
        return True

    def action_add_widget(self):
        """Open wizard to add a new widget to this dashboard"""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': f'Añadir Widget a {self.name}',
            'res_model': 'financial.dashboard.add.widget.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_dashboard_id': self.id,
                'default_title': 'Nuevo Widget',
            }
        }

    @api.model
    def create_default_dashboard(self, user_id=None):
        """Create a default dashboard for a user"""
        if not user_id:
            user_id = self.env.uid

        # Check if user already has a default dashboard
        existing = self.search([
            ('user_id', '=', user_id),
            ('is_default', '=', True)
        ])

        if existing:
            return existing

        # Create default dashboard
        dashboard = self.create({
            'name': 'Dashboard Principal',
            'user_id': user_id,
            'is_default': True,
            'description': 'Dashboard financiero principal del usuario',
            'layout_config': json.dumps({
                'widgets': [],
                'grid_options': {
                    'columns': 12,
                    'margin': 10,
                    'animate': True
                }
            }, indent=2)
        })

        return dashboard

    def get_widget_count(self):
        """Get the number of widgets in this dashboard"""
        self.ensure_one()
        if not self.layout_config:
            return 0

        try:
            config = json.loads(self.layout_config)
            return len(config.get('widgets', []))
        except (json.JSONDecodeError, TypeError):
            return 0

    @api.depends('layout_config')
    def _compute_widget_count(self):
        """Compute the number of widgets"""
        for dashboard in self:
            dashboard.widget_count = dashboard.get_widget_count()

    widget_count = fields.Integer(
        string='Número de Widgets',
        compute='_compute_widget_count',
        store=True,
        help="Número total de widgets en este dashboard"
    )
