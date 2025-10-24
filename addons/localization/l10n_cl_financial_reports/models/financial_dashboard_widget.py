# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.exceptions import ValidationError

import logging

_logger = logging.getLogger(__name__)

class FinancialDashboardWidget(models.Model):
    _name = 'financial.dashboard.widget'
    _description = 'Plantilla para Widgets del Dashboard Financiero'
    _order = 'sequence, name'

    name = fields.Char(
        string='Nombre del Widget', 
        required=True, 
        translate=True,
        help="Nombre descriptivo que verá el usuario en la biblioteca. Ej: 'KPI: Ventas Netas'."
    )
    sequence = fields.Integer(string='Secuencia', default=10)
    widget_type = fields.Selection([
        ('kpi', 'KPI Card'),
        ('chart_line', 'Line Chart'),
        ('chart_bar', 'Bar Chart'),
        ('chart_pie', 'Pie Chart'),
        ('chart_doughnut', 'Doughnut Chart'),
        ('chart_area', 'Area Chart'),
        ('table', 'Data Table'),
        ('gauge', 'Gauge Meter'),
        ('heatmap', 'Heat Map'),
        ('sparkline', 'Sparkline'),
        ('metric_trend', 'Metric with Trend'),
    ], string='Tipo de Widget', required=True, default='kpi')
    
    data_service_model = fields.Char(
        string='Modelo del Servicio de Datos',
        help="Nombre técnico del modelo de Odoo que provee los datos. Ej: 'account.ratio.analysis.service'."
    )
    data_service_method = fields.Char(
        string='Método del Servicio de Datos',
        help="Nombre del método en el modelo de servicio que será llamado para obtener los datos del widget."
    )
    
    default_size_w = fields.Integer(string='Ancho por Defecto', default=4)
    default_size_h = fields.Integer(string='Alto por Defecto', default=2)

    icon = fields.Char(string='Icono FontAwesome', default='fa-line-chart', help="Icono a mostrar en la biblioteca de widgets.")
    
    # Mobile specific fields
    mobile_priority = fields.Integer(
        string='Prioridad Móvil',
        default=0,
        help="Prioridad del widget en dispositivos móviles. Mayor número = mayor prioridad. 0 = no mostrar en móvil."
    )
    mobile_size_w = fields.Integer(
        string='Ancho Móvil',
        default=12,
        help="Ancho del widget en dispositivos móviles (columnas de 12)"
    )
    mobile_size_h = fields.Integer(
        string='Alto Móvil',
        default=1,
        help="Alto del widget en dispositivos móviles"
    )
    
    # Performance settings
    refresh_interval = fields.Integer(
        string='Intervalo de Actualización (segundos)',
        default=300,
        help="Frecuencia de actualización automática del widget. 0 = sin actualización automática."
    )
    enable_cache = fields.Boolean(
        string='Habilitar Caché',
        default=True,
        help="Habilitar caché de datos para mejorar el rendimiento"
    )
    cache_duration = fields.Integer(
        string='Duración del Caché (segundos)',
        default=300,
        help="Tiempo que los datos permanecen en caché antes de actualizarse"
    )
    
    @api.depends('widget_type', 'data_service_model', 'data_service_method')
    def _compute_display_name(self):
        for widget in self:
            widget.display_name = f"{widget.name} ({widget.widget_type})"
    
    def get_widget_data(self, filters=None):
        """Get widget data from the configured service"""
        self.ensure_one()
        
        if not self.data_service_model or not self.data_service_method:
            return {'value': 0, 'label': 'No configurado'}
        
        try:
            # Get the service model
            Service = self.env[self.data_service_model]
            
            # Call the service method
            method = getattr(Service, self.data_service_method, None)
            if not method:
                raise ValidationError(f"Method {self.data_service_method} not found in {self.data_service_model}")
            
            # Pass filters if the method accepts them
            result = method(filters) if filters else method()
            
            return result
        except Exception as e:
            _logger.error(f"Error: {e}", exc_info=True)
            return {
                'error': True,
                'message': str(e),
                'value': 0
            }
