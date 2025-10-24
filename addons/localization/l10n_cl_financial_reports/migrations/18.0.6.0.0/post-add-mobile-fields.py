# -*- coding: utf-8 -*-
from odoo import SUPERUSER_ID, api

def migrate(cr, version):
    """Add mobile priority to existing widgets"""
    env = api.Environment(cr, SUPERUSER_ID, {})
    
    # Set default mobile priorities for existing widgets
    widget_priorities = {
        'kpi': 10,  # KPIs have highest priority on mobile
        'gauge': 8,
        'metric_trend': 8,
        'sparkline': 6,
        'chart_pie': 5,
        'chart_doughnut': 5,
        'chart_line': 4,
        'chart_bar': 4,
        'chart_area': 3,
        'table': 2,
        'heatmap': 1,
    }
    
    widgets = env['financial.dashboard.widget'].search([])
    for widget in widgets:
        if widget.widget_type in widget_priorities:
            widget.mobile_priority = widget_priorities[widget.widget_type]
            
            # Set appropriate mobile sizes based on widget type
            if widget.widget_type == 'kpi':
                widget.mobile_size_w = 6  # Half width on mobile
                widget.mobile_size_h = 1
            elif widget.widget_type in ['gauge', 'metric_trend']:
                widget.mobile_size_w = 6
                widget.mobile_size_h = 2
            elif widget.widget_type.startswith('chart_'):
                widget.mobile_size_w = 12  # Full width for charts
                widget.mobile_size_h = 3
            elif widget.widget_type == 'table':
                widget.mobile_size_w = 12
                widget.mobile_size_h = 4
            else:
                widget.mobile_size_w = 12
                widget.mobile_size_h = 2