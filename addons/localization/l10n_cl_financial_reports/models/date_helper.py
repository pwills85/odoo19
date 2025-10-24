# -*- coding: utf-8 -*-
"""
Date Helper Model para Odoo 18
Proporciona campos computados para fechas en vistas XML
Compatible con Odoo 18 que no permite expresiones complejas en dominios
"""
from odoo import models, fields, api
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta


class DateHelper(models.TransientModel):
    """Helper para proporcionar fechas computadas en vistas XML."""
    _name = 'account.date.helper'
    _description = 'Helper de Fechas para Reportes Financieros'
    
    # Fechas actuales
    today = fields.Date(
        string="Hoy",
        compute='_compute_dates',
        search='_search_today'
    )
    
    current_month = fields.Integer(
        string="Mes Actual",
        compute='_compute_dates'
    )
    
    current_year = fields.Integer(
        string="Año Actual", 
        compute='_compute_dates'
    )
    
    # Fechas del mes anterior
    last_month_start = fields.Date(
        string="Inicio Mes Anterior",
        compute='_compute_dates'
    )
    
    last_month_end = fields.Date(
        string="Fin Mes Anterior",
        compute='_compute_dates'
    )
    
    # Fechas del trimestre actual
    current_quarter_start = fields.Date(
        string="Inicio Trimestre Actual",
        compute='_compute_dates'
    )
    
    current_quarter_end = fields.Date(
        string="Fin Trimestre Actual",
        compute='_compute_dates'
    )
    
    # Fechas del año fiscal
    fiscal_year_start = fields.Date(
        string="Inicio Año Fiscal",
        compute='_compute_dates'
    )
    
    fiscal_year_end = fields.Date(
        string="Fin Año Fiscal",
        compute='_compute_dates'
    )
    
    @api.depends()
    def _compute_dates(self):
        """Calcula todas las fechas auxiliares según Odoo 18."""
        for record in self:
            # Usar fields.Date.context_today para obtener fecha según timezone
            today = fields.Date.context_today(record)
            
            record.today = today
            record.current_month = today.month
            record.current_year = today.year
            
            # Mes anterior
            last_month = today - relativedelta(months=1)
            record.last_month_start = last_month.replace(day=1)
            record.last_month_end = today.replace(day=1) - timedelta(days=1)
            
            # Trimestre actual
            quarter = (today.month - 1) // 3
            quarter_start_month = quarter * 3 + 1
            record.current_quarter_start = today.replace(month=quarter_start_month, day=1)
            
            if quarter_start_month + 2 <= 12:
                quarter_end = today.replace(month=quarter_start_month + 2)
                # Último día del mes
                next_month = quarter_end + relativedelta(months=1, day=1)
                record.current_quarter_end = next_month - timedelta(days=1)
            else:
                record.current_quarter_end = today.replace(month=12, day=31)
            
            # Año fiscal (asumiendo año calendario)
            record.fiscal_year_start = today.replace(month=1, day=1)
            record.fiscal_year_end = today.replace(month=12, day=31)
    
    def _search_today(self, operator, value):
        """Permite búsquedas por fecha actual."""
        # Este método es requerido cuando se usa search en campos computados
        return [('id', '!=', False)]