# -*- coding: utf-8 -*-
"""
Base Financial Service
Clase base para todos los servicios financieros con funcionalidad común
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging
from datetime import datetime, timedelta
from collections import defaultdict

_logger = logging.getLogger(__name__)


class BaseFinancialService(models.AbstractModel):
    """Clase base abstracta para servicios financieros."""
    
    _name = 'base.financial.service'
    _description = 'Base Financial Service'
    
    # Campos comunes
    name = fields.Char(string='Nombre', required=True)
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )
    date_from = fields.Date(string='Fecha Desde', required=True)
    date_to = fields.Date(string='Fecha Hasta', required=True)
    
    # Cache configuration
    _cache_timeout = 300  # 5 minutos por defecto
    
    def _get_cache_key(self, prefix=''):
        """Genera clave de cache única."""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        self.ensure_one()
        return f'{prefix}_{self._name}_{self.company_id.id}_{self.date_from}_{self.date_to}'
    
    def _get_cached_data(self, cache_key):
        """Obtiene datos del cache si existen."""
        return self.env.cache.get(cache_key)
    
    def _set_cached_data(self, cache_key, data, timeout=None):
        """Guarda datos en cache."""
        if timeout is None:
            timeout = self._cache_timeout
        self.env.cache.set(cache_key, data, timeout=timeout)
    
    def _get_account_move_lines(self, additional_domain=None):
        """Obtiene líneas de asientos con dominio base."""
        self.ensure_one()
        
        domain = [
            ('company_id', '=', self.company_id.id),
            ('date', '>=', self.date_from),
            ('date', '<=', self.date_to),
            ('parent_state', '=', 'posted')
        ]
        
        if additional_domain:
            domain.extend(additional_domain)
        
        return self.env['account.move.line'].search(domain)
    
    def _sum_by_account_type(self, move_lines, account_types):
        """Suma balances por tipo de cuenta."""
        if isinstance(account_types, str):
            account_types = [account_types]
        
        return sum(
            line.balance for line in move_lines
            if line.account_id.account_type in account_types
        )
    
    def _group_by_period(self, move_lines, period='month'):
        """Agrupa líneas por período."""
        grouped = defaultdict(lambda: {'debit': 0, 'credit': 0, 'balance': 0})
        
        for line in move_lines:
            if period == 'month':
                key = line.date.strftime('%Y-%m')
            elif period == 'quarter':
                quarter = (line.date.month - 1) // 3 + 1
                key = f'{line.date.year}-Q{quarter}'
            elif period == 'year':
                key = str(line.date.year)
            else:
                key = str(line.date)
            
            grouped[key]['debit'] += line.debit
            grouped[key]['credit'] += line.credit
            grouped[key]['balance'] += line.balance
        
        return dict(grouped)
    
    def _prepare_chart_data(self, data_dict, chart_type='line'):
        """Prepara datos para gráficos."""
        labels = list(data_dict.keys())
        values = [item['balance'] for item in data_dict.values()]
        
        chart_data = {
            'labels': labels,
            'datasets': [{
                'label': self.name,
                'data': values,
                'borderColor': 'rgb(75, 192, 192)',
                'backgroundColor': 'rgba(75, 192, 192, 0.2)',
            }]
        }
        
        if chart_type == 'bar':
            chart_data['datasets'][0]['backgroundColor'] = 'rgba(54, 162, 235, 0.2)'
            chart_data['datasets'][0]['borderColor'] = 'rgb(54, 162, 235)'
        
        return chart_data
    
    @api.model
    def _format_currency(self, amount, currency=None):
        """Formatea monto a moneda."""
        if not currency:
            currency = self.env.company.currency_id
        return f'{currency.symbol} {amount:,.2f}'
    
    @api.model
    def _calculate_variation(self, current, previous):
        """Calcula variación porcentual."""
        if not previous:
            return 0.0
        return ((current - previous) / abs(previous)) * 100
    
    def _validate_date_range(self):
        """Valida que el rango de fechas sea válido."""
        self.ensure_one()
        if self.date_from > self.date_to:
            raise UserError(_("La fecha desde no puede ser mayor a la fecha hasta."))
        
        # Verificar que no sea un rango muy amplio (máximo 5 años)
        days_diff = (self.date_to - self.date_from).days
        if days_diff > 1825:  # 5 años
            raise UserError(_("El rango de fechas no puede exceder 5 años."))
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para validaciones."""
        records = super().create(vals_list)
        for record in records:
            record._validate_date_range()
        return records
    
    def write(self, vals):
        """Override write para validaciones."""
        res = super().write(vals)
        if 'date_from' in vals or 'date_to' in vals:
            self._validate_date_range()
        return res
