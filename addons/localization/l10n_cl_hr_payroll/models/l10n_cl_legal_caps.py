# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import date


class L10nClLegalCaps(models.Model):
    """
    Topes Legales Parametrizados Chile
    
    Almacena límites legales dinámicos que cambian con el tiempo:
    - Tope APV mensual (50 UF)
    - Tope APV anual (600 UF)
    - Tope AFC (120.2 UF)
    - Etc.
    
    Permite actualizar topes sin modificar código.
    """
    _name = 'l10n_cl.legal.caps'
    _description = 'Legal Caps Chile'
    _order = 'code, valid_from desc'
    
    name = fields.Char(
        string='Name',
        compute='_compute_name',
        store=True
    )
    
    code = fields.Selection([
        ('APV_CAP_MONTHLY', 'APV - Tope Mensual'),
        ('APV_CAP_ANNUAL', 'APV - Tope Anual'),
        ('AFC_CAP', 'AFC - Tope Imponible'),
        ('GRATIFICATION_CAP', 'Gratificación - Tope Legal'),
    ], string='Code', required=True)
    
    amount = fields.Float(
        string='Amount',
        required=True,
        help='Valor del tope'
    )
    
    unit = fields.Selection([
        ('uf', 'UF'),
        ('utm', 'UTM'),
        ('clp', 'CLP'),
        ('percent', '%'),
    ], string='Unit', required=True, default='uf')
    
    valid_from = fields.Date(
        string='Valid From',
        required=True,
        default=lambda self: date.today().replace(month=1, day=1),
        help='Fecha inicio de vigencia (primer día del mes)'
    )
    
    valid_until = fields.Date(
        string='Valid Until',
        help='Fecha fin de vigencia (vacío = indefinido)'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True
    )
    
    _sql_constraints = [
        ('code_valid_from_unique', 
         'UNIQUE(code, valid_from)', 
         'Ya existe un tope con el mismo código y vigencia'),
    ]
    
    @api.depends('code', 'amount', 'unit', 'valid_from')
    def _compute_name(self):
        """Generar nombre descriptivo"""
        code_names = dict(self._fields['code'].selection)
        for cap in self:
            code_label = code_names.get(cap.code, cap.code)
            unit_label = cap.unit.upper() if cap.unit else ''
            date_str = cap.valid_from.strftime('%Y') if cap.valid_from else '?'
            cap.name = f"{code_label}: {cap.amount} {unit_label} ({date_str})"
    
    @api.constrains('valid_from', 'valid_until')
    def _check_validity_dates(self):
        """Validar fechas de vigencia"""
        for cap in self:
            if cap.valid_from and cap.valid_from.day != 1:
                raise ValidationError(_(
                    "La vigencia debe comenzar el primer día del mes"
                ))
            
            if cap.valid_until:
                if cap.valid_until.day != 1:
                    raise ValidationError(_(
                        "La vigencia debe terminar el primer día del mes"
                    ))
                
                if cap.valid_until <= cap.valid_from:
                    raise ValidationError(_(
                        "La fecha de fin debe ser posterior a la fecha de inicio"
                    ))
    
    @api.model
    def get_cap(self, code, target_date=None):
        """
        Obtener tope vigente para una fecha
        
        Args:
            code: Código del tope (ej: 'APV_CAP_MONTHLY')
            target_date: Fecha para buscar (default: hoy)
            
        Returns:
            float: Valor del tope en la unidad especificada
        """
        if target_date is None:
            target_date = date.today()
        
        if isinstance(target_date, str):
            target_date = fields.Date.from_string(target_date)
        
        # Buscar tope vigente
        domain = [
            ('code', '=', code),
            ('valid_from', '<=', target_date),
            '|',
            ('valid_until', '=', False),
            ('valid_until', '>', target_date)
        ]
        
        cap = self.search(domain, order='valid_from desc', limit=1)
        
        if not cap:
            raise ValidationError(_(
                'No se encontró tope legal "%s" vigente para %s. '
                'Por favor, configure los topes en Configuración > Legal Caps.'
            ) % (code, target_date.strftime('%Y-%m-%d')))
        
        return cap.amount, cap.unit
