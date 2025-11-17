# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import date


class HrTaxBracket(models.Model):
    """
    Tramos Impuesto Único Segunda Categoría Chile
    
    Modelo parametrizado para tramos de impuesto según SII.
    Permite versionamiento y actualización anual sin tocar código.
    
    Fuente: Ley de Impuesto a la Renta, Art. 43 bis
    """
    _name = 'hr.tax.bracket'
    _description = 'Tramos Impuesto Único Chile'
    _order = 'vigencia_desde desc, desde'
    
    name = fields.Char(
        string='Nombre',
        compute='_compute_name',
        store=True
    )
    
    # Tramo
    tramo = fields.Integer(
        string='Tramo',
        required=True,
        help='Número de tramo (1-8)'
    )
    
    # Rangos en UTM
    desde = fields.Float(
        string='Desde (UTM)',
        digits=(10, 2),
        required=True,
        help='Límite inferior del tramo en UTM'
    )
    hasta = fields.Float(
        string='Hasta (UTM)',
        digits=(10, 2),
        help='Límite superior del tramo en UTM (0 = infinito)'
    )
    
    # Fórmula tributaria
    tasa = fields.Float(
        string='Tasa (%)',
        digits=(5, 2),
        required=True,
        help='Porcentaje de impuesto a aplicar'
    )
    rebaja = fields.Float(
        string='Rebaja (UTM)',
        digits=(10, 2),
        default=0.0,
        help='Factor de rebaja en UTM'
    )
    
    # Vigencia
    vigencia_desde = fields.Date(
        string='Vigente Desde',
        required=True,
        default=lambda self: date.today().replace(month=1, day=1),
        help='Fecha inicio de vigencia (primer día del mes)'
    )
    vigencia_hasta = fields.Date(
        string='Vigente Hasta',
        help='Fecha fin de vigencia (vacío = indefinido)'
    )
    
    active = fields.Boolean(
        string='Activo',
        default=True
    )

    @api.constrains('tramo', 'vigencia_desde', 'vigencia_hasta')
    def _check_tramo_vigencia_unique(self):
        """Validar que no existan duplicados de tramo+vigencia (migrado desde _sql_constraints en Odoo 19)"""
        for bracket in self:
            domain = [
                ('tramo', '=', bracket.tramo),
                ('vigencia_desde', '=', bracket.vigencia_desde),
                ('id', '!=', bracket.id)
            ]
            # Si vigencia_hasta está definido, también lo validamos
            if bracket.vigencia_hasta:
                domain.append(('vigencia_hasta', '=', bracket.vigencia_hasta))
            else:
                # Si vigencia_hasta es False/None, buscamos otros con False/None también
                domain.append(('vigencia_hasta', '=', False))

            existing = self.search_count(domain)
            if existing:
                raise ValidationError(_('Ya existe un tramo con la misma vigencia'))

    @api.depends('tramo', 'desde', 'hasta', 'tasa', 'vigencia_desde')
    def _compute_name(self):
        """Generar nombre descriptivo del tramo"""
        for bracket in self:
            if bracket.hasta > 0:
                rango = f"{bracket.desde:.1f} - {bracket.hasta:.1f} UTM"
            else:
                rango = f"> {bracket.desde:.1f} UTM"
            
            vigencia = bracket.vigencia_desde.strftime('%Y') if bracket.vigencia_desde else '?'
            bracket.name = f"Tramo {bracket.tramo}: {rango} ({bracket.tasa}%) - {vigencia}"
    
    @api.constrains('desde', 'hasta')
    def _check_range(self):
        """Validar rangos del tramo"""
        for bracket in self:
            if bracket.desde < 0:
                raise ValidationError(_("El límite inferior no puede ser negativo"))
            
            if bracket.hasta > 0 and bracket.hasta <= bracket.desde:
                raise ValidationError(_(
                    "El límite superior debe ser mayor al límite inferior"
                ))
    
    @api.constrains('tasa')
    def _check_tasa(self):
        """Validar tasa de impuesto"""
        for bracket in self:
            if bracket.tasa < 0 or bracket.tasa > 100:
                raise ValidationError(_("La tasa debe estar entre 0% y 100%"))
    
    @api.constrains('vigencia_desde', 'vigencia_hasta')
    def _check_vigencia(self):
        """Validar fechas de vigencia"""
        for bracket in self:
            # Debe ser primer día del mes
            if bracket.vigencia_desde and bracket.vigencia_desde.day != 1:
                raise ValidationError(_(
                    "La vigencia debe comenzar el primer día del mes"
                ))
            
            if bracket.vigencia_hasta:
                if bracket.vigencia_hasta.day != 1:
                    raise ValidationError(_(
                        "La vigencia debe terminar el primer día del mes"
                    ))
                
                if bracket.vigencia_hasta <= bracket.vigencia_desde:
                    raise ValidationError(_(
                        "La fecha de fin debe ser posterior a la fecha de inicio"
                    ))
    
    @api.model
    def get_brackets_for_date(self, target_date):
        """
        Obtener tramos vigentes para una fecha
        
        Args:
            target_date: Fecha para buscar tramos (Date o str)
            
        Returns:
            Recordset con tramos vigentes ordenados por 'desde'
        """
        if isinstance(target_date, str):
            target_date = fields.Date.from_string(target_date)
        
        # Buscar tramos vigentes
        domain = [
            ('vigencia_desde', '<=', target_date),
            '|',
            ('vigencia_hasta', '=', False),
            ('vigencia_hasta', '>', target_date)
        ]
        
        brackets = self.search(domain, order='desde')
        
        if not brackets:
            raise ValidationError(_(
                'No se encontraron tramos de impuesto vigentes para %s. '
                'Por favor, configure los tramos en Configuración > Impuesto Único.'
            ) % target_date.strftime('%Y-%m-%d'))
        
        return brackets
    
    @api.model
    def calculate_tax(self, base_tributable, target_date, extreme_zone=False):
        """
        Calcular impuesto único según tramos vigentes
        
        Args:
            base_tributable: Base imponible en CLP
            target_date: Fecha del cálculo
            extreme_zone: Rebaja 50% zona extrema
            
        Returns:
            float: Monto de impuesto a descontar
        """
        brackets = self.get_brackets_for_date(target_date)
        
        # Obtener indicador para convertir UTM a CLP
        indicator = self.env['hr.economic.indicators'].get_indicator_for_date(target_date)
        utm_clp = indicator.utm
        
        # Convertir base a UTM
        base_utm = base_tributable / utm_clp
        
        # Buscar tramo correspondiente
        bracket = None
        for b in brackets:
            if b.hasta == 0:  # Tramo sin límite superior
                if base_utm >= b.desde:
                    bracket = b
                    break
            else:
                if b.desde <= base_utm < b.hasta:
                    bracket = b
                    break
        
        if not bracket:
            # Si no hay tramo, está exento
            return 0.0
        
        # Calcular impuesto: (Base * Tasa) - Rebaja
        tax_utm = (base_utm * bracket.tasa / 100.0) - bracket.rebaja
        tax_clp = tax_utm * utm_clp
        
        # Aplicar rebaja zona extrema (50%)
        if extreme_zone:
            tax_clp = tax_clp * 0.5
        
        # El impuesto no puede ser negativo
        return max(0.0, tax_clp)
