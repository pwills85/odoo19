# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import date


class HrEconomicIndicators(models.Model):
    """
    Indicadores Económicos Mensuales Chile
    
    Almacena valores históricos de UF, UTM, UTA y otros indicadores
    necesarios para cálculos de nómina.
    
    Fuente: Previred, SII, Banco Central
    """
    _name = 'hr.economic.indicators'
    _description = 'Indicadores Económicos Chile'
    _order = 'period desc'
    
    name = fields.Char(
        string='Nombre',
        compute='_compute_name',
        store=True
    )
    period = fields.Date(
        string='Período',
        required=True,
        help='Primer día del mes del indicador'
    )
    
    # Indicadores principales
    uf = fields.Float(
        string='UF',
        digits=(10, 2),
        required=True,
        help='Unidad de Fomento'
    )
    utm = fields.Float(
        string='UTM',
        digits=(10, 2),
        required=True,
        help='Unidad Tributaria Mensual'
    )
    uta = fields.Float(
        string='UTA',
        digits=(10, 2),
        required=True,
        help='Unidad Tributaria Anual'
    )
    
    # Salarios y topes
    minimum_wage = fields.Float(
        string='Sueldo Mínimo',
        digits=(10, 2),
        required=True,
        help='Ingreso Mínimo Mensual'
    )
    afp_limit = fields.Float(
        string='Tope AFP (UF)',
        digits=(10, 2),
        default=83.1,
        help='Tope imponible AFP en UF (83.1 UF)'
    )
    
    # Asignaciones familiares
    family_allowance_t1 = fields.Float(
        string='Asignación Familiar Tramo 1',
        digits=(10, 2),
        help='Hasta $439,242'
    )
    family_allowance_t2 = fields.Float(
        string='Asignación Familiar Tramo 2',
        digits=(10, 2),
        help='$439,243 - $641,914'
    )
    family_allowance_t3 = fields.Float(
        string='Asignación Familiar Tramo 3',
        digits=(10, 2),
        help='$641,915 - $1,000,381'
    )
    
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    _sql_constraints = [
        ('period_unique', 'UNIQUE(period)', 'Ya existe un indicador para este período'),
    ]
    
    @api.depends('period')
    def _compute_name(self):
        """Generar nombre del indicador"""
        for indicator in self:
            if indicator.period:
                indicator.name = indicator.period.strftime('%B %Y')
            else:
                indicator.name = 'Nuevo Indicador'
    
    @api.constrains('period')
    def _check_period(self):
        """Validar que el período sea primer día del mes"""
        for indicator in self:
            if indicator.period and indicator.period.day != 1:
                raise ValidationError(_('El período debe ser el primer día del mes'))
    
    @api.model
    def get_indicator_for_date(self, target_date):
        """
        Obtener indicador para una fecha específica
        
        Args:
            target_date: Fecha para buscar indicador
            
        Returns:
            Recordset con el indicador del mes correspondiente
        """
        if isinstance(target_date, str):
            target_date = fields.Date.from_string(target_date)
        
        # Buscar indicador del mes
        period = date(target_date.year, target_date.month, 1)
        indicator = self.search([('period', '=', period)], limit=1)
        
        if not indicator:
            raise ValidationError(_(
                'No se encontró indicador económico para el período %s. '
                'Por favor, cargue los indicadores del mes.'
            ) % period.strftime('%B %Y'))
        
        return indicator
    
    @api.model
    def get_indicator_for_payslip(self, payslip_date):
        """
        Obtener indicador para cálculo de nómina
        
        Alias de get_indicator_for_date con mensaje más específico
        """
        return self.get_indicator_for_date(payslip_date)
    
    @api.model
    def fetch_from_ai_service(self, year, month):
        """
        Obtener indicadores desde AI-Service
        
        TODO: Implementar integración con AI-Service
        Por ahora retorna error indicando que debe cargarse manualmente
        
        Args:
            year: Año (2025)
            month: Mes (1-12)
        
        Returns:
            Recordset hr.economic.indicators creado
        """
        import requests
        import os
        
        # URL del AI-Service
        ai_service_url = os.getenv('AI_SERVICE_URL', 'http://ai-service:8000')
        api_key = os.getenv('AI_SERVICE_API_KEY', '')
        
        _logger.info(
            "Obteniendo indicadores %s-%02d desde AI-Service",
            year, month
        )
        
        try:
            # Llamar AI-Service
            response = requests.post(
                f"{ai_service_url}/api/ai/payroll/previred/extract",
                json={"period": f"{year}-{month:02d}"},
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=60
            )
            
            response.raise_for_status()
            result = response.json()
            
            if not result.get('success'):
                raise Exception(result.get('detail', 'Error desconocido'))
            
            # Extraer indicadores
            data = result['indicators']
            
            # Crear registro
            period = date(year, month, 1)
            
            indicator = self.create({
                'period': period,
                'uf': data.get('uf', 0),
                'utm': data.get('utm', 0),
                'uta': data.get('uta', 0),
                'minimum_wage': data.get('sueldo_minimo', 0),
                'afp_limit': data.get('afp_tope_uf', 87.8),
                'family_allowance_t1': data.get('asig_fam_tramo_1', 0),
                'family_allowance_t2': data.get('asig_fam_tramo_2', 0),
                'family_allowance_t3': data.get('asig_fam_tramo_3', 0),
            })
            
            _logger.info(
                "✅ Indicadores %s creados desde AI-Service (ID: %d)",
                period.strftime('%Y-%m'),
                indicator.id
            )
            
            return indicator
            
        except Exception as e:
            _logger.error(
                "❌ Error obteniendo indicadores desde AI-Service: %s",
                str(e)
            )
            
            raise UserError(_(
                "No se pudieron obtener indicadores para %s-%02d\n\n"
                "Error: %s\n\n"
                "Acciones sugeridas:\n"
                "• Verificar que AI-Service esté corriendo\n"
                "• Cargar indicadores manualmente\n"
                "• Contactar soporte técnico"
            ) % (year, month, str(e)))
