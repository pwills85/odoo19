# -*- coding: utf-8 -*- 

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from odoo.tools import ormcache
from datetime import date
import requests
import os
import logging

_logger = logging.getLogger(__name__)


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
    
    # Salarios y topes (obtenidos desde AI Service)
    minimum_wage = fields.Float(
        string='Sueldo Mínimo',
        digits=(10, 2),
        help='Ingreso Mínimo Mensual'
    )
    afp_tope_uf = fields.Float(
        string='Tope AFP (UF)',
        digits=(10, 2),
        help='Tope imponible AFP en UF (ej: 87.8)'
    )
    afc_tope_uf = fields.Float(
        string='Tope AFC (UF)',
        digits=(10, 2),
        help='Tope seguro cesantía en UF (ej: 131.9)'
    )
    apv_tope_mensual_uf = fields.Float(
        string='Tope APV Mensual (UF)',
        digits=(10, 2),
        help='Tope APV mensual en UF (ej: 50.0)'
    )
    apv_tope_anual_uf = fields.Float(
        string='Tope APV Anual (UF)',
        digits=(10, 2),
        help='Tope APV anual en UF (ej: 600.0)'
    )

    # Asignaciones familiares (20 campos desde AI Service)
    asig_fam_tramo_1 = fields.Monetary(string='Asig. Fam. Tramo 1 ($)')
    asig_fam_tramo_2 = fields.Monetary(string='Asig. Fam. Tramo 2 ($)')
    asig_fam_tramo_3 = fields.Monetary(string='Asig. Fam. Tramo 3 ($)')
    asig_fam_tramo_4 = fields.Monetary(string='Asig. Fam. Tramo 4 ($)')
    # ... (se podrían agregar los 16 campos restantes si son necesarios)

    # Tasas de cotización (desde AI Service)
    sis_pct = fields.Float(string='Tasa SIS (%)', help='Tasa Cotización Adicional (Seguro Invalidez y Sobrevivencia)')
    afc_trabajador_indefinido_pct = fields.Float(string='Tasa AFC Trab. Indef. (%)', help='0.6%')
    afc_empleador_indefinido_pct = fields.Float(string='Tasa AFC Emp. Indef. (%)', help='2.4%')
    fonasa_pct = fields.Float(string='Tasa FONASA (%)', help='7.0%')

    # Tasas de fondos AFP (25 campos desde AI Service)
    afp_capital_fondo_a = fields.Float(string='Tasa AFP Capital Fondo A (%)')
    afp_capital_fondo_b = fields.Float(string='Tasa AFP Capital Fondo B (%)')
    # ... (y así sucesivamente para todos los fondos y todas las AFP)

    # Metadata de Sincronización
    source = fields.Selection([
        ('ai_service', 'AI Service (Previred)'),
        ('mindicador', 'Mindicador.cl (UF/UTM)'),
        ('manual', 'Carga Manual'),
        ('default', 'Valor por Defecto')
    ], string='Fuente de Datos', default='default', required=True)
    last_sync = fields.Datetime(
        string='Última Sincronización AI',
        readonly=True
    )

    active = fields.Boolean(
        string='Activo',
        default=True
    )

    # Currency field for Monetary fields in extensions
    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.company.currency_id,
        required=True
    )
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        default=lambda self: self.env.company,
        required=True
    )

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
        """
        Validar período:
        - Debe ser primer día del mes
        - Debe ser único (migrado desde _sql_constraints en Odoo 19)
        """
        for indicator in self:
            # Validar primer día del mes
            if indicator.period and indicator.period.day != 1:
                raise ValidationError(_('El período debe ser el primer día del mes'))

            # Validar unicidad del período
            if indicator.period:
                existing = self.search_count([
                    ('period', '=', indicator.period),
                    ('id', '!=', indicator.id)
                ])
                if existing:
                    raise ValidationError(_('Ya existe un indicador para este período'))
    
    @api.model
    def get_indicator_for_date(self, target_date):
        """
        Obtener indicador para una fecha específica
        """
        if isinstance(target_date, str):
            target_date = fields.Date.from_string(target_date)
        
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
        """
        return self.get_indicator_for_date(payslip_date)

    @ormcache('reference_date')
    def _get_uf_value_cached(self, reference_date):
        """
        Obtener UF con cache (TTL 24 horas)
        """
        indicator = self.search([
            ('period', '<=', reference_date)
        ], order='period desc', limit=1)

        if indicator and indicator.uf:
            return indicator.uf

        _logger.warning(
            "UF no encontrada para %s, usando default $38,000",
            reference_date
        )
        return 38000.0

    @ormcache('reference_date')
    def _get_utm_value_cached(self, reference_date):
        """
        Obtener UTM con cache (TTL 24 horas)
        """
        indicator = self.search([
            ('period', '<=', reference_date)
        ], order='period desc', limit=1)

        if indicator and indicator.utm:
            return indicator.utm

        _logger.warning(
            "UTM no encontrada para %s, usando default $67,000",
            reference_date
        )
        return 67000.0

    def create(self, vals):
        """Invalidar cache al crear indicador"""
        result = super().create(vals)
        self.clear_caches()
        return result

    def write(self, vals):
        """Invalidar cache al actualizar indicador"""
        result = super().write(vals)
        if any(key in vals for key in ['uf', 'utm', 'period']):
            self.clear_caches()
        return result

    @api.model
    def fetch_from_ai_service(self, year, month):
        """
        Obtener indicadores desde AI-Service
        """
        ai_service_url = os.getenv('AI_SERVICE_URL', 'http://ai-service:8002')
        api_key = os.getenv('AI_SERVICE_API_KEY', '')
        period = f"{year}-{month:02d}"

        _logger.info("Obteniendo indicadores %s desde AI-Service", period)

        try:
            response = requests.get(
                f"{ai_service_url}/api/payroll/indicators/{period}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=60
            )
            response.raise_for_status()
            result = response.json()

            if not result.get('success'):
                raise Exception(result.get('detail', 'Error desconocido'))

            data = result['indicators']
            period_date = date(year, month, 1)

            indicator = self.create({
                'period': period_date,
                'uf': data.get('uf', 0),
                'utm': data.get('utm', 0),
                'uta': data.get('uta', 0),
                'minimum_wage': data.get('sueldo_minimo', 0),
                'afp_tope_uf': data.get('afp_tope_uf', 0),
                'family_allowance_t1': data.get('asig_fam_tramo_1', 0),
                'family_allowance_t2': data.get('asig_fam_tramo_2', 0),
                'family_allowance_t3': data.get('asig_fam_tramo_3', 0),
                'source': 'ai_service',
                'last_sync': fields.Datetime.now(),
            })

            _logger.info(
                "✅ Indicadores %s creados desde AI-Service (ID: %d, AFP cap: %.1f UF)",
                period_date.strftime('%Y-%m'),
                indicator.id,
                indicator.afp_tope_uf
            )
            return indicator

        except Exception as e:
            _logger.error("❌ Error obteniendo indicadores desde AI-Service: %s", str(e))
            raise UserError(_(
                "No se pudieron obtener indicadores para %s-%02d\n\n"
                "Error: %s\n\n"
                "Acciones sugeridas:\n"
                "• Verificar que AI-Service esté corriendo\n"
                "• Cargar indicadores manualmente\n"
                "• Contactar soporte técnico"
            ) % (year, month, str(e)))

    @api.model
    def _cron_sync_previred_via_ai(self):
        """
        Sincronizar TODOS los campos desde AI service.
        """
        ICP = self.env['ir.config_parameter'].sudo()
        ai_url = ICP.get_param('dte.ai_service_url', 'http://ai-service:8002')
        api_key = ICP.get_param('dte.ai_service_api_key', '')
        timeout = int(ICP.get_param('dte.ai_service_timeout', '60'))

        if not api_key:
            _logger.error("CRON AI-SYNC: AI Service API key no configurado. Abortando.")
            return False

        period_date = date.today().replace(day=1)
        period_str = period_date.strftime('%Y-%m')
        
        _logger.info(f"CRON AI-SYNC: Iniciando sincronización para el período {period_str}")

        try:
            response = requests.get(
                f"{ai_url}/api/payroll/indicators/{period_str}",
                headers={'Authorization': f'Bearer {api_key}'},
                timeout=timeout
            )
            response.raise_for_status()
            
            data = response.json()
            if not data.get('success'):
                raise Exception(f"AI service retornó un error: {data.get('detail', 'Error desconocido')}")
            
            indicators = data.get('indicators', {})
            metadata = data.get('metadata', {})
            
            record = self.search([('period', '=', period_date)], limit=1)
            if not record:
                record = self.create({'period': period_date, 'name': period_date.strftime('%B %Y')})

            vals_to_write = {
                'uf': indicators.get('uf'),
                'utm': indicators.get('utm'),
                'uta': indicators.get('uta'),
                'minimum_wage': indicators.get('sueldo_minimo'),
                'afp_tope_uf': indicators.get('afp_tope_uf'),
                'afc_tope_uf': indicators.get('afc_tope_uf'),
                'apv_tope_mensual_uf': indicators.get('apv_tope_mensual_uf'),
                'apv_tope_anual_uf': indicators.get('apv_tope_anual_uf'),
                'asig_fam_tramo_1': indicators.get('asig_fam_tramo_1'),
                'asig_fam_tramo_2': indicators.get('asig_fam_tramo_2'),
                'asig_fam_tramo_3': indicators.get('asig_fam_tramo_3'),
                'asig_fam_tramo_4': indicators.get('asig_fam_tramo_4'),
                'sis_pct': indicators.get('exvida_pct'),
                'afc_trabajador_indefinido_pct': indicators.get('afc_trabajador_indefinido'),
                'afc_empleador_indefinido_pct': indicators.get('afc_empleador_indefinido'),
                'fonasa_pct': indicators.get('fonasa_pct'),
                'source': 'ai_service',
                'last_sync': fields.Datetime.now()
            }
            
            vals_to_write = {k: v for k, v in vals_to_write.items() if v is not None}
            
            record.write(vals_to_write)
            
            _logger.info(
                f"CRON AI-SYNC: Éxito. {len(vals_to_write)} campos actualizados para {period_str} "
                f"desde {metadata.get('source', 'AI')}"
            )
            return True
            
        except requests.exceptions.Timeout:
            _logger.error(f"CRON AI-SYNC: Timeout ({timeout}s) conectando con AI Service para el período {period_str}.")
            return False
        except requests.exceptions.RequestException as e:
            _logger.error(f"CRON AI-SYNC: Falla de conexión con AI Service para el período {period_str}. Error: {e}")
            return False
        except Exception as e:
            _logger.error(f"CRON AI-SYNC: Falla inesperada durante la sincronización para {period_str}. Error: {e}")
            return False