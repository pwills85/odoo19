# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
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

        Fix GAP-002: Elimina hardcoded AFP cap (87.8 UF), usa tabla legal.caps

        Args:
            year: Año (2025)
            month: Mes (1-12)

        Returns:
            Recordset hr.economic.indicators creado
        """
        import requests
        import os
        import logging

        _logger = logging.getLogger(__name__)

        # URL del AI-Service (puerto correcto: 8002, no 8000)
        ai_service_url = os.getenv('AI_SERVICE_URL', 'http://ai-service:8002')
        api_key = os.getenv('AI_SERVICE_API_KEY', '')

        period = f"{year}-{month:02d}"

        _logger.info(
            "Obteniendo indicadores %s desde AI-Service",
            period
        )

        try:
            # Llamar AI-Service (GET, no POST - endpoint correcto)
            response = requests.get(  # ✅ GET en vez de POST
                f"{ai_service_url}/api/payroll/indicators/{period}",  # ✅ Endpoint correcto
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=60  # Puede tardar 15-30s en descargar PDF
            )

            response.raise_for_status()
            result = response.json()

            if not result.get('success'):
                raise Exception(result.get('detail', 'Error desconocido'))

            # Extraer indicadores
            data = result['indicators']

            # Crear registro
            period_date = date(year, month, 1)

            # GAP-002: Obtener tope AFP desde tabla l10n_cl.legal.caps
            afp_cap_uf = self._get_afp_cap_from_legal_table(period_date)

            indicator = self.create({
                'period': period_date,
                'uf': data.get('uf', 0),
                'utm': data.get('utm', 0),
                'uta': data.get('uta', 0),
                'minimum_wage': data.get('sueldo_minimo', 0),
                'afp_limit': afp_cap_uf,  # ✅ Desde tabla legal.caps
                'family_allowance_t1': data.get('asig_fam_tramo_1', 0),
                'family_allowance_t2': data.get('asig_fam_tramo_2', 0),
                'family_allowance_t3': data.get('asig_fam_tramo_3', 0),
            })

            _logger.info(
                "✅ Indicadores %s creados desde AI-Service (ID: %d, AFP cap: %.1f UF)",
                period_date.strftime('%Y-%m'),
                indicator.id,
                afp_cap_uf
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

    def _get_afp_cap_from_legal_table(self, target_date):
        """
        Obtener tope AFP desde tabla l10n_cl.legal.caps

        Fix GAP-002: Elimina valores hardcoded, usa configuración parametrizable

        Args:
            target_date: Fecha para buscar tope AFP vigente

        Returns:
            float: Tope AFP en UF (ej: 83.1)

        Raises:
            ValidationError: Si no existe cap AFP configurado
        """
        LegalCaps = self.env['l10n_cl.legal.caps']

        # Buscar cap AFP vigente para la fecha
        afp_cap_uf, unit = LegalCaps.get_cap('AFP_IMPONIBLE_CAP', target_date)

        if not afp_cap_uf:
            raise ValidationError(_(
                'Tope AFP no configurado para fecha %s.\n\n'
                'Configure en: Nómina > Configuración > Topes Legales\n'
                'Código: AFP_IMPONIBLE_CAP\n'
                'Valor 2025: 83.1 UF'
            ) % target_date)

        # Validar unidad correcta
        if unit != 'uf':
            raise ValidationError(_(
                'Tope AFP debe estar en UF, recibido: %s'
            ) % unit)

        return afp_cap_uf
    
    @api.model
    def _run_fetch_indicators_cron(self):
        """
        Cron automático: obtener indicadores del mes siguiente - P0-4
        
        Ejecuta día 1 de cada mes a las 05:00 AM
        Idempotente: si registro existe, no duplica
        
        Reintentos: 3 intentos con backoff exponencial
        """
        import logging
        import time
        from datetime import timedelta
        
        _logger = logging.getLogger(__name__)
        
        today = date.today()
        # Mes siguiente
        next_month = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
        
        year = next_month.year
        month = next_month.month
        
        _logger.info(
            "🔄 Cron indicadores: obteniendo %s-%02d",
            year, month
        )
        
        # Verificar si ya existe (idempotencia)
        existing = self.search([('period', '=', next_month)], limit=1)
        if existing:
            _logger.info(
                "ℹ️  Indicadores %s-%02d ya existen (ID: %d), skip",
                year, month, existing.id
            )
            return existing
        
        # Intentar fetch con reintentos
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                _logger.info(
                    "Intento %d/%d: obteniendo indicadores desde AI-Service...",
                    attempt, max_retries
                )
                
                indicator = self.fetch_from_ai_service(year, month)
                
                _logger.info(
                    "✅ Indicadores %s-%02d creados en intento %d",
                    year, month, attempt
                )
                
                return indicator
                
            except Exception as e:
                _logger.warning(
                    "⚠️  Intento %d/%d falló: %s",
                    attempt, max_retries, str(e)
                )
                
                if attempt < max_retries:
                    # Backoff exponencial: 5s, 10s, 15s
                    sleep_time = 5 * attempt
                    _logger.info("Reintentando en %ds...", sleep_time)
                    time.sleep(sleep_time)
                else:
                    # Último intento falló
                    _logger.error(
                        "❌ Todos los intentos fallaron para %s-%02d. "
                        "Se requiere carga manual.",
                        year, month
                    )
                    
                    # Notificar a admin
                    self._notify_indicators_failure(year, month)

                    # FAIL-SOFT: Return None instead of raising to avoid cron traceback
                    # Admin notification sent above
                    return False
    
    def _notify_indicators_failure(self, year, month):
        """
        Notificar a administradores que debe cargar indicadores manualmente - P0-4
        
        Crea una actividad para el grupo de administradores de nómina.
        """
        import logging
        _logger = logging.getLogger(__name__)
        
        try:
            # Buscar usuarios administradores de nómina
            admin_group = self.env.ref('l10n_cl_hr_payroll.group_hr_payroll_manager')
            admin_users = admin_group.users
            
            if not admin_users:
                _logger.warning("No hay usuarios administradores de nómina")
                return
            
            # Crear actividad para cada admin
            for user in admin_users:
                self.env['mail.activity'].create({
                    'res_model_id': self.env.ref('l10n_cl_hr_payroll.model_hr_economic_indicators').id,
                    'res_id': 0,
                    'activity_type_id': self.env.ref('mail.mail_activity_data_todo').id,
                    'summary': f'Cargar indicadores económicos {year}-{month:02d} manualmente',
                    'note': f'''
                        <p>El cron automático de indicadores económicos falló.</p>
                        <p><b>Mes:</b> {year}-{month:02d}</p>
                        <p><b>Acción requerida:</b></p>
                        <ul>
                            <li>Ir a Nómina > Configuración > Indicadores Económicos</li>
                            <li>Usar el wizard de carga manual (CSV)</li>
                            <li>O crear el registro manualmente</li>
                        </ul>
                    ''',
                    'date_deadline': date.today(),
                    'user_id': user.id,
                })
            
            _logger.info(
                "📧 Notificaciones enviadas a %d administradores",
                len(admin_users)
            )
            
        except Exception as e:
            _logger.error(
                "Error enviando notificaciones: %s",
                str(e)
            )
