# -*- coding: utf-8 -*-

import logging
import time
import requests
from datetime import datetime, timedelta
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError

_logger = logging.getLogger(__name__)


class HrAFP(models.Model):
    """
    Administradoras de Fondos de Pensiones (AFP) Chile
    
    Modelo maestro con las 10 AFPs vigentes en Chile.
    Tasas actualizadas según normativa 2025.
    
    HIGH-007: Auto-actualización mensual de comisiones AFP desde API
    Superintendencia de Pensiones.
    """
    _name = 'hr.afp'
    _description = 'AFP Chile'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'name'
    
    name = fields.Char(
        string='Nombre AFP',
        required=True,
        help='Nombre completo de la AFP'
    )
    code = fields.Char(
        string='Código',
        required=True,
        help='Código único de la AFP (para Previred)'
    )
    rate = fields.Float(
        string='Tasa AFP (%)',
        digits=(5, 4),
        required=True,
        help='Tasa de cotización AFP (10.49% - 11.54%)',
        tracking=True
    )
    sis_rate = fields.Float(
        string='Tasa SIS (%)',
        digits=(5, 4),
        default=0.0157,
        help='Tasa Seguro de Invalidez y Sobrevivencia (1.57%)',
        tracking=True
    )
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    last_update_date = fields.Date(
        string='Última Actualización',
        readonly=True,
        help='Fecha última actualización comisiones desde API Superintendencia Pensiones',
        tracking=True
    )

    @api.constrains('code')
    def _check_code_unique(self):
        """Validar que el código sea único (migrado desde _sql_constraints en Odoo 19)"""
        for afp in self:
            if afp.code:
                existing = self.search_count([
                    ('code', '=', afp.code),
                    ('id', '!=', afp.id)
                ])
                if existing:
                    raise ValidationError(_('El código de la AFP debe ser único'))

    @api.constrains('rate', 'sis_rate')
    def _check_rates(self):
        """Validar que las tasas estén en rangos válidos"""
        for afp in self:
            if afp.rate < 0 or afp.rate > 20:
                raise ValidationError(_('La tasa AFP debe estar entre 0% y 20%'))
            if afp.sis_rate < 0 or afp.sis_rate > 5:
                raise ValidationError(_('La tasa SIS debe estar entre 0% y 5%'))
    
    def name_get(self):
        """Mostrar nombre con tasa"""
        result = []
        for afp in self:
            name = f"{afp.name} ({afp.rate:.2f}%)"
            result.append((afp.id, name))
        return result

    # ═══════════════════════════════════════════════════════════════════════
    # HIGH-007: AUTO-UPDATE AFP RATES FROM SUPERINTENDENCIA PENSIONES API
    # ═══════════════════════════════════════════════════════════════════════

    @api.model
    def _cron_update_afp_rates(self):
        """
        Cron job mensual: Actualizar comisiones AFP desde Superintendencia Pensiones.
        
        Features:
        - API call: https://www.spensiones.cl/apps/rentabilidadReal/getRentabilidad.php
        - Retry logic: 3 intentos con exponential backoff (10s, 20s, 40s)
        - Tracking: Chatter messages con audit trail completo
        - Notificaciones: Actividad para HR Manager en caso de fallo persistente
        - Validación: Solo actualizar si cambio >0.01%
        
        Returns:
            bool: True si éxito, False si fallo persistente
        """
        _logger.info('🔄 [HIGH-007] Iniciando actualización automática comisiones AFP...')
        
        max_retries = 3
        backoff_delays = [10, 20, 40]  # Exponential backoff en segundos
        
        for attempt in range(max_retries):
            try:
                # Intentar actualizar desde API
                updated_count = self._fetch_and_update_afp_rates()
                
                if updated_count is not None:
                    _logger.info(
                        f'✅ [HIGH-007] Actualización exitosa: {updated_count} AFPs actualizadas'
                    )
                    self._notify_success_update(updated_count)
                    return True
                    
            except Exception as e:
                _logger.warning(
                    f'⚠️ [HIGH-007] Intento {attempt + 1}/{max_retries} falló: {str(e)}'
                )
                
                if attempt < max_retries - 1:
                    delay = backoff_delays[attempt]
                    _logger.info(f'⏳ Reintentando en {delay} segundos...')
                    time.sleep(delay)
                else:
                    # Fallo persistente: notificar admin
                    _logger.error(
                        f'❌ [HIGH-007] Fallo persistente tras {max_retries} intentos'
                    )
                    self._notify_failure_update(str(e))
                    return False
        
        return False

    def _fetch_and_update_afp_rates(self):
        """
        Fetch AFP rates from Superintendencia Pensiones API and update records.
        
        Returns:
            int: Número de AFPs actualizadas (None si fallo API)
        
        Raises:
            UserError: Si API retorna error o respuesta inválida
        """
        # API URL (puede cambiar, ver documentación SP)
        api_url = 'https://www.spensiones.cl/apps/rentabilidadReal/getRentabilidad.php'
        
        try:
            response = requests.get(api_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Validar estructura respuesta
            if not isinstance(data, dict) or 'afps' not in data:
                raise UserError(_('Respuesta API inválida: estructura incorrecta'))
            
            afps_data = data['afps']
            updated_count = 0
            
            for afp_info in afps_data:
                # Mapear datos API → campos Odoo
                afp_code = afp_info.get('codigo')
                new_rate = float(afp_info.get('comision', 0))
                
                if not afp_code:
                    continue
                
                # Buscar AFP por código
                afp = self.search([('code', '=', afp_code)], limit=1)
                
                if afp:
                    # Validar si hay cambio significativo (>0.01%)
                    rate_change = abs(afp.rate - new_rate)
                    
                    if rate_change > 0.01:
                        old_rate = afp.rate
                        afp.write({
                            'rate': new_rate,
                            'last_update_date': fields.Date.today(),
                        })
                        
                        # Log en chatter
                        afp.message_post(
                            body=_(
                                'Comisión AFP actualizada automáticamente:<br/>'
                                '<b>Tasa anterior:</b> %(old_rate).4f%%<br/>'
                                '<b>Tasa nueva:</b> %(new_rate).4f%%<br/>'
                                '<b>Cambio:</b> %(change)+.4f%%<br/>'
                                '<b>Fuente:</b> Superintendencia Pensiones API'
                            ) % {
                                'old_rate': old_rate,
                                'new_rate': new_rate,
                                'change': new_rate - old_rate,
                            },
                            message_type='notification',
                            subtype_xmlid='mail.mt_note',
                        )
                        
                        updated_count += 1
                        _logger.info(
                            f'✅ AFP {afp.name}: {old_rate:.4f}% → {new_rate:.4f}%'
                        )
            
            return updated_count
            
        except requests.exceptions.RequestException as e:
            raise UserError(
                _('Error conectando con API Superintendencia Pensiones: %s') % str(e)
            )
        except (ValueError, KeyError) as e:
            raise UserError(_('Error procesando respuesta API: %s') % str(e))

    def _notify_success_update(self, updated_count):
        """
        Enviar notificación éxito actualización AFP.
        
        Args:
            updated_count (int): Número de AFPs actualizadas
        """
        # Buscar grupo HR Manager
        group_hr_manager = self.env.ref('hr.group_hr_manager', raise_if_not_found=False)
        
        if not group_hr_manager:
            return
        
        # Mensaje para todos los managers
        message = _(
            'Actualización automática comisiones AFP completada:<br/>'
            '<b>AFPs actualizadas:</b> %(count)d<br/>'
            '<b>Fecha:</b> %(date)s<br/>'
            '<b>Fuente:</b> Superintendencia Pensiones'
        ) % {
            'count': updated_count,
            'date': fields.Date.today().strftime('%d/%m/%Y'),
        }
        
        # Enviar notificación al canal (si existe)
        channel = self.env['mail.channel'].search([
            ('name', '=', 'HR Payroll Updates')
        ], limit=1)
        
        if channel:
            channel.message_post(
                body=message,
                message_type='notification',
                subtype_xmlid='mail.mt_comment',
            )

    def _notify_failure_update(self, error_message):
        """
        Crear actividad para HR Manager en caso de fallo persistente.
        
        Args:
            error_message (str): Mensaje de error detallado
        """
        # Buscar grupo HR Manager
        group_hr_manager = self.env.ref('hr.group_hr_manager', raise_if_not_found=False)
        
        if not group_hr_manager:
            return
        
        # Buscar usuarios con rol HR Manager
        hr_managers = self.env['res.users'].search([
            ('groups_id', 'in', group_hr_manager.id)
        ])
        
        if not hr_managers:
            return
        
        # Crear actividad para cada manager
        activity_type = self.env.ref('mail.mail_activity_data_todo', raise_if_not_found=False)
        
        for manager in hr_managers:
            self.env['mail.activity'].create({
                'activity_type_id': activity_type.id if activity_type else False,
                'summary': _('ERROR: Actualización comisiones AFP falló'),
                'note': _(
                    'La actualización automática de comisiones AFP desde '
                    'Superintendencia Pensiones falló tras 3 intentos.<br/><br/>'
                    '<b>Error:</b> %(error)s<br/><br/>'
                    '<b>Acción requerida:</b><br/>'
                    '1. Verificar conectividad API Superintendencia Pensiones<br/>'
                    '2. Revisar logs Odoo para detalles técnicos<br/>'
                    '3. Actualizar comisiones manualmente si necesario<br/>'
                    '4. Contactar soporte si problema persiste'
                ) % {'error': error_message},
                'res_id': self.env['hr.afp'].search([], limit=1).id,
                'res_model_id': self.env['ir.model']._get('hr.afp').id,
                'user_id': manager.id,
                'date_deadline': fields.Date.today() + timedelta(days=1),
            })

