# -*- coding: utf-8 -*-

from odoo import models, fields, api, _


class ResConfigSettings(models.TransientModel):
    """
    Configuración del módulo l10n_cl_dte
    """
    _inherit = 'res.config.settings'
    
    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN MICROSERVICIOS
    # ═══════════════════════════════════════════════════════════
    
    dte_service_url = fields.Char(
        string='URL DTE Service',
        config_parameter='l10n_cl_dte.dte_service_url',
        default='http://odoo-eergy-services:8001',
        help='URL del microservicio DTE (red interna Docker)'
    )
    
    dte_api_key = fields.Char(
        string='API Key DTE Service',
        config_parameter='l10n_cl_dte.dte_api_key',
        help='API key para autenticación con DTE Service'
    )
    
    ai_service_url = fields.Char(
        string='URL AI Service',
        config_parameter='l10n_cl_dte.ai_service_url',
        default='http://ai-service:8002',
        help='URL del microservicio AI (red interna Docker)'
    )
    
    ai_api_key = fields.Char(
        string='API Key AI Service',
        config_parameter='l10n_cl_dte.ai_api_key',
        help='API key para autenticación con AI Service'
    )
    
    use_ai_validation = fields.Boolean(
        string='Usar Pre-validación IA',
        config_parameter='l10n_cl_dte.use_ai_validation',
        default=False,
        help='Activar pre-validación inteligente antes de enviar DTEs'
    )

    # ═══════════════════════════════════════════════════════════
    # PARÁMETROS CRÍTICOS (P2.4 GAP CLOSURE)
    # ═══════════════════════════════════════════════════════════

    redis_url = fields.Char(
        string='URL Redis',
        config_parameter='l10n_cl_dte.redis_url',
        default='redis://redis:6379/1',
        help='URL de conexión a Redis para métricas de rendimiento y rate limiting'
    )

    metrics_enabled = fields.Boolean(
        string='Métricas de Rendimiento',
        config_parameter='l10n_cl_dte.metrics_enabled',
        default=True,
        help='Activar/desactivar métricas de rendimiento (P50/P95/P99) para operaciones DTE'
    )

    webhook_key = fields.Char(
        string='Webhook Key',
        config_parameter='l10n_cl_dte.webhook_key',
        help='Clave secreta para firmar webhooks (HMAC-SHA256). Generada automáticamente.'
    )

    # ═══════════════════════════════════════════════════════════
    # DATOS TRIBUTARIOS EMPRESA (desde res.company)
    # ═══════════════════════════════════════════════════════════

    # DEPRECADO: Usar l10n_cl_activity_ids (multiple selection)
    l10n_cl_activity_code = fields.Char(
        related='company_id.l10n_cl_activity_code',
        string='Código Actividad Económica (DEPRECADO)',
        readonly=False,
        help='Campo DEPRECADO: Usar l10n_cl_activity_ids (selección múltiple)'
    )

    # NUEVO: Actividades Económicas (selección múltiple)
    l10n_cl_activity_ids = fields.Many2many(
        related='company_id.l10n_cl_activity_ids',
        string='Actividades Económicas SII',
        readonly=False,
        help='Códigos de Actividad Económica SII (CIIU Rev. 4 CL 2012).\n'
             'Puede seleccionar múltiples actividades (hasta 4 en DTEs).'
    )

    # Giro de la Empresa
    l10n_cl_activity_description = fields.Char(
        related='company_id.l10n_cl_activity_description',
        string='Giro de la Empresa',
        readonly=False,
        help='Descripción textual de la actividad económica (máx 80 caracteres).\n'
             'Se usa en XML DTE como elemento <GiroEmis> (OBLIGATORIO).'
    )

    # Ubicación Tributaria (para referencia visual)
    partner_id = fields.Many2one(
        related='company_id.partner_id',
        string='Partner Empresa',
        readonly=True,
        help='Partner asociado a la empresa (para mostrar ubicación)'
    )

    dte_resolution_number = fields.Char(
        related='company_id.dte_resolution_number',
        string='Número Resolución SII',
        readonly=False,
        help='Número de resolución de autorización de DTEs del SII'
    )

    dte_resolution_date = fields.Date(
        related='company_id.dte_resolution_date',
        string='Fecha Resolución DTE',
        readonly=False,
        help='Fecha de la resolución de autorización de DTEs'
    )

    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN SII
    # ═══════════════════════════════════════════════════════════
    
    sii_environment = fields.Selection([
        ('sandbox', 'Sandbox (Maullin - Pruebas)'),
        ('production', 'Producción (Palena)'),
    ], string='Ambiente SII',
       config_parameter='l10n_cl_dte.sii_environment',
       default='sandbox',
       help='Ambiente del SII a utilizar')
    
    sii_timeout = fields.Integer(
        string='Timeout SII (segundos)',
        config_parameter='l10n_cl_dte.sii_timeout',
        default=60,
        help='Tiempo máximo de espera para respuesta del SII'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ACCIONES
    # ═══════════════════════════════════════════════════════════
    
    def action_test_dte_service(self):
        """Prueba conexión con DTE Service"""
        from odoo.addons.l10n_cl_dte.tools.dte_api_client import DTEApiClient
        
        client = DTEApiClient(self.env)
        
        if client.health_check():
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Conexión Exitosa'),
                    'message': _('DTE Service está disponible en %s') % self.dte_service_url,
                    'type': 'success',
                }
            }
        else:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Error de Conexión'),
                    'message': _('No se puede conectar con DTE Service en %s') % self.dte_service_url,
                    'type': 'danger',
                }
            }
    
    def action_test_ai_service(self):
        """Prueba conexión con AI Service"""
        from odoo.addons.l10n_cl_dte.tools.dte_api_client import AIApiClient
        
        client = AIApiClient(self.env)
        
        if client.health_check():
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Conexión Exitosa'),
                    'message': _('AI Service está disponible en %s') % self.ai_service_url,
                    'type': 'success',
                }
            }
        else:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Error de Conexión'),
                    'message': _('No se puede conectar con AI Service en %s') % self.ai_service_url,
                    'type': 'danger',
                }
            }

