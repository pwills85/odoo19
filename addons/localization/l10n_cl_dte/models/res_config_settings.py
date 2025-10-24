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
    # DATOS TRIBUTARIOS EMPRESA (desde res.company)
    # ═══════════════════════════════════════════════════════════

    l10n_cl_activity_code = fields.Char(
        related='company_id.l10n_cl_activity_code',
        string='Código Actividad Económica',
        readonly=False,
        help='Código SII de 6 dígitos (OBLIGATORIO en XML DTE)'
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

