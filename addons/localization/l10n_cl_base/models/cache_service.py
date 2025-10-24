# -*- coding: utf-8 -*-
from odoo import models, fields, api


class L10nClCacheService(models.AbstractModel):
    """
    Servicio de caché para optimización de consultas en módulos chilenos.

    Proporciona funcionalidades de caché compartidas entre:
    - l10n_cl_dte
    - l10n_cl_hr_payroll
    - l10n_cl_financial_reports
    """
    _name = 'l10n_cl_base.cache_service'
    _description = 'Chilean Localization Cache Service'

    @api.model
    def get_cached(self, key, ttl=3600):
        """
        Obtiene valor desde caché con TTL.

        Args:
            key (str): Clave del caché
            ttl (int): Time to live en segundos (default: 3600)

        Returns:
            any: Valor cacheado o None si no existe/expiró
        """
        # Implementación simple usando ir.config_parameter como storage
        param_key = f'l10n_cl_cache.{key}'
        cache_data = self.env['ir.config_parameter'].sudo().get_param(param_key)

        if cache_data:
            try:
                import json
                from datetime import datetime
                data = json.loads(cache_data)

                # Verificar TTL
                if 'timestamp' in data and 'value' in data:
                    timestamp = datetime.fromisoformat(data['timestamp'])
                    now = datetime.now()

                    if (now - timestamp).total_seconds() < ttl:
                        return data['value']
            except:
                pass

        return None

    @api.model
    def set_cached(self, key, value):
        """
        Almacena valor en caché.

        Args:
            key (str): Clave del caché
            value (any): Valor a cachear (debe ser JSON serializable)
        """
        import json
        from datetime import datetime

        param_key = f'l10n_cl_cache.{key}'
        cache_data = {
            'value': value,
            'timestamp': datetime.now().isoformat()
        }

        self.env['ir.config_parameter'].sudo().set_param(
            param_key,
            json.dumps(cache_data)
        )

    @api.model
    def clear_cache(self, key=None):
        """
        Limpia caché.

        Args:
            key (str, optional): Clave específica a limpiar. Si es None, limpia todo.
        """
        if key:
            param_key = f'l10n_cl_cache.{key}'
            self.env['ir.config_parameter'].sudo().search([
                ('key', '=', param_key)
            ]).unlink()
        else:
            # Limpiar todas las claves de caché chileno
            self.env['ir.config_parameter'].sudo().search([
                ('key', 'like', 'l10n_cl_cache.%')
            ]).unlink()


class L10nClCacheServiceAlias(models.AbstractModel):
    """Alias para compatibilidad con l10n_cl.cache.service"""
    _name = 'l10n_cl.cache.service'
    _description = 'Chilean Cache Service (Alias)'
    _inherit = 'l10n_cl_base.cache_service'
