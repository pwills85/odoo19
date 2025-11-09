# -*- coding: utf-8 -*-
"""
l10n_cl_dte Module Hooks
Funciones ejecutadas en instalación/actualización del módulo

Sprint 0.2: Seguridad Enterprise
- B-003: Generación automática de webhook_key segura
"""

import secrets
import logging

_logger = logging.getLogger(__name__)


def post_init_hook(env):
    """
    Hook ejecutado después de la instalación del módulo

    Genera claves secretas si no existen:
    - l10n_cl_dte.webhook_key: Key para firmar webhooks (HMAC-SHA256)

    Args:
        env: Odoo environment (Odoo 19 signature)

    Security:
        - Genera keys de 64 caracteres hexadecimales (256 bits)
        - Solo genera si no existe o si es default inseguro
        - Logs de warning cuando genera nueva key (debe guardarse en vault)
    """

    # ═══════════════════════════════════════════════════════════
    # B-003: Webhook Key Segura
    # ═══════════════════════════════════════════════════════════
    webhook_key = env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.webhook_key')

    # Lista de defaults inseguros a reemplazar
    insecure_defaults = [
        None,
        '',
        'default_webhook_key_change_in_production',
        'changeme',
        'secret'
    ]

    if webhook_key in insecure_defaults:
        # Generar key segura: 64 hex chars = 256 bits
        new_key = secrets.token_hex(32)

        env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_dte.webhook_key',
            new_key
        )

        _logger.warning(
            "==================================================================="
        )
        _logger.warning(
            "SECURITY: Generated new webhook_key for DTE webhooks"
        )
        _logger.warning(
            "Key preview: %s...",
            new_key[:16]
        )
        _logger.warning(
            "⚠️  IMPORTANT: Store this key securely in your secrets vault!"
        )
        _logger.warning(
            "⚠️  Share this key with external services that call webhooks"
        )
        _logger.warning(
            "==================================================================="
        )

    # ═══════════════════════════════════════════════════════════
    # Otros parámetros de configuración (defaults seguros)
    # ═══════════════════════════════════════════════════════════

    # Redis URL (default: docker compose redis)
    if not env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.redis_url'):
        env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_dte.redis_url',
            'redis://redis:6379/1'
        )
        _logger.info("Set default Redis URL: redis://redis:6379/1")

    # Rate limit: 100 req/min
    if not env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.ratelimit_max'):
        env['ir.config_parameter'].sudo().set_param('l10n_cl_dte.ratelimit_max', '100')
        _logger.info("Set default rate limit: 100 req/min")

    # Webhook timestamp window: 300s (5 min)
    if not env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.webhook_window_sec'):
        env['ir.config_parameter'].sudo().set_param('l10n_cl_dte.webhook_window_sec', '300')
        _logger.info("Set default webhook timestamp window: 300s")

    # IP whitelist (default: localhost + docker network)
    if not env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.webhook_ip_whitelist'):
        env['ir.config_parameter'].sudo().set_param(
            'l10n_cl_dte.webhook_ip_whitelist',
            '127.0.0.1,172.18.0.0/16'
        )
        _logger.info("Set default IP whitelist: 127.0.0.1,172.18.0.0/16")

    # SII timeout: 30s
    if not env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.sii_timeout'):
        env['ir.config_parameter'].sudo().set_param('l10n_cl_dte.sii_timeout', '30')
        _logger.info("Set default SII timeout: 30s")

    _logger.info("l10n_cl_dte post_init_hook completed successfully")
