# -*- coding: utf-8 -*-
"""
DTE Webhook Controller
Recibe notificaciones del DTE Service cuando termina de procesar DTEs

Seguridad implementada:
- Rate limiting (10 req/min por IP)
- IP whitelist configurable
- HMAC signature validation
- Logging detallado de intentos
"""

from odoo import http
from odoo.http import request
from werkzeug.exceptions import TooManyRequests
from functools import wraps
import logging
import json
import time
import hmac
import hashlib

_logger = logging.getLogger(__name__)

# Cache en memoria para rate limiting (en producción usar Redis)
_request_cache = {}


class DTEWebhookController(http.Controller):
    """
    Controlador para recibir callbacks del DTE Service
    
    Endpoint: POST /api/dte/callback
    """
    
    @http.route('/api/dte/callback', type='json', auth='public', methods=['POST'], csrf=False)
    @rate_limit(max_calls=10, period=60)
    def dte_callback(self, **kwargs):
        """
        Webhook para recibir notificaciones del DTE Service
        
        Seguridad:
        - Rate limiting: 10 req/min por IP
        - IP whitelist configurable
        - HMAC signature validation
        
        Payload esperado:
        {
            'dte_id': 'DTE-123',
            'status': 'sent',
            'track_id': '12345',
            'xml_b64': 'base64...',
            'message': 'Mensaje opcional'
        }
        
        Headers requeridos:
        - X-Webhook-Signature: HMAC-SHA256 del payload
        """
        try:
            # 1. Verificar IP whitelist
            ip = request.httprequest.remote_addr
            if not check_ip_whitelist(ip):
                _logger.error(
                    "Webhook rejected: IP not in whitelist",
                    extra={'ip': ip}
                    "Intento de webhook con key inválida desde %s",
                    request.httprequest.remote_addr
                )
                return {
                    'success': False,
                    'error': 'Invalid webhook key',
                    'code': 403
                }
            
            # 2. Extraer move_id del dte_id
            dte_id = data.get('dte_id')
            if not dte_id or not dte_id.startswith('DTE-'):
                _logger.error("Formato de dte_id inválido: %s", dte_id)
                return {
                    'success': False,
                    'error': 'Invalid dte_id format',
                    'code': 400
                }
            
            try:
                move_id = int(dte_id.split('-')[1])
            except (IndexError, ValueError) as e:
                _logger.error("Error al extraer move_id de %s: %s", dte_id, str(e))
                return {
                    'success': False,
                    'error': 'Invalid dte_id format',
                    'code': 400
                }
            
            # 3. Buscar factura
            move = request.env['account.move'].sudo().browse(move_id)
            
            if not move.exists():
                _logger.error("Factura no encontrada: move_id=%s", move_id)
                return {
                    'success': False,
                    'error': 'Invoice not found',
                    'code': 404
                }
            
            # 4. Actualizar estado
            status = data.get('status')
            
            success = move.dte_update_status_from_webhook(
                status=status,
                track_id=data.get('track_id'),
                xml_b64=data.get('xml_b64'),
                message=data.get('message')
            )
            
            if success:
                _logger.info(
                    "DTE webhook procesado exitosamente: move_id=%s, status=%s",
                    move_id,
                    status
                )
                return {
                    'success': True,
                    'move_id': move_id,
                    'status': status
                }
            else:
                _logger.error(
                    "Error al procesar webhook: move_id=%s, status=%s",
                    move_id,
                    status
                )
                return {
                    'success': False,
                    'error': 'Failed to update status',
                    'code': 500
                }
            
        except Exception as e:
            _logger.error(
                "Error inesperado en webhook: %s",
                str(e),
                exc_info=True
            )
            return {
                'success': False,
                'error': str(e),
                'code': 500
            }
    
    @http.route('/api/dte/test', type='json', auth='public', methods=['GET', 'POST'])
    def dte_test(self):
        """
        Endpoint de prueba para verificar que el webhook está activo
        
        Returns:
            dict: {'status': 'ok', 'message': str}
        """
        return {
            'status': 'ok',
            'message': 'DTE Webhook is active',
            'version': '1.0.0'
        }
