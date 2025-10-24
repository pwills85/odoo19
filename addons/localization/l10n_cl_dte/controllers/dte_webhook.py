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


def rate_limit(max_calls=10, period=60):
    """
    Rate limiter decorator
    
    Args:
        max_calls: Máximo de llamadas permitidas
        period: Período en segundos
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Obtener IP del request
            ip = request.httprequest.remote_addr
            now = time.time()
            
            # Limpiar cache viejo
            if ip in _request_cache:
                _request_cache[ip] = [
                    t for t in _request_cache[ip] 
                    if now - t < period
                ]
            
            # Verificar límite
            if len(_request_cache.get(ip, [])) >= max_calls:
                _logger.warning(
                    "Rate limit exceeded",
                    extra={
                        'ip': ip,
                        'calls': len(_request_cache[ip]),
                        'period': period
                    }
                )
                raise TooManyRequests(
                    f"Rate limit exceeded: {max_calls} calls per {period}s"
                )
            
            # Registrar request
            _request_cache.setdefault(ip, []).append(now)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def check_ip_whitelist(ip):
    """
    Verifica si IP está en whitelist
    
    Args:
        ip: IP address del request
        
    Returns:
        bool: True si está permitida
    """
    whitelist_param = request.env['ir.config_parameter'].sudo().get_param(
        'l10n_cl_dte.webhook_ip_whitelist',
        '127.0.0.1,localhost,172.18.0.0/16,odoo-eergy-services'
    )
    
    whitelist = [ip.strip() for ip in whitelist_param.split(',')]
    
    # Verificar IP exacta o hostname
    if ip in whitelist:
        return True
    
    # Verificar rangos CIDR (simplificado)
    for allowed in whitelist:
        if '/' in allowed:  # Es un rango CIDR
            # Para producción, usar ipaddress module
            base = allowed.split('/')[0]
            if ip.startswith(base.rsplit('.', 1)[0]):
                return True
    
    _logger.warning(
        "IP not in whitelist",
        extra={'ip': ip, 'whitelist': whitelist}
    )
    return False


def verify_hmac_signature(payload, signature, secret):
    """
    Verifica firma HMAC del payload
    
    Args:
        payload: Payload del request (string)
        signature: Firma recibida
        secret: Secret key compartida
        
    Returns:
        bool: True si la firma es válida
    """
    if not signature or not secret:
        return False
    
    expected = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected)


class DTEWebhookController(http.Controller):
    """
    Controlador para recibir callbacks del DTE Service
    
    Endpoint: POST /api/dte/callback
    """
    
    @http.route('/api/dte/callback', type='jsonrpc', auth='public', methods=['POST'], csrf=False)
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
                )
                return {
                    'success': False,
                    'error': 'IP not allowed',
                    'code': 403
                }
            
            # 2. Verificar firma HMAC
            signature = request.httprequest.headers.get('X-Webhook-Signature')
            webhook_key = request.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.webhook_key',
                'default_webhook_key_change_in_production'
            )
            
            payload = json.dumps(kwargs, sort_keys=True)
            
            if not verify_hmac_signature(payload, signature, webhook_key):
                _logger.error(
                    "Webhook rejected: Invalid HMAC signature",
                    extra={
                        'ip': ip,
                        'signature_received': signature[:20] if signature else None
                    }
                )
                return {
                    'success': False,
                    'error': 'Invalid signature',
                    'code': 401
                }
            
            # 3. Procesar webhook
            _logger.info(
                "Webhook received and validated",
                extra={
                    'dte_id': kwargs.get('dte_id'),
                    'status': kwargs.get('status'),
                    'ip': ip,
                    'signature_valid': True
                }
            )
            
            # 4. Extraer move_id del dte_id
            dte_id = kwargs.get('dte_id')
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
            
            # 5. Buscar factura
            move = request.env['account.move'].sudo().browse(move_id)
            
            if not move.exists():
                _logger.error("Factura no encontrada: move_id=%s", move_id)
                return {
                    'success': False,
                    'error': 'Invoice not found',
                    'code': 404
                }
            
            # 6. Actualizar estado
            status = kwargs.get('status')
            
            success = move.dte_update_status_from_webhook(
                status=status,
                track_id=kwargs.get('track_id'),
                xml_b64=kwargs.get('xml_b64'),
                message=kwargs.get('message')
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
    
    @http.route('/api/dte/test', type='jsonrpc', auth='public', methods=['GET', 'POST'])
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
