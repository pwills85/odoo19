# -*- coding: utf-8 -*-
"""
DTE Webhook Controller - Enterprise Security
Recibe notificaciones del DTE Service cuando termina de procesar DTEs

Seguridad Enterprise implementada (Sprint 0.2):
- HMAC-SHA256 signature validation con timestamp + nonce
- Replay attack protection (Redis SETNX con TTL)
- Timestamp validation (ventana 300s)
- IP whitelist con soporte CIDR real (ipaddress module)
- Rate limiting distribuido Redis (ver Sprint 0.3)
- Logging estructurado con campos auditables
- Fail-secure: no default keys, fallar si falta config

Referencias:
- B-002: Webhook timestamp/nonce validation
- B-003: Secure webhook key generation
- OWASP: Authentication, Session Management
"""

from odoo import http
from odoo.http import request
from werkzeug.exceptions import TooManyRequests, Forbidden, Unauthorized
from functools import wraps
import logging
import json
import time
import hmac
import hashlib
import ipaddress

# P1.3 GAP CLOSURE: Performance metrics instrumentation
from odoo.addons.l10n_cl_dte.libs.performance_metrics import measure_performance

_logger = logging.getLogger(__name__)

# Safe Redis exception handling (lazy import compatible)
try:
    import redis
    RedisError = redis.RedisError
except ImportError:
    # If redis not installed, treat as generic exception
    RedisError = Exception
    _logger.warning("Redis library not installed. Webhook features will be limited.")


def get_redis_client():
    """
    Obtiene cliente Redis desde configuración

    Returns:
        redis.Redis: Cliente Redis configurado

    Raises:
        RuntimeError: Si Redis no está configurado o no responde
    """
    # Lazy import para evitar bloqueo si redis no está instalado
    try:
        import redis
    except ImportError:
        raise RuntimeError("Redis library not installed. Install with: pip install redis")

    redis_url = request.env['ir.config_parameter'].sudo().get_param(
        'l10n_cl_dte.redis_url',
        'redis://redis:6379/1'
    )

    try:
        client = redis.from_url(redis_url, decode_responses=True)
        # Verificar conexión
        client.ping()
        return client
    except Exception as e:
        _logger.error(
            "Redis connection failed",
            extra={'redis_url': redis_url, 'error': str(e)}
        )
        raise RuntimeError(f"Redis unavailable: {e}")


def rate_limit_redis(max_calls=100, period=60):
    """
    Rate limiter decorator usando Redis (distribuido, persistente)

    Args:
        max_calls: Máximo de llamadas permitidas (default: 100/min)
        period: Período en segundos (default: 60s)

    Raises:
        TooManyRequests: Si se excede el límite
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.httprequest.remote_addr
            now = int(time.time())
            window_start = now - period

            # Obtener parámetros configurables
            max_calls_config = int(request.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.ratelimit_max',
                str(max_calls)
            ))

            try:
                r = get_redis_client()
                key = f"ratelimit:webhook:{ip}"

                # Añadir request actual al sorted set (score = timestamp)
                r.zadd(key, {str(now): now})

                # Eliminar requests fuera de la ventana
                r.zremrangebyscore(key, 0, window_start)

                # Contar requests en ventana
                count = r.zcard(key)

                # Expirar key en 2x period (cleanup)
                r.expire(key, period * 2)

                if count > max_calls_config:
                    _logger.warning(
                        "Rate limit exceeded (Redis)",
                        extra={
                            'ip': ip,
                            'count': count,
                            'limit': max_calls_config,
                            'period': period,
                            'endpoint': request.httprequest.path
                        }
                    )
                    raise TooManyRequests(
                        f"Rate limit exceeded: {max_calls_config} calls per {period}s"
                    )
                
                return f(*args, **kwargs)

            except RedisError as e:
                # FAIL-SECURE: si Redis falla, rechazar request (consistent with replay protection)
                _logger.error(
                    "Rate limit check failed (Redis error) - REJECTING",
                    extra={'ip': ip, 'error': str(e)}
                )
                raise TooManyRequests("Rate limiting temporarily unavailable (Redis error)")
        return wrapper
    return decorator


def check_ip_whitelist(ip):
    """
    Verifica si IP está en whitelist con soporte CIDR real

    Args:
        ip: IP address del request

    Returns:
        bool: True si está permitida

    Raises:
        None: Devuelve False si no está permitida
    """
    whitelist_param = request.env['ir.config_parameter'].sudo().get_param(
        'l10n_cl_dte.webhook_ip_whitelist',
        '127.0.0.1,172.18.0.0/16'  # Defaults seguros: localhost + docker network
    )

    whitelist = [entry.strip() for entry in whitelist_param.split(',')]

    try:
        ip_obj = ipaddress.ip_address(ip)

        for allowed in whitelist:
            try:
                # Verificar si es red CIDR
                if '/' in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if ip_obj in network:
                        return True
                # Verificar IP exacta
                else:
                    if ip_obj == ipaddress.ip_address(allowed):
                        return True
            except ValueError:
                # Entry inválida en whitelist, skip
                _logger.warning(
                    "Invalid whitelist entry",
                    extra={'entry': allowed}
                )
                continue

        _logger.warning(
            "IP not in whitelist",
            extra={'ip': ip, 'whitelist': whitelist}
        )
        return False

    except ValueError:
        _logger.error(
            "Invalid IP address",
            extra={'ip': ip}
        )
        return False


def verify_hmac_signature(payload, signature, timestamp, nonce, secret):
    """
    Verifica firma HMAC del payload con timestamp y nonce

    Args:
        payload: Payload del request (dict)
        signature: Firma HMAC-SHA256 recibida (hex)
        timestamp: Unix timestamp del request
        nonce: Nonce único del request
        secret: Secret key compartida

    Returns:
        bool: True si la firma es válida

    Security:
        - Incluye timestamp y nonce en firma para prevenir replay
        - Usa hmac.compare_digest() para prevenir timing attacks
    """
    if not signature or not secret:
        return False

    # Construir mensaje firmado: payload + timestamp + nonce
    payload_str = json.dumps(payload, sort_keys=True)
    message = f"{payload_str}|{timestamp}|{nonce}"

    expected = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


def validate_timestamp(timestamp, window_seconds=300):
    """
    Valida que timestamp esté dentro de ventana permitida

    Args:
        timestamp: Unix timestamp a validar
        window_seconds: Ventana de validez en segundos (default: 300s = 5 min)

    Returns:
        bool: True si timestamp es válido

    Security:
        - Previene replay attacks con requests antiguos
        - Previene ataques con timestamps futuros
    """
    try:
        ts = int(timestamp)
        now = int(time.time())
        delta = abs(now - ts)

        if delta > window_seconds:
            _logger.warning(
                "Timestamp outside allowed window",
                extra={
                    'timestamp': ts,
                    'now': now,
                    'delta_seconds': delta,
                    'window_seconds': window_seconds
                }
            )
            return False

        return True

    except (ValueError, TypeError):
        _logger.error(
            "Invalid timestamp format",
            extra={'timestamp': timestamp}
        )
        return False


def check_replay_attack(nonce, ttl_seconds=600):
    """
    Verifica que nonce no haya sido usado (replay attack protection)

    Args:
        nonce: Nonce único del request
        ttl_seconds: TTL del nonce en Redis (default: 600s = 10 min)

    Returns:
        bool: True si nonce es válido (no usado previamente)

    Security:
        - Usa Redis SETNX para garantizar atomicidad
        - TTL automático para cleanup
        - Previene replay attacks
    """
    try:
        r = get_redis_client()
        key = f"nonce:webhook:{nonce}"

        # SETNX: set if not exists (atómico)
        is_new = r.set(key, '1', ex=ttl_seconds, nx=True)

        if not is_new:
            _logger.error(
                "Replay attack detected: nonce already used",
                extra={'nonce': nonce}
            )
            return False

        return True

    except RedisError as e:
        # FAIL-SECURE: si Redis falla, rechazar request
        _logger.error(
            "Replay check failed (Redis error) - REJECTING",
            extra={'nonce': nonce, 'error': str(e)}
        )
        return False


class DTEWebhookController(http.Controller):
    """
    Controlador para recibir callbacks del DTE Service

    Endpoint: POST /api/dte/callback

    Security Layers (Defense in Depth):
    1. Rate limiting (Redis): 100 req/min por IP
    2. IP whitelist (CIDR support)
    3. HMAC signature validation (SHA-256)
    4. Timestamp validation (ventana 300s)
    5. Replay attack protection (Redis nonce)
    6. Structured logging para auditoría
    """

    @http.route('/api/dte/callback', type='jsonrpc', auth='public', methods=['POST'], csrf=False)
    @rate_limit_redis(max_calls=100, period=60)
    @measure_performance('procesar_webhook')
    def dte_callback(self, **kwargs):
        """
        Webhook para recibir notificaciones del DTE Service

        P1.3 GAP CLOSURE: Instrumented with performance metrics.

        Security Requirements:
        - Rate limiting: 100 req/min por IP (Redis distribuido)
        - IP whitelist: CIDR support con ipaddress module
        - HMAC signature: SHA-256 con timestamp + nonce
        - Replay protection: Redis SETNX nonce con TTL 600s
        - Timestamp window: 300s (5 minutos)

        Payload esperado:
        {
            'dte_id': 'DTE-123',
            'status': 'sent' | 'accepted' | 'rejected',
            'track_id': '12345',
            'xml_b64': 'base64...',
            'message': 'Mensaje opcional'
        }

        Headers requeridos:
        - X-Webhook-Signature: HMAC-SHA256(payload|timestamp|nonce)
        - X-Webhook-Timestamp: Unix timestamp (int)
        - X-Webhook-Nonce: UUID único del request

        Returns:
            dict: {'success': bool, 'move_id': int, 'status': str, 'error': str, 'code': int}
        """
        start_time = time.time()
        ip = request.httprequest.remote_addr

        try:
            # ═══════════════════════════════════════════════════════════
            # SECURITY LAYER 1: IP Whitelist
            # ═══════════════════════════════════════════════════════════
            if not check_ip_whitelist(ip):
                _logger.error(
                    "Webhook rejected: IP not in whitelist",
                    extra={
                        'ip': ip,
                        'endpoint': request.httprequest.path,
                        'security_layer': 'ip_whitelist'
                    }
                )
                raise Forbidden("IP not allowed")

            # ═══════════════════════════════════════════════════════════
            # SECURITY LAYER 2: Extract and validate headers
            # ═══════════════════════════════════════════════════════════
            headers = request.httprequest.headers
            signature = headers.get('X-Webhook-Signature')
            timestamp = headers.get('X-Webhook-Timestamp')
            nonce = headers.get('X-Webhook-Nonce')

            if not signature or not timestamp or not nonce:
                _logger.error(
                    "Webhook rejected: Missing required headers",
                    extra={
                        'ip': ip,
                        'has_signature': bool(signature),
                        'has_timestamp': bool(timestamp),
                        'has_nonce': bool(nonce),
                        'security_layer': 'headers_validation'
                    }
                )
                raise Unauthorized("Missing required headers: X-Webhook-Signature, X-Webhook-Timestamp, X-Webhook-Nonce")

            # ═══════════════════════════════════════════════════════════
            # SECURITY LAYER 3: Timestamp validation (ventana 300s)
            # ═══════════════════════════════════════════════════════════
            window_seconds = int(request.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.webhook_window_sec',
                '300'
            ))

            if not validate_timestamp(timestamp, window_seconds):
                _logger.error(
                    "Webhook rejected: Timestamp outside allowed window",
                    extra={
                        'ip': ip,
                        'timestamp': timestamp,
                        'window_seconds': window_seconds,
                        'security_layer': 'timestamp_validation'
                    }
                )
                raise Unauthorized("Timestamp expired or invalid")

            # ═══════════════════════════════════════════════════════════
            # SECURITY LAYER 4: Replay attack protection (nonce)
            # ═══════════════════════════════════════════════════════════
            if not check_replay_attack(nonce, ttl_seconds=600):
                _logger.error(
                    "Webhook rejected: Replay attack detected",
                    extra={
                        'ip': ip,
                        'nonce': nonce,
                        'security_layer': 'replay_protection'
                    }
                )
                raise Unauthorized("Replay attack detected: nonce already used")

            # ═══════════════════════════════════════════════════════════
            # SECURITY LAYER 5: HMAC signature validation
            # ═══════════════════════════════════════════════════════════
            webhook_key = request.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.webhook_key'
            )

            if not webhook_key:
                _logger.critical(
                    "SECURITY MISCONFIGURATION: webhook_key not set",
                    extra={'ip': ip}
                )
                raise RuntimeError("Server misconfigured: webhook_key missing")

            if not verify_hmac_signature(kwargs, signature, timestamp, nonce, webhook_key):
                _logger.error(
                    "Webhook rejected: Invalid HMAC signature",
                    extra={
                        'ip': ip,
                        'nonce': nonce,
                        'signature_received': signature[:20] if signature else None,
                        'security_layer': 'hmac_validation'
                    }
                )
                raise Unauthorized("Invalid HMAC signature")

            # ═══════════════════════════════════════════════════════════
            # BUSINESS LOGIC: Process webhook
            # ═══════════════════════════════════════════════════════════
            _logger.info(
                "Webhook security validated - processing",
                extra={
                    'ip': ip,
                    'nonce': nonce,
                    'timestamp': timestamp,
                    'dte_id': kwargs.get('dte_id'),
                    'status': kwargs.get('status'),
                    'security_layers_passed': 5
                }
            )

            # Extraer move_id del dte_id
            dte_id = kwargs.get('dte_id')
            if not dte_id or not dte_id.startswith('DTE-'):
                _logger.error(
                    "Invalid dte_id format",
                    extra={'dte_id': dte_id, 'ip': ip}
                )
                return {
                    'success': False,
                    'error': 'Invalid dte_id format (expected: DTE-{move_id})',
                    'code': 400
                }

            try:
                move_id = int(dte_id.split('-')[1])
            except (IndexError, ValueError) as e:
                _logger.error(
                    "Failed to extract move_id from dte_id",
                    extra={'dte_id': dte_id, 'error': str(e), 'ip': ip}
                )
                return {
                    'success': False,
                    'error': 'Invalid dte_id format',
                    'code': 400
                }

            # Buscar factura
            move = request.env['account.move'].sudo().browse(move_id)

            if not move.exists():
                _logger.error(
                    "Invoice not found",
                    extra={'move_id': move_id, 'dte_id': dte_id, 'ip': ip}
                )
                return {
                    'success': False,
                    'error': 'Invoice not found',
                    'code': 404
                }

            # Actualizar estado
            status = kwargs.get('status')

            success = move.dte_update_status_from_webhook(
                status=status,
                track_id=kwargs.get('track_id'),
                xml_b64=kwargs.get('xml_b64'),
                message=kwargs.get('message')
            )

            elapsed_ms = int((time.time() - start_time) * 1000)

            if success:
                _logger.info(
                    "Webhook processed successfully",
                    extra={
                        'move_id': move_id,
                        'dte_id': dte_id,
                        'status': status,
                        'track_id': kwargs.get('track_id'),
                        'ip': ip,
                        'nonce': nonce,
                        'elapsed_ms': elapsed_ms
                    }
                )
                return {
                    'success': True,
                    'move_id': move_id,
                    'status': status
                }
            else:
                _logger.error(
                    "Failed to update DTE status",
                    extra={
                        'move_id': move_id,
                        'status': status,
                        'ip': ip,
                        'elapsed_ms': elapsed_ms
                    }
                )
                return {
                    'success': False,
                    'error': 'Failed to update status',
                    'code': 500
                }

        except (Forbidden, Unauthorized) as e:
            # Security exceptions - ya loggeadas
            elapsed_ms = int((time.time() - start_time) * 1000)
            return {
                'success': False,
                'error': str(e),
                'code': e.code
            }

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            _logger.error(
                "Unexpected error in webhook",
                extra={
                    'error': str(e),
                    'ip': ip,
                    'elapsed_ms': elapsed_ms
                },
                exc_info=True
            )
            return {
                'success': False,
                'error': str(e),
                'code': 500
            }

    @http.route('/api/dte/health', type='jsonrpc', auth='public', methods=['GET'])
    def dte_health(self):
        """
        Health check endpoint para verificar webhook activo

        Returns:
            dict: {'status': 'ok', 'redis': bool, 'version': str}
        """
        redis_ok = False
        try:
            r = get_redis_client()
            r.ping()
            redis_ok = True
        except Exception:
            pass

        return {
            'status': 'ok',
            'message': 'DTE Webhook is active',
            'version': '2.0.0-enterprise',
            'redis': redis_ok,
            'security_layers': [
                'rate_limiting_redis',
                'ip_whitelist_cidr',
                'hmac_sha256',
                'timestamp_validation',
                'replay_protection'
            ]
        }
