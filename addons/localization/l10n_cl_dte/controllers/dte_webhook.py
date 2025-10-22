# -*- coding: utf-8 -*-
"""
DTE Webhook Controller
Recibe notificaciones del DTE Service cuando termina de procesar DTEs
"""

from odoo import http
from odoo.http import request
import logging
import json

_logger = logging.getLogger(__name__)


class DTEWebhookController(http.Controller):
    """
    Controlador para recibir callbacks del DTE Service
    
    Endpoint: POST /api/dte/callback
    """
    
    @http.route('/api/dte/callback', type='json', auth='public', methods=['POST'], csrf=False)
    def dte_callback(self, **kwargs):
        """
        Recibe notificaciones del DTE Service
        
        Payload esperado:
        {
            "webhook_key": "secret_key",
            "dte_id": "DTE-123",
            "status": "sent|accepted|rejected|error",
            "track_id": "TRACK-XXX",
            "xml_b64": "base64...",
            "message": "Mensaje descriptivo"
        }
        
        Returns:
            dict: {'success': bool, 'move_id': int, 'status': str}
        """
        try:
            data = request.jsonrequest
            
            _logger.info(
                "DTE Webhook recibido: dte_id=%s, status=%s",
                data.get('dte_id'),
                data.get('status')
            )
            
            # 1. Validar webhook key
            ICP = request.env['ir.config_parameter'].sudo()
            expected_key = ICP.get_param('dte.webhook_key', 'default_key')
            
            if data.get('webhook_key') != expected_key:
                _logger.warning(
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
