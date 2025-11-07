# -*- coding: utf-8 -*-
"""
Dashboard WebSocket Controller
Maneja conexiones WebSocket para actualizaciones en tiempo real
Siguiendo PROMPT_AGENT_IA.md
"""

import json
import logging
import threading
import time
from datetime import datetime
from collections import defaultdict
from odoo import http
from odoo.http import request


_logger = logging.getLogger(__name__)

# WebSocket connection tracking for rate limiting
_websocket_connections = defaultdict(list)
_websocket_lock = threading.Lock()


class DashboardWebSocketController(http.Controller):
    """
    Controlador WebSocket para el dashboard financiero.
    Gestiona suscripciones y envía actualizaciones en tiempo real.
    """
    
    # Almacén de conexiones activas
    _connections = {}
    _subscriptions = {}
    _lock = threading.Lock()
    
    def __init__(self):
        super().__init__()
        # Iniciar thread de heartbeat
        self._start_heartbeat_thread()
        # Iniciar thread de monitoreo de cambios
        self._start_monitor_thread()
    
    @http.route('/websocket/dashboard', type='websocket', auth='user', cors='*')
    def dashboard_websocket(self, websocket):
        """
        Endpoint principal del WebSocket del dashboard
        Enhanced with security controls
        """
        user_id = request.env.user.id
        client_ip = request.httprequest.remote_addr
        connection_id = f"{user_id}_{datetime.now().timestamp()}"
        
        # Rate limiting for WebSocket connections
        with _websocket_lock:
            current_time = time.time()
            client_key = f"{client_ip}:{user_id}"
            
            # Clean old connections (older than 1 hour)
            hour_ago = current_time - 3600
            _websocket_connections[client_key] = [
                conn_time for conn_time in _websocket_connections[client_key]
                if conn_time > hour_ago
            ]
            
            # Check connection limit (max 5 connections per user per hour)
            if len(_websocket_connections[client_key]) >= 5:
                _logger.warning(f"WebSocket connection limit exceeded for {client_key}")
                websocket.close(code=1008, reason="Connection limit exceeded")
                return
            
            _websocket_connections[client_key].append(current_time)
        
        _logger.info(f"WebSocket connection established: {connection_id} from {client_ip}")
        
        try:
            # Registrar conexión
            with self._lock:
                self._connections[connection_id] = {
                    'websocket': websocket,
                    'user_id': user_id,
                    'connected_at': datetime.now(),
                    'subscriptions': set()
                }
            
            # Enviar confirmación de conexión
            self._send_to_connection(connection_id, {
                'type': 'connection',
                'status': 'connected',
                'connection_id': connection_id
            })
            
            # Procesar mensajes
            while True:
                message = websocket.receive()
                if message is None:
                    break
                
                try:
                    data = json.loads(message)
                    self._handle_message(connection_id, data)
                except json.JSONDecodeError:
                    _logger.error(f"Invalid JSON received: {message}")
                except Exception as e:
                    _logger.error(f"Error handling message: {str(e)}")
                    
        except Exception as e:
            _logger.error(f"WebSocket error: {str(e)}")
        finally:
            # Limpiar al desconectar
            self._cleanup_connection(connection_id)
            _logger.info(f"WebSocket connection closed: {connection_id}")
    
    def _handle_message(self, connection_id, data):
        """
        Procesa mensajes recibidos del cliente
        """
        action = data.get('action')
        
        if action == 'subscribe':
            self._handle_subscribe(connection_id, data)
        elif action == 'unsubscribe':
            self._handle_unsubscribe(connection_id, data)
        elif action == 'update_filters':
            self._handle_update_filters(connection_id, data)
        elif action == 'ping':
            self._handle_ping(connection_id)
        else:
            _logger.warning(f"Unknown action: {action}")
    
    def _handle_subscribe(self, connection_id, data):
        """
        Maneja suscripción a un widget
        """
        widget_id = data.get('widget_id')
        widget_type = data.get('widget_type')
        filters = data.get('filters', {})
        
        if not widget_id:
            return
        
        subscription_key = f"{widget_id}_{connection_id}"
        
        with self._lock:
            # Registrar suscripción
            self._subscriptions[subscription_key] = {
                'connection_id': connection_id,
                'widget_id': widget_id,
                'widget_type': widget_type,
                'filters': filters,
                'user_id': self._connections[connection_id]['user_id']
            }
            
            # Añadir a las suscripciones de la conexión
            self._connections[connection_id]['subscriptions'].add(subscription_key)
        
        # Enviar datos iniciales
        self._send_widget_update(subscription_key)
        
        _logger.info(f"Subscribed to widget {widget_id} for connection {connection_id}")
    
    def _handle_unsubscribe(self, connection_id, data):
        """
        Maneja cancelación de suscripción
        """
        widget_id = data.get('widget_id')
        if not widget_id:
            return
        
        subscription_key = f"{widget_id}_{connection_id}"
        
        with self._lock:
            if subscription_key in self._subscriptions:
                del self._subscriptions[subscription_key]
            
            if connection_id in self._connections:
                self._connections[connection_id]['subscriptions'].discard(subscription_key)
        
        _logger.info(f"Unsubscribed from widget {widget_id} for connection {connection_id}")
    
    def _handle_update_filters(self, connection_id, data):
        """
        Actualiza filtros de una suscripción
        """
        widget_id = data.get('widget_id')
        filters = data.get('filters', {})
        
        if not widget_id:
            return
        
        subscription_key = f"{widget_id}_{connection_id}"
        
        with self._lock:
            if subscription_key in self._subscriptions:
                self._subscriptions[subscription_key]['filters'] = filters
        
        # Enviar datos actualizados
        self._send_widget_update(subscription_key)
    
    def _handle_ping(self, connection_id):
        """
        Responde a ping con pong
        """
        self._send_to_connection(connection_id, {'type': 'pong'})
    
    def _send_widget_update(self, subscription_key):
        """
        Envía actualización de datos de un widget
        """
        with self._lock:
            subscription = self._subscriptions.get(subscription_key)
            if not subscription:
                return
        
        try:
            # Cambiar al entorno del usuario
            user_id = subscription['user_id']
            widget_id = subscription['widget_id']
            widget_type = subscription['widget_type']
            filters = subscription['filters']
            
            # Obtener datos del widget
            with request.env.cr.savepoint():
                env = request.env(user=user_id)
                
                # Obtener widget
                widget = env['financial.dashboard.widget'].browse(int(widget_id))
                if not widget.exists():
                    return
                
                # Obtener datos usando el servicio
                data = widget.get_widget_data(filters)
                
                # Preparar mensaje
                message = {
                    'type': 'widget_update',
                    'widget_id': widget_id,
                    'widget_type': widget_type,
                    'update_data': data,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Enviar a la conexión
                self._send_to_connection(subscription['connection_id'], message)
                
        except Exception as e:
            _logger.error(f"Error sending widget update: {str(e)}")
    
    def _send_to_connection(self, connection_id, message):
        """
        Envía mensaje a una conexión específica
        """
        with self._lock:
            connection = self._connections.get(connection_id)
            if connection:
                try:
                    connection['websocket'].send(json.dumps(message))
                except Exception as e:
                    _logger.error(f"Error sending to connection {connection_id}: {str(e)}")
                    # Marcar para limpieza
                    self._cleanup_connection(connection_id)
    
    def _broadcast_to_widget_subscribers(self, widget_id, message):
        """
        Envía mensaje a todos los suscriptores de un widget
        """
        with self._lock:
            for subscription_key, subscription in list(self._subscriptions.items()):
                if subscription['widget_id'] == widget_id:
                    self._send_to_connection(subscription['connection_id'], message)
    
    def _cleanup_connection(self, connection_id):
        """
        Limpia una conexión y sus suscripciones
        """
        with self._lock:
            # Eliminar suscripciones
            if connection_id in self._connections:
                for subscription_key in self._connections[connection_id]['subscriptions']:
                    if subscription_key in self._subscriptions:
                        del self._subscriptions[subscription_key]
                
                # Eliminar conexión
                del self._connections[connection_id]
    
    def _start_heartbeat_thread(self):
        """
        Inicia thread para enviar heartbeats
        """
        def heartbeat():
            while True:
                time.sleep(30)  # Cada 30 segundos
                
                with self._lock:
                    for connection_id in list(self._connections.keys()):
                        self._send_to_connection(connection_id, {'type': 'heartbeat'})
        
        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
    
    def _start_monitor_thread(self):
        """
        Inicia thread para monitorear cambios y enviar actualizaciones
        """
        def monitor():
            while True:
                time.sleep(5)  # Cada 5 segundos
                
                try:
                    # Verificar actualizaciones para cada suscripción
                    with self._lock:
                        subscription_keys = list(self._subscriptions.keys())
                    
                    for subscription_key in subscription_keys:
                        # Aquí se podría implementar lógica más sofisticada
                        # para detectar cambios reales en los datos
                        # Por ahora, actualizamos periódicamente
                        if self._should_update_widget(subscription_key):
                            self._send_widget_update(subscription_key)
                            
                except Exception as e:
                    _logger.error(f"Error in monitor thread: {str(e)}")
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def _should_update_widget(self, subscription_key):
        """
        Determina si un widget debe actualizarse
        """
        # Por ahora, actualizar widgets de tipo gauge y kpi cada 30 segundos
        with self._lock:
            subscription = self._subscriptions.get(subscription_key)
            if subscription:
                widget_type = subscription.get('widget_type')
                if widget_type in ['gauge', 'kpi']:
                    # Simple throttling - actualizar cada 30 segundos
                    last_update = subscription.get('last_update', 0)
                    if time.time() - last_update > 30:
                        subscription['last_update'] = time.time()
                        return True
        
        return False
    
    @classmethod
    def notify_widget_update(cls, widget_id, update_type='data'):
        """
        Método público para notificar actualizaciones de widgets
        Puede ser llamado desde otros módulos
        """
        message = {
            'type': 'widget_update',
            'widget_id': str(widget_id),
            'update_type': update_type,
            'timestamp': datetime.now().isoformat()
        }
        
        controller = cls()
        controller._broadcast_to_widget_subscribers(str(widget_id), message)
    
    @classmethod
    def send_dashboard_alert(cls, title, message, severity='info', user_ids=None):
        """
        Envía una alerta a usuarios del dashboard
        """
        alert_message = {
            'type': 'alert',
            'title': title,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        controller = cls()
        
        with controller._lock:
            for connection_id, connection in controller._connections.items():
                if user_ids is None or connection['user_id'] in user_ids:
                    controller._send_to_connection(connection_id, alert_message)