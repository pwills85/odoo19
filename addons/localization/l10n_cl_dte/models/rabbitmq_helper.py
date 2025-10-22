# -*- coding: utf-8 -*-
"""
RabbitMQ Helper para Odoo
Permite publicar mensajes a RabbitMQ desde modelos Odoo
"""

import pika
import json
import logging
from odoo import api, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class RabbitMQHelper(models.AbstractModel):
    """
    Helper para publicar mensajes a RabbitMQ
    
    Uso:
        rabbitmq = self.env['rabbitmq.helper']
        rabbitmq.publish_message(
            exchange='dte.direct',
            routing_key='generate',
            message={'dte_id': 'DTE-123', ...}
        )
    """
    
    _name = 'rabbitmq.helper'
    _description = 'RabbitMQ Helper'
    
    @api.model
    def _get_connection_params(self):
        """
        Obtiene parámetros de conexión desde ir.config_parameter
        
        Returns:
            dict: Parámetros para pika.ConnectionParameters
        """
        ICP = self.env['ir.config_parameter'].sudo()
        
        host = ICP.get_param('rabbitmq.host', 'rabbitmq')
        port = int(ICP.get_param('rabbitmq.port', '5672'))
        vhost = ICP.get_param('rabbitmq.vhost', '/odoo')
        user = ICP.get_param('rabbitmq.user', 'admin')
        password = ICP.get_param('rabbitmq.password', 'changeme')
        
        return {
            'host': host,
            'port': port,
            'virtual_host': vhost,
            'credentials': pika.PlainCredentials(user, password),
            'heartbeat': 60,
            'blocked_connection_timeout': 300
        }
    
    @api.model
    def publish_message(self, exchange, routing_key, message, priority=5):
        """
        Publica mensaje a RabbitMQ
        
        Args:
            exchange (str): Nombre del exchange (ej: 'dte.direct')
            routing_key (str): Routing key (ej: 'generate', 'validate', 'send')
            message (dict): Diccionario con datos del mensaje
            priority (int): Prioridad 0-10 (10 = más alta, default: 5)
            
        Returns:
            bool: True si se publicó exitosamente
            
        Raises:
            UserError: Si falla la publicación
        """
        connection = None
        
        try:
            # Validar priority
            if not 0 <= priority <= 10:
                raise ValueError(f"Priority debe estar entre 0 y 10, recibido: {priority}")
            
            # Conectar a RabbitMQ
            params = pika.ConnectionParameters(**self._get_connection_params())
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            
            # Serializar mensaje
            body = json.dumps(message, ensure_ascii=False)
            
            # Publicar con propiedades
            channel.basic_publish(
                exchange=exchange,
                routing_key=routing_key,
                body=body.encode('utf-8'),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # persistent
                    priority=priority,
                    content_type='application/json',
                    content_encoding='utf-8'
                )
            )
            
            _logger.info(
                "RabbitMQ: Mensaje publicado exitosamente - "
                "exchange=%s, routing_key=%s, dte_id=%s, priority=%s",
                exchange, routing_key, message.get('dte_id'), priority
            )
            
            return True
            
        except pika.exceptions.AMQPConnectionError as e:
            _logger.error(
                "RabbitMQ: Error de conexión - %s",
                str(e),
                exc_info=True
            )
            raise UserError(_(
                "No se pudo conectar a RabbitMQ. "
                "Verifique que el servicio esté activo.\n"
                "Error: %s"
            ) % str(e))
            
        except pika.exceptions.AMQPChannelError as e:
            _logger.error(
                "RabbitMQ: Error de canal - %s",
                str(e),
                exc_info=True
            )
            raise UserError(_(
                "Error al publicar mensaje a RabbitMQ.\n"
                "Error: %s"
            ) % str(e))
            
        except Exception as e:
            _logger.error(
                "RabbitMQ: Error inesperado - %s",
                str(e),
                exc_info=True
            )
            raise UserError(_(
                "Error al publicar mensaje a RabbitMQ.\n"
                "Error: %s"
            ) % str(e))
            
        finally:
            # Cerrar conexión
            if connection and connection.is_open:
                try:
                    connection.close()
                except Exception as e:
                    _logger.warning(
                        "RabbitMQ: Error al cerrar conexión - %s",
                        str(e)
                    )
    
    @api.model
    def test_connection(self):
        """
        Prueba la conexión a RabbitMQ
        
        Returns:
            dict: {'success': bool, 'message': str}
        """
        connection = None
        
        try:
            params = pika.ConnectionParameters(**self._get_connection_params())
            connection = pika.BlockingConnection(params)
            
            if connection.is_open:
                return {
                    'success': True,
                    'message': 'Conexión exitosa a RabbitMQ'
                }
            else:
                return {
                    'success': False,
                    'message': 'No se pudo abrir conexión'
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f'Error: {str(e)}'
            }
            
        finally:
            if connection and connection.is_open:
                connection.close()
