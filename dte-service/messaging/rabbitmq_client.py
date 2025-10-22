# -*- coding: utf-8 -*-
"""
Cliente RabbitMQ Profesional para DTE Service

Features:
- Reconnection automática con exponential backoff
- Dead Letter Queues para mensajes fallidos
- Priority queues (0-10)
- Message TTL por queue
- Retry logic (máximo 3 intentos)
- Prefetch control para throughput
- Logging estructurado
- Graceful shutdown

Uso:
    client = RabbitMQClient(url="amqp://admin:pass@rabbitmq:5672//odoo")
    await client.connect()
    
    # Publish
    message = DTEMessage(...)
    await client.publish(message, routing_key="generate")
    
    # Consume
    await client.consume("dte.generate", callback_function)
"""

import asyncio
import structlog
from aio_pika import connect_robust, Message, DeliveryMode, ExchangeType
from aio_pika.abc import (
    AbstractRobustConnection,
    AbstractRobustChannel,
    AbstractIncomingMessage,
    AbstractExchange,
    AbstractQueue
)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from typing import Optional, Callable, Dict, Any
from .models import DTEMessage, DTEAction

logger = structlog.get_logger(__name__)


class RabbitMQClient:
    """
    Cliente RabbitMQ profesional con features enterprise
    
    Attributes:
        url: URL de conexión AMQP
        prefetch_count: Número de mensajes a prefetch
        exchange_name: Nombre del exchange principal
        connection: Conexión robusta a RabbitMQ
        channel: Canal de comunicación
        exchange: Exchange principal
        
    Example:
        >>> client = RabbitMQClient(url="amqp://admin:pass@rabbitmq:5672//odoo")
        >>> await client.connect()
        >>> message = DTEMessage(dte_id="DTE-001", dte_type="33", action=DTEAction.GENERATE, payload={})
        >>> await client.publish(message, routing_key="generate")
    """
    
    def __init__(
        self,
        url: str,
        prefetch_count: int = 10,
        exchange_name: str = "dte.direct"
    ):
        """
        Inicializa el cliente RabbitMQ
        
        Args:
            url: URL de conexión AMQP (ej: amqp://user:pass@host:5672//vhost)
            prefetch_count: Número de mensajes a prefetch (default: 10)
            exchange_name: Nombre del exchange principal (default: dte.direct)
        """
        self.url = url
        self.prefetch_count = prefetch_count
        self.exchange_name = exchange_name
        
        self.connection: Optional[AbstractRobustConnection] = None
        self.channel: Optional[AbstractRobustChannel] = None
        self.exchange: Optional[AbstractExchange] = None
        
        logger.info(
            "rabbitmq_client_initialized",
            url=self._mask_password(url),
            prefetch=prefetch_count,
            exchange=exchange_name
        )
        
    @staticmethod
    def _mask_password(url: str) -> str:
        """
        Enmascara la contraseña en la URL para logging seguro
        
        Args:
            url: URL completa con credenciales
            
        Returns:
            URL con contraseña enmascarada
        """
        if "@" in url and "://" in url:
            protocol, rest = url.split("://", 1)
            if "@" in rest:
                credentials, host = rest.split("@", 1)
                if ":" in credentials:
                    user, _ = credentials.split(":", 1)
                    return f"{protocol}://{user}:****@{host}"
        return url
        
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        retry=retry_if_exception_type((ConnectionError, OSError)),
        reraise=True
    )
    async def connect(self):
        """
        Conecta a RabbitMQ con retry automático y exponential backoff
        
        Intenta conectar hasta 5 veces con delays de 4, 8, 16, 32, 60 segundos.
        
        Raises:
            ConnectionError: Si no puede conectar después de 5 intentos
            
        Example:
            >>> client = RabbitMQClient(url="amqp://...")
            >>> await client.connect()
        """
        logger.info("rabbitmq_connecting", url=self._mask_password(self.url))
        
        try:
            # Conexión robusta con reconnection automática
            self.connection = await connect_robust(
                self.url,
                heartbeat=60,
                connection_attempts=5,
                retry_delay=5
            )
            
            # Crear canal con QoS
            self.channel = await self.connection.channel()
            await self.channel.set_qos(prefetch_count=self.prefetch_count)
            
            # Declarar exchange principal
            self.exchange = await self.channel.declare_exchange(
                self.exchange_name,
                ExchangeType.DIRECT,
                durable=True
            )
            
            logger.info(
                "rabbitmq_connected",
                exchange=self.exchange_name,
                prefetch=self.prefetch_count
            )
            
        except Exception as e:
            logger.error(
                "rabbitmq_connection_error",
                error=str(e),
                url=self._mask_password(self.url)
            )
            raise ConnectionError(f"Failed to connect to RabbitMQ: {e}")
            
    async def publish(
        self,
        message: DTEMessage,
        routing_key: str,
        priority: Optional[int] = None
    ):
        """
        Publica mensaje con prioridad y persistencia
        
        Args:
            message: Mensaje DTE a publicar
            routing_key: Routing key (generate, validate, send)
            priority: Prioridad opcional 0-10 (override message.priority)
            
        Raises:
            ConnectionError: Si no hay conexión activa
            ValueError: Si priority está fuera de rango
            
        Example:
            >>> message = DTEMessage(dte_id="DTE-001", dte_type="33", action=DTEAction.GENERATE, payload={})
            >>> await client.publish(message, routing_key="generate", priority=8)
        """
        if not self.exchange:
            logger.warning("rabbitmq_not_connected_attempting_reconnect")
            await self.connect()
            
        # Validar priority
        final_priority = priority if priority is not None else message.priority
        if not 0 <= final_priority <= 10:
            raise ValueError(f"Priority must be 0-10, got {final_priority}")
            
        # Serializar mensaje
        body = message.model_dump_json().encode()
        
        # Crear mensaje AMQP
        msg = Message(
            body=body,
            delivery_mode=DeliveryMode.PERSISTENT,
            priority=final_priority,
            content_type="application/json",
            headers={
                "x-retry-count": message.retry_count,
                "x-dte-id": message.dte_id,
                "x-dte-type": message.dte_type,
                "x-action": message.action.value
            }
        )
        
        # Publicar
        await self.exchange.publish(
            msg,
            routing_key=routing_key
        )
        
        logger.info(
            "message_published",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            action=message.action.value,
            routing_key=routing_key,
            priority=final_priority,
            retry_count=message.retry_count
        )
        
    async def consume(
        self,
        queue_name: str,
        callback: Callable,
        auto_ack: bool = False,
        max_retries: int = 3
    ):
        """
        Consume mensajes con callback y manejo de errores
        
        Args:
            queue_name: Nombre de la cola a consumir
            callback: Función async a ejecutar por cada mensaje
            auto_ack: Auto-acknowledge (default False, manual ack)
            max_retries: Número máximo de reintentos (default 3)
            
        Example:
            >>> async def process_message(message: DTEMessage):
            ...     print(f"Processing {message.dte_id}")
            >>> await client.consume("dte.generate", process_message)
        """
        if not self.channel:
            await self.connect()
            
        # Declarar cola (idempotente)
        queue = await self.channel.declare_queue(
            queue_name,
            durable=True,
            arguments={
                "x-message-ttl": 3600000,  # 1 hora
                "x-max-priority": 10,
                "x-dead-letter-exchange": "dte.dlx",
                "x-dead-letter-routing-key": f"{queue_name}.dlq"
            }
        )
        
        # Bind a exchange
        await queue.bind(self.exchange, routing_key=queue_name.split(".")[-1])
        
        logger.info(
            "consumer_started",
            queue=queue_name,
            max_retries=max_retries,
            auto_ack=auto_ack
        )
        
        # Consumir mensajes
        async with queue.iterator() as queue_iter:
            async for amqp_message in queue_iter:
                async with amqp_message.process(ignore_processed=True):
                    try:
                        # Parsear mensaje
                        dte_message = DTEMessage.model_validate_json(amqp_message.body)
                        
                        logger.debug(
                            "message_received",
                            dte_id=dte_message.dte_id,
                            queue=queue_name,
                            retry_count=dte_message.retry_count
                        )
                        
                        # Ejecutar callback
                        await callback(dte_message)
                        
                        # Acknowledge si no es auto
                        if not auto_ack:
                            await amqp_message.ack()
                            
                        logger.info(
                            "message_processed_successfully",
                            dte_id=dte_message.dte_id,
                            queue=queue_name
                        )
                        
                    except Exception as e:
                        logger.error(
                            "message_processing_error",
                            error=str(e),
                            error_type=type(e).__name__,
                            queue=queue_name,
                            message_id=amqp_message.message_id
                        )
                        
                        # Obtener retry count
                        retry_count = amqp_message.headers.get("x-retry-count", 0)
                        
                        # Decidir: requeue o DLQ
                        if retry_count < max_retries:
                            # Requeue para retry
                            await amqp_message.nack(requeue=True)
                            logger.info(
                                "message_requeued_for_retry",
                                retry_count=retry_count,
                                max_retries=max_retries,
                                queue=queue_name
                            )
                        else:
                            # Enviar a Dead Letter Queue
                            await amqp_message.nack(requeue=False)
                            logger.warning(
                                "message_sent_to_dlq",
                                retry_count=retry_count,
                                max_retries=max_retries,
                                queue=queue_name,
                                dlq=f"{queue_name}.dlq"
                            )
                            
    async def close(self):
        """
        Cierra conexión gracefully
        
        Example:
            >>> await client.close()
        """
        if self.connection:
            await self.connection.close()
            logger.info("rabbitmq_disconnected")


# ═══════════════════════════════════════════════════════════
# FACTORY PATTERN (Singleton)
# ═══════════════════════════════════════════════════════════

_rabbitmq_client: Optional[RabbitMQClient] = None


def get_rabbitmq_client(url: str, prefetch_count: int = 10) -> RabbitMQClient:
    """
    Factory para obtener instancia singleton de RabbitMQ client
    
    Args:
        url: URL de conexión AMQP
        prefetch_count: Número de mensajes a prefetch
        
    Returns:
        Instancia única de RabbitMQClient
        
    Example:
        >>> client = get_rabbitmq_client(url="amqp://admin:pass@rabbitmq:5672//odoo")
        >>> await client.connect()
    """
    global _rabbitmq_client
    
    if _rabbitmq_client is None:
        _rabbitmq_client = RabbitMQClient(url=url, prefetch_count=prefetch_count)
        logger.info("rabbitmq_client_factory_created_new_instance")
    else:
        logger.debug("rabbitmq_client_factory_returned_existing_instance")
        
    return _rabbitmq_client


def reset_rabbitmq_client():
    """
    Reset del singleton (útil para testing)
    
    Example:
        >>> reset_rabbitmq_client()
    """
    global _rabbitmq_client
    _rabbitmq_client = None
    logger.debug("rabbitmq_client_factory_reset")
