# -*- coding: utf-8 -*-
"""
Messaging Package - RabbitMQ Integration

Este paquete contiene toda la lógica de mensajería RabbitMQ para el DTE Service.

Módulos:
    - models: Modelos Pydantic para mensajes
    - rabbitmq_client: Cliente RabbitMQ profesional
    - consumers: Consumers para procesar mensajes

Fase 2 - RabbitMQ Implementation
"""

__version__ = "1.0.0"
__author__ = "Eergygroup"

from .models import DTEMessage, DTEAction
from .rabbitmq_client import RabbitMQClient, get_rabbitmq_client

__all__ = [
    "DTEMessage",
    "DTEAction",
    "RabbitMQClient",
    "get_rabbitmq_client",
]
