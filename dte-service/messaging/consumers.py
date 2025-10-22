# -*- coding: utf-8 -*-
"""
Consumers RabbitMQ para DTE Service

Define los consumers que procesan mensajes de las colas:
- generate_consumer: Genera XML DTE
- validate_consumer: Valida DTE contra SII
- send_consumer: Envía DTE al SII

Cada consumer:
1. Recibe mensaje DTEMessage
2. Procesa según acción
3. Publica resultado o error
4. Maneja reintentos automáticos
"""

import structlog
import httpx
from typing import Dict, Any
from .models import DTEMessage, DTEAction

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════
# HELPER: Notificar a Odoo
# ═══════════════════════════════════════════════════════════

async def _notify_odoo(dte_id: str, status: str, **kwargs):
    """
    Notifica a Odoo el resultado del procesamiento
    
    Args:
        dte_id: ID del DTE (ej: "DTE-123")
        status: Estado ('sent', 'accepted', 'rejected', 'error')
        **kwargs: Datos adicionales (track_id, xml_b64, message, etc.)
    """
    from config import settings
    
    try:
        payload = {
            'webhook_key': settings.odoo_webhook_key,
            'dte_id': dte_id,
            'status': status,
            **kwargs
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{settings.odoo_url}/api/dte/callback",
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logger.info(
                        "odoo_notified_successfully",
                        dte_id=dte_id,
                        status=status
                    )
                else:
                    logger.error(
                        "odoo_notification_failed",
                        dte_id=dte_id,
                        error=result.get('error')
                    )
            else:
                logger.error(
                    "odoo_notification_http_error",
                    dte_id=dte_id,
                    status_code=response.status_code,
                    response=response.text[:200]
                )
                
    except httpx.TimeoutException:
        logger.error(
            "odoo_notification_timeout",
            dte_id=dte_id,
            timeout=10.0
        )
    except Exception as e:
        logger.error(
            "odoo_notification_error",
            dte_id=dte_id,
            error=str(e),
            error_type=type(e).__name__
        )
        # No re-raise: notificación es best-effort


# ═══════════════════════════════════════════════════════════
# GENERATE CONSUMER
# ═══════════════════════════════════════════════════════════

async def generate_consumer(message: DTEMessage):
    """
    Consumer para generar XML DTE
    
    Procesa mensajes de la cola dte.generate y genera el XML
    del DTE según el tipo y payload.
    
    Args:
        message: Mensaje con datos del DTE a generar
        
    Raises:
        ValueError: Si el payload es inválido
        Exception: Si falla la generación
        
    Example:
        >>> message = DTEMessage(
        ...     dte_id="DTE-001",
        ...     dte_type="33",
        ...     action=DTEAction.GENERATE,
        ...     payload={"folio": 1, "fecha": "2025-10-21"}
        ... )
        >>> await generate_consumer(message)
    """
    logger.info(
        "generate_consumer_started",
        dte_id=message.dte_id,
        dte_type=message.dte_type,
        retry_count=message.retry_count
    )
    
    try:
        # Validar que sea acción GENERATE
        if message.action != DTEAction.GENERATE:
            raise ValueError(f"Expected GENERATE action, got {message.action}")
            
        # Validar payload mínimo
        if not message.payload:
            raise ValueError("Payload cannot be empty")
            
        # TODO: Implementar generación real de XML
        # Por ahora, simulamos el proceso
        logger.info(
            "generate_consumer_processing",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            payload_keys=list(message.payload.keys())
        )
        
        # Simular procesamiento
        # En producción, aquí iría:
        # 1. Validar datos del payload
        # 2. Generar XML según tipo DTE
        # 3. Firmar XML
        # 4. Retornar XML generado
        
        xml_generated = f"<DTE tipo='{message.dte_type}' id='{message.dte_id}'>...</DTE>"
        
        logger.info(
            "generate_consumer_success",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            xml_length=len(xml_generated)
        )
        
        # ⭐ BRECHA 5: Notificar a Odoo
        await _notify_odoo(
            dte_id=message.dte_id,
            status='processing',
            message='DTE generado, iniciando validación'
        )
        
        # TODO: Publicar resultado a siguiente cola (validate)
        # await rabbitmq_client.publish(
        #     DTEMessage(..., action=DTEAction.VALIDATE),
        #     routing_key="validate"
        # )
        
    except ValueError as e:
        logger.error(
            "generate_consumer_validation_error",
            dte_id=message.dte_id,
            error=str(e)
        )
        # ⭐ BRECHA 5: Notificar error a Odoo
        await _notify_odoo(
            dte_id=message.dte_id,
            status='error',
            message=f'Error de validación: {str(e)}'
        )
        raise
        
    except Exception as e:
        logger.error(
            "generate_consumer_error",
            dte_id=message.dte_id,
            error=str(e),
            error_type=type(e).__name__
        )
        # ⭐ BRECHA 5: Notificar error a Odoo
        await _notify_odoo(
            dte_id=message.dte_id,
            status='error',
            message=f'Error al generar DTE: {str(e)}'
        )
        raise


# ═══════════════════════════════════════════════════════════
# VALIDATE CONSUMER
# ═══════════════════════════════════════════════════════════

async def validate_consumer(message: DTEMessage):
    """
    Consumer para validar DTE contra SII
    
    Procesa mensajes de la cola dte.validate y valida el XML
    del DTE contra los esquemas y reglas del SII.
    
    Args:
        message: Mensaje con XML DTE a validar
        
    Raises:
        ValueError: Si el XML es inválido
        Exception: Si falla la validación
        
    Example:
        >>> message = DTEMessage(
        ...     dte_id="DTE-001",
        ...     dte_type="33",
        ...     action=DTEAction.VALIDATE,
        ...     payload={"xml": "<DTE>...</DTE>"}
        ... )
        >>> await validate_consumer(message)
    """
    logger.info(
        "validate_consumer_started",
        dte_id=message.dte_id,
        dte_type=message.dte_type,
        retry_count=message.retry_count
    )
    
    try:
        # Validar que sea acción VALIDATE
        if message.action != DTEAction.VALIDATE:
            raise ValueError(f"Expected VALIDATE action, got {message.action}")
            
        # Validar que tenga XML
        if "xml" not in message.payload:
            raise ValueError("Payload must contain 'xml' key")
            
        xml_content = message.payload["xml"]
        
        # TODO: Implementar validación real contra SII
        # Por ahora, simulamos el proceso
        logger.info(
            "validate_consumer_processing",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            xml_length=len(xml_content)
        )
        
        # Simular validación
        # En producción, aquí iría:
        # 1. Validar contra XSD del SII
        # 2. Validar TED (Timbre Electrónico)
        # 3. Validar estructura según tipo DTE
        # 4. Validar RUT emisor y receptor
        
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        logger.info(
            "validate_consumer_success",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            valid=validation_result["valid"]
        )
        
        # TODO: Publicar resultado a siguiente cola (send)
        # if validation_result["valid"]:
        #     await rabbitmq_client.publish(
        #         DTEMessage(..., action=DTEAction.SEND),
        #         routing_key="send"
        #     )
        
    except ValueError as e:
        logger.error(
            "validate_consumer_validation_error",
            dte_id=message.dte_id,
            error=str(e)
        )
        raise
        
    except Exception as e:
        logger.error(
            "validate_consumer_error",
            dte_id=message.dte_id,
            error=str(e),
            error_type=type(e).__name__
        )
        raise


# ═══════════════════════════════════════════════════════════
# SEND CONSUMER
# ═══════════════════════════════════════════════════════════

async def send_consumer(message: DTEMessage):
    """
    Consumer para enviar DTE al SII
    
    Procesa mensajes de la cola dte.send y envía el DTE
    validado al Servicio de Impuestos Internos.
    
    Args:
        message: Mensaje con XML DTE validado a enviar
        
    Raises:
        ValueError: Si faltan datos requeridos
        ConnectionError: Si falla la conexión con SII
        Exception: Si falla el envío
        
    Example:
        >>> message = DTEMessage(
        ...     dte_id="DTE-001",
        ...     dte_type="33",
        ...     action=DTEAction.SEND,
        ...     payload={"xml": "<DTE>...</DTE>", "rut_emisor": "76123456-K"}
        ... )
        >>> await send_consumer(message)
    """
    logger.info(
        "send_consumer_started",
        dte_id=message.dte_id,
        dte_type=message.dte_type,
        retry_count=message.retry_count
    )
    
    try:
        # Validar que sea acción SEND
        if message.action != DTEAction.SEND:
            raise ValueError(f"Expected SEND action, got {message.action}")
            
        # Validar datos requeridos
        required_keys = ["xml", "rut_emisor"]
        missing_keys = [k for k in required_keys if k not in message.payload]
        if missing_keys:
            raise ValueError(f"Missing required keys: {missing_keys}")
            
        xml_content = message.payload["xml"]
        rut_emisor = message.payload["rut_emisor"]
        
        # TODO: Implementar envío real al SII
        # Por ahora, simulamos el proceso
        logger.info(
            "send_consumer_processing",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            rut_emisor=rut_emisor,
            xml_length=len(xml_content)
        )
        
        # Simular envío
        # En producción, aquí iría:
        # 1. Conectar a SOAP del SII
        # 2. Autenticar con certificado
        # 3. Enviar DTE
        # 4. Recibir track_id
        # 5. Guardar track_id para consulta posterior
        
        send_result = {
            "success": True,
            "track_id": f"TRACK-{message.dte_id}",
            "timestamp": "2025-10-21T22:50:00"
        }
        
        logger.info(
            "send_consumer_success",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            track_id=send_result["track_id"]
        )
        
        # TODO: Notificar a Odoo del resultado
        # await notify_odoo(message.dte_id, send_result)
        
    except ValueError as e:
        logger.error(
            "send_consumer_validation_error",
            dte_id=message.dte_id,
            error=str(e)
        )
        raise
        
    except ConnectionError as e:
        logger.error(
            "send_consumer_connection_error",
            dte_id=message.dte_id,
            error=str(e)
        )
        raise
        
    except Exception as e:
        logger.error(
            "send_consumer_error",
            dte_id=message.dte_id,
            error=str(e),
            error_type=type(e).__name__
        )
        raise


# ═══════════════════════════════════════════════════════════
# CONSUMER REGISTRY
# ═══════════════════════════════════════════════════════════

CONSUMERS: Dict[str, Any] = {
    "dte.generate": generate_consumer,
    "dte.validate": validate_consumer,
    "dte.send": send_consumer,
}
"""
Registry de consumers disponibles

Mapea nombre de cola a función consumer correspondiente.
Útil para iniciar consumers dinámicamente.

Example:
    >>> for queue_name, consumer_func in CONSUMERS.items():
    ...     await rabbitmq_client.consume(queue_name, consumer_func)
"""
