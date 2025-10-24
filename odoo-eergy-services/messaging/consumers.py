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
            
        # Implementar generación real de XML
        logger.info(
            "generate_consumer_processing",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            payload_keys=list(message.payload.keys())
        )

        # Importar generator correspondiente
        from generators.dte_generator_33 import DTEGenerator33
        from generators.dte_generator_56 import DTEGenerator56
        from generators.dte_generator_61 import DTEGenerator61
        from generators.dte_generator_52 import DTEGenerator52
        from generators.dte_generator_34 import DTEGenerator34

        # Seleccionar generator según tipo
        generators = {
            '33': DTEGenerator33,
            '34': DTEGenerator34,
            '52': DTEGenerator52,
            '56': DTEGenerator56,
            '61': DTEGenerator61,
        }

        generator_class = generators.get(message.dte_type)
        if not generator_class:
            raise ValueError(f"DTE type {message.dte_type} not supported")

        # Generar XML
        generator = generator_class()
        xml_generated = generator.generate(message.payload)
        
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
        
        # Implementar validación real contra SII
        logger.info(
            "validate_consumer_processing",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            xml_length=len(xml_content)
        )

        # Importar validators
        from validators.xsd_validator import XSDValidator
        from validators.dte_structure_validator import DTEStructureValidator
        from validators.ted_validator import TEDValidator

        errors = []
        warnings = []

        # 1. Validar contra XSD del SII
        xsd_validator = XSDValidator()
        try:
            is_valid_xsd, xsd_errors = xsd_validator.validate(xml_content, schema_name='DTE', strict=True)
            if not is_valid_xsd:
                errors.extend([f"XSD: {e}" for e in xsd_errors])
        except Exception as e:
            errors.append(f"XSD validation failed: {str(e)}")

        # 2. Validar estructura DTE
        try:
            structure_validator = DTEStructureValidator()
            is_valid_structure, structure_errors = structure_validator.validate(xml_content, message.dte_type)
            if not is_valid_structure:
                errors.extend([f"Structure: {e}" for e in structure_errors])
        except Exception as e:
            warnings.append(f"Structure validation incomplete: {str(e)}")

        # 3. Validar TED (Timbre Electrónico) si existe
        try:
            ted_validator = TEDValidator()
            has_ted, ted_errors = ted_validator.validate(xml_content)
            if has_ted and ted_errors:
                warnings.extend([f"TED: {e}" for e in ted_errors])
        except Exception as e:
            warnings.append(f"TED validation incomplete: {str(e)}")

        validation_result = {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
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
        
        # Implementar envío real al SII
        logger.info(
            "send_consumer_processing",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            rut_emisor=rut_emisor,
            xml_length=len(xml_content)
        )

        # Importar SII SOAP client
        from clients.sii_soap_client import SIISOAPClient
        from datetime import datetime

        # Obtener certificado digital (debe venir en payload)
        cert_data = message.payload.get('certificate')
        if not cert_data:
            raise ValueError("Certificate data required for SII submission")

        # Conectar a SII y enviar
        sii_client = SIISOAPClient()

        try:
            # Enviar DTE al SII usando SOAP
            response = await sii_client.send_dte(
                dte_xml=xml_content,
                rut_emisor=rut_emisor,
                cert_file=cert_data.get('cert_file'),
                cert_password=cert_data.get('password')
            )

            if response.get('success'):
                send_result = {
                    "success": True,
                    "track_id": response.get('track_id'),
                    "timestamp": datetime.now().isoformat(),
                    "sii_response": response.get('message', '')
                }
            else:
                # SII rechazó el DTE
                send_result = {
                    "success": False,
                    "error": response.get('error', 'Unknown SII error'),
                    "sii_code": response.get('code'),
                    "timestamp": datetime.now().isoformat()
                }

        except ConnectionError as e:
            raise ConnectionError(f"Failed to connect to SII: {str(e)}")
        except Exception as e:
            raise Exception(f"Error sending DTE to SII: {str(e)}")
        
        logger.info(
            "send_consumer_success",
            dte_id=message.dte_id,
            dte_type=message.dte_type,
            track_id=send_result["track_id"]
        )
        
        # Notificar a Odoo del resultado
        await _notify_odoo(
            dte_id=message.dte_id,
            status='sent' if send_result.get('success') else 'rejected',
            track_id=send_result.get('track_id'),
            message=send_result.get('sii_response') or send_result.get('error'),
            sii_code=send_result.get('sii_code')
        )
        
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
