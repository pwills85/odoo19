# -*- coding: utf-8 -*-
"""
Modelos de mensajería RabbitMQ para DTE Service

Define los modelos Pydantic para mensajes que circulan por RabbitMQ.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum


class DTEAction(str, Enum):
    """
    Acciones disponibles para DTEs
    
    Attributes:
        GENERATE: Generar XML DTE
        VALIDATE: Validar DTE contra SII
        SEND: Enviar DTE al SII
    """
    GENERATE = "generate"
    VALIDATE = "validate"
    SEND = "send"


class DTEMessage(BaseModel):
    """
    Modelo de mensaje DTE para RabbitMQ
    
    Este modelo define la estructura de los mensajes que circulan
    por las colas de RabbitMQ para procesamiento de DTEs.
    
    Attributes:
        dte_id: ID único del DTE (ej: "DTE-2025-001")
        dte_type: Tipo DTE según SII (33, 34, 52, 56, 61)
        action: Acción a realizar (generate, validate, send)
        payload: Datos del DTE en formato dict
        priority: Prioridad 0-10 (10 = más alta)
        retry_count: Número de reintentos realizados
        created_at: Timestamp de creación del mensaje
        company_id: ID de compañía Odoo (opcional)
        user_id: ID de usuario Odoo (opcional)
        
    Example:
        >>> message = DTEMessage(
        ...     dte_id="DTE-2025-001",
        ...     dte_type="33",
        ...     action=DTEAction.GENERATE,
        ...     payload={"folio": 1, "fecha": "2025-10-21"},
        ...     priority=8
        ... )
    """
    
    # ═══════════════════════════════════════════════════════════
    # IDENTIFICACIÓN
    # ═══════════════════════════════════════════════════════════
    
    dte_id: str = Field(
        ...,
        description="ID único del DTE",
        min_length=1,
        max_length=100,
        examples=["DTE-2025-001", "INVOICE-123"]
    )
    
    dte_type: str = Field(
        ...,
        description="Tipo DTE según SII (33, 34, 52, 56, 61)",
        pattern="^(33|34|39|41|43|46|52|56|61)$",
        examples=["33", "34", "52"]
    )
    
    # ═══════════════════════════════════════════════════════════
    # ACCIÓN
    # ═══════════════════════════════════════════════════════════
    
    action: DTEAction = Field(
        ...,
        description="Acción a realizar: generate, validate, send"
    )
    
    # ═══════════════════════════════════════════════════════════
    # PAYLOAD
    # ═══════════════════════════════════════════════════════════
    
    payload: Dict[str, Any] = Field(
        ...,
        description="Datos del DTE en formato dict",
        examples=[{
            "folio": 1,
            "fecha_emision": "2025-10-21",
            "emisor": {"rut": "76123456-K"},
            "receptor": {"rut": "12345678-5"},
            "totales": {"monto_total": 119000}
        }]
    )
    
    # ═══════════════════════════════════════════════════════════
    # METADATOS
    # ═══════════════════════════════════════════════════════════
    
    priority: int = Field(
        default=5,
        ge=0,
        le=10,
        description="Prioridad 0-10 (10 = más alta)"
    )
    
    retry_count: int = Field(
        default=0,
        ge=0,
        le=10,
        description="Número de reintentos realizados"
    )
    
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp de creación del mensaje"
    )
    
    # ═══════════════════════════════════════════════════════════
    # OPCIONALES (ODOO)
    # ═══════════════════════════════════════════════════════════
    
    company_id: Optional[int] = Field(
        default=None,
        description="ID de compañía Odoo"
    )
    
    user_id: Optional[int] = Field(
        default=None,
        description="ID de usuario Odoo que creó el DTE"
    )
    
    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN
    # ═══════════════════════════════════════════════════════════
    
    class Config:
        """Configuración del modelo Pydantic"""
        json_schema_extra = {
            "example": {
                "dte_id": "DTE-2025-001",
                "dte_type": "33",
                "action": "generate",
                "payload": {
                    "folio": 1,
                    "fecha_emision": "2025-10-21",
                    "emisor": {
                        "rut": "76123456-K",
                        "razon_social": "Empresa Demo"
                    },
                    "receptor": {
                        "rut": "12345678-5",
                        "razon_social": "Cliente Demo"
                    },
                    "totales": {
                        "monto_neto": 100000,
                        "monto_iva": 19000,
                        "monto_total": 119000
                    }
                },
                "priority": 8,
                "retry_count": 0,
                "company_id": 1,
                "user_id": 2
            }
        }
        
    def increment_retry(self) -> "DTEMessage":
        """
        Incrementa el contador de reintentos
        
        Returns:
            Nueva instancia con retry_count incrementado
        """
        return self.model_copy(update={"retry_count": self.retry_count + 1})
        
    def can_retry(self, max_retries: int = 3) -> bool:
        """
        Verifica si el mensaje puede ser reintentado
        
        Args:
            max_retries: Número máximo de reintentos permitidos
            
        Returns:
            True si puede ser reintentado, False si no
        """
        return self.retry_count < max_retries
        
    def get_routing_key(self) -> str:
        """
        Obtiene la routing key según la acción
        
        Returns:
            Routing key para RabbitMQ
        """
        return self.action.value
