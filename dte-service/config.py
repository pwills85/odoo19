# -*- coding: utf-8 -*-
"""
Configuración del DTE Microservice
"""

from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    """Configuración del DTE Service"""
    
    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN GENERAL
    # ═══════════════════════════════════════════════════════════
    
    app_name: str = "DTE Microservice"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # ═══════════════════════════════════════════════════════════
    # SEGURIDAD
    # ═══════════════════════════════════════════════════════════
    
    api_key: str = "default_dte_api_key"  # Cambiar en producción
    allowed_origins: list[str] = ["http://odoo:8069", "http://localhost:8069"]
    
    # ═══════════════════════════════════════════════════════════
    # SII CONFIGURATION
    # ═══════════════════════════════════════════════════════════
    
    sii_environment: Literal["sandbox", "production"] = "sandbox"
    sii_timeout: int = 60  # segundos
    
    # URLs SII
    sii_sandbox_url: str = "https://maullin.sii.cl/DTEWS/DTEServiceTest.asmx?wsdl"
    sii_production_url: str = "https://palena.sii.cl/DTEWS/DTEService.asmx?wsdl"
    
    @property
    def sii_wsdl_url(self) -> str:
        """Retorna URL según ambiente"""
        if self.sii_environment == "production":
            return self.sii_production_url
        return self.sii_sandbox_url
    
    # ═══════════════════════════════════════════════════════════
    # REDIS
    # ═══════════════════════════════════════════════════════════
    
    redis_url: str = "redis://redis:6379/0"
    redis_cache_ttl: int = 3600  # 1 hora
    
    # ═══════════════════════════════════════════════════════════
    # RABBITMQ - FASE 1: Actualizado con credenciales seguras
    # ═══════════════════════════════════════════════════════════
    
    rabbitmq_url: str = "amqp://admin:changeme@rabbitmq:5672//odoo"
    rabbitmq_queue_name: str = "dte_queue"
    
    # ═══════════════════════════════════════════════════════════
    # ODOO CALLBACK
    # ═══════════════════════════════════════════════════════════
    
    odoo_url: str = "http://odoo:8069"
    odoo_webhook_key: str = "default_webhook_key"  # Cambiar en producción
    
    # ═══════════════════════════════════════════════════════════
    # LOGGING
    # ═══════════════════════════════════════════════════════════
    
    log_level: str = "INFO"
    
    # ═══════════════════════════════════════════════════════════
    # LOAD FROM .env
    # ═══════════════════════════════════════════════════════════
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Instancia global de configuración
settings = Settings()

