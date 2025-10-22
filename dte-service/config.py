# -*- coding: utf-8 -*-
"""
Configuración del DTE Microservice
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Literal, Optional


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
    # RABBITMQ - FASE 2: Credenciales desde environment
    # ═══════════════════════════════════════════════════════════
    
    rabbitmq_user: str = Field(default="admin", env="RABBITMQ_USER")
    rabbitmq_pass: str = Field(default="changeme", env="RABBITMQ_PASS")
    rabbitmq_host: str = Field(default="rabbitmq", env="RABBITMQ_HOST")
    rabbitmq_port: int = Field(default=5672, env="RABBITMQ_PORT")
    rabbitmq_vhost: str = Field(default="/odoo", env="RABBITMQ_VHOST")
    
    @property
    def rabbitmq_url(self) -> str:
        """Construye URL de RabbitMQ desde componentes"""
        return f"amqp://{self.rabbitmq_user}:{self.rabbitmq_pass}@{self.rabbitmq_host}:{self.rabbitmq_port}/{self.rabbitmq_vhost}"
    
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

