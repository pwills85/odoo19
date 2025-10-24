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

    # FIX A1: API Key DEBE venir de variable de entorno
    # No hay valor por defecto - fuerza configuración explícita
    api_key: str = Field(..., env="EERGY_SERVICES_API_KEY")

    allowed_origins: list[str] = ["http://odoo:8069", "http://localhost:8069"]
    
    # ═══════════════════════════════════════════════════════════
    # SII CONFIGURATION
    # ═══════════════════════════════════════════════════════════

    sii_environment: Literal["sandbox", "production"] = "sandbox"
    sii_timeout: int = 60  # segundos

    # FIX A2: XSD Strict Mode - Si True, falla si schema no está cargado
    strict_xsd_validation: bool = Field(default=True, env="STRICT_XSD_VALIDATION")
    
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
    # ODOO CALLBACK - BRECHA 5
    # ═══════════════════════════════════════════════════════════
    
    odoo_url: str = Field(default="http://odoo:8069", env="ODOO_URL")
    odoo_webhook_key: str = Field(
        default="secret_webhook_key_change_in_production",
        env="ODOO_WEBHOOK_KEY"
    )
    
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

