# -*- coding: utf-8 -*-
"""
Configuración del AI Microservice
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Configuración del AI Service"""
    
    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN GENERAL
    # ═══════════════════════════════════════════════════════════
    
    app_name: str = "AI Microservice - DTE Intelligence"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # ═══════════════════════════════════════════════════════════
    # SEGURIDAD
    # ═══════════════════════════════════════════════════════════
    
    api_key: str = "default_ai_api_key"  # Cambiar en producción
    allowed_origins: list[str] = ["http://odoo:8069", "http://dte-service:8001"]
    
    # ═══════════════════════════════════════════════════════════
    # ANTHROPIC API
    # ═══════════════════════════════════════════════════════════
    
    anthropic_api_key: str
    anthropic_model: str = "claude-3-5-sonnet-20241022"
    anthropic_max_tokens: int = 4096
    
    # ═══════════════════════════════════════════════════════════
    # OPENAI API (Fallback LLM)
    # ═══════════════════════════════════════════════════════════

    openai_api_key: str = ""  # Optional fallback
    openai_model: str = "gpt-4-turbo-preview"
    openai_max_tokens: int = 4096
    
    # ═══════════════════════════════════════════════════════════
    # CHAT ENGINE
    # ═══════════════════════════════════════════════════════════

    chat_session_ttl: int = 3600  # 1 hour
    chat_max_context_messages: int = 10  # Last N messages
    chat_default_temperature: float = 0.7  # Creativity (0-2)
    
    # ═══════════════════════════════════════════════════════════
    # REDIS CACHE
    # ═══════════════════════════════════════════════════════════
    
    redis_url: str = "redis://redis:6379/1"
    redis_cache_ttl: int = 3600  # 1 hora
    
    # ═══════════════════════════════════════════════════════════
    # ODOO INTEGRATION
    # ═══════════════════════════════════════════════════════════
    
    odoo_url: str = "http://odoo:8069"
    odoo_api_key: str = "default_odoo_api_key"
    
    # ═══════════════════════════════════════════════════════════
    # THRESHOLDS Y CONFIGURACIÓN IA
    # ═══════════════════════════════════════════════════════════
    
    validation_confidence_threshold: float = 0.80  # 80%

    # ═══════════════════════════════════════════════════════════
    # KNOWLEDGE BASE
    # ═══════════════════════════════════════════════════════════

    knowledge_base_path: str = "/app/knowledge"  # Markdown docs directory
    knowledge_base_modules: list[str] = ["l10n_cl_dte"]  # Supported modules
    
    # ═══════════════════════════════════════════════════════════
    # FEATURE FLAGS (UPGRADE TO MULTI-MODULE)
    # ═══════════════════════════════════════════════════════════
    
    # Plugin system
    enable_plugin_system: bool = False
    enable_multi_module_kb: bool = False
    enable_dynamic_prompts: bool = False
    enable_generic_validation: bool = False
    
    # Backward compatibility (always True in production)
    force_dte_compatibility_mode: bool = True
    
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

