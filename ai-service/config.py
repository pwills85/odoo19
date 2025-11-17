# -*- coding: utf-8 -*-
"""
Configuración del AI Microservice
"""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
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
    
    # ✅ FIX [P0-1]: API key now REQUIRED from environment (no default)
    # MUST set via environment variable AI_SERVICE_API_KEY
    # Application will FAIL TO START if not provided (fail-safe security)
    api_key: str = Field(..., description="Required API key from AI_SERVICE_API_KEY env var")

    @field_validator('api_key')
    @classmethod
    def validate_api_key_not_default(cls, v):
        """Prevent usage of insecure default values - ENHANCED P0-1"""
        # Expanded forbidden list
        forbidden_values = [
            'default', 'changeme', 'default_ai_api_key', 'test', 'dev',
            'admin', 'password', '12345', 'secret', 'api_key', 'key',
            'YOUR_API_KEY_HERE', 'REPLACE_ME', 'TODO'
        ]

        # Case-insensitive check
        v_lower = v.lower()
        for forbidden in forbidden_values:
            if forbidden in v_lower:
                raise ValueError(
                    f"Insecure API key detected: contains '{forbidden}'. "
                    f"Set AI_SERVICE_API_KEY environment variable with a strong production key."
                )

        # Minimum length validation (increased to 32 for better security)
        if len(v) < 32:
            raise ValueError(
                "API key must be at least 32 characters for production security. "
                f"Current length: {len(v)}"
            )

        return v
    allowed_origins: list[str] = ["http://odoo:8069", "http://odoo-eergy-services:8001"]
    
    # ═══════════════════════════════════════════════════════════
    # ANTHROPIC API (Solo Claude) - Actualizado 2025-10-23
    # ═══════════════════════════════════════════════════════════

    anthropic_api_key: str
    # ✅ FIX [H3 CICLO3]: Model from env var for flexibility
    anthropic_model: str = Field(
        default="claude-sonnet-4-5-20250929",
        description="Anthropic model from ANTHROPIC_MODEL env var (default: Claude Sonnet 4.5)"
    )

    # Max tokens por caso de uso
    anthropic_max_tokens_default: int = 8192
    chat_max_tokens: int = 16384
    dte_validation_max_tokens: int = 4096
    payroll_validation_max_tokens: int = 2048
    previred_scraping_max_tokens: int = 4096
    analytics_matching_max_tokens: int = 1024
    sii_monitoring_max_tokens: int = 8192

    # Configuración avanzada
    anthropic_temperature_default: float = 0.7
    anthropic_timeout_seconds: int = 60
    anthropic_max_retries: int = 3

    # Prompt Caching (OPTIMIZATION 2025-10-24)
    # Reduces costs by 90% and latency by 85%
    enable_prompt_caching: bool = True
    cache_control_ttl_minutes: int = 5  # Ephemeral cache duration

    # Token Control (OPTIMIZATION 2025-10-24)
    # Pre-count tokens to prevent unexpected costs
    enable_token_precounting: bool = True
    max_tokens_per_request: int = 100000  # Safety limit per request
    max_estimated_cost_per_request: float = 1.0  # Max $1 per request
    
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
    # ✅ FIX [P0-2]: Odoo API key now REQUIRED from environment (no default)
    # MUST set via environment variable ODOO_API_KEY
    # Application will FAIL TO START if not provided (fail-safe security)
    odoo_api_key: str = Field(..., description="Required from ODOO_API_KEY env var")

    @field_validator('odoo_api_key')
    @classmethod
    def validate_odoo_api_key_not_default(cls, v):
        """Prevent usage of insecure default Odoo API key - ENHANCED P0-2"""
        # Expanded forbidden list for Odoo keys
        forbidden_values = [
            'default', 'changeme', 'admin', 'password', 'odoo',
            'test', 'dev', '12345', 'secret', 'api_key', 'key',
            'YOUR_ODOO_KEY', 'REPLACE_ME', 'TODO', 'demo'
        ]

        # Case-insensitive check
        v_lower = v.lower()
        for forbidden in forbidden_values:
            if forbidden in v_lower:
                raise ValueError(
                    f"Insecure Odoo API key detected: contains '{forbidden}'. "
                    f"Set ODOO_API_KEY environment variable with a strong production key."
                )

        # Minimum length validation (increased to 32 for better security)
        if len(v) < 32:
            raise ValueError(
                "Odoo API key must be at least 32 characters for production security. "
                f"Current length: {len(v)}"
            )

        return v
    
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
    
    # Plugin system (ENABLED 2025-10-24)
    # Multi-agent architecture: +90.2% accuracy improvement
    enable_plugin_system: bool = True
    enable_multi_module_kb: bool = True
    enable_dynamic_prompts: bool = True
    enable_generic_validation: bool = False

    # Streaming (OPTIMIZATION 2025-10-24)
    # Improves UX: 3x faster perceived response time
    enable_streaming: bool = True
    
    # Backward compatibility (always True in production)
    force_dte_compatibility_mode: bool = True
    
    # ═══════════════════════════════════════════════════════════
    # LOGGING
    # ═══════════════════════════════════════════════════════════
    
    log_level: str = "INFO"
    
    # ═══════════════════════════════════════════════════════════
    # ENVIRONMENT CONFIGURATION
    # ═══════════════════════════════════════════════════════════
    # 
    # PRODUCTION (Docker):
    #   Variables are loaded from docker-compose.yml which reads from
    #   project root .env file: /Users/pedro/Documents/odoo19/.env
    #   No local .env file is needed or used.
    #
    # DEVELOPMENT (Local without Docker):
    #   Create local .env file or export variables from root .env:
    #   $ export $(cat ../.env | grep -v '^#' | xargs)
    #
    # See: /docs/ANALISIS_VARIABLES_ENTORNO_AI_SERVICE.md
    # ═══════════════════════════════════════════════════════════
    
    class Config:
        # NOTE: In Docker, this env_file is NOT used.
        # Variables come from docker-compose.yml environment section.
        # This setting only applies to local development.
        env_file = ".env"
        env_file_encoding = "utf-8"


# Instancia global de configuración
settings = Settings()

