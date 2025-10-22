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
    # OLLAMA (LLM LOCAL)
    # ═══════════════════════════════════════════════════════════
    
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "llama2"  # Modelo por defecto
    
    # ═══════════════════════════════════════════════════════════
    # EMBEDDINGS
    # ═══════════════════════════════════════════════════════════
    
    embedding_model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    embedding_dimension: int = 384
    
    # ═══════════════════════════════════════════════════════════
    # VECTOR DATABASE (CHROMADB)
    # ═══════════════════════════════════════════════════════════
    
    chromadb_path: str = "/app/data/chromadb"
    chromadb_collection: str = "dte_embeddings"
    
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
    reconciliation_similarity_threshold: float = 0.85  # 85%
    
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

