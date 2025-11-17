# -*- coding: utf-8 -*-
"""
Pytest Configuration for Integration Tests
==========================================

Shared fixtures and configuration for integration tests.

Features:
- FastAPI test client setup
- Mock Anthropic client
- Test data generators
- Redis mock for caching tests
- Async test support

Author: EERGYGROUP - Test Automation Sprint 2025-11-09
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, AsyncMock
from typing import Dict, Any, List
import uuid

from fastapi.testclient import TestClient
from config import settings


# ═══════════════════════════════════════════════════════════
# PYTEST CONFIGURATION
# ═══════════════════════════════════════════════════════════

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "api: mark test as API endpoint test"
    )
    config.addinivalue_line(
        "markers", "async: mark test as asynchronous"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running (>1s)"
    )


# ═══════════════════════════════════════════════════════════
# ASYNCIO FIXTURE
# ═══════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ═══════════════════════════════════════════════════════════
# FASTAPI TEST CLIENT
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def app_client():
    """Create FastAPI test client."""
    from main import app
    return TestClient(app)


# ═══════════════════════════════════════════════════════════
# MOCK CLIENTS
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def mock_anthropic_client():
    """Create mock Anthropic client."""
    from clients.anthropic_client import AnthropicClient

    mock_client = MagicMock(spec=AnthropicClient)

    # Mock async methods
    mock_client.validate_dte = AsyncMock()
    mock_client.estimate_tokens = AsyncMock()
    mock_client.call_with_caching = AsyncMock()

    return mock_client


@pytest.fixture
def mock_redis_client():
    """Create mock Redis client."""
    mock_redis = MagicMock()

    # Mock basic Redis operations
    mock_redis.get = MagicMock(return_value=None)
    mock_redis.set = MagicMock(return_value=True)
    mock_redis.delete = MagicMock(return_value=1)
    mock_redis.exists = MagicMock(return_value=False)
    mock_redis.ping = MagicMock(return_value=True)
    mock_redis.expire = MagicMock(return_value=True)

    return mock_redis


# ═══════════════════════════════════════════════════════════
# TEST DATA FACTORIES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def sample_dte_data() -> Dict[str, Any]:
    """Factory for sample DTE data."""
    return {
        "tipo_dte": "33",
        "folio": 12345,
        "fecha_emision": "2025-10-23",
        "fecha_vencimiento": "2025-11-23",
        "monto_neto": 1000000,
        "monto_iva": 190000,
        "monto_total": 1190000,
        "emisor_rut": "12345678-9",
        "emisor_razon_social": "EMPRESA TEST SPA",
        "receptor_rut": "98765432-1",
        "receptor_razon_social": "CLIENTE TEST LTDA",
        "glosa": "Descripción de la operación",
        "moneda": "CLP",
        "lineas": [
            {
                "linea_num": 1,
                "descripcion": "Servicio de consultoría",
                "cantidad": 1,
                "precio_unitario": 1000000,
                "descto_pct": 0,
                "monto_linea": 1000000
            }
        ]
    }


@pytest.fixture
def sample_validation_request(sample_dte_data) -> Dict[str, Any]:
    """Factory for DTE validation request."""
    return {
        "dte_data": sample_dte_data,
        "company_id": 1,
        "history": []
    }


@pytest.fixture
def sample_chat_message() -> Dict[str, Any]:
    """Factory for chat message request."""
    return {
        "session_id": str(uuid.uuid4()),
        "message": "¿Cómo genero un DTE 33?",
        "user_context": {
            "company_name": "Test Company SPA",
            "company_rut": "12345678-9",
            "user_role": "Contador",
            "environment": "Sandbox"
        }
    }


@pytest.fixture
def sample_messages() -> List[Dict[str, str]]:
    """Factory for message list."""
    return [
        {
            "role": "user",
            "content": "¿Cómo genero un DTE 33 en Odoo?"
        }
    ]


@pytest.fixture
def sample_conversation_history() -> List[Dict[str, str]]:
    """Factory for conversation history."""
    return [
        {
            "role": "user",
            "content": "¿Qué es un DTE?",
            "timestamp": "2025-10-23T10:00:00Z"
        },
        {
            "role": "assistant",
            "content": "Un DTE es un Documento Tributario Electrónico...",
            "timestamp": "2025-10-23T10:00:05Z"
        },
        {
            "role": "user",
            "content": "¿Cómo lo genero en Odoo?",
            "timestamp": "2025-10-23T10:00:10Z"
        }
    ]


# ═══════════════════════════════════════════════════════════
# MOCK RESPONSES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def mock_validation_response() -> Dict[str, Any]:
    """Factory for validation response."""
    return {
        "confidence": 95.0,
        "warnings": [],
        "errors": [],
        "recommendation": "send",
        "input_tokens": 500,
        "output_tokens": 50,
        "cache_creation_tokens": 0,
        "cache_read_tokens": 0
    }


@pytest.fixture
def mock_validation_response_with_cache() -> Dict[str, Any]:
    """Factory for validation response with cache hit."""
    return {
        "confidence": 95.0,
        "warnings": [],
        "errors": [],
        "recommendation": "send",
        "input_tokens": 2500,
        "output_tokens": 50,
        "cache_creation_tokens": 0,
        "cache_read_tokens": 2000
    }


@pytest.fixture
def mock_chat_response() -> Dict[str, Any]:
    """Factory for chat response."""
    return {
        "message": "Para generar un DTE 33, debes seguir estos pasos...",
        "sources": ["DTE Generation Guide", "Odoo Documentation"],
        "confidence": 95.0,
        "session_id": str(uuid.uuid4()),
        "llm_used": "anthropic",
        "tokens_used": {
            "input_tokens": 500,
            "output_tokens": 250,
            "total_tokens": 750
        },
        "plugin_used": "l10n_cl_dte"
    }


@pytest.fixture
def mock_stream_chunks() -> List[Dict[str, Any]]:
    """Factory for streaming response chunks."""
    return [
        {"type": "text", "content": "Para "},
        {"type": "text", "content": "generar "},
        {"type": "text", "content": "un DTE 33 "},
        {"type": "text", "content": "debes... "},
        {
            "type": "done",
            "metadata": {
                "sources": ["Guide"],
                "confidence": 95.0,
                "llm_used": "anthropic",
                "tokens_used": {
                    "input": 500,
                    "output": 100,
                    "total": 600
                }
            }
        }
    ]


@pytest.fixture
def mock_token_estimation_response() -> Dict[str, Any]:
    """Factory for token estimation response."""
    return {
        "input_tokens": 150,
        "estimated_output_tokens": 50,
        "estimated_total_tokens": 200,
        "estimated_cost_usd": 0.0012
    }


# ═══════════════════════════════════════════════════════════
# CONTEXT MANAGERS FOR COMMON OPERATIONS
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def api_key_header() -> Dict[str, str]:
    """Return API key header for requests."""
    return {"Authorization": f"Bearer {settings.api_key}"}


@pytest.fixture
def invalid_api_key_header() -> Dict[str, str]:
    """Return invalid API key header for error testing."""
    return {"Authorization": "Bearer invalid-key-12345"}


# ═══════════════════════════════════════════════════════════
# SETTINGS FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def app_settings():
    """Provide app settings."""
    return settings


@pytest.fixture
def feature_flags() -> Dict[str, bool]:
    """Factory for feature flags."""
    return {
        "enable_prompt_caching": settings.enable_prompt_caching if hasattr(settings, 'enable_prompt_caching') else True,
        "enable_token_precounting": settings.enable_token_precounting if hasattr(settings, 'enable_token_precounting') else True,
        "enable_streaming": settings.enable_streaming if hasattr(settings, 'enable_streaming') else True,
        "enable_plugin_system": settings.enable_plugin_system if hasattr(settings, 'enable_plugin_system') else False
    }


# ═══════════════════════════════════════════════════════════
# ANTHROPIC API MOCKS
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def mock_anthropic_message():
    """Create mock Anthropic message object."""
    message = MagicMock()

    # Content
    message.content = [MagicMock(text='{"c": 95, "w": [], "e": [], "r": "send"}')]

    # Usage
    message.usage = MagicMock()
    message.usage.input_tokens = 500
    message.usage.output_tokens = 50
    message.usage.cache_creation_input_tokens = 0
    message.usage.cache_read_input_tokens = 0

    return message


@pytest.fixture
def mock_anthropic_message_with_cache():
    """Create mock Anthropic message with cache hit."""
    message = MagicMock()

    # Content
    message.content = [MagicMock(text='{"c": 95, "w": [], "e": [], "r": "send"}')]

    # Usage with cache hit
    message.usage = MagicMock()
    message.usage.input_tokens = 2500
    message.usage.output_tokens = 50
    message.usage.cache_creation_input_tokens = 0
    message.usage.cache_read_input_tokens = 2000

    return message


@pytest.fixture
def mock_anthropic_stream():
    """Create mock Anthropic streaming response."""
    stream = MagicMock()

    # Mock text_stream
    async def async_gen():
        yield "Token "
        yield "one "
        yield "token "
        yield "two"

    stream.text_stream = async_gen()

    # Mock get_final_message
    async def get_final():
        message = MagicMock()
        message.usage = MagicMock()
        message.usage.input_tokens = 100
        message.usage.output_tokens = 20
        message.usage.cache_read_input_tokens = 0
        message.usage.cache_creation_input_tokens = 0
        return message

    stream.get_final_message = AsyncMock(side_effect=get_final)

    return stream


# ═══════════════════════════════════════════════════════════
# CLEANUP FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup after each test."""
    yield

    # Any cleanup code here
    # This runs after each test
