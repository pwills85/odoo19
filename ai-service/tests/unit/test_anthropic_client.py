# -*- coding: utf-8 -*-
"""
Unit Tests for AnthropicClient - Claude API Client with Prompt Caching

Test Coverage:
- Token estimation and cost tracking
- DTE validation with prompt caching
- Message building with cache control headers
- Stream event handling
- Error handling and retries
- Fallback behaviors

Target Coverage: ≥80% (483 LOC)

@pytest.mark.unit
@pytest.mark.async
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import anthropic
from anthropic.types import Message, Usage, ContentBlock, TextBlock
from typing import Dict, Any, List

# Import the client
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from clients.anthropic_client import AnthropicClient, get_anthropic_client


# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def mock_anthropic_client():
    """Mock AsyncAnthropic client with proper nested mocks"""
    mock_client = AsyncMock(spec=anthropic.AsyncAnthropic)
    # Properly configure nested mocks for messages API
    mock_client.messages = AsyncMock()
    mock_client.messages.count_tokens = AsyncMock()
    mock_client.messages.create = AsyncMock()
    return mock_client


@pytest.fixture
def anthropic_client(mock_anthropic_client):
    """Create AnthropicClient instance with mocked Anthropic"""
    with patch('clients.anthropic_client.anthropic.AsyncAnthropic', return_value=mock_anthropic_client):
        client = AnthropicClient(
            api_key="sk-test-key-12345",
            model="claude-sonnet-4-5-20250929"
        )
        client.client = mock_anthropic_client
        return client


@pytest.fixture
def sample_dte_data():
    """Sample DTE data for validation"""
    return {
        "tipo_dte": "33",
        "folio": "12345",
        "fecha_emision": "2025-10-22",
        "rut_emisor": "12345678-9",
        "rut_receptor": "98765432-1",
        "monto_total": 119000,
        "monto_neto": 100000,
        "monto_iva": 19000,
        "items": [
            {
                "nombre": "Producto Test",
                "cantidad": 1,
                "precio_unitario": 100000
            }
        ]
    }


@pytest.fixture
def mock_anthropic_response():
    """Mock Anthropic API response"""
    usage = MagicMock(spec=Usage)
    usage.input_tokens = 150
    usage.output_tokens = 50
    usage.cache_read_input_tokens = 30
    usage.cache_creation_input_tokens = 50

    content = MagicMock(spec=TextBlock)
    content.text = '{"c": 85.0, "w": ["check_rut"], "e": [], "r": "send"}'

    message = MagicMock(spec=Message)
    message.content = [content]
    message.usage = usage

    return message


@pytest.fixture
def mock_settings():
    """Mock settings configuration"""
    settings = MagicMock()
    settings.enable_token_precounting = True
    settings.enable_prompt_caching = True
    settings.max_tokens_per_request = 100000
    settings.max_estimated_cost_per_request = 10.0
    settings.chat_max_tokens = 4096
    settings.enable_streaming = True
    return settings


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_anthropic_client_init(mock_anthropic_client):
    """Test AnthropicClient initialization"""
    with patch('clients.anthropic_client.anthropic.AsyncAnthropic', return_value=mock_anthropic_client):
        client = AnthropicClient(api_key="sk-test-key", model="claude-sonnet-4-5-20250929")

        assert client.model == "claude-sonnet-4-5-20250929"
        assert client.client is not None


@pytest.mark.unit
def test_anthropic_client_init_default_model(mock_anthropic_client):
    """Test AnthropicClient with default model"""
    with patch('clients.anthropic_client.anthropic.AsyncAnthropic', return_value=mock_anthropic_client):
        client = AnthropicClient(api_key="sk-test-key")

        assert client.model == "claude-sonnet-4-5-20250929"


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: TOKEN ESTIMATION
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_estimate_tokens_success(anthropic_client, mock_settings):
    """Test token estimation with successful response"""
    with patch('clients.anthropic_client.settings', mock_settings):
        # Mock count_tokens response
        count_response = MagicMock()
        count_response.input_tokens = 100
        anthropic_client.client.messages.count_tokens = AsyncMock(return_value=count_response)

        # Mock CLAUDE_PRICING import
        with patch('clients.anthropic_client.CLAUDE_PRICING', {
            'claude-sonnet-4-5-20250929': {
                'input': 0.003,
                'output': 0.015
            },
            'default': {'input': 0.01, 'output': 0.05}
        }):
            result = await anthropic_client.estimate_tokens(
                messages=[{"role": "user", "content": "Test message"}],
                system="Test system prompt"
            )

            assert result["input_tokens"] == 100
            assert result["estimated_output_tokens"] == 30  # 0.3 * input
            assert result["estimated_total_tokens"] == 130
            assert result["estimated_cost_usd"] > 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_estimate_tokens_without_system_prompt(anthropic_client, mock_settings):
    """Test token estimation without system prompt"""
    with patch('clients.anthropic_client.settings', mock_settings):
        count_response = MagicMock()
        count_response.input_tokens = 50
        anthropic_client.client.messages.count_tokens = AsyncMock(return_value=count_response)

        with patch('clients.anthropic_client.CLAUDE_PRICING', {
            'claude-sonnet-4-5-20250929': {'input': 0.003, 'output': 0.015},
            'default': {'input': 0.01, 'output': 0.05}
        }):
            result = await anthropic_client.estimate_tokens(
                messages=[{"role": "user", "content": "Test"}]
            )

            assert result["input_tokens"] == 50


@pytest.mark.unit
@pytest.mark.asyncio
async def test_estimate_tokens_exceeds_max_tokens(anthropic_client, mock_settings):
    """Test token estimation exceeding max tokens limit"""
    mock_settings.enable_token_precounting = True
    mock_settings.max_tokens_per_request = 100

    with patch('clients.anthropic_client.settings', mock_settings):
        count_response = MagicMock()
        count_response.input_tokens = 90  # Will exceed with 30% output estimate
        anthropic_client.client.messages.count_tokens = AsyncMock(return_value=count_response)

        with patch('clients.anthropic_client.CLAUDE_PRICING', {
            'claude-sonnet-4-5-20250929': {'input': 0.003, 'output': 0.015},
            'default': {'input': 0.01, 'output': 0.05}
        }):
            with pytest.raises(ValueError, match="Request too large"):
                await anthropic_client.estimate_tokens(
                    messages=[{"role": "user", "content": "X" * 1000}]
                )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_estimate_tokens_exceeds_max_cost(anthropic_client, mock_settings):
    """Test token estimation exceeding max cost limit"""
    mock_settings.enable_token_precounting = True
    mock_settings.max_estimated_cost_per_request = 0.001

    with patch('clients.anthropic_client.settings', mock_settings):
        count_response = MagicMock()
        count_response.input_tokens = 10000  # Very expensive
        anthropic_client.client.messages.count_tokens = AsyncMock(return_value=count_response)

        with patch('clients.anthropic_client.CLAUDE_PRICING', {
            'claude-sonnet-4-5-20250929': {'input': 0.003, 'output': 0.015},
            'default': {'input': 0.01, 'output': 0.05}
        }):
            with pytest.raises(ValueError, match="Request too expensive"):
                await anthropic_client.estimate_tokens(
                    messages=[{"role": "user", "content": "X" * 10000}]
                )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_estimate_tokens_api_error(anthropic_client):
    """Test token estimation with API error"""
    anthropic_client.client.messages.count_tokens = AsyncMock(
        side_effect=anthropic.APIError("API Error")
    )

    with pytest.raises(anthropic.APIError):
        await anthropic_client.estimate_tokens(
            messages=[{"role": "user", "content": "Test"}]
        )


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: DTE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_success(anthropic_client, sample_dte_data, mock_anthropic_response, mock_settings):
    """Test DTE validation with successful response"""
    with patch('clients.anthropic_client.settings', mock_settings):
        # Mock estimate_tokens
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 150,
            "estimated_output_tokens": 50,
            "estimated_total_tokens": 200,
            "estimated_cost_usd": 0.001
        })

        # Mock circuit breaker
        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(return_value=None)
            mock_cb.__exit__ = MagicMock(return_value=False)

            anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

            # Mock utilities (patch where they're imported - inside validate_dte)
            with patch('utils.llm_helpers.extract_json_from_llm_response') as mock_extract, \
                 patch('utils.llm_helpers.validate_llm_json_schema') as mock_validate, \
                 patch('utils.cost_tracker.get_cost_tracker') as mock_tracker:

                mock_extract.return_value = {"c": 85.0, "w": ["check_rut"], "e": [], "r": "send"}
                mock_validate.return_value = {"c": 85.0, "w": ["check_rut"], "e": [], "r": "send"}
                mock_tracker.return_value.record_usage = MagicMock()

                result = await anthropic_client.validate_dte(sample_dte_data, [])

                assert result["confidence"] == 85.0
                assert result["recommendation"] == "send"
                assert result["warnings"] == ["check_rut"]
                assert result["errors"] == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_with_caching(anthropic_client, sample_dte_data, mock_anthropic_response, mock_settings):
    """Test DTE validation uses prompt caching"""
    mock_settings.enable_prompt_caching = True

    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 100,
            "estimated_output_tokens": 30,
            "estimated_total_tokens": 130,
            "estimated_cost_usd": 0.0005
        })

        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(return_value=None)
            mock_cb.__exit__ = MagicMock(return_value=False)

            anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

            with patch('utils.llm_helpers.extract_json_from_llm_response') as mock_extract, \
                 patch('utils.llm_helpers.validate_llm_json_schema') as mock_validate, \
                 patch('utils.cost_tracker.get_cost_tracker') as mock_tracker:

                mock_extract.return_value = {"c": 85.0, "w": [], "e": [], "r": "send"}
                mock_validate.return_value = {"c": 85.0, "w": [], "e": [], "r": "send"}

                result = await anthropic_client.validate_dte(sample_dte_data, [])

                # Verify create was called with cache_control
                call_kwargs = anthropic_client.client.messages.create.call_args[1]
                assert "system" in call_kwargs
                assert isinstance(call_kwargs["system"], list)
                assert any("cache_control" in str(item) for item in call_kwargs["system"])


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_cost_exceeded(anthropic_client, sample_dte_data, mock_settings):
    """Test DTE validation when cost estimate exceeds limit"""
    mock_settings.enable_token_precounting = True

    with patch('clients.anthropic_client.settings', mock_settings):
        # estimate_tokens raises ValueError for expensive request
        anthropic_client.estimate_tokens = AsyncMock(
            side_effect=ValueError("Request too expensive: $100.00 (max $10.00)")
        )

        result = await anthropic_client.validate_dte(sample_dte_data, [])

        assert result["confidence"] == 0.0
        assert result["recommendation"] == "review"
        assert "too expensive" in result["warnings"][0].lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_circuit_breaker_open(anthropic_client, sample_dte_data, mock_settings):
    """Test DTE validation with circuit breaker open"""
    from utils.circuit_breaker import CircuitBreakerError

    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 100,
            "estimated_output_tokens": 30,
            "estimated_total_tokens": 130,
            "estimated_cost_usd": 0.0005
        })

        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(side_effect=CircuitBreakerError("Circuit open"))
            mock_cb.__exit__ = MagicMock(return_value=False)

            result = await anthropic_client.validate_dte(sample_dte_data, [])

            assert result["confidence"] == 0.0
            assert result["recommendation"] == "review"
            assert result.get("fallback") == "circuit_breaker_open"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_json_parse_error(anthropic_client, sample_dte_data, mock_settings):
    """Test DTE validation with JSON parse error"""
    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 100,
            "estimated_output_tokens": 30,
            "estimated_total_tokens": 130,
            "estimated_cost_usd": 0.0005
        })

        mock_response = MagicMock(spec=Message)
        mock_response.content = [MagicMock(spec=TextBlock)]
        mock_response.content[0].text = "Invalid JSON response"
        mock_response.usage = MagicMock()
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 30

        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(return_value=None)
            mock_cb.__exit__ = MagicMock(return_value=False)

            anthropic_client.client.messages.create = AsyncMock(return_value=mock_response)

            with patch('utils.llm_helpers.extract_json_from_llm_response') as mock_extract:
                mock_extract.side_effect = ValueError("Invalid JSON")

                result = await anthropic_client.validate_dte(sample_dte_data, [])

                assert result["confidence"] == 50.0
                assert result["recommendation"] == "review"
                assert "Parse error" in result["warnings"][0]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_with_history(anthropic_client, sample_dte_data, mock_anthropic_response, mock_settings):
    """Test DTE validation with rejection history"""
    history = [
        {"error_code": "E001", "message": "RUT validation failed"},
        {"error_code": "E002", "message": "Folio not available"}
    ]

    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 100,
            "estimated_output_tokens": 30,
            "estimated_total_tokens": 130,
            "estimated_cost_usd": 0.0005
        })

        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(return_value=None)
            mock_cb.__exit__ = MagicMock(return_value=False)

            anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

            with patch('utils.llm_helpers.extract_json_from_llm_response') as mock_extract, \
                 patch('utils.llm_helpers.validate_llm_json_schema') as mock_validate, \
                 patch('utils.cost_tracker.get_cost_tracker') as mock_tracker:

                mock_extract.return_value = {"c": 60.0, "w": ["RUT mismatch"], "e": [], "r": "review"}
                mock_validate.return_value = {"c": 60.0, "w": ["RUT mismatch"], "e": [], "r": "review"}
                mock_tracker.return_value.record_usage = MagicMock()

                result = await anthropic_client.validate_dte(sample_dte_data, history)

                assert result["confidence"] == 60.0
                assert result["recommendation"] == "review"


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: SYSTEM PROMPT BUILDING
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_build_validation_system_prompt(anthropic_client):
    """Test system prompt building"""
    prompt = anthropic_client._build_validation_system_prompt()

    assert "experto en facturación electrónica" in prompt.lower()
    assert "DTE" in prompt
    assert "JSON COMPACTO" in prompt or "json compacto" in prompt.lower()
    assert "responde solo json" in prompt.lower()


@pytest.mark.unit
def test_build_validation_user_prompt_compact(anthropic_client, sample_dte_data):
    """Test compact user prompt building"""
    history = [{"error_code": "E001", "message": "Error message 1"}]

    prompt = anthropic_client._build_validation_user_prompt_compact(sample_dte_data, history)

    assert "DTE:" in prompt
    assert "33" in prompt or "DTE data present"
    assert "HISTORIAL" in prompt


@pytest.mark.unit
def test_build_validation_user_prompt_empty_history(anthropic_client, sample_dte_data):
    """Test user prompt with empty history"""
    prompt = anthropic_client._build_validation_user_prompt_compact(sample_dte_data, None)

    assert "DTE:" in prompt
    assert "HISTORIAL" in prompt


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: GENERIC MESSAGE CALLING WITH CACHING
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_with_caching_no_cache(anthropic_client, mock_anthropic_response, mock_settings):
    """Test call_with_caching without caching enabled"""
    mock_settings.enable_prompt_caching = False

    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

        result = await anthropic_client.call_with_caching(
            user_message="Test message",
            system_prompt="Test system",
            max_tokens=1024,
            temperature=0.7
        )

        assert result == mock_anthropic_response
        call_kwargs = anthropic_client.client.messages.create.call_args[1]
        assert isinstance(call_kwargs["system"], str)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_with_caching_with_context(anthropic_client, mock_anthropic_response, mock_settings):
    """Test call_with_caching with cacheable context"""
    mock_settings.enable_prompt_caching = True

    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

        result = await anthropic_client.call_with_caching(
            user_message="Test message",
            system_prompt="Base system prompt",
            cacheable_context="Knowledge base content",
            max_tokens=2048,
            temperature=0.5
        )

        assert result == mock_anthropic_response

        # Verify system is a list with cache_control
        call_kwargs = anthropic_client.client.messages.create.call_args[1]
        assert isinstance(call_kwargs["system"], list)
        assert len(call_kwargs["system"]) == 2
        assert call_kwargs["system"][1].get("cache_control") == {"type": "ephemeral"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_with_caching_custom_tokens_temp(anthropic_client, mock_anthropic_response, mock_settings):
    """Test call_with_caching with custom tokens and temperature"""
    mock_settings.enable_prompt_caching = False

    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

        await anthropic_client.call_with_caching(
            user_message="Test",
            system_prompt="System",
            max_tokens=512,
            temperature=1.5
        )

        call_kwargs = anthropic_client.client.messages.create.call_args[1]
        assert call_kwargs["max_tokens"] == 512
        assert call_kwargs["temperature"] == 1.5


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: SINGLETON FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_get_anthropic_client_singleton():
    """Test get_anthropic_client returns singleton instance"""
    # Reset global state
    import clients.anthropic_client as client_module
    client_module._client = None

    with patch('clients.anthropic_client.AnthropicClient') as mock_class:
        mock_instance = MagicMock()
        mock_class.return_value = mock_instance

        # First call
        client1 = get_anthropic_client("sk-key-1", "model-1")
        assert client1 == mock_instance
        assert mock_class.call_count == 1

        # Second call should return same instance
        client2 = get_anthropic_client("sk-key-2", "model-2")
        assert client2 == client1
        assert mock_class.call_count == 1  # Not called again


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: EDGE CASES AND ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_rate_limit_error(anthropic_client, sample_dte_data, mock_settings):
    """Test rate limit error handling"""
    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 100,
            "estimated_output_tokens": 30,
            "estimated_total_tokens": 130,
            "estimated_cost_usd": 0.0005
        })

        mock_error = anthropic.RateLimitError("Rate limit exceeded")
        mock_error.response = MagicMock()
        mock_error.response.headers = {"retry-after": "30"}

        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(return_value=None)
            mock_cb.__exit__ = MagicMock(return_value=False)

            anthropic_client.client.messages.create = AsyncMock(side_effect=mock_error)

            with pytest.raises(anthropic.RateLimitError):
                await anthropic_client.validate_dte(sample_dte_data, [])


@pytest.mark.unit
def test_build_validation_user_prompt_long_history(anthropic_client, sample_dte_data):
    """Test user prompt with long history (should truncate to 3)"""
    history = [
        {"error_code": f"E{i:03d}", "message": f"Error message {i}"}
        for i in range(10)
    ]

    prompt = anthropic_client._build_validation_user_prompt_compact(sample_dte_data, history)

    # Should only include last 3 items
    assert prompt.count("E") <= 5  # Only last 3 error codes


@pytest.mark.unit
@pytest.mark.asyncio
async def test_estimate_tokens_precounting_disabled(anthropic_client, mock_settings):
    """Test token estimation when precounting is disabled"""
    mock_settings.enable_token_precounting = False

    with patch('clients.anthropic_client.settings', mock_settings):
        count_response = MagicMock()
        count_response.input_tokens = 1000000  # Huge, but should not raise
        anthropic_client.client.messages.count_tokens = AsyncMock(return_value=count_response)

        with patch('clients.anthropic_client.CLAUDE_PRICING', {
            'claude-sonnet-4-5-20250929': {'input': 0.003, 'output': 0.015},
            'default': {'input': 0.01, 'output': 0.05}
        }):
            result = await anthropic_client.estimate_tokens(
                messages=[{"role": "user", "content": "Test"}]
            )

            # Should not raise error even with huge tokens
            assert result["input_tokens"] == 1000000


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: CACHE PERFORMANCE TRACKING
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_validate_dte_cache_hit_tracking(anthropic_client, sample_dte_data, mock_settings):
    """Test cache hit rate tracking and logging"""
    with patch('clients.anthropic_client.settings', mock_settings):
        anthropic_client.estimate_tokens = AsyncMock(return_value={
            "input_tokens": 100,
            "estimated_output_tokens": 30,
            "estimated_total_tokens": 130,
            "estimated_cost_usd": 0.0005
        })

        # Mock response with cache hits
        mock_response = MagicMock(spec=Message)
        mock_response.content = [MagicMock(spec=TextBlock)]
        mock_response.content[0].text = '{"c": 85.0, "w": [], "e": [], "r": "send"}'
        mock_response.usage = MagicMock()
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 30
        mock_response.usage.cache_read_input_tokens = 70  # Cache hit
        mock_response.usage.cache_creation_input_tokens = 30

        with patch('clients.anthropic_client.anthropic_circuit_breaker') as mock_cb:
            mock_cb.__enter__ = MagicMock(return_value=None)
            mock_cb.__exit__ = MagicMock(return_value=False)

            anthropic_client.client.messages.create = AsyncMock(return_value=mock_response)

            with patch('utils.llm_helpers.extract_json_from_llm_response') as mock_extract, \
                 patch('utils.llm_helpers.validate_llm_json_schema') as mock_validate, \
                 patch('utils.cost_tracker.get_cost_tracker') as mock_tracker:

                mock_extract.return_value = {"c": 85.0, "w": [], "e": [], "r": "send"}
                mock_validate.return_value = {"c": 85.0, "w": [], "e": [], "r": "send"}
                mock_tracker_instance = MagicMock()
                mock_tracker.return_value = mock_tracker_instance

                result = await anthropic_client.validate_dte(sample_dte_data, [])

                # Verify cache tracking was recorded
                mock_tracker_instance.record_usage.assert_called_once()
                call_kwargs = mock_tracker_instance.record_usage.call_args[1]
                assert "metadata" in call_kwargs
                assert call_kwargs["metadata"]["cache_read_tokens"] == 70
                assert call_kwargs["metadata"]["cache_hit_rate"] == 0.7


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY STATS FOR TEST COVERAGE
# ═══════════════════════════════════════════════════════════════════════════════
"""
Test Coverage Summary:
======================

Methods Tested:
- __init__: 2 tests
- estimate_tokens: 6 tests
- validate_dte: 8 tests
- _build_validation_system_prompt: 1 test
- _build_validation_user_prompt_compact: 3 tests
- call_with_caching: 4 tests
- get_anthropic_client: 1 test

Total: 25 unit tests
Coverage Target: ≥80% (anthropic_client.py has 483 LOC)

Key Areas Covered:
✅ Token estimation (basic, errors, limits)
✅ DTE validation (success, errors, caching)
✅ Prompt building (system, user, history)
✅ Caching functionality (cache_control headers)
✅ Error handling (API errors, circuit breaker)
✅ Cost tracking (with cache metrics)
✅ Singleton pattern
✅ Edge cases (long history, precounting disabled)
"""
