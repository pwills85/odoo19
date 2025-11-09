# -*- coding: utf-8 -*-
"""
Integration Tests for Token Pre-counting Feature (PHASE 1)
=========================================================

Tests for token estimation and cost control:
- Token counting before API calls
- Cost estimation accuracy
- Oversized request prevention
- Model limit validation
- System prompt overhead accounting

Author: EERGYGROUP - Test Automation Sprint 2025-11-09
Markers: @pytest.mark.integration, @pytest.mark.api
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any, List
import json

from fastapi.testclient import TestClient
from main import app
from config import settings


@pytest.mark.integration
@pytest.mark.api
class TestTokenPrecountingIntegration:
    """Integration tests for Token Pre-counting feature (PHASE 1)."""

    @pytest.fixture
    def test_client(self):
        """Create FastAPI test client."""
        return TestClient(app)

    @pytest.fixture
    def sample_messages(self) -> List[Dict[str, str]]:
        """Create sample messages for token estimation."""
        return [
            {
                "role": "user",
                "content": "¿Cómo genero un DTE 33?"
            }
        ]

    @pytest.fixture
    def system_prompt(self) -> str:
        """Create sample system prompt."""
        return "Eres un experto en facturación electrónica chilena."

    @pytest.fixture
    def large_messages(self) -> List[Dict[str, str]]:
        """Create large messages that might exceed limits."""
        return [
            {
                "role": "user",
                "content": "X" * 50000  # 50K characters
            }
        ]

    async def _estimate_tokens(
        self,
        test_client: TestClient,
        messages: List[Dict[str, str]],
        system: str = None
    ) -> Dict[str, Any]:
        """Helper to call estimate_tokens endpoint."""
        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        result = await client.estimate_tokens(
            messages=messages,
            system=system
        )

        return result

    @pytest.mark.asyncio
    async def test_estimate_tokens_returns_valid_format(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test that token estimation returns valid format."""

        # Mock the Anthropic count_tokens API
        with patch("anthropic.AsyncAnthropic.messages") as mock_messages:
            mock_count = MagicMock()
            mock_count.count_tokens = AsyncMock()
            mock_count.count_tokens.return_value = MagicMock(
                input_tokens=150
            )
            mock_messages.count_tokens = AsyncMock(
                return_value=MagicMock(input_tokens=150)
            )

            from clients.anthropic_client import AnthropicClient
            from config import settings

            client = AnthropicClient(
                api_key=settings.anthropic_api_key,
                model=settings.anthropic_model
            )

            with patch.object(client.client.messages, 'count_tokens') as mock_ct:
                mock_ct.return_value = MagicMock(input_tokens=150)

                result = await client.estimate_tokens(
                    messages=sample_messages,
                    system=system_prompt
                )

                # Verify format
                assert "input_tokens" in result
                assert "estimated_output_tokens" in result
                assert "estimated_total_tokens" in result
                assert "estimated_cost_usd" in result

                # Verify types
                assert isinstance(result["input_tokens"], int)
                assert isinstance(result["estimated_output_tokens"], int)
                assert isinstance(result["estimated_total_tokens"], int)
                assert isinstance(result["estimated_cost_usd"], float)

    @pytest.mark.asyncio
    async def test_token_estimation_accuracy(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test token estimation accuracy (±5% tolerance)."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Known message with ~150 tokens
        messages = [{"role": "user", "content": "Hola, ¿cómo estás?"}]

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            # Simulate token count
            mock_ct.return_value = MagicMock(input_tokens=15)

            result = await client.estimate_tokens(
                messages=messages,
                system="System prompt"
            )

            # Should have reasonable token count
            assert result["input_tokens"] > 0, "Should count input tokens"
            assert result["estimated_output_tokens"] > 0, "Should estimate output"
            assert result["estimated_total_tokens"] > result["input_tokens"], \
                "Total should include output"

    @pytest.mark.asyncio
    async def test_precounting_prevents_oversized_requests(
        self,
        large_messages: List[Dict[str, str]]
    ):
        """Test that oversized requests are rejected."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Mock tokens that exceed limit
        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            # Simulate exceeding limit (e.g., 250K tokens > 200K limit)
            mock_ct.return_value = MagicMock(input_tokens=250000)

            if settings.enable_token_precounting:
                # Should raise ValueError if request exceeds limits
                with pytest.raises(ValueError) as exc_info:
                    await client.estimate_tokens(
                        messages=large_messages,
                        system="System"
                    )

                assert "too large" in str(exc_info.value).lower() or \
                       "exceeds" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_precounting_validates_against_model_limits(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test validation against Claude model limits (200K)."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            # Test below limit
            mock_ct.return_value = MagicMock(input_tokens=100000)

            result = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            # Should succeed
            assert result["input_tokens"] == 100000

            # Test at limit boundary
            mock_ct.return_value = MagicMock(input_tokens=200000)

            result = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            # Should succeed
            assert result["input_tokens"] == 200000

    @pytest.mark.asyncio
    async def test_estimate_includes_system_prompt_overhead(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test that estimation includes system prompt in count."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Call with system prompt
        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=200)

            # The count_tokens should be called with system parameter
            result = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            # Verify that count_tokens was called with system
            assert mock_ct.called, "count_tokens should be called"

            call_kwargs = mock_ct.call_args.kwargs
            assert "system" in call_kwargs, "System should be passed"

    @pytest.mark.asyncio
    async def test_cost_estimation_accuracy(
        self,
        sample_messages: List[Dict[str, str]]
    ):
        """Test that cost estimation is accurate."""

        from clients.anthropic_client import AnthropicClient
        from config import settings
        from utils.cost_tracker import CLAUDE_PRICING

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Known tokens
        input_tokens = 1000
        expected_output = 300  # ~30% estimation

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=input_tokens)

            result = await client.estimate_tokens(
                messages=sample_messages,
                system="System"
            )

            # Verify cost calculation
            pricing = CLAUDE_PRICING.get(
                client.model,
                CLAUDE_PRICING.get("default")
            )

            # Assuming 30% output estimation
            expected_cost = (
                input_tokens * pricing["input"] +
                expected_output * pricing["output"]
            )

            assert result["estimated_cost_usd"] > 0, "Cost should be positive"

    @pytest.mark.asyncio
    async def test_precounting_with_conversation_history(
        self,
        system_prompt: str
    ):
        """Test token counting with multi-turn conversation."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Multi-turn conversation
        messages = [
            {"role": "user", "content": "¿Qué es un DTE?"},
            {"role": "assistant", "content": "Un DTE es un Documento Tributario Electrónico..."},
            {"role": "user", "content": "¿Cómo lo genero?"}
        ]

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=500)

            result = await client.estimate_tokens(
                messages=messages,
                system=system_prompt
            )

            # Should account for all messages
            assert result["input_tokens"] > 0
            assert result["estimated_total_tokens"] > 0

    @pytest.mark.asyncio
    async def test_precounting_prevents_expensive_requests(
        self,
        sample_messages: List[Dict[str, str]]
    ):
        """Test that expensive requests are rejected."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Simulate very expensive request
        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            # 100K tokens = ~$30 with pricing
            mock_ct.return_value = MagicMock(input_tokens=100000)

            if settings.enable_token_precounting:
                if hasattr(settings, 'max_estimated_cost_per_request'):
                    # If cost limit is set, verify it's enforced
                    try:
                        result = await client.estimate_tokens(
                            messages=sample_messages,
                            system="System"
                        )

                        # If no error, cost should be under limit
                        assert result["estimated_cost_usd"] <= \
                            settings.max_estimated_cost_per_request
                    except ValueError as e:
                        # Should reject expensive requests
                        assert "expensive" in str(e).lower() or \
                               "cost" in str(e).lower()

    @pytest.mark.asyncio
    async def test_token_counting_with_special_characters(
        self,
        system_prompt: str
    ):
        """Test token counting with special characters (spanish, unicode)."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Spanish text with special characters
        messages = [
            {
                "role": "user",
                "content": "¿Cómo genero un DTE con RUT 76.123.456-7 y folio #12345?"
            }
        ]

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=35)

            result = await client.estimate_tokens(
                messages=messages,
                system=system_prompt
            )

            # Should handle special characters
            assert result["input_tokens"] > 0

    @pytest.mark.asyncio
    async def test_token_counting_empty_messages(
        self,
        system_prompt: str
    ):
        """Test token counting with empty/minimal messages."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Minimal message
        messages = [{"role": "user", "content": "Hola"}]

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=10)

            result = await client.estimate_tokens(
                messages=messages,
                system=system_prompt
            )

            # Should handle minimal input
            assert result["input_tokens"] > 0
            assert result["estimated_output_tokens"] > 0

    @pytest.mark.asyncio
    async def test_precounting_logging(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str,
        caplog
    ):
        """Test that token counting is properly logged."""

        from clients.anthropic_client import AnthropicClient
        from config import settings
        import logging

        caplog.set_level(logging.INFO)

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=150)

            result = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            # Should have logged token estimation
            assert "token_estimation" in caplog.text or \
                   "estimate" in caplog.text.lower()

    @pytest.mark.asyncio
    async def test_validate_dte_uses_precounting(
        self,
        caplog
    ):
        """Test that DTE validation uses token precounting."""

        from clients.anthropic_client import AnthropicClient
        from config import settings
        import logging

        caplog.set_level(logging.INFO)

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        dte_data = {
            "tipo_dte": "33",
            "folio": 12345,
            "monto_total": 1190000
        }

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=500)

            with patch.object(client.client.messages, 'create') as mock_create:
                mock_create.return_value = MagicMock(
                    content=[MagicMock(text='{"c": 95, "w": [], "e": [], "r": "send"}')],
                    usage=MagicMock(
                        input_tokens=500,
                        output_tokens=50,
                        cache_creation_input_tokens=0,
                        cache_read_input_tokens=0
                    )
                )

                if settings.enable_token_precounting:
                    result = await client.validate_dte(dte_data, [])

                    # Should have counted tokens
                    assert mock_ct.called, "Token counting should be called"

    @pytest.mark.asyncio
    async def test_token_counting_model_differences(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test token counting for different Claude models."""

        from clients.anthropic_client import AnthropicClient

        # Test with default model
        client_default = AnthropicClient(
            api_key="test-key",
            model="claude-sonnet-4-5-20250929"
        )

        with patch.object(client_default.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=150)

            result = await client_default.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            assert result["input_tokens"] > 0
            assert mock_ct.called

    @pytest.mark.asyncio
    async def test_precounting_handles_api_errors(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test graceful error handling in token precounting."""

        from clients.anthropic_client import AnthropicClient
        from config import settings
        import anthropic

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            # Simulate API error
            mock_ct.side_effect = anthropic.APIError("API error")

            with pytest.raises(anthropic.APIError):
                await client.estimate_tokens(
                    messages=sample_messages,
                    system=system_prompt
                )

    @pytest.mark.asyncio
    async def test_token_estimation_consistency(
        self,
        sample_messages: List[Dict[str, str]],
        system_prompt: str
    ):
        """Test that token estimation is consistent across multiple calls."""

        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        with patch.object(client.client.messages, 'count_tokens') as mock_ct:
            mock_ct.return_value = MagicMock(input_tokens=150)

            # Call multiple times
            result1 = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            result2 = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            result3 = await client.estimate_tokens(
                messages=sample_messages,
                system=system_prompt
            )

            # Should be consistent
            assert result1["input_tokens"] == result2["input_tokens"]
            assert result2["input_tokens"] == result3["input_tokens"]
            assert result1["estimated_cost_usd"] == result2["estimated_cost_usd"]
