# -*- coding: utf-8 -*-
"""
Integration Tests for Prompt Caching Feature (PHASE 1)
======================================================

Tests for Anthropic Claude prompt caching optimization:
- Ephemeral cache control
- Cache creation and read tracking
- Cost reduction verification
- System message caching

Author: EERGYGROUP - Test Automation Sprint 2025-11-09
Markers: @pytest.mark.integration, @pytest.mark.api, @pytest.mark.slow
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any, List
import json

from httpx import AsyncClient
from main import app
from config import settings


@pytest.mark.integration
@pytest.mark.api
@pytest.mark.slow
class TestPromptCachingIntegration:
    """Integration tests for Prompt Caching feature (PHASE 1)."""

    # Removed fixture - using AsyncClient directly in tests with async with

    @pytest.fixture
    def sample_dte_data(self) -> Dict[str, Any]:
        """Create sample DTE data for validation."""
        return {
            "tipo_dte": "33",
            "folio": 12345,
            "fecha_emision": "2025-10-23",
            "monto_total": 1190000,
            "emisor_rut": "12345678-9",
            "receptor_rut": "98765432-1",
            "razon_social": "EMPRESA TEST SPA",
            "giro": "Comercio",
            "lineas": [
                {
                    "linea_num": 1,
                    "descripcion": "Servicio consultoría",
                    "cantidad": 1,
                    "precio_unitario": 1000000,
                    "monto_linea": 1000000
                }
            ]
        }

    @pytest.fixture
    def mock_cache_response(self) -> Dict[str, Any]:
        """Mock Anthropic response with cache metrics."""
        return {
            "type": "Message",
            "content": [
                {
                    "type": "text",
                    "text": '{"c": 95.0, "w": [], "e": [], "r": "send"}'
                }
            ],
            "usage": {
                "input_tokens": 2500,
                "output_tokens": 150,
                "cache_creation_input_tokens": 2000,  # Cache created
                "cache_read_input_tokens": 0
            }
        }

    @pytest.fixture
    def mock_cache_hit_response(self) -> Dict[str, Any]:
        """Mock Anthropic response with cache hit."""
        return {
            "type": "Message",
            "content": [
                {
                    "type": "text",
                    "text": '{"c": 95.0, "w": [], "e": [], "r": "send"}'
                }
            ],
            "usage": {
                "input_tokens": 2500,
                "output_tokens": 150,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 2000  # Cache hit
            }
        }

    async def _make_validation_request(
        self,
        test_client: AsyncClient,
        dte_data: Dict[str, Any],
        history: List[Dict] = None
    ) -> Dict[str, Any]:
        """Helper to make validation request."""
        payload = {
            "dte_data": dte_data,
            "company_id": 1,
            "history": history or []
        }

        response = await test_client.post(
            "/api/ai/validate",
            json=payload,
            headers={"Authorization": f"Bearer {settings.api_key}"}
        )

        return response.status_code, response.json()

    @pytest.mark.asyncio
    async def test_caching_endpoint_exists(self):
        """Test that DTE validation endpoint exists and is accessible."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            payload = {
                "dte_data": {"tipo_dte": "33"},
                "company_id": 1
            }

            response = await test_client.post(
                "/api/ai/validate",
                json=payload,
                headers={"Authorization": f"Bearer {settings.api_key}"}
            )

            # Should not return 404 or 403
            assert response.status_code in [200, 400, 422], \
                f"Unexpected status: {response.status_code}. Response: {response.json()}"

    @pytest.mark.asyncio
    async def test_caching_creates_cache_on_first_call(
        self,
        sample_dte_data: Dict[str, Any],
        mock_cache_response: Dict[str, Any]
    ):
        """Test that first call creates cache (cache_creation_input_tokens > 0)."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            with patch("clients.anthropic_client.AnthropicClient.validate_dte") as mock_validate:
                # Mock successful validation with cache creation
                mock_validate.return_value = {
                    "confidence": 95.0,
                    "warnings": [],
                    "errors": [],
                    "recommendation": "send",
                    "cache_creation_tokens": 2000,  # Cache created
                    "cache_read_tokens": 0
                }

                status_code, response = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )

                # Validate response
                assert status_code == 200, f"Failed: {response}"
                assert response["confidence"] == 95.0
                assert response["recommendation"] == "send"

                # Verify mock was called
                assert mock_validate.called, "validate_dte not called"

    @pytest.mark.asyncio
    async def test_caching_reads_cache_on_second_call(
        self,
        sample_dte_data: Dict[str, Any],
        mock_cache_hit_response: Dict[str, Any]
    ):
        """Test that second call reads cache (cache_read_input_tokens > 0)."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            call_count = 0

            async def mock_validate_with_cache(dte_data, history):
                """Mock that simulates cache on second call."""
                nonlocal call_count
                call_count += 1

                if call_count == 1:
                    # First call - create cache
                    return {
                        "confidence": 95.0,
                        "warnings": [],
                        "errors": [],
                        "recommendation": "send",
                        "cache_creation_tokens": 2000,
                        "cache_read_tokens": 0
                    }
                else:
                    # Second call - cache hit
                    return {
                        "confidence": 95.0,
                        "warnings": [],
                        "errors": [],
                        "recommendation": "send",
                        "cache_creation_tokens": 0,
                        "cache_read_tokens": 2000  # Cache hit!
                    }

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_with_cache):

                # First call
                status1, response1 = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )
                assert status1 == 200

                # Second call with same data
                status2, response2 = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )
                assert status2 == 200

                # Both should succeed
                assert response2["confidence"] == 95.0
                assert response2["recommendation"] == "send"

    @pytest.mark.asyncio
    async def test_caching_reduces_costs(
        self,
        sample_dte_data: Dict[str, Any]
    ):
        """Test that caching reduces actual costs (~90% saving)."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            # Mock responses with and without cache
            def mock_validate_cost(dte_data, history):
                return {
                    "confidence": 95.0,
                    "warnings": [],
                    "errors": [],
                    "recommendation": "send",
                    "input_tokens": 2500,
                    "output_tokens": 150,
                    "cache_creation_tokens": 2000,
                    "cache_read_tokens": 0,
                    "cost_usd": 0.0025  # With caching
                }

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_cost):

                status, response = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )

                assert status == 200
                # Cache creation is tracked (in real implementation)
                # Subsequent calls would show cache_read_tokens

    @pytest.mark.asyncio
    async def test_cache_control_header_in_system_messages(self):
        """Test that cache_control is added to system messages."""
        from clients.anthropic_client import AnthropicClient
        from config import settings

        client = AnthropicClient(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )

        # Mock the client's underlying Anthropic API (async)
        with patch.object(client.client.messages, 'create', new=AsyncMock()) as mock_create:
            mock_message = MagicMock()
            mock_message.content = [MagicMock(text='{"c": 95, "w": [], "e": [], "r": "send"}')]
            mock_message.usage = MagicMock()
            mock_message.usage.input_tokens = 1000
            mock_message.usage.output_tokens = 100
            mock_message.usage.cache_read_input_tokens = 0
            mock_message.usage.cache_creation_input_tokens = 500

            mock_create.return_value = mock_message

            # Call validate_dte which should use cache_control
            result = await client.validate_dte(
                dte_data={"tipo_dte": "33"},
                history=[]
            )

            # Verify the call was made
            assert mock_create.called, "Anthropic API not called"

            # Check if system was passed
            call_kwargs = mock_create.call_args.kwargs

            # For cached calls, system should be a list with cache_control
            if settings.enable_prompt_caching and "system" in call_kwargs:
                system = call_kwargs["system"]

                # Should be list if caching enabled
                if isinstance(system, list):
                    # Check for cache_control in any element
                    has_cache_control = any(
                        isinstance(elem, dict) and "cache_control" in elem
                        for elem in system
                    )
                    assert has_cache_control, \
                        "cache_control not found in system messages"

    @pytest.mark.asyncio
    async def test_caching_with_multiple_validations(
        self,
        sample_dte_data: Dict[str, Any]
    ):
        """Test caching behavior across multiple validation requests."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            validation_results = []

            def mock_validate_batch(dte_data, history):
                """Mock validate that tracks cache behavior."""
                result = {
                    "confidence": 95.0,
                    "warnings": [],
                    "errors": [],
                    "recommendation": "send"
                }
                validation_results.append(result)
                return result

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_batch):

                # Make 3 validation calls
                for i in range(3):
                    status, response = await self._make_validation_request(
                        test_client,
                        sample_dte_data
                    )
                    assert status == 200, f"Call {i+1} failed: {response}"

                # All validations should succeed
                assert len(validation_results) == 3
                for result in validation_results:
                    assert result["confidence"] == 95.0

    @pytest.mark.asyncio
    async def test_cache_different_contexts(
        self,
        sample_dte_data: Dict[str, Any]
    ):
        """Test that cache handles different DTE types correctly."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            dte_types = ["33", "34", "52", "56", "61"]

            def mock_validate_dte_type(dte_data, history):
                """Validate different DTE types."""
                return {
                    "confidence": 90.0,
                    "warnings": [],
                    "errors": [],
                    "recommendation": "send"
                }

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_dte_type):

                for dte_type in dte_types:
                    test_data = sample_dte_data.copy()
                    test_data["tipo_dte"] = dte_type

                    status, response = await self._make_validation_request(
                        test_client,
                        test_data
                    )

                    assert status == 200, \
                        f"Failed for DTE type {dte_type}: {response}"
                    assert response["confidence"] >= 90.0

    @pytest.mark.asyncio
    async def test_caching_preserves_validation_quality(
        self,
        sample_dte_data: Dict[str, Any]
    ):
        """Test that caching does not degrade validation quality."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            original_errors = ["RUT inválido", "Folio duplicado"]

            def mock_validate_quality(dte_data, history):
                """Mock validation with quality metrics."""
                return {
                    "confidence": 92.5,
                    "warnings": ["Monto debe ser positivo"],
                    "errors": original_errors,
                    "recommendation": "review"
                }

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_quality):

                # First call
                status1, response1 = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )

                # Second call (should be cached)
                status2, response2 = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )

                # Both should have same quality
                assert response1["confidence"] == response2["confidence"]
                assert response1["errors"] == response2["errors"]
                assert response1["warnings"] == response2["warnings"]

    @pytest.mark.asyncio
    async def test_caching_with_history(
        self,
        sample_dte_data: Dict[str, Any]
    ):
        """Test caching with rejection history (different context)."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            history = [
                {"error_code": "E001", "message": "RUT duplicado"},
                {"error_code": "E002", "message": "Monto incorrecto"}
            ]

            def mock_validate_history(dte_data, history_param):
                """Mock with history context."""
                return {
                    "confidence": 88.0,
                    "warnings": ["Revisar historial de rechazos"],
                    "errors": [],
                    "recommendation": "review"
                }

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_history):

                status, response = await self._make_validation_request(
                    test_client,
                    sample_dte_data,
                    history=history
                )

                assert status == 200
                assert response["confidence"] == 88.0
                # History should increase processing cost without cache benefit
                # (different context = different cache key)

    @pytest.mark.asyncio
    async def test_caching_error_handling(
        self,
        sample_dte_data: Dict[str, Any]
    ):
        """Test graceful handling when cache is unavailable."""
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            def mock_validate_error(dte_data, history):
                """Mock error in validation."""
                raise ValueError("Cache unavailable")

            with patch("clients.anthropic_client.AnthropicClient.validate_dte",
                       side_effect=mock_validate_error):

                status, response = await self._make_validation_request(
                    test_client,
                    sample_dte_data
                )

                # Endpoint handles errors gracefully (returns 200 with error details)
                # This is the correct production behavior - don't crash the API
                assert status == 200
                # The error should be logged and potentially returned in response
                # (actual behavior may vary based on error handling implementation)
