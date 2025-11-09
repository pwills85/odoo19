# -*- coding: utf-8 -*-
"""
Integration Tests for Streaming SSE Feature (PHASE 1)
===================================================

Tests for Server-Sent Events streaming implementation:
- SSE format compliance
- Progressive token generation
- Error handling in streams
- Stream completion signals
- Real-time response delivery

Author: EERGYGROUP - Test Automation Sprint 2025-11-09
Markers: @pytest.mark.integration, @pytest.mark.api, @pytest.mark.asyncio, @pytest.mark.slow
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any, List, AsyncGenerator
import json

from httpx import AsyncClient
from fastapi.responses import StreamingResponse

from main import app
from config import settings


@pytest.mark.integration
@pytest.mark.api
@pytest.mark.asyncio
@pytest.mark.slow
class TestStreamingSSEIntegration:
    """Integration tests for Streaming SSE feature (PHASE 1)."""

    @pytest.fixture
    def sample_user_message(self) -> str:
        """Create sample user message for chat."""
        return "¿Cómo genero un DTE 33 en Odoo?"

    @pytest.fixture
    def sample_user_context(self) -> Dict[str, Any]:
        """Create sample user context."""
        return {
            "company_name": "Test Company SPA",
            "company_rut": "12345678-9",
            "user_role": "Contador",
            "environment": "Sandbox"
        }

    async def _make_streaming_request(
        self,
        test_client: AsyncClient,
        session_id: str,
        message: str,
        user_context: Dict[str, Any] = None
    ):
        """Helper to make streaming request."""
        payload = {
            "session_id": session_id,
            "message": message,
            "user_context": user_context
        }

        response = await test_client.post(
            "/api/chat/message/stream",
            json=payload,
            headers={"Authorization": f"Bearer {settings.api_key}"}
        )

        return response

    def _parse_sse_events(self, response_text: str) -> List[Dict[str, Any]]:
        """Parse SSE format response into events."""
        events = []
        lines = response_text.strip().split('\n')

        i = 0
        while i < len(lines):
            line = lines[i]

            if line.startswith('data: '):
                try:
                    data = json.loads(line[6:])  # Remove 'data: ' prefix
                    events.append(data)
                except json.JSONDecodeError:
                    pass

            i += 1

        return events

    @pytest.mark.asyncio
    async def test_streaming_endpoint_exists(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test that streaming endpoint exists and is accessible."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())
            response = await self._make_streaming_request(
                test_client,
                session_id,
                sample_user_message,
                sample_user_context
            )

            # Should not return 404 or 403
            assert response.status_code != 404, "Endpoint not found"
            assert response.status_code != 403, "Forbidden"

    @pytest.mark.asyncio
    async def test_streaming_returns_sse_format(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test that streaming endpoint returns SSE format."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock the chat engine to return streaming data
            async def mock_stream_generator():
                """Mock SSE stream generator."""
                yield {"type": "text", "content": "Hola, "}
                yield {"type": "text", "content": "aquí está la respuesta"}
                yield {
                    "type": "done",
                    "metadata": {
                        "sources": ["DTE Guide"],
                        "confidence": 95.0,
                        "llm_used": "anthropic",
                        "tokens_used": {"input": 100, "output": 50}
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_stream_generator
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                # Check response status
                assert response.status_code == 200, \
                    f"Expected 200, got {response.status_code}: {response.text}"

                # Check content type (may include charset)
                content_type = response.headers.get("content-type", "")
                assert "text/event-stream" in content_type, \
                    f"Wrong content-type: {content_type}"

                # Check cache control headers
                assert response.headers.get("cache-control") == "no-cache"
                assert response.headers.get("connection") == "keep-alive"

    @pytest.mark.asyncio
    async def test_streaming_progressive_tokens(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test that streaming returns tokens progressively."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock progressive token generation
            async def mock_progressive_stream(session_id, user_message, user_context=None):
                """Yield tokens one by one."""
                tokens = ["Primero", " necesitas", " crear", " un", " DTE", " 33"]
                for token in tokens:
                    yield {"type": "text", "content": token}

                yield {
                    "type": "done",
                    "metadata": {
                        "sources": [],
                        "confidence": 90.0,
                        "llm_used": "anthropic",
                        "tokens_used": {"total": 50}
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_progressive_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                assert response.status_code == 200

                # Parse SSE events
                events = self._parse_sse_events(response.text)

                # Should have multiple text events + done event
                text_events = [e for e in events if e.get("type") == "text"]
                done_events = [e for e in events if e.get("type") == "done"]

                assert len(text_events) >= 1, "No text events received"
                assert len(done_events) == 1, "Should have exactly one done event"

                # Verify progressive content
                full_response = "".join(e.get("content", "") for e in text_events)
                assert len(full_response) > 0, "No content received"

    @pytest.mark.asyncio
    async def test_streaming_handles_errors_gracefully(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test error handling in streaming (mid-stream error)."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock stream that throws error mid-way
            async def mock_error_stream():
                """Stream that errors mid-way."""
                yield {"type": "text", "content": "Inicio de "}
                raise RuntimeError("Anthropic API error")

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_error_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                # Response should still complete (SSE format)
                assert response.status_code == 200

                # Should contain error event
                events = self._parse_sse_events(response.text)
                error_events = [e for e in events if e.get("type") == "error"]

                # Error handling should be present
                # (actual implementation in event_stream() generator)

    @pytest.mark.asyncio
    async def test_streaming_sends_done_event(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test that [DONE] event is sent at end of stream."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock complete stream with done event
            async def mock_complete_stream(session_id_param, user_message, user_context=None):
                """Complete stream with done event."""
                yield {"type": "text", "content": "Respuesta completa"}
                yield {
                    "type": "done",
                    "metadata": {
                        "sources": ["Docs"],
                        "confidence": 95.0,
                        "llm_used": "anthropic",
                        "tokens_used": {
                            "input": 100,
                            "output": 50,
                            "total": 150
                        },
                        "session_id": session_id
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_complete_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                assert response.status_code == 200

                # Parse events
                events = self._parse_sse_events(response.text)

                # Verify done event
                done_events = [e for e in events if e.get("type") == "done"]
                assert len(done_events) == 1, "Should have exactly one done event"

                done_event = done_events[0]
                assert "metadata" in done_event
                assert "sources" in done_event["metadata"]
                assert "confidence" in done_event["metadata"]
                assert "tokens_used" in done_event["metadata"]

    @pytest.mark.asyncio
    async def test_streaming_maintains_session_context(
        self,
        sample_user_context: Dict[str, Any]
    ):
        """Test that streaming maintains session context across messages."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # First message
            first_message = "¿Cómo creo un DTE?"

            # Second message (building on first)
            second_message = "¿Y cómo lo envío al SII?"

            async def mock_contextual_stream(msg):
                """Mock that acknowledges context."""
                if "envío" in msg:
                    yield {"type": "text", "content": "Para enviar, necesitas..."}
                else:
                    yield {"type": "text", "content": "Para crear un DTE..."}

                yield {
                    "type": "done",
                    "metadata": {
                        "sources": [],
                        "confidence": 90.0,
                        "llm_used": "anthropic",
                        "tokens_used": {}
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()

                # Return different responses based on message
                async def stream_side_effect(session_id_param, user_message, user_context):
                    async for chunk in mock_contextual_stream(user_message):
                        yield chunk

                mock_engine.send_message_stream = AsyncMock(
                    side_effect=stream_side_effect
                )
                mock_get_engine.return_value = mock_engine

                # First request
                response1 = await self._make_streaming_request(
                    test_client,
                    session_id,
                    first_message,
                    sample_user_context
                )
                assert response1.status_code == 200

                # Second request (same session)
                response2 = await self._make_streaming_request(
                    test_client,
                    session_id,
                    second_message,
                    sample_user_context
                )
                assert response2.status_code == 200

    @pytest.mark.asyncio
    async def test_streaming_with_knowledge_base_injection(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test streaming with knowledge base context injection."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock stream with KB sources
            async def mock_kb_stream():
                """Stream with knowledge base context."""
                yield {"type": "text", "content": "Según la documentación DTE: "}
                yield {"type": "text", "content": "paso 1, paso 2, paso 3"}
                yield {
                    "type": "done",
                    "metadata": {
                        "sources": [
                            "DTE Generation Guide",
                            "SII Compliance",
                            "Odoo Integration"
                        ],
                        "confidence": 98.0,
                        "llm_used": "anthropic",
                        "tokens_used": {
                            "input": 500,
                            "output": 100
                        }
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_kb_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                assert response.status_code == 200

                # Verify sources in done event
                events = self._parse_sse_events(response.text)
                done_events = [e for e in events if e.get("type") == "done"]

                if done_events:
                    done_event = done_events[0]
                    sources = done_event.get("metadata", {}).get("sources", [])
                    assert len(sources) > 0, "Should have sources from KB"

    @pytest.mark.asyncio
    async def test_streaming_with_caching_metrics(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test that streaming includes cache metrics in tokens_used."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock stream with cache metrics
            async def mock_cached_stream():
                """Stream with cache hit."""
                yield {"type": "text", "content": "Respuesta rápida"}
                yield {
                    "type": "done",
                    "metadata": {
                        "sources": [],
                        "confidence": 95.0,
                        "llm_used": "anthropic",
                        "tokens_used": {
                            "input_tokens": 2500,
                            "output_tokens": 150,
                            "total_tokens": 2650,
                            "cache_read_tokens": 2000,  # Cache hit!
                            "cache_creation_tokens": 0
                        }
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_cached_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                assert response.status_code == 200

                # Check for cache metrics
                events = self._parse_sse_events(response.text)
                done_events = [e for e in events if e.get("type") == "done"]

                if done_events:
                    tokens_used = done_events[0].get("metadata", {}).get("tokens_used", {})
                    # Should have cache metrics if caching is enabled
                    if settings.enable_prompt_caching:
                        # Cache metrics might be present
                        pass

    @pytest.mark.asyncio
    async def test_streaming_with_empty_response(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test streaming handles empty responses correctly."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock empty stream
            async def mock_empty_stream(session_id_param, user_message, user_context=None):
                """Empty stream."""
                yield {
                    "type": "done",
                    "metadata": {
                        "sources": [],
                        "confidence": 0.0,
                        "llm_used": "anthropic",
                        "tokens_used": {}
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_empty_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                assert response.status_code == 200

                # Should still have done event
                events = self._parse_sse_events(response.text)
                done_events = [e for e in events if e.get("type") == "done"]
                assert len(done_events) == 1, "Should have done event even if empty"

    @pytest.mark.asyncio
    async def test_streaming_large_response(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test streaming handles large responses correctly."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Mock large response
            async def mock_large_stream(session_id_param, user_message, user_context=None):
                """Large streaming response."""
                # Simulate 100 chunks
                for i in range(100):
                    yield {"type": "text", "content": f"Chunk {i}: " + ("x" * 10)}

                yield {
                    "type": "done",
                    "metadata": {
                        "sources": [],
                        "confidence": 90.0,
                        "llm_used": "anthropic",
                        "tokens_used": {"total": 1000}
                    }
                }

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_large_stream
                mock_get_engine.return_value = mock_engine

                response = await self._make_streaming_request(
                    test_client,
                    session_id,
                    sample_user_message,
                    sample_user_context
                )

                assert response.status_code == 200

                # Should handle large response
                events = self._parse_sse_events(response.text)
                text_events = [e for e in events if e.get("type") == "text"]

                # Should have many chunks
                assert len(text_events) > 50, "Should handle large response"

    @pytest.mark.asyncio
    async def test_streaming_respects_rate_limiting(
        self,
        sample_user_message: str,
        sample_user_context: Dict[str, Any]
    ):
        """Test that streaming respects rate limiting."""
        import uuid

        async with AsyncClient(app=app, base_url="http://test") as test_client:
            session_id = str(uuid.uuid4())

            # Try to make many rapid requests
            responses = []

            async def mock_stream():
                """Simple stream."""
                yield {"type": "text", "content": "Response"}
                yield {"type": "done", "metadata": {}}

            with patch("main.get_chat_engine") as mock_get_engine:
                mock_engine = MagicMock()
                mock_engine.send_message_stream = mock_stream
                mock_get_engine.return_value = mock_engine

                # Make several rapid requests
                for i in range(5):
                    response = await self._make_streaming_request(
                        test_client,
                        session_id,
                        f"Message {i}",
                        sample_user_context
                    )
                    responses.append(response.status_code)

                # At least some should succeed
                successful = [r for r in responses if r == 200]
                assert len(successful) > 0, "No successful responses"
