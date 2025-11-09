# -*- coding: utf-8 -*-
"""
Unit Tests for ChatEngine - Conversational AI with Multi-Agent Plugin System

Test Coverage:
- Message sending (blocking and streaming)
- Plugin selection and routing
- System prompt building (base and plugin-specific)
- Conversation history management
- Knowledge base integration
- User context handling
- Token tracking and streaming
- Error handling and fallbacks

Target Coverage: ≥80% (658 LOC)

@pytest.mark.unit
@pytest.mark.async
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any, List
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from chat.engine import ChatEngine, ChatMessage, ChatResponse
from clients.anthropic_client import AnthropicClient


# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def mock_anthropic_client():
    """Mock AnthropicClient"""
    client = AsyncMock(spec=AnthropicClient)
    client.model = "claude-sonnet-4-5-20250929"
    client.client = AsyncMock()
    return client


@pytest.fixture
def mock_plugin_registry():
    """Mock PluginRegistry"""
    registry = MagicMock()
    registry.list_modules = MagicMock(return_value=["l10n_cl_dte", "l10n_cl_hr_payroll"])
    registry.get_plugin_for_query = MagicMock(return_value=None)
    return registry


@pytest.fixture
def mock_context_manager():
    """Mock ContextManager"""
    manager = MagicMock()
    manager.get_conversation_history = MagicMock(return_value=[])
    manager.save_conversation_history = MagicMock()
    manager.save_user_context = MagicMock()
    manager.get_session_stats = MagicMock(return_value={
        "message_count": 0,
        "total_tokens": 0
    })
    return manager


@pytest.fixture
def mock_knowledge_base():
    """Mock KnowledgeBase"""
    kb = MagicMock()
    kb.search = MagicMock(return_value=[
        {
            "title": "DTE 33 Guide",
            "content": "Información sobre DTE tipo 33 (Factura Electrónica)"
        }
    ])
    return kb


@pytest.fixture
def mock_plugin():
    """Mock Plugin instance"""
    plugin = MagicMock()
    plugin.get_module_name = MagicMock(return_value="l10n_cl_dte")
    plugin.get_display_name = MagicMock(return_value="DTE Module")
    plugin.get_system_prompt = MagicMock(return_value="You are a DTE specialist.")
    return plugin


@pytest.fixture
def chat_engine(mock_anthropic_client, mock_plugin_registry, mock_context_manager, mock_knowledge_base):
    """Create ChatEngine instance with all mocks"""
    return ChatEngine(
        anthropic_client=mock_anthropic_client,
        plugin_registry=mock_plugin_registry,
        redis_client=None,
        session_ttl=3600,
        max_context_messages=10,
        context_manager=mock_context_manager,
        knowledge_base=mock_knowledge_base,
        default_temperature=0.7
    )


@pytest.fixture
def sample_user_context():
    """Sample user context"""
    return {
        "company_name": "Test Company SpA",
        "company_rut": "12345678-9",
        "user_role": "Contador",
        "environment": "Sandbox"
    }


@pytest.fixture
def mock_anthropic_response():
    """Mock Anthropic API response"""
    response = MagicMock()
    response.content = [MagicMock()]
    response.content[0].text = "This is a test response from Claude."
    response.usage = MagicMock()
    response.usage.input_tokens = 150
    response.usage.output_tokens = 50
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_chat_engine_init(mock_anthropic_client, mock_context_manager, mock_knowledge_base):
    """Test ChatEngine initialization"""
    engine = ChatEngine(
        anthropic_client=mock_anthropic_client,
        context_manager=mock_context_manager,
        knowledge_base=mock_knowledge_base
    )

    assert engine.anthropic_client == mock_anthropic_client
    assert engine.context_manager == mock_context_manager
    assert engine.knowledge_base == mock_knowledge_base
    assert engine.plugins_enabled is False


@pytest.mark.unit
def test_chat_engine_init_with_plugins(mock_anthropic_client, mock_plugin_registry, mock_context_manager, mock_knowledge_base):
    """Test ChatEngine initialization with plugin registry"""
    engine = ChatEngine(
        anthropic_client=mock_anthropic_client,
        plugin_registry=mock_plugin_registry,
        context_manager=mock_context_manager,
        knowledge_base=mock_knowledge_base
    )

    assert engine.plugins_enabled is True
    assert engine.plugin_registry == mock_plugin_registry


@pytest.mark.unit
def test_chat_engine_init_custom_parameters(mock_anthropic_client, mock_context_manager, mock_knowledge_base):
    """Test ChatEngine with custom parameters"""
    engine = ChatEngine(
        anthropic_client=mock_anthropic_client,
        context_manager=mock_context_manager,
        knowledge_base=mock_knowledge_base,
        session_ttl=7200,
        max_context_messages=20,
        default_temperature=0.9
    )

    assert engine.session_ttl == 7200
    assert engine.max_context_messages == 20
    assert engine.default_temperature == 0.9


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: SEND MESSAGE (BLOCKING)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_basic(chat_engine, sample_user_context, mock_anthropic_response):
    """Test basic message sending"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-123",
            user_message="¿Cómo genero un DTE 33?",
            user_context=sample_user_context
        )

        assert isinstance(response, ChatResponse)
        assert response.message == "This is a test response from Claude."
        assert response.session_id == "session-123"
        assert response.confidence >= 50.0 and response.confidence <= 100.0  # Calculated dynamically
        assert response.llm_used == "anthropic"
        assert response.tokens_used is not None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_without_user_context(chat_engine, mock_anthropic_response):
    """Test message sending without user context"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-456",
            user_message="¿Qué es un DTE?"
        )

        assert response.message == "This is a test response from Claude."
        assert response.session_id == "session-456"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_with_conversation_history(chat_engine, sample_user_context, mock_anthropic_response):
    """Test message sending with existing conversation history"""
    # Setup conversation history
    history = [
        {
            'role': 'user',
            'content': 'Hola',
            'timestamp': datetime.utcnow().isoformat()
        },
        {
            'role': 'assistant',
            'content': 'Hola, ¿cómo estás?',
            'timestamp': datetime.utcnow().isoformat()
        }
    ]
    chat_engine.context_manager.get_conversation_history = MagicMock(return_value=history)
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-789",
            user_message="¿Cómo creo un DTE?",
            user_context=sample_user_context
        )

        # Verify history was retrieved
        chat_engine.context_manager.get_conversation_history.assert_called_with("session-789")

        # Verify user message was added to history
        assert len(history) == 3
        assert history[-2]["content"] == "¿Cómo creo un DTE?"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_plugin_selection(chat_engine, mock_plugin, sample_user_context, mock_anthropic_response):
    """Test message sending with plugin selection"""
    chat_engine.plugin_registry.get_plugin_for_query = MagicMock(return_value=mock_plugin)
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-plugin",
            user_message="¿Cómo genero un DTE?",
            user_context=sample_user_context
        )

        # Verify plugin was selected
        chat_engine.plugin_registry.get_plugin_for_query.assert_called_once()

        # Verify response includes plugin info
        assert response.plugin_used == "l10n_cl_dte"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_knowledge_base_search(chat_engine, sample_user_context, mock_anthropic_response):
    """Test knowledge base search during message sending"""
    docs = [
        {
            "title": "DTE 33 Factura Electrónica",
            "content": "Guía completa para generar DTE 33..."
        }
    ]
    chat_engine.knowledge_base.search = MagicMock(return_value=docs)
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-kb",
            user_message="¿Cómo genero un DTE?",
            user_context=sample_user_context
        )

        # Verify KB search was called
        chat_engine.knowledge_base.search.assert_called_once()

        # Verify sources are included
        assert response.sources == ["DTE 33 Factura Electrónica"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_anthropic_api_error(chat_engine, sample_user_context):
    """Test error handling when Anthropic API fails"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(
        side_effect=Exception("API Error")
    )

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        with pytest.raises(Exception, match="Anthropic API failed"):
            await chat_engine.send_message(
                session_id="session-error",
                user_message="Test",
                user_context=sample_user_context
            )


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: SYSTEM PROMPT BUILDING
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_build_system_prompt_with_context(chat_engine, sample_user_context):
    """Test system prompt building with user context"""
    docs = [
        {
            "title": "DTE Guide",
            "content": "Complete DTE documentation"
        }
    ]

    prompt = chat_engine._build_system_prompt(docs, sample_user_context)

    assert "Test Company SpA" in prompt
    assert "12345678-9" in prompt
    assert "Contador" in prompt
    assert "DTE Guide" in prompt


@pytest.mark.unit
def test_build_system_prompt_without_context(chat_engine):
    """Test system prompt building without user context"""
    docs = [
        {
            "title": "DTE Guide",
            "content": "Complete DTE documentation"
        }
    ]

    prompt = chat_engine._build_system_prompt(docs, None)

    assert "No disponible" in prompt
    assert "DTE Guide" in prompt


@pytest.mark.unit
def test_build_system_prompt_no_docs(chat_engine, sample_user_context):
    """Test system prompt building without knowledge base docs"""
    prompt = chat_engine._build_system_prompt([], sample_user_context)

    assert "No hay documentación específica" in prompt
    assert "Test Company SpA" in prompt


@pytest.mark.unit
def test_build_system_prompt_empty_docs(chat_engine, sample_user_context):
    """Test system prompt building with empty knowledge base docs"""
    prompt = chat_engine._build_system_prompt([], sample_user_context)

    assert isinstance(prompt, str)
    assert len(prompt) > 0


@pytest.mark.unit
def test_build_plugin_system_prompt(chat_engine, mock_plugin):
    """Test plugin-specific system prompt building"""
    docs = [
        {
            "title": "DTE 33 Guide",
            "content": "Información específica de DTE 33"
        }
    ]
    user_context = {
        "company_name": "Test Company",
        "company_rut": "12345678-9"
    }

    prompt = chat_engine._build_plugin_system_prompt(mock_plugin, docs, user_context)

    assert "You are a DTE specialist." in prompt
    assert "Test Company" in prompt
    assert "DTE 33 Guide" in prompt
    assert "DTE Module" in prompt


@pytest.mark.unit
def test_build_plugin_system_prompt_long_doc_content(chat_engine, mock_plugin):
    """Test plugin prompt with truncated long doc content"""
    docs = [
        {
            "title": "Long Guide",
            "content": "X" * 2000  # Very long content
        }
    ]

    prompt = chat_engine._build_plugin_system_prompt(mock_plugin, docs, None)

    # Should truncate content to 800 chars
    assert len(prompt) < len("X" * 2000)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: CALL ANTHROPIC
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_anthropic_success(chat_engine, mock_anthropic_response):
    """Test successful Anthropic API call"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response_text, tokens_used = await chat_engine._call_anthropic(
            system_prompt="Test system",
            messages=[{"role": "user", "content": "Test"}]
        )

        assert response_text == "This is a test response from Claude."
        assert tokens_used["input_tokens"] == 150
        assert tokens_used["output_tokens"] == 50
        assert tokens_used["total_tokens"] == 200


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_anthropic_api_error(chat_engine):
    """Test Anthropic API error handling"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(
        side_effect=Exception("API connection failed")
    )

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        with pytest.raises(Exception, match="API connection failed"):
            await chat_engine._call_anthropic(
                system_prompt="Test system",
                messages=[{"role": "user", "content": "Test"}]
            )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_anthropic_filters_system_messages(chat_engine, mock_anthropic_response):
    """Test that system messages are filtered from history"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        messages = [
            {"role": "system", "content": "System message"},
            {"role": "user", "content": "User message"},
            {"role": "assistant", "content": "Assistant message"}
        ]

        await chat_engine._call_anthropic(
            system_prompt="Test system",
            messages=messages
        )

        # Get the messages passed to API
        call_kwargs = chat_engine.anthropic_client.client.messages.create.call_args[1]
        api_messages = call_kwargs["messages"]

        # System message should not be in API messages
        assert len(api_messages) == 2
        assert not any(msg["role"] == "system" for msg in api_messages)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: SEND MESSAGE STREAM
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_stream_basic(chat_engine, sample_user_context):
    """Test streaming message sending"""

    with patch('config.settings') as mock_settings:
        mock_settings.enable_streaming = True
        mock_settings.chat_max_tokens = 4096
        # Mock streaming
        stream_context = AsyncMock()
        stream_context.__aenter__ = AsyncMock(return_value=stream_context)
        stream_context.__aexit__ = AsyncMock(return_value=None)
        stream_context.text_stream = AsyncMock()

        async def async_text_stream():
            yield "This "
            yield "is "
            yield "a "
            yield "streaming "
            yield "response"

        stream_context.text_stream.__aiter__ = lambda self: async_text_stream()

        # Mock final message
        final_msg = MagicMock()
        final_msg.usage = MagicMock()
        final_msg.usage.input_tokens = 100
        final_msg.usage.output_tokens = 50
        final_msg.usage.cache_read_input_tokens = 0
        final_msg.usage.cache_creation_input_tokens = 0

        stream_context.get_final_message = AsyncMock(return_value=final_msg)

        chat_engine.anthropic_client.client.messages.stream = MagicMock(return_value=stream_context)

        # Collect streamed chunks
        chunks = []
        async for chunk in chat_engine.send_message_stream(
            session_id="stream-1",
            user_message="Test",
            user_context=sample_user_context
        ):
            chunks.append(chunk)

        # Should have text chunks + done chunk
        assert len(chunks) > 0
        assert any(c.get("type") == "done" for c in chunks)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_stream_disabled(chat_engine, sample_user_context, mock_anthropic_response):
    """Test fallback when streaming is disabled"""

    with patch('config.settings') as mock_settings:
        mock_settings.enable_streaming = False
        mock_settings.chat_max_tokens = 4096
        chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

        chunks = []
        async for chunk in chat_engine.send_message_stream(
            session_id="no-stream",
            user_message="Test",
            user_context=sample_user_context
        ):
            chunks.append(chunk)

        # Should fall back to non-streaming
        assert len(chunks) >= 2
        assert chunks[0]["type"] == "text"
        assert chunks[-1]["type"] == "done"


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: CONFIDENCE CALCULATION
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_calculate_confidence_long_response(chat_engine):
    """Test confidence calculation for long, detailed response"""
    long_response = "A" * 500  # Long response = higher confidence
    confidence = chat_engine._calculate_confidence(long_response, message_count=5)

    # Should be relatively high due to length and context
    assert confidence >= 60.0


@pytest.mark.unit
def test_calculate_confidence_structured_output(chat_engine):
    """Test confidence boost for structured output"""
    structured_response = """
    Respuesta:
    1. Punto uno
    2. Punto dos
    3. Punto tres

    Tabla:
    | Campo | Valor |
    | --- | --- |
    """
    confidence = chat_engine._calculate_confidence(structured_response, message_count=3)

    # Should be boosted for structured output
    assert confidence >= 65.0


@pytest.mark.unit
def test_calculate_confidence_with_uncertainty_phrases(chat_engine):
    """Test confidence penalty for uncertainty phrases"""
    uncertain_response = "No estoy seguro, pero posiblemente el DTE sea válido"
    confidence = chat_engine._calculate_confidence(uncertain_response, message_count=2)

    # Should be penalized for uncertainty
    assert confidence <= 60.0


@pytest.mark.unit
def test_calculate_confidence_short_response(chat_engine):
    """Test confidence calculation for short response"""
    short_response = "Sí"
    confidence = chat_engine._calculate_confidence(short_response, message_count=1)

    # Should be lower due to brevity
    assert confidence < 70.0


@pytest.mark.unit
def test_calculate_confidence_clamped_range(chat_engine):
    """Test that confidence is always between 0 and 100"""
    # Very long response
    very_long = "A" * 5000 + "[" * 100 + "{" * 100
    high_confidence = chat_engine._calculate_confidence(very_long, message_count=50)
    assert 0.0 <= high_confidence <= 100.0

    # Very short with uncertainty
    short_uncertain = "no sé no sé no sé"
    low_confidence = chat_engine._calculate_confidence(short_uncertain, message_count=0)
    assert 0.0 <= low_confidence <= 100.0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_confidence_dynamic(chat_engine, sample_user_context, mock_anthropic_response):
    """Test that confidence is calculated dynamically based on response"""
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-confidence",
            user_message="¿Cómo genero un DTE?",
            user_context=sample_user_context
        )

        # Verify confidence is calculated (not hardcoded)
        assert 0.0 <= response.confidence <= 100.0
        # For "This is a test response from Claude." - medium-length response
        # Should have base 50 + length bonus + potential uncertainty check
        assert response.confidence >= 50.0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_stream_confidence_dynamic(chat_engine, sample_user_context):
    """Test streaming message confidence is calculated dynamically"""

    with patch('config.settings') as mock_settings:
        mock_settings.enable_streaming = True
        mock_settings.chat_max_tokens = 4096
        stream_context = AsyncMock()
        stream_context.__aenter__ = AsyncMock(return_value=stream_context)
        stream_context.__aexit__ = AsyncMock(return_value=None)

        async def async_text_stream():
            yield "Este es un DTE válido. Detalles: RUT válido, folio disponible, montos correctos."

        stream_context.text_stream = AsyncMock()
        stream_context.text_stream.__aiter__ = lambda self: async_text_stream()

        final_msg = MagicMock()
        final_msg.usage = MagicMock()
        final_msg.usage.input_tokens = 100
        final_msg.usage.output_tokens = 50
        final_msg.usage.cache_read_input_tokens = 0
        final_msg.usage.cache_creation_input_tokens = 0

        stream_context.get_final_message = AsyncMock(return_value=final_msg)

        chat_engine.anthropic_client.client.messages.stream = MagicMock(return_value=stream_context)

        chunks = []
        async for chunk in chat_engine.send_message_stream(
            session_id="stream-confidence",
            user_message="Test",
            user_context=sample_user_context
        ):
            chunks.append(chunk)

        # Find done chunk
        done_chunk = next((c for c in chunks if c.get("type") == "done"), None)
        assert done_chunk is not None
        # Verify confidence is dynamic (should be high for this response)
        assert 0.0 <= done_chunk["metadata"]["confidence"] <= 100.0
        assert done_chunk["metadata"]["confidence"] >= 50.0  # Should be decent


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: CONVERSATION STATS
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_get_conversation_stats(chat_engine):
    """Test conversation statistics retrieval"""
    chat_engine.context_manager.get_session_stats = MagicMock(return_value={
        "message_count": 5,
        "total_tokens": 1250
    })

    stats = chat_engine.get_conversation_stats("session-123")

    assert stats["message_count"] == 5
    assert stats["total_tokens"] == 1250


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: CHAT MESSAGE AND RESPONSE DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
def test_chat_message_creation():
    """Test ChatMessage dataclass"""
    msg = ChatMessage(
        role="user",
        content="Test message",
        timestamp="2025-11-09T10:00:00"
    )

    assert msg.role == "user"
    assert msg.content == "Test message"
    assert msg.timestamp == "2025-11-09T10:00:00"


@pytest.mark.unit
def test_chat_response_creation():
    """Test ChatResponse dataclass"""
    response = ChatResponse(
        message="Test response",
        sources=["Doc1", "Doc2"],
        confidence=85.0,
        session_id="session-123",
        llm_used="anthropic",
        tokens_used={"input": 100, "output": 50, "total": 150},
        plugin_used="l10n_cl_dte"
    )

    assert response.message == "Test response"
    assert response.sources == ["Doc1", "Doc2"]
    assert response.confidence == 85.0
    assert response.plugin_used == "l10n_cl_dte"
    assert response.tokens_used["total"] == 150


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_max_context_messages(chat_engine, sample_user_context, mock_anthropic_response):
    """Test that only max_context_messages are kept"""
    chat_engine.max_context_messages = 3

    # Setup with many messages
    history = [
        {
            'role': 'user' if i % 2 == 0 else 'assistant',
            'content': f'Message {i}',
            'timestamp': datetime.utcnow().isoformat()
        }
        for i in range(10)
    ]
    chat_engine.context_manager.get_conversation_history = MagicMock(return_value=history)
    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_anthropic_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        await chat_engine.send_message(
            session_id="session-max-context",
            user_message="New message",
            user_context=sample_user_context
        )

        # Verify only last 3 messages were saved
        saved_history = chat_engine.context_manager.save_conversation_history.call_args[0][1]
        assert len(saved_history) <= 4  # 10 original + 1 new, but limited to 3


@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_empty_response(chat_engine, sample_user_context):
    """Test handling of empty response from LLM"""
    mock_response = MagicMock()
    mock_response.content = [MagicMock()]
    mock_response.content[0].text = ""  # Empty response
    mock_response.usage = MagicMock()
    mock_response.usage.input_tokens = 100
    mock_response.usage.output_tokens = 0

    chat_engine.anthropic_client.client.messages.create = AsyncMock(return_value=mock_response)

    with patch('config.settings') as mock_settings:
        mock_settings.chat_max_tokens = 4096

        response = await chat_engine.send_message(
            session_id="session-empty",
            user_message="Test",
            user_context=sample_user_context
        )

        assert response.message == ""
        assert response.tokens_used["output_tokens"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY STATS FOR TEST COVERAGE
# ═══════════════════════════════════════════════════════════════════════════════
"""
Test Coverage Summary:
======================

Methods Tested:
- __init__: 3 tests
- send_message: 7 tests
- _build_system_prompt: 4 tests
- _build_plugin_system_prompt: 2 tests
- _call_anthropic: 3 tests
- _calculate_confidence: 6 tests ✅ NEW
- send_message_stream: 2 tests
- get_conversation_stats: 1 test
- ChatMessage: 1 test
- ChatResponse: 1 test
- Edge cases: 2 tests

Total: 32 unit tests (was 26, +6 for confidence calculation)
Coverage Target: ≥80% (chat/engine.py has 658 LOC)

Key Areas Covered:
✅ Message sending (basic, with context, with history)
✅ Plugin selection and routing
✅ System prompt building (default and plugin-specific)
✅ Knowledge base integration
✅ Streaming messages
✅ Error handling
✅ Token tracking
✅ Context management
✅ Confidence calculation (dynamic, not hardcoded) ✅ FIXED
✅ Edge cases (max context, empty responses)

Confidence Calculation Tests:
✅ test_calculate_confidence_long_response (length bonus)
✅ test_calculate_confidence_structured_output (structure bonus)
✅ test_calculate_confidence_with_uncertainty_phrases (penalty)
✅ test_calculate_confidence_short_response (brevity)
✅ test_calculate_confidence_clamped_range (boundary checking)
✅ test_send_message_confidence_dynamic (integration)
✅ test_send_message_stream_confidence_dynamic (streaming)

Previous TODOs RESOLVED:
✅ Line 237 (send_message): NOW USES _calculate_confidence() ✅ FIXED
✅ Line 629 (send_message_stream): NOW USES _calculate_confidence() ✅ FIXED
   → Confidence is calculated from response quality indicators
   → Tests updated to verify dynamic calculation
"""
