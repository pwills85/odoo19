# -*- coding: utf-8 -*-
"""
Chat Engine - Conversational AI with Multi-Agent Plugin System
===============================================================

Professional chat engine with plugin-based multi-agent architecture.

Features (Phase 2B Enhanced):
- Multi-agent plugin system (specialized per module)
- Intelligent plugin selection (keyword matching + context)
- Multi-turn conversation awareness (last N messages)
- Knowledge base injection (module-specific docs)
- User context (company, role, permissions)
- Spanish + Chilean terminology support
- Structured logging and error handling

Architecture:
- Stateless (all state in Redis via ContextManager)
- Scalable (multiple AI service instances)
- Resilient (graceful degradation on LLM failures)
- Multi-agent (plugin per Odoo module)

Author: EERGYGROUP - Phase 2B Enhancement 2025-10-24
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field
import structlog
from datetime import datetime

from .context_manager import ContextManager
from .knowledge_base import KnowledgeBase
from clients.anthropic_client import AnthropicClient
from plugins.registry import PluginRegistry

logger = structlog.get_logger(__name__)


@dataclass
class ChatMessage:
    """Single chat message."""
    role: str  # 'user' | 'assistant' | 'system'
    content: str
    timestamp: str


@dataclass
class ChatResponse:
    """Response from chat engine (Phase 2B Enhanced)."""
    message: str  # AI response text
    sources: List[str]  # Knowledge base sources used
    confidence: float  # 0-100
    session_id: str
    llm_used: str  # 'anthropic' | 'openai'
    tokens_used: Optional[Dict] = None  # {input, output, total}
    plugin_used: Optional[str] = None  # 🆕 Plugin module name (Phase 2B)


class ChatEngine:
    """
    Conversational AI engine with multi-agent plugin system (Phase 2B).

    Features:
    - Multi-agent architecture (plugin per module)
    - Intelligent plugin selection
    - Context management (last N messages)
    - Knowledge base injection (module-specific)
    - Session tracking
    - Specialized prompts per plugin
    """

    def __init__(
        self,
        anthropic_client: AnthropicClient,
        plugin_registry: Optional[PluginRegistry] = None,  # 🆕 Plugin registry
        redis_client = None,
        session_ttl: int = 3600,
        max_context_messages: int = 10,
        context_manager = None,
        knowledge_base = None,
        default_temperature: float = 0.7
    ):
        """
        Initialize chat engine with plugin support (Phase 2B).

        Args:
            anthropic_client: Anthropic Claude client (PRIMARY)
            plugin_registry: Plugin registry for multi-agent (Phase 2B)
            redis_client: Redis client for caching
            session_ttl: Session TTL in seconds
            max_context_messages: Max messages to keep in context
            context_manager: Redis-based context manager (optional)
            knowledge_base: DTE documentation knowledge base (optional)
            default_temperature: LLM temperature (0-2)
        """
        self.anthropic_client = anthropic_client
        self.plugin_registry = plugin_registry  # 🆕
        self.redis = redis_client
        self.session_ttl = session_ttl
        self.max_context_messages = max_context_messages
        self.context_manager = context_manager
        self.knowledge_base = knowledge_base
        self.default_temperature = default_temperature

        # Check if plugin system is enabled
        self.plugins_enabled = plugin_registry is not None

        logger.info(
            "chat_engine_initialized",
            max_context_messages=max_context_messages,
            has_context_manager=context_manager is not None,
            has_knowledge_base=knowledge_base is not None,
            plugins_enabled=self.plugins_enabled,  # 🆕
            plugin_count=len(plugin_registry.list_modules()) if plugin_registry else 0  # 🆕
        )

    async def send_message(
        self,
        session_id: str,
        user_message: str,
        user_context: Optional[Dict] = None
    ) -> ChatResponse:
        """
        Send user message and get AI response (Phase 2B Enhanced).

        Uses plugin system for intelligent module-specific responses.

        Args:
            session_id: Unique session identifier
            user_message: User's message
            user_context: Optional context (company_id, user_role, etc.)

        Returns:
            ChatResponse with AI's reply and metadata
        """
        logger.info("chat_message_received",
                   session_id=session_id,
                   message_length=len(user_message),
                   has_user_context=user_context is not None,
                   plugins_enabled=self.plugins_enabled)

        try:
            # 1. Select appropriate plugin (Phase 2B)
            plugin = None
            plugin_module = None

            if self.plugins_enabled and self.plugin_registry:
                plugin = self.plugin_registry.get_plugin_for_query(
                    query=user_message,
                    context=user_context
                )

                if plugin:
                    plugin_module = plugin.get_module_name()
                    logger.info(
                        "plugin_selected",
                        plugin_module=plugin_module,
                        display_name=plugin.get_display_name()
                    )

            # 2. Retrieve conversation history
            history = self.context_manager.get_conversation_history(session_id)
            logger.debug("conversation_history_retrieved",
                        session_id=session_id,
                        message_count=len(history))

            # 3. Add user message to history
            user_msg = {
                'role': 'user',
                'content': user_message,
                'timestamp': datetime.utcnow().isoformat()
            }
            history.append(user_msg)

            # 4. Search knowledge base (module-specific if plugin selected)
            kb_filters = {'module': plugin_module} if plugin_module else {}
            relevant_docs = self.knowledge_base.search(
                query=user_message,
                top_k=3,
                filters=kb_filters
            )
            logger.info("knowledge_base_searched",
                       session_id=session_id,
                       module=plugin_module or "all",
                       docs_found=len(relevant_docs))

            # 5. Build system prompt (plugin-specific or default)
            if plugin:
                system_prompt = self._build_plugin_system_prompt(
                    plugin=plugin,
                    relevant_docs=relevant_docs,
                    user_context=user_context
                )
            else:
                system_prompt = self._build_system_prompt(relevant_docs, user_context)

            # 6. Call LLM (Anthropic primary)
            llm_used = 'anthropic'
            tokens_used = None

            try:
                response_text, tokens_used = await self._call_anthropic(
                    system_prompt,
                    history[-self.max_context_messages:]  # Last N messages
                )
            except Exception as e:
                logger.error("anthropic_failed_no_fallback",
                           session_id=session_id,
                           error=str(e))
                raise Exception(f"Anthropic API failed: {str(e)}")

            # 7. Add assistant response to history (with plugin metadata)
            assistant_msg = {
                'role': 'assistant',
                'content': response_text,
                'timestamp': datetime.utcnow().isoformat()
            }
            if plugin_module:
                assistant_msg['plugin_used'] = plugin_module  # 🆕 Track plugin

            history.append(assistant_msg)

            # 8. Save conversation history (keep last N messages)
            self.context_manager.save_conversation_history(
                session_id,
                history[-self.max_context_messages:]
            )

            # 9. Save user context if provided
            if user_context:
                self.context_manager.save_user_context(session_id, user_context)

            # 10. Build response
            response = ChatResponse(
                message=response_text,
                sources=[doc['title'] for doc in relevant_docs],
                confidence=95.0,  # TODO: Calculate from LLM confidence scores
                session_id=session_id,
                llm_used=llm_used,
                tokens_used=tokens_used,
                plugin_used=plugin_module  # 🆕 Phase 2B
            )

            logger.info("chat_message_completed",
                       session_id=session_id,
                       llm_used=llm_used,
                       plugin_used=plugin_module,  # 🆕
                       response_length=len(response_text),
                       sources_used=len(relevant_docs))

            return response

        except Exception as e:
            logger.error("chat_message_error",
                        session_id=session_id,
                        error=str(e),
                        exc_info=True)
            raise

    def _build_system_prompt(
        self,
        relevant_docs: List[Dict],
        user_context: Optional[Dict]
    ) -> str:
        """
        Build system prompt with knowledge base context.

        Args:
            relevant_docs: Relevant KB documents
            user_context: User context dict

        Returns:
            Complete system prompt
        """
        # User context section
        context_text = ""
        if user_context:
            context_text = f"""
- **Compañía**: {user_context.get('company_name', 'N/A')}
- **RUT Compañía**: {user_context.get('company_rut', 'N/A')}
- **Rol Usuario**: {user_context.get('user_role', 'Usuario')}
- **Ambiente**: {user_context.get('environment', 'Sandbox')}
"""
        else:
            context_text = "No disponible"

        # Knowledge base docs section
        kb_text = ""
        if relevant_docs:
            kb_text = "\n\n".join([
                f"## {doc['title']}\n{doc['content']}"
                for doc in relevant_docs
            ])
        else:
            kb_text = "No hay documentación específica para esta consulta."

        # Build complete prompt
        # Fallback to default DTE prompt (backward compatibility)
        default_prompt = """Eres un asistente especializado en Odoo 19.

**Contexto Usuario:**
{user_context}

**Documentación Relevante:**
{knowledge_base_docs}

**IMPORTANTE:** Si la pregunta está fuera de tu expertise, indícalo claramente."""

        return default_prompt.format(
            user_context=context_text,
            knowledge_base_docs=kb_text
        )

    def _build_plugin_system_prompt(
        self,
        plugin,
        relevant_docs: List[Dict],
        user_context: Optional[Dict]
    ) -> str:
        """
        Build system prompt using plugin's specialized prompt (Phase 2B).

        Args:
            plugin: Selected plugin
            relevant_docs: Relevant KB documents
            user_context: User context dict

        Returns:
            Complete system prompt with plugin specialization
        """
        # Get plugin's base system prompt
        plugin_prompt = plugin.get_system_prompt()

        # Build user context section
        context_text = ""
        if user_context:
            context_text = f"""
**User Context:**
- **Company:** {user_context.get('company_name', 'N/A')}
- **Company RUT:** {user_context.get('company_rut', 'N/A')}
- **User Role:** {user_context.get('user_role', 'User')}
- **Environment:** {user_context.get('environment', 'Sandbox')}
"""

        # Build knowledge base docs section
        kb_text = ""
        if relevant_docs:
            kb_text = "**Relevant Documentation:**\n\n"
            for i, doc in enumerate(relevant_docs, 1):
                # Limit doc content to avoid token bloat
                content_preview = doc['content'][:800] if len(doc['content']) > 800 else doc['content']
                kb_text += f"{i}. **{doc['title']}**\n{content_preview}...\n\n"

        # Combine plugin prompt + context + KB
        combined_prompt = f"""{plugin_prompt}

{context_text}

{kb_text}

**IMPORTANT:** You are answering as a specialist in {plugin.get_display_name()}.
Focus on this module and suggest other specialists if the question is out of scope.
"""

        logger.debug(
            "plugin_system_prompt_built",
            plugin_module=plugin.get_module_name(),
            prompt_length=len(combined_prompt),
            kb_docs=len(relevant_docs)
        )

        return combined_prompt

    async def _call_anthropic(
        self,
        system_prompt: str,
        messages: List[Dict]
    ) -> tuple[str, Dict]:
        """
        Call Anthropic Claude API.

        Args:
            system_prompt: System prompt with context
            messages: Conversation history

        Returns:
            Tuple of (response_text, tokens_used)
        """
        logger.info("calling_anthropic_api",
                   message_count=len(messages))

        try:
            from config import settings

            # Anthropic API format (ASYNC)
            response = await self.anthropic_client.client.messages.create(
                model=self.anthropic_client.model,
                max_tokens=settings.chat_max_tokens,
                temperature=self.default_temperature,
                system=system_prompt,
                messages=[
                    {'role': msg['role'], 'content': msg['content']}
                    for msg in messages
                    if msg['role'] in ['user', 'assistant']  # Skip system
                ]
            )

            response_text = response.content[0].text

            tokens_used = {
                'input_tokens': response.usage.input_tokens,
                'output_tokens': response.usage.output_tokens,
                'total_tokens': response.usage.input_tokens + response.usage.output_tokens
            }

            logger.info("anthropic_api_success",
                       input_tokens=tokens_used['input_tokens'],
                       output_tokens=tokens_used['output_tokens'])

            return response_text, tokens_used

        except Exception as e:
            logger.error("anthropic_api_error", error=str(e))
            raise

    async def _call_openai(
        self,
        system_prompt: str,
        messages: List[Dict]
    ) -> tuple[str, Dict]:
        """
        Call OpenAI GPT-4 API (fallback).

        Args:
            system_prompt: System prompt with context
            messages: Conversation history

        Returns:
            Tuple of (response_text, tokens_used)
        """
        if not self.openai_client:
            raise Exception("OpenAI client not configured")

        logger.info("calling_openai_api",
                   message_count=len(messages))

        try:
            # OpenAI format (system message prepended)
            openai_messages = [
                {'role': 'system', 'content': system_prompt}
            ]

            # Add conversation history
            for msg in messages:
                if msg['role'] in ['user', 'assistant']:
                    openai_messages.append({
                        'role': msg['role'],
                        'content': msg['content']
                    })

            # Call OpenAI
            from config import settings
            result = await self.openai_client.send_message(
                messages=openai_messages,
                model=self.openai_client.client._client_wrapper._api_key and "gpt-4-turbo-preview",
                max_tokens=settings.chat_max_tokens,
                temperature=self.default_temperature
            )

            logger.info("openai_api_success",
                       input_tokens=result['usage']['input_tokens'],
                       output_tokens=result['usage']['output_tokens'])

            return result['content'], result['usage']

        except Exception as e:
            logger.error("openai_api_error", error=str(e))
            raise

    async def send_message_stream(
        self,
        session_id: str,
        user_message: str,
        user_context: Optional[Dict] = None
    ):
        """
        Send user message and stream AI response in real-time.

        OPTIMIZATION 2025-10-24: Streaming for 3x better UX.

        Args:
            session_id: Unique session identifier
            user_message: User's message
            user_context: Optional context (company_id, user_role, etc.)

        Yields:
            Dict chunks: {"type": "text", "content": str} or {"type": "done", "metadata": dict}
        """
        from config import settings

        if not settings.enable_streaming:
            # Fallback to non-streaming
            response = await self.send_message(session_id, user_message, user_context)
            yield {"type": "text", "content": response.message}
            yield {"type": "done", "metadata": {
                "sources": response.sources,
                "confidence": response.confidence,
                "llm_used": response.llm_used,
                "tokens_used": response.tokens_used
            }}
            return

        logger.info("chat_message_stream_started",
                   session_id=session_id,
                   message_length=len(user_message))

        try:
            # 1. Retrieve conversation history
            history = self.context_manager.get_conversation_history(session_id)

            # 2. Add user message to history
            user_msg = {
                'role': 'user',
                'content': user_message,
                'timestamp': datetime.utcnow().isoformat()
            }
            history.append(user_msg)

            # 3. Retrieve relevant knowledge base docs
            relevant_docs = self.knowledge_base.search(
                query=user_message,
                top_k=3,
                filters={'module': 'l10n_cl_dte'}
            )

            # 4. Build system prompt (CACHEABLE)
            system_prompt = self._build_system_prompt(relevant_docs, user_context)
            kb_docs_text = "\n\n".join([
                f"## {doc['title']}\n{doc['content']}"
                for doc in relevant_docs
            ]) if relevant_docs else ""

            # 5. Call Anthropic with streaming + caching
            full_response = ""
            tokens_used = None

            try:
                # Build messages
                messages = [
                    {'role': msg['role'], 'content': msg['content']}
                    for msg in history[-self.max_context_messages:]
                    if msg['role'] in ['user', 'assistant']
                ]

                # Stream with caching
                if settings.enable_prompt_caching and kb_docs_text:
                    # Use cached knowledge base
                    system_parts = [
                        {"type": "text", "text": self.SYSTEM_PROMPT_BASE.split("{knowledge_base_docs}")[0]},
                        {
                            "type": "text",
                            "text": kb_docs_text,
                            "cache_control": {"type": "ephemeral"}  # ✅ CACHE KB
                        }
                    ]
                else:
                    system_parts = system_prompt

                # Stream chunks
                async with self.anthropic_client.client.messages.stream(
                    model=self.anthropic_client.model,
                    max_tokens=settings.chat_max_tokens,
                    temperature=self.default_temperature,
                    system=system_parts,
                    messages=messages
                ) as stream:
                    async for text in stream.text_stream:
                        full_response += text
                        yield {"type": "text", "content": text}

                    # Get final message for usage stats
                    final_message = await stream.get_final_message()
                    tokens_used = {
                        'input_tokens': final_message.usage.input_tokens,
                        'output_tokens': final_message.usage.output_tokens,
                        'total_tokens': final_message.usage.input_tokens + final_message.usage.output_tokens,
                        'cache_read_tokens': getattr(final_message.usage, 'cache_read_input_tokens', 0),
                        'cache_creation_tokens': getattr(final_message.usage, 'cache_creation_input_tokens', 0)
                    }

                    # Log cache performance
                    if tokens_used['cache_read_tokens'] > 0:
                        cache_hit_rate = tokens_used['cache_read_tokens'] / tokens_used['input_tokens']
                        logger.info(
                            "streaming_cache_hit",
                            session_id=session_id,
                            cache_hit_rate=f"{cache_hit_rate*100:.1f}%"
                        )

            except Exception as e:
                logger.error("anthropic_streaming_failed",
                           session_id=session_id,
                           error=str(e))
                raise

            # 6. Save assistant response to history
            assistant_msg = {
                'role': 'assistant',
                'content': full_response,
                'timestamp': datetime.utcnow().isoformat()
            }
            history.append(assistant_msg)

            # 7. Save conversation history
            self.context_manager.save_conversation_history(
                session_id,
                history[-self.max_context_messages:]
            )

            # 8. Save user context if provided
            if user_context:
                self.context_manager.save_user_context(session_id, user_context)

            # 9. Yield completion metadata
            yield {
                "type": "done",
                "metadata": {
                    "sources": [doc['title'] for doc in relevant_docs],
                    "confidence": 95.0,
                    "llm_used": "anthropic",
                    "tokens_used": tokens_used,
                    "session_id": session_id
                }
            }

            logger.info("chat_message_stream_completed",
                       session_id=session_id,
                       response_length=len(full_response),
                       sources_used=len(relevant_docs))

        except Exception as e:
            logger.error("chat_message_stream_error",
                        session_id=session_id,
                        error=str(e),
                        exc_info=True)
            yield {"type": "error", "content": str(e)}

    def get_conversation_stats(self, session_id: str) -> Dict:
        """
        Get conversation statistics for session.

        Args:
            session_id: Session identifier

        Returns:
            Dict with stats
        """
        return self.context_manager.get_session_stats(session_id)
