# -*- coding: utf-8 -*-
"""
Chat Engine - Conversational AI with Context Management
========================================================

Professional chat engine for multi-turn conversations with LLM routing.

Features:
- Multi-turn conversation awareness (last N messages)
- Knowledge base injection (relevant DTE docs)
- LLM routing (Anthropic primary, OpenAI fallback)
- User context (company, role, permissions)
- Spanish + Chilean terminology support
- Structured logging and error handling

Architecture:
- Stateless (all state in Redis via ContextManager)
- Scalable (multiple AI service instances)
- Resilient (graceful degradation on LLM failures)
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import structlog
from datetime import datetime

from .context_manager import ContextManager
from .knowledge_base import KnowledgeBase
from clients.anthropic_client import AnthropicClient
# OpenAI eliminado - Solo Anthropic

logger = structlog.get_logger(__name__)


@dataclass
class ChatMessage:
    """Single chat message."""
    role: str  # 'user' | 'assistant' | 'system'
    content: str
    timestamp: str


@dataclass
class ChatResponse:
    """Response from chat engine."""
    message: str  # AI response text
    sources: List[str]  # Knowledge base sources used
    confidence: float  # 0-100
    session_id: str
    llm_used: str  # 'anthropic' | 'openai'
    tokens_used: Optional[Dict] = None  # {input, output, total}


class ChatEngine:
    """
    Conversational AI engine with multi-turn context awareness.

    Features:
    - Multi-LLM support (Anthropic primary, OpenAI fallback)
    - Context management (last N messages)
    - Knowledge base injection
    - Session tracking
    - Chilean DTE specialized prompts
    """

    # System prompt base (especializado en DTE chileno)
    SYSTEM_PROMPT_BASE = """Eres un asistente especializado en Facturación Electrónica Chilena (DTE) para Odoo 19.

**Tu Experiencia Incluye:**
- Generación de DTEs (tipos 33, 34, 52, 56, 61)
- Compliance SII (Servicio de Impuestos Internos de Chile)
- Gestión de certificados digitales y CAF
- Operación en modo contingencia
- Resolución de errores comunes
- Mejores prácticas fiscales chilenas

**Cómo Debes Responder:**
1. **Claro y Accionable**: Instrucciones paso a paso cuando sea apropiado
2. **Específico a Odoo**: Referencias a pantallas, wizards, y menús concretos
3. **Terminología Chilena**: Usa vocabulario local (ej: "factura", "folio", "RUT")
4. **Ejemplos Prácticos**: Casos de uso reales cuando ayude
5. **Troubleshooting**: Si detectas error, explica causa + solución

**Formato de Respuestas:**
- Usa **negritas** para términos clave
- Usa listas numeradas para procesos paso a paso
- Usa ✅ ❌ ⚠️ para indicar estados
- Incluye comandos/rutas exactas cuando sea relevante

**Contexto Usuario:**
{user_context}

**Documentación Relevante:**
{knowledge_base_docs}

**IMPORTANTE:** Si la pregunta está fuera de tu expertise (DTE/Odoo), indícalo claramente y sugiere dónde buscar."""

    def __init__(
        self,
        anthropic_client: AnthropicClient,
        redis_client = None,
        session_ttl: int = 3600,
        max_context_messages: int = 10,
        context_manager = None,
        knowledge_base = None,
        default_temperature: float = 0.7
    ):
        """
        Initialize chat engine.

        Args:
            anthropic_client: Anthropic Claude client (PRIMARY)
            redis_client: Redis client for caching
            session_ttl: Session TTL in seconds
            max_context_messages: Max messages to keep in context
            context_manager: Redis-based context manager (optional)
            knowledge_base: DTE documentation knowledge base (optional)
            default_temperature: LLM temperature (0-2)
        """
        self.anthropic_client = anthropic_client
        self.redis = redis_client
        self.session_ttl = session_ttl
        self.max_context_messages = max_context_messages
        self.context_manager = context_manager
        self.knowledge_base = knowledge_base
        self.default_temperature = default_temperature

        logger.info("chat_engine_initialized",
                   max_context_messages=max_context_messages,
                   has_context_manager=context_manager is not None,
                   has_knowledge_base=knowledge_base is not None)

    async def send_message(
        self,
        session_id: str,
        user_message: str,
        user_context: Optional[Dict] = None
    ) -> ChatResponse:
        """
        Send user message and get AI response.

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
                   has_user_context=user_context is not None)

        try:
            # 1. Retrieve conversation history
            history = self.context_manager.get_conversation_history(session_id)
            logger.debug("conversation_history_retrieved",
                        session_id=session_id,
                        message_count=len(history))

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
            logger.info("knowledge_base_searched",
                       session_id=session_id,
                       docs_found=len(relevant_docs))

            # 4. Build system prompt with knowledge
            system_prompt = self._build_system_prompt(relevant_docs, user_context)

            # 5. Call LLM (Anthropic primary, OpenAI fallback)
            llm_used = 'anthropic'
            tokens_used = None

            try:
                response_text, tokens_used = await self._call_anthropic(
                    system_prompt,
                    history[-self.max_context_messages:]  # Last N messages
                )
            except Exception as e:
                logger.warning("anthropic_failed_fallback_to_openai",
                             session_id=session_id,
                             error=str(e))

                # NO FALLBACK - Solo Anthropic
                logger.error("anthropic_failed_no_fallback",
                           session_id=session_id,
                           error=str(e))
                raise Exception(f"Anthropic API failed: {str(e)}")

            # 6. Add assistant response to history
            assistant_msg = {
                'role': 'assistant',
                'content': response_text,
                'timestamp': datetime.utcnow().isoformat()
            }
            history.append(assistant_msg)

            # 7. Save conversation history (keep last N messages)
            self.context_manager.save_conversation_history(
                session_id,
                history[-self.max_context_messages:]
            )

            # 8. Save user context if provided
            if user_context:
                self.context_manager.save_user_context(session_id, user_context)

            # 9. Build response
            response = ChatResponse(
                message=response_text,
                sources=[doc['title'] for doc in relevant_docs],
                confidence=95.0,  # TODO: Calculate from LLM confidence scores
                session_id=session_id,
                llm_used=llm_used,
                tokens_used=tokens_used
            )

            logger.info("chat_message_completed",
                       session_id=session_id,
                       llm_used=llm_used,
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
        return self.SYSTEM_PROMPT_BASE.format(
            user_context=context_text,
            knowledge_base_docs=kb_text
        )

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

    def get_conversation_stats(self, session_id: str) -> Dict:
        """
        Get conversation statistics for session.

        Args:
            session_id: Session identifier

        Returns:
            Dict with stats
        """
        return self.context_manager.get_session_stats(session_id)
