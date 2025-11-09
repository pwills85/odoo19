# AI Service Transformation Plan
## From Generic AI Service → Specialized Support Agent

**Date**: 2025-10-22
**Objective**: Transform AI Service into a **professional support assistant** for DTE operations (and future modules)
**Strategy**: API-only (Anthropic + OpenAI), no local models
**Status**: 🔄 Planning

---

## Executive Summary

### Current State (As-Is)

**AI Service** actualmente tiene:
- ✅ Anthropic Claude API integration (validation + SII monitoring)
- ⚠️ **Ollama integration** (not used, adds complexity)
- ⚠️ **sentence-transformers** (local embeddings, heavy, slow startup)
- ⚠️ **ChromaDB** (vector DB, not utilized)
- ⚠️ Generic endpoints (validation, reconciliation) - limited utility
- ⚠️ No conversational capability (one-shot calls only)
- ⚠️ No context management (stateless)
- ⚠️ No user session handling

**Problems**:
1. **Heavy dependencies**: sentence-transformers (1.2 GB model download)
2. **Slow startup**: Model loading takes 30-60 seconds
3. **Underutilized**: Only validation and SII monitoring used
4. **No chat**: Can't provide real-time support to users
5. **No memory**: Each request is isolated (no conversation history)
6. **Maintenance burden**: Local models require updates, GPU optimization, etc.

### Target State (To-Be)

**AI Support Assistant** will be:
- ✅ **Conversational**: Multi-turn chat with context awareness
- ✅ **Specialized**: Deep knowledge of DTE operations (Chilean tax compliance)
- ✅ **Multi-LLM**: Anthropic Claude (default) + OpenAI GPT-4 (fallback)
- ✅ **Lightweight**: API-only, no local models (fast startup < 5s)
- ✅ **Contextual**: Redis-based session + conversation memory
- ✅ **Extensible**: Easy to add support for new Odoo modules
- ✅ **Cost-Effective**: $0.15-0.50 per support conversation (vs $50+ human agent)

**Use Cases**:
1. **DTE Support**: "¿Cómo genero un DTE 33?" → Guides user through wizard
2. **Error Resolution**: "Error: CAF sin folios" → Explains CAF management, suggests actions
3. **Compliance Questions**: "¿Qué es el modo contingencia?" → Explains with examples
4. **Troubleshooting**: "DTE rechazado por SII" → Analyzes error, suggests fixes
5. **Future**: Inventory, accounting, payroll support (modular expansion)

---

## Architecture Comparison

### Current Architecture (As-Is)

```
┌────────────────────────────────────────────────────┐
│               AI SERVICE (Port 8002)               │
│                                                    │
│  Dependencies (Heavy):                             │
│  - anthropic 0.7.8          ✅ (keep)             │
│  - ollama 0.1.6             ❌ (remove)            │
│  - sentence-transformers    ❌ (remove 1.2GB)     │
│  - chromadb                 ❌ (remove)            │
│  - torch (implicit)         ❌ (remove 2GB+)      │
│                                                    │
│  Endpoints:                                        │
│  POST /api/ai/validate      (DTE validation)       │
│  POST /api/ai/reconcile     (Invoice matching)     │
│  POST /api/ai/sii/monitor   (SII news scraping)    │
│  GET  /api/ai/sii/status    (Monitoring status)    │
│                                                    │
│  Startup Time: 30-60 seconds (model loading)       │
│  Memory Usage: 2-4 GB                              │
│  Docker Image: ~8 GB                               │
└────────────────────────────────────────────────────┘
```

### Target Architecture (To-Be)

```
┌────────────────────────────────────────────────────────────────┐
│          AI SUPPORT ASSISTANT (Port 8002)                      │
│                                                                │
│  Dependencies (Lightweight):                                   │
│  - anthropic 0.7.8          ✅ (primary LLM)                  │
│  - openai 1.6.1             ✅ (fallback LLM)                 │
│  - redis 5.0.1              ✅ (session/context storage)       │
│  - fastapi 0.104.1          ✅ (web framework)                │
│  - structlog 23.2.0         ✅ (logging)                       │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  CHAT ENGINE                                             │ │
│  │  - Multi-turn conversations                              │ │
│  │  - Context management (last N messages)                  │ │
│  │  - Session tracking (Redis)                              │ │
│  │  - LLM router (Anthropic → OpenAI fallback)              │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  KNOWLEDGE BASE                                          │ │
│  │  - DTE operations (generate, query, contingency)         │ │
│  │  - SII compliance (tax codes, document types)            │ │
│  │  - Error catalog (common issues + solutions)             │ │
│  │  - Module-specific docs (extensible)                     │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  CONTEXT MANAGER (Redis)                                 │ │
│  │  - User sessions (session_id → messages)                 │ │
│  │  - Conversation history (last 10 turns)                  │ │
│  │  - User context (company, permissions, preferences)      │ │
│  │  - TTL: 1 hour (auto-cleanup)                            │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  Endpoints:                                                    │
│  POST /api/chat/message          (Send message, get response) │
│  POST /api/chat/session/new      (Start new conversation)     │
│  GET  /api/chat/session/{id}     (Get conversation history)   │
│  DELETE /api/chat/session/{id}   (Clear session)              │
│  POST /api/chat/feedback         (User feedback on response)  │
│                                                                │
│  Legacy Endpoints (Maintained):                                │
│  POST /api/ai/sii/monitor        (SII monitoring)             │
│  GET  /api/ai/sii/status         (Monitoring status)          │
│                                                                │
│  Startup Time: < 5 seconds (no model loading)                 │
│  Memory Usage: < 512 MB                                        │
│  Docker Image: ~500 MB                                         │
└────────────────────────────────────────────────────────────────┘
                              ↓ HTTP/JSON
┌────────────────────────────────────────────────────────────────┐
│                     EXTERNAL LLM APIs                          │
│                                                                │
│  Anthropic Claude API (Primary)                                │
│  - Model: claude-3-5-sonnet-20241022                           │
│  - Cost: $3/MTok input, $15/MTok output                        │
│  - Latency: ~1-3 seconds (streaming)                           │
│  - Rate Limit: 4000 RPM, 400k TPM                              │
│                                                                │
│  OpenAI GPT-4 API (Fallback)                                   │
│  - Model: gpt-4-turbo-preview                                  │
│  - Cost: $10/MTok input, $30/MTok output                       │
│  - Latency: ~2-4 seconds (streaming)                           │
│  - Rate Limit: 500 RPM, 150k TPM                               │
└────────────────────────────────────────────────────────────────┘
```

---

## Detailed Implementation Plan

### Phase 1: Cleanup & Simplification (2 hours)

#### 1.1 Remove Ollama Integration

**Files to modify**:
- ✅ `requirements.txt` - Remove `ollama==0.1.6`
- ✅ `config.py` - Remove ollama settings
- ✅ `main.py` - Remove ollama references in health check

**Benefits**:
- -50 MB Docker image
- Cleaner codebase
- No confusion about which LLM to use

#### 1.2 Remove sentence-transformers & ChromaDB

**Files to modify**:
- ✅ `requirements.txt` - Remove:
  - `sentence-transformers==2.2.2`
  - `chromadb==0.4.22`
  - `torch` (implicit dependency)
- ✅ `reconciliation/invoice_matcher.py` - Delete or stub
- ✅ `main.py` - Remove matcher singleton
- ✅ `config.py` - Remove embedding settings

**Benefits**:
- -7 GB Docker image (torch + models)
- -30-60 seconds startup time
- -2-4 GB memory usage

**Note**: Reconciliation endpoint can be reimplemented using Claude API later if needed.

#### 1.3 Remove Unused Dependencies

**Remove**:
- `numpy` (only used by sentence-transformers)
- `pypdf`, `pdfplumber`, `python-docx`, `pytesseract` (document processing - not used)
- `Pillow` (image processing - not used)

**Keep** (still useful):
- `lxml` (XML parsing for DTE)
- `beautifulsoup4`, `html5lib` (SII monitoring)
- `slack-sdk` (notifications)
- `redis` (cache + sessions)

---

### Phase 2: Chat Engine Implementation (8 hours)

#### 2.1 Core Chat Engine (3 hours)

**New file**: `chat/engine.py`

```python
"""
Chat Engine - Conversational AI with context management
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import structlog
from clients.anthropic_client import get_anthropic_client
from clients.openai_client import get_openai_client  # NEW
from chat.context_manager import ContextManager
from chat.knowledge_base import KnowledgeBase

logger = structlog.get_logger()


@dataclass
class ChatMessage:
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: str


@dataclass
class ChatResponse:
    message: str
    sources: List[str]  # Knowledge base sources used
    confidence: float  # 0-100
    session_id: str
    llm_used: str  # 'anthropic' or 'openai'


class ChatEngine:
    """
    Conversational AI engine with multi-turn context awareness.

    Features:
    - Multi-LLM support (Anthropic primary, OpenAI fallback)
    - Context management (last N messages)
    - Knowledge base injection
    - Session tracking
    - Streaming support (future)
    """

    def __init__(
        self,
        context_manager: ContextManager,
        knowledge_base: KnowledgeBase,
        anthropic_api_key: str,
        openai_api_key: str,
        default_model: str = "claude-3-5-sonnet-20241022",
        max_context_messages: int = 10
    ):
        self.context_manager = context_manager
        self.knowledge_base = knowledge_base
        self.anthropic_client = get_anthropic_client(anthropic_api_key, default_model)
        self.openai_client = get_openai_client(openai_api_key)
        self.max_context_messages = max_context_messages

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
            ChatResponse with AI's reply
        """
        logger.info("chat_message_received",
                    session_id=session_id,
                    message_length=len(user_message))

        # 1. Retrieve conversation history
        history = self.context_manager.get_conversation_history(session_id)

        # 2. Add user message to history
        history.append({
            'role': 'user',
            'content': user_message
        })

        # 3. Retrieve relevant knowledge
        relevant_docs = self.knowledge_base.search(
            query=user_message,
            top_k=3,
            filters={'module': 'l10n_cl_dte'}  # DTE module
        )

        # 4. Build system prompt with knowledge
        system_prompt = self._build_system_prompt(relevant_docs, user_context)

        # 5. Call LLM (Anthropic primary, OpenAI fallback)
        try:
            response = await self._call_anthropic(system_prompt, history)
            llm_used = 'anthropic'
        except Exception as e:
            logger.warning("anthropic_failed_fallback_to_openai", error=str(e))
            response = await self._call_openai(system_prompt, history)
            llm_used = 'openai'

        # 6. Add assistant response to history
        history.append({
            'role': 'assistant',
            'content': response
        })

        # 7. Save conversation history (keep last N messages)
        self.context_manager.save_conversation_history(
            session_id,
            history[-self.max_context_messages:]
        )

        # 8. Return response
        return ChatResponse(
            message=response,
            sources=[doc['title'] for doc in relevant_docs],
            confidence=95.0,  # TODO: Calculate based on LLM confidence
            session_id=session_id,
            llm_used=llm_used
        )

    def _build_system_prompt(
        self,
        relevant_docs: List[Dict],
        user_context: Optional[Dict]
    ) -> str:
        """Build system prompt with knowledge base context."""

        prompt = """You are a specialized AI assistant for Chilean Electronic Invoicing (DTE) operations in Odoo 19.

Your expertise includes:
- DTE generation (types 33, 34, 52, 56, 61)
- SII compliance (Chilean tax authority)
- Certificate and CAF management
- Contingency mode operations
- Error resolution
- Best practices

Always provide:
- Clear, actionable answers
- Step-by-step instructions when appropriate
- References to specific Odoo screens/wizards
- Chilean Spanish terminology (when relevant)

Context:
"""

        if user_context:
            prompt += f"\n- Company: {user_context.get('company_name', 'N/A')}"
            prompt += f"\n- User Role: {user_context.get('user_role', 'N/A')}"

        if relevant_docs:
            prompt += "\n\nRelevant Documentation:\n"
            for doc in relevant_docs:
                prompt += f"\n## {doc['title']}\n{doc['content']}\n"

        return prompt

    async def _call_anthropic(
        self,
        system_prompt: str,
        messages: List[Dict]
    ) -> str:
        """Call Anthropic Claude API."""
        response = await self.anthropic_client.send_message(
            system=system_prompt,
            messages=messages,
            max_tokens=2048
        )
        return response['content']

    async def _call_openai(
        self,
        system_prompt: str,
        messages: List[Dict]
    ) -> str:
        """Call OpenAI GPT-4 API (fallback)."""
        # Prepend system message (OpenAI format)
        openai_messages = [
            {'role': 'system', 'content': system_prompt},
            *messages
        ]

        response = await self.openai_client.send_message(
            messages=openai_messages,
            model="gpt-4-turbo-preview",
            max_tokens=2048
        )
        return response['content']
```

#### 2.2 Context Manager (2 hours)

**New file**: `chat/context_manager.py`

```python
"""
Context Manager - Redis-based session and conversation history
"""

import redis
import json
from typing import List, Dict, Optional
from datetime import timedelta
import structlog

logger = structlog.get_logger()


class ContextManager:
    """
    Manages user sessions and conversation history using Redis.

    Storage format:
    - Key: session:{session_id}:history
    - Value: JSON array of messages [{role, content, timestamp}, ...]
    - TTL: 1 hour (3600 seconds)
    """

    def __init__(self, redis_client: redis.Redis, ttl_seconds: int = 3600):
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds

    def get_conversation_history(self, session_id: str) -> List[Dict]:
        """
        Retrieve conversation history for session.

        Returns:
            List of messages, or empty list if no history
        """
        key = f"session:{session_id}:history"

        try:
            data = self.redis.get(key)
            if data:
                return json.loads(data)
            return []
        except Exception as e:
            logger.error("failed_to_get_history", session_id=session_id, error=str(e))
            return []

    def save_conversation_history(
        self,
        session_id: str,
        messages: List[Dict]
    ):
        """
        Save conversation history to Redis.

        Args:
            session_id: Session identifier
            messages: List of messages to save
        """
        key = f"session:{session_id}:history"

        try:
            self.redis.setex(
                key,
                self.ttl_seconds,
                json.dumps(messages)
            )
            logger.info("conversation_saved",
                        session_id=session_id,
                        message_count=len(messages))
        except Exception as e:
            logger.error("failed_to_save_history",
                        session_id=session_id,
                        error=str(e))

    def clear_session(self, session_id: str):
        """Delete session history."""
        key = f"session:{session_id}:history"
        self.redis.delete(key)
        logger.info("session_cleared", session_id=session_id)

    def get_user_context(self, session_id: str) -> Optional[Dict]:
        """Get user context (company, role, etc.)."""
        key = f"session:{session_id}:context"

        try:
            data = self.redis.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error("failed_to_get_context", error=str(e))
            return None

    def save_user_context(self, session_id: str, context: Dict):
        """Save user context."""
        key = f"session:{session_id}:context"

        try:
            self.redis.setex(
                key,
                self.ttl_seconds,
                json.dumps(context)
            )
        except Exception as e:
            logger.error("failed_to_save_context", error=str(e))
```

#### 2.3 Knowledge Base (3 hours)

**New file**: `chat/knowledge_base.py`

```python
"""
Knowledge Base - DTE operations documentation
"""

from typing import List, Dict, Optional
import structlog

logger = structlog.get_logger()


class KnowledgeBase:
    """
    In-memory knowledge base for DTE operations.

    Future: Load from Markdown files or database.
    """

    def __init__(self):
        self.documents = self._load_documents()

    def _load_documents(self) -> List[Dict]:
        """
        Load DTE documentation.

        Future: Load from /app/knowledge/*.md files
        """
        return [
            {
                'id': 'dte_generation_wizard',
                'title': 'How to Generate DTE Using Wizard',
                'module': 'l10n_cl_dte',
                'tags': ['dte', 'wizard', 'generation', 'factura'],
                'content': '''
To generate a DTE (Electronic Tax Document):

1. Open posted invoice (Accounting → Customers → Invoices)
2. Click "Generate DTE" button (blue, primary)
3. Wizard opens with:
   - Service health status (✅ OK or ⚠️ Unavailable)
   - Certificate (auto-selected)
   - CAF (auto-selected, shows available folios)
   - Environment (Sandbox/Production)
4. Review pre-flight checks:
   - Invoice posted ✅
   - Certificate valid ✅
   - CAF has folios ✅
   - Customer RUT present ✅
5. Click "Generate DTE"
6. Wait for notification (success/error)
7. View DTE info in "DTE Information" tab

Common errors:
- "CAF has no folios": Request new CAF from SII
- "Certificate expired": Upload new certificate
- "Customer RUT missing": Add RUT to customer record
                '''
            },
            {
                'id': 'contingency_mode',
                'title': 'Contingency Mode Operation',
                'module': 'l10n_cl_dte',
                'tags': ['contingency', 'offline', 'sii'],
                'content': '''
Contingency Mode allows DTE generation when SII is unavailable.

When Active:
- DTEs generated offline (no SII send)
- Status: "Contingency"
- Folio assigned (from CAF)
- Track ID: empty
- Stored locally for batch upload later

How to Check:
- Open DTE wizard
- Look for banner: "⚠️ Contingency Mode Active"

Automatic Upload:
- When DTE Service detects SII recovery
- Batch upload of pending DTEs
- Reconcile folios with SII response

Manual Upload (if needed):
- Use legacy "Enviar a SII" button
- Or wait for automatic batch (every 15 min)
                '''
            },
            {
                'id': 'caf_management',
                'title': 'CAF (Folio Authorization) Management',
                'module': 'l10n_cl_dte',
                'tags': ['caf', 'folios', 'sii'],
                'content': '''
CAF (Código Autorización Folios) manages folio ranges.

Requesting CAF from SII:
1. Login to Maullin (sandbox) or Palena (production)
2. Navigate: Facturación Electrónica → Folios
3. Select DTE type (33, 34, 52, 56, 61)
4. Request quantity (e.g., 100 folios)
5. Download CAF XML file

Uploading to Odoo:
1. Go to: Accounting → Chilean DTE → CAF Files
2. Click "Create"
3. Fill:
   - Name: "CAF DTE 33 - 2025"
   - Company: (select)
   - DTE Type: 33
   - CAF File: (upload XML)
4. Save
5. Verify:
   - Status: Active
   - Available Folios: 100
   - Start/End Folio: (range)

When CAF Runs Out:
- Error: "CAF has no available folios"
- Solution: Request new CAF from SII
- Note: Plan ahead (request before exhausting)
                '''
            },
            # Add more documents...
        ]

    def search(
        self,
        query: str,
        top_k: int = 3,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search knowledge base for relevant documents.

        Simple keyword matching for now.
        Future: Use embeddings or FTS.

        Args:
            query: User query
            top_k: Number of results to return
            filters: Optional filters (e.g., {'module': 'l10n_cl_dte'})

        Returns:
            List of relevant documents
        """
        query_lower = query.lower()

        # Filter by module if specified
        candidates = self.documents
        if filters and 'module' in filters:
            candidates = [d for d in candidates if d['module'] == filters['module']]

        # Score documents by keyword matches
        scored = []
        for doc in candidates:
            score = 0

            # Check title
            if any(keyword in doc['title'].lower() for keyword in query_lower.split()):
                score += 10

            # Check tags
            for tag in doc['tags']:
                if tag in query_lower:
                    score += 5

            # Check content
            content_lower = doc['content'].lower()
            for keyword in query_lower.split():
                if keyword in content_lower:
                    score += 1

            if score > 0:
                scored.append((score, doc))

        # Sort by score descending
        scored.sort(reverse=True, key=lambda x: x[0])

        # Return top K
        return [doc for score, doc in scored[:top_k]]
```

---

### Phase 3: API Endpoints (4 hours)

#### 3.1 Chat Endpoints

**Modify**: `main.py`

```python
# ═══════════════════════════════════════════════════════════
# [NEW] CHAT ENDPOINTS
# ═══════════════════════════════════════════════════════════

from chat.engine import ChatEngine, ChatResponse
from chat.context_manager import ContextManager
from chat.knowledge_base import KnowledgeBase
import uuid

# Models
class ChatMessageRequest(BaseModel):
    """Request to send chat message"""
    session_id: Optional[str] = None  # If None, create new session
    message: str
    user_context: Optional[Dict] = None  # company_id, user_role, etc.


class NewSessionRequest(BaseModel):
    """Request to create new chat session"""
    user_context: Optional[Dict] = None


class NewSessionResponse(BaseModel):
    """Response with new session ID"""
    session_id: str
    message: str  # Welcome message


# Global instances (singleton)
_chat_engine = None

def get_chat_engine() -> ChatEngine:
    """Get or create chat engine singleton."""
    global _chat_engine

    if _chat_engine is None:
        # Initialize components
        context_manager = ContextManager(
            redis_client=get_redis_client(),
            ttl_seconds=3600  # 1 hour
        )

        knowledge_base = KnowledgeBase()

        _chat_engine = ChatEngine(
            context_manager=context_manager,
            knowledge_base=knowledge_base,
            anthropic_api_key=settings.anthropic_api_key,
            openai_api_key=settings.openai_api_key,
            default_model=settings.anthropic_model,
            max_context_messages=10
        )

        logger.info("chat_engine_initialized")

    return _chat_engine


@app.post(
    "/api/chat/message",
    response_model=ChatResponse,
    tags=["Chat"],
    summary="Send chat message",
    description="Send message to AI assistant and get response"
)
async def send_chat_message(
    request: ChatMessageRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Send message to AI assistant.

    If session_id is None, creates new session.
    """
    # Verify API key
    await verify_api_key(credentials)

    # Create new session if needed
    session_id = request.session_id or str(uuid.uuid4())

    logger.info("chat_message_request",
                session_id=session_id,
                message_preview=request.message[:50])

    try:
        engine = get_chat_engine()

        response = await engine.send_message(
            session_id=session_id,
            user_message=request.message,
            user_context=request.user_context
        )

        return response

    except Exception as e:
        logger.error("chat_message_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chat failed: {str(e)}"
        )


@app.post(
    "/api/chat/session/new",
    response_model=NewSessionResponse,
    tags=["Chat"],
    summary="Create new chat session"
)
async def create_chat_session(
    request: NewSessionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Create new chat session."""
    await verify_api_key(credentials)

    session_id = str(uuid.uuid4())

    # Save initial context
    if request.user_context:
        context_mgr = ContextManager(get_redis_client())
        context_mgr.save_user_context(session_id, request.user_context)

    logger.info("new_session_created", session_id=session_id)

    return NewSessionResponse(
        session_id=session_id,
        message="¡Hola! Soy tu asistente especializado en facturación electrónica chilena. ¿En qué puedo ayudarte?"
    )


@app.get(
    "/api/chat/session/{session_id}",
    tags=["Chat"],
    summary="Get conversation history"
)
async def get_conversation_history(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get conversation history for session."""
    await verify_api_key(credentials)

    context_mgr = ContextManager(get_redis_client())
    history = context_mgr.get_conversation_history(session_id)

    return {
        "session_id": session_id,
        "message_count": len(history),
        "messages": history
    }


@app.delete(
    "/api/chat/session/{session_id}",
    tags=["Chat"],
    summary="Clear session"
)
async def clear_chat_session(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Clear conversation history for session."""
    await verify_api_key(credentials)

    context_mgr = ContextManager(get_redis_client())
    context_mgr.clear_session(session_id)

    return {"status": "cleared", "session_id": session_id}
```

---

### Phase 4: OpenAI Client Implementation (2 hours)

**New file**: `clients/openai_client.py`

```python
"""
OpenAI GPT-4 Client - Fallback LLM
"""

import openai
from typing import List, Dict, Optional
import structlog

logger = structlog.get_logger()


class OpenAIClient:
    """
    Client for OpenAI GPT-4 API.

    Used as fallback when Anthropic Claude fails.
    """

    def __init__(self, api_key: str):
        self.client = openai.AsyncOpenAI(api_key=api_key)

    async def send_message(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4-turbo-preview",
        max_tokens: int = 2048,
        temperature: float = 0.7
    ) -> Dict:
        """
        Send message to OpenAI API.

        Args:
            messages: List of messages [{role, content}, ...]
            model: Model ID
            max_tokens: Max tokens in response
            temperature: Randomness (0-2)

        Returns:
            Dict with 'content' and metadata
        """
        try:
            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature
            )

            return {
                'content': response.choices[0].message.content,
                'model': model,
                'usage': {
                    'input_tokens': response.usage.prompt_tokens,
                    'output_tokens': response.usage.completion_tokens
                }
            }

        except Exception as e:
            logger.error("openai_api_error", error=str(e))
            raise


def get_openai_client(api_key: str) -> OpenAIClient:
    """Factory function for OpenAI client."""
    return OpenAIClient(api_key)
```

---

### Phase 5: Configuration Updates (1 hour)

#### 5.1 Update `requirements.txt`

```txt
# AI Support Assistant - Python Dependencies
# Python 3.11+

# ═══════════════════════════════════════════════════════════
# WEB FRAMEWORK
# ═══════════════════════════════════════════════════════════
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
pydantic-settings==2.1.0

# ═══════════════════════════════════════════════════════════
# AI / LLM (API-Only)
# ═══════════════════════════════════════════════════════════
anthropic==0.7.8          # Primary LLM
openai==1.6.1             # Fallback LLM

# ═══════════════════════════════════════════════════════════
# XML PARSING (for DTE)
# ═══════════════════════════════════════════════════════════
lxml>=4.9.0

# ═══════════════════════════════════════════════════════════
# HTTP Y COMUNICACIÓN
# ═══════════════════════════════════════════════════════════
httpx>=0.25.2
requests>=2.31.0

# ═══════════════════════════════════════════════════════════
# CACHE Y SESSION STORAGE
# ═══════════════════════════════════════════════════════════
redis>=5.0.1

# ═══════════════════════════════════════════════════════════
# UTILIDADES
# ═══════════════════════════════════════════════════════════
python-dotenv>=1.0.0
python-dateutil>=2.8.2
structlog>=23.2.0

# ═══════════════════════════════════════════════════════════
# SII MONITORING (Mantener)
# ═══════════════════════════════════════════════════════════
beautifulsoup4>=4.12.0    # Parse HTML del SII
html5lib>=1.1             # HTML parser robusto
slack-sdk>=3.23.0         # Notificaciones Slack
slowapi>=0.1.9            # Rate limiting API
validators>=0.22.0        # Validación URLs/emails

# ═══════════════════════════════════════════════════════════
# TESTING
# ═══════════════════════════════════════════════════════════
pytest>=7.4.3
pytest-asyncio>=0.21.1
pytest-cov>=4.1.0
responses>=0.20.0

# ═══════════════════════════════════════════════════════════
# REMOVED (Heavy/Unused)
# ═══════════════════════════════════════════════════════════
# ollama==0.1.6                    # Local LLM - not used
# sentence-transformers==2.2.2     # Heavy (1.2GB) - not needed
# chromadb==0.4.22                 # Vector DB - not needed
# numpy>=1.24.0                    # Only for sentence-transformers
# pypdf, pdfplumber, python-docx   # Document processing - not used
# pytesseract, Pillow              # OCR/Images - not used
```

#### 5.2 Update `config.py`

```python
class Settings(BaseSettings):
    """Configuración del AI Support Assistant"""

    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN GENERAL
    # ═══════════════════════════════════════════════════════════

    app_name: str = "AI Support Assistant - Chilean DTE"
    app_version: str = "2.0.0"  # Major version bump
    debug: bool = False

    # ═══════════════════════════════════════════════════════════
    # SEGURIDAD
    # ═══════════════════════════════════════════════════════════

    api_key: str = "default_ai_api_key"  # Cambiar en producción
    allowed_origins: list[str] = [
        "http://odoo:8069",
        "http://dte-service:8001",
        "http://localhost:8169"  # Para testing local
    ]

    # ═══════════════════════════════════════════════════════════
    # ANTHROPIC API (Primary LLM)
    # ═══════════════════════════════════════════════════════════

    anthropic_api_key: str
    anthropic_model: str = "claude-3-5-sonnet-20241022"
    anthropic_max_tokens: int = 4096

    # ═══════════════════════════════════════════════════════════
    # OPENAI API (Fallback LLM)
    # ═══════════════════════════════════════════════════════════

    openai_api_key: str = ""  # Optional
    openai_model: str = "gpt-4-turbo-preview"
    openai_max_tokens: int = 4096

    # ═══════════════════════════════════════════════════════════
    # CHAT ENGINE
    # ═══════════════════════════════════════════════════════════

    chat_session_ttl: int = 3600  # 1 hour
    chat_max_context_messages: int = 10  # Last N messages
    chat_default_temperature: float = 0.7  # Creativity (0-2)

    # ═══════════════════════════════════════════════════════════
    # REDIS (Session + Cache)
    # ═══════════════════════════════════════════════════════════

    redis_url: str = "redis://redis:6379/1"
    redis_cache_ttl: int = 3600  # 1 hora

    # ═══════════════════════════════════════════════════════════
    # KNOWLEDGE BASE
    # ═══════════════════════════════════════════════════════════

    knowledge_base_path: str = "/app/knowledge"  # Markdown docs
    knowledge_base_modules: list[str] = ["l10n_cl_dte"]  # Supported modules

    # ═══════════════════════════════════════════════════════════
    # LOGGING
    # ═══════════════════════════════════════════════════════════

    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
```

---

## Cost Analysis

### Before (As-Is)

**Infrastructure**:
- Docker Image: ~8 GB
- Memory: 2-4 GB
- Startup Time: 30-60 seconds
- GPU: Not used (but torch requires CUDA support)

**Maintenance**:
- Model updates (sentence-transformers)
- GPU optimization (if scaling)
- Vector DB management (ChromaDB)

### After (To-Be)

**Infrastructure**:
- Docker Image: ~500 MB (**-94%**)
- Memory: < 512 MB (**-88%**)
- Startup Time: < 5 seconds (**-92%**)
- GPU: Not needed

**API Costs** (per 1,000 support conversations):

**Anthropic Claude**:
- Avg conversation: 10 turns
- Avg input: 1,500 tokens/turn × 10 = 15,000 tokens
- Avg output: 500 tokens/turn × 10 = 5,000 tokens
- Cost: (15k × $3/MTok) + (5k × $15/MTok) = $0.045 + $0.075 = **$0.12 per conversation**
- 1,000 conversations: **$120/month**

**OpenAI GPT-4** (fallback, 10% usage):
- Same tokens
- Cost: (15k × $10/MTok) + (5k × $30/MTok) = $0.15 + $0.15 = **$0.30 per conversation**
- 100 conversations: **$30/month**

**Total**: **$150/month** for 1,000 support conversations

**ROI**:
- Human agent: $50/conversation × 1,000 = $50,000/month
- AI assistant: $150/month
- **Savings: $49,850/month (99.7%)**

---

## Migration Path

### Week 1: Cleanup & Core (12 hours)

**Day 1-2**: Cleanup (4 hours)
- ✅ Remove Ollama integration
- ✅ Remove sentence-transformers
- ✅ Remove ChromaDB
- ✅ Update requirements.txt
- ✅ Update config.py
- ✅ Rebuild Docker image
- ✅ Test startup time (target: < 5s)

**Day 3-4**: Chat Engine (8 hours)
- ✅ Implement ChatEngine class
- ✅ Implement ContextManager (Redis)
- ✅ Implement KnowledgeBase (in-memory)
- ✅ Write unit tests
- ✅ Test multi-turn conversations

### Week 2: API & Integration (10 hours)

**Day 1-2**: OpenAI Client (4 hours)
- ✅ Implement OpenAIClient
- ✅ Test fallback logic
- ✅ Add error handling
- ✅ Write unit tests

**Day 3-4**: API Endpoints (6 hours)
- ✅ Implement /api/chat/message
- ✅ Implement /api/chat/session/new
- ✅ Implement /api/chat/session/{id}
- ✅ Implement /api/chat/session/{id} DELETE
- ✅ Update health endpoint
- ✅ Write integration tests

### Week 3: Knowledge Base & Testing (8 hours)

**Day 1-2**: Knowledge Base Expansion (4 hours)
- ✅ Add 20+ DTE documentation articles
- ✅ Add common error resolutions
- ✅ Add troubleshooting guides
- ✅ Add SII compliance docs

**Day 3-4**: Testing & Refinement (4 hours)
- ✅ End-to-end testing
- ✅ Load testing (100 concurrent users)
- ✅ Cost monitoring
- ✅ Performance optimization

---

## Success Criteria

### Functional:
- ✅ Multi-turn conversations work
- ✅ Context preserved across turns (last 10 messages)
- ✅ Knowledge base injection works
- ✅ Anthropic → OpenAI fallback works
- ✅ Session management (create/get/delete)
- ✅ User context saved (company, role)

### Non-Functional:
- ✅ Startup time < 5 seconds
- ✅ Memory usage < 512 MB
- ✅ Docker image < 500 MB
- ✅ Response time < 3 seconds (p95)
- ✅ Cost < $0.50 per conversation
- ✅ Uptime > 99.9%

### Quality:
- ✅ 80% code coverage (tests)
- ✅ Professional logging (structlog)
- ✅ Error handling (graceful degradation)
- ✅ Documentation (API, knowledge base)

---

## Risks & Mitigation

### Risk 1: API Rate Limits

**Anthropic**: 4000 RPM, 400k TPM
**OpenAI**: 500 RPM, 150k TPM

**Mitigation**:
- Implement rate limiting (slowapi)
- Queue requests if needed
- Cache common responses (Redis)
- Fallback between providers

### Risk 2: API Costs Exceed Budget

**Scenario**: 10,000 conversations/month = $1,500/month

**Mitigation**:
- Set monthly budget alerts ($500, $1000, $1500)
- Implement cost tracking per session
- Optimize prompts (shorter system prompts)
- Use cheaper models for simple queries (Claude Haiku)

### Risk 3: Knowledge Base Outdated

**Problem**: Documentation becomes stale

**Mitigation**:
- Version control knowledge base (Git)
- Monthly review process
- User feedback on responses
- Auto-sync from official docs (future)

---

## Future Enhancements (Phase 2)

### 1. Streaming Responses
- WebSocket support
- Real-time token streaming
- Better UX (progressive reveal)

### 2. Multi-Module Support
- Inventory module docs
- Accounting module docs
- Payroll module docs
- Dynamic module loading

### 3. Advanced Knowledge Base
- Load from Markdown files
- Vector search (if justified)
- External docs integration (official Odoo docs)

### 4. Analytics
- Conversation metrics (duration, satisfaction)
- Common questions analysis
- Knowledge gap detection

### 5. Proactive Assistance
- Error prediction (before DTE generation)
- Workflow suggestions
- Best practice recommendations

---

## Conclusion

**Recommendation**: ✅ **PROCEED with transformation**

**Justification**:
1. **Simplified stack**: -94% image size, -88% memory, -92% startup time
2. **Better UX**: Conversational support vs one-shot validation
3. **Cost-effective**: $150/month vs $50k/month (human agents)
4. **Extensible**: Easy to add new modules
5. **Maintainable**: No local models, no GPU, no ML ops

**Timeline**: 3 weeks (30 hours total)

**Next Step**: Start with Phase 1 (Cleanup) - 4 hours

---

**Document Version**: 1.0
**Created**: 2025-10-22
**Status**: Ready for implementation
