# -*- coding: utf-8 -*-
"""
AI Microservice - Main Application
FastAPI service para inteligencia artificial aplicada a DTEs
"""

from fastapi import FastAPI, Depends, HTTPException, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import structlog
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings

# ═══════════════════════════════════════════════════════════
# ROUTER IMPORTS
# ═══════════════════════════════════════════════════════════
from routes.analytics import router as analytics_router

# ═══════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════

logger = structlog.get_logger()

# ═══════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Microservicio de IA para validación y análisis de DTEs",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# ═══════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ═══════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════
# ROUTER REGISTRATION
# ═══════════════════════════════════════════════════════════
app.include_router(analytics_router)

# ═══════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════

security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verifica API key en header Authorization"""
    if credentials.credentials != settings.api_key:
        logger.warning("invalid_api_key_attempt")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return credentials

# ═══════════════════════════════════════════════════════════
# MODELS (PYDANTIC)
# ═══════════════════════════════════════════════════════════

class DTEValidationRequest(BaseModel):
    """Request para validación de DTE"""
    dte_data: Dict[str, Any]
    company_id: int
    history: Optional[List[Dict]] = []

class DTEValidationResponse(BaseModel):
    """Response de validación"""
    confidence: float  # 0-100
    warnings: List[str]
    errors: List[str]
    recommendation: str  # 'send' o 'review'

class ReconciliationRequest(BaseModel):
    """Request para reconciliación"""
    dte_xml: str
    pending_pos: List[Dict[str, Any]]

class ReconciliationResponse(BaseModel):
    """Response de reconciliación"""
    po_id: Optional[int]
    confidence: float  # 0-100
    line_matches: List[Dict[str, Any]]

# ═══════════════════════════════════════════════════════════
# GLOBAL INSTANCES (Singleton Pattern)
# ═══════════════════════════════════════════════════════════

# Removed: InvoiceMatcher (sentence-transformers) - not used
# Future: Reimplementar reconciliation con Claude API si se necesita

# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "anthropic_configured": bool(settings.anthropic_api_key),
        "openai_configured": bool(settings.openai_api_key)
    }

@app.post("/api/ai/validate",
          response_model=DTEValidationResponse,
          dependencies=[Depends(verify_api_key)])
@limiter.limit("20/minute")  # Max 20 validaciones por minuto por IP
async def validate_dte(request: DTEValidationRequest, http_request: Request):
    """
    Pre-validación inteligente de un DTE antes de envío al SII.
    
    Usa Claude de Anthropic para detectar errores comparando con historial.
    """
    logger.info("ai_validation_started", company_id=request.company_id)
    
    try:
        # Usar cliente Anthropic REAL
        from clients.anthropic_client import get_anthropic_client
        
        client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )
        
        # Validar con Claude
        result = client.validate_dte(request.dte_data, request.history)
        
        return DTEValidationResponse(
            confidence=result.get('confidence', 95.0),
            warnings=result.get('warnings', []),
            errors=result.get('errors', []),
            recommendation=result.get('recommendation', 'send')
        )
        
    except Exception as e:
        logger.error("ai_validation_error", error=str(e))
        
        # Retornar resultado neutro en caso de error (no bloquear flujo)
        return DTEValidationResponse(
            confidence=50.0,
            warnings=[f"AI Service error: {str(e)}"],
            errors=[],
            recommendation="send"
        )

@app.post("/api/ai/reconcile",
          response_model=ReconciliationResponse,
          dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")  # Max 30 reconciliaciones por minuto
async def reconcile_invoice(request: ReconciliationRequest, http_request: Request):
    """
    Reconcilia una factura recibida con órdenes de compra pendientes.

    DEPRECATED: Endpoint mantenido para compatibilidad.
    TODO: Reimplementar con Claude API si se necesita.
    """
    logger.warning("reconcile_endpoint_deprecated",
                   message="Endpoint deprecated - sentence-transformers removed")

    # Retornar respuesta vacía (endpoint no funcional)
    return ReconciliationResponse(
        po_id=None,
        confidence=0.0,
        line_matches=[]
    )

# ═══════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# [NUEVO] SII MONITORING ENDPOINTS - Added 2025-10-22
# ═══════════════════════════════════════════════════════════

# Modelos Pydantic
class SIIMonitorRequest(BaseModel):
    """Request para trigger de monitoreo SII"""
    force: bool = False  # Si True, ignora cache


class SIIMonitorResponse(BaseModel):
    """Response de monitoreo SII"""
    status: str
    execution_time: Optional[str]
    urls_scraped: int
# Lazy initialization del orchestrator
_orchestrator = None

def get_orchestrator():
    """Obtiene instancia del orchestrator (singleton)"""
    global _orchestrator
    
    if _orchestrator is None:
        # Importar aquí para evitar import circular
        from sii_monitor.orchestrator import MonitoringOrchestrator
        from clients.anthropic_client import get_anthropic_client
        import redis
        import os
        
        # Inicializar clientes
        anthropic_client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )
        
        redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'redis'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            db=int(os.getenv('REDIS_DB', 0)),
            decode_responses=False
        )
        
        slack_token = os.getenv('SLACK_TOKEN')
        
        _orchestrator = MonitoringOrchestrator(
            anthropic_client=anthropic_client,
            redis_client=redis_client,
            slack_token=slack_token
        )
    
    return _orchestrator


@app.post(
    "/api/ai/sii/monitor",
    response_model=SIIMonitorResponse,
    tags=["SII Monitoring"],
    summary="Trigger monitoreo SII",
    description="Ejecuta ciclo completo de monitoreo de noticias del SII"
)
@limiter.limit("5/minute")  # Max 5 triggers de monitoreo por minuto
async def trigger_sii_monitoring(
    request: SIIMonitorRequest,
    http_request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Trigger manual de monitoreo SII.
    
    Ejecuta:
    1. Scraping de URLs SII
    2. Detección de cambios
    3. Análisis con Claude API
    4. Clasificación de impacto
    5. Notificaciones Slack
    
    Args:
        request: Parámetros del monitoreo
        credentials: Bearer token
    
    Returns:
        Resultados de la ejecución
    """
    # Verificar API key
    if credentials.credentials != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    logger.info("sii_monitoring_triggered", force=request.force)
    
    try:
        orchestrator = get_orchestrator()
        results = orchestrator.execute_monitoring(force=request.force)
        
        return SIIMonitorResponse(**results)
        
    except Exception as e:
        logger.error("sii_monitoring_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Monitoring failed: {str(e)}"
        )


@app.get(
    "/api/ai/sii/status",
    tags=["SII Monitoring"],
    summary="Estado del monitoreo",
    description="Obtiene estado actual del sistema de monitoreo"
)
async def get_sii_monitoring_status(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Obtiene estado del sistema de monitoreo SII.
    
    Returns:
        Dict con estado del sistema
    """
    if credentials.credentials != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    try:
        orchestrator = get_orchestrator()
        
        # TODO: Agregar métricas reales desde Redis
        status_data = {
            "status": "operational",
            "orchestrator_initialized": orchestrator is not None,
            "last_execution": None,  # TODO: Obtener desde Redis
            "news_count_last_24h": 0,  # TODO: Obtener desde Redis
        }
        
        return status_data
        
    except Exception as e:
        logger.error("status_check_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.on_event("startup")
async def startup_event():
    """Inicialización al arrancar el servicio"""
    logger.info("ai_service_starting",
                version=settings.app_version,
                anthropic_model=settings.anthropic_model,
                openai_configured=bool(settings.openai_api_key))

@app.on_event("shutdown")
async def shutdown_event():
    """Limpieza al detener el servicio"""
    logger.info("ai_service_stopping")

# ═══════════════════════════════════════════════════════════
# [NEW] CHAT SUPPORT ENDPOINTS - Added 2025-10-22
# ═══════════════════════════════════════════════════════════

from chat.engine import ChatEngine, ChatResponse as EngineChatResponse
from chat.context_manager import ContextManager
from chat.knowledge_base import KnowledgeBase
from utils.redis_helper import get_redis_client
import uuid


# Pydantic Models for Chat API
class ChatMessageRequest(BaseModel):
    """Request to send chat message"""
    session_id: Optional[str] = None  # If None, creates new session
    message: str
    user_context: Optional[Dict[str, Any]] = None


class NewSessionRequest(BaseModel):
    """Request to create new chat session"""
    user_context: Optional[Dict[str, Any]] = None


class NewSessionResponse(BaseModel):
    """Response with new session ID"""
    session_id: str
    welcome_message: str


# Global Chat Engine (singleton)
_chat_engine: Optional[ChatEngine] = None


def get_chat_engine() -> ChatEngine:
    """Get or create chat engine singleton."""
    global _chat_engine

    if _chat_engine is None:
        logger.info("chat_engine_initializing")

        # Initialize components
        redis_client = get_redis_client()

        context_manager = ContextManager(
            redis_client=redis_client,
            ttl_seconds=settings.chat_session_ttl
        )

        knowledge_base = KnowledgeBase()

        # Get LLM clients
        from clients.anthropic_client import get_anthropic_client
        from clients.openai_client import get_openai_client

        anthropic_client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )

        openai_client = get_openai_client(settings.openai_api_key) if settings.openai_api_key else None

        # Create chat engine
        _chat_engine = ChatEngine(
            context_manager=context_manager,
            knowledge_base=knowledge_base,
            anthropic_client=anthropic_client,
            openai_client=openai_client,
            max_context_messages=settings.chat_max_context_messages,
            default_temperature=settings.chat_default_temperature
        )

        logger.info("chat_engine_initialized",
                   has_openai_fallback=openai_client is not None)

    return _chat_engine


@app.post(
    "/api/chat/message",
    response_model=EngineChatResponse,
    tags=["Chat Support"],
    summary="Send chat message",
    description="Send message to AI support assistant and get response with context awareness"
)
@limiter.limit("30/minute")  # Max 30 mensajes de chat por minuto
async def send_chat_message(
    request: ChatMessageRequest,
    http_request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Send message to AI support assistant.

    If session_id is None, creates new session automatically.
    Context is preserved across messages in same session.

    Example:
    ```json
    {
      "session_id": "uuid-here",
      "message": "¿Cómo genero un DTE 33?",
      "user_context": {
        "company_name": "Mi Empresa SpA",
        "company_rut": "12345678-9",
        "user_role": "Contador",
        "environment": "Sandbox"
      }
    }
    ```
    """
    # Verify API key
    await verify_api_key(credentials)

    # Create session if needed
    session_id = request.session_id or str(uuid.uuid4())

    logger.info("chat_message_request",
                session_id=session_id,
                message_preview=request.message[:100],
                has_user_context=request.user_context is not None)

    try:
        engine = get_chat_engine()

        response = await engine.send_message(
            session_id=session_id,
            user_message=request.message,
            user_context=request.user_context
        )

        return response

    except Exception as e:
        logger.error("chat_message_error",
                    session_id=session_id,
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chat failed: {str(e)}"
        )


@app.post(
    "/api/chat/session/new",
    response_model=NewSessionResponse,
    tags=["Chat Support"],
    summary="Create new chat session",
    description="Start new conversation with AI assistant"
)
async def create_chat_session(
    request: NewSessionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Create new chat session.

    Returns session_id to use in subsequent /api/chat/message calls.
    Optionally saves user context for the session.
    """
    await verify_api_key(credentials)

    session_id = str(uuid.uuid4())

    # Save user context if provided
    if request.user_context:
        engine = get_chat_engine()
        engine.context_manager.save_user_context(session_id, request.user_context)

    logger.info("new_chat_session_created",
                session_id=session_id,
                has_user_context=request.user_context is not None)

    # Welcome message (español chileno)
    welcome = "¡Hola! Soy tu asistente especializado en facturación electrónica chilena. ¿En qué puedo ayudarte hoy?"

    return NewSessionResponse(
        session_id=session_id,
        welcome_message=welcome
    )


@app.get(
    "/api/chat/session/{session_id}",
    tags=["Chat Support"],
    summary="Get conversation history",
    description="Retrieve conversation history for a session"
)
async def get_conversation_history(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get conversation history for session.

    Returns all messages in the session (up to max_context_messages).
    """
    await verify_api_key(credentials)

    try:
        engine = get_chat_engine()
        history = engine.context_manager.get_conversation_history(session_id)
        stats = engine.get_conversation_stats(session_id)

        return {
            "session_id": session_id,
            "message_count": len(history),
            "messages": history,
            "stats": stats
        }

    except Exception as e:
        logger.error("get_history_error",
                    session_id=session_id,
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get history: {str(e)}"
        )


@app.delete(
    "/api/chat/session/{session_id}",
    tags=["Chat Support"],
    summary="Clear session",
    description="Delete conversation history and context for a session"
)
async def clear_chat_session(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Clear session (delete history and context).

    Use this to start fresh or for privacy/cleanup.
    """
    await verify_api_key(credentials)

    try:
        engine = get_chat_engine()
        engine.context_manager.clear_session(session_id)

        logger.info("chat_session_cleared", session_id=session_id)

        return {
            "status": "cleared",
            "session_id": session_id,
            "message": "Session history and context deleted"
        }

    except Exception as e:
        logger.error("clear_session_error",
                    session_id=session_id,
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear session: {str(e)}"
        )


@app.get(
    "/api/chat/knowledge/search",
    tags=["Chat Support"],
    summary="Search knowledge base",
    description="Search DTE documentation knowledge base"
)
async def search_knowledge_base(
    query: str,
    top_k: int = 3,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Search knowledge base directly (without chat context).

    Useful for testing knowledge base coverage.
    """
    await verify_api_key(credentials)

    try:
        engine = get_chat_engine()
        results = engine.knowledge_base.search(query, top_k=top_k)

        return {
            "query": query,
            "results_found": len(results),
            "results": results
        }

    except Exception as e:
        logger.error("knowledge_search_error",
                    query=query,
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8002,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )

