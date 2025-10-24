# -*- coding: utf-8 -*-
"""
AI Microservice - Main Application
FastAPI service para inteligencia artificial aplicada a DTEs
"""

from fastapi import FastAPI, Depends, HTTPException, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
import re
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
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════

from middleware.observability import ObservabilityMiddleware, ErrorTrackingMiddleware

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Observability Middleware
app.add_middleware(ObservabilityMiddleware)
app.add_middleware(ErrorTrackingMiddleware)

# ═══════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ═══════════════════════════════════════════════════════════
# ROUTER REGISTRATION
# ═══════════════════════════════════════════════════════════

# Apply rate limiting to analytics router endpoints
@app.middleware("http")
async def rate_limit_analytics_middleware(request: Request, call_next):
    """Apply rate limiting to analytics endpoints."""
    if request.url.path.startswith("/api/ai/analytics/"):
        # Rate limit applied: 30 requests per minute
        await limiter.limit("30/minute")(request)
    response = await call_next(request)
    return response

app.include_router(analytics_router)

# ═══════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════

security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Verifica API key en header Authorization.

    Uses secrets.compare_digest() to prevent timing attacks.
    """
    import secrets

    # Timing-attack resistant comparison
    if not secrets.compare_digest(
        credentials.credentials.encode('utf-8'),
        settings.api_key.encode('utf-8')
    ):
        logger.warning("invalid_api_key_attempt",
                      remote_addr=get_remote_address)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return credentials

# ═══════════════════════════════════════════════════════════
# MODELS (PYDANTIC)
# ═══════════════════════════════════════════════════════════

class DTEValidationRequest(BaseModel):
    """Request para validación de DTE con validaciones robustas"""
    dte_data: Dict[str, Any] = Field(..., description="Datos del DTE a validar")
    company_id: int = Field(..., gt=0, description="ID de la compañía (debe ser positivo)")
    history: Optional[List[Dict]] = Field(default=[], max_items=100, description="Historial de validaciones (máximo 100)")
    
    @validator('dte_data')
    def validate_dte_data(cls, v):
        """Validar estructura mínima del DTE."""
        if not isinstance(v, dict) or not v:
            raise ValueError("dte_data debe ser un diccionario no vacío")
        
        # Validar tipo_dte presente
        if 'tipo_dte' not in v:
            raise ValueError("Campo 'tipo_dte' es requerido en dte_data")
        
        # Validar tipo_dte válido
        valid_types = ['33', '34', '52', '56', '61']
        if str(v.get('tipo_dte')) not in valid_types:
            raise ValueError(f"tipo_dte debe ser uno de: {', '.join(valid_types)}")
        
        return v
    
    @validator('history')
    def validate_history_size(cls, v):
        """Limitar tamaño total del history."""
        if v:
            total_size = len(str(v))
            if total_size > 100_000:  # 100KB max
                raise ValueError(f"History demasiado grande: {total_size} bytes (máximo 100KB)")
        return v

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

class POMatchRequest(BaseModel):
    """Request para matching de PO con validaciones robustas"""
    invoice_data: Dict[str, Any] = Field(..., description="Datos de la factura")
    pending_pos: List[Dict[str, Any]] = Field(..., max_items=200, description="Órdenes de compra pendientes (máximo 200)")
    
    @validator('pending_pos')
    def validate_pending_pos(cls, v):
        """Validar que la lista no esté vacía"""
        if not v:
            raise ValueError("pending_pos no puede estar vacío")
        return v

class POMatchResponse(BaseModel):
    """Response con resultado matching PO"""
    matched_po_id: Optional[int]
    confidence: float
    line_matches: List[Dict[str, Any]]
    reasoning: str

class PayrollValidationRequest(BaseModel):
    """Request para validación de liquidación con validaciones robustas"""
    employee_id: int = Field(..., gt=0, description="ID del empleado")
    period: str = Field(..., pattern=r'^\d{4}-\d{2}$', description="Período YYYY-MM")
    wage: float = Field(..., gt=0, description="Sueldo base (debe ser > 0)")
    lines: List[Dict[str, Any]] = Field(..., min_items=1, max_items=100, description="Líneas liquidación (1-100)")
    
    @validator('lines')
    def validate_lines(cls, v):
        """Validar estructura de líneas"""
        for i, line in enumerate(v, 1):
            if 'code' not in line:
                raise ValueError(f"Línea {i} sin campo 'code'")
            if 'amount' not in line:
                raise ValueError(f"Línea {i} sin campo 'amount'")
            if not isinstance(line['amount'], (int, float)):
                raise ValueError(f"Línea {i}: 'amount' debe ser numérico")
        return v

class PayrollValidationResponse(BaseModel):
    """Response de validación de liquidación"""
    success: bool
    confidence: float = Field(..., ge=0, le=100)
    errors: List[str]
    warnings: List[str]
    recommendation: str  # approve | review | reject

class PreviredIndicatorsResponse(BaseModel):
    """Response con indicadores Previred"""
    success: bool
    indicators: Dict[str, float]
    metadata: Dict[str, Any]

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
    """Health check endpoint with real dependency verification"""
    from datetime import datetime
    from fastapi.responses import JSONResponse
    
    health = {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {}
    }
    
    # 1. Check Redis connectivity
    try:
        from utils.redis_helper import get_redis_client
        redis_client = get_redis_client()
        redis_client.ping()
        health["dependencies"]["redis"] = {
            "status": "up",
            "message": "Connection successful"
        }
    except Exception as e:
        health["dependencies"]["redis"] = {
            "status": "down",
            "error": str(e)[:200]
        }
        health["status"] = "degraded"
        logger.error("health_check_redis_failed", error=str(e))
    
    # 2. Check Anthropic API configuration (not calling API to avoid costs)
    health["dependencies"]["anthropic"] = {
        "status": "configured" if settings.anthropic_api_key else "not_configured",
        "model": settings.anthropic_model if settings.anthropic_api_key else None
    }
    
    # OpenAI eliminado - Solo Anthropic
    
    # Return 503 if any critical dependency is down
    if health["status"] == "degraded":
        return JSONResponse(status_code=503, content=health)
    
    return health


@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint.

    Exposes metrics in Prometheus text format:
    - HTTP request metrics (count, latency, errors)
    - Claude API metrics (tokens, cost, rate limits)
    - Circuit breaker metrics
    - Cache metrics
    - Business metrics (DTEs, projects, payroll)

    Note: This endpoint does NOT require authentication
    to allow Prometheus scraper access.
    """
    from fastapi.responses import Response
    from utils.metrics import get_metrics, get_content_type

    try:
        metrics_data = get_metrics()
        return Response(
            content=metrics_data,
            media_type=get_content_type()
        )
    except Exception as e:
        logger.error("metrics_endpoint_error", error=str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Error generating metrics: {str(e)}"
        )


@app.get("/metrics/costs")
async def metrics_costs(
    period: str = "today",
    _: None = Depends(verify_api_key)
):
    """
    Cost metrics endpoint (requires authentication).

    Returns detailed cost breakdown by operation and model.

    Query params:
        period: "today", "yesterday", "this_month", "all_time"
    """
    from utils.cost_tracker import get_cost_tracker

    try:
        tracker = get_cost_tracker()
        stats = tracker.get_stats(period=period)

        return {
            "period": period,
            "summary": {
                "total_calls": stats.get("total_calls", 0),
                "total_tokens": stats.get("total_tokens", 0),
                "total_input_tokens": stats.get("total_input_tokens", 0),
                "total_output_tokens": stats.get("total_output_tokens", 0),
                "total_cost_usd": stats.get("total_cost_usd", 0.0),
                "avg_tokens_per_call": stats.get("avg_tokens_per_call", 0.0),
                "avg_cost_per_call": stats.get("avg_cost_per_call", 0.0)
            },
            "by_operation": stats.get("by_operation", {}),
            "by_model": stats.get("by_model", {})
        }

    except Exception as e:
        logger.error("cost_metrics_error", error=str(e), period=period)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving cost metrics: {str(e)}"
        )


@app.post("/api/ai/validate",
          response_model=DTEValidationResponse,
          dependencies=[Depends(verify_api_key)])
@limiter.limit("20/minute")  # Max 20 validaciones por minuto por IP
async def validate_dte(data: DTEValidationRequest, request: Request):
    """
    Pre-validación inteligente de un DTE antes de envío al SII.
    
    Usa Claude de Anthropic para detectar errores comparando con historial.
    """
    logger.info("ai_validation_started", company_id=data.company_id)
    
    try:
        # Usar cliente Anthropic REAL
        from clients.anthropic_client import get_anthropic_client
        
        client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )

        # Validar con Claude (ASYNC)
        result = await client.validate_dte(data.dte_data, data.history)
        
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
async def reconcile_invoice(data: ReconciliationRequest, request: Request):
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

@app.post(
    "/api/ai/reception/match_po",
    response_model=POMatchResponse,
    tags=["DTE Reception"],
    summary="Match DTE recibido con Purchase Orders",
    description="Matching inteligente de DTEs recibidos con POs pendientes usando Claude AI",
    dependencies=[Depends(verify_api_key)]
)
@limiter.limit("30/minute")  # Max 30 matchings por minuto
async def match_purchase_order(
    data: POMatchRequest,
    request: Request
):
    """
    Match DTE recibido con Purchase Orders usando Claude AI.
    
    Analiza DTE recibido y busca PO matching considerando:
    - RUT emisor (proveedor)
    - Monto total
    - Líneas de productos/servicios
    - Fecha de emisión
    - Historial de compras al proveedor
    
    Args:
        request: Datos del DTE recibido
    
    Returns:
        POMatchResponse con PO matched (si existe) y nivel de confianza
    
    Example:
        ```json
        {
          "dte_data": {...},
          "company_id": 1,
          "emisor_rut": "12345678-9",
          "monto_total": 1190000,
          "fecha_emision": "2025-10-23"
        }
        ```
    """
    logger.info("po_matching_started",
               company_id=data.company_id,
               emisor_rut=data.emisor_rut,
               monto_total=data.monto_total)
    
    try:
        # TODO FASE 2: Implementar lógica completa con Claude
        # Requiere:
        # 1. Consultar POs pendientes del proveedor (API Odoo)
        # 2. Comparar líneas DTE vs PO con Claude
        # 3. Calcular confidence score
        # 4. Retornar mejor match
        
        # Por ahora: graceful degradation (no bloquea flujo)
        logger.info("po_matching_completed",
                   matched=False,
                   reason="Matching automático pendiente de implementación completa")
        
        return POMatchResponse(
            matched_po_id=None,
            confidence=0.0,
            line_matches=[],
            reasoning="Matching automático de Purchase Orders en desarrollo. Por favor, realizar matching manual desde Odoo."
        )
        
    except Exception as e:
        logger.error("po_matching_error",
                    company_id=data.company_id,
                    emisor_rut=data.emisor_rut,
                    error=str(e),
                    exc_info=True)
        
        # No fallar - retornar sin match (graceful degradation)
        return POMatchResponse(
            matched_po_id=None,
            confidence=0.0,
            line_matches=[],
            reasoning=f"Error en matching: {str(e)[:100]}. Realizar matching manual."
        )

# ═══════════════════════════════════════════════════════════
# [NUEVO] PAYROLL ENDPOINTS - Added 2025-10-23
# ═══════════════════════════════════════════════════════════

@app.post(
    "/api/payroll/validate",
    response_model=PayrollValidationResponse,
    tags=["Payroll"],
    summary="Validar liquidación con IA",
    description="Valida liquidación de sueldo usando Claude API para detectar errores",
    dependencies=[Depends(verify_api_key)]
)
@limiter.limit("20/minute")  # Max 20 validaciones por minuto
async def validate_payslip(
    data: PayrollValidationRequest,
    request: Request
):
    """
    Validar liquidación con IA.
    
    Analiza liquidación y detecta:
    - Errores en cálculo AFP, Salud, impuestos
    - Incoherencias en haberes/descuentos
    - Líquido negativo
    - Tasas incorrectas vs indicadores Previred
    
    Args:
        request: Datos de la liquidación
    
    Returns:
        Resultado con errores, warnings, confianza y recomendación
    
    Example:
        ```json
        {
          "employee_id": 1,
          "period": "2025-10",
          "wage": 1500000,
          "lines": [
            {"code": "SUELDO", "name": "Sueldo Base", "amount": 1500000},
            {"code": "AFP", "name": "AFP", "amount": -157350}
          ]
        }
        ```
    """
    logger.info(
        "payroll_validation_started",
        employee_id=data.employee_id,
        period=data.period,
        wage=data.wage
    )
    
    try:
        from payroll.payroll_validator import PayrollValidator
        from clients.anthropic_client import get_anthropic_client
        
        client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )
        
        validator = PayrollValidator(client)
        result = await validator.validate_payslip(data.dict())
        
        logger.info(
            "payroll_validation_completed",
            employee_id=data.employee_id,
            recommendation=result.get('recommendation'),
            confidence=result.get('confidence')
        )
        
        return PayrollValidationResponse(**result)
        
    except Exception as e:
        logger.error(
            "payroll_validation_error",
            employee_id=data.employee_id,
            error=str(e),
            exc_info=True
        )
        
        # Graceful degradation
        return PayrollValidationResponse(
            success=False,
            confidence=0.0,
            errors=[f"Error en validación: {str(e)[:100]}"],
            warnings=[],
            recommendation="review"
        )


@app.get(
    "/api/payroll/indicators/{period}",
    response_model=PreviredIndicatorsResponse,
    tags=["Payroll"],
    summary="Obtener indicadores Previred",
    description="Extrae 60 campos de indicadores previsionales desde PDF oficial Previred",
    dependencies=[Depends(verify_api_key)]
)
@limiter.limit("10/minute")  # Max 10 extracciones por minuto
async def get_previred_indicators(
    period: str,
    request: Request,
    force: bool = False
):
    """
    Obtener indicadores Previred.
    
    Extrae 60 campos desde PDF oficial:
    - UF, UTM, UTA, sueldo mínimo
    - Tasas AFP por fondo (5 AFPs × 5 fondos)
    - Topes imponibles
    - Tasas cotización
    - Asignación familiar por tramo
    
    Args:
        period: Período YYYY-MM (ej: "2025-10")
        force: Si True, ignora cache y descarga PDF nuevamente
    
    Returns:
        Dict con 60 campos de indicadores
    
    Example:
        GET /api/payroll/indicators/2025-10
        GET /api/payroll/indicators/2025-10?force=true
    """
    logger.info("previred_indicators_requested", period=period, force=force)
    
    # Validar formato período
    import re
    if not re.match(r'^\d{4}-\d{2}$', period):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Formato de período inválido: {period}. Esperado: YYYY-MM"
        )
    
    try:
        from payroll.previred_scraper import PreviredScraper
        from clients.anthropic_client import get_anthropic_client
        
        client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )
        
        scraper = PreviredScraper(client)
        result = await scraper.extract_indicators(period)
        
        logger.info(
            "previred_indicators_completed",
            period=period,
            fields_extracted=len(result.get('indicators', {}))
        )
        
        return PreviredIndicatorsResponse(**result)
        
    except Exception as e:
        logger.error(
            "previred_indicators_error",
            period=period,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error extrayendo indicadores: {str(e)[:200]}"
        )


# ═══════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# [NUEVO] SII MONITORING ENDPOINTS - Added 2025-10-22
# ═══════════════════════════════════════════════════════════

# Modelos Pydantic
class SIIMonitorRequest(BaseModel):
    """Request para trigger de monitoreo SII con validaciones"""
    force: bool = Field(default=False, description="Si True, ignora cache y fuerza scraping")


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
    data: SIIMonitorRequest,
    request: Request,
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
    
    logger.info("sii_monitoring_triggered", force=data.force)
    
    try:
        orchestrator = get_orchestrator()
        results = orchestrator.execute_monitoring(force=data.force)
        
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
                anthropic_model=settings.anthropic_model)

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
    """Request to send chat message con validaciones robustas"""
    session_id: Optional[str] = Field(None, description="Session ID (auto-generado si None)")
    message: str = Field(..., min_length=1, max_length=5000, description="Mensaje del usuario (1-5000 caracteres)")
    user_context: Optional[Dict[str, Any]] = Field(None, description="Contexto del usuario (opcional)")
    
    @validator('session_id')
    def validate_session_id(cls, v):
        """Validar formato UUID si se proporciona"""
        if v:
            import uuid
            try:
                uuid.UUID(v)
            except ValueError:
                raise ValueError(f"session_id debe ser un UUID válido: {v}")
        return v

    @validator('message')
    def validate_message(cls, v):
        """Validar y sanitizar mensaje."""
        if not v or not v.strip():
            raise ValueError("Mensaje no puede estar vacío")
        
        # Sanitizar
        v = v.strip()
        
        if len(v) < 1:
            raise ValueError("Mensaje demasiado corto")
        
        return v


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

        # Get Anthropic client (solo LLM)
        from clients.anthropic_client import get_anthropic_client

        anthropic_client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )

        # Create chat engine (solo Anthropic)
        _chat_engine = ChatEngine(
            anthropic_client=anthropic_client,
            redis_client=redis_client,
            session_ttl=settings.chat_session_ttl,
            max_context_messages=settings.chat_max_context_messages,
            context_manager=context_manager,
            knowledge_base=knowledge_base,
            default_temperature=settings.chat_default_temperature
        )

        logger.info("chat_engine_initialized",
                   model=settings.anthropic_model)

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
    data: ChatMessageRequest,
    request: Request,
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
    session_id = data.session_id or str(uuid.uuid4())

    logger.info("chat_message_request",
                session_id=session_id,
                message_preview=data.message[:100],
                has_user_context=data.user_context is not None)

    try:
        engine = get_chat_engine()

        response = await engine.send_message(
            session_id=session_id,
            user_message=data.message,
            user_context=data.user_context
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
    "/api/chat/message/stream",
    tags=["Chat Support"],
    summary="Send chat message with streaming response",
    description="Send message to AI assistant and get real-time streaming response for better UX"
)
@limiter.limit("30/minute")  # Same limit as non-streaming
async def send_chat_message_stream(
    data: ChatMessageRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Send message to AI support assistant with streaming response.

    OPTIMIZATION 2025-10-24: Streaming for 3x better perceived UX.

    Returns Server-Sent Events (SSE) stream with:
    - Text chunks as they are generated
    - Final metadata (sources, tokens, confidence)

    Example client-side usage (JavaScript):
    ```javascript
    const response = await fetch('/api/chat/message/stream', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer API_KEY',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        session_id: 'uuid',
        message: '¿Cómo genero un DTE 33?'
      })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const {done, value} = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value);
      const lines = chunk.split('\\n');

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = JSON.parse(line.substring(6));
          if (data.type === 'text') {
            console.log(data.content);  // Stream text
          } else if (data.type === 'done') {
            console.log(data.metadata);  // Final metadata
          }
        }
      }
    }
    ```
    """
    # Verify API key
    await verify_api_key(credentials)

    # Create session if needed
    session_id = data.session_id or str(uuid.uuid4())

    logger.info("chat_message_stream_request",
                session_id=session_id,
                message_preview=data.message[:100])

    async def event_stream():
        """Generator for Server-Sent Events."""
        try:
            engine = get_chat_engine()

            async for chunk in engine.send_message_stream(
                session_id=session_id,
                user_message=data.message,
                user_context=data.user_context
            ):
                # Send SSE formatted message
                import json
                yield f"data: {json.dumps(chunk)}\\n\\n"

        except Exception as e:
            logger.error("chat_stream_error",
                        session_id=session_id,
                        error=str(e))
            import json
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\\n\\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable nginx buffering
        }
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

