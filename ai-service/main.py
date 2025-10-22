# -*- coding: utf-8 -*-
"""
AI Microservice - Main Application
FastAPI service para inteligencia artificial aplicada a DTEs
"""

from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import structlog

from config import settings

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

_matcher_instance = None

def get_matcher_singleton():
    """
    Singleton para InvoiceMatcher.
    Carga el modelo una sola vez y lo reutiliza.
    """
    global _matcher_instance
    
    if _matcher_instance is None:
        from reconciliation.invoice_matcher import InvoiceMatcher
        logger.info("initializing_invoice_matcher")
        _matcher_instance = InvoiceMatcher(settings.embedding_model)
        logger.info("invoice_matcher_ready")
    
    return _matcher_instance

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
        "ollama_url": settings.ollama_url
    }

@app.post("/api/ai/validate",
          response_model=DTEValidationResponse,
          dependencies=[Depends(verify_api_key)])
async def validate_dte(request: DTEValidationRequest):
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
async def reconcile_invoice(request: ReconciliationRequest):
    """
    Reconcilia una factura recibida con órdenes de compra pendientes.
    
    Usa embeddings semánticos con sentence-transformers.
    """
    logger.info("ai_reconciliation_started", 
                pending_pos_count=len(request.pending_pos))
    
    try:
        # Parsear DTE XML para extraer datos
        from receivers.xml_parser import XMLParser
        
        parser = XMLParser()
        invoice_data = parser.parse_dte(request.dte_xml)
        
        # Usar InvoiceMatcher REAL (singleton)
        matcher = get_matcher_singleton()
        
        # Hacer matching con embeddings
        result = matcher.match_invoice_to_po(
            invoice_data,
            request.pending_pos,
            threshold=settings.reconciliation_similarity_threshold
        )
        
        return ReconciliationResponse(
            po_id=result.get('po_id'),
            confidence=result.get('confidence', 0.0),
            line_matches=result.get('line_matches', [])
        )
        
    except Exception as e:
        logger.error("ai_reconciliation_error", error=str(e))
        
        # Retornar sin match en caso de error (no bloquear)
        return ReconciliationResponse(
            po_id=None,
            confidence=0.0,
            line_matches=[],
            message=f"Error: {str(e)}"
        )

# ═══════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════

@app.on_event("startup")

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
    changes_detected: int
    news_created: int
    notifications_sent: int
    errors: List[str]


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
async def trigger_sii_monitoring(
    request: SIIMonitorRequest,
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

async def startup_event():
    """Inicialización al arrancar el servicio"""
    logger.info("ai_service_starting",
                version=settings.app_version,
                anthropic_model=settings.anthropic_model,
                ollama_url=settings.ollama_url)

@app.on_event("shutdown")
async def shutdown_event():
    """Limpieza al detener el servicio"""
    logger.info("ai_service_stopping")

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

