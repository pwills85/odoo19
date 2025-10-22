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

