# -*- coding: utf-8 -*-
"""
FastAPI Routes - Analytics

Endpoints para funcionalidades analíticas con IA:
- Sugerencia de proyectos para facturas
- Validación de DTEs
- Análisis predictivo

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-10-23
"""

from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import os
import logging
import re

# Import del matcher (asumiendo estructura ai-service/)
try:
    from analytics.project_matcher_claude import ProjectMatcherClaude
except ImportError:
    from ..analytics.project_matcher_claude import ProjectMatcherClaude

# Import analytics tracker
try:
    from utils.analytics_tracker import get_analytics_tracker
except ImportError:
    from ..utils.analytics_tracker import get_analytics_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai/analytics", tags=["Analytics"])


# ═══════════════════════════════════════════════════════════
# PYDANTIC MODELS (REQUEST/RESPONSE)
# ═══════════════════════════════════════════════════════════

class InvoiceLine(BaseModel):
    """Línea de factura"""
    description: str
    quantity: float
    price: float


class Project(BaseModel):
    """Proyecto disponible"""
    id: int
    name: str
    code: Optional[str] = None
    partner_name: Optional[str] = None
    state: str = 'active'
    budget: float = 0.0


class HistoricalPurchase(BaseModel):
    """Compra histórica del proveedor"""
    date: str
    project_name: str
    amount: float


class ProjectSuggestionRequest(BaseModel):
    """Request para sugerencia de proyecto"""
    partner_id: int
    partner_vat: str
    partner_name: str
    invoice_lines: List[InvoiceLine]
    company_id: int
    available_projects: List[Project]
    historical_purchases: Optional[List[HistoricalPurchase]] = None


class ProjectSuggestionResponse(BaseModel):
    """Response con sugerencia de proyecto"""
    project_id: Optional[int]
    project_name: Optional[str]
    confidence: float = Field(..., ge=0, le=100)
    reasoning: str


# ═══════════════════════════════════════════════════════════
# DEPENDENCY: API KEY AUTHENTICATION
# ═══════════════════════════════════════════════════════════

async def verify_api_key(authorization: str = Header(None)) -> bool:
    """
    Verifica API key en header Authorization.

    Args:
        authorization: Header "Authorization: Bearer <api_key>"

    Returns:
        True if API key is valid

    Raises:
        HTTPException: Si API key inválida
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    # Formato: "Bearer <api_key>"
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected: Bearer <api_key>"
        )

    api_key = parts[1]
    expected_api_key = os.getenv('AI_SERVICE_API_KEY', '')

    if not expected_api_key:
        logger.warning("AI_SERVICE_API_KEY not configured, allowing all requests")
        return True

    if api_key != expected_api_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )

    return True


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@router.post("/suggest_project", response_model=ProjectSuggestionResponse)
async def suggest_project(
    request: ProjectSuggestionRequest,
    http_request: Request,
    authorized: bool = Depends(verify_api_key)
) -> ProjectSuggestionResponse:
    """
    Sugiere proyecto para factura usando Claude 3.5 Sonnet.

    **Requiere autenticación** (Bearer token).

    **Casos de uso:**
    - Factura proveedor recibida SIN orden de compra asociada
    - Sistema sugiere automáticamente a qué proyecto pertenece

    **Threshold de confianza:**
    - ≥85%: Auto-asignar proyecto
    - 70-84%: Sugerir proyecto (requiere confirmación)
    - <70%: No sugerir (asignación manual)
    """
    api_key = os.getenv('ANTHROPIC_API_KEY')

    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="ANTHROPIC_API_KEY not configured in environment"
        )

    # Inicializar matcher
    matcher = ProjectMatcherClaude(api_key)

    # Convertir Pydantic models a dicts
    invoice_lines_dict = [line.dict() for line in request.invoice_lines]
    projects_dict = [proj.dict() for proj in request.available_projects]
    historical_dict = (
        [h.dict() for h in request.historical_purchases]
        if request.historical_purchases
        else None
    )

    # Llamar a Claude (versión async nativa)
    try:
        result = await matcher.suggest_project(
            partner_name=request.partner_name,
            partner_vat=request.partner_vat,
            invoice_lines=invoice_lines_dict,
            available_projects=projects_dict,
            historical_purchases=historical_dict
        )

        # Track analytics (P0-1 implementation)
        try:
            tracker = get_analytics_tracker()
            tracker.track_suggestion(
                result=result,
                partner_id=request.partner_id,
                partner_name=request.partner_name,
                company_id=request.company_id,
                metadata={
                    "invoice_lines_count": len(invoice_lines_dict),
                    "available_projects_count": len(projects_dict),
                    "has_historical": historical_dict is not None
                }
            )
            logger.info(
                "analytics_tracked",
                project_id=result.get("project_id"),
                confidence=result.get("confidence"),
                partner_id=request.partner_id
            )
        except Exception as tracking_error:
            # Don't fail request if tracking fails, just log warning
            logger.warning(
                "analytics_tracking_failed",
                error=str(tracking_error),
                partner_id=request.partner_id
            )

        return ProjectSuggestionResponse(**result)

    except Exception as e:
        logger.exception("Error in suggest_project endpoint: %s", str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Error processing request: {str(e)[:200]}"
        )


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint (no requiere autenticación)"""
    anthropic_key_configured = bool(os.getenv('ANTHROPIC_API_KEY'))

    return {
        "status": "healthy",
        "service": "analytics",
        "anthropic_configured": anthropic_key_configured,
        "features": [
            "project_matching",
            "dte_validation",
            "predictive_analytics"
        ]
    }


@router.get("/stats")
async def get_stats(authorized: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    """
    Estadísticas del servicio (requiere autenticación).

    Returns real-time analytics from Redis backend.

    Response includes:
    - total_suggestions: Total number of project suggestions made
    - avg_confidence: Average confidence score across all suggestions
    - projects_matched: Total unique projects matched
    - top_projects: Top 10 most frequently matched projects
    - confidence_distribution: Distribution of confidence levels (high/medium/low)
    """
    try:
        tracker = get_analytics_tracker()
        stats = tracker.get_stats(limit_top_projects=10)

        logger.info(
            "analytics_stats_requested",
            total_suggestions=stats.get("total_suggestions", 0),
            avg_confidence=stats.get("avg_confidence", 0)
        )

        return stats

    except Exception as e:
        logger.exception("Error retrieving analytics stats: %s", str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving stats: {str(e)[:200]}"
        )
