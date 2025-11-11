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
import time
from datetime import datetime, timezone
import structlog
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hashlib
import json
import uuid

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
# SERVICE UPTIME TRACKING
# ═══════════════════════════════════════════════════════════

SERVICE_START_TIME = time.time()

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

def get_user_identifier(request: Request) -> str:
    """
    Get unique user identifier for rate limiting.

    Combines API key (if present) + IP address to prevent
    bypassing rate limits by rotating IPs.

    Args:
        request: FastAPI Request object

    Returns:
        str: Unique identifier (api_key_prefix:ip_address)
    """
    # Try to get API key from Authorization header
    api_key = "anonymous"
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        # Extract token (first 8 chars for identifier, avoid logging full key)
        token = auth_header[7:]  # Skip "Bearer "
        api_key = token[:8] if token else "anonymous"

    # Get client IP
    ip_address = request.client.host if request.client else "unknown"

    # Combine for unique identifier
    return f"{api_key}:{ip_address}"


limiter = Limiter(key_func=get_user_identifier)
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
    """Request para validación de DTE con validaciones robustas (P0-4 Enhanced)"""
    dte_data: Dict[str, Any] = Field(..., description="Datos del DTE a validar")
    company_id: int = Field(..., gt=0, description="ID de la compañía (debe ser positivo)")
    history: Optional[List[Dict]] = Field(default=[], max_items=100, description="Historial de validaciones (máximo 100)")

    @validator('dte_data')
    def validate_dte_data(cls, v):
        """
        Validar estructura y datos del DTE con reglas de negocio chilenas.

        Validaciones (P0-4):
        - RUT formato válido (12345678-9)
        - RUT dígito verificador correcto (módulo 11)
        - Monto positivo y razonable
        - Fecha no futura
        - Tipo DTE válido según SII

        Performance: ~2-3ms (sin impacto significativo)
        """
        import structlog
        logger = structlog.get_logger()

        if not isinstance(v, dict) or not v:
            raise ValueError("dte_data debe ser un diccionario no vacío")

        # Validar RUT emisor (si existe)
        if 'rut_emisor' in v:
            rut = str(v['rut_emisor']).strip()
            if not re.match(r'^\d{1,8}-[\dkK]$', rut):
                logger.warning("validation_failed_rut_emisor", rut=rut)
                raise ValueError(f"RUT emisor inválido: {rut}. Formato esperado: 12345678-9")

            # Validar dígito verificador
            try:
                rut_num, dv = rut.split('-')
                expected_dv = cls._calculate_dv(rut_num)
                if expected_dv.upper() != dv.upper():
                    logger.warning("validation_failed_dv_emisor", rut=rut, expected=expected_dv, got=dv)
                    raise ValueError(f"RUT emisor con dígito verificador inválido: {rut} (esperado: {expected_dv})")
            except ValueError:
                raise
            except:
                pass  # Si falla parsing, continuar (formato ya validado)

        # Validar RUT receptor (si existe)
        if 'rut_receptor' in v:
            rut = str(v['rut_receptor']).strip()
            if not re.match(r'^\d{1,8}-[\dkK]$', rut):
                logger.warning("validation_failed_rut_receptor", rut=rut)
                raise ValueError(f"RUT receptor inválido: {rut}. Formato esperado: 12345678-9")

        # Validar monto total positivo
        if 'monto_total' in v:
            try:
                monto = float(v['monto_total'])
                if monto <= 0:
                    logger.warning("validation_failed_monto_negative", monto=monto)
                    raise ValueError(f"Monto total debe ser positivo: {monto}")
                if monto > 999999999999:  # ~1 trillion CLP (sanity check)
                    logger.warning("validation_failed_monto_excessive", monto=monto)
                    raise ValueError(f"Monto total excede límite razonable: {monto}")
            except (TypeError, ValueError) as e:
                if "debe ser positivo" in str(e) or "excede límite" in str(e):
                    raise
                raise ValueError(f"Monto total inválido: {v['monto_total']}")

        # Validar fecha emisión no futura
        if 'fecha_emision' in v:
            from datetime import datetime, timedelta
            try:
                # Soportar múltiples formatos
                fecha_str = str(v['fecha_emision'])

                # Intentar parsear ISO format (YYYY-MM-DD o YYYY-MM-DDTHH:MM:SS)
                if 'T' in fecha_str:
                    fecha = datetime.fromisoformat(fecha_str.replace('Z', '+00:00'))
                else:
                    fecha = datetime.strptime(fecha_str, '%Y-%m-%d')

                # Permitir +24 horas (zona horaria)
                now_plus_buffer = datetime.now() + timedelta(hours=24)

                if fecha > now_plus_buffer:
                    logger.warning("validation_failed_fecha_futura", fecha=fecha_str)
                    raise ValueError(f"Fecha emisión no puede ser futura: {fecha_str}")

            except ValueError as e:
                if "no puede ser futura" in str(e):
                    raise
                raise ValueError(f"Fecha emisión inválida: {v['fecha_emision']}")

        # Validar tipo_dte
        if 'tipo_dte' not in v:
            raise ValueError("Campo 'tipo_dte' es requerido en dte_data")

        # Validar tipo_dte válido (DTEs más comunes en Chile según SII)
        valid_types = [
            '33',   # Factura Electrónica
            '34',   # Factura Exenta
            '39',   # Boleta Electrónica
            '41',   # Boleta Exenta
            '43',   # Liquidación Factura
            '46',   # Factura Compra
            '52',   # Guía Despacho
            '56',   # Nota Débito
            '61',   # Nota Crédito
            '110',  # Factura Exportación
            '111',  # Nota Débito Exportación
            '112'   # Nota Crédito Exportación
        ]

        tipo_dte = str(v.get('tipo_dte'))
        if tipo_dte not in valid_types:
            logger.warning("validation_failed_tipo_dte", tipo_dte=tipo_dte)
            raise ValueError(
                f"tipo_dte '{tipo_dte}' no válido. "
                f"Tipos permitidos: {', '.join(valid_types)}"
            )

        return v

    @staticmethod
    def _calculate_dv(rut_num: str) -> str:
        """
        Calcular dígito verificador de RUT chileno (Módulo 11).

        Args:
            rut_num: Número de RUT sin DV (ej: "12345678")

        Returns:
            str: Dígito verificador ('0'-'9' o 'K')
        """
        reversed_digits = map(int, reversed(rut_num))
        factors = [2, 3, 4, 5, 6, 7]

        s = sum(d * factors[i % 6] for i, d in enumerate(reversed_digits))
        remainder = s % 11
        dv_num = 11 - remainder

        if dv_num == 11:
            return '0'
        elif dv_num == 10:
            return 'K'
        else:
            return str(dv_num)

    @validator('history')
    def validate_history_size(cls, v):
        """
        Limitar tamaño total del history para evitar OOM.

        Performance: ~1ms
        """
        if v:
            # Limitar número de elementos
            if len(v) > 100:
                raise ValueError(f"History demasiado largo: {len(v)} elementos (máximo 100)")

            # Limitar tamaño total serializado
            total_size = len(str(v))
            if total_size > 100_000:  # 100KB max
                raise ValueError(
                    f"History demasiado grande: {total_size} bytes (máximo 100KB)"
                )
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
    """Request para validación de liquidación con validaciones robustas (P0-4 Enhanced)"""
    employee_id: int = Field(..., gt=0, description="ID del empleado")
    period: str = Field(..., pattern=r'^\d{4}-\d{2}$', description="Período YYYY-MM")
    wage: float = Field(..., gt=0, description="Sueldo base (debe ser > 0)")
    lines: List[Dict[str, Any]] = Field(..., min_items=1, max_items=100, description="Líneas liquidación (1-100)")

    @validator('wage')
    def validate_wage(cls, v):
        """
        Validar sueldo contra normativa chilena (P0-4).

        Validaciones:
        - Sueldo >= mínimo legal (~$460.000 CLP 2025)
        - Sueldo <= tope razonable (CEO level)

        Performance: <1ms
        """
        import structlog
        logger = structlog.get_logger()

        # Chile: Sueldo mínimo ~$460.000 (2025)
        # Usamos $400.000 como buffer (por ley 21.456)
        MIN_WAGE_CLP = 400000

        if v < MIN_WAGE_CLP:
            logger.warning("validation_wage_below_minimum", wage=v, minimum=MIN_WAGE_CLP)
            raise ValueError(
                f"Sueldo ${v:,.0f} menor al mínimo legal "
                f"(~${MIN_WAGE_CLP:,.0f} CLP)"
            )

        # Tope razonable: $50M CLP (~$60K USD)
        # Sueldos mayores requieren revisión manual
        MAX_WAGE_CLP = 50000000

        if v > MAX_WAGE_CLP:
            logger.warning("validation_wage_exceeds_reasonable", wage=v, maximum=MAX_WAGE_CLP)
            raise ValueError(
                f"Sueldo ${v:,.0f} excede límite razonable "
                f"(${MAX_WAGE_CLP:,.0f} CLP). Revisar manualmente"
            )

        return v

    @validator('period')
    def validate_period(cls, v):
        """
        Validar período de liquidación (P0-4).

        Validaciones:
        - Formato YYYY-MM válido
        - No permitir períodos futuros >2 meses
        - No permitir períodos muy antiguos (>12 meses)

        Performance: <1ms
        """
        import structlog
        from datetime import datetime

        logger = structlog.get_logger()

        # Validar formato
        if not re.match(r'^20\d{2}-(0[1-9]|1[0-2])$', v):
            raise ValueError(f"Período inválido: {v} (formato esperado: YYYY-MM)")

        # Parsear fecha
        year, month = map(int, v.split('-'))
        period_date = datetime(year, month, 1)
        now = datetime.now()

        # No permitir períodos futuros >2 meses
        days_diff = (period_date - now).days
        if days_diff > 60:
            logger.warning("validation_period_too_future", period=v, days_diff=days_diff)
            raise ValueError(
                f"Período muy futuro: {v} "
                f"({days_diff} días). Máximo 2 meses"
            )

        # No permitir períodos muy antiguos (>12 meses atrás)
        if days_diff < -365:
            logger.warning("validation_period_too_old", period=v, days_diff=abs(days_diff))
            raise ValueError(
                f"Período muy antiguo: {v} "
                f"({abs(days_diff)} días atrás). Máximo 12 meses"
            )

        return v

    @validator('lines')
    def validate_lines(cls, v):
        """
        Validar estructura de líneas de liquidación (P0-4).

        Performance: ~1-2ms para 50 líneas
        """
        for i, line in enumerate(v, 1):
            if 'code' not in line:
                raise ValueError(f"Línea {i} sin campo 'code'")
            if 'amount' not in line:
                raise ValueError(f"Línea {i} sin campo 'amount'")
            if not isinstance(line['amount'], (int, float)):
                raise ValueError(f"Línea {i}: 'amount' debe ser numérico")

            # Validar códigos mínimos requeridos
            # (opcional: agregar validación de códigos Previred válidos)

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
    """
    Enhanced health check endpoint with comprehensive dependency validation.

    Returns comprehensive status of:
    - Redis Sentinel cluster
    - Anthropic API configuration
    - Plugin Registry
    - Knowledge Base
    - Service metrics

    Returns:
        dict: Health status with dependency details

    Status Codes:
        200: All dependencies healthy
        207: Service degraded (some non-critical issues)
        503: Service unhealthy (critical dependency down)
    """
    from fastapi.responses import JSONResponse

    start_time = time.time()
    overall_status = "healthy"
    dependencies = {}

    # 1. Check Redis Sentinel
    try:
        from utils.redis_helper import get_redis_client

        redis_start = time.time()
        redis_client = get_redis_client()
        redis_client.ping()
        redis_latency = (time.time() - redis_start) * 1000

        # Get sentinel info (if available)
        sentinel_info = {}
        try:
            from utils.redis_helper import sentinel
            if sentinel:
                # Get master info
                master_info = sentinel.discover_master('mymaster')
                replicas_info = sentinel.discover_slaves('mymaster')
                sentinels_info = sentinel.discover_sentinels('mymaster')

                sentinel_info = {
                    "type": "sentinel",
                    "master": f"{master_info[0]}:{master_info[1]}",
                    "replicas": len(replicas_info),
                    "sentinels": len(sentinels_info) + 1  # +1 for current
                }
        except:
            sentinel_info = {"type": "standalone"}

        dependencies["redis"] = {
            "status": "up",
            **sentinel_info,
            "latency_ms": round(redis_latency, 2)
        }

        # Alert if latency > 100ms (P1-7)
        if redis_latency > 100:
            overall_status = "degraded"
            dependencies["redis"]["warning"] = f"High latency: {redis_latency:.1f}ms"
            logger.warning("health_check_redis_slow", latency_ms=redis_latency)
    except Exception as e:
        dependencies["redis"] = {
            "status": "down",
            "error": str(e)[:200]
        }
        overall_status = "unhealthy"
        logger.error("health_check_redis_failed", error=str(e))

    # 2. Check Anthropic API
    try:
        api_key_present = bool(settings.anthropic_api_key and
                              settings.anthropic_api_key != "default_key")

        anthropic_status = {
            "status": "configured" if api_key_present else "not_configured",
            "model": settings.anthropic_model,
            "api_key_present": api_key_present
        }

        # Optional: Test actual connectivity (commented out for performance)
        # Uncomment if you want to test real API calls
        # try:
        #     from clients.anthropic_client import AnthropicClient
        #     client = AnthropicClient()
        #     # Make a lightweight test call (count tokens)
        #     await client.estimate_tokens("health check test", max_tokens=10)
        #     anthropic_status["connectivity"] = "ok"
        # except:
        #     anthropic_status["connectivity"] = "unreachable"
        #     overall_status = "degraded"

        dependencies["anthropic"] = anthropic_status

    except Exception as e:
        dependencies["anthropic"] = {
            "status": "error",
            "error": str(e)[:200]
        }
        overall_status = "degraded"
        logger.error("health_check_anthropic_failed", error=str(e))

    # 3. Check Plugin Registry
    try:
        from plugins.registry import get_plugin_registry

        plugin_registry = get_plugin_registry()
        plugins_list = plugin_registry.list_plugins()

        # Extract module names from plugin dicts
        plugin_modules = [plugin.get('module', 'unknown') for plugin in plugins_list]

        dependencies["plugin_registry"] = {
            "status": "loaded",
            "plugins_count": len(plugins_list),
            "plugins": plugin_modules
        }
    except Exception as e:
        dependencies["plugin_registry"] = {
            "status": "error",
            "error": str(e)[:200]
        }
        overall_status = "degraded"
        logger.error("health_check_plugins_failed", error=str(e))

    # 4. Check Knowledge Base
    try:
        from chat.knowledge_base import KnowledgeBase

        knowledge_base = KnowledgeBase()

        modules_set = set()
        for doc in knowledge_base.documents:
            modules_set.add(doc.get("module", "unknown"))

        dependencies["knowledge_base"] = {
            "status": "loaded",
            "documents_count": len(knowledge_base.documents),
            "modules": sorted(list(modules_set))
        }
    except Exception as e:
        dependencies["knowledge_base"] = {
            "status": "error",
            "error": str(e)[:200]
        }
        overall_status = "degraded"
        logger.error("health_check_knowledge_base_failed", error=str(e))

    # 5. Get metrics (optional, from Redis if available)
    metrics = {}
    try:
        if dependencies.get("redis", {}).get("status") == "up":
            # Try to get metrics from Redis
            from utils.redis_helper import get_redis_client
            redis_client = get_redis_client(read_only=True)

            total_requests = redis_client.get("metrics:total_requests")
            cache_hits = redis_client.get("metrics:cache_hits")
            cache_total = redis_client.get("metrics:cache_total")

            metrics = {
                "total_requests": int(total_requests) if total_requests else 0,
                "cache_hit_rate": (
                    round(int(cache_hits) / int(cache_total), 3)
                    if cache_total and int(cache_total) > 0
                    else 0.0
                )
            }
    except:
        # Metrics are optional
        pass

    # Build response
    health_response = {
        "status": overall_status,
        "service": "AI Microservice - DTE Intelligence",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int(time.time() - SERVICE_START_TIME),
        "dependencies": dependencies,
        "health_check_duration_ms": round((time.time() - start_time) * 1000, 2)
    }

    if metrics:
        health_response["metrics"] = metrics

    # Return appropriate HTTP status code
    status_code = 200 if overall_status == "healthy" else (
        503 if overall_status == "unhealthy" else 207  # 207 = Multi-Status (degraded)
    )

    logger.info("health_check_completed",
                status=overall_status,
                duration_ms=health_response["health_check_duration_ms"])

    return JSONResponse(
        content=health_response,
        status_code=status_code
    )


@app.get("/ready")
async def readiness_check():
    """
    Readiness probe for Kubernetes/orchestrators.

    Returns 200 only if service is ready to accept traffic.
    More strict than health check - verifies all critical dependencies.

    Returns:
        dict: Simple ready/not-ready status

    Status Codes:
        200: Service ready to accept traffic
        503: Service not ready
    """
    from fastapi.responses import JSONResponse

    try:
        # Check critical dependencies only
        from utils.redis_helper import get_redis_client
        redis_client = get_redis_client()
        redis_client.ping()

        # Check that essential components are loaded
        from plugins.registry import get_plugin_registry
        from chat.knowledge_base import KnowledgeBase

        plugin_registry = get_plugin_registry()
        knowledge_base = KnowledgeBase()

        plugins_list = plugin_registry.list_plugins()
        if len(plugins_list) == 0:
            raise Exception("No plugins loaded")

        if len(knowledge_base.documents) == 0:
            raise Exception("No knowledge base documents")

        logger.info("readiness_check_passed",
                    plugins=len(plugins_list),
                    kb_docs=len(knowledge_base.documents))

        return {"status": "ready"}

    except Exception as e:
        logger.error("readiness_check_failed", error=str(e))
        return JSONResponse(
            content={"status": "not_ready", "error": str(e)[:200]},
            status_code=503
        )


@app.get("/live")
async def liveness_check():
    """
    Liveness probe for Kubernetes/orchestrators.

    Returns 200 if the application is alive (even if dependencies are down).
    Used to determine if container should be restarted.

    Returns:
        dict: Simple alive status

    Status Codes:
        200: Service is alive
    """
    return {
        "status": "alive",
        "uptime_seconds": int(time.time() - SERVICE_START_TIME)
    }


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


# ═══════════════════════════════════════════════════════════
# CACHE HELPER FUNCTIONS (P1-5 Implementation)
# ═══════════════════════════════════════════════════════════

def _generate_cache_key(data: Dict[str, Any], prefix: str, company_id: Optional[int] = None) -> str:
    """
    Generate deterministic cache key from data.

    Args:
        data: Data to hash (dict or similar)
        prefix: Cache key prefix (e.g., "dte_validation", "chat_message")
        company_id: Optional company ID to include in key

    Returns:
        Cache key in format: "{prefix}:{company_id}:{hash}"

    Example:
        key = _generate_cache_key({"foo": "bar"}, "dte_validation", 1)
        # Returns: "dte_validation:1:5c4de..."
    """
    # Serialize data to JSON (sorted keys for determinism)
    content = json.dumps(data, sort_keys=True, default=str)

    # Generate MD5 hash
    hash_val = hashlib.md5(content.encode()).hexdigest()

    # Build cache key
    if company_id:
        return f"{prefix}:{company_id}:{hash_val}"
    else:
        return f"{prefix}:{hash_val}"


async def _get_cached_response(cache_key: str) -> Optional[Dict[str, Any]]:
    """
    Get cached response from Redis.

    Args:
        cache_key: Cache key to lookup

    Returns:
        Cached data as dict, or None if not found or error

    Note:
        Errors are logged but not raised to avoid breaking request flow.
    """
    try:
        from utils.redis_helper import get_redis_client
        redis_client = get_redis_client()

        cached = redis_client.get(cache_key)

        if cached:
            if isinstance(cached, bytes):
                cached = cached.decode('utf-8')

            logger.info("cache_hit", cache_key=cache_key[:50])
            return json.loads(cached)
        else:
            logger.info("cache_miss", cache_key=cache_key[:50])
            return None

    except Exception as e:
        logger.warning("cache_get_failed", error=str(e), cache_key=cache_key[:50])
        return None


async def _set_cached_response(
    cache_key: str,
    data: Dict[str, Any],
    ttl_seconds: int = 900
) -> bool:
    """
    Store response in Redis cache.

    Args:
        cache_key: Cache key to store under
        data: Data to cache (will be JSON serialized)
        ttl_seconds: Time-to-live in seconds (default: 15 minutes)

    Returns:
        True if cached successfully, False otherwise

    Note:
        Errors are logged but not raised to avoid breaking request flow.
    """
    try:
        from utils.redis_helper import get_redis_client
        redis_client = get_redis_client()

        # Serialize data
        serialized = json.dumps(data, default=str)

        # Store with TTL
        redis_client.setex(cache_key, ttl_seconds, serialized)

        logger.debug("cache_set", cache_key=cache_key[:50], ttl_seconds=ttl_seconds)
        return True

    except Exception as e:
        logger.warning("cache_set_failed", error=str(e), cache_key=cache_key[:50])
        return False


@app.post("/api/ai/validate",
          response_model=DTEValidationResponse,
          dependencies=[Depends(verify_api_key)])
@limiter.limit("20/minute")  # Max 20 validaciones por minuto por IP
async def validate_dte(data: DTEValidationRequest, request: Request):
    """
    Pre-validación inteligente de un DTE antes de envío al SII.

    Usa Claude de Anthropic para detectar errores comparando con historial.

    Cache: 15 minutos TTL
    Cache key: Based on dte_data hash + company_id
    """
    logger.info("ai_validation_started", company_id=data.company_id)

    # P1-5: Generate cache key
    cache_key = _generate_cache_key(
        data={"dte_data": data.dte_data, "history": data.history},
        prefix="dte_validation",
        company_id=data.company_id
    )

    # P1-5: Check cache first
    cached_response = await _get_cached_response(cache_key)
    if cached_response:
        logger.info("dte_validation_cache_hit", company_id=data.company_id)
        return DTEValidationResponse(**cached_response)

    try:
        # Usar cliente Anthropic REAL
        from clients.anthropic_client import get_anthropic_client

        client = get_anthropic_client(
            settings.anthropic_api_key,
            settings.anthropic_model
        )

        # Validar con Claude (ASYNC)
        result = await client.validate_dte(data.dte_data, data.history)

        response = DTEValidationResponse(
            confidence=result.get('confidence', 95.0),
            warnings=result.get('warnings', []),
            errors=result.get('errors', []),
            recommendation=result.get('recommendation', 'send')
        )

        # P1-5: Cache successful response (TTL: 15 minutes)
        await _set_cached_response(
            cache_key=cache_key,
            data=response.dict(),
            ttl_seconds=900  # 15 minutes
        )

        return response

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
    Obtiene estado del sistema de monitoreo SII con métricas desde Redis.
    
    Métricas recuperadas:
    - sii_monitor:stats - Estadísticas generales (total_checks, error_rate)
    - sii_monitor:alerts - Alertas activas
    - sii_monitor:last_check - Timestamp del último chequeo
    
    Returns:
        Dict con estado del sistema y métricas reales desde Redis
    """
    if credentials.credentials != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    try:
        orchestrator = get_orchestrator()
        
        # Retrieve metrics from Redis
        redis_client = get_redis()
        
        # Get stats
        stats_data = {}
        last_execution = None
        news_count = 0
        
        try:
            # Try to get stats from Redis
            stats_raw = await redis_client.get("sii_monitor:stats")
            if stats_raw:
                import json
                stats_data = json.loads(stats_raw)
            
            # Get last check timestamp
            last_check_raw = await redis_client.get("sii_monitor:last_check")
            if last_check_raw:
                last_execution = last_check_raw.decode('utf-8') if isinstance(last_check_raw, bytes) else last_check_raw
            
            # Get alerts count (list length)
            alerts_raw = await redis_client.get("sii_monitor:alerts")
            if alerts_raw:
                alerts_data = json.loads(alerts_raw)
                news_count = len(alerts_data) if isinstance(alerts_data, list) else 0
                
        except Exception as redis_error:
            logger.warning("redis_metrics_retrieval_failed", 
                          error=str(redis_error),
                          message="Falling back to default values")
        
        status_data = {
            "status": "operational",
            "orchestrator_initialized": orchestrator is not None,
            "last_execution": last_execution,
            "news_count_last_24h": news_count,
            "total_checks": stats_data.get("total_checks", 0),
            "error_rate": stats_data.get("error_rate", 0.0)
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
    """Request to send chat message con validaciones robustas (P0-4 Enhanced)"""
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
        """
        Validar y sanitizar mensaje (P0-4).

        Protecciones:
        - HTML/script injection (XSS)
        - Spam patterns
        - Exceso de caracteres especiales
        - SQL injection patterns

        Performance: ~1-2ms
        """
        import structlog
        logger = structlog.get_logger()

        if not v or not v.strip():
            raise ValueError("Mensaje no puede estar vacío")

        # Sanitizar (strip whitespace)
        v = v.strip()

        # Detectar y remover scripts (XSS protection)
        if '<script' in v.lower() or 'javascript:' in v.lower():
            logger.warning("validation_blocked_xss_attempt", message_preview=v[:50])
            v = re.sub(r'<script[^>]*>.*?</script>', '', v, flags=re.DOTALL | re.IGNORECASE)
            v = re.sub(r'javascript:', '', v, flags=re.IGNORECASE)

        # Remover HTML tags (permitir solo texto plano)
        if '<' in v and '>' in v:
            v = re.sub(r'<[^>]+>', '', v)

        # Detectar exceso de caracteres especiales (posible spam/injection)
        special_chars = re.findall(r'[^\w\s\.\,\;\:\¿\?\¡\!\-\(\)\[\]áéíóúñÁÉÍÓÚÑ]', v)
        if len(special_chars) > 30:
            logger.warning("validation_excessive_special_chars", count=len(special_chars))
            raise ValueError(f"Demasiados caracteres especiales: {len(special_chars)} (máximo 30)")

        # Detectar SPAM pattern: todo mayúsculas largo
        if v.upper() == v and len(v) > 50 and not v.startswith('DTE'):
            logger.warning("validation_blocked_spam_caps", message_preview=v[:50])
            raise ValueError("Mensaje parece spam (todo en mayúsculas)")

        # Detectar posible SQL injection
        sql_patterns = ['DROP TABLE', 'DELETE FROM', 'INSERT INTO', '; --', 'UNION SELECT']
        for pattern in sql_patterns:
            if pattern.lower() in v.lower():
                logger.warning("validation_blocked_sql_injection", pattern=pattern)
                raise ValueError("Mensaje contiene patrones sospechosos")

        # Validar longitud final después de sanitización
        if len(v) < 1:
            raise ValueError("Mensaje demasiado corto después de sanitización")

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
    """Get or create chat engine singleton (Phase 2B Enhanced)."""
    global _chat_engine

    if _chat_engine is None:
        logger.info("chat_engine_initializing", plugins_enabled=settings.enable_plugin_system)

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

        # Initialize plugin registry (Phase 2B)
        plugin_registry = None
        if settings.enable_plugin_system:
            from plugins.registry import get_plugin_registry
            plugin_registry = get_plugin_registry()
            logger.info(
                "plugin_registry_loaded",
                plugin_count=len(plugin_registry.list_modules()),
                modules=plugin_registry.list_modules()
            )

        # Create chat engine with plugin support (Phase 2B Enhanced)
        _chat_engine = ChatEngine(
            anthropic_client=anthropic_client,
            plugin_registry=plugin_registry,  # 🆕 Phase 2B
            redis_client=redis_client,
            session_ttl=settings.chat_session_ttl,
            max_context_messages=settings.chat_max_context_messages,
            context_manager=context_manager,
            knowledge_base=knowledge_base,
            default_temperature=settings.chat_default_temperature
        )

        logger.info("chat_engine_initialized",
                   model=settings.anthropic_model,
                   plugins_enabled=settings.enable_plugin_system)

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

    Cache: 5 minutes TTL (only if confidence > 80%)
    Cache key: Based on message hash + session_id

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

    # P1-5: Generate cache key (based on session + message)
    cache_key = _generate_cache_key(
        data={"session_id": session_id, "message": data.message},
        prefix="chat_message"
    )

    # P1-5: Check cache first
    cached_response = await _get_cached_response(cache_key)
    if cached_response:
        logger.info("chat_message_cache_hit", session_id=session_id)
        return EngineChatResponse(**cached_response)

    try:
        engine = get_chat_engine()

        response = await engine.send_message(
            session_id=session_id,
            user_message=data.message,
            user_context=data.user_context
        )

        # P1-5: Cache only if confidence > 80% (high confidence responses)
        # This ensures we only cache reliable, deterministic responses
        confidence = getattr(response, 'confidence', 0.0)
        if confidence > 80.0:
            await _set_cached_response(
                cache_key=cache_key,
                data=response.dict(),
                ttl_seconds=300  # 5 minutes (shorter than DTE validation)
            )
            logger.debug(
                "chat_message_cached",
                session_id=session_id,
                confidence=confidence
            )
        else:
            logger.debug(
                "chat_message_not_cached_low_confidence",
                session_id=session_id,
                confidence=confidence
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

