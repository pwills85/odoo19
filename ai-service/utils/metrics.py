# -*- coding: utf-8 -*-
"""
Prometheus Metrics - Observability & Monitoring
================================================

Exposes Prometheus metrics for the AI Service.

Metrics Categories:
- Request metrics (count, latency, errors)
- Claude API metrics (tokens, cost, rate limits)
- Circuit breaker metrics (state, failures)
- Cache metrics (hits, misses, evictions)
- Business metrics (DTEs validated, projects matched)

Author: EERGYGROUP - Gap Closure Sprint
Date: 2025-10-23
"""

from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST
)
import structlog

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════
# REQUEST METRICS
# ═══════════════════════════════════════════════════════════

http_requests_total = Counter(
    'ai_service_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'ai_service_http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

http_request_errors_total = Counter(
    'ai_service_http_request_errors_total',
    'Total HTTP request errors',
    ['method', 'endpoint', 'error_type']
)


# ═══════════════════════════════════════════════════════════
# CLAUDE API METRICS
# ═══════════════════════════════════════════════════════════

claude_api_calls_total = Counter(
    'ai_service_claude_api_calls_total',
    'Total Claude API calls',
    ['model', 'operation', 'status']
)

claude_api_tokens_total = Counter(
    'ai_service_claude_api_tokens_total',
    'Total tokens consumed',
    ['model', 'operation', 'token_type']  # token_type: input/output
)

claude_api_cost_usd_total = Counter(
    'ai_service_claude_api_cost_usd_total',
    'Total API cost in USD',
    ['model', 'operation']
)

claude_api_duration_seconds = Histogram(
    'ai_service_claude_api_duration_seconds',
    'Claude API call duration',
    ['model', 'operation'],
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0]
)

claude_api_rate_limit_errors = Counter(
    'ai_service_claude_api_rate_limit_errors_total',
    'Rate limit errors from Claude API',
    ['model']
)


# ═══════════════════════════════════════════════════════════
# CIRCUIT BREAKER METRICS
# ═══════════════════════════════════════════════════════════

circuit_breaker_state = Gauge(
    'ai_service_circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 2=half_open)',
    ['name']
)

circuit_breaker_failures_total = Counter(
    'ai_service_circuit_breaker_failures_total',
    'Total circuit breaker failures',
    ['name']
)

circuit_breaker_successes_total = Counter(
    'ai_service_circuit_breaker_successes_total',
    'Total circuit breaker successes',
    ['name']
)


# ═══════════════════════════════════════════════════════════
# CACHE METRICS
# ═══════════════════════════════════════════════════════════

cache_hits_total = Counter(
    'ai_service_cache_hits_total',
    'Total cache hits',
    ['cache_type']  # llm, redis, etc.
)

cache_misses_total = Counter(
    'ai_service_cache_misses_total',
    'Total cache misses',
    ['cache_type']
)

cache_size_bytes = Gauge(
    'ai_service_cache_size_bytes',
    'Current cache size in bytes',
    ['cache_type']
)


# ═══════════════════════════════════════════════════════════
# BUSINESS METRICS
# ═══════════════════════════════════════════════════════════

dte_validations_total = Counter(
    'ai_service_dte_validations_total',
    'Total DTE validations',
    ['recommendation']  # send/review
)

dte_validation_confidence = Histogram(
    'ai_service_dte_validation_confidence',
    'DTE validation confidence scores',
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100]
)

project_suggestions_total = Counter(
    'ai_service_project_suggestions_total',
    'Total project suggestions',
    ['confidence_tier']  # high (>=85), medium (70-84), low (<70)
)

payroll_validations_total = Counter(
    'ai_service_payroll_validations_total',
    'Total payroll validations',
    ['result']  # success/error
)


# ═══════════════════════════════════════════════════════════
# SERVICE INFO
# ═══════════════════════════════════════════════════════════

service_info = Info(
    'ai_service_info',
    'AI Service version and configuration'
)


# ═══════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════

def init_service_info(version: str, model: str):
    """Initialize service info metrics"""
    service_info.info({
        'version': version,
        'default_model': model,
        'framework': 'fastapi',
        'llm_provider': 'anthropic'
    })


def record_request(method: str, endpoint: str, status: int, duration: float):
    """Record HTTP request metrics"""
    http_requests_total.labels(
        method=method,
        endpoint=endpoint,
        status=str(status)
    ).inc()

    http_request_duration_seconds.labels(
        method=method,
        endpoint=endpoint
    ).observe(duration)


def record_claude_call(
    model: str,
    operation: str,
    status: str,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    duration: float
):
    """Record Claude API call metrics"""
    claude_api_calls_total.labels(
        model=model,
        operation=operation,
        status=status
    ).inc()

    claude_api_tokens_total.labels(
        model=model,
        operation=operation,
        token_type='input'
    ).inc(input_tokens)

    claude_api_tokens_total.labels(
        model=model,
        operation=operation,
        token_type='output'
    ).inc(output_tokens)

    claude_api_cost_usd_total.labels(
        model=model,
        operation=operation
    ).inc(cost_usd)

    claude_api_duration_seconds.labels(
        model=model,
        operation=operation
    ).observe(duration)


def record_circuit_breaker_state(name: str, state: str):
    """
    Record circuit breaker state.

    Args:
        name: Circuit breaker name
        state: "closed", "open", or "half_open"
    """
    state_map = {"closed": 0, "open": 1, "half_open": 2}
    circuit_breaker_state.labels(name=name).set(state_map.get(state, 0))


def record_dte_validation(recommendation: str, confidence: float):
    """Record DTE validation business metrics"""
    dte_validations_total.labels(recommendation=recommendation).inc()
    dte_validation_confidence.observe(confidence)


def record_project_suggestion(confidence: float):
    """Record project suggestion business metrics"""
    if confidence >= 85:
        tier = "high"
    elif confidence >= 70:
        tier = "medium"
    else:
        tier = "low"

    project_suggestions_total.labels(confidence_tier=tier).inc()


def get_metrics() -> bytes:
    """
    Generate Prometheus metrics in text format.

    Returns:
        Bytes with metrics in Prometheus format
    """
    return generate_latest()


def get_content_type() -> str:
    """Get Prometheus content type"""
    return CONTENT_TYPE_LATEST
