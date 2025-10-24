# -*- coding: utf-8 -*-
"""
Observability Middleware - Request Tracking & Metrics
======================================================

FastAPI middleware for automatic observability:
- Request/response logging
- Prometheus metrics recording
- Error tracking
- Performance monitoring

Author: EERGYGROUP - Gap Closure Sprint
Date: 2025-10-23
"""

import time
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Callable

logger = structlog.get_logger(__name__)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for automatic request observability.

    Records:
    - HTTP request metrics (count, latency, status)
    - Structured logging for all requests
    - Error tracking with full context
    - Performance timing

    Usage:
        from middleware.observability import ObservabilityMiddleware
        app.add_middleware(ObservabilityMiddleware)
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with full observability.

        Args:
            request: FastAPI request
            call_next: Next middleware/handler

        Returns:
            Response with metrics recorded
        """
        start_time = time.time()
        method = request.method
        path = request.url.path

        # Skip metrics endpoint to avoid recursion
        if path == "/metrics":
            return await call_next(request)

        # Request started
        logger.info(
            "request_started",
            method=method,
            path=path,
            client=request.client.host if request.client else "unknown"
        )

        response = None
        error = None

        try:
            # Process request
            response = await call_next(request)
            status_code = response.status_code

        except Exception as e:
            # Record error
            error = e
            status_code = 500
            logger.error(
                "request_error",
                method=method,
                path=path,
                error=str(e),
                error_type=type(e).__name__
            )
            raise

        finally:
            # Calculate duration
            duration = time.time() - start_time

            # Record metrics
            try:
                from utils.metrics import record_request
                record_request(
                    method=method,
                    endpoint=path,
                    status=status_code,
                    duration=duration
                )
            except Exception as e:
                logger.warning("metrics_recording_failed", error=str(e))

            # Log completion
            if error is None:
                logger.info(
                    "request_completed",
                    method=method,
                    path=path,
                    status=status_code,
                    duration_ms=round(duration * 1000, 2)
                )

        return response


class ErrorTrackingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for detailed error tracking.

    Captures and logs all exceptions with full context.
    Useful for alerting and debugging.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            return await call_next(request)

        except Exception as e:
            # Enhanced error logging
            logger.error(
                "unhandled_exception",
                method=request.method,
                path=request.url.path,
                error=str(e),
                error_type=type(e).__name__,
                client=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent", "unknown"),
                exc_info=True
            )

            # Record error metric
            try:
                from utils.metrics import http_request_errors_total
                http_request_errors_total.labels(
                    method=request.method,
                    endpoint=request.url.path,
                    error_type=type(e).__name__
                ).inc()
            except:
                pass

            # Re-raise to let FastAPI handle it
            raise
