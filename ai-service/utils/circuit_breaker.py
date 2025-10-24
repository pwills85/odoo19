# -*- coding: utf-8 -*-
"""
Circuit Breaker Pattern - Resilience for External APIs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementa patrón Circuit Breaker para proteger contra fallos en cascada
cuando servicios externos (Anthropic API) están caídos.

Estados:
- CLOSED: Normal operation, requests pasan
- OPEN: Servicio external caído, requests fallan inmediatamente
- HALF_OPEN: Prueba recuperación, permite request limitado

Autor: EERGYGROUP - Gap Closure Sprint
Fecha: 2025-10-23
"""

import time
import structlog
from typing import Callable, Any, Optional
from functools import wraps
from enum import Enum
from dataclasses import dataclass
from threading import Lock

logger = structlog.get_logger(__name__)


class CircuitState(Enum):
    """Estados del circuit breaker"""
    CLOSED = "closed"          # Normal operation
    OPEN = "open"              # Failing, block requests
    HALF_OPEN = "half_open"    # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuración del circuit breaker"""
    failure_threshold: int = 5          # Fallos consecutivos para abrir
    recovery_timeout: float = 60.0      # Segundos antes de intentar recovery
    success_threshold: int = 2          # Éxitos para cerrar desde half-open
    timeout: float = 30.0               # Timeout para requests


class CircuitBreakerError(Exception):
    """Error cuando circuit breaker está abierto"""
    pass


class CircuitBreaker:
    """
    Circuit Breaker para proteger llamadas a servicios externos.

    Usage:
        breaker = CircuitBreaker(name="anthropic_api")

        @breaker.call
        def call_external_api():
            return external_api.request()

    O manualmente:
        try:
            with breaker:
                result = external_api.request()
        except CircuitBreakerError:
            # Fallback logic
            result = cached_response
    """

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ):
        """
        Initialize circuit breaker.

        Args:
            name: Nombre identificador del circuit breaker
            config: Configuración personalizada (opcional)
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = Lock()

        logger.info("circuit_breaker_initialized",
                   name=name,
                   failure_threshold=self.config.failure_threshold,
                   recovery_timeout=self.config.recovery_timeout)

    @property
    def state(self) -> CircuitState:
        """Estado actual del circuit breaker"""
        return self._state

    @property
    def is_closed(self) -> bool:
        """Circuit breaker cerrado (operación normal)"""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Circuit breaker abierto (bloqueando requests)"""
        return self._state == CircuitState.OPEN

    def _transition_to_open(self):
        """Transición a estado OPEN"""
        with self._lock:
            self._state = CircuitState.OPEN
            self._last_failure_time = time.time()
            logger.warning("circuit_breaker_opened",
                          name=self.name,
                          failure_count=self._failure_count)

    def _transition_to_half_open(self):
        """Transición a estado HALF_OPEN"""
        with self._lock:
            self._state = CircuitState.HALF_OPEN
            self._success_count = 0
            logger.info("circuit_breaker_half_open",
                       name=self.name)

    def _transition_to_closed(self):
        """Transición a estado CLOSED"""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            logger.info("circuit_breaker_closed",
                       name=self.name)

    def _should_attempt_reset(self) -> bool:
        """Verificar si debe intentar recovery"""
        if self._state != CircuitState.OPEN:
            return False

        if self._last_failure_time is None:
            return True

        time_since_failure = time.time() - self._last_failure_time
        return time_since_failure >= self.config.recovery_timeout

    def _record_success(self):
        """Registrar llamada exitosa"""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                logger.debug("circuit_breaker_success_in_half_open",
                           name=self.name,
                           success_count=self._success_count)

                if self._success_count >= self.config.success_threshold:
                    self._transition_to_closed()
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    def _record_failure(self):
        """Registrar llamada fallida"""
        with self._lock:
            self._failure_count += 1
            logger.warning("circuit_breaker_failure",
                          name=self.name,
                          failure_count=self._failure_count)

            if self._state == CircuitState.HALF_OPEN:
                # Back to OPEN on any failure in HALF_OPEN
                self._transition_to_open()
            elif self._failure_count >= self.config.failure_threshold:
                self._transition_to_open()

    def __enter__(self):
        """Context manager entry"""
        # Check if should attempt reset
        if self._should_attempt_reset():
            self._transition_to_half_open()

        # Block if circuit is open
        if self._state == CircuitState.OPEN:
            logger.error("circuit_breaker_blocking_request",
                        name=self.name,
                        state=self._state.value)
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' is OPEN. "
                f"Service temporarily unavailable."
            )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type is None:
            # Success
            self._record_success()
        else:
            # Failure
            self._record_failure()

        # Don't suppress exception
        return False

    def call(self, func: Callable) -> Callable:
        """
        Decorator para proteger función con circuit breaker.

        Usage:
            @circuit_breaker.call
            def my_function():
                return external_api.request()
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self:
                return func(*args, **kwargs)

        return wrapper

    def get_stats(self) -> dict:
        """Obtener estadísticas del circuit breaker"""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "last_failure_time": self._last_failure_time,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "success_threshold": self.config.success_threshold,
            }
        }


# ═══════════════════════════════════════════════════════════
# GLOBAL CIRCUIT BREAKERS
# ═══════════════════════════════════════════════════════════

# Circuit breaker para Anthropic Claude API
anthropic_circuit_breaker = CircuitBreaker(
    name="anthropic_api",
    config=CircuitBreakerConfig(
        failure_threshold=5,      # 5 fallos consecutivos
        recovery_timeout=60.0,    # Esperar 1 minuto antes de reintentar
        success_threshold=2,      # 2 éxitos para considerar recuperado
        timeout=30.0              # 30 segundos timeout por request
    )
)
