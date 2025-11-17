"""
Circuit Breaker Pattern
=======================

Implementa circuit breaker para proteger llamadas al SII.
Previene saturación del SII durante caídas o timeouts.

Based on Odoo 18: l10n_cl_fe/models/circuit_breaker.py

States:
- CLOSED: Normal operation, todas las llamadas pasan
- OPEN: SII no disponible, llamadas fallan rápido (fail-fast)
- HALF_OPEN: Probando recuperación, 1 llamada de prueba

Pattern: Martin Fowler Circuit Breaker
"""

import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Any, Optional
import redis
import json

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Estados del circuit breaker."""
    CLOSED = "CLOSED"        # Normal operation
    OPEN = "OPEN"            # Failing, block all requests
    HALF_OPEN = "HALF_OPEN"  # Testing recovery


class CircuitBreakerConfig:
    """Configuración del circuit breaker."""

    def __init__(
        self,
        failure_threshold: int = 5,          # Failures before opening
        success_threshold: int = 2,          # Successes to close from half-open
        timeout_seconds: int = 60,           # Time to wait before half-open
        half_open_max_calls: int = 1         # Max calls in half-open state
    ):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout_seconds = timeout_seconds
        self.half_open_max_calls = half_open_max_calls


class CircuitBreaker:
    """
    Circuit Breaker para proteger llamadas al SII.

    Features:
    - State machine: CLOSED → OPEN → HALF_OPEN → CLOSED
    - Automatic recovery attempts
    - Redis-backed state (shared across workers)
    - Per-operation circuit breakers (send_dte, query_status, etc)
    - Metrics tracking
    """

    REDIS_KEY_PREFIX = "circuit_breaker:"

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        redis_host: str = 'redis',
        redis_port: int = 6379,
        redis_db: int = 0
    ):
        """
        Inicializa circuit breaker.

        Args:
            name: Nombre del circuit breaker (ej: 'sii_send_dte')
            config: Configuración (opcional, usa defaults)
            redis_host: Host de Redis
            redis_port: Puerto de Redis
            redis_db: Base de datos Redis
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()

        # Redis client para estado compartido
        try:
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                decode_responses=True,
                socket_connect_timeout=5
            )
            self.redis_client.ping()
            logger.info(f"Circuit breaker '{name}' initialized with Redis")
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed for circuit breaker '{name}': {e}")
            raise

        # Initialize state if not exists
        self._initialize_state()

    def _initialize_state(self):
        """Inicializa estado en Redis si no existe."""
        state_key = f"{self.REDIS_KEY_PREFIX}{self.name}:state"

        if not self.redis_client.exists(state_key):
            initial_state = {
                'state': CircuitState.CLOSED.value,
                'failure_count': 0,
                'success_count': 0,
                'last_failure_time': None,
                'opened_at': None,
                'half_open_calls': 0
            }
            self.redis_client.set(state_key, json.dumps(initial_state))
            logger.info(f"Circuit breaker '{self.name}' initialized to CLOSED")

    def _get_state(self) -> dict:
        """Obtiene estado actual desde Redis."""
        state_key = f"{self.REDIS_KEY_PREFIX}{self.name}:state"
        state_json = self.redis_client.get(state_key)

        if state_json:
            return json.loads(state_json)
        else:
            # Recreate if lost
            self._initialize_state()
            return self._get_state()

    def _set_state(self, state: dict):
        """Guarda estado en Redis."""
        state_key = f"{self.REDIS_KEY_PREFIX}{self.name}:state"
        self.redis_client.set(state_key, json.dumps(state))

    def _transition_to_open(self, state: dict):
        """Transición a estado OPEN."""
        state['state'] = CircuitState.OPEN.value
        state['opened_at'] = datetime.now().isoformat()
        self._set_state(state)

        logger.warning(
            f"Circuit breaker '{self.name}' opened",
            extra={
                'failure_count': state['failure_count'],
                'threshold': self.config.failure_threshold
            }
        )

    def _transition_to_half_open(self, state: dict):
        """Transición a estado HALF_OPEN."""
        state['state'] = CircuitState.HALF_OPEN.value
        state['half_open_calls'] = 0
        state['success_count'] = 0
        self._set_state(state)

        logger.info(f"Circuit breaker '{self.name}' half-opened (testing recovery)")

    def _transition_to_closed(self, state: dict):
        """Transición a estado CLOSED."""
        state['state'] = CircuitState.CLOSED.value
        state['failure_count'] = 0
        state['success_count'] = 0
        state['opened_at'] = None
        self._set_state(state)

        logger.info(f"Circuit breaker '{self.name}' closed (recovered)")

    def _should_attempt_reset(self, state: dict) -> bool:
        """Verifica si debe intentar reset desde OPEN a HALF_OPEN."""
        if state['state'] != CircuitState.OPEN.value:
            return False

        if not state['opened_at']:
            return False

        opened_at = datetime.fromisoformat(state['opened_at'])
        timeout = timedelta(seconds=self.config.timeout_seconds)

        return datetime.now() >= opened_at + timeout

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Ejecuta función protegida por circuit breaker.

        Args:
            func: Función a ejecutar
            *args: Argumentos posicionales
            **kwargs: Argumentos con nombre

        Returns:
            Resultado de la función

        Raises:
            CircuitBreakerOpenError: Si circuit está OPEN
            Exception: Si la función falla
        """
        state = self._get_state()

        # State machine logic
        if state['state'] == CircuitState.OPEN.value:
            # Check if timeout elapsed
            if self._should_attempt_reset(state):
                self._transition_to_half_open(state)
                state = self._get_state()
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is OPEN. "
                    f"SII unavailable. Retry after {self.config.timeout_seconds}s"
                )

        if state['state'] == CircuitState.HALF_OPEN.value:
            # Limit calls in half-open state
            if state['half_open_calls'] >= self.config.half_open_max_calls:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is HALF_OPEN. "
                    f"Max test calls reached. Wait for current call to complete."
                )

            # Increment half-open calls counter
            state['half_open_calls'] += 1
            self._set_state(state)

        # Execute function
        try:
            result = func(*args, **kwargs)
            self._on_success(state)
            return result

        except Exception as e:
            self._on_failure(state, e)
            raise

    def _on_success(self, state: dict):
        """Maneja éxito de llamada."""
        if state['state'] == CircuitState.HALF_OPEN.value:
            # Increment success counter
            state['success_count'] += 1

            # Check if should close
            if state['success_count'] >= self.config.success_threshold:
                self._transition_to_closed(state)
            else:
                self._set_state(state)

        elif state['state'] == CircuitState.CLOSED.value:
            # Reset failure counter on success
            if state['failure_count'] > 0:
                state['failure_count'] = 0
                self._set_state(state)

    def _on_failure(self, state: dict, exception: Exception):
        """Maneja fallo de llamada."""
        state['last_failure_time'] = datetime.now().isoformat()

        if state['state'] == CircuitState.HALF_OPEN.value:
            # Immediate open on failure in half-open
            self._transition_to_open(state)

        elif state['state'] == CircuitState.CLOSED.value:
            # Increment failure counter
            state['failure_count'] += 1

            # Check if should open
            if state['failure_count'] >= self.config.failure_threshold:
                self._transition_to_open(state)
            else:
                self._set_state(state)

        logger.error(
            f"Circuit breaker '{self.name}' recorded failure",
            extra={
                'state': state['state'],
                'failure_count': state['failure_count'],
                'error': str(exception)
            }
        )

    def get_state(self) -> CircuitState:
        """Obtiene estado actual del circuit breaker."""
        state = self._get_state()
        return CircuitState(state['state'])

    def get_stats(self) -> dict:
        """Obtiene estadísticas del circuit breaker."""
        state = self._get_state()

        return {
            'name': self.name,
            'state': state['state'],
            'failure_count': state['failure_count'],
            'success_count': state['success_count'],
            'failure_threshold': self.config.failure_threshold,
            'success_threshold': self.config.success_threshold,
            'timeout_seconds': self.config.timeout_seconds,
            'opened_at': state.get('opened_at'),
            'last_failure_time': state.get('last_failure_time')
        }

    def reset(self):
        """Reset manual del circuit breaker a CLOSED."""
        state = self._get_state()
        self._transition_to_closed(state)
        logger.info(f"Circuit breaker '{self.name}' manually reset")


class CircuitBreakerOpenError(Exception):
    """Excepción cuando circuit breaker está OPEN."""
    pass


# ═══════════════════════════════════════════════════════════
# GLOBAL CIRCUIT BREAKERS
# ═══════════════════════════════════════════════════════════

# Singleton instances por operación SII
_circuit_breakers = {}


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """
    Obtiene circuit breaker por nombre (singleton pattern).

    Args:
        name: Nombre del circuit breaker
        config: Configuración (opcional)

    Returns:
        CircuitBreaker instance
    """
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name, config)

    return _circuit_breakers[name]


def get_all_circuit_states() -> dict:
    """
    Obtiene estado de todos los circuit breakers.

    Returns:
        Dict con estados de todos los breakers
    """
    return {
        name: breaker.get_state().value
        for name, breaker in _circuit_breakers.items()
    }
