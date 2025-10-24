# -*- coding: utf-8 -*-
"""
Cliente Async para Anthropic Claude API con Circuit Breaker

Incluye:
- AsyncAnthropic para concurrencia mejorada
- Circuit breaker para resiliencia
- Retry logic con exponential backoff
- Caching de respuestas
- Fallback graceful

FASE 3: Async & Performance - 2025-10-23
Gap Closure Sprint
"""

import anthropic
import structlog
from typing import Dict, Any, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from utils.cache import cache_method
from utils.circuit_breaker import anthropic_circuit_breaker, CircuitBreakerError

logger = structlog.get_logger()


class AnthropicClient:
    """
    Cliente Async para interactuar con Claude API.

    IMPORTANTE: Usa AsyncAnthropic para mejor throughput y concurrencia.
    Todos los métodos son async y deben ser llamados con await.
    """

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5-20250929"):
        """
        Inicializa el cliente async de Anthropic.

        Args:
            api_key: API key de Anthropic
            model: Modelo de Claude a utilizar (default: claude-sonnet-4-5-20250929)
        """
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

        logger.info("anthropic_async_client_initialized", model=model)
    
    # NOTA: cache_method no soporta async methods actualmente
    # TODO: Implementar async cache decorator en FASE 3
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((
            anthropic.RateLimitError,
            anthropic.APIConnectionError,
            anthropic.InternalServerError
        )),
        before_sleep=lambda retry_state: logger.warning(
            "anthropic_retry",
            attempt=retry_state.attempt_number
        )
    )
    async def validate_dte(self, dte_data: Dict[str, Any], history: List[Dict]) -> Dict[str, Any]:
        """
        Valida un DTE usando Claude con retry automático (ASYNC).

        Analiza los datos del DTE y compara con historial de rechazos
        para detectar posibles errores.

        Args:
            dte_data: Datos del DTE a validar
            history: Historial de rechazos previos

        Returns:
            Dict con resultado de validación

        Note:
            Este método es async. Debe ser llamado con await.
        """
        from utils.llm_helpers import extract_json_from_llm_response, validate_llm_json_schema
        from utils.cache import cache_llm_response
        from config import settings

        logger.info("claude_validation_started")

        try:
            # Construir prompt
            prompt = self._build_validation_prompt(dte_data, history)

            # Llamar a Claude con circuit breaker protection (ASYNC)
            try:
                with anthropic_circuit_breaker:
                    message = await self.client.messages.create(
                        model=self.model,
                        max_tokens=settings.dte_validation_max_tokens,
                        temperature=0.1,
                        messages=[
                            {"role": "user", "content": prompt}
                        ]
                    )
            except CircuitBreakerError as e:
                logger.error("circuit_breaker_open_fallback",
                           error=str(e))
                # Fallback graceful: retornar respuesta conservadora
                return {
                    'confidence': 0.0,
                    'warnings': [
                        'AI validation service temporarily unavailable',
                        'Recommend manual review before sending to SII'
                    ],
                    'errors': [],
                    'recommendation': 'review',
                    'fallback': 'circuit_breaker_open'
                }

            # Parsear respuesta con validación
            response_text = message.content[0].text

            # Track token usage and cost
            try:
                from utils.cost_tracker import get_cost_tracker
                tracker = get_cost_tracker()
                tracker.record_usage(
                    input_tokens=message.usage.input_tokens,
                    output_tokens=message.usage.output_tokens,
                    model=self.model,
                    endpoint="/api/dte/validate",
                    operation="dte_validation"
                )
            except Exception as e:
                logger.warning("cost_tracking_failed", error=str(e))

            try:
                result = extract_json_from_llm_response(response_text)
                
                # Validar schema esperado
                result = validate_llm_json_schema(
                    result,
                    required_fields=['confidence', 'warnings', 'errors', 'recommendation'],
                    field_types={
                        'confidence': (int, float),
                        'warnings': list,
                        'errors': list,
                        'recommendation': str
                    }
                )
                
                logger.info("claude_validation_completed",
                           confidence=result['confidence'],
                           warnings_count=len(result['warnings']),
                           errors_count=len(result['errors']))
                
                return result
                
            except (ValueError, KeyError) as e:
                logger.error("claude_json_parse_error",
                           error=str(e),
                           response_preview=response_text[:300])
                
                # Fallback: respuesta neutral
                return {
                    'confidence': 50.0,
                    'warnings': [f'Error parsing AI response: {str(e)}'],
                    'errors': [],
                    'recommendation': 'review',
                    'claude_response': response_text[:500]
                }
            
        except anthropic.APIError as e:
            logger.error("claude_api_error", error=str(e), status_code=getattr(e, 'status_code', None))
            raise
        except Exception as e:
            logger.error("claude_validation_error", error=str(e))
            raise
    
    def _build_validation_prompt(self, dte_data: Dict, history: List[Dict]) -> str:
        """Construye prompt para validación"""
        
        prompt = f"""Eres un experto en facturación electrónica chilena (DTEs).

Analiza este DTE y detecta posibles errores antes de enviarlo al SII:

DATOS DEL DTE:
{dte_data}

HISTORIAL DE RECHAZOS PREVIOS:
{history if history else 'Sin historial'}

TAREA:
1. Analiza el RUT del emisor y receptor
2. Verifica montos y cálculos
3. Compara con rechazos previos
4. Detecta patrones de error

RESPONDE EN FORMATO JSON:
{{
  "confidence": 0-100,
  "warnings": ["lista de advertencias"],
  "errors": ["lista de errores"],
  "recommendation": "send" o "review"
}}
"""
        return prompt


# Instancia global (lazy loading)
_client: Optional[AnthropicClient] = None

def get_anthropic_client(api_key: str, model: str) -> AnthropicClient:
    """Obtiene instancia singleton del cliente"""
    global _client
    if _client is None:
        _client = AnthropicClient(api_key, model)
    return _client

