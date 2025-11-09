# -*- coding: utf-8 -*-
"""
[NOMBRE_AGENTE] Plugin Template
=================================

INSTRUCCIONES:
1. Reemplazar [NOMBRE_AGENTE] con nombre del agente (ej: Payroll, Projects, Purchase)
2. Reemplazar [MODULE_NAME] con módulo Odoo (ej: l10n_cl_hr_payroll)
3. Completar system_prompt con expertise específica
4. Implementar validaciones custom si aplica
5. Agregar knowledge base en archivo separado

UBICACIÓN:
/Users/pedro/Documents/odoo19/ai-service/plugins/[nombre]/plugin.py
"""
from typing import Dict, List, Optional, Any
import structlog
import json
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class [NOMBRE_AGENTE]Plugin(AIPlugin):
    """
    Plugin for [descripción del dominio].

    Expertise:
    - [Lista de expertise 1]
    - [Lista de expertise 2]
    - [Lista de expertise 3]

    Integration:
    - Odoo Module: [MODULE_NAME]
    - External APIs: [si aplica]
    - Dependencies: [si aplica]
    """

    def __init__(self):
        """Initialize plugin with lazy loading."""
        self.anthropic_client = None  # Lazy initialization
        logger.info("[nombre_agente]_plugin_initialized")

    # ═══════════════════════════════════════════════════════════
    # Required Methods (from AIPlugin base)
    # ═══════════════════════════════════════════════════════════

    def get_module_name(self) -> str:
        """
        Odoo module name.

        Examples: 'l10n_cl_dte', 'l10n_cl_hr_payroll', 'project', 'purchase'
        """
        return "[MODULE_NAME]"

    def get_display_name(self) -> str:
        """
        Human-readable name for UI/logs.

        Examples: 'Facturación Electrónica', 'Nóminas Chile', 'Proyectos'
        """
        return "[DISPLAY_NAME]"

    def get_system_prompt(self) -> str:
        """
        System prompt defining agent personality and expertise.

        IMPORTANTE: Este es el "cerebro" del agente.
        - Define cómo responde
        - Qué sabe hacer
        - Cómo se comporta
        - Cuándo derivar a otro agente

        Temperatura recomendada:
        - Chat: 0.7 (más creativo, conversacional)
        - Validación: 0.1 (más preciso, determinista)
        """
        return """Eres un asistente especializado en [DOMINIO] para Odoo 19.

**Tu Experiencia Incluye:**
- [Expertise detallada 1 - Qué sabes hacer específicamente]
- [Expertise detallada 2 - Normativas/compliance si aplica]
- [Expertise detallada 3 - Integraciones con otros módulos]
- [Expertise detallada 4 - Casos de uso comunes]
- [Mejores prácticas del dominio]

**Cómo Debes Responder:**
1. **Claro y Accionable**: Instrucciones paso a paso cuando sea apropiado
2. **Específico a Odoo**: Referencias a pantallas, wizards, y menús concretos
3. **Terminología [Local/Técnica]**: Usa vocabulario del dominio (español técnico)
4. **Ejemplos Prácticos**: Casos de uso reales cuando ayude
5. **Troubleshooting**: Si detectas error, explica causa + solución

**Formato de Respuestas:**
- Usa **negritas** para términos clave
- Usa listas numeradas para procesos paso a paso
- Usa ✅ ❌ ⚠️ para indicar estados
- Incluye comandos/rutas exactas cuando sea relevante
- Usa tablas para comparaciones o cálculos

**Casos de Uso Típicos:**
- [Pregunta frecuente 1]: [Cómo responder]
- [Pregunta frecuente 2]: [Cómo responder]
- [Pregunta frecuente 3]: [Cómo responder]

**Limitaciones:**
- Si la pregunta está fuera de tu expertise ([DOMINIO]), indícalo claramente
- Sugiere consultar al agente especializado correspondiente
- No inventes información si no estás seguro

**Integración con Otros Agentes:**
- DTE Agent → Para facturación electrónica
- Payroll Agent → Para nóminas
- Project Agent → Para gestión de proyectos
- [Otros agentes relevantes]
"""

    # ═══════════════════════════════════════════════════════════
    # Validation Method (async)
    # ═══════════════════════════════════════════════════════════

    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate [entity] data using Claude AI.

        Args:
            data: [Entity] data to validate (dict with relevant fields)
            context: Optional context:
                - company_id: int
                - history: List[Dict] (errores previos)
                - user_id: int (opcional)
                - additional_params: Dict

        Returns:
            Dict with validation result:
            {
                'confidence': float (0-100),
                'warnings': List[str] (advertencias no críticas),
                'errors': List[str] (errores críticos),
                'recommendation': str ('send' | 'review' | 'reject'),
                'suggestions': List[str] (opcional, mejoras sugeridas),
                'metadata': Dict (información adicional)
            }

        Raises:
            Exception: Si falla llamada a Claude o parsing

        Example:
            >>> plugin = [NOMBRE_AGENTE]Plugin()
            >>> result = await plugin.validate(
            ...     data={'field1': 'value1'},
            ...     context={'company_id': 1}
            ... )
            >>> assert result['confidence'] > 80
            >>> assert result['recommendation'] == 'send'
        """
        logger.info("[nombre_agente]_validation_started",
                   company_id=context.get('company_id') if context else None,
                   data_keys=list(data.keys()))

        try:
            # 1. Lazy initialize Anthropic client
            if self.anthropic_client is None:
                from config import settings
                from clients.anthropic_client import get_anthropic_client

                self.anthropic_client = get_anthropic_client(
                    settings.anthropic_api_key,
                    settings.anthropic_model
                )
                logger.info("anthropic_client_initialized")

            # 2. Extract context
            history = context.get('history', []) if context else []
            company_id = context.get('company_id') if context else None
            user_id = context.get('user_id') if context else None

            # 3. Build validation prompt
            prompt = self._build_validation_prompt(data, history, company_id)

            # 4. Call Claude (async) with circuit breaker
            try:
                from utils.circuit_breaker import anthropic_circuit_breaker, CircuitBreakerError
                from config import settings

                with anthropic_circuit_breaker:
                    response = await self.anthropic_client.client.messages.create(
                        model=self.anthropic_client.model,
                        max_tokens=settings.chat_max_tokens,
                        temperature=0.1,  # Low temperature for validation (precise)
                        messages=[{"role": "user", "content": prompt}]
                    )

            except CircuitBreakerError as e:
                logger.error("circuit_breaker_open_fallback", error=str(e))
                # Fallback: conservative response
                return {
                    'confidence': 0.0,
                    'warnings': ['AI validation service temporarily unavailable'],
                    'errors': [],
                    'recommendation': 'review',
                    'fallback': 'circuit_breaker_open'
                }

            # 5. Parse Claude's response
            response_text = response.content[0].text
            result = self._parse_validation_response(response_text)

            # 6. Track cost (Anthropic token usage)
            try:
                from utils.cost_tracker import get_cost_tracker
                tracker = get_cost_tracker()
                tracker.record_usage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    model=self.anthropic_client.model,
                    endpoint=f"/api/[nombre]/validate",
                    operation="[nombre]_validation"
                )
            except Exception as e:
                logger.warning("cost_tracking_failed", error=str(e))

            # 7. Log completion
            logger.info("[nombre_agente]_validation_completed",
                       confidence=result.get('confidence'),
                       warnings_count=len(result.get('warnings', [])),
                       errors_count=len(result.get('errors', [])),
                       recommendation=result.get('recommendation'))

            return result

        except Exception as e:
            logger.error("[nombre_agente]_validation_error",
                        error=str(e),
                        data_preview=str(data)[:200],
                        exc_info=True)
            raise

    # ═══════════════════════════════════════════════════════════
    # Helper Methods (private)
    # ═══════════════════════════════════════════════════════════

    def _build_validation_prompt(
        self,
        data: Dict,
        history: List[Dict],
        company_id: Optional[int]
    ) -> str:
        """
        Build validation prompt for Claude.

        Args:
            data: Entity data to validate
            history: Historical errors/rejections
            company_id: Company ID for context

        Returns:
            Complete prompt string
        """
        # Format data for readability
        data_formatted = json.dumps(data, indent=2, ensure_ascii=False)
        history_formatted = json.dumps(history, indent=2, ensure_ascii=False) if history else "Sin historial"

        prompt = f"""Eres un experto en {self.get_display_name()}.

Analiza estos datos y detecta posibles errores antes de procesar:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATOS A VALIDAR:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{data_formatted}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HISTORIAL DE ERRORES PREVIOS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{history_formatted}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTO:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Compañía ID: {company_id or 'N/A'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAREA DE VALIDACIÓN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Analiza los campos críticos específicos de {self.get_display_name()}
2. Verifica cálculos, formatos, y lógica de negocio
3. Compara con errores históricos (si hay)
4. Detecta patrones de problemas recurrentes
5. Genera recomendación accionable

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FORMATO DE RESPUESTA (JSON ESTRICTO):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{
  "confidence": 85.0,           // 0-100 (confianza en análisis)
  "warnings": [                 // Advertencias no críticas
    "Campo X podría mejorarse...",
    "Considera revisar Y..."
  ],
  "errors": [                   // Errores críticos que bloquean
    "Campo Z es inválido porque...",
    "Cálculo W incorrecto..."
  ],
  "recommendation": "send",     // 'send' | 'review' | 'reject'
  "suggestions": [              // Opcional: mejoras
    "Sugerencia 1...",
    "Sugerencia 2..."
  ],
  "metadata": {{                 // Opcional: info adicional
    "risk_level": "low",
    "estimated_processing_time": "2min"
  }}
}}

IMPORTANTE:
- Responde SOLO con JSON válido
- No agregues comentarios fuera del JSON
- Sé específico en warnings/errors (no genérico)
- Recommendation debe ser accionable
"""
        return prompt

    def _parse_validation_response(self, response_text: str) -> Dict:
        """
        Parse Claude's JSON response with error handling.

        Args:
            response_text: Raw response from Claude

        Returns:
            Validated dict with expected schema

        Raises:
            ValueError: If JSON invalid or missing required fields
        """
        try:
            # Extract JSON from markdown code block if present
            if "```json" in response_text:
                start = response_text.index("```json") + 7
                end = response_text.index("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                start = response_text.index("```") + 3
                end = response_text.index("```", start)
                response_text = response_text[start:end].strip()

            # Parse JSON
            result = json.loads(response_text)

            # Validate required fields
            required = ['confidence', 'warnings', 'errors', 'recommendation']
            for field in required:
                if field not in result:
                    raise ValueError(f"Missing required field: {field}")

            # Validate types
            if not isinstance(result['confidence'], (int, float)):
                raise ValueError(f"confidence must be number, got {type(result['confidence'])}")
            if not isinstance(result['warnings'], list):
                raise ValueError(f"warnings must be list, got {type(result['warnings'])}")
            if not isinstance(result['errors'], list):
                raise ValueError(f"errors must be list, got {type(result['errors'])}")
            if result['recommendation'] not in ['send', 'review', 'reject']:
                raise ValueError(f"Invalid recommendation: {result['recommendation']}")

            # Normalize confidence to 0-100 range
            if result['confidence'] < 0:
                result['confidence'] = 0.0
            elif result['confidence'] > 100:
                result['confidence'] = 100.0

            return result

        except json.JSONDecodeError as e:
            logger.error("json_decode_error",
                        error=str(e),
                        response_preview=response_text[:300])
            # Fallback: conservative response
            return {
                'confidence': 50.0,
                'warnings': [f'Error parsing AI response: {str(e)}'],
                'errors': [],
                'recommendation': 'review',
                'claude_raw_response': response_text[:500]
            }
        except Exception as e:
            logger.error("validation_parse_error",
                        error=str(e),
                        response_preview=response_text[:300])
            return {
                'confidence': 50.0,
                'warnings': [f'Unexpected error: {str(e)}'],
                'errors': [],
                'recommendation': 'review'
            }

    # ═══════════════════════════════════════════════════════════
    # Additional Methods (opcional, según necesidad)
    # ═══════════════════════════════════════════════════════════

    async def generate_suggestions(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate intelligent suggestions based on context.

        Example use cases:
        - Suggest [entity] based on historical data
        - Recommend best practices
        - Predict next actions

        Args:
            context: Context data (company_id, user_input, etc.)

        Returns:
            Dict with suggestions:
            {
                'suggestions': List[Dict],
                'confidence': float,
                'reasoning': str (opcional)
            }
        """
        logger.info("[nombre_agente]_suggestions_started",
                   context_keys=list(context.keys()))

        # TODO: Implement suggestion logic
        # Similar to analytics/project_matcher_claude.py

        return {
            'suggestions': [],
            'confidence': 0.0,
            'reasoning': 'Not implemented yet'
        }

    async def analyze(
        self,
        data: Dict[str, Any],
        analysis_type: str = "general"
    ) -> Dict[str, Any]:
        """
        Perform deep analysis on data.

        Example use cases:
        - Analyze trends
        - Detect anomalies
        - Generate insights

        Args:
            data: Data to analyze
            analysis_type: Type of analysis ('general', 'trend', 'anomaly', etc.)

        Returns:
            Dict with analysis results
        """
        logger.info("[nombre_agente]_analysis_started",
                   analysis_type=analysis_type)

        # TODO: Implement analysis logic

        return {
            'insights': [],
            'anomalies': [],
            'trends': []
        }


# ═══════════════════════════════════════════════════════════
# Singleton Instance (lazy loading)
# ═══════════════════════════════════════════════════════════

_plugin_instance: Optional[[NOMBRE_AGENTE]Plugin] = None

def get_[nombre_agente]_plugin() -> [NOMBRE_AGENTE]Plugin:
    """
    Get singleton instance of [NOMBRE_AGENTE]Plugin.

    Returns:
        Plugin instance
    """
    global _plugin_instance
    if _plugin_instance is None:
        _plugin_instance = [NOMBRE_AGENTE]Plugin()
    return _plugin_instance
