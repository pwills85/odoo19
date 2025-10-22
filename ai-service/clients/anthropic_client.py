# -*- coding: utf-8 -*-
"""
Cliente para Anthropic Claude API
"""

import anthropic
import structlog
from typing import Dict, Any, List

logger = structlog.get_logger()


class AnthropicClient:
    """Cliente para interactuar con Claude API"""
    
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        """
        Inicializa el cliente de Anthropic.
        
        Args:
            api_key: API key de Anthropic
            model: Modelo de Claude a utilizar
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        
        logger.info("anthropic_client_initialized", model=model)
    
    def validate_dte(self, dte_data: Dict[str, Any], history: List[Dict]) -> Dict[str, Any]:
        """
        Valida un DTE usando Claude.
        
        Analiza los datos del DTE y compara con historial de rechazos
        para detectar posibles errores.
        
        Args:
            dte_data: Datos del DTE a validar
            history: Historial de rechazos previos
        
        Returns:
            Dict con resultado de validación
        """
        logger.info("claude_validation_started")
        
        try:
            # Construir prompt
            prompt = self._build_validation_prompt(dte_data, history)
            
            # Llamar a Claude
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Parsear respuesta
            response_text = message.content[0].text
            
            # TODO: Parsear JSON de respuesta de Claude
            # Por ahora, mock response
            
            logger.info("claude_validation_completed")
            
            return {
                'confidence': 95.0,
                'warnings': [],
                'errors': [],
                'recommendation': 'send',
                'claude_response': response_text
            }
            
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

