# -*- coding: utf-8 -*-
"""
LLM Response Helpers
====================

Utilidades para procesar respuestas de LLMs (Claude, GPT-4).
Maneja casos edge como JSON en markdown, texto extra, etc.
"""

import re
import json
from typing import Any, Dict
import structlog

logger = structlog.get_logger(__name__)


def extract_json_from_llm_response(text: str) -> Dict[str, Any]:
    """
    Extrae y parsea JSON de respuesta LLM.
    
    Maneja múltiples formatos:
    - JSON puro: {"key": "value"}
    - JSON en markdown: ```json {...} ```
    - JSON con texto antes/después
    - JSON con espacios/saltos de línea extras
    
    Args:
        text: Respuesta completa del LLM
    
    Returns:
        Dict parseado
    
    Raises:
        ValueError: Si no se encuentra JSON válido
    
    Examples:
        >>> extract_json_from_llm_response('{"status": "ok"}')
        {'status': 'ok'}
        
        >>> extract_json_from_llm_response('```json\\n{"status": "ok"}\\n```')
        {'status': 'ok'}
        
        >>> extract_json_from_llm_response('Here is the result: {"status": "ok"} Hope this helps!')
        {'status': 'ok'}
    """
    if not text or not isinstance(text, str):
        raise ValueError(f"Invalid input: expected string, got {type(text)}")
    
    # 1. Intentar encontrar JSON en bloque markdown
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
    if json_match:
        text = json_match.group(1)
        logger.debug("json_extracted_from_markdown")
    
    # 2. Buscar primer { y último } (maneja texto antes/después)
    start = text.find('{')
    end = text.rfind('}')
    
    if start == -1 or end == -1 or start > end:
        # No hay {} válidos, intentar con []
        start = text.find('[')
        end = text.rfind(']')
        
        if start == -1 or end == -1 or start > end:
            logger.error("no_json_found", text_preview=text[:200])
            raise ValueError(f"No JSON found in LLM response. Preview: {text[:200]}")
    
    # 3. Extraer substring JSON
    json_str = text[start:end+1].strip()
    
    # 4. Parsear
    try:
        result = json.loads(json_str)
        logger.debug("json_parsed_successfully", 
                    keys=list(result.keys()) if isinstance(result, dict) else len(result))
        return result
        
    except json.JSONDecodeError as e:
        logger.error("json_parse_failed",
                    error=str(e),
                    json_preview=json_str[:300])
        raise ValueError(
            f"Invalid JSON in LLM response: {e}\n"
            f"Position: {e.pos}\n"
            f"JSON preview: {json_str[:300]}"
        )


def validate_llm_json_schema(
    data: Dict[str, Any],
    required_fields: list,
    field_types: Dict[str, type] = None
) -> Dict[str, Any]:
    """
    Valida que JSON de LLM tenga campos requeridos y tipos correctos.
    
    Args:
        data: Dict parseado de LLM
        required_fields: Lista de campos obligatorios
        field_types: Dict opcional con tipos esperados {campo: tipo}
    
    Returns:
        Dict validado (mismo input si pasa validación)
    
    Raises:
        ValueError: Si falta campo o tipo incorrecto
    
    Example:
        >>> validate_llm_json_schema(
        ...     {"confidence": 95, "warnings": []},
        ...     required_fields=["confidence", "warnings"],
        ...     field_types={"confidence": (int, float), "warnings": list}
        ... )
        {'confidence': 95, 'warnings': []}
    """
    # Validar campos requeridos
    missing_fields = [f for f in required_fields if f not in data]
    if missing_fields:
        raise ValueError(
            f"LLM response missing required fields: {', '.join(missing_fields)}\n"
            f"Received fields: {', '.join(data.keys())}"
        )
    
    # Validar tipos si especificados
    if field_types:
        for field, expected_type in field_types.items():
            if field in data:
                value = data[field]
                
                # Permitir múltiples tipos (ej: int o float)
                if isinstance(expected_type, tuple):
                    if not isinstance(value, expected_type):
                        raise ValueError(
                            f"Field '{field}' has wrong type. "
                            f"Expected {expected_type}, got {type(value).__name__}"
                        )
                else:
                    if not isinstance(value, expected_type):
                        raise ValueError(
                            f"Field '{field}' has wrong type. "
                            f"Expected {expected_type.__name__}, got {type(value).__name__}"
                        )
    
    return data


def sanitize_llm_response(text: str, max_length: int = 10000) -> str:
    """
    Sanitiza respuesta LLM antes de procesamiento.
    
    - Limita longitud (evita responses gigantes)
    - Elimina caracteres de control
    - Normaliza espacios
    
    Args:
        text: Respuesta LLM
        max_length: Longitud máxima permitida
    
    Returns:
        Texto sanitizado
    """
    if not text:
        return ""
    
    # Limitar longitud
    if len(text) > max_length:
        logger.warning("llm_response_truncated",
                      original_length=len(text),
                      max_length=max_length)
        text = text[:max_length]
    
    # Eliminar caracteres de control (excepto \n, \r, \t)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    
    # Normalizar múltiples espacios
    text = re.sub(r' +', ' ', text)
    
    # Normalizar múltiples saltos de línea
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    return text.strip()

