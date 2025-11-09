# -*- coding: utf-8 -*-
"""
Unit Tests - LLM Helpers
=========================

Tests para utilidades de procesamiento de respuestas LLM.
"""

import pytest
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from utils.llm_helpers import (
    extract_json_from_llm_response,
    validate_llm_json_schema,
    sanitize_llm_response
)


class TestExtractJSON:
    """Tests para extract_json_from_llm_response"""
    
    def test_plain_json(self):
        """Test con JSON puro."""
        text = '{"status": "ok", "value": 42}'
        result = extract_json_from_llm_response(text)
        
        assert result == {"status": "ok", "value": 42}
    
    def test_json_in_markdown(self):
        """Test con JSON en bloque markdown."""
        text = '''```json
{
  "status": "ok",
  "value": 42
}
```'''
        result = extract_json_from_llm_response(text)
        
        assert result == {"status": "ok", "value": 42}
    
    def test_json_with_text_before_after(self):
        """Test con texto antes y después."""
        text = '''Here is the result:
{"status": "ok", "value": 42}
Hope this helps!'''
        result = extract_json_from_llm_response(text)
        
        assert result == {"status": "ok", "value": 42}
    
    def test_json_array(self):
        """Test con array JSON."""
        text = '[{"id": 1}, {"id": 2}]'
        result = extract_json_from_llm_response(text)
        
        assert result == [{"id": 1}, {"id": 2}]
    
    def test_invalid_no_json(self):
        """Test con texto sin JSON."""
        text = "This is just plain text without JSON"
        
        with pytest.raises(ValueError, match="No JSON found"):
            extract_json_from_llm_response(text)
    
    def test_invalid_malformed_json(self):
        """Test con JSON malformado."""
        text = '{"status": "ok", "value": }'  # Falta valor
        
        with pytest.raises(ValueError, match="Invalid JSON"):
            extract_json_from_llm_response(text)


class TestValidateJSONSchema:
    """Tests para validate_llm_json_schema"""
    
    def test_valid_schema(self):
        """Test con schema válido."""
        data = {
            "confidence": 95,
            "warnings": [],
            "recommendation": "send"
        }
        
        result = validate_llm_json_schema(
            data,
            required_fields=["confidence", "warnings"],
            field_types={"confidence": (int, float), "warnings": list}
        )
        
        assert result == data
    
    def test_missing_required_field(self):
        """Test con campo requerido faltante."""
        data = {"confidence": 95}
        
        with pytest.raises(ValueError, match="missing required fields"):
            validate_llm_json_schema(
                data,
                required_fields=["confidence", "warnings"]
            )
    
    def test_wrong_field_type(self):
        """Test con tipo de campo incorrecto."""
        data = {"confidence": "95"}  # String en vez de número
        
        with pytest.raises(ValueError, match="wrong type"):
            validate_llm_json_schema(
                data,
                required_fields=["confidence"],
                field_types={"confidence": (int, float)}
            )


class TestSanitizeResponse:
    """Tests para sanitize_llm_response"""
    
    def test_normal_text(self):
        """Test con texto normal."""
        text = "Normal response text"
        result = sanitize_llm_response(text)
        
        assert result == "Normal response text"
    
    def test_multiple_spaces(self):
        """Test normalización de espacios."""
        text = "Text  with    multiple     spaces"
        result = sanitize_llm_response(text)
        
        assert result == "Text with multiple spaces"
    
    def test_truncate_long_text(self):
        """Test truncado de texto muy largo."""
        text = "x" * 15000
        result = sanitize_llm_response(text, max_length=10000)
        
        assert len(result) == 10000
    
    def test_remove_control_chars(self):
        """Test eliminación caracteres de control."""
        text = "Text\x00with\x01control\x02chars"
        result = sanitize_llm_response(text)
        
        assert "\x00" not in result
        assert "\x01" not in result
        assert result == "Textwithcontrolchars"

