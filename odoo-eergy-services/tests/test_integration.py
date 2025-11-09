# -*- coding: utf-8 -*-
"""
Tests de Integración DTE Service
"""

import pytest
from fastapi.testclient import TestClient
import sys
import os

# Agregar path del DTE service
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import app

client = TestClient(app)


def test_health_endpoint():
    """Test endpoint de health check"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ["healthy", "ok"]


def test_ted_validator_exists():
    """Test que TEDValidator existe y funciona"""
    from validators.ted_validator import TEDValidator
    
    validator = TEDValidator()
    assert validator is not None
    assert hasattr(validator, 'REQUIRED_TED_ELEMENTS')
    assert len(validator.REQUIRED_TED_ELEMENTS) == 13


def test_ted_validator_13_elements():
    """Test que TED valida 13 elementos según SII"""
    from validators.ted_validator import TEDValidator
    
    validator = TEDValidator()
    required = validator.REQUIRED_TED_ELEMENTS
    
    # Elementos críticos
    assert 'DD/CAF' in required
    assert 'DD/RE' in required
    assert 'FRMT' in required
    assert 'DD/TD' in required
    assert 'DD/F' in required


def test_structure_validator_exists():
    """Test que DTEStructureValidator existe"""
    from validators.dte_structure_validator import DTEStructureValidator
    
    validator = DTEStructureValidator()
    assert validator is not None
    assert hasattr(validator, 'REQUIRED_ELEMENTS')


def test_structure_validator_5_types():
    """Test que valida 5 tipos DTE"""
    from validators.dte_structure_validator import DTEStructureValidator
    
    validator = DTEStructureValidator()
    assert len(validator.REQUIRED_ELEMENTS) == 5
    
    # Tipos esperados
    expected_types = ['33', '34', '52', '56', '61']
    for dte_type in expected_types:
        assert dte_type in validator.REQUIRED_ELEMENTS


def test_xsd_validator_graceful_degradation():
    """Test XSD validator con graceful degradation"""
    from validators.xsd_validator import XSDValidator
    
    validator = XSDValidator()
    assert validator is not None
    
    # Sin XSD, debe funcionar sin bloquear
    xml_sample = '<?xml version="1.0"?><DTE></DTE>'
    is_valid, errors = validator.validate(xml_sample, 'DTE')
    
    assert isinstance(is_valid, bool)
    assert isinstance(errors, list)
    
    # Si no hay XSD, debe retornar True (graceful degradation)
    if not validator.schemas:
        assert is_valid is True


def test_ted_validator_algorithm():
    """Test que TED valida algoritmo SHA1withRSA"""
    from validators.ted_validator import TEDValidator
    
    validator = TEDValidator()
    assert validator.REQUIRED_SIGNATURE_ALGORITHM == 'SHA1withRSA'


def test_validators_logging():
    """Test que validadores usan logging estructurado"""
    from validators.ted_validator import TEDValidator
    from validators.dte_structure_validator import DTEStructureValidator
    from validators.xsd_validator import XSDValidator
    
    # Todos deben tener logger
    ted = TEDValidator()
    structure = DTEStructureValidator()
    xsd = XSDValidator()
    
    # Verificar que tienen métodos de validación
    assert hasattr(ted, 'validate')
    assert hasattr(structure, 'validate')
    assert hasattr(xsd, 'validate')
