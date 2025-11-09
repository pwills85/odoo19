# -*- coding: utf-8 -*-
"""
Integration Tests - Critical Endpoints
=======================================

Tests de integración para endpoints críticos del ai-service.
Verifica contratos de API con Odoo.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from main import app
from config import settings


@pytest.fixture
def client():
    """FastAPI test client"""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Valid auth headers"""
    return {"Authorization": f"Bearer {settings.api_key}"}


class TestDTEValidationEndpoint:
    """Tests para /api/ai/validate"""
    
    def test_validate_dte_success(self, client, auth_headers):
        """Test validación exitosa con datos mínimos."""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {
                    "tipo_dte": "33",
                    "rut_emisor": "12345678-9",
                    "rut_receptor": "98765432-1",
                    "monto_total": 119000
                },
                "company_id": 1,
                "history": []
            },
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verificar contrato con Odoo
        assert "confidence" in data
        assert "warnings" in data
        assert "errors" in data
        assert "recommendation" in data
        assert isinstance(data["confidence"], (int, float))
        assert isinstance(data["warnings"], list)
        assert isinstance(data["errors"], list)
        assert data["recommendation"] in ["send", "review", "reject"]  # Valid recommendations
    
    def test_validate_dte_invalid_tipo(self, client, auth_headers):
        """Test con tipo DTE inválido."""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {
                    "tipo_dte": "99",  # Tipo inválido
                },
                "company_id": 1
            },
            headers=auth_headers
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_validate_dte_negative_company_id(self, client, auth_headers):
        """Test con company_id negativo."""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {"tipo_dte": "33"},
                "company_id": -1  # Inválido
            },
            headers=auth_headers
        )
        
        assert response.status_code == 422
    
    def test_validate_dte_unauthorized(self, client):
        """Test sin autenticación."""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {"tipo_dte": "33"},
                "company_id": 1
            }
        )
        
        assert response.status_code == 403


class TestPOMatchingEndpoint:
    """Tests para /api/ai/reception/match_po"""
    
    def test_match_po_endpoint_exists(self, client, auth_headers):
        """Verificar que endpoint existe y responde."""
        response = client.post(
            "/api/ai/reception/match_po",
            json={
                "dte_data": {"tipo_dte": "33"},
                "company_id": 1,
                "emisor_rut": "12345678-9",
                "monto_total": 100000,
                "fecha_emision": "2025-10-23"
            },
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verificar contrato
        assert "matched_po_id" in data
        assert "confidence" in data
        assert "line_matches" in data
        assert "reasoning" in data
    
    def test_match_po_invalid_rut(self, client, auth_headers):
        """Test con RUT inválido."""
        response = client.post(
            "/api/ai/reception/match_po",
            json={
                "dte_data": {},
                "company_id": 1,
                "emisor_rut": "12345678",  # Sin dígito verificador
                "monto_total": 100000
            },
            headers=auth_headers
        )
        
        assert response.status_code == 422
    
    def test_match_po_invalid_monto(self, client, auth_headers):
        """Test con monto negativo."""
        response = client.post(
            "/api/ai/reception/match_po",
            json={
                "dte_data": {},
                "company_id": 1,
                "emisor_rut": "12345678-9",
                "monto_total": -100  # Negativo inválido
            },
            headers=auth_headers
        )
        
        assert response.status_code == 422


class TestAnalyticsEndpoint:
    """Tests para /api/ai/analytics/suggest_project"""
    
    def test_suggest_project_success(self, client, auth_headers):
        """Test sugerencia exitosa."""
        response = client.post(
            "/api/ai/analytics/suggest_project",
            json={
                "partner_id": 1,
                "partner_vat": "12345678-9",
                "partner_name": "Proveedor Test",
                "invoice_lines": [
                    {"description": "Servicio X", "quantity": 1, "price": 100000}
                ],
                "company_id": 1,
                "available_projects": [
                    {"id": 1, "name": "Proyecto A", "state": "active"}
                ]
            },
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "project_id" in data
        assert "confidence" in data
        assert "reasoning" in data


class TestChatEndpoints:
    """Tests para endpoints de chat"""
    
    def test_create_session(self, client, auth_headers):
        """Test creación sesión."""
        response = client.post(
            "/api/chat/session/new",
            json={
                "user_context": {
                    "company_name": "Test SpA",
                    "user_role": "Contador"
                }
            },
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "session_id" in data
        assert "welcome_message" in data
        assert len(data["session_id"]) > 0
    
    def test_send_message_invalid_long(self, client, auth_headers):
        """Test mensaje demasiado largo."""
        response = client.post(
            "/api/chat/message",
            json={
                "message": "x" * 10000,  # 10k caracteres
                "session_id": "test-session-123"
            },
            headers=auth_headers
        )
        
        assert response.status_code == 422


class TestHealthEndpoint:
    """Tests para /health"""
    
    def test_health_check(self, client):
        """Test health check sin autenticación."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert "status" in data
        assert data["status"] == "healthy"
        # Check anthropic is configured in dependencies
        assert "dependencies" in data
        assert "anthropic" in data["dependencies"]
        assert data["dependencies"]["anthropic"]["status"] == "configured"


class TestRateLimiting:
    """Tests de rate limiting"""
    
    def test_rate_limit_validation_endpoint(self, client, auth_headers):
        """Test que rate limiting funciona en /api/ai/validate."""
        
        # Hacer 25 requests rápidos (límite es 20/min)
        responses = []
        for i in range(25):
            resp = client.post(
                "/api/ai/validate",
                json={
                    "dte_data": {"tipo_dte": "33"},
                    "company_id": 1
                },
                headers=auth_headers
            )
            responses.append(resp.status_code)
        
        # Verificar que algunos fueron rate limited
        # Nota: En tests el IP es siempre el mismo
        assert 429 in responses, "Rate limiting no funcionó"
        
        # Los primeros 20 deben ser exitosos (o errores de validación)
        successful_or_validation_errors = [
            r for r in responses[:20] 
            if r in [200, 422, 500]
        ]
        assert len(successful_or_validation_errors) >= 15

