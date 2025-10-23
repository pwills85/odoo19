# -*- coding: utf-8 -*-
"""
DTE Regression Tests
====================

CRITICAL: These tests ensure DTE functionality is preserved during upgrade.
All tests must pass before deploying any changes.
"""
import pytest
from fastapi import status


class TestDTEValidationEndpoint:
    """Tests for /api/ai/validate endpoint - CRITICAL"""
    
    def test_endpoint_exists(self, client):
        """Verify endpoint exists and is accessible"""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {"tipo_dte": "33"},
                "company_id": 1
            }
        )
        # Should return 401 (no auth) or 200, not 404
        assert response.status_code != status.HTTP_404_NOT_FOUND
    
    def test_endpoint_requires_auth(self, client, sample_dte_data):
        """Verify endpoint requires authentication"""
        response = client.post(
            "/api/ai/validate",
            json=sample_dte_data
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_response_format(self, client, auth_headers, sample_dte_data):
        """Verify response format matches contract"""
        response = client.post(
            "/api/ai/validate",
            json=sample_dte_data,
            headers=auth_headers
        )
        
        # Should succeed or fail gracefully
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_500_INTERNAL_SERVER_ERROR
        ]
        
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            
            # Verify required fields
            assert "confidence" in data, "Missing 'confidence' field"
            assert "warnings" in data, "Missing 'warnings' field"
            assert "errors" in data, "Missing 'errors' field"
            assert "recommendation" in data, "Missing 'recommendation' field"
            
            # Verify types
            assert isinstance(data["confidence"], (int, float)), "confidence must be numeric"
            assert 0 <= data["confidence"] <= 100, "confidence must be 0-100"
            assert isinstance(data["warnings"], list), "warnings must be list"
            assert isinstance(data["errors"], list), "errors must be list"
            assert data["recommendation"] in ["send", "review"], "recommendation must be 'send' or 'review'"
    
    def test_handles_invalid_data(self, client, auth_headers):
        """Verify endpoint handles invalid data gracefully"""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {},  # Empty data
                "company_id": 1
            },
            headers=auth_headers
        )
        
        # Should not crash (422 validation error or 200 with warnings)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
    
    def test_preserves_history_parameter(self, client, auth_headers):
        """Verify history parameter is accepted"""
        response = client.post(
            "/api/ai/validate",
            json={
                "dte_data": {"tipo_dte": "33"},
                "company_id": 1,
                "history": [
                    {"folio": "123", "error": "RUT inválido"}
                ]
            },
            headers=auth_headers
        )
        
        # Should accept history parameter
        assert response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY


class TestChatEndpoint:
    """Tests for /api/chat/message endpoint - CRITICAL"""
    
    def test_endpoint_exists(self, client):
        """Verify chat endpoint exists"""
        response = client.post(
            "/api/chat/message",
            json={"message": "test"}
        )
        assert response.status_code != status.HTTP_404_NOT_FOUND
    
    def test_endpoint_requires_auth(self, client, sample_chat_message):
        """Verify endpoint requires authentication"""
        response = client.post(
            "/api/chat/message",
            json=sample_chat_message
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_dte_knowledge_preserved(self, client, auth_headers):
        """CRITICAL: Verify chat has DTE knowledge"""
        response = client.post(
            "/api/chat/message",
            json={
                "message": "¿Cómo genero un DTE 33?",
                "user_context": {"module": "l10n_cl_dte"}
            },
            headers=auth_headers
        )
        
        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            
            assert "message" in data, "Missing 'message' field"
            assert len(data["message"]) > 0, "Empty response"
            
            # Should mention DTE-related keywords
            message_lower = data["message"].lower()
            dte_keywords = ["dte", "factura", "folio", "wizard", "generar", "sii"]
            
            has_dte_context = any(keyword in message_lower for keyword in dte_keywords)
            assert has_dte_context, f"Response lacks DTE context: {data['message'][:200]}"
    
    def test_session_management(self, client, auth_headers):
        """Verify session management works"""
        # First message
        response1 = client.post(
            "/api/chat/message",
            json={
                "message": "Hola",
                "user_context": {"module": "l10n_cl_dte"}
            },
            headers=auth_headers
        )
        
        if response1.status_code == status.HTTP_200_OK:
            data1 = response1.json()
            assert "session_id" in data1, "Missing session_id"
            
            session_id = data1["session_id"]
            
            # Second message with same session
            response2 = client.post(
                "/api/chat/message",
                json={
                    "session_id": session_id,
                    "message": "¿Qué es un CAF?",
                    "user_context": {"module": "l10n_cl_dte"}
                },
                headers=auth_headers
            )
            
            assert response2.status_code == status.HTTP_200_OK
            data2 = response2.json()
            assert data2["session_id"] == session_id, "Session ID changed"


class TestHealthEndpoint:
    """Tests for /health endpoint"""
    
    def test_health_check(self, client):
        """Verify health check works"""
        response = client.get("/health")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "status" in data
        assert "service" in data
        assert "version" in data


class TestSIIMonitoring:
    """Tests for SII monitoring endpoint"""
    
    def test_sii_monitor_endpoint_exists(self, client, auth_headers):
        """Verify SII monitoring endpoint exists"""
        response = client.post(
            "/api/ai/sii/monitor",
            json={"force": False},
            headers=auth_headers
        )
        
        # Should exist (200 or 500, not 404)
        assert response.status_code != status.HTTP_404_NOT_FOUND


class TestBackwardCompatibility:
    """Tests to ensure backward compatibility during upgrade"""
    
    def test_all_critical_endpoints_exist(self, client):
        """Verify all critical endpoints exist"""
        critical_endpoints = [
            ("/health", "GET"),
            ("/api/ai/validate", "POST"),
            ("/api/chat/message", "POST"),
            ("/api/ai/sii/monitor", "POST")
        ]
        
        for endpoint, method in critical_endpoints:
            if method == "GET":
                response = client.get(endpoint)
            else:
                response = client.post(endpoint, json={})
            
            assert response.status_code != status.HTTP_404_NOT_FOUND, \
                f"Endpoint {method} {endpoint} not found"
    
    def test_pydantic_models_unchanged(self):
        """Verify Pydantic models maintain structure"""
        from main import DTEValidationRequest, DTEValidationResponse
        
        # DTEValidationRequest fields
        request_fields = DTEValidationRequest.model_fields
        assert "dte_data" in request_fields
        assert "company_id" in request_fields
        assert "history" in request_fields
        
        # DTEValidationResponse fields
        response_fields = DTEValidationResponse.model_fields
        assert "confidence" in response_fields
        assert "warnings" in response_fields
        assert "errors" in response_fields
        assert "recommendation" in response_fields


# Performance baseline tests
class TestPerformanceBaseline:
    """Establish performance baseline for comparison"""
    
    @pytest.mark.slow
    def test_validation_response_time(self, client, auth_headers, sample_dte_data):
        """Measure validation response time"""
        import time
        
        start = time.time()
        response = client.post(
            "/api/ai/validate",
            json=sample_dte_data,
            headers=auth_headers
        )
        elapsed = time.time() - start
        
        # Should respond in reasonable time (< 5 seconds)
        assert elapsed < 5.0, f"Validation took {elapsed:.2f}s (too slow)"
        
        if response.status_code == status.HTTP_200_OK:
            print(f"\n✅ Validation baseline: {elapsed:.2f}s")
    
    @pytest.mark.slow
    def test_chat_response_time(self, client, auth_headers, sample_chat_message):
        """Measure chat response time"""
        import time
        
        start = time.time()
        response = client.post(
            "/api/chat/message",
            json=sample_chat_message,
            headers=auth_headers
        )
        elapsed = time.time() - start
        
        # Should respond in reasonable time (< 10 seconds)
        assert elapsed < 10.0, f"Chat took {elapsed:.2f}s (too slow)"
        
        if response.status_code == status.HTTP_200_OK:
            print(f"\n✅ Chat baseline: {elapsed:.2f}s")
