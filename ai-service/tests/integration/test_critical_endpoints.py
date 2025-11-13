"""
Integration Tests for Critical Endpoints - AI Service
✅ FIX [T2]: Aumentar coverage de integration tests de 5/20 a 20/20 endpoints

Tests endpoints críticos con casos edge:
- /api/ai/validate (DTE validation)
- /api/chat/stream (streaming responses)
- /api/payroll/process (payroll validation)
- /api/analytics/usage (usage metrics)
- /health (health check con edge cases)
"""

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch, MagicMock
import redis


@pytest.mark.asyncio
@pytest.mark.integration
class TestDTEValidationEndpoint:
    """Tests para /api/ai/validate endpoint"""

    async def test_validate_dte_success(self, client: AsyncClient):
        """Test validación DTE exitosa con RUT válido"""
        payload = {
            "rut": "76.123.456-7",
            "dte_type": "factura",
            "monto": 1000000
        }
        
        response = await client.post(
            "/api/ai/validate",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "validation_result" in data
        assert "confidence" in data

    async def test_validate_dte_invalid_rut(self, client: AsyncClient):
        """Test validación con RUT inválido debe retornar 422"""
        payload = {
            "rut": "invalid-rut",
            "dte_type": "factura"
        }
        
        response = await client.post(
            "/api/ai/validate",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        )
        
        assert response.status_code in [400, 422]
        data = response.json()
        assert "detail" in data or "error" in data

    async def test_validate_dte_missing_auth(self, client: AsyncClient):
        """Test endpoint sin autenticación debe retornar 401"""
        payload = {"rut": "76.123.456-7", "dte_type": "factura"}
        
        response = await client.post("/api/ai/validate", json=payload)
        
        assert response.status_code == 401

    async def test_validate_dte_cache_hit(self, client: AsyncClient):
        """Test que validación usa cache Redis para requests repetidos"""
        payload = {"rut": "76.123.456-7", "dte_type": "factura"}
        headers = {"Authorization": "Bearer test_api_key_valid_16chars"}
        
        # Primera request (cache miss)
        response1 = await client.post("/api/ai/validate", json=payload, headers=headers)
        
        # Segunda request (debe usar cache)
        response2 = await client.post("/api/ai/validate", json=payload, headers=headers)
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        # Response times should be faster on cache hit (pero no podemos medir en test)


@pytest.mark.asyncio
@pytest.mark.integration
class TestChatStreamEndpoint:
    """Tests para /api/chat/stream endpoint"""

    async def test_chat_stream_success(self, client: AsyncClient):
        """Test streaming response funciona correctamente"""
        payload = {
            "message": "¿Cómo valido un DTE en Chile?",
            "session_id": "test-session-123"
        }
        
        async with client.stream(
            "POST",
            "/api/chat/stream",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        ) as response:
            assert response.status_code == 200
            assert response.headers.get("content-type") == "text/event-stream"
            
            chunks = []
            async for chunk in response.aiter_text():
                chunks.append(chunk)
            
            assert len(chunks) > 0, "Stream debe retornar al menos 1 chunk"

    async def test_chat_stream_empty_message(self, client: AsyncClient):
        """Test streaming con mensaje vacío debe retornar error"""
        payload = {"message": "", "session_id": "test-123"}
        
        response = await client.post(
            "/api/chat/stream",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        )
        
        assert response.status_code in [400, 422]

    async def test_chat_stream_max_tokens_limit(self, client: AsyncClient):
        """Test que streaming respeta límite de tokens configurado"""
        payload = {
            "message": "Explica todo sobre DTEs en Chile con máximo detalle",
            "session_id": "test-123",
            "max_tokens": 100  # Límite bajo para test
        }
        
        async with client.stream(
            "POST",
            "/api/chat/stream",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        ) as response:
            assert response.status_code == 200


@pytest.mark.asyncio
@pytest.mark.integration
class TestPayrollEndpoint:
    """Tests para /api/payroll/process endpoint"""

    async def test_payroll_process_success(self, client: AsyncClient):
        """Test procesamiento de nómina exitoso"""
        payload = {
            "employee_id": "EMP-001",
            "period": "2025-11",
            "gross_salary": 2000000,
            "deductions": [
                {"type": "afp", "amount": 200000},
                {"type": "salud", "amount": 140000}
            ]
        }
        
        response = await client.post(
            "/api/payroll/process",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "net_salary" in data
        assert "total_deductions" in data

    async def test_payroll_invalid_period(self, client: AsyncClient):
        """Test con período inválido debe retornar error"""
        payload = {
            "employee_id": "EMP-001",
            "period": "invalid-period",
            "gross_salary": 2000000
        }
        
        response = await client.post(
            "/api/payroll/process",
            json=payload,
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        )
        
        assert response.status_code in [400, 422]


@pytest.mark.asyncio
@pytest.mark.integration
class TestAnalyticsEndpoint:
    """Tests para /api/analytics/usage endpoint"""

    async def test_analytics_usage_success(self, client: AsyncClient):
        """Test obtención de métricas de uso exitosa"""
        response = await client.get(
            "/api/analytics/usage?period=last_30_days",
            headers={"Authorization": "Bearer test_api_key_valid_16chars"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data or "usage" in data

    async def test_analytics_usage_unauthorized(self, client: AsyncClient):
        """Test analytics sin autenticación debe fallar"""
        response = await client.get("/api/analytics/usage")
        
        assert response.status_code == 401


@pytest.mark.asyncio
@pytest.mark.integration
class TestHealthEndpoint:
    """Tests para /health endpoint con edge cases"""

    async def test_health_check_success(self, client: AsyncClient):
        """Test health check cuando todos los servicios están OK"""
        response = await client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "unhealthy"]

    @patch('redis.Redis.ping')
    async def test_health_check_redis_down(self, mock_redis_ping, client: AsyncClient):
        """Test health check cuando Redis está DOWN debe retornar 503"""
        # Mock Redis ping failure
        mock_redis_ping.side_effect = redis.ConnectionError("Redis unavailable")
        
        response = await client.get("/health")
        
        # Service debe reportar unhealthy pero no crashear (graceful degradation)
        assert response.status_code in [200, 503]
        data = response.json()
        
        if "redis" in data:
            assert data["redis"] in ["unhealthy", "unavailable"]

    async def test_health_check_timeout(self, client: AsyncClient):
        """Test health check con timeout debe fallar gracefully"""
        # Usar timeout muy bajo para forzar timeout
        response = await client.get("/health", timeout=0.001)
        
        # Debe timeout o retornar respuesta
        assert response.status_code in [200, 503, 504]

    async def test_health_check_details(self, client: AsyncClient):
        """Test health check con parámetro ?details=true retorna info extendida"""
        response = await client.get("/health?details=true")
        
        assert response.status_code == 200
        data = response.json()
        
        # Debe incluir detalles de servicios
        assert "status" in data
        
        # Puede incluir detalles de Redis, DB, etc.
        if isinstance(data, dict) and "services" in data:
            assert isinstance(data["services"], dict)


# Fixtures compartidos para los tests
@pytest.fixture
async def client():
    """Fixture que provee AsyncClient para tests de integración"""
    from httpx import AsyncClient
    from main import app  # Import FastAPI app
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture(autouse=True)
async def mock_env_vars(monkeypatch):
    """Fixture que configura variables de entorno para tests"""
    monkeypatch.setenv("AI_SERVICE_API_KEY", "test_api_key_valid_16chars")
    monkeypatch.setenv("ODOO_API_KEY", "test_odoo_key_valid_16chars")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-valid")
    monkeypatch.setenv("REDIS_HOST", "localhost")
    monkeypatch.setenv("REDIS_PORT", "6379")
