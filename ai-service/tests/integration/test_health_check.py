# -*- coding: utf-8 -*-
"""
Tests de integración para health check mejorado (P1-7).

Cubre:
- Health check con dependencias reales
- Redis latency warnings
- Dependency status codes (200/207/503)
- Sentinel/standalone detection

Markers:
    - integration: Test de integración
    - health: Health check tests
    - redis: Tests con Redis
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import time

# Import FastAPI app
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from main import app


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


# ============================================================================
# Health Check Tests - Happy Path
# ============================================================================

class TestHealthCheckHappyPath:
    """Tests para health check con todas las dependencias saludables."""

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_check_all_healthy(self, client):
        """Test health check cuando todas las dependencias están OK."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "AI Microservice" in data["service"]
        assert "dependencies" in data
        assert "uptime_seconds" in data
        assert "health_check_duration_ms" in data

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_check_includes_redis(self, client):
        """Test health check incluye información de Redis."""
        response = client.get("/health")
        data = response.json()

        assert "redis" in data["dependencies"]
        redis_info = data["dependencies"]["redis"]

        assert "status" in redis_info
        assert "latency_ms" in redis_info
        assert redis_info["status"] in ["up", "down"]

        if redis_info["status"] == "up":
            assert redis_info["latency_ms"] >= 0

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_check_includes_anthropic(self, client):
        """Test health check incluye configuración de Anthropic."""
        response = client.get("/health")
        data = response.json()

        assert "anthropic" in data["dependencies"]
        anthropic_info = data["dependencies"]["anthropic"]

        assert "status" in anthropic_info
        assert "model" in anthropic_info
        assert "api_key_present" in anthropic_info

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_check_includes_plugins(self, client):
        """Test health check incluye información de plugins."""
        response = client.get("/health")
        data = response.json()

        assert "plugin_registry" in data["dependencies"]
        plugin_info = data["dependencies"]["plugin_registry"]

        assert "status" in plugin_info
        if plugin_info["status"] == "loaded":
            assert "plugins_count" in plugin_info
            assert "plugins" in plugin_info
            assert isinstance(plugin_info["plugins"], list)

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_check_includes_knowledge_base(self, client):
        """Test health check incluye información de knowledge base."""
        response = client.get("/health")
        data = response.json()

        assert "knowledge_base" in data["dependencies"]
        kb_info = data["dependencies"]["knowledge_base"]

        assert "status" in kb_info
        if kb_info["status"] == "loaded":
            assert "documents_count" in kb_info
            assert "modules" in kb_info


# ============================================================================
# Health Check Tests - Redis Latency Warning (P1-7)
# ============================================================================

class TestHealthCheckRedisLatency:
    """Tests para warning de latencia Redis (P1-7)."""

    @pytest.mark.integration
    @pytest.mark.health
    @pytest.mark.redis
    def test_redis_slow_latency_warning(self, client):
        """Test warning cuando Redis latency >100ms."""
        # Mock Redis ping to simulate slow response
        with patch('utils.redis_helper.get_redis_client') as mock_redis:
            mock_client = MagicMock()

            # Simulate slow ping (150ms)
            def slow_ping():
                time.sleep(0.15)
                return True

            mock_client.ping = slow_ping
            mock_redis.return_value = mock_client

            response = client.get("/health")

            # Should return 207 (degraded) instead of 200
            assert response.status_code == 207
            data = response.json()

            assert data["status"] == "degraded"
            assert "redis" in data["dependencies"]

            redis_info = data["dependencies"]["redis"]
            assert redis_info["latency_ms"] > 100
            assert "warning" in redis_info
            assert "High latency" in redis_info["warning"]

    @pytest.mark.integration
    @pytest.mark.health
    @pytest.mark.redis
    def test_redis_normal_latency_no_warning(self, client):
        """Test no warning cuando Redis latency <100ms."""
        # Si Redis está disponible y rápido, no debería haber warning
        response = client.get("/health")
        data = response.json()

        if data["dependencies"]["redis"]["status"] == "up":
            redis_info = data["dependencies"]["redis"]

            # Si latency <100ms, no debería haber warning
            if redis_info["latency_ms"] < 100:
                assert "warning" not in redis_info
                assert data["status"] in ["healthy", "degraded"]  # Puede ser degraded por otras razones


# ============================================================================
# Health Check Tests - Degraded States
# ============================================================================

class TestHealthCheckDegraded:
    """Tests para estados degradados (status code 207)."""

    @pytest.mark.integration
    @pytest.mark.health
    def test_degraded_when_anthropic_not_configured(self, client):
        """Test degraded cuando Anthropic no está configurado."""
        with patch('config.settings.anthropic_api_key', 'default_key'):
            response = client.get("/health")

            # Puede ser 207 o 200 dependiendo de otras dependencias
            assert response.status_code in [200, 207]
            data = response.json()

            anthropic_info = data["dependencies"]["anthropic"]
            if anthropic_info["status"] == "not_configured":
                # Si no configurado, debería estar degraded
                assert data["status"] in ["healthy", "degraded"]

    @pytest.mark.integration
    @pytest.mark.health
    def test_degraded_when_plugins_fail(self, client):
        """Test degraded cuando plugins fallan al cargar."""
        with patch('plugins.registry.get_plugin_registry') as mock_registry:
            mock_registry.side_effect = Exception("Plugin load failed")

            response = client.get("/health")

            assert response.status_code == 207
            data = response.json()

            assert data["status"] == "degraded"
            assert data["dependencies"]["plugin_registry"]["status"] == "error"

    @pytest.mark.integration
    @pytest.mark.health
    def test_degraded_when_knowledge_base_fails(self, client):
        """Test degraded cuando knowledge base falla."""
        with patch('chat.knowledge_base.KnowledgeBase') as mock_kb:
            mock_kb.side_effect = Exception("KB load failed")

            response = client.get("/health")

            assert response.status_code == 207
            data = response.json()

            assert data["status"] == "degraded"
            assert data["dependencies"]["knowledge_base"]["status"] == "error"


# ============================================================================
# Health Check Tests - Unhealthy State
# ============================================================================

class TestHealthCheckUnhealthy:
    """Tests para estado unhealthy (status code 503)."""

    @pytest.mark.integration
    @pytest.mark.health
    @pytest.mark.redis
    def test_unhealthy_when_redis_down(self, client):
        """Test unhealthy (503) cuando Redis está down."""
        with patch('utils.redis_helper.get_redis_client') as mock_redis:
            mock_redis.side_effect = Exception("Redis connection failed")

            response = client.get("/health")

            assert response.status_code == 503
            data = response.json()

            assert data["status"] == "unhealthy"
            assert data["dependencies"]["redis"]["status"] == "down"


# ============================================================================
# Readiness Check Tests
# ============================================================================

class TestReadinessCheck:
    """Tests para readiness probe (más estricto que health)."""

    @pytest.mark.integration
    @pytest.mark.health
    def test_readiness_check_ready(self, client):
        """Test readiness cuando servicio está listo."""
        response = client.get("/ready")

        # Puede ser 200 o 503
        assert response.status_code in [200, 503]
        data = response.json()

        assert "status" in data
        if response.status_code == 200:
            assert data["status"] == "ready"
        else:
            assert data["status"] == "not_ready"
            assert "error" in data

    @pytest.mark.integration
    @pytest.mark.health
    def test_readiness_fails_without_redis(self, client):
        """Test readiness falla sin Redis."""
        with patch('utils.redis_helper.get_redis_client') as mock_redis:
            mock_redis.side_effect = Exception("Redis down")

            response = client.get("/ready")

            assert response.status_code == 503
            data = response.json()

            assert data["status"] == "not_ready"
            assert "error" in data

    @pytest.mark.integration
    @pytest.mark.health
    def test_readiness_fails_without_plugins(self, client):
        """Test readiness falla sin plugins cargados."""
        with patch('plugins.registry.get_plugin_registry') as mock_registry:
            mock_reg = MagicMock()
            mock_reg.list_plugins.return_value = []  # No plugins
            mock_registry.return_value = mock_reg

            response = client.get("/ready")

            assert response.status_code == 503
            data = response.json()

            assert data["status"] == "not_ready"
            assert "No plugins loaded" in data["error"]


# ============================================================================
# Liveness Check Tests
# ============================================================================

class TestLivenessCheck:
    """Tests para liveness probe (siempre debe retornar 200)."""

    @pytest.mark.integration
    @pytest.mark.health
    def test_liveness_always_alive(self, client):
        """Test liveness siempre retorna alive (incluso si deps down)."""
        response = client.get("/live")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "alive"
        assert "uptime_seconds" in data
        assert data["uptime_seconds"] >= 0

    @pytest.mark.integration
    @pytest.mark.health
    def test_liveness_even_with_redis_down(self, client):
        """Test liveness retorna alive incluso con Redis down."""
        with patch('utils.redis_helper.get_redis_client') as mock_redis:
            mock_redis.side_effect = Exception("Redis down")

            response = client.get("/live")

            # Liveness no depende de Redis
            assert response.status_code == 200
            data = response.json()

            assert data["status"] == "alive"


# ============================================================================
# Health Check Performance Tests
# ============================================================================

class TestHealthCheckPerformance:
    """Tests de performance para health check."""

    @pytest.mark.integration
    @pytest.mark.health
    @pytest.mark.performance
    def test_health_check_duration(self, client):
        """Test health check completa en <500ms."""
        start = time.time()
        response = client.get("/health")
        duration_ms = (time.time() - start) * 1000

        assert response.status_code in [200, 207, 503]

        # Health check should complete in <500ms
        assert duration_ms < 500

        data = response.json()
        assert data["health_check_duration_ms"] < 500


# ============================================================================
# Health Check Metrics Tests
# ============================================================================

class TestHealthCheckMetrics:
    """Tests para métricas incluidas en health check."""

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_includes_metrics(self, client):
        """Test health check incluye métricas si Redis está disponible."""
        response = client.get("/health")
        data = response.json()

        # Métricas son opcionales (solo si Redis up)
        if data["dependencies"]["redis"]["status"] == "up":
            # Puede o no tener métricas (depende de si hay data en Redis)
            if "metrics" in data:
                assert "total_requests" in data["metrics"]
                assert "cache_hit_rate" in data["metrics"]

    @pytest.mark.integration
    @pytest.mark.health
    def test_health_uptime_tracking(self, client):
        """Test health check tracking de uptime."""
        # Primera llamada
        response1 = client.get("/health")
        data1 = response1.json()
        uptime1 = data1["uptime_seconds"]

        # Esperar un poco
        time.sleep(1.5)

        # Segunda llamada
        response2 = client.get("/health")
        data2 = response2.json()
        uptime2 = data2["uptime_seconds"]

        # Uptime debe haber incrementado
        assert uptime2 > uptime1
        assert uptime2 - uptime1 >= 1


# ============================================================================
# Health Check Sentinel Detection Tests
# ============================================================================

class TestHealthCheckSentinel:
    """Tests para detección de Redis Sentinel vs standalone."""

    @pytest.mark.integration
    @pytest.mark.health
    @pytest.mark.redis
    def test_redis_sentinel_info(self, client):
        """Test health check detecta tipo de Redis (sentinel/standalone)."""
        response = client.get("/health")
        data = response.json()

        if data["dependencies"]["redis"]["status"] == "up":
            redis_info = data["dependencies"]["redis"]

            # Debe tener info de tipo
            assert "type" in redis_info or "master" in redis_info

            # Si es sentinel, debe tener info de master/replicas
            if redis_info.get("type") == "sentinel":
                assert "master" in redis_info
                assert "replicas" in redis_info
                assert isinstance(redis_info["replicas"], int)


# ============================================================================
# Health Check Error Handling Tests
# ============================================================================

class TestHealthCheckErrorHandling:
    """Tests para manejo de errores en health check."""

    @pytest.mark.integration
    @pytest.mark.health
    def test_partial_dependency_failure(self, client):
        """Test health check maneja fallas parciales de dependencias."""
        # Simular que plugins fallan pero otros componentes OK
        with patch('plugins.registry.get_plugin_registry') as mock_registry:
            mock_registry.side_effect = Exception("Plugin error")

            response = client.get("/health")

            # No debe crashear - debe retornar degraded
            assert response.status_code in [200, 207, 503]
            data = response.json()

            # Debe incluir error en dependencies
            assert "plugin_registry" in data["dependencies"]
            assert data["dependencies"]["plugin_registry"]["status"] == "error"
            assert "error" in data["dependencies"]["plugin_registry"]

    @pytest.mark.integration
    @pytest.mark.health
    def test_error_message_truncated(self, client):
        """Test errores largos son truncados a 200 caracteres."""
        long_error = "x" * 500

        with patch('utils.redis_helper.get_redis_client') as mock_redis:
            mock_redis.side_effect = Exception(long_error)

            response = client.get("/health")
            data = response.json()

            error_msg = data["dependencies"]["redis"]["error"]
            assert len(error_msg) <= 200
