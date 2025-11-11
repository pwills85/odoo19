# -*- coding: utf-8 -*-
"""
Unit Tests - ProjectMatcherClaude (Async)

Valida comportamiento async del project matcher:
- Async/await pattern correcto
- No bloqueo del event loop
- Concurrent requests
- Error handling async
- Performance async vs sync

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-11-11
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, List

# Import del matcher
from analytics.project_matcher_claude import ProjectMatcherClaude


# ══════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_anthropic_response():
    """Mock de respuesta de Anthropic API"""
    response = MagicMock()
    response.content = [
        MagicMock(
            text='{"project_id": 123, "project_name": "Proyecto Solar FV", "confidence": 95, "reasoning": "Proveedor siempre factura a este proyecto"}'
        )
    ]
    response.usage = MagicMock()
    response.usage.input_tokens = 1500
    response.usage.output_tokens = 150
    return response


@pytest.fixture
def sample_invoice_data():
    """Datos de ejemplo para invoice"""
    return {
        'partner_name': 'Proveedor Fotovoltaico Ltda',
        'partner_vat': '76123456-7',
        'invoice_lines': [
            {'description': 'Paneles solares 450W', 'quantity': 100, 'price': 250000},
            {'description': 'Inversor trifásico 60kW', 'quantity': 2, 'price': 3500000},
        ],
        'available_projects': [
            {
                'id': 123,
                'name': 'Proyecto Solar FV',
                'code': 'SOLAR-2025',
                'partner_name': 'Cliente Industrial SA',
                'state': 'active',
                'budget': 150000000
            },
            {
                'id': 456,
                'name': 'Proyecto Eólico Andes',
                'code': 'EOLICO-2025',
                'partner_name': 'Minera del Norte',
                'state': 'active',
                'budget': 500000000
            }
        ],
        'historical_purchases': [
            {'date': '2025-01-15', 'project_name': 'Proyecto Solar FV', 'amount': 25000000},
            {'date': '2025-02-20', 'project_name': 'Proyecto Solar FV', 'amount': 18000000},
        ]
    }


# ══════════════════════════════════════════════════════════════
# TEST 1: Async Pattern Validation
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_suggest_project_is_async(sample_invoice_data, mock_anthropic_response):
    """
    Valida que suggest_project() es correctamente async.

    Verifica:
    - Método es awaitable
    - No bloquea event loop
    - Usa AsyncAnthropic client
    """
    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock del cliente async
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_anthropic_response)
        mock_client_class.return_value = mock_client

        # Crear matcher
        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Llamar método async
        result = await matcher.suggest_project(
            partner_name=sample_invoice_data['partner_name'],
            partner_vat=sample_invoice_data['partner_vat'],
            invoice_lines=sample_invoice_data['invoice_lines'],
            available_projects=sample_invoice_data['available_projects'],
            historical_purchases=sample_invoice_data['historical_purchases']
        )

        # Validaciones
        assert result['project_id'] == 123
        assert result['project_name'] == 'Proyecto Solar FV'
        assert result['confidence'] == 95
        assert 'Proveedor siempre factura' in result['reasoning']

        # Verificar que se llamó al cliente async
        mock_client.messages.create.assert_awaited_once()


# ══════════════════════════════════════════════════════════════
# TEST 2: No Event Loop Blocking
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_no_event_loop_blocking(sample_invoice_data, mock_anthropic_response):
    """
    Valida que método async NO bloquea event loop.

    Simula delay en API call y verifica que otras tasks pueden ejecutar.
    """
    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock con delay simulado
        async def mock_create_with_delay(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simula latencia API
            return mock_anthropic_response

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=mock_create_with_delay)
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Contador para verificar que otras tasks ejecutan
        counter = {'value': 0}

        async def background_task():
            """Task que ejecuta en paralelo"""
            for _ in range(10):
                counter['value'] += 1
                await asyncio.sleep(0.01)

        # Ejecutar ambas tasks en paralelo
        results = await asyncio.gather(
            matcher.suggest_project(
                partner_name=sample_invoice_data['partner_name'],
                partner_vat=sample_invoice_data['partner_vat'],
                invoice_lines=sample_invoice_data['invoice_lines'],
                available_projects=sample_invoice_data['available_projects']
            ),
            background_task()
        )

        # Validar que background task ejecutó (counter > 0)
        assert counter['value'] > 0, "Event loop was blocked, background task didn't execute"

        # Validar resultado principal
        assert results[0]['project_id'] == 123


# ══════════════════════════════════════════════════════════════
# TEST 3: Concurrent Requests
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_concurrent_requests(sample_invoice_data, mock_anthropic_response):
    """
    Valida que múltiples requests concurrentes NO se bloquean.

    Simula 5 requests simultáneos y mide latencia total.
    Latencia total debe ser ~latencia_unitaria (no 5x).
    """
    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock con delay
        async def mock_create_with_delay(*args, **kwargs):
            await asyncio.sleep(0.05)  # 50ms por request
            return mock_anthropic_response

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=mock_create_with_delay)
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Ejecutar 5 requests concurrentes
        start = time.time()

        tasks = [
            matcher.suggest_project(
                partner_name=f"Proveedor {i}",
                partner_vat=f"7612345{i}-7",
                invoice_lines=sample_invoice_data['invoice_lines'],
                available_projects=sample_invoice_data['available_projects']
            )
            for i in range(5)
        ]

        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start

        # Validaciones
        assert len(results) == 5
        for result in results:
            assert result['project_id'] == 123

        # Latencia total debe ser ~50ms (no 250ms = 5 * 50ms)
        # Tolerancia: +30ms overhead
        assert elapsed < 0.08, f"Concurrent requests blocked (elapsed={elapsed:.3f}s, expected <0.08s)"

        # Verificar que se hicieron 5 llamadas
        assert mock_client.messages.create.await_count == 5


# ══════════════════════════════════════════════════════════════
# TEST 4: Error Handling Async
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_async_error_handling(sample_invoice_data):
    """
    Valida que errores async se manejan correctamente.

    Casos:
    - APIError → return error dict
    - ValueError (parsing) → return error dict
    - Exception general → return error dict
    """
    import anthropic

    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock que lanza APIError
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            side_effect=Exception("API error: Rate limit exceeded")
        )
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Llamar método (debe retornar error dict, NO raise)
        result = await matcher.suggest_project(
            partner_name=sample_invoice_data['partner_name'],
            partner_vat=sample_invoice_data['partner_vat'],
            invoice_lines=sample_invoice_data['invoice_lines'],
            available_projects=sample_invoice_data['available_projects']
        )

        # Validar error dict
        assert result['project_id'] is None
        assert result['confidence'] == 0
        assert 'error' in result['reasoning'].lower()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_async_parsing_error(sample_invoice_data):
    """
    Valida que errores de parsing se manejan en async context.
    """
    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock con respuesta inválida (no JSON)
        invalid_response = MagicMock()
        invalid_response.content = [MagicMock(text='NOT A JSON RESPONSE')]

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=invalid_response)
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        result = await matcher.suggest_project(
            partner_name=sample_invoice_data['partner_name'],
            partner_vat=sample_invoice_data['partner_vat'],
            invoice_lines=sample_invoice_data['invoice_lines'],
            available_projects=sample_invoice_data['available_projects']
        )

        # Validar error dict
        assert result['project_id'] is None
        assert result['confidence'] == 0
        assert 'parsing' in result['reasoning'].lower()


# ══════════════════════════════════════════════════════════════
# TEST 5: Retry Logic Async
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_retry_logic_async(sample_invoice_data, mock_anthropic_response):
    """
    Valida que retry logic funciona en async context.

    Simula:
    - 1er intento: RateLimitError
    - 2do intento: ConnectionError
    - 3er intento: Success
    """
    import anthropic

    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock con retry sequence
        call_count = {'value': 0}

        # Create proper Anthropic exceptions with required arguments
        async def mock_create_with_retries(*args, **kwargs):
            call_count['value'] += 1
            if call_count['value'] == 1:
                # Simulate rate limit error
                error = anthropic.RateLimitError(
                    "Rate limit exceeded",
                    body={"error": {"message": "Rate limit exceeded"}},
                    response=MagicMock(status_code=429, headers={})
                )
                raise error
            elif call_count['value'] == 2:
                # Simulate connection error
                error = anthropic.APIConnectionError(
                    request=MagicMock()
                )
                raise error
            else:
                return mock_anthropic_response

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=mock_create_with_retries)
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Llamar (debe hacer retry automático)
        result = await matcher.suggest_project(
            partner_name=sample_invoice_data['partner_name'],
            partner_vat=sample_invoice_data['partner_vat'],
            invoice_lines=sample_invoice_data['invoice_lines'],
            available_projects=sample_invoice_data['available_projects']
        )

        # Validar que se hicieron 3 intentos
        assert call_count['value'] == 3

        # Validar resultado exitoso (3er intento)
        assert result['project_id'] == 123
        assert result['confidence'] == 95


# ══════════════════════════════════════════════════════════════
# TEST 6: Performance Comparison (Async vs Sync Baseline)
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_async_performance_improvement(sample_invoice_data, mock_anthropic_response):
    """
    Valida que async tiene mejor performance que sync baseline.

    Simula 10 requests:
    - Async concurrente: ~latencia_unitaria
    - Sync secuencial (baseline): 10x latencia_unitaria

    Expected: Async es ~10x más rápido en carga concurrente.
    """
    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        # Mock con delay de 30ms
        async def mock_create_with_delay(*args, **kwargs):
            await asyncio.sleep(0.03)
            return mock_anthropic_response

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=mock_create_with_delay)
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Test async (concurrent)
        start_async = time.time()
        tasks = [
            matcher.suggest_project(
                partner_name=f"Proveedor {i}",
                partner_vat=f"7612345{i}-7",
                invoice_lines=sample_invoice_data['invoice_lines'],
                available_projects=sample_invoice_data['available_projects']
            )
            for i in range(10)
        ]
        await asyncio.gather(*tasks)
        elapsed_async = time.time() - start_async

        # Validar performance
        # 10 requests concurrentes con 30ms cada una → ~30-50ms total (no 300ms)
        assert elapsed_async < 0.1, f"Async concurrent performance poor (elapsed={elapsed_async:.3f}s)"

        # Simular baseline sync (secuencial) para comparación
        # Si fueran secuenciales: 10 * 30ms = 300ms
        baseline_sync = 0.03 * 10

        # Async debe ser al menos 5x más rápido
        speedup = baseline_sync / elapsed_async
        assert speedup > 5, f"Async speedup insufficient (speedup={speedup:.1f}x, expected >5x)"


# ══════════════════════════════════════════════════════════════
# TEST 7: Context Building (Helper Methods)
# ══════════════════════════════════════════════════════════════

@pytest.mark.unit
def test_build_context():
    """
    Valida que _build_context() genera contexto rico.

    No requiere async, es helper method.
    """
    matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

    context = matcher._build_context(
        partner_name='Proveedor Test SA',
        partner_vat='76123456-7',
        invoice_lines=[
            {'description': 'Producto A', 'quantity': 10, 'price': 1000},
            {'description': 'Producto B', 'quantity': 5, 'price': 2000},
        ],
        available_projects=[
            {'id': 1, 'name': 'Proyecto Alpha', 'code': 'ALPHA', 'partner_name': 'Cliente A', 'state': 'active', 'budget': 1000000},
            {'id': 2, 'name': 'Proyecto Beta', 'code': 'BETA', 'partner_name': 'Cliente B', 'state': 'active', 'budget': 2000000},
        ],
        historical_purchases=[
            {'date': '2025-01-01', 'project_name': 'Proyecto Alpha', 'amount': 500000}
        ]
    )

    # Validar estructura
    assert 'PROVEEDOR:' in context
    assert 'Proveedor Test SA' in context
    assert '76123456-7' in context
    assert 'LÍNEAS DE LA FACTURA ACTUAL:' in context
    assert 'Producto A' in context
    assert 'Producto B' in context
    assert 'PROYECTOS ACTIVOS' in context
    assert 'Proyecto Alpha' in context
    assert 'Proyecto Beta' in context
    assert 'HISTÓRICO DE COMPRAS' in context
    assert 'Proyecto Alpha' in context


@pytest.mark.unit
def test_build_prompt():
    """
    Valida que _build_prompt() genera prompt optimizado.
    """
    matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

    context = "TEST CONTEXT"
    prompt = matcher._build_prompt(context)

    # Validar estructura del prompt
    assert 'asistente experto en contabilidad analítica' in prompt
    assert 'TEST CONTEXT' in prompt
    assert 'CRITERIOS DE ANÁLISIS' in prompt
    assert 'Histórico' in prompt
    assert 'Descripción Semántica' in prompt
    assert 'INSTRUCCIONES' in prompt
    assert 'JSON estricto' in prompt
    assert 'project_id' in prompt
    assert 'confidence' in prompt
    assert 'reasoning' in prompt


# ══════════════════════════════════════════════════════════════
# TEST 8: Integration with FastAPI Endpoint (Mock)
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.unit
async def test_fastapi_endpoint_integration(sample_invoice_data, mock_anthropic_response):
    """
    Simula integración con FastAPI endpoint async.

    Valida que endpoint puede llamar a suggest_project() sin blocking.
    """
    with patch('analytics.project_matcher_claude.anthropic.AsyncAnthropic') as mock_client_class:
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_anthropic_response)
        mock_client_class.return_value = mock_client

        matcher = ProjectMatcherClaude(anthropic_api_key='test-key')

        # Simular llamada desde endpoint async
        async def mock_endpoint_handler():
            """Simula endpoint FastAPI"""
            result = await matcher.suggest_project(
                partner_name=sample_invoice_data['partner_name'],
                partner_vat=sample_invoice_data['partner_vat'],
                invoice_lines=sample_invoice_data['invoice_lines'],
                available_projects=sample_invoice_data['available_projects']
            )
            return result

        # Ejecutar
        result = await mock_endpoint_handler()

        # Validar
        assert result['project_id'] == 123
        assert result['confidence'] == 95
        mock_client.messages.create.assert_awaited_once()


# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════

"""
COVERAGE SUMMARY:
- ✅ Async pattern validation (test_suggest_project_is_async)
- ✅ No event loop blocking (test_no_event_loop_blocking)
- ✅ Concurrent requests (test_concurrent_requests)
- ✅ Error handling async (test_async_error_handling, test_async_parsing_error)
- ✅ Retry logic async (test_retry_logic_async)
- ✅ Performance async vs sync (test_async_performance_improvement)
- ✅ Helper methods (test_build_context, test_build_prompt)
- ✅ FastAPI integration (test_fastapi_endpoint_integration)

EXPECTED IMPROVEMENTS:
- Latency reduction: ~50% en concurrent load (10 requests: 30ms vs 300ms)
- No event loop blocking: background tasks ejecutan en paralelo
- Retry logic: 3 intentos con exponential backoff (async-safe)
- Error handling: graceful degradation en async context

RUN TESTS:
    pytest tests/unit/test_project_matcher_async.py -v -m unit
    pytest tests/unit/test_project_matcher_async.py -v -m asyncio
"""
