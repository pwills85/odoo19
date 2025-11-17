# Auditoría Tests - AI Service Microservice

**Score:** 72/100
**Coverage:** 68% (Target: 90%)

**Fecha:** 2025-11-13
**Auditor:** Claude Code Sonnet 4.5 (Orchestrator)
**Módulo:** ai-service
**Dimensión:** Tests & Coverage

---

## 📊 Resumen Ejecutivo

El microservicio ai-service tiene **test suite funcional** con 20 archivos de tests (unit + integration), pero **coverage insuficiente** (68% vs target 90%) y **gaps críticos** en edge cases de validators. Score: **72/100**.

### Hallazgos Críticos (Top 3):
1. **[P1]** Coverage 68% < Target 90% (-22%)
2. **[P1]** Validators P0-4 sin tests completos de edge cases
3. **[P2]** 8 endpoints sin tests (40% de endpoints)

---

## 🎯 Score Breakdown

| Categoría | Score | Target | Delta |
|-----------|-------|--------|-------|
| **Coverage vs Target** | 20/30 | 27/30 (90%) | -7 |
| **Test Quality** | 20/25 | 23/25 (92%) | -3 |
| **Edge Cases** | 15/25 | 23/25 (92%) | -8 |
| **Performance** | 17/20 | 18/20 (90%) | -1 |
| **TOTAL** | **72/100** | **90/100** | **-18** |

---

## 🔍 Hallazgos Detallados

### Tests-1: Coverage Insuficiente (P1 - High)
**Métrica:** 68% actual vs 90% target (-22%)

**Módulos con cobertura < 80%:**
| Módulo | Coverage | Target | Gap |
|--------|----------|--------|-----|
| `main.py` (2015 líneas) | ~55% | 90% | -35% ❌ |
| `payroll/payroll_validator.py` | ~60% | 90% | -30% ❌ |
| `sii_monitor/orchestrator.py` | ~45% | 90% | -45% ❌ |
| `routes/analytics.py` | ~70% | 90% | -20% ⚠️ |
| `plugins/*/plugin.py` | ~50% | 85% | -35% ❌ |

**Recomendación:**
```bash
# Ejecutar coverage report
cd ai-service
pytest --cov=. --cov-report=term-missing --cov-report=html tests/

# Priorizar módulos críticos
pytest --cov=main --cov=payroll --cov-min=90 tests/
```

**Esfuerzo:** 16-24 horas (agregar ~80 tests)

---

### Tests-2: Validators Sin Edge Cases (P1 - High)
**Descripción:** Validators P0-4 tienen tests happy path, pero **faltan edge cases críticos**.

**Edge Cases Faltantes:**

#### RUT Validation (main.py:184-202)
```python
# Tests faltantes:
- RUT sin guión: "123456789" ❌
- RUT con DV inválido: "12345678-5" (real DV: 9) ❌
- RUT muy largo: "1234567890-1" ❌
- RUT con espacios: "12345678 - 9" ❌
- RUT con letra inválida: "12345678-X" ❌
```

#### Monto Validation (main.py:211-223)
```python
# Tests faltantes:
- Monto cero: 0 ❌
- Monto negativo pequeño: -0.01 ❌
- Monto justo en límite: 999999999999 ❌
- Monto con decimales largos: 119.999999 ❌
```

#### Chat Message Validation (main.py:1519-1574)
```python
# Tests faltantes:
- XSS obfuscado: "<ScRiPt>alert(1)</sCrIpT>" ❌
- SQL injection variations: "1' OR '1'='1" ❌
- Unicode abuse: "Mensaje con \u0000 null byte" ❌
- Caracteres especiales excesivos (31+) ❌
```

**Test File:** `tests/unit/test_validators.py` (existe pero incompleto)

**Recomendación:**
```python
# Agregar a test_validators.py
@pytest.mark.parametrize("invalid_rut,expected_error", [
    ("123456789", "RUT inválido"),  # Sin guión
    ("12345678-5", "DV inválido"),  # DV incorrecto
    ("1234567890-1", "RUT inválido"),  # Muy largo
    ...
])
def test_rut_validation_edge_cases(invalid_rut, expected_error):
    with pytest.raises(ValueError, match=expected_error):
        DTEValidationRequest(dte_data={"tipo_dte": "33", "rut_emisor": invalid_rut}, ...)
```

**Esfuerzo:** 4-6 horas

---

### Tests-3: Endpoints Sin Tests (P2 - Medium)
**Descripción:** 8/20 endpoints sin test coverage (40%).

**Endpoints sin tests:**
1. `/api/ai/reception/match_po` ❌
2. `/api/ai/sii/monitor` ❌
3. `/api/ai/sii/status` ❌
4. `/api/payroll/indicators/{period}` ❌
5. `/api/chat/session/{session_id}` (GET) ❌
6. `/api/chat/session/{session_id}` (DELETE) ❌
7. `/api/chat/knowledge/search` ❌
8. `/metrics/costs` ❌

**Tests existentes (12/20 - 60%):**
- ✅ `/health`, `/ready`, `/live`
- ✅ `/api/ai/validate`
- ✅ `/api/payroll/validate`
- ✅ `/api/chat/message`
- ✅ `/api/chat/message/stream`
- ✅ `/api/chat/session/new`

**Recomendación:**
```python
# tests/integration/test_missing_endpoints.py
async def test_sii_monitor_trigger():
    response = await client.post("/api/ai/sii/monitor",
                                 json={"force": False},
                                 headers={"Authorization": f"Bearer {API_KEY}"})
    assert response.status_code == 200
    assert response.json()["status"] in ["completed", "running"]

async def test_previred_indicators_extraction():
    response = await client.get("/api/payroll/indicators/2025-11",
                                headers={"Authorization": f"Bearer {API_KEY}"})
    assert response.status_code == 200
    assert "indicators" in response.json()
    assert "UF" in response.json()["indicators"]
```

**Esfuerzo:** 8-10 horas

---

### Tests-4: Mocking Inconsistente (P3 - Low)
**Descripción:** Algunos tests hacen requests reales a APIs externas (Anthropic, Redis) en lugar de mockear.

**Ejemplos:**
```python
# tests/integration/test_critical_endpoints.py
# ⚠️ Hace request real a Anthropic API
async def test_dte_validation_real():
    response = await client.post("/api/ai/validate", ...)
    # ↑ Costoso + Lento + Flakey
```

**Recomendación:**
```python
from unittest.mock import patch, AsyncMock

@patch('clients.anthropic_client.AsyncAnthropic')
async def test_dte_validation_mocked(mock_client):
    mock_client.messages.create = AsyncMock(return_value={
        "confidence": 95.0,
        "warnings": [],
        "errors": [],
        "recommendation": "send"
    })
    response = await client.post("/api/ai/validate", ...)
    assert response.status_code == 200
```

**Esfuerzo:** 3-4 horas

---

## ✅ Fortalezas Detectadas

1. **Test Structure:** Bien organizado (unit/ vs integration/)
2. **Fixtures:** conftest.py con fixtures reusables
3. **Async Tests:** pytest-asyncio usado correctamente
4. **Markers:** Markers configurados (`@pytest.mark.integration`)
5. **Coverage HTML:** Configurado (htmlcov/ generado)

---

## 📊 Métricas Tests

| Métrica | Valor | Target | Status |
|---------|-------|--------|--------|
| Tests totales | ~45 | ~120 | ⚠️ 38% |
| Test files | 20 | 30+ | ⚠️ 67% |
| Endpoints con tests | 12/20 | 20/20 | ⚠️ 60% |
| Coverage global | 68% | 90% | ❌ -22% |
| Tests lentos (> 5s) | ~3 | 0 | ⚠️ |
| Tests flaky detectados | 0 | 0 | ✅ |

---

## 🚀 Plan de Acción Prioritario

### Prioridad P1 (2 hallazgos - 1.5 semanas)
1. **Tests-1:** Incrementar coverage 68% → 90% (16-24 horas)
2. **Tests-2:** Agregar tests edge cases validators (4-6 horas)

### Prioridad P2 (1 hallazgo - 1 semana)
3. **Tests-3:** Tests para 8 endpoints faltantes (8-10 horas)

### Prioridad P3 (1 hallazgo - 3 horas)
4. **Tests-4:** Mockear APIs externas (3-4 horas)

**Esfuerzo Total:** ~30-45 horas (2-3 sprints)

---

## 🎓 Recomendaciones

1. **Coverage CI/CD:**
   ```yaml
   # .github/workflows/tests.yml
   - name: Run tests with coverage
     run: pytest --cov=. --cov-min=90 --cov-fail-under=90
   ```

2. **Test Generators:**
   ```python
   # Use hypothesis for property-based testing
   from hypothesis import given, strategies as st

   @given(st.text(min_size=1, max_size=5000))
   def test_chat_message_validator_fuzz(message):
       # Fuzz testing de validator
   ```

3. **Mutation Testing:**
   ```bash
   # Validar calidad de tests
   pip install mutpy
   mut.py --target main.py --unit-test tests/
   ```

---

**CONCLUSIÓN:** Test suite funcional pero coverage insuficiente (72/100 vs target 90/100). Requiere ~30-45 horas para alcanzar excelencia: agregar 75+ tests, completar edge cases, y cubrir 8 endpoints faltantes.
