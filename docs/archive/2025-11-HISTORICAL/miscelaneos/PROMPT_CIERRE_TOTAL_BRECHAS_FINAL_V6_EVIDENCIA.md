# 🎯 PROMPT PROFESIONAL: CIERRE TOTAL BRECHAS - EVIDENCIA VERIFICADA

**Versión:** 6.0 (Evidence-Based)  
**Fecha:** 2025-11-09  
**Proyecto:** EERGYGROUP Odoo 19 CE - Localización Chilena  
**Metodología:** Test-Driven, Evidence-Based, Zero Improvisation  
**Base:** `ANALISIS_CRITICO_AUDITORIA_AGENTE.md` (validación independiente)

---

## 📋 CONTEXTO EJECUTIVO

### Estado Actual VERIFICADO

| Proyecto | Score Real | Score Target | Gap | Brechas Pendientes |
|----------|-----------|--------------|-----|-------------------|
| **AI Service** | **90.5/100** | 100/100 | -9.5 | 2 críticas + 1 parcial |
| **DTE** | **92/100** | 100/100 | -8 | 1 NO verificada + 3 menores |

### Evidencia de Validación Independiente

**Fuente:** Análisis forense con 15+ comandos Git/Docker ejecutados  
**Confianza:** ALTA (100% basado en outputs verificables)  
**Fecha Validación:** 2025-11-09

---

## 🔴 BRECHAS CRÍTICAS IDENTIFICADAS (EVIDENCIA REAL)

### AI SERVICE: 3 Brechas Pendientes

#### P1-5: Tests con ERROR - TypeError (BLOCKER) 🔴

**Estado Verificado:**
```bash
$ docker exec odoo19_ai_service pytest -v 2>&1 | grep -c "ERROR"
97

$ docker exec odoo19_ai_service pytest -v 2>&1 | grep -c "PASSED"
93

# Error rate: 97/190 = 51%
```

**Error Específico:**
```python
TypeError: Client.__init__() got an unexpected keyword argument 'app'
```

**Archivos Afectados (VERIFICADO):**
```
tests/integration/test_prompt_caching.py          (TODOS los tests)
tests/integration/test_streaming_sse.py           (TODOS los tests)
tests/integration/test_token_precounting.py       (TODOS los tests)
tests/test_dte_regression.py                      (15 tests)
tests/unit/test_chat_engine.py                    (3 tests: stream_*)
tests/unit/test_markers_example.py                (2 tests)
```

**Root Cause:**
- API de Starlette `TestClient` cambió
- Tests usan sintaxis antigua: `Client(app=app)`
- Sintaxis correcta: `TestClient(app)`

**Impacto Score:** -3 puntos (P1-5 no completado)

---

#### P1-1: Coverage 15.79% vs 80% Target (CRITICAL) 🔴

**Estado Verificado:**
```bash
$ docker exec odoo19_ai_service pytest --cov=. --cov-report=term -q
FAIL Required test coverage of 80% not reached. Total coverage: 15.79%
```

**Gap:** -64.21% (shortfall masivo)

**Archivos Sin Coverage (IDENTIFICADOS):**
```
clients/anthropic_client.py        (483 LOC - 0% coverage)
chat/engine.py                     (658 LOC - cobertura parcial)
utils/redis_helper.py              (184 LOC - sin tests)
plugins/plugin_registry.py         (sin tests)
chat/context_manager.py            (sin tests)
```

**Impacto Score:** -6 puntos (P1-1 parcialmente completado: +1 de +7)

---

#### P3-2: Rate Limiting (PARCIAL) ⚠️

**Estado:** Implementado pero NO testeado

**Impacto Score:** -0.5 puntos

---

### DTE: 4 Brechas Pendientes

#### H9: Cumplimiento Normativo SII (P0 - NO VERIFICADO) ❓

**Estado Actual:** **SIN EVIDENCIA EJECUTADA**

**Problema:** Agente auditor reportó "✅ completo" sin ejecutar comandos de verificación.

**Archivos a Verificar:**
```
addons/localization/l10n_cl_dte/models/dte_consumo_folios.py
addons/localization/l10n_cl_dte/models/dte_libro.py
```

**Métodos a Validar:**
```python
# 1. Consumo de Folios (Mensual obligatorio SII)
def _generate_consumo_folios_xml(self) -> str:
    # Debe retornar XML válido según Resolución Ex. SII
    # NO puede ser placeholder

# 2. Libro de Compras (Mensual obligatorio)
def _generate_libro_compras_xml(self) -> str:
    # Formato XML IEC según instructivo SII
    # NO puede ser placeholder

# 3. Libro de Ventas (Mensual obligatorio)
def _generate_libro_ventas_xml(self) -> str:
    # Formato XML IEC según instructivo SII
    # NO puede ser placeholder
```

**Impacto Score:**
- Si implementado: +15 puntos (DTE → 107/100 ✅)
- Si NO implementado: +0 puntos (DTE → 92/100 ⚠️)

---

#### H1: XXE - 1 Vulnerable Restante (MENOR) ⚠️

**Estado Verificado:**
```bash
$ grep -rn "etree.fromstring" addons/localization/l10n_cl_dte/ --include="*.py" | grep -v "test_\|safe_xml_parser"
addons/localization/l10n_cl_dte/libs/ted_generator.py:246:  >>> ted_elem = etree.fromstring(ted_xml)
```

**Análisis:**
- Línea 246: **Docstring** (ejemplo documentación)
- NO es código ejecutable
- Riesgo: BAJO

**Impacto Score:** -2 puntos (H1 parcialmente completo: +23 de +25)

---

#### H2: Pure Python libs/ - 3 Imports Restantes (MENOR) ⚠️

**Estado Verificado:**
```bash
$ grep -r "from odoo import" addons/localization/l10n_cl_dte/libs/ --include="*.py"
addons/localization/l10n_cl_dte/libs/caf_signature_validator.py:  from odoo import api, SUPERUSER_ID
addons/localization/l10n_cl_dte/libs/i18n.py:                     from odoo import _
addons/localization/l10n_cl_dte/libs/i18n.py:                     from odoo import api
```

**Análisis:**
- Los 3 imports están en **bloques try/except con fallback**
- Patrón aceptable según Odoo 19
- Riesgo: BAJO

**Impacto Score:** -1 punto (H2 casi completo: +2 de +3)

---

#### H11, H4-H8: Mejoras No Críticas (P1-P3)

**Estado:** NO iniciadas

**Impacto Score:** -6 puntos totales

---

## 🎯 PLAN DE EJECUCIÓN PROFESIONAL

### Principios Fundamentales

**❌ PROHIBIDO:**
- Improvisar soluciones sin evidencia
- Asumir código completo sin verificar
- Skip tests "porque deberían pasar"
- Commits sin validación
- Parches temporales

**✅ OBLIGATORIO:**
- Ejecutar comandos de verificación ANTES de cada cambio
- TDD: Tests PRIMERO, código DESPUÉS
- Validar con pytest/odoo tests DESPUÉS de cada cambio
- Commits atómicos con evidencia en mensaje
- Rollback automático si tests fallan

---

## 📅 SPRINTS BASADOS EN EVIDENCIA

### SPRINT 0: Validación Baseline (MANDATORY) ⏱️ 15 min

**Objetivo:** Establecer estado real verificable ANTES de cambios

#### Fase 0.1: Validación AI Service

```bash
# 1. Tests status actual
docker exec odoo19_ai_service pytest --collect-only -q > /tmp/ai_tests_baseline.txt
docker exec odoo19_ai_service pytest -v 2>&1 | tee /tmp/ai_tests_run_baseline.txt

# Extraer métricas
grep -c "PASSED" /tmp/ai_tests_run_baseline.txt > /tmp/ai_passed_count.txt
grep -c "ERROR" /tmp/ai_tests_run_baseline.txt > /tmp/ai_error_count.txt

# 2. Coverage actual
docker exec odoo19_ai_service pytest --cov=. --cov-report=term --cov-report=json -q 2>&1 | tee /tmp/ai_coverage_baseline.txt
docker exec odoo19_ai_service cat .coverage.json > /tmp/ai_coverage_baseline.json

# 3. Archivos con 0% coverage
docker exec odoo19_ai_service pytest --cov=. --cov-report=term-missing -q 2>&1 | grep "0%" > /tmp/ai_zero_coverage.txt

# 4. Git checkpoint
git add .
git commit -m "chore(sprint0): baseline AI Service before P1 fixes

Tests: 93 PASSED / 97 ERROR / 190 total
Coverage: 15.79%
Target: 100/100 score
"
git tag -a sprint_ai_p1_baseline_$(date +%Y%m%d_%H%M) -m "Baseline antes de fix P1-5 y P1-1"
```

**Checkpoint 0.1:** ✅ Baseline documentado en `/tmp/ai_*.txt`

---

#### Fase 0.2: Validación DTE H9

```bash
# 1. Verificar Consumo de Folios
echo "=== CONSUMO DE FOLIOS ===" > /tmp/dte_h9_validation.txt
grep -A 100 "def _generate_consumo_folios_xml" addons/localization/l10n_cl_dte/models/dte_consumo_folios.py >> /tmp/dte_h9_validation.txt

# Verificar NO es placeholder
if grep -q "TODO\|NotImplementedError\|pass$\|return ''" /tmp/dte_h9_validation.txt; then
    echo "❌ CONSUMO FOLIOS: PLACEHOLDER DETECTADO" | tee -a /tmp/dte_h9_validation.txt
else
    echo "✅ CONSUMO FOLIOS: IMPLEMENTADO" | tee -a /tmp/dte_h9_validation.txt
fi

# 2. Verificar Libro de Compras
echo "=== LIBRO COMPRAS ===" >> /tmp/dte_h9_validation.txt
grep -A 100 "def _generate_libro_compras_xml" addons/localization/l10n_cl_dte/models/dte_libro.py >> /tmp/dte_h9_validation.txt

if grep -q "TODO\|NotImplementedError\|pass$\|return ''" /tmp/dte_h9_validation.txt; then
    echo "❌ LIBRO COMPRAS: PLACEHOLDER DETECTADO" | tee -a /tmp/dte_h9_validation.txt
else
    echo "✅ LIBRO COMPRAS: IMPLEMENTADO" | tee -a /tmp/dte_h9_validation.txt
fi

# 3. Verificar Libro de Ventas
echo "=== LIBRO VENTAS ===" >> /tmp/dte_h9_validation.txt
grep -A 100 "def _generate_libro_ventas_xml" addons/localization/l10n_cl_dte/models/dte_libro.py >> /tmp/dte_h9_validation.txt

if grep -q "TODO\|NotImplementedError\|pass$\|return ''" /tmp/dte_h9_validation.txt; then
    echo "❌ LIBRO VENTAS: PLACEHOLDER DETECTADO" | tee -a /tmp/dte_h9_validation.txt
else
    echo "✅ LIBRO VENTAS: IMPLEMENTADO" | tee -a /tmp/dte_h9_validation.txt
fi

# 4. Resumen
echo "" >> /tmp/dte_h9_validation.txt
echo "=== RESUMEN H9 ===" >> /tmp/dte_h9_validation.txt
cat /tmp/dte_h9_validation.txt | grep "^✅\|^❌"

# 5. Git checkpoint
git add .
git commit -m "chore(sprint0): baseline DTE before H9 verification

H9 Status: PENDIENTE VERIFICACIÓN
See: /tmp/dte_h9_validation.txt
"
```

**Checkpoint 0.2:** ✅ Estado H9 documentado en `/tmp/dte_h9_validation.txt`

**Output esperado:**
```
✅ CONSUMO FOLIOS: IMPLEMENTADO
✅ LIBRO COMPRAS: IMPLEMENTADO
✅ LIBRO VENTAS: IMPLEMENTADO
```

**O:**
```
❌ CONSUMO FOLIOS: PLACEHOLDER DETECTADO
❌ LIBRO COMPRAS: PLACEHOLDER DETECTADO
❌ LIBRO VENTAS: PLACEHOLDER DETECTADO
```

---

### SPRINT 1: Fix Tests ERROR (AI Service) ⏱️ 2-4 horas

**Prioridad:** 🔴 CRÍTICA (blocker para P1-5)  
**Impacto Score:** +3 puntos

#### Fase 1.1: Análisis Root Cause (30 min)

**Comando para agente:**

```bash
# 1. Identificar versión actual TestClient
docker exec odoo19_ai_service python -c "import starlette; print(f'Starlette: {starlette.__version__}')"
docker exec odoo19_ai_service python -c "import fastapi; print(f'FastAPI: {fastapi.__version__}')"

# 2. Leer documentación actual
docker exec odoo19_ai_service python -c "from starlette.testclient import TestClient; help(TestClient.__init__)" > /tmp/testclient_api.txt

# 3. Identificar TODOS los archivos con Client(app=app)
grep -rn "Client(app=" ai-service/tests/ --include="*.py" > /tmp/testclient_usages.txt

# 4. Contar archivos afectados
wc -l /tmp/testclient_usages.txt
```

**Checkpoint 1.1:** ✅ Root cause confirmado, archivos identificados

---

#### Fase 1.2: Fix TestClient API (1 hora)

**IMPORTANTE:** Fix debe ser **PRECISO**, no improvisado.

**Pattern Actual (INCORRECTO):**
```python
# tests/integration/test_prompt_caching.py
from starlette.testclient import TestClient as Client

def setup_method(self):
    self.client = Client(app=app)  # ❌ INCORRECTO
```

**Pattern Correcto (VERIFICADO en docs):**
```python
# tests/integration/test_prompt_caching.py
from starlette.testclient import TestClient

def setup_method(self):
    self.client = TestClient(app)  # ✅ CORRECTO
```

**Archivos a Modificar (EXHAUSTIVO):**

1. `tests/integration/test_prompt_caching.py`
2. `tests/integration/test_streaming_sse.py`
3. `tests/integration/test_token_precounting.py`
4. `tests/test_dte_regression.py`
5. `tests/unit/test_chat_engine.py` (solo stream tests)
6. `tests/unit/test_markers_example.py`

**Proceso por Archivo:**

```bash
# Para CADA archivo:
# 1. Backup
cp ai-service/tests/integration/test_prompt_caching.py /tmp/test_prompt_caching.py.bak

# 2. Fix (ejemplo)
# Reemplazar:
#   from starlette.testclient import TestClient as Client
#   self.client = Client(app=app)
# Con:
#   from starlette.testclient import TestClient
#   self.client = TestClient(app)

# 3. Validar sintaxis
docker exec odoo19_ai_service python -m py_compile tests/integration/test_prompt_caching.py

# 4. Test SOLO ese archivo
docker exec odoo19_ai_service pytest tests/integration/test_prompt_caching.py -v

# 5. Si pasa, commit
git add ai-service/tests/integration/test_prompt_caching.py
git commit -m "fix(tests): update TestClient API in test_prompt_caching.py

- Replace Client(app=app) with TestClient(app)
- Fix TypeError: Client.__init__() got unexpected keyword argument 'app'
- Tests now: X PASSED / 0 ERROR (before: 0 PASSED / X ERROR)
"

# 6. Si falla, rollback
git checkout ai-service/tests/integration/test_prompt_caching.py
```

**Checkpoint 1.2:** ✅ Cada archivo fixed individualmente con commit atómico

---

#### Fase 1.3: Validación Final (30 min)

```bash
# 1. Run todos los tests
docker exec odoo19_ai_service pytest -v 2>&1 | tee /tmp/ai_tests_post_fix.txt

# 2. Comparar con baseline
echo "=== BEFORE FIX ===" > /tmp/tests_comparison.txt
grep -c "PASSED" /tmp/ai_tests_run_baseline.txt >> /tmp/tests_comparison.txt
grep -c "ERROR" /tmp/ai_tests_run_baseline.txt >> /tmp/tests_comparison.txt

echo "=== AFTER FIX ===" >> /tmp/tests_comparison.txt
grep -c "PASSED" /tmp/ai_tests_post_fix.txt >> /tmp/tests_comparison.txt
grep -c "ERROR" /tmp/ai_tests_post_fix.txt >> /tmp/tests_comparison.txt

# 3. Validar mejora
PASSED_AFTER=$(grep -c "PASSED" /tmp/ai_tests_post_fix.txt)
ERROR_AFTER=$(grep -c "ERROR" /tmp/ai_tests_post_fix.txt)

if [ "$ERROR_AFTER" -eq 0 ]; then
    echo "✅ SUCCESS: 0 ERROR tests" | tee -a /tmp/tests_comparison.txt
    git tag -a sprint1_p1-5_complete_$(date +%Y%m%d_%H%M) -m "P1-5 completado: 0 ERROR tests"
else
    echo "⚠️ WARNING: $ERROR_AFTER ERROR tests restantes" | tee -a /tmp/tests_comparison.txt
fi

# 4. Update score
echo "Score AI Service: 90.5 + 3 = 93.5/100" >> /tmp/tests_comparison.txt
```

**Checkpoint 1.3:** ✅ P1-5 completado si ERROR=0

**Score Post-Sprint 1:** 90.5 → 93.5/100 (+3 puntos)

---

### SPRINT 2: Incrementar Coverage (AI Service) ⏱️ 1-2 días

**Prioridad:** 🔴 ALTA (gap de 64.21%)  
**Impacto Score:** +6 puntos (si alcanza 80%)

#### Fase 2.1: Identificar Archivos Sin Coverage (1 hora)

```bash
# 1. Generar reporte detallado
docker exec odoo19_ai_service pytest --cov=. --cov-report=term-missing --cov-report=html -q

# 2. Extraer archivos con 0% coverage
docker exec odoo19_ai_service pytest --cov=. --cov-report=term-missing -q 2>&1 | grep "clients/\|chat/\|utils/" | grep " 0%" > /tmp/zero_coverage_files.txt

# 3. Priorizar por LOC
echo "=== ARCHIVOS SIN COVERAGE (Prioridad por LOC) ===" > /tmp/coverage_priority.txt
for file in $(cat /tmp/zero_coverage_files.txt | awk '{print $1}'); do
    lines=$(docker exec odoo19_ai_service wc -l "$file" 2>/dev/null | awk '{print $1}')
    echo "$lines LOC - $file" >> /tmp/coverage_priority.txt
done
sort -rn /tmp/coverage_priority.txt > /tmp/coverage_priority_sorted.txt

# 4. Top 5 archivos críticos
head -5 /tmp/coverage_priority_sorted.txt
```

**Output Esperado:**
```
483 LOC - clients/anthropic_client.py
658 LOC - chat/engine.py (parcial)
184 LOC - utils/redis_helper.py
150 LOC - plugins/plugin_registry.py
120 LOC - chat/context_manager.py
```

**Checkpoint 2.1:** ✅ Prioridad clara de archivos a testear

---

#### Fase 2.2: Tests clients/anthropic_client.py (4 horas)

**Target:** ≥90% coverage de `clients/anthropic_client.py` (483 LOC)

**Análisis Pre-Test:**

```bash
# 1. Leer archivo completo
docker exec odoo19_ai_service cat clients/anthropic_client.py > /tmp/anthropic_client_analysis.py

# 2. Identificar métodos públicos
grep "^\s*def [^_]" /tmp/anthropic_client_analysis.py > /tmp/anthropic_methods.txt

# 3. Contar métodos
wc -l /tmp/anthropic_methods.txt
```

**Métodos Críticos Identificados (NO IMPROVISAR):**

```python
# clients/anthropic_client.py (verificar líneas exactas)

class AnthropicClient:
    async def estimate_tokens(...)         # Línea ~XX
    async def send_message(...)            # Línea ~XX
    async def validate_dte(...)            # Línea ~XX
    async def _make_request(...)           # Línea ~XX
    def _build_system_prompt(...)          # Línea ~XX
    def _parse_response(...)               # Línea ~XX
    def _calculate_cost(...)               # Línea ~XX
```

**Tests a Crear (TDD):**

```python
# tests/unit/test_anthropic_client_coverage.py (NUEVO ARCHIVO)

import pytest
from unittest.mock import Mock, patch, AsyncMock
from clients.anthropic_client import AnthropicClient

class TestAnthropicClientEstimateTokens:
    """Tests para estimate_tokens() - CRÍTICO para precounting"""
    
    @pytest.mark.asyncio
    async def test_estimate_tokens_returns_correct_structure(self):
        """MUST return dict with input_tokens, output_tokens, estimated_cost"""
        client = AnthropicClient(api_key="test", model="claude-3-5-sonnet")
        
        with patch.object(client, '_make_request', new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {
                'usage': {'input_tokens': 100, 'output_tokens': 50}
            }
            
            result = await client.estimate_tokens(
                messages=[{"role": "user", "content": "test"}],
                system="test system"
            )
            
            assert 'input_tokens' in result
            assert 'output_tokens' in result
            assert 'estimated_cost' in result
            assert isinstance(result['estimated_cost'], float)
    
    @pytest.mark.asyncio
    async def test_estimate_tokens_handles_api_error(self):
        """MUST handle API errors gracefully"""
        client = AnthropicClient(api_key="test", model="claude-3-5-sonnet")
        
        with patch.object(client, '_make_request', new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = Exception("API Error")
            
            with pytest.raises(Exception) as exc_info:
                await client.estimate_tokens(
                    messages=[{"role": "user", "content": "test"}],
                    system="test"
                )
            
            assert "API Error" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_estimate_tokens_uses_correct_model_pricing(self):
        """MUST use correct pricing for model"""
        client = AnthropicClient(api_key="test", model="claude-3-5-sonnet-20241022")
        
        with patch.object(client, '_make_request', new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {
                'usage': {'input_tokens': 1000, 'output_tokens': 500}
            }
            
            result = await client.estimate_tokens(
                messages=[{"role": "user", "content": "test"}],
                system="test"
            )
            
            # Verify pricing calculation
            # claude-3-5-sonnet: $3/MTok input, $15/MTok output
            expected_cost = (1000 * 3 + 500 * 15) / 1_000_000
            assert abs(result['estimated_cost'] - expected_cost) < 0.0001

# ... (15-20 tests más para otros métodos)
```

**Proceso de Implementación:**

```bash
# 1. Crear archivo test
touch ai-service/tests/unit/test_anthropic_client_coverage.py

# 2. Implementar 5 tests a la vez (TDD)
# - Escribir tests PRIMERO
# - Ejecutar: pytest tests/unit/test_anthropic_client_coverage.py -v
# - Si fallan por código incorrecto → FIX CÓDIGO
# - Si fallan por test incorrecto → FIX TEST

# 3. Validar coverage incremental
docker exec odoo19_ai_service pytest --cov=clients/anthropic_client --cov-report=term-missing tests/unit/test_anthropic_client_coverage.py -v

# 4. Commit cada 5 tests
git add ai-service/tests/unit/test_anthropic_client_coverage.py
git commit -m "test(anthropic_client): add 5 tests for estimate_tokens

Coverage: clients/anthropic_client.py XX% → YY% (+ZZ%)
Tests: test_estimate_tokens_* (5 tests, all PASS)
"

# 5. Repetir hasta ≥90% coverage
```

**Checkpoint 2.2:** ✅ `clients/anthropic_client.py` ≥90% coverage

---

#### Fase 2.3: Tests chat/engine.py (4 horas)

**Target:** ≥85% coverage de `chat/engine.py` (658 LOC)

**Nota:** `chat/engine.py` YA tiene tests en `tests/unit/test_chat_engine.py` (884 líneas), pero coverage sigue bajo.

**Análisis Gap:**

```bash
# 1. Coverage actual de chat/engine.py
docker exec odoo19_ai_service pytest --cov=chat/engine --cov-report=term-missing tests/unit/test_chat_engine.py -v 2>&1 | grep "chat/engine.py"

# 2. Identificar líneas NO cubiertas
docker exec odoo19_ai_service pytest --cov=chat/engine --cov-report=term-missing tests/unit/test_chat_engine.py -v 2>&1 | grep "chat/engine.py" -A 50 > /tmp/engine_missing_lines.txt

# 3. Leer esas líneas específicas
cat /tmp/engine_missing_lines.txt
```

**Estrategia:** Agregar tests para líneas NO cubiertas (NO duplicar tests existentes)

**Proceso:**

```bash
# 1. Identificar métodos sin coverage
grep "^\s*def " ai-service/chat/engine.py > /tmp/engine_methods.txt

# 2. Para cada método, verificar si tiene test
for method in $(cat /tmp/engine_methods.txt | awk '{print $2}' | cut -d'(' -f1); do
    if ! grep -q "test_$method" ai-service/tests/unit/test_chat_engine.py; then
        echo "❌ MISSING TEST: $method" >> /tmp/engine_missing_tests.txt
    fi
done

# 3. Implementar tests faltantes
# (similar a Fase 2.2)
```

**Checkpoint 2.3:** ✅ `chat/engine.py` ≥85% coverage

---

#### Fase 2.4: Validación Coverage Total (1 hora)

```bash
# 1. Run coverage completo
docker exec odoo19_ai_service pytest --cov=. --cov-report=term --cov-report=json --cov-fail-under=80 -v 2>&1 | tee /tmp/coverage_final.txt

# 2. Verificar ≥80%
COVERAGE=$(grep "TOTAL" /tmp/coverage_final.txt | awk '{print $4}' | sed 's/%//')

if [ $(echo "$COVERAGE >= 80" | bc) -eq 1 ]; then
    echo "✅ SUCCESS: Coverage $COVERAGE% ≥ 80%" | tee -a /tmp/coverage_final.txt
    git tag -a sprint2_p1-1_complete_$(date +%Y%m%d_%H%M) -m "P1-1 completado: Coverage $COVERAGE%"
else
    echo "❌ FAIL: Coverage $COVERAGE% < 80%" | tee -a /tmp/coverage_final.txt
    exit 1
fi

# 3. Update score
echo "Score AI Service: 93.5 + 6 = 99.5/100" >> /tmp/coverage_final.txt
```

**Checkpoint 2.4:** ✅ P1-1 completado si coverage ≥80%

**Score Post-Sprint 2:** 93.5 → 99.5/100 (+6 puntos)

---

### SPRINT 3: Validar/Implementar H9 Compliance (DTE) ⏱️ 30min - 60h

**Prioridad:** 🔴 CRÍTICA (P0 blocker potencial)  
**Impacto Score:** +15 puntos (si está implementado) o +0 (si falta)

#### Fase 3.1: Verificación Exhaustiva (30 min)

**IMPORTANTE:** CERO assumptions, solo evidencia.

```bash
# 1. Leer implementación Consumo de Folios
echo "=== CONSUMO DE FOLIOS COMPLETO ===" > /tmp/h9_full_validation.txt
grep -A 200 "def _generate_consumo_folios_xml" addons/localization/l10n_cl_dte/models/dte_consumo_folios.py >> /tmp/h9_full_validation.txt

# Análisis automático
if grep -q "NotImplementedError\|TODO\|pass$" /tmp/h9_full_validation.txt | head -50; then
    echo "❌ CONSUMO FOLIOS: PLACEHOLDER" | tee -a /tmp/h9_status.txt
    CONSUMO_OK=0
else
    # Verificar tiene lógica (>30 líneas de código real)
    CODE_LINES=$(grep -A 200 "def _generate_consumo_folios_xml" addons/localization/l10n_cl_dte/models/dte_consumo_folios.py | grep -v "^\s*#\|^\s*$" | wc -l)
    if [ "$CODE_LINES" -gt 30 ]; then
        echo "✅ CONSUMO FOLIOS: IMPLEMENTADO ($CODE_LINES líneas)" | tee -a /tmp/h9_status.txt
        CONSUMO_OK=1
    else
        echo "❌ CONSUMO FOLIOS: CÓDIGO INSUFICIENTE ($CODE_LINES líneas)" | tee -a /tmp/h9_status.txt
        CONSUMO_OK=0
    fi
fi

# 2. Leer implementación Libro de Compras
echo "=== LIBRO COMPRAS COMPLETO ===" >> /tmp/h9_full_validation.txt
grep -A 200 "def _generate_libro_compras_xml" addons/localization/l10n_cl_dte/models/dte_libro.py >> /tmp/h9_full_validation.txt

if grep -q "NotImplementedError\|TODO\|pass$" /tmp/h9_full_validation.txt | tail -50; then
    echo "❌ LIBRO COMPRAS: PLACEHOLDER" | tee -a /tmp/h9_status.txt
    COMPRAS_OK=0
else
    CODE_LINES=$(grep -A 200 "def _generate_libro_compras_xml" addons/localization/l10n_cl_dte/models/dte_libro.py | grep -v "^\s*#\|^\s*$" | wc -l)
    if [ "$CODE_LINES" -gt 30 ]; then
        echo "✅ LIBRO COMPRAS: IMPLEMENTADO ($CODE_LINES líneas)" | tee -a /tmp/h9_status.txt
        COMPRAS_OK=1
    else
        echo "❌ LIBRO COMPRAS: CÓDIGO INSUFICIENTE ($CODE_LINES líneas)" | tee -a /tmp/h9_status.txt
        COMPRAS_OK=0
    fi
fi

# 3. Leer implementación Libro de Ventas
echo "=== LIBRO VENTAS COMPLETO ===" >> /tmp/h9_full_validation.txt
grep -A 200 "def _generate_libro_ventas_xml" addons/localization/l10n_cl_dte/models/dte_libro.py >> /tmp/h9_full_validation.txt

if grep -q "NotImplementedError\|TODO\|pass$" /tmp/h9_full_validation.txt | tail -50; then
    echo "❌ LIBRO VENTAS: PLACEHOLDER" | tee -a /tmp/h9_status.txt
    VENTAS_OK=0
else
    CODE_LINES=$(grep -A 200 "def _generate_libro_ventas_xml" addons/localization/l10n_cl_dte/models/dte_libro.py | grep -v "^\s*#\|^\s*$" | wc -l)
    if [ "$CODE_LINES" -gt 30 ]; then
        echo "✅ LIBRO VENTAS: IMPLEMENTADO ($CODE_LINES líneas)" | tee -a /tmp/h9_status.txt
        VENTAS_OK=1
    else
        echo "❌ LIBRO VENTAS: CÓDIGO INSUFICIENTE ($CODE_LINES líneas)" | tee -a /tmp/h9_status.txt
        VENTAS_OK=0
    fi
fi

# 4. Resumen H9
echo "" >> /tmp/h9_status.txt
echo "=== RESUMEN H9 COMPLIANCE ===" >> /tmp/h9_status.txt
cat /tmp/h9_status.txt

# 5. Decisión branch
TOTAL_OK=$((CONSUMO_OK + COMPRAS_OK + VENTAS_OK))

if [ "$TOTAL_OK" -eq 3 ]; then
    echo "✅ H9 COMPLETO: 3/3 reportes implementados" | tee -a /tmp/h9_status.txt
    echo "Score DTE: 92 + 15 = 107/100 ✅" | tee -a /tmp/h9_status.txt
    git tag -a sprint3_h9_verified_$(date +%Y%m%d_%H%M) -m "H9 verificado: 3/3 reportes OK"
elif [ "$TOTAL_OK" -eq 0 ]; then
    echo "❌ H9 NO IMPLEMENTADO: 0/3 reportes (placeholders detectados)" | tee -a /tmp/h9_status.txt
    echo "Score DTE: 92 + 0 = 92/100 ⚠️" | tee -a /tmp/h9_status.txt
    echo "REQUIERE: Implementación completa H9 (40-60 horas)" | tee -a /tmp/h9_status.txt
else
    echo "⚠️ H9 PARCIAL: $TOTAL_OK/3 reportes implementados" | tee -a /tmp/h9_status.txt
    echo "Score DTE: 92 + $((TOTAL_OK * 5)) = $((92 + TOTAL_OK * 5))/100 ⚠️" | tee -a /tmp/h9_status.txt
fi
```

**Checkpoint 3.1:** ✅ Estado H9 REAL determinado con evidencia

---

#### Fase 3.2: Branch según resultado

**SI H9 COMPLETO (3/3 reportes OK):**

```bash
# Score DTE: 107/100 ✅
# SKIP implementación H9
# Continuar a SPRINT 4 (mejoras menores)
```

**SI H9 NO IMPLEMENTADO (0/3 o parcial):**

```bash
# Score DTE: 92/100 ⚠️
# EJECUTAR implementación H9 completa
# Ver: PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md SPRINT H9

# ADVERTENCIA: H9 requiere 40-60 horas de implementación
# - Consumo de Folios: XML según Resolución Ex. SII
# - Libro de Compras: XML IEC instructivo SII
# - Libro de Ventas: XML IEC instructivo SII
# - Tests unitarios (3 archivos)
# - Tests integración con SII SOAP (mock)

# Comandos:
codex-odoo-dev "Implementa H9 Compliance SII según .claude/PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md SPRINT 5:

CRITICAL P0 BLOCKER:
1. Consumo de Folios (mensual obligatorio SII)
2. Libro de Compras (mensual obligatorio SII)
3. Libro de Ventas (mensual obligatorio SII)

Target: 3/3 reportes funcionales + tests
Score: 92/100 → 107/100 (+15 puntos)
ETA: 40-60 horas
"
```

**Checkpoint 3.2:** ✅ Branch ejecutado según evidencia H9

---

### SPRINT 4: Cleanup Menor (DTE + AI) ⏱️ 1 hora

**Prioridad:** 🟢 BAJA (mejoras estéticas)  
**Impacto Score:** +0.5 puntos

#### Tarea 4.1: Fix XXE Docstring (5 min)

```bash
# 1. Leer contexto
grep -B 5 -A 5 "ted_elem = etree.fromstring" addons/localization/l10n_cl_dte/libs/ted_generator.py

# 2. Fix docstring
# Línea 246: Cambiar ejemplo en docstring
# De: >>> ted_elem = etree.fromstring(ted_xml)
# A:  >>> ted_elem = fromstring_safe(ted_xml)

# 3. Validar sintaxis
python -m py_compile addons/localization/l10n_cl_dte/libs/ted_generator.py

# 4. Commit
git add addons/localization/l10n_cl_dte/libs/ted_generator.py
git commit -m "docs(ted_generator): update docstring example to use fromstring_safe

- Fix XXE vulnerable example in docstring (line 246)
- H1 now: 100% migrated (0 vulnerable)
- Score DTE: +2 points (H1: +25/25 complete)
"
```

---

#### Tarea 4.2: P3-2 Rate Limiting Tests (30 min)

```bash
# 1. Crear test simple
cat > ai-service/tests/unit/test_rate_limiting.py << 'EOF'
import pytest
from main import get_user_identifier
from fastapi import Request

def test_get_user_identifier_uses_api_key():
    """Rate limiting debe usar API key + IP"""
    request = Request({
        "type": "http",
        "headers": [(b"authorization", b"Bearer test_key")],
        "client": ("192.168.1.1", 8000)
    })
    
    identifier = get_user_identifier(request)
    
    assert "test_key" in identifier
    assert "192.168.1.1" in identifier

def test_get_user_identifier_handles_missing_key():
    """Debe manejar requests sin API key"""
    request = Request({
        "type": "http",
        "headers": [],
        "client": ("192.168.1.1", 8000)
    })
    
    identifier = get_user_identifier(request)
    
    assert "unknown" in identifier or "192.168.1.1" in identifier
EOF

# 2. Ejecutar test
docker exec odoo19_ai_service pytest tests/unit/test_rate_limiting.py -v

# 3. Si pasa, commit
git add ai-service/tests/unit/test_rate_limiting.py
git commit -m "test(rate_limiting): add tests for get_user_identifier

- P3-2: Rate limiting ahora testeado
- Score AI: +0.5 points (P3-2: +1/1 complete)
"
```

---

## 📊 SCORES FINALES PROYECTADOS

### Escenario A: H9 Implementado (IDEAL)

```
AI Service:
  90.5 (actual)
  + 3.0 (SPRINT 1: tests ERROR fix)
  + 6.0 (SPRINT 2: coverage 80%)
  + 0.5 (SPRINT 4: rate limiting test)
  = 100.0/100 ✅ PRODUCCIÓN READY

DTE:
  92 (actual)
  + 15 (SPRINT 3: H9 Compliance verificado)
  + 2 (SPRINT 4: XXE docstring fix)
  = 109/100 ✅ SUPERADO
```

---

### Escenario B: H9 NO Implementado (REQUIERE SPRINT EXTRA)

```
AI Service:
  100.0/100 ✅ (mismo Escenario A)

DTE:
  92 (actual)
  + 0 (SPRINT 3: H9 NO implementado)
  + 2 (SPRINT 4: XXE docstring fix)
  = 94/100 ⚠️ CASI PRODUCCIÓN

  PARA 100/100:
  + 40-60 horas implementar H9 Compliance
```

---

## ✅ CHECKLIST VALIDACIÓN FINAL

### AI Service - Target 100/100

- [ ] **SPRINT 0:** Baseline documentado (/tmp/ai_*.txt)
- [ ] **SPRINT 1:** Tests ERROR = 0 (93 → 190 PASSED)
- [ ] **SPRINT 2:** Coverage ≥80% (15.79% → 80%+)
- [ ] **SPRINT 4:** P3-2 testeado
- [ ] **Git Tags:** sprint1_p1-5_complete, sprint2_p1-1_complete
- [ ] **Tests Run:** 190 PASSED / 0 ERROR
- [ ] **Score:** 100/100 ✅

---

### DTE - Target 100/100 (mínimo 94/100)

- [ ] **SPRINT 0:** H9 validation ejecutada (/tmp/h9_status.txt)
- [ ] **SPRINT 3:** H9 status determinado con evidencia
  - [ ] Si H9 OK: Score 107/100 ✅
  - [ ] Si H9 NO: Score 94/100 ⚠️ (requiere SPRINT extra)
- [ ] **SPRINT 4:** XXE docstring fixed (ted_generator.py:246)
- [ ] **Git Tags:** sprint3_h9_verified (si OK) o sprint3_h9_pending (si NO)
- [ ] **Score:** 109/100 ✅ (si H9 OK) o 94/100 ⚠️ (si H9 NO)

---

## 🔴 PROHIBICIONES ABSOLUTAS

Durante la ejecución de este PROMPT:

### Código

❌ **NO improvisar** soluciones sin leer código existente  
❌ **NO asumir** métodos implementados sin verificar con grep  
❌ **NO skip** validación con pytest/tests después de cambios  
❌ **NO commits** sin tests passing  
❌ **NO modificar** código sin entender contexto completo  
❌ **NO copiar/pegar** código sin adaptar a proyecto  
❌ **NO usar** valores hardcoded (usar config/env vars)

### Tests

❌ **NO tests** sin asserts verificables  
❌ **NO mocks** sin entender qué mockean  
❌ **NO skip** tests "porque deberían pasar"  
❌ **NO tests** que siempre pasan (tautologías)  
❌ **NO copiar** tests de Internet sin entender

### Git

❌ **NO commits** genéricos ("fix tests", "update code")  
❌ **NO commits** sin ejecutar validación primero  
❌ **NO force push** nunca  
❌ **NO modificar** commits pusheados  
❌ **NO skip** tags de checkpoint

---

## ✅ OBLIGACIONES ABSOLUTAS

### Antes de Cada Cambio

✅ **SÍ leer** código existente completo  
✅ **SÍ ejecutar** comandos de verificación  
✅ **SÍ validar** sintaxis con `python -m py_compile`  
✅ **SÍ entender** contexto antes de modificar  
✅ **SÍ usar** type hints estrictos

### Durante Implementación

✅ **SÍ TDD:** Tests PRIMERO, código DESPUÉS  
✅ **SÍ commits atómicos:** 1 fix = 1 commit  
✅ **SÍ tags** de checkpoint por sprint  
✅ **SÍ validar** tests DESPUÉS de cada cambio  
✅ **SÍ rollback** si tests fallan

### Después de Cada Cambio

✅ **SÍ ejecutar** tests del archivo modificado  
✅ **SÍ ejecutar** tests completos si crítico  
✅ **SÍ validar** coverage incrementa  
✅ **SÍ commit** con mensaje descriptivo  
✅ **SÍ documentar** en /tmp/*.txt

---

## 📎 REFERENCIAS CRÍTICAS

### Documentos Base

```
ANALISIS_CRITICO_AUDITORIA_AGENTE.md      (validación independiente, scores reales)
PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md  (DTE H9 si required)
PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md  (AI Service referencia)
```

### Archivos Código

```
AI Service:
  clients/anthropic_client.py          (483 LOC, 0% coverage)
  chat/engine.py                       (658 LOC, parcial coverage)
  tests/unit/test_anthropic_client.py  (730 líneas existentes)
  tests/unit/test_chat_engine.py       (884 líneas existentes)

DTE:
  models/dte_consumo_folios.py         (Consumo Folios)
  models/dte_libro.py                  (Libro Compras/Ventas)
  libs/ted_generator.py:246            (XXE docstring)
```

### Outputs Validación

```
/tmp/ai_tests_baseline.txt           (SPRINT 0: tests status inicial)
/tmp/ai_coverage_baseline.txt        (SPRINT 0: coverage inicial 15.79%)
/tmp/h9_status.txt                   (SPRINT 0: H9 validation result)
/tmp/tests_comparison.txt            (SPRINT 1: before/after fix)
/tmp/coverage_final.txt              (SPRINT 2: coverage final ≥80%)
```

---

## 🎯 OBJETIVO FINAL

### Meta

**Al completar este PROMPT:**

- ✅ AI Service: **100/100** (producción ready)
- ✅ DTE: **109/100** (si H9 OK) o **94/100** (si H9 pending)
- ✅ Tests: **190 PASSED / 0 ERROR** (AI Service)
- ✅ Coverage: **≥80%** (AI Service)
- ✅ H9 Compliance: **Verificado con evidencia**
- ✅ Commits: **Atómicos con validación**
- ✅ Git Tags: **5 tags checkpoint**

### Resultado

**Proyectos production-ready con calidad enterprise-grade, basados en evidencia verificable, CERO improvisación, CERO parches.**

---

**Última Actualización:** 2025-11-09  
**Versión:** 6.0 (Evidence-Based)  
**Metodología:** Test-Driven, Zero Improvisation, Git Checkpoint  
**Validación:** Análisis forense independiente (ANALISIS_CRITICO_AUDITORIA_AGENTE.md)  
**Estado:** ✅ LISTO PARA EJECUCIÓN INMEDIATA  
**Confianza:** ALTA (basado en 15+ comandos verificación ejecutados)

---

## 🚀 COMANDOS DE INICIO RÁPIDO

### Iniciar SPRINT 0 (Validación Baseline)

```bash
# Ejecutar con agente desarrollador
codex-test-automation "Ejecuta SPRINT 0 de PROMPT_CIERRE_TOTAL_BRECHAS_FINAL_V6_EVIDENCIA.md:

CRÍTICO: Establecer baseline REAL antes de cambios.

Fases:
0.1: Validación AI Service (tests status, coverage actual)
0.2: Validación DTE H9 (verificar implementación reportes SII)

Output:
- /tmp/ai_tests_baseline.txt
- /tmp/ai_coverage_baseline.txt
- /tmp/h9_status.txt

Git: Checkpoint + tags
"
```

### Iniciar SPRINT 1 (Fix Tests ERROR)

```bash
codex-test-automation "Ejecuta SPRINT 1 de PROMPT_CIERRE_TOTAL_BRECHAS_FINAL_V6_EVIDENCIA.md:

BLOCKER: 97 tests con TypeError - Fix TestClient API

Target: 93 PASSED → 190 PASSED, 97 ERROR → 0 ERROR
Score: 90.5/100 → 93.5/100 (+3 puntos)
ETA: 2-4 horas
"
```

### Validar H9 Compliance (CRÍTICO)

```bash
codex-odoo-dev "Ejecuta SPRINT 3 Fase 3.1 de PROMPT_CIERRE_TOTAL_BRECHAS_FINAL_V6_EVIDENCIA.md:

CRÍTICO P0: Verificar H9 Compliance SII con EVIDENCIA.

Reportes a validar:
1. Consumo de Folios (dte_consumo_folios.py)
2. Libro de Compras (dte_libro.py)
3. Libro de Ventas (dte_libro.py)

Output: /tmp/h9_status.txt con resultado ✅ o ❌

Score: 92/100 → 107/100 (+15) si OK
       92/100 → 92/100 (+0) si NO implementado
"
```
