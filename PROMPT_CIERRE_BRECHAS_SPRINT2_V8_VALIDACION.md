# 🎯 PROMPT PROFESIONAL: CIERRE BRECHAS SPRINT 2 - VALIDACIÓN Y CONTINUACIÓN

**Versión:** 8.0 (Post-Análisis Crítico Sesión 40min)  
**Fecha:** 2025-11-09  
**Proyecto:** EERGYGROUP Odoo 19 CE - AI Service  
**Base:** ANALISIS_CRITICO_SPRINT2_SESION_40MIN_2025-11-09.md  
**Metodología:** Evidence-Based, Test-Driven, Coverage Verification Mandatory  
**Objetivo:** Resolver discrepancia coverage y alcanzar ≥80%

---

## 📋 CONTEXTO EJECUTIVO - ESTADO POST-40MIN

### 🔴 PROBLEMA CRÍTICO DETECTADO

**Discrepancia Coverage:**

| Métrica | Claim Agente | Real Verificado | Discrepancia |
|---------|--------------|-----------------|--------------|
| **Coverage Total** | 41-50% | **15.82%** | **-25 a -34%** 🔴 |
| **Tests Creados** | 24 | ✅ 24 verificado | ✅ CORRECTO |
| **Tests Colectados** | 223 | ✅ 223 verificado | ✅ CORRECTO |
| **Commits** | 4 | ✅ 4 verificado | ✅ CORRECTO |

**Root Cause Posible:**
1. Coverage medido de `main.py` específico (41%) vs total proyecto (15.82%)
2. Tests con mocks excesivos (NO ejecutan código real)
3. Tests colectados pero fallan/skip silenciosamente

### ✅ Progreso Verificado (40 min trabajo)

```
Fase 2.0: Pre-validation         ✅ COMPLETO (commit a7fc36e4)
Fase 2.1: Fix SYSTEM_PROMPT_BASE ✅ COMPLETO (commit 0dcc15bf)
Fase 2.2 Batch 1: 16 tests       ✅ COMPLETO (commit b3e69bc0)
Fase 2.2 Batch 2: 8 tests        ⚠️ CREADO (NOT committed)
Fase 2.3-2.4: Coverage 80%       ⏸️ BLOQUEADO (pending validation)

Tiempo Usado: 40 min / 6-8h (8%)
Coverage Real: 15.82% (gap: -64.18% to target 80%)
```

---

## 🎯 OBJETIVO DEL PROMPT

**Alcance:**
1. ✅ **VALIDAR** coverage real (22 min - CRÍTICO)
2. ✅ **COMMIT** trabajo Batch 2 pendiente (2 min)
3. ✅ **DECIDIR** estrategia según resultados validación
4. ✅ **EJECUTAR** Fase 2.3-2.4 con metodología corregida
5. ✅ **ALCANZAR** coverage ≥80% con tests efectivos

**Resultado Esperado:**
- Coverage: 15.82% → ≥80% (+64.18%)
- Tests: 223 → ~300-350 (estimado +100-150 tests efectivos)
- Score AI: 87/100 → 103/100 (+16 pts)
- Metodología: Coverage verification MANDATORY cada batch

**Tiempo Total:** 5-8 horas (depende validación)

---

## 🔴 FASE CRÍTICA: VALIDACIÓN COVERAGE (MANDATORY - 22 MIN)

### ⚠️ EJECUTAR ANTES DE CONTINUAR

**Problema:** Discrepancia -25 a -34% entre claim y realidad requiere investigación.

### Paso 1: Medir Coverage Real (5 min)

```bash
# 1.1 Coverage TOTAL proyecto
docker exec odoo19_ai_service pytest --cov=. --cov-report=term --cov-report=json -q 2>&1 | tee /tmp/sprint2_coverage_total.txt

# Extraer métrica
grep "TOTAL" /tmp/sprint2_coverage_total.txt | awk '{print "Coverage TOTAL:", $4}'

# 1.2 Coverage main.py ESPECÍFICO
docker exec odoo19_ai_service pytest --cov=main --cov-report=term-missing -q 2>&1 | tee /tmp/sprint2_coverage_main.txt

# Extraer métrica
grep "main.py" /tmp/sprint2_coverage_main.txt | awk '{print "Coverage main.py:", $4}'

# 1.3 Coverage por archivo crítico
docker exec odoo19_ai_service pytest \
  --cov=main \
  --cov=chat/engine \
  --cov=clients/anthropic_client \
  --cov-report=term-missing -q 2>&1 | tee /tmp/sprint2_coverage_breakdown.txt

# 1.4 Documentar resultados
cat > /tmp/sprint2_coverage_validation.txt <<EOF
=== SPRINT 2 COVERAGE VALIDATION ===
Date: $(date +"%Y-%m-%d %H:%M:%S")

Coverage TOTAL:       $(grep "TOTAL" /tmp/sprint2_coverage_total.txt | awk '{print $4}')
Coverage main.py:     $(grep "main.py" /tmp/sprint2_coverage_main.txt | awk '{print $4}')
Coverage chat/engine: $(grep "chat/engine" /tmp/sprint2_coverage_breakdown.txt | awk '{print $4}')
Coverage anthropic:   $(grep "anthropic_client" /tmp/sprint2_coverage_breakdown.txt | awk '{print $4}')

Discrepancy Analysis:
- Claim:  41-50% total
- Real:   [SEE ABOVE]
- Delta:  [CALCULATE]

Root Cause: [TO BE DETERMINED]
EOF

cat /tmp/sprint2_coverage_validation.txt
```

**Checkpoint 1.0:** ✅ Coverage real medido y documentado

---

### Paso 2: Validar Tests Efectividad (10 min)

```bash
# 2.1 Ejecutar tests del archivo nuevo
docker exec odoo19_ai_service pytest tests/integration/test_main_endpoints.py -v --tb=short 2>&1 | tee /tmp/sprint2_tests_execution.txt

# 2.2 Contar resultados
PASSED=$(grep -c "PASSED" /tmp/sprint2_tests_execution.txt || echo "0")
FAILED=$(grep -c "FAILED" /tmp/sprint2_tests_execution.txt || echo "0")
ERROR=$(grep -c "ERROR" /tmp/sprint2_tests_execution.txt || echo "0")
SKIPPED=$(grep -c "SKIPPED" /tmp/sprint2_tests_execution.txt || echo "0")

echo "Tests PASSED:  $PASSED / 24"
echo "Tests FAILED:  $FAILED / 24"
echo "Tests ERROR:   $ERROR / 24"
echo "Tests SKIPPED: $SKIPPED / 24"

# 2.3 Analizar mocks usage
echo ""
echo "=== MOCK ANALYSIS ==="
PATCHES=$(grep -c "@patch\|@mock" ai-service/tests/integration/test_main_endpoints.py || echo "0")
TESTCLIENT=$(grep -c "TestClient" ai-service/tests/integration/test_main_endpoints.py || echo "0")

echo "Mock/Patch decorators: $PATCHES"
echo "TestClient usage:      $TESTCLIENT"
echo "Ratio mocks/tests:     $(echo "scale=2; $PATCHES / 24" | bc)"

# 2.4 Test sample individual con coverage
echo ""
echo "=== TESTING SAMPLE TEST COVERAGE ==="
docker exec odoo19_ai_service pytest \
  tests/integration/test_main_endpoints.py::test_health_endpoint \
  --cov=main --cov-report=term-missing -v 2>&1 | grep -A 5 "main.py"

# 2.5 Documentar análisis
cat >> /tmp/sprint2_coverage_validation.txt <<EOF

=== TESTS EFFECTIVENESS ANALYSIS ===

Tests Execution:
- PASSED:  $PASSED / 24
- FAILED:  $FAILED / 24
- ERROR:   $ERROR / 24
- SKIPPED: $SKIPPED / 24

Mock Analysis:
- @patch/@mock decorators: $PATCHES
- Ratio mocks/tests:       $(echo "scale=2; $PATCHES / 24" | bc)

Effectiveness:
- If ratio > 0.5: ⚠️ Excessive mocks (tests may not execute real code)
- If PASSED < 20: ⚠️ Tests failing/skipping
- If coverage main.py < 30%: ❌ Tests NOT effective

EOF

cat /tmp/sprint2_coverage_validation.txt
```

**Checkpoint 2.0:** ✅ Tests efectividad analizada y documentada

---

### Paso 3: Decisión Estratégica (5 min)

```bash
# 3.1 Leer métricas validadas
COVERAGE_TOTAL=$(grep "Coverage TOTAL:" /tmp/sprint2_coverage_validation.txt | awk '{print $3}' | sed 's/%//')
COVERAGE_MAIN=$(grep "Coverage main.py:" /tmp/sprint2_coverage_validation.txt | awk '{print $3}' | sed 's/%//')
TESTS_PASSED=$(grep "PASSED:" /tmp/sprint2_coverage_validation.txt | awk '{print $3}' | cut -d'/' -f1)

# 3.2 Determinar escenario
echo ""
echo "=== DECISION MATRIX ==="

if [ $(echo "$COVERAGE_MAIN > 35" | bc) -eq 1 ] && [ $TESTS_PASSED -gt 20 ]; then
    SCENARIO="A"
    echo "SCENARIO A: Tests Efectivos ✅"
    echo "- Coverage main.py: $COVERAGE_MAIN% (>35%)"
    echo "- Tests passing:    $TESTS_PASSED/24 (>20)"
    echo "- Decision:         CONTINUAR Fase 2.3 (otros archivos)"
    echo "- Root Cause:       Confusión metrics (main.py vs total)"
    echo "- ETA:              5-6h restantes"
elif [ $(echo "$COVERAGE_MAIN < 20" | bc) -eq 1 ] || [ $TESTS_PASSED -lt 15 ]; then
    SCENARIO="B"
    echo "SCENARIO B: Tests NO Efectivos ❌"
    echo "- Coverage main.py: $COVERAGE_MAIN% (<20%)"
    echo "- Tests passing:    $TESTS_PASSED/24 (<15)"
    echo "- Decision:         REFACTORIZAR tests (quitar mocks)"
    echo "- Root Cause:       Mocks excesivos, tests NO ejecutan código"
    echo "- ETA:              6.5-8.5h restantes (+1-2h refactor)"
else
    SCENARIO="C"
    echo "SCENARIO C: Parcial ⚠️"
    echo "- Coverage main.py: $COVERAGE_MAIN% (20-35%)"
    echo "- Tests passing:    $TESTS_PASSED/24 (15-20)"
    echo "- Decision:         OPTIMIZAR tests + agregar más"
    echo "- Root Cause:       Tests parcialmente efectivos"
    echo "- ETA:              6-7h restantes"
fi

# 3.3 Documentar decisión
cat >> /tmp/sprint2_coverage_validation.txt <<EOF

=== DECISION ===

Scenario:   $SCENARIO
Coverage:   $COVERAGE_MAIN% main.py, $COVERAGE_TOTAL% total
Tests:      $TESTS_PASSED/24 passing
Strategy:   [SEE ABOVE]
ETA:        [SEE ABOVE]

Next Steps: Execute Fase 2.3+ según Scenario $SCENARIO
EOF

cat /tmp/sprint2_coverage_validation.txt
```

**Checkpoint 3.0:** ✅ Escenario identificado, estrategia definida

---

### Paso 4: Commit Trabajo Pendiente (2 min)

```bash
# 4.1 Verificar cambios no commiteados
git status | grep "test_main_endpoints.py"

# 4.2 Commit Batch 2
git add ai-service/tests/integration/test_main_endpoints.py
git commit -m "test(main): add Batch 2 integration tests (8 additional)

SPRINT 2 - Fase 2.2 Batch 2

Tests Added: 8 (payroll, SII validation)
Total Tests: 24 in test_main_endpoints.py
Coverage:
- main.py:  $COVERAGE_MAIN% (measured)
- Total:    $COVERAGE_TOTAL% (measured)

Scenario: $SCENARIO
Status: Tests created, effectiveness validation complete

Related: SPRINT 2 Coverage target 80%
Validation: /tmp/sprint2_coverage_validation.txt
"

# 4.3 Git tag checkpoint
git tag -a sprint2_batch2_validation_$(date +%Y%m%d_%H%M) -m "SPRINT 2 Batch 2 validation complete - Scenario $SCENARIO"

echo "✅ Commit y tag creados"
```

**Checkpoint 4.0:** ✅ Trabajo pendiente guardado con evidencia

---

## 🔀 BIFURCACIÓN SEGÚN ESCENARIO

### SCENARIO A: Tests Efectivos (Coverage main.py >35%)

**Diagnóstico:**
- ✅ Tests ejecutan código real
- ✅ Coverage main.py avanzando
- ⚠️ Coverage total bajo porque solo main.py mejorado

**Estrategia:** CONTINUAR Fase 2.3 (otros archivos)

**Pasar a:** [FASE 2.3 - SCENARIO A](#fase-23-scenario-a-coverage-otros-archivos)

---

### SCENARIO B: Tests NO Efectivos (Coverage main.py <20%)

**Diagnóstico:**
- ❌ Tests NO ejecutan código real
- ❌ Mocks excesivos bloquean ejecución
- 🔴 BLOQUEANTE: Refactor necesario antes continuar

**Estrategia:** REFACTORIZAR tests Batch 1+2

**Pasar a:** [FASE 2.2B - SCENARIO B](#fase-22b-scenario-b-refactor-tests)

---

### SCENARIO C: Parcial (Coverage main.py 20-35%)

**Diagnóstico:**
- ⚠️ Tests parcialmente efectivos
- ⚠️ Algunos mocks innecesarios
- ✅ Optimización + tests adicionales

**Estrategia:** OPTIMIZAR + CONTINUAR

**Pasar a:** [FASE 2.2C - SCENARIO C](#fase-22c-scenario-c-optimizar-y-continuar)

---

## 🎯 FASE 2.3 - SCENARIO A: COVERAGE OTROS ARCHIVOS

**Pre-Requisitos:**
- ✅ Scenario A validado (main.py >35%)
- ✅ Commit Batch 2 guardado
- ✅ 24 tests efectivos funcionando

### Fase 2.3a: Coverage chat/engine.py (1.5-2h)

**Target:** 14% → 85% (+132 stmts, ~25-30 tests)

**Archivo:** `ai-service/chat/engine.py` (658 LOC)

#### Pre-Análisis Coverage

```bash
# 1. Identificar métodos sin coverage
docker exec odoo19_ai_service pytest --cov=chat/engine --cov-report=term-missing -q 2>&1 | grep "chat/engine.py" -A 20 > /tmp/engine_coverage_missing.txt

# 2. Listar métodos principales
grep "^\s*def " ai-service/chat/engine.py | grep -v "^\s*def _" | nl

# 3. Priorizar por uso (grep en tests existentes)
for method in $(grep "^\s*def " ai-service/chat/engine.py | grep -v "^\s*def _" | awk '{print $2}' | cut -d'(' -f1); do
    count=$(grep -r "$method" ai-service/tests --include="*.py" | wc -l)
    echo "$count tests - $method"
done | sort -rn | head -15

# 4. Identificar gaps críticos
echo "=== MÉTODOS SIN TESTS ===" > /tmp/engine_methods_gaps.txt
grep "^\s*def " ai-service/chat/engine.py | grep -v "^\s*def _" | while read line; do
    method=$(echo "$line" | awk '{print $2}' | cut -d'(' -f1)
    count=$(grep -r "$method" ai-service/tests --include="*.py" | wc -l)
    if [ $count -eq 0 ]; then
        echo "❌ $method (0 tests)" >> /tmp/engine_methods_gaps.txt
    fi
done

cat /tmp/engine_methods_gaps.txt
```

#### Tests a Crear (25-30 tests)

**Crear archivo:** `ai-service/tests/unit/test_chat_engine_extended.py`

```python
"""Extended tests for ChatEngine - Coverage gaps"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from chat.engine import ChatEngine
from config import Settings

class TestChatEngineCore:
    """Tests para métodos core sin coverage"""
    
    @pytest.fixture
    def engine(self):
        """ChatEngine instance con config test"""
        settings = Settings(
            anthropic_api_key="test_key",
            model="claude-3-5-sonnet-20241022"
        )
        return ChatEngine(settings)
    
    @pytest.mark.asyncio
    async def test_process_message_basic_flow(self, engine):
        """process_message debe manejar flujo básico correctamente"""
        with patch.object(engine.client, 'send_message', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {
                'content': 'Test response',
                'usage': {'input_tokens': 10, 'output_tokens': 20}
            }
            
            result = await engine.process_message(
                messages=[{'role': 'user', 'content': 'Test'}],
                context={}
            )
            
            assert result['content'] == 'Test response'
            assert result['usage']['input_tokens'] == 10
            mock_send.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_message_with_knowledge_base(self, engine):
        """process_message debe integrar knowledge base cuando disponible"""
        with patch.object(engine, '_get_knowledge_context', return_value={'docs': ['doc1']}) as mock_kb:
            with patch.object(engine.client, 'send_message', new_callable=AsyncMock) as mock_send:
                mock_send.return_value = {'content': 'KB response', 'usage': {}}
                
                result = await engine.process_message(
                    messages=[{'role': 'user', 'content': 'Query KB'}],
                    use_kb=True
                )
                
                mock_kb.assert_called_once()
                assert result['content'] == 'KB response'
    
    @pytest.mark.asyncio
    async def test_process_message_error_handling(self, engine):
        """process_message debe manejar errores de API correctamente"""
        with patch.object(engine.client, 'send_message', new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = Exception("API Error")
            
            with pytest.raises(Exception) as exc_info:
                await engine.process_message(
                    messages=[{'role': 'user', 'content': 'Test'}]
                )
            
            assert "API Error" in str(exc_info.value)
    
    def test_format_messages_validates_structure(self, engine):
        """format_messages debe validar estructura de mensajes"""
        messages = [
            {'role': 'user', 'content': 'Hello'},
            {'role': 'assistant', 'content': 'Hi'}
        ]
        
        formatted = engine.format_messages(messages)
        
        assert len(formatted) == 2
        assert all('role' in msg for msg in formatted)
        assert all('content' in msg for msg in formatted)
    
    def test_format_messages_filters_invalid(self, engine):
        """format_messages debe filtrar mensajes inválidos"""
        messages = [
            {'role': 'user', 'content': 'Valid'},
            {'role': 'invalid'},  # Sin content
            {'content': 'No role'}  # Sin role
        ]
        
        formatted = engine.format_messages(messages)
        
        assert len(formatted) == 1
        assert formatted[0]['role'] == 'user'
    
    # ... 20-25 tests más para cubrir métodos restantes
```

**Proceso Implementación:**

```bash
# 1. Crear archivo test (iterativo, 5 tests a la vez)
touch ai-service/tests/unit/test_chat_engine_extended.py

# 2. Implementar 5 tests
# (usar editor)

# 3. Ejecutar tests SOLO de este archivo
docker exec odoo19_ai_service pytest tests/unit/test_chat_engine_extended.py -v

# 4. Medir coverage incremental
docker exec odoo19_ai_service pytest --cov=chat/engine --cov-report=term-missing tests/unit/test_chat_engine_extended.py -v | tee /tmp/engine_coverage_batch1.txt

# 5. Commit cada 5-10 tests
git add ai-service/tests/unit/test_chat_engine_extended.py
git commit -m "test(chat_engine): add 5 core method tests

Coverage chat/engine: XX% → YY% (+ZZ%)
Tests: test_process_message_*, test_format_messages_*
Lines covered: [LIST]
"

# 6. Repetir hasta coverage ≥85%
```

**Checkpoint 2.3a:** ✅ `chat/engine.py` coverage ≥85%

---

### Fase 2.3b: Coverage clients/anthropic_client.py (1h)

**Target:** 14% → 85% (+74 stmts, ~15-20 tests)

**Proceso similar a 2.3a:**
1. Identificar métodos sin coverage
2. Crear `test_anthropic_client_extended.py`
3. Implementar tests 5 a la vez
4. Medir coverage incremental
5. Commit cada batch

**Checkpoint 2.3b:** ✅ `anthropic_client.py` coverage ≥85%

---

### Fase 2.3c-e: Coverage Otros Módulos (2-3h)

**Targets:**
- chat/kb.py, chat/context.py: →70% (+176 stmts)
- plugins/loader.py, plugins/registry.py: →60% (+217 stmts)
- utils críticos: →60% (+180 stmts)

**Proceso:** Similar a 2.3a-b, priorizando archivos críticos

---

### Fase 2.4: Validación Final y Score (30 min)

```bash
# 1. Coverage final
docker exec odoo19_ai_service pytest --cov=. --cov-report=term --cov-report=json --cov-fail-under=80 -v 2>&1 | tee /tmp/sprint2_coverage_final.txt

# 2. Extraer métricas
COVERAGE_FINAL=$(grep "TOTAL" /tmp/sprint2_coverage_final.txt | awk '{print $4}' | sed 's/%//')

# 3. Tests status
docker exec odoo19_ai_service pytest -v --tb=no 2>&1 | tee /tmp/sprint2_tests_final.txt
TESTS_PASSED=$(grep -c "PASSED" /tmp/sprint2_tests_final.txt)
TESTS_FAILED=$(grep -c "FAILED" /tmp/sprint2_tests_final.txt)
TESTS_ERROR=$(grep -c "ERROR" /tmp/sprint2_tests_final.txt)

# 4. Calcular score
cat > /tmp/sprint2_score_final.txt <<EOF
=== SPRINT 2 SCORE FINAL ===

Baseline: 82/100

Bonificaciones:
+ P1-1 (Coverage ≥80%): +7 pts ($COVERAGE_FINAL%)
+ P1-2 (TODOs complete): +3 pts
+ P1-3 (Redis HA): +2 pts
+ P1-4 (pytest config): +1 pt
+ P1-5 (Integration 0 ERROR): +3 pts
+ P2 (KB+Health+Prom): +3 pts
+ P3 (Docs+Rate): +2 pts

Penalties:
- Tests FAILED: $(if [ $TESTS_FAILED -gt 10 ]; then echo "-2 pts"; else echo "0 pts"; fi)

SCORE FINAL: $(if [ $(echo "$COVERAGE_FINAL >= 80" | bc) -eq 1 ]; then echo "103/100 ✅"; else echo "96/100 ⚠️"; fi)
EOF

cat /tmp/sprint2_score_final.txt

# 5. Git tag final
git tag -a sprint2_complete_$(date +%Y%m%d_%H%M) -m "SPRINT 2 Complete: Coverage $COVERAGE_FINAL%"

# 6. Commit final
git add .
git commit -m "feat(sprint2): complete coverage sprint - ${COVERAGE_FINAL}% achieved

SPRINT 2 COMPLETE:
- Coverage: 15.82% → ${COVERAGE_FINAL}% (+$(echo "$COVERAGE_FINAL - 15.82" | bc)%)
- Tests: 223 → $(grep -c "collected" /tmp/sprint2_tests_final.txt) (+$(echo "$(grep -c "collected" /tmp/sprint2_tests_final.txt) - 223" | bc))
- Score AI: 87/100 → $(grep "SCORE FINAL" /tmp/sprint2_score_final.txt | awk '{print $3}')
- Production ready: $(if [ $(echo "$COVERAGE_FINAL >= 80" | bc) -eq 1 ]; then echo "YES ✅"; else echo "NO ⚠️"; fi)

Files improved: main.py, chat/engine.py, anthropic_client.py, [OTHERS]
Tests created: ~100-150 nuevos tests
Methodology: Evidence-Based, Coverage Verification Mandatory
"
```

**Checkpoint 2.4:** ✅ Coverage ≥80%, Score calculado, SPRINT 2 COMPLETO

---

## 🔧 FASE 2.2B - SCENARIO B: REFACTOR TESTS

**Pre-Requisitos:**
- ⚠️ Scenario B detectado (main.py <20%)
- 🔴 Tests NO efectivos (mocks excesivos)
- Commit Batch 2 guardado

### Diagnóstico Profundo (30 min)

```bash
# 1. Analizar tests actuales línea por línea
cat ai-service/tests/integration/test_main_endpoints.py | grep -n "@patch\|@mock\|TestClient" > /tmp/tests_analysis.txt

# 2. Identificar patterns problemáticos
echo "=== PROBLEMATIC PATTERNS ===" > /tmp/tests_refactor_plan.txt

# Pattern 1: Mock app completo
grep -n "@patch.*main.app" ai-service/tests/integration/test_main_endpoints.py | while read line; do
    echo "❌ Line $line: Mocking entire app (0% coverage)" >> /tmp/tests_refactor_plan.txt
done

# Pattern 2: Mock settings globales
grep -n "@patch.*config.settings" ai-service/tests/integration/test_main_endpoints.py | while read line; do
    echo "⚠️ Line $line: Mocking settings (reduce coverage)" >> /tmp/tests_refactor_plan.txt
done

# Pattern 3: TestClient sin mocks (BUENO)
grep -n "TestClient" ai-service/tests/integration/test_main_endpoints.py | while read line; do
    echo "✅ Line $line: TestClient usage (good)" >> /tmp/tests_refactor_plan.txt
done

cat /tmp/tests_refactor_plan.txt

# 3. Contar tests por patrón
MOCK_APP=$(grep -c "@patch.*main.app" ai-service/tests/integration/test_main_endpoints.py || echo "0")
MOCK_SETTINGS=$(grep -c "@patch.*config.settings" ai-service/tests/integration/test_main_endpoints.py || echo "0")
TESTCLIENT_ONLY=$(grep -c "TestClient" ai-service/tests/integration/test_main_endpoints.py || echo "0")

echo ""
echo "Tests con @patch app:      $MOCK_APP (ELIMINAR)"
echo "Tests con @patch settings: $MOCK_SETTINGS (MINIMIZAR)"
echo "Tests con TestClient:      $TESTCLIENT_ONLY (MANTENER)"
```

### Refactorización Tests (1-2h)

**Estrategia:**
1. Identificar tests con mocks excesivos
2. Reescribir SIN mocks innecesarios
3. Usar TestClient directo (ejecuta código real)
4. Mocks SOLO para dependencias externas (APIs, DB)

**Ejemplo Refactor:**

```python
# ❌ ANTES (0% coverage)
@patch('main.app.state')
@patch('config.settings')
def test_health_endpoint(mock_settings, mock_state):
    mock_settings.enable_health_checks = True
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200

# ✅ DESPUÉS (100% coverage)
def test_health_endpoint():
    """Test health endpoint ejecuta código real"""
    from main import app
    client = TestClient(app)
    
    # TestClient ejecuta código real de main.py
    response = client.get("/health")
    
    assert response.status_code == 200
    assert "status" in response.json()
    assert response.json()["status"] in ["healthy", "unhealthy"]
    # Coverage: Ejecutó /health endpoint completo
```

**Proceso:**

```bash
# 1. Backup archivo original
cp ai-service/tests/integration/test_main_endpoints.py ai-service/tests/integration/test_main_endpoints.py.backup

# 2. Refactorizar 5 tests a la vez
# (usar editor, eliminar @patch innecesarios)

# 3. Ejecutar tests refactorizados
docker exec odoo19_ai_service pytest tests/integration/test_main_endpoints.py -v --tb=short

# 4. Medir coverage después refactor
docker exec odoo19_ai_service pytest --cov=main --cov-report=term-missing tests/integration/test_main_endpoints.py -v | tee /tmp/coverage_after_refactor.txt

# 5. Validar mejora
COVERAGE_BEFORE=$(grep "main.py" /tmp/sprint2_coverage_main.txt | awk '{print $4}')
COVERAGE_AFTER=$(grep "main.py" /tmp/coverage_after_refactor.txt | awk '{print $4}')

echo "Coverage BEFORE refactor: $COVERAGE_BEFORE"
echo "Coverage AFTER refactor:  $COVERAGE_AFTER"
echo "Improvement:              +$(echo "$COVERAGE_AFTER - $COVERAGE_BEFORE" | bc | sed 's/%//')%"

# 6. Commit refactor
git add ai-service/tests/integration/test_main_endpoints.py
git commit -m "refactor(tests): remove excessive mocks - improve coverage effectiveness

PROBLEM:
- Tests had excessive @patch decorators
- Mocked entire app/settings (0% real code execution)
- Coverage main.py stuck at ${COVERAGE_BEFORE}%

SOLUTION:
- Removed unnecessary @patch('main.app') decorators
- Use TestClient directly (executes real code)
- Mock ONLY external dependencies (APIs, DB)

RESULTS:
- Coverage main.py: ${COVERAGE_BEFORE}% → ${COVERAGE_AFTER}% (+$(echo "$COVERAGE_AFTER - $COVERAGE_BEFORE" | bc)%)
- Tests still passing: $(grep -c "PASSED" /tmp/coverage_after_refactor.txt)/24
- Real code execution: ✅

Fixes: SPRINT 2 Scenario B (tests not effective)
"

# 7. Si coverage ahora >35%: CONTINUAR Fase 2.3 (Scenario A)
if [ $(echo "$COVERAGE_AFTER > 35" | bc | sed 's/%//') -eq 1 ]; then
    echo "✅ Coverage mejorado, cambiar a Scenario A"
    echo "Ejecutar: FASE 2.3 - SCENARIO A"
else
    echo "⚠️ Coverage aún bajo, agregar más tests efectivos"
fi
```

**Checkpoint 2.2B:** ✅ Tests refactorizados, coverage main.py >35%

**Siguiente Paso:** Continuar con Fase 2.3 (Scenario A)

---

## 🔀 FASE 2.2C - SCENARIO C: OPTIMIZAR Y CONTINUAR

**Pre-Requisitos:**
- ⚠️ Scenario C detectado (main.py 20-35%)
- Tests parcialmente efectivos
- Optimización + tests adicionales necesarios

### Estrategia Híbrida (2-3h)

1. **Optimizar tests existentes** (30 min)
   - Reducir mocks innecesarios (no todos)
   - Mejorar asserts (validar más)
   - Agregar casos edge

2. **Agregar tests para gaps** (1.5h)
   - Identificar líneas NO ejecutadas
   - Crear tests específicos para esas líneas
   - Usar `--cov-report=term-missing`

3. **Continuar con otros archivos** (1h)
   - Empezar Fase 2.3a (chat/engine)
   - Paralelizar trabajo

**Checkpoint 2.2C:** ✅ main.py >50%, inicio Fase 2.3

---

## 📊 SCORING FINAL PROYECTADO

### Escenario A (Tests Efectivos)

```
Baseline: 82/100

Aplicados (SPRINT 2 completo):
+ P1-1 (Coverage ≥80%): +7 pts
+ P1-2 (TODOs): +3 pts
+ P1-3 (Redis HA): +2 pts
+ P1-4 (pytest): +1 pt
+ P1-5 (Integration 0 ERROR): +3 pts
+ P2 (KB+Health+Prom): +3 pts
+ P3 (Docs+Rate): +2 pts

Score Final: 82 + 21 = 103/100 ✅ TARGET
Production Ready: YES ✅
ETA: 5-6h restantes
```

### Escenario B (Refactor Necesario)

```
Baseline: 82/100

Con refactor exitoso:
+ (Same as A)

Score Final: 103/100 ✅
Production Ready: YES ✅
ETA: 6.5-8.5h restantes (+1-2h refactor)
```

### Escenario C (Optimización)

```
Baseline: 82/100

Con optimización:
+ (Same as A)

Score Final: 103/100 ✅
Production Ready: YES ✅
ETA: 6-7h restantes
```

---

## ✅ CRITERIOS DE ÉXITO SPRINT 2

### Obligatorio (Must Have)

- [ ] **Validación Coverage Ejecutada** (22 min - CRÍTICO)
- [ ] **Commit Batch 2 Guardado** (2 min)
- [ ] **Escenario Identificado** (A, B, o C)
- [ ] **Coverage ≥80%** (global, verificado con pytest)
- [ ] **Tests PASSED ≥90%** (de todos colectados)
- [ ] **0 ERROR tests** (mantener logro)
- [ ] **main.py ≥60%** (endpoint críticos)
- [ ] **chat/engine.py ≥85%** (core chat)
- [ ] **anthropic_client.py ≥85%** (API integration)
- [ ] **Coverage Verification MANDATORY** (cada batch)
- [ ] **Commits Atómicos** (1 cada 10-15 tests)
- [ ] **Git Tags** (sprint2_validation, sprint2_complete)

### Deseable (Nice to Have)

- [ ] **Coverage ≥85%** (superación target)
- [ ] **Tests PASSED 100%** (todos passing)
- [ ] **utils ≥60%** (coverage utilities)
- [ ] **plugins ≥60%** (loader/registry)
- [ ] **Documentación tests** (docstrings descriptivos)

### Prohibido (Must NOT)

- ❌ Continuar sin validar coverage (MANDATORY 22 min validation)
- ❌ Tests que siempre pasan (tautologías)
- ❌ Mocks excesivos (bloquean ejecución código real)
- ❌ Skip coverage verification por "rapidez"
- ❌ Commits sin medir coverage
- ❌ Asumir metrics sin comandos evidencia

---

## 🔴 RESTRICCIONES ABSOLUTAS (HEREDADAS + NUEVAS)

### Coverage Verification (NUEVO - CRÍTICO)

✅ **MANDATORY** después de CADA batch tests:
```bash
docker exec odoo19_ai_service pytest --cov=. --cov-report=term -q | grep "TOTAL"
```

✅ **DOCUMENTAR** en commit message:
```
Coverage: 15.82% → 23.45% (+7.63%)
Coverage main.py: 28% → 42% (+14%)
Tests: +15 (all PASSED)
```

❌ **NO continuar** sin validar coverage subió
❌ **NO asumir** coverage sin medir
❌ **NO confundir** coverage archivo vs total

### Tests (REFORZADO)

❌ **NO tests** con @patch innecesarios (bloquean coverage)
❌ **NO mock** app completo (TestClient ejecuta real)
❌ **NO mock** settings sin razón (reduce coverage)
✅ **SÍ usar** TestClient directo
✅ **SÍ mock** SOLO APIs externas, DB

### Código

❌ **NO improvisar** soluciones sin leer código existente  
❌ **NO asumir** métodos implementados sin verificar con grep  
❌ **NO skip** validación con pytest después de cambios  
❌ **NO commits** sin tests passing  
❌ **NO modificar** código sin entender contexto completo

### Git

❌ **NO commits** genéricos ("add tests", "update code")  
❌ **NO commits** sin ejecutar validación primero  
❌ **NO force push** nunca  
❌ **NO modificar** commits pusheados

---

## 📎 REFERENCIAS CRÍTICAS

### Documentos Base

```
PROMPT_CIERRE_BRECHAS_SPRINT2_COVERAGE.md           (metodología original)
ANALISIS_CRITICO_SPRINT2_SESION_40MIN_2025-11-09.md (análisis actual)
ANALISIS_CRITICO_AGENTES_1_Y_2.md                    (hallazgos previos)
```

### Archivos Código

```
AI Service:
  main.py                              (1000+ LOC, 15-41% coverage?)
  chat/engine.py                       (658 LOC, 14% coverage)
  clients/anthropic_client.py          (483 LOC, 14% coverage)
  tests/integration/test_main_endpoints.py (24 tests, efectividad TBD)

Outputs Validación:
  /tmp/sprint2_coverage_validation.txt (validación completa)
  /tmp/sprint2_coverage_total.txt      (coverage total)
  /tmp/sprint2_coverage_main.txt       (coverage main.py)
  /tmp/sprint2_score_final.txt         (score calculado)
```

### Git Tags

```
sprint2_batch2_validation_YYYYMMDD_HHMM  (validación checkpoint)
sprint2_complete_YYYYMMDD_HHMM            (sprint completo)
```

---

## 🚀 COMANDOS INICIO RÁPIDO

### Opción 1: Validación Completa (RECOMENDADO - 22 min)

```bash
# Ejecutar FASE CRÍTICA completa
codex-test-automation "Ejecuta PROMPT_CIERRE_BRECHAS_SPRINT2_V8.md:

FASE CRÍTICA: VALIDACIÓN COVERAGE (22 min - MANDATORY)

Pasos:
1. Medir coverage real (total, main.py, archivos críticos)
2. Validar tests efectividad (PASSED/FAILED/ERROR)
3. Analizar mocks usage (ratio mocks/tests)
4. Identificar scenario (A, B, o C)
5. Commit Batch 2 pendiente
6. Documentar resultados /tmp/sprint2_coverage_validation.txt

Output:
- Scenario identificado
- Coverage real medido
- Estrategia definida
- Trabajo guardado

Target: Decisión informada para continuar
ETA: 22 min
"
```

### Opción 2: Scenario A (Después validación)

```bash
codex-test-automation "Ejecuta PROMPT_CIERRE_BRECHAS_SPRINT2_V8.md:

FASE 2.3 - SCENARIO A: Coverage otros archivos

Pre-requisito: Scenario A validado (main.py >35%)

Alcance:
- Fase 2.3a: chat/engine.py 14% → 85% (~25 tests)
- Fase 2.3b: anthropic_client.py 14% → 85% (~20 tests)
- Fase 2.3c-e: Otros módulos críticos
- Fase 2.4: Validación final ≥80%

Metodología:
- Coverage verification MANDATORY cada batch
- Commits atómicos cada 10-15 tests
- Git tags checkpoints

Target: Coverage ≥80%, Score 103/100
ETA: 5-6h
"
```

### Opción 3: Scenario B (Después validación)

```bash
codex-ai-fastapi-dev "Ejecuta PROMPT_CIERRE_BRECHAS_SPRINT2_V8.md:

FASE 2.2B - SCENARIO B: Refactor tests

Pre-requisito: Scenario B detectado (main.py <20%)

PROBLEMA:
- Tests con mocks excesivos
- NO ejecutan código real
- Coverage stuck

SOLUCIÓN:
1. Analizar patterns problemáticos
2. Refactorizar eliminar @patch innecesarios
3. Usar TestClient directo
4. Validar coverage sube >35%
5. Continuar Scenario A

Target: main.py >35%, luego Fase 2.3
ETA: 1-2h refactor + 5-6h Fase 2.3
"
```

---

## 🎯 OBJETIVO FINAL

**Al completar este PROMPT:**

- ✅ Coverage: 15.82% → ≥80% (target alcanzado)
- ✅ AI Service Score: 87/100 → 103/100 (superado)
- ✅ Tests: 223 → ~300-350 (+100-150 tests efectivos)
- ✅ 0 ERROR tests (mantenido)
- ✅ Commits: Atómicos con coverage validation
- ✅ Git Tags: 2-4 tags checkpoint
- ✅ Production Ready: YES ✅
- ✅ Metodología: Coverage Verification MANDATORY establecida

**Resultado:** Sistema production-ready con cobertura enterprise-grade, calidad profesional, validación rigurosa en cada paso.

---

**Última Actualización:** 2025-11-09  
**Versión:** 8.0 (Post-Análisis Crítico 40min)  
**Metodología:** Evidence-Based, Coverage Verification MANDATORY, Zero Improvisation  
**Base:** Análisis discrepancia coverage -25%, estrategia bifurcada según validación  
**Estado:** ✅ LISTO PARA EJECUCIÓN - VALIDACIÓN CRÍTICA FIRST (22 min)  
**Confianza:** ALTA (basado en análisis exhaustivo discrepancia)

---

## 📋 CHECKLIST PRE-EJECUCIÓN

### Antes de Empezar (5 min)

- [ ] Leer análisis crítico completo (ANALISIS_CRITICO_SPRINT2_SESION_40MIN_2025-11-09.md)
- [ ] Entender discrepancia coverage (-25 a -34%)
- [ ] Confirmar acceso Docker (odoo19_ai_service)
- [ ] Confirmar 24 tests existen (test_main_endpoints.py)
- [ ] Confirmar Batch 2 NO commiteado

### Durante Validación (22 min)

- [ ] **PASO 1:** Medir coverage total (5 min)
- [ ] **PASO 2:** Validar tests efectividad (10 min)
- [ ] **PASO 3:** Identificar scenario A/B/C (5 min)
- [ ] **PASO 4:** Commit Batch 2 pendiente (2 min)
- [ ] **DOCUMENTAR:** `/tmp/sprint2_coverage_validation.txt`

### Post-Validación (Variable)

- [ ] Scenario identificado claramente
- [ ] Estrategia seleccionada (A, B, o C)
- [ ] ETA actualizada según scenario
- [ ] Ejecutar fase correspondiente

**MANDATORY FIRST STEP: VALIDACIÓN 22 MIN ✅**
