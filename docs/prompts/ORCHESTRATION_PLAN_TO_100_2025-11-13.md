# 🎯 Plan de Orquestación: AI Service 79/100 → 100/100
## Ciclo Iterativo Multi-Agente v1.1 LEAN

**Fecha Inicio:** 2025-11-13
**Orchestrator:** Claude Code Sonnet 4.5
**Módulo:** ai-service
**Score Baseline:** 79.0/100 (Backend: 78, Security: 82, Tests: 68, Performance: 88)
**Score Target:** 100/100
**Gap Total:** -21 puntos
**Estrategia:** Fire and Forget + File Polling (v1.1 LEAN)

---

## 📋 Roadmap Completo (7 Fases)

### ✅ Phase 1: Discovery (COMPLETADO)
**Status:** ✅ Completado
**Output:** Estructura ai-service analizada (78 Python files, 20 tests, FastAPI)

---

### ✅ Phase 2: Audit 360° (COMPLETADO)
**Status:** ✅ Completado con v1.1 LEAN
**Scores:**
- Backend: 78/100
- Security: 82/100
- Tests: 68/100
- Performance: 88/100
- **Promedio: 79.0/100**

**Hallazgos:** 10 P1+P2 identificados (ver CONTROL_CYCLE_REPORT_V1_1)

---

### 🔥 Phase 3: Close Gaps P1 (EN EJECUCIÓN)

**Objetivo:** Resolver hallazgos críticos P1 para alcanzar **85-88/100**

**Hallazgos P1 a Cerrar:**

| ID | Dimensión | Hallazgo | Esfuerzo | CLI Agent Asignado |
|----|-----------|----------|----------|-------------------|
| BE-1 | Backend | main.py 2,015 → <1,000 líneas | 8-12h | Copilot (refactoring) |
| T-1 | Tests | Coverage 55-60% → 90% | 15-20h | Copilot (testing specialist) |
| S-1 | Security | Proteger `/metrics` endpoint | 2h | Copilot (security) |
| S-2 | Security | Fix CORS wildcard | 1h | Copilot (security) |

**Sub-fases Phase 3:**

#### 3.1. Refactoring Backend (BE-1)
**Tarea:** Modularizar main.py de 2,015 líneas a <1,000 líneas

**Strategy:**
```bash
# CLI Agent: Copilot
# Task: Refactoring main.py modular
# Autonomía: Full access lectura/escritura ai-service/
# Restricción: NO romper tests existentes, NO cambiar APIs públicas
```

**Acciones:**
1. Crear `models/dte.py`, `models/payroll.py`, `models/chat.py`
2. Crear `routes/dte.py`, `routes/payroll.py`, `routes/chat.py`, `routes/sii.py`
3. Crear `services/cache.py`, `services/singletons.py`
4. Refactorizar main.py → ~200-300 líneas (solo FastAPI app + router imports)
5. Ejecutar tests para validar NO regresiones

**Output:**
- Código refactorizado en ai-service/
- Reporte: `docs/prompts/06_outputs/2025-11/REFACTORING_BACKEND_REPORT_2025-11-13.md`
- Tests passing: 100%

**Esfuerzo:** 8-12 horas
**Score Esperado Post-Task:** Backend 78 → 85 (+7 puntos)

---

#### 3.2. Incrementar Tests Coverage (T-1)
**Tarea:** Coverage 55-60% → 90%

**Strategy:**
```bash
# CLI Agent: Copilot
# Task: Agregar ~75 tests unitarios + integration
# Autonomía: Full access lectura/escritura ai-service/tests/
# Restricción: NO modificar código source (solo tests)
```

**Acciones:**
1. Ejecutar `pytest --cov` para baseline preciso
2. Identificar módulos < 80% coverage
3. Agregar tests para:
   - main.py endpoints sin coverage (8 endpoints)
   - Validators edge cases (RUT frontera, montos límite, unicode)
   - Error paths (try/except blocks)
   - Plugin loading scenarios
4. Re-ejecutar `pytest --cov --cov-min=90`

**Output:**
- ~75 nuevos tests en ai-service/tests/
- Coverage report HTML (90%+)
- Reporte: `docs/prompts/06_outputs/2025-11/TESTS_COVERAGE_REPORT_2025-11-13.md`

**Esfuerzo:** 15-20 horas
**Score Esperado Post-Task:** Tests 68 → 88 (+20 puntos)

---

#### 3.3. Security Hardening (S-1, S-2)
**Tarea:** Proteger `/metrics` + Fix CORS

**Strategy:**
```bash
# CLI Agent: Copilot
# Task: Security fixes P1
# Autonomía: Full access lectura/escritura ai-service/
# Restricción: NO cambiar lógica negocio, solo seguridad
```

**Acciones:**
1. **S-1: Proteger /metrics**
   ```python
   # main.py - Agregar auth a /metrics endpoint
   from fastapi import Depends, HTTPException
   from config import settings

   async def verify_metrics_access(request: Request):
       client_ip = request.client.host
       if client_ip not in settings.METRICS_ALLOWED_IPS:
           raise HTTPException(403, "Access denied")

   @app.get("/metrics", dependencies=[Depends(verify_metrics_access)])
   async def metrics():
       ...
   ```

2. **S-2: Fix CORS wildcard**
   ```python
   # main.py - CORS single origin
   from fastapi.middleware.cors import CORSMiddleware

   app.add_middleware(
       CORSMiddleware,
       allow_origins=[settings.CORS_ORIGIN],  # ← Single origin, no wildcard
       allow_methods=["GET", "POST", "PUT", "DELETE"],  # ← Explicit, no "*"
       allow_headers=["*"],
       allow_credentials=True,
   )
   ```

3. Agregar tests para security fixes
4. Validar con security scan

**Output:**
- Security fixes en ai-service/main.py + config.py
- Tests de security
- Reporte: `docs/prompts/06_outputs/2025-11/SECURITY_HARDENING_REPORT_2025-11-13.md`

**Esfuerzo:** 3 horas
**Score Esperado Post-Task:** Security 82 → 92 (+10 puntos)

---

**Phase 3 Summary:**
- **Esfuerzo Total:** 26-35 horas (~4-5 sprints de 8h)
- **Score Target:** 85-88/100
- **Hallazgos Cerrados:** 4/4 P1
- **Control Point:** Validar scores con re-audit parcial

---

### 🚀 Phase 4: Enhancement P2 (Planificado)

**Objetivo:** Cerrar hallazgos P2 para alcanzar **90-92/100**

**Hallazgos P2 a Cerrar:**

| ID | Dimensión | Hallazgo | Esfuerzo | Prioridad |
|----|-----------|----------|----------|-----------|
| BE-2 | Backend | Version sync README/config | 15min | Quick win |
| T-2 | Tests | 8 endpoints sin tests | 8-10h | Media |
| T-3 | Tests | Validators edge cases | 4-6h | Media |
| P-1 | Performance | Métricas cache hit rate | 2-3h | Media |
| P-2 | Performance | Fix blocking operation | 1h | Media |
| S-3 | Security | CSP + security headers | 2h | Media |

**Sub-tareas:**

#### 4.1. Quick Wins (BE-2)
```bash
# 15 minutos - Yo mismo
# Fix: config.py app_version = "1.2.0"
```

#### 4.2. Tests Endpoints Faltantes (T-2)
```bash
# CLI Agent: Copilot
# Task: Integration tests para 8 endpoints
# Esfuerzo: 8-10h
```

#### 4.3. Validators Edge Cases (T-3)
```bash
# CLI Agent: Copilot
# Task: Unit tests edge cases
# Esfuerzo: 4-6h
```

#### 4.4. Performance Metrics (P-1, P-2)
```bash
# CLI Agent: Copilot
# Task: Prometheus metrics + fix blocking
# Esfuerzo: 3-4h
```

#### 4.5. Security Headers (S-3)
```bash
# CLI Agent: Copilot
# Task: CSP middleware + headers
# Esfuerzo: 2h
```

**Phase 4 Summary:**
- **Esfuerzo Total:** 17-23 horas (~2-3 sprints)
- **Score Target:** 90-92/100
- **Hallazgos Cerrados:** 6/6 P2

---

### 🧪 Phase 5: Testing & Validation (Planificado)

**Objetivo:** Validar que cambios NO introducen regresiones

**Tareas:**

#### 5.1. Suite Completa de Tests
```bash
cd ai-service
pytest tests/ -v --cov=. --cov-report=html --cov-report=term-missing
```

**Criterio Éxito:**
- ✅ Todos los tests pasan (100%)
- ✅ Coverage >= 90%
- ✅ NO regresiones en funcionalidad

#### 5.2. Type Checking
```bash
mypy ai-service/ --strict
```

**Criterio Éxito:** ✅ NO type errors (100% type hints coverage)

#### 5.3. Security Scan
```bash
# Dependency vulnerabilities
pip-audit

# Security headers
curl -I http://localhost:8002 | grep -E "X-Frame|CSP|X-Content"
```

**Criterio Éxito:**
- ✅ NO critical vulnerabilities
- ✅ Security headers presentes

#### 5.4. Load Testing (Opcional)
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8002
```

**Criterio Éxito:** ✅ Response times < targets documentados

**Phase 5 Summary:**
- **Esfuerzo:** 4-6 horas
- **Output:** Validation report con métricas

---

### 🔍 Phase 6: Re-Audit 360° (Planificado)

**Objetivo:** Re-auditar con v1.1 LEAN para validar score >= 90/100

**Strategy:** Fire and Forget + File Polling (mismo flujo Phase 2)

**Tareas:**
1. Lanzar 4 CLI agents (Backend, Security, Tests, Performance) con v1.1
2. File polling para reportes v3
3. Leer summaries (head -50)
4. Comparar scores vs baseline (79/100)

**Output:**
- 4 reportes auditoría v3
- Score validation report
- Gap analysis (Target 90 vs Actual)

**Esfuerzo:** ~1 hora (orquestación) + 80s (CLI agents)

**Criterio Éxito:**
- ✅ Score promedio >= 90/100
- ✅ Todas las dimensiones >= 85/100
- ✅ NO hallazgos P1 nuevos

**Si Score < 90/100:** Iterar Phase 3-6 hasta alcanzar target

---

### 🌟 Phase 7: Final Enhancement (Opcional - Si >= 95/100)

**Objetivo:** Alcanzar excelencia (95-100/100) con nice-to-have features

**Tareas P3 (Opcional):**
1. APM Integration (Datadog/New Relic) - 4h
2. Profiling production (py-spy) - 2h
3. Advanced observability (distributed tracing) - 4h
4. Performance benchmarking exhaustivo - 3h
5. Documentation completa API (OpenAPI full) - 2h

**Esfuerzo:** 10-15 horas
**Score Target:** 95-100/100

---

## 🎮 Estrategia de Orquestación v1.1 LEAN

### Principios Aplicados

**1. Fire and Forget + File Polling**
- CLI agents ejecutan autónomos
- NO leer logs (file polling)
- Leer SOLO summaries (head -50)

**2. Autonomía Total**
- Prompts con permisos explícitos
- `--allow-all-tools --allow-all-paths`
- Referencia a CLI_AGENTS_SYSTEM_CONTEXT.md

**3. Delegation over DIY**
- CLI agents hacen el trabajo
- Orchestrator coordina, NO ejecuta
- Task tool para sub-tareas complejas

**4. Token Efficiency**
- Prompts autónomos detallados (~2K tokens)
- File polling (~0.5K tokens)
- Summaries (~4K tokens total)
- **Phase 3 Target: <15K tokens** (vs 112K en v1.0)

### Control Points

**CP1: Inicio Phase 3**
- Timestamp
- Hallazgos P1 seleccionados
- CLI agents assignments
- Token budget inicial

**CP2: Post-Refactoring**
- Backend score validado
- Tests passing confirmado
- Regression check

**CP3: Post-Tests Coverage**
- Coverage report (target: 90%+)
- Tests score validado
- Edge cases cubiertos

**CP4: Post-Security Hardening**
- Security score validado
- Vulnerabilities cerradas
- Headers verificados

**CP5: Post-Testing**
- Suite completa pasando
- Type checking OK
- Security scan OK

**CP6: Post-Re-Audit**
- Scores finales vs baseline
- Gap to 100/100
- Decisión: Continuar Phase 7 o finalizar

---

## 📊 Matriz de Éxito

| Phase | Esfuerzo | Score Target | Criterio Éxito | Status |
|-------|----------|--------------|----------------|--------|
| Phase 1 | - | - | Discovery completado | ✅ |
| Phase 2 | 80s | 79/100 | 4 audits v1.1 | ✅ |
| **Phase 3** | **26-35h** | **85-88/100** | **4/4 P1 cerrados** | 🔥 **INICIANDO** |
| Phase 4 | 17-23h | 90-92/100 | 6/6 P2 cerrados | ⏸️ Pendiente |
| Phase 5 | 4-6h | - | Tests + validation OK | ⏸️ Pendiente |
| Phase 6 | 1h | >= 90/100 | Re-audit confirmado | ⏸️ Pendiente |
| Phase 7 | 10-15h | 95-100/100 | Excelencia alcanzada | ⏸️ Opcional |

**Esfuerzo Total Estimado:** 48-80 horas (~6-10 sprints de 8h)

---

## 🚀 Ejecución Inmediata

### Phase 3.1: Refactoring Backend (INICIANDO)

**CLI Agent:** Copilot (GPT-4o)
**Task:** Modularizar main.py de 2,015 → <1,000 líneas
**Autonomía:** Full access ai-service/
**Output:** docs/prompts/06_outputs/2025-11/REFACTORING_BACKEND_REPORT_2025-11-13.md

**Prompt Autónomo:** `.tmp_prompt_refactoring_backend.md`

**Launch Command:**
```bash
copilot --allow-all-tools --allow-all-paths \
    -p "$(cat .tmp_prompt_refactoring_backend.md)" \
    2>&1 | tee /tmp/refactoring_backend.log &
```

**File Polling:**
```bash
./docs/prompts/08_scripts/wait_for_audit_reports.sh \
    docs/prompts/06_outputs/2025-11 \
    7200 \
    30 \
    REFACTORING_BACKEND_REPORT_2025-11-13.md
```

**Validation:**
```bash
# Post-refactoring
cd ai-service
pytest tests/ -v  # Todos deben pasar
wc -l main.py     # Debe ser < 1,000 líneas
```

---

## 📝 Restricciones del Ciclo

**Automáticas (Ya Aplicadas):**
- ❌ NO destruir código masivo sin justificación
- ❌ NO crear nuevos módulos/microservicios sin instrucción explícita
- ⏱️ Máximo 3 iteraciones Phase 3-6 (si no alcanza 90/100 en 3 intentos, pausar y revisar)

**Manuales (Confirmación Requerida):**
- 🔒 Cambios a APIs públicas (endpoints, schemas)
- 🔒 Migraciones de DB (N/A - no usa DB relacional)
- 🔒 Cambios a configuración producción

---

## 🎯 Meta Final

**Score Target:** 100/100
- Backend: 95/100
- Security: 98/100
- Tests: 100/100
- Performance: 95/100

**Timeline Estimado:** 6-10 sprints de 8h (~2-3 semanas)

**Success Criteria:**
- ✅ Score promedio >= 100/100
- ✅ Todas las dimensiones >= 95/100
- ✅ NO hallazgos P1 o P2 pendientes
- ✅ Coverage >= 90%
- ✅ Security headers A+ (securityheaders.com)
- ✅ Load testing < targets documentados

---

**Orquestador:** Claude Code Sonnet 4.5
**Framework:** Multi-Agent Orchestration System v1.1 LEAN
**Status:** 🔥 **PLAN COMPLETO - INICIANDO PHASE 3.1**
