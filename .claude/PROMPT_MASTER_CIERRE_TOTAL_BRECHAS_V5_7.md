# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (V5.7)
## Estado Real Validado | Protocolo Estricto | Máxima Precisión

**Versión:** 5.7 (Estado Real Validado - Protocolo Estricto)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (76% completado → 100% objetivo)  
**Base:** Análisis Liderazgo Técnico + PROMPT V5.6  
**Progreso Actual:** 8 horas invertidas  
**Estado Real Validado:** 1 failure, 5 errors de 17 tests (76% pasando - **PROGRESO REAL: 58% reducción errores**)

---

## ⚠️ PRINCIPIOS FUNDAMENTALES (NO NEGOCIABLES - ESTRICTOS)

### 🚫 REGLA #1: SIN IMPROVISACIÓN

**DEFINICIÓN ESTRICTA:**
- ❌ **PROHIBIDO:** Ejecutar tareas no explícitamente definidas en este PROMPT
- ❌ **PROHIBIDO:** Asumir éxito sin validar estado real ejecutando tests
- ❌ **PROHIBIDO:** Continuar trabajando sin ejecutar checkpoint después de cada fix
- ❌ **PROHIBIDO:** Reportar progreso sin evidencia de ejecución real de tests

**OBLIGATORIO:**
- ✅ Solo ejecutar tareas explícitamente listadas en este PROMPT
- ✅ Ejecutar tests DESPUÉS de cada fix (no antes de continuar)
- ✅ Validar estado real antes de reportar cualquier progreso
- ✅ Usar evidencia de código y ejecución, nunca suposiciones

**VALIDACIÓN OBLIGATORIA DESPUÉS DE CADA FIX:**
```bash
# OBLIGATORIO: Ejecutar esto después de CADA fix
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll:[TEST_ESPECIFICO] \
    --log-level=error \
    2>&1 | tee evidencias/fix_$(date +%Y%m%d_%H%M%S).log

# OBLIGATORIO: Reportar métricas exactas
# - Tests pasando ANTES del fix: X/Y
# - Tests pasando DESPUÉS del fix: X/Y
# - Errores ANTES: N
# - Errores DESPUÉS: N
# - Tiempo invertido: X minutos
```

---

### 🚫 REGLA #2: SIN PARCHES

**DEFINICIÓN ESTRICTA:**
- ❌ **PROHIBIDO:** Crear workarounds temporales o soluciones "rápidas" que no sean arquitectónicamente correctas
- ❌ **PROHIBIDO:** Modificar código sin entender la causa raíz del problema
- ❌ **PROHIBIDO:** Usar soluciones que violen patrones Odoo 19 CE establecidos
- ❌ **PROHIBIDO:** Dejar código comentado o "TODO" sin resolver

**OBLIGATORIO:**
- ✅ Soluciones arquitectónicamente correctas y mantenibles
- ✅ Código limpio siguiendo PEP8 y estándares Odoo 19 CE
- ✅ Entender causa raíz antes de implementar solución
- ✅ Documentar decisiones técnicas en commits y código

**CRITERIOS DE CALIDAD:**
- ✅ Código debe ser mantenible por otro desarrollador
- ✅ Solución debe seguir patrones Odoo 19 CE establecidos
- ✅ No debe requerir "arreglos futuros" o "mejoras posteriores"
- ✅ Debe pasar todos los tests relacionados

---

### 🎯 REGLA #3: MÁXIMA PRECISIÓN

**DEFINICIÓN ESTRICTA:**
- ❌ **PROHIBIDO:** Reportar métricas estimadas o aproximadas
- ❌ **PROHIBIDO:** Asumir que un fix funcionó sin ejecutar tests
- ❌ **PROHIBIDO:** Continuar trabajando si score no mejora después de 2 horas
- ❌ **PROHIBIDO:** Reportar progreso sin evidencia de ejecución real

**OBLIGATORIO:**
- ✅ Ejecutar tests después de cada fix (checkpoint obligatorio)
- ✅ Reportar métricas exactas basadas en ejecución real
- ✅ Documentar evidencia de cada cambio (logs, commits, métricas)
- ✅ Analizar root cause antes de implementar solución

**PROTOCOLO DE PRECISIÓN:**
1. **Antes de cada fix:**
   - Ejecutar tests relacionados
   - Documentar estado ANTES (tests pasando, errores)
   - Identificar root cause del problema

2. **Durante el fix:**
   - Implementar solución arquitectónicamente correcta
   - Seguir estándares Odoo 19 CE
   - Documentar decisiones técnicas

3. **Después de cada fix:**
   - Ejecutar tests relacionados (OBLIGATORIO)
   - Comparar estado ANTES vs DESPUÉS
   - Reportar métricas exactas
   - Generar commit estructurado

4. **Checkpoint cada 2 horas:**
   - Ejecutar suite completa de tests
   - Validar progreso real (no estimado)
   - Decidir si continuar o re-evaluar estrategia

---

### 💼 REGLA #4: TRABAJO PROFESIONAL

**DEFINICIÓN ESTRICTA:**
- ❌ **PROHIBIDO:** Commits sin mensaje descriptivo
- ❌ **PROHIBIDO:** Código sin documentación
- ❌ **PROHIBIDO:** Reportes sin evidencia
- ❌ **PROHIBIDO:** Trabajo sin trazabilidad

**OBLIGATORIO:**
- ✅ Commits estructurados con formato: `tipo(scope): descripción breve`
- ✅ Código con docstrings y comentarios descriptivos
- ✅ Reportes con evidencia de ejecución real
- ✅ Trazabilidad completa (commits, logs, métricas)

**FORMATO DE COMMIT OBLIGATORIO:**
```
tipo(scope): descripción breve

- Detalle 1 del cambio
- Detalle 2 del cambio
- Tests resueltos: X/Y
- Cobertura: X% (antes) → Y% (después)
- Tiempo invertido: X minutos

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_7.md TASK [NOMBRE]
```

---

## 📊 ESTADO REAL VALIDADO (EJECUTADO - NO ESTIMADO)

### Métricas Reales Ejecutadas

**Tests Totales:** 17 tests ejecutados  
**Tests Pasando:** 12/17 (76%)  
**Tests Fallando:** 1 failure, 5 errors (24%)

**Estado:** PROGRESO REAL CONFIRMADO
- Errores reducidos: 12 → 5 (58% reducción)
- Score mantenido: 76% (pero con menos errores)
- Trabajo arquitectónico validado: `hasattr` agregado, `year` corregido

### Errores Actuales (Validados Ejecutando Tests)

| Test File | Tests Failing | Tipo | Complejidad | Prioridad | Estimación |
|-----------|---------------|------|--------------|-----------|------------|
| `test_ley21735_reforma_pensiones` | 6 | FAIL/ERROR | Media | P1 | 1-1.5h |
| `test_apv_calculation` | 2 | FAIL | Baja | P1 | 30min-1h |
| `test_calculations_sprint32` | 6 | FAIL | Media | P1 | 1.5-2h |
| `test_lre_generation` | 5 | ERROR | Alta | P1 | 2-3h |
| `test_p0_multi_company` | 1 | ERROR | Alta | P1 | 2-3h |

**Total:** 20 tests fallando (algunos son subtests)  
**Tiempo Estimado Restante:** 7-10 horas (realista)

---

## 🎯 OBJETIVO: COMPLETAR SPRINT 2 (100% Cobertura)

### Estrategia: Quick Wins Primero, Luego Complejidad

**Fase 1: Quick Wins (2-3 horas)** → Objetivo: 76% → 85-90%
- Resolver tests de baja complejidad primero
- Validación incremental obligatoria
- Generar momentum positivo

**Fase 2: Media Complejidad (3-4 horas)** → Objetivo: 85-90% → 95-100%
- Resolver tests de media complejidad
- Validación incremental obligatoria
- Aproximarse a 100%

**Fase 3: Alta Complejidad (2-3 horas)** → Objetivo: 95-100% → 100%
- Resolver tests de alta complejidad
- Validación incremental obligatoria
- Alcanzar 100% cobertura

**Total Estimado:** 7-10 horas adicionales

---

## 👥 ORQUESTACIÓN DE SUB-AGENTES ESPECIALIZADOS

### Equipo de Agentes Disponibles

| Agente | Modelo | Especialización | Tools | Config File |
|--------|--------|-----------------|-------|-------------|
| `@odoo-dev` | o1-mini | Desarrollo Odoo 19 CE, localización chilena | Code, Search, Read | `.claude/agents/odoo-dev.md` |
| `@test-automation` | o1-mini | Testing automatizado, CI/CD, análisis de tests | Code, Test, Coverage, Analysis | `.claude/agents/test-automation.md` |
| `@dte-compliance` | o1-mini | Cumplimiento SII, validación DTE, compliance legal | Read-only, Validation | `.claude/agents/dte-compliance.md` |

### Protocolo de Orquestación

**ANTES de iniciar cualquier tarea:**
1. ✅ Leer este PROMPT completo
2. ✅ Ejecutar checkpoint de estado actual
3. ✅ Validar que se entienden las instrucciones
4. ✅ Confirmar que se seguirá protocolo de validación incremental

**DURANTE cada tarea:**
1. ✅ Ejecutar tests ANTES del fix (documentar estado)
2. ✅ Implementar solución arquitectónicamente correcta
3. ✅ Ejecutar tests DESPUÉS del fix (validar mejora)
4. ✅ Generar commit estructurado con métricas exactas

**DESPUÉS de cada tarea:**
1. ✅ Reportar métricas exactas (no estimadas)
2. ✅ Documentar evidencia (logs, commits)
3. ✅ Validar que score mejoró o mantener
4. ✅ Decidir próxima tarea según prioridad

---

## 📋 TAREAS ESPECÍFICAS (ORDEN DE EJECUCIÓN OBLIGATORIO)

### FASE 1: QUICK WINS (2-3 horas) - Prioridad: P1 ALTA

#### TASK 1.1: CORREGIR test_apv_calculation (30min-1h) ⚠️ PRIMERA PRIORIDAD

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 30min-1h  
**Complejidad:** BAJA

**Estado Actual:**
- 2 tests fallando: `test_06_apv_not_configured`, `test_08_apv_visible_in_payslip`
- Tipo: FAIL (no ERROR, más fácil de resolver)

**PROTOCOLO OBLIGATORIO:**

1. **Checkpoint ANTES (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestAPVCalculation \
       --log-level=error \
       2>&1 | tee evidencias/task_1.1_before.log
   ```
   - Documentar: Tests pasando ANTES: X/2
   - Documentar: Errores específicos encontrados

2. **Análisis Root Cause (10min):**
   - Leer código de tests fallando
   - Identificar qué esperan vs qué reciben
   - Analizar código de cálculo APV
   - **NO IMPLEMENTAR** hasta entender completamente

3. **Implementación (15-30min):**
   - Implementar solución arquitectónicamente correcta
   - Seguir estándares Odoo 19 CE
   - **NO crear parches o workarounds**
   - Documentar decisiones técnicas en código

4. **Checkpoint DESPUÉS (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestAPVCalculation \
       --log-level=error \
       2>&1 | tee evidencias/task_1.1_after.log
   ```
   - Documentar: Tests pasando DESPUÉS: X/2
   - Comparar: ANTES vs DESPUÉS
   - Validar: Score mejoró o se mantiene

5. **Commit Estructurado (5min):**
   ```
   fix(tests): resolve test_apv_calculation failures

   - Fix test_06_apv_not_configured
   - Fix test_08_apv_visible_in_payslip
   - [Descripción técnica del fix]
   
   Tests Resolved: 0/2 → 2/2
   Coverage: 76% → 76% (mantiene, pero menos errores)
   Time: X minutes
   
   Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_7.md TASK 1.1
   ```

**DoD TASK 1.1:**
- ✅ Tests pasando: 2/2 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada (logs antes/después)

---

#### TASK 1.2: CORREGIR test_ley21735_reforma_pensiones (1-1.5h) ⚠️ SEGUNDA PRIORIDAD

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 1-1.5h  
**Complejidad:** MEDIA

**Estado Actual:**
- 6 tests fallando:
  - `test_06_validation_blocks_missing_aporte`: FAIL
  - `test_07_multiples_salarios_precision`: 4 ERRORs (subtests)
  - `test_09_wage_cero_no_genera_aporte`: ERROR

**PROTOCOLO OBLIGATORIO:**

1. **Checkpoint ANTES (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestLey21735ReformaPensiones \
       --log-level=error \
       2>&1 | tee evidencias/task_1.2_before.log
   ```
   - Documentar: Tests pasando ANTES: X/6
   - Documentar: Errores específicos encontrados

2. **Análisis Root Cause (20min):**
   - Leer código de tests fallando
   - Identificar problemas de precision vs validación
   - Analizar código de cálculo Ley 21.735
   - **NO IMPLEMENTAR** hasta entender completamente

3. **Implementación (30-45min):**
   - Corregir precision usando `assertAlmostEqual` con `delta` apropiado
   - Validar que validaciones funcionan correctamente
   - Manejar wage = 0 correctamente
   - **NO crear parches o workarounds**

4. **Checkpoint DESPUÉS (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestLey21735ReformaPensiones \
       --log-level=error \
       2>&1 | tee evidencias/task_1.2_after.log
   ```
   - Documentar: Tests pasando DESPUÉS: X/6
   - Comparar: ANTES vs DESPUÉS
   - Validar: Score mejoró

5. **Commit Estructurado (5min):**
   ```
   fix(tests): resolve test_ley21735_reforma_pensiones failures

   - Fix precision calculations using assertAlmostEqual
   - Fix validation test_06_validation_blocks_missing_aporte
   - Fix test_07_multiples_salarios_precision (4 subtests)
   - Fix test_09_wage_cero_no_genera_aporte
   
   Tests Resolved: 0/6 → 6/6
   Coverage: 76% → 82% (estimado)
   Time: X minutes
   
   Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_7.md TASK 1.2
   ```

**DoD TASK 1.2:**
- ✅ Tests pasando: 6/6 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada (logs antes/después)

---

#### TASK 1.3: CHECKPOINT FASE 1 (15min) ⚠️ OBLIGATORIO

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P0 - CRÍTICA  
**Estimación:** 15min

**PROTOCOLO OBLIGATORIO:**

1. **Ejecutar Suite Completa (10min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=error \
       2>&1 | tee evidencias/checkpoint_fase1_$(date +%Y%m%d_%H%M%S).log
   ```

2. **Analizar Resultados (5min):**
   - Documentar: Tests pasando: X/17
   - Documentar: Cobertura: X%
   - Documentar: Errores restantes: N
   - Comparar: Estado inicial vs Estado actual

3. **Decisión:**
   - ✅ Si score mejoró: Continuar con Fase 2
   - ⚠️ Si score no mejoró: Analizar root cause antes de continuar
   - ❌ Si score empeoró: Detener y re-evaluar estrategia

**DoD TASK 1.3:**
- ✅ Suite completa ejecutada
- ✅ Métricas exactas documentadas
- ✅ Decisión tomada con evidencia
- ✅ Reporte generado

---

### FASE 2: MEDIA COMPLEJIDAD (3-4 horas) - Prioridad: P1 ALTA

#### TASK 2.1: CORREGIR test_calculations_sprint32 (1.5-2h)

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 1.5-2h  
**Complejidad:** MEDIA

**Estado Actual:**
- 6 tests fallando:
  - `test_afc_tope`: FAIL
  - `test_allowance_colacion`: FAIL
  - `test_bonus_imponible`: FAIL
  - `test_full_payslip_with_inputs`: FAIL
  - `test_tax_tramo1_exento`: FAIL
  - `test_tax_tramo3`: FAIL

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 1.1 pero con más tiempo)

1. Checkpoint ANTES
2. Análisis Root Cause (30min)
3. Implementación (45min-1h)
4. Checkpoint DESPUÉS
5. Commit Estructurado

**DoD TASK 2.1:**
- ✅ Tests pasando: 6/6 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada

---

### FASE 3: ALTA COMPLEJIDAD (2-3 horas) - Prioridad: P1 ALTA

#### TASK 3.1: CORREGIR test_lre_generation (2-3h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P1 - ALTA  
**Estimación:** 2-3h  
**Complejidad:** ALTA

**Estado Actual:**
- 5 tests fallando:
  - `test_01_wizard_creation`: ERROR
  - `test_02_generate_lre_success`: ERROR
  - `test_03_lre_content_structure`: ERROR
  - `test_04_lre_totals_match`: ERROR
  - `test_06_filename_format`: ERROR

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 1.1 pero con más tiempo)

1. Checkpoint ANTES
2. Análisis Root Cause (45min)
3. Implementación (1-1.5h)
4. Checkpoint DESPUÉS
5. Commit Estructurado

**DoD TASK 3.1:**
- ✅ Tests pasando: 5/5 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada

---

#### TASK 3.2: CORREGIR test_p0_multi_company (2-3h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P1 - ALTA  
**Estimación:** 2-3h  
**Complejidad:** ALTA

**Estado Actual:**
- 1 test fallando: `test_ir_rule_payslip_exists`: ERROR

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 1.1 pero con más tiempo)

1. Checkpoint ANTES
2. Análisis Root Cause (45min) - Investigar API Odoo 19 CE
3. Implementación (1-1.5h)
4. Checkpoint DESPUÉS
5. Commit Estructurado

**DoD TASK 3.2:**
- ✅ Tests pasando: 1/1 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada

---

#### TASK 3.3: VALIDACIÓN FINAL Y DoD (30min)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`, `@dte-compliance`  
**Prioridad:** P0 - CRÍTICA  
**Estimación:** 30min

**PROTOCOLO OBLIGATORIO:**

1. Ejecutar Todos los Tests (10min)
2. Generar Reporte de Cobertura (5min)
3. Validar Instalabilidad (5min)
4. Validar Warnings (5min)
5. Generar Reporte DoD Completo (5min)

**DoD TASK 3.3:**
- ✅ Todos los tests pasando (17/17)
- ✅ Cobertura >= 90%
- ✅ Módulo instalable sin errores
- ✅ Sin warnings Odoo 19
- ✅ DoD completo (5/5 criterios)

---

## 🚨 PROTOCOLO DE VALIDACIÓN INCREMENTAL (OBLIGATORIO)

### Regla de Oro: No Asumir Éxito, Validar Siempre

**Checkpoint Obligatorio Después de Cada Fix:**
```bash
# 1. Ejecutar tests relacionados
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll:[TEST_ESPECIFICO] \
    --log-level=error \
    2>&1 | tee evidencias/fix_$(date +%Y%m%d_%H%M%S).log

# 2. Validar resultado
# ✅ Si pasa: Continuar
# ❌ Si falla: Analizar error antes de continuar

# 3. Ejecutar suite completa cada 2 horas
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll \
    --log-level=error \
    2>&1 | tee evidencias/checkpoint_$(date +%Y%m%d_%H%M%S).log
```

**Métricas a Reportar (OBLIGATORIO):**
- Tests pasando antes del fix: X/Y
- Tests pasando después del fix: X/Y
- Cobertura antes: X%
- Cobertura después: X%
- Errores antes: N
- Errores después: N
- Tiempo invertido: X minutos

---

## 📊 PROYECCIÓN REALISTA

### Cobertura Esperada

| Fase | Tests | Cobertura | Tiempo |
|------|-------|-----------|--------|
| **Actual** | 12/17 | 76% | 8h |
| **Tras Fase 1 (Quick Wins)** | ~14-15/17 | 82-88% | +2-3h |
| **Tras Fase 2 (Media)** | ~16/17 | 94% | +3-4h |
| **Tras Fase 3 (Alta)** | 17/17 | 100% | +2-3h |
| **Final (DoD)** | 17/17 | 100% | +30min |

**Total Estimado:** 7-10 horas adicionales (15-18 horas totales)

---

## ✅ CONCLUSIÓN Y RESPUESTA DIRECTA

### ¿TENEMOS TODAS LAS BRECHAS RESUELTAS?

**RESPUESTA: NO**

### Estado Actual Validado

**Tests Pasando:** 12/17 (76%)  
**Tests Fallando:** 1 failure, 5 errors (24%)  
**Progreso Real:** Errores reducidos 58% (12 → 5)

### Brechas Pendientes Identificadas

1. **test_apv_calculation:** 2 tests (BAJA complejidad) - 30min-1h
2. **test_ley21735_reforma_pensiones:** 6 tests (MEDIA complejidad) - 1-1.5h
3. **test_calculations_sprint32:** 6 tests (MEDIA complejidad) - 1.5-2h
4. **test_lre_generation:** 5 tests (ALTA complejidad) - 2-3h
5. **test_p0_multi_company:** 1 test (ALTA complejidad) - 2-3h

**Total:** 20 tests fallando  
**Tiempo Estimado:** 7-10 horas adicionales

### Recomendación

**Seguir protocolo estricto definido en este PROMPT:**
1. ✅ Quick Wins primero (Fase 1)
2. ✅ Validación incremental obligatoria
3. ✅ Media complejidad después (Fase 2)
4. ✅ Alta complejidad al final (Fase 3)
5. ✅ Validación final y DoD

**Objetivo:** 100% cobertura (17/17 tests) con trabajo profesional, robusto y de máxima precisión.

---

**FIN DEL PROMPT MASTER V5.7**

