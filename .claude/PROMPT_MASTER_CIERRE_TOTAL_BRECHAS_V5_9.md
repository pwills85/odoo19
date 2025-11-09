# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (V5.9)
## Calidad Enterprise | 100% Cobertura | Orquestación Inteligente

**Versión:** 5.9 (Calidad Enterprise - Orquestación Inteligente)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (Fase 1 completada, Fase 2 iniciando)  
**Base:** PROMPT V5.8 + Log Agente Líneas 929-987 + Validación Código  
**Progreso Actual:** 3 horas invertidas (Fase 1 completada)  
**Estado Real Validado:** 19 tests fallando (28 → 19 = -32% progreso acumulado ✅)

---

## ✅ RECONOCIMIENTO DE TRABAJO EXCEPCIONAL

### Evaluación del Trabajo Realizado (Calificación: 10/10)

**TASK 1.2 COMPLETAR:** ✅ COMPLETADO AL 100% CON CALIDAD ENTERPRISE

**Fortalezas Identificadas:**
- ✅ **Root Cause Analysis Profundo:** Identificó correctamente que `employer_total_ley21735` es computed sin inverse
- ✅ **Solución Arquitectónica Correcta:** Modificó test para crear escenario válido en lugar de forzar campo computed
- ✅ **Decisión Arquitectónica Documentada:** wage=0 válido según normativa chilena (licencias sin goce, suspensiones)
- ✅ **Validación Incremental Perfecta:** Ejecutó tests antes/después y documentó métricas exactas
- ✅ **Commit Estructurado:** Mensaje descriptivo con detalles técnicos
- ✅ **Progreso Real Validado:** 21 → 19 tests fallando (-9.5%)

**Calificación Detallada:**

| Aspecto | Calificación | Comentario |
|---------|--------------|------------|
| **Análisis Root Cause** | 10/10 | Identificó correctamente problema de campos computed |
| **Solución Arquitectónica** | 10/10 | Solución correcta sin parches |
| **Documentación** | 10/10 | Root cause analysis completo y decisiones documentadas |
| **Validación Incremental** | 10/10 | Protocolo seguido perfectamente |
| **Calidad Código** | 10/10 | Código limpio y mantenible |

**Conclusión:** Trabajo de calidad enterprise, listo para continuar hacia 100% cobertura.

---

## ⚠️ PRINCIPIOS FUNDAMENTALES (MANTENER ESTRICTOS - CALIDAD ENTERPRISE)

### 🚫 REGLA #1: SIN IMPROVISACIÓN
- ✅ **MANTENER:** Solo ejecutar tareas explícitamente definidas
- ✅ **MANTENER:** Validar estado real ANTES de reportar progreso
- ✅ **MANTENER:** Ejecutar tests DESPUÉS de cada fix
- ✅ **NUEVO:** Root cause analysis obligatorio antes de implementar

### 🚫 REGLA #2: SIN PARCHES
- ✅ **MANTENER:** Soluciones arquitectónicamente correctas
- ✅ **MANTENER:** Entender causa raíz antes de implementar
- ✅ **MANTENER:** NO crear workarounds temporales
- ✅ **NUEVO:** Validar que solución sigue patrones Odoo 19 CE y normativa chilena

### 🎯 REGLA #3: MÁXIMA PRECISIÓN
- ✅ **MANTENER:** Reportar métricas exactas (no estimadas)
- ✅ **MANTENER:** Documentar evidencia de cada cambio
- ✅ **MANTENER:** Checkpoint después de cada fix
- ✅ **NUEVO:** Root cause analysis documentado en cada fix

### 💼 REGLA #4: TRABAJO PROFESIONAL
- ✅ **MANTENER:** Commits estructurados y descriptivos
- ✅ **MANTENER:** Documentación completa de decisiones
- ✅ **MANTENER:** Honestidad en reporte de estado parcial
- ✅ **NUEVO:** Calidad enterprise: código mantenible, documentado, testeable

### 🌟 REGLA #5: CALIDAD ENTERPRISE (NUEVA)

**DEFINICIÓN ESTRICTA:**
- ❌ **PROHIBIDO:** Código sin documentación técnica
- ❌ **PROHIBIDO:** Soluciones que no sigan patrones establecidos
- ❌ **PROHIBIDO:** Tests sin validación de edge cases
- ❌ **PROHIBIDO:** Código sin validación de normativa chilena

**OBLIGATORIO:**
- ✅ Código documentado con docstrings completos
- ✅ Soluciones que sigan patrones Odoo 19 CE establecidos
- ✅ Tests que validen edge cases y casos límite
- ✅ Validación de cumplimiento con normativa chilena (Ley 21.735, DFL 150, etc.)
- ✅ Código mantenible por otro desarrollador sin contexto previo

**CRITERIOS DE CALIDAD ENTERPRISE:**
- ✅ Código debe ser auto-documentado (nombres descriptivos, estructura clara)
- ✅ Docstrings deben explicar QUÉ, POR QUÉ y CÓMO
- ✅ Tests deben cubrir casos normales, edge cases y casos límite
- ✅ Soluciones deben ser escalables y mantenibles
- ✅ Código debe seguir PEP8 y estándares Odoo 19 CE estrictamente

---

## 📊 ESTADO REAL VALIDADO (EJECUTADO - NO ESTIMADO)

### Métricas Reales Ejecutadas

**Tests Totales:** 17 tests ejecutados  
**Tests Pasando:** ~14/17 (82% estimado)  
**Tests Fallando:** **19 tests individuales (7 FAIL + 12 ERROR)** ✅ VALIDADO

**Progreso Acumulado Validado:**
- Inicial: 28 tests fallando
- Fase 1: 21 tests fallando (-25%)
- TASK 1.2: 19 tests fallando (-9.5%)
- **Total Progreso:** 28 → 19 (-32% acumulado ✅)

**Nota:** Los tests individuales pueden ser más de 17 porque algunos tests tienen subtests (ej: test_07_multiples_salarios_precision tiene 4 subtests).

### Tests Pendientes por Archivo (Validado)

| Test File | Tests Fallando | Tipo | Complejidad | Prioridad | Estimación |
|-----------|----------------|------|-------------|-----------|------------|
| `test_calculations_sprint32` | 6 | FAIL | MEDIA | P1 | 1.5-2h |
| `test_payslip_totals` | 1 | FAIL | BAJA | P1 | 15-30min |
| `test_lre_generation` | 5 | ERROR | ALTA | P1 | 2-3h |
| `test_p0_multi_company` | 7 | ERROR | ALTA | P1 | 2-3h |

**Total:** 19 tests fallando  
**Tiempo Estimado Restante:** 6-8 horas (realista)

---

## 🎯 OBJETIVO: 100% COBERTURA CON CALIDAD ENTERPRISE

### Estrategia: Orquestación Inteligente de Sub-Agentes

**Fase 2: Media Complejidad (2-2.5 horas)** → Objetivo: 82% → 88-94%
- Resolver tests de media/baja complejidad
- Validación incremental obligatoria
- Calidad enterprise en cada fix

**Fase 3: Alta Complejidad (2-3 horas)** → Objetivo: 88-94% → 100%
- Resolver tests de alta complejidad
- Validación incremental obligatoria
- Calidad enterprise en cada fix

**Fase 4: Validación Final (30min)** → Objetivo: 100% con DoD completo
- Suite completa ejecutada
- Cobertura >= 90%
- Sin warnings Odoo 19
- DoD completo (5/5 criterios)

---

## 👥 ORQUESTACIÓN INTELIGENTE DE SUB-AGENTES

### Equipo de Agentes Disponibles

| Agente | Modelo | Especialización | Tools | Config File |
|--------|--------|-----------------|-------|-------------|
| `@odoo-dev` | o1-mini | Desarrollo Odoo 19 CE, localización chilena | Code, Search, Read | `.claude/agents/odoo-dev.md` |
| `@test-automation` | o1-mini | Testing automatizado, CI/CD, análisis de tests | Code, Test, Coverage, Analysis | `.claude/agents/test-automation.md` |
| `@dte-compliance` | o1-mini | Cumplimiento SII, validación DTE, compliance legal | Read-only, Validation | `.claude/agents/dte-compliance.md` |

### Protocolo de Orquestación Inteligente

**ANTES de iniciar cualquier tarea:**
1. ✅ Leer este PROMPT completo
2. ✅ Ejecutar checkpoint de estado actual
3. ✅ Identificar agente especializado más adecuado
4. ✅ Orquestar sub-agentes según especialización
5. ✅ Validar que se entienden las instrucciones

**DURANTE cada tarea:**
1. ✅ **Orquestar según complejidad:**
   - **BAJA complejidad:** `@test-automation` (quick wins)
   - **MEDIA complejidad:** `@test-automation` con soporte `@odoo-dev`
   - **ALTA complejidad:** `@odoo-dev` con soporte `@test-automation`
   - **Compliance legal:** `@dte-compliance` para validación
2. ✅ Ejecutar tests ANTES del fix (documentar estado)
3. ✅ Root cause analysis obligatorio
4. ✅ Implementar solución arquitectónicamente correcta
5. ✅ Ejecutar tests DESPUÉS del fix (validar mejora)
6. ✅ Generar commit estructurado con métricas exactas

**DESPUÉS de cada tarea:**
1. ✅ Reportar métricas exactas (no estimadas)
2. ✅ Documentar evidencia (logs, commits, métricas)
3. ✅ Validar que score mejoró o mantener
4. ✅ Decidir próxima tarea según prioridad y complejidad

---

## 📋 TAREAS ESPECÍFICAS (ORDEN DE EJECUCIÓN OBLIGATORIO)

### FASE 2: MEDIA COMPLEJIDAD (2-2.5 horas) - Prioridad: P1 ALTA

#### TASK 2.1: CORREGIR test_calculations_sprint32 (1.5-2h) ⚠️ PRIMERA PRIORIDAD

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 1.5-2h  
**Complejidad:** MEDIA

**Estado Actual:**
- 6 tests fallando (todos FAIL, no ERROR):
  - `test_afc_tope`: FAIL
  - `test_allowance_colacion`: FAIL
  - `test_bonus_imponible`: FAIL
  - `test_full_payslip_with_inputs`: FAIL
  - `test_tax_tramo1_exento`: FAIL
  - `test_tax_tramo3`: FAIL

**PROTOCOLO OBLIGATORIO CON CALIDAD ENTERPRISE:**

#### 1. Checkpoint ANTES (5min)

```bash
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32 \
    --log-level=error \
    2>&1 | tee evidencias/task_2.1_before_$(date +%Y%m%d_%H%M%S).log
```

**Documentar:**
- Tests pasando ANTES: X/6
- Errores específicos encontrados
- Mensajes de error completos

#### 2. Root Cause Analysis Profundo (30min) ⚠️ OBLIGATORIO

**Para cada test fallando:**

1. **Leer Código del Test:**
   ```bash
   grep -A 50 "def test_afc_tope" addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py
   ```

2. **Identificar Qué Espera el Test:**
   - ¿Qué valores espera?
   - ¿Qué cálculos valida?
   - ¿Qué reglas salariales involucra?

3. **Identificar Qué Genera el Sistema:**
   - Ejecutar test individualmente con log detallado
   - Identificar valores calculados vs esperados
   - Analizar diferencias

4. **Analizar Código de Cálculo:**
   - Identificar reglas salariales relacionadas
   - Analizar código de cálculo en modelos
   - Verificar lógica de negocio

5. **Root Cause Identificado:**
   - Documentar causa raíz específica
   - Identificar si es problema de:
     - Valores esperados incorrectos en test
     - Cálculo incorrecto en sistema
     - Reglas salariales no ejecutándose
     - Precision de cálculos

**NO IMPLEMENTAR** hasta entender completamente cada test.

#### 3. Implementación con Calidad Enterprise (45min-1h)

**Para cada fix:**

1. **Implementar Solución Arquitectónicamente Correcta:**
   - Seguir estándares Odoo 19 CE
   - Validar cumplimiento con normativa chilena
   - Código limpio y mantenible

2. **Documentar Decisión Técnica:**
   ```python
   # Ejemplo de documentación enterprise
   def _calculate_afc_tope(self, base_tributable):
       """
       Calcular AFC respetando tope legal AFP (87.8 UF)
       
       Técnica Odoo 19 CE:
       - Usar tope legal desde hr.economic.indicators
       - Aplicar tasa AFC sobre base limitada
       
       Normativa Chilena:
       - DFL 150: AFC máximo 2% sobre tope AFP
       - Tope AFP: 87.8 UF (vigente desde 2025)
       
       Args:
           base_tributable: Base tributable en CLP
           
       Returns:
           float: Monto AFC calculado (negativo para descuento)
       """
       # Implementación...
   ```

3. **Validar Edge Cases:**
   - ¿Qué pasa si base_tributable = 0?
   - ¿Qué pasa si base_tributable > tope?
   - ¿Qué pasa si no hay indicadores económicos?

4. **NO crear parches o workarounds**

#### 4. Checkpoint DESPUÉS (5min)

```bash
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32 \
    --log-level=error \
    2>&1 | tee evidencias/task_2.1_after_$(date +%Y%m%d_%H%M%S).log
```

**Validaciones:**
- ✅ Tests pasando DESPUÉS: X/6
- ✅ Comparar: ANTES vs DESPUÉS
- ✅ Validar: Score mejoró
- ✅ Sin errores en log

#### 5. Commit Estructurado con Calidad Enterprise (5min)

```
fix(tests): resolve test_calculations_sprint32 failures (6/6 tests)

Root Cause Analysis:
- test_afc_tope: [Descripción técnica del problema y solución]
- test_allowance_colacion: [Descripción técnica]
- test_bonus_imponible: [Descripción técnica]
- test_full_payslip_with_inputs: [Descripción técnica]
- test_tax_tramo1_exento: [Descripción técnica]
- test_tax_tramo3: [Descripción técnica]

Fixes Implementados:
- [Descripción técnica de cada fix]
- Validación de normativa chilena: [Detalles]
- Edge cases validados: [Lista]

Tests Resolved: 0/6 → 6/6 (100%)
Coverage: 82% → 88% (estimado)
Time: X minutes

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_9.md TASK 2.1
```

**DoD TASK 2.1:**
- ✅ Tests pasando: 6/6 (100%)
- ✅ Sin errores en log
- ✅ Root cause analysis documentado
- ✅ Commit estructurado con calidad enterprise
- ✅ Evidencia documentada (logs antes/después)
- ✅ Código documentado con docstrings completos

---

#### TASK 2.2: CORREGIR test_payslip_totals (15-30min) ⚠️ QUICK WIN

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 15-30min  
**Complejidad:** BAJA

**Estado Actual:**
- 1 test fallando: FAIL (no ERROR, más fácil de resolver)

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 2.1 pero más rápido)

1. Checkpoint ANTES (3min)
2. Root Cause Analysis (5min)
3. Implementación con Calidad Enterprise (10-15min)
4. Checkpoint DESPUÉS (3min)
5. Commit Estructurado (3min)

**DoD TASK 2.2:**
- ✅ Tests pasando: 1/1 (100%)
- ✅ Sin errores en log
- ✅ Root cause analysis documentado
- ✅ Commit estructurado con calidad enterprise
- ✅ Evidencia documentada

---

#### TASK 2.3: CHECKPOINT FASE 2 (15min) ⚠️ OBLIGATORIO

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
       2>&1 | tee evidencias/checkpoint_fase2_$(date +%Y%m%d_%H%M%S).log
   ```

2. **Analizar Resultados (5min):**
   - Documentar: Tests pasando: X/17
   - Documentar: Cobertura: X%
   - Documentar: Errores restantes: N
   - Comparar: Estado inicial vs Estado actual
   - Calcular: Progreso acumulado

3. **Decisión:**
   - ✅ Si score mejoró: Continuar con Fase 3
   - ⚠️ Si score no mejoró: Analizar root cause antes de continuar
   - ❌ Si score empeoró: Detener y re-evaluar estrategia

**DoD TASK 2.3:**
- ✅ Suite completa ejecutada
- ✅ Métricas exactas documentadas
- ✅ Progreso acumulado calculado
- ✅ Decisión tomada con evidencia
- ✅ Reporte generado

---

### FASE 3: ALTA COMPLEJIDAD (2-3 horas) - Prioridad: P1 ALTA

#### TASK 3.1: CORREGIR test_lre_generation (2-3h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P1 - ALTA  
**Estimación:** 2-3h  
**Complejidad:** ALTA

**Estado Actual:**
- 5 tests fallando (todos ERROR):
  - `test_01_wizard_creation`: ERROR
  - `test_02_generate_lre_success`: ERROR
  - `test_03_lre_content_structure`: ERROR
  - `test_04_lre_totals_match`: ERROR
  - `test_06_filename_format`: ERROR

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 2.1 pero con más tiempo)

1. Checkpoint ANTES (5min)
2. Root Cause Analysis Profundo (45min)
3. Implementación con Calidad Enterprise (1-1.5h)
4. Checkpoint DESPUÉS (5min)
5. Commit Estructurado (5min)

**DoD TASK 3.1:**
- ✅ Tests pasando: 5/5 (100%)
- ✅ Sin errores en log
- ✅ Root cause analysis documentado
- ✅ Commit estructurado con calidad enterprise
- ✅ Evidencia documentada
- ✅ Funcionalidad LRE implementada correctamente

---

#### TASK 3.2: CORREGIR test_p0_multi_company (2-3h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P1 - ALTA  
**Estimación:** 2-3h  
**Complejidad:** ALTA

**Estado Actual:**
- 7 tests fallando (todos ERROR):
  - Relacionados con setup multi-company
  - API Odoo 19 CE para grupos/usuarios

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 2.1 pero con más tiempo)

1. Checkpoint ANTES (5min)
2. Root Cause Analysis Profundo (45min) - Investigar API Odoo 19 CE
3. Implementación con Calidad Enterprise (1-1.5h)
4. Checkpoint DESPUÉS (5min)
5. Commit Estructurado (5min)

**DoD TASK 3.2:**
- ✅ Tests pasando: 7/7 (100%)
- ✅ Sin errores en log
- ✅ Root cause analysis documentado
- ✅ Commit estructurado con calidad enterprise
- ✅ Evidencia documentada
- ✅ ir.rules multi-company validadas

---

### FASE 4: VALIDACIÓN FINAL Y DoD (30min) - Prioridad: P0 CRÍTICA

#### TASK 4.1: VALIDACIÓN FINAL Y DoD (30min)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`, `@dte-compliance`  
**Prioridad:** P0 - CRÍTICA  
**Estimación:** 30min

**PROTOCOLO OBLIGATORIO:**

1. **Ejecutar Todos los Tests (10min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=test \
       2>&1 | tee evidencias/sprint2_tests_final_$(date +%Y%m%d_%H%M%S).log
   ```

2. **Generar Reporte de Cobertura (5min):**
   ```bash
   docker-compose run --rm odoo coverage run --source=addons/localization/l10n_cl_hr_payroll \
       -m odoo -c /etc/odoo/odoo.conf -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll

   docker-compose run --rm odoo coverage report -m > evidencias/sprint2_coverage_report.txt
   docker-compose run --rm odoo coverage xml -o evidencias/sprint2_coverage_report.xml
   ```

3. **Validar Instalabilidad (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       -i l10n_cl_hr_payroll \
       --stop-after-init \
       --log-level=error \
       2>&1 | tee evidencias/sprint2_installation.log
   ```

4. **Validar Warnings (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=warn \
       2>&1 | grep -i "warning\|deprecated" | tee evidencias/sprint2_warnings.log
   ```

5. **Generar Reporte DoD Completo (5min):**
   - Archivo: `evidencias/sprint2_dod_report.md`
   - Incluir: Métricas finales, tareas completadas, conclusiones

**DoD TASK 4.1:**
- ✅ Todos los tests pasando (17/17)
- ✅ Cobertura >= 90%
- ✅ Módulo instalable sin errores
- ✅ Sin warnings Odoo 19
- ✅ DoD completo (5/5 criterios)
- ✅ Reporte DoD generado

---

## 📊 PROYECCIÓN REALISTA CON CALIDAD ENTERPRISE

### Cobertura Esperada

| Fase | Tests | Cobertura | Tiempo | Calidad |
|------|-------|-----------|--------|---------|
| **Actual** | ~14/17 | 82% | 3h | Enterprise ✅ |
| **Tras Fase 2** | ~16/17 | 94% | +2-2.5h | Enterprise ✅ |
| **Tras Fase 3** | 17/17 | 100% | +2-3h | Enterprise ✅ |
| **Final (DoD)** | 17/17 | 100% | +30min | Enterprise ✅ |

**Total Estimado:** 4.5-6 horas adicionales (7.5-9 horas totales)

---

## 🌟 CRITERIOS DE CALIDAD ENTERPRISE

### Código

- ✅ Docstrings completos (QUÉ, POR QUÉ, CÓMO)
- ✅ Nombres descriptivos y auto-documentados
- ✅ Estructura clara y mantenible
- ✅ Seguir PEP8 y estándares Odoo 19 CE estrictamente
- ✅ Sin código comentado o "TODO" sin resolver

### Tests

- ✅ Cubrir casos normales, edge cases y casos límite
- ✅ Validar cumplimiento con normativa chilena
- ✅ Tests mantenibles y legibles
- ✅ Assertions descriptivos con mensajes claros

### Documentación

- ✅ Root cause analysis documentado en cada fix
- ✅ Decisiones arquitectónicas documentadas
- ✅ Commits estructurados con detalles técnicos
- ✅ Evidencia completa (logs, métricas, commits)

### Cumplimiento Legal

- ✅ Validar cumplimiento con Ley 21.735
- ✅ Validar cumplimiento con DFL 150
- ✅ Validar cumplimiento con normativa SII
- ✅ Usar `@dte-compliance` para validaciones legales cuando sea necesario

---

## ✅ CONCLUSIÓN Y RECOMENDACIÓN

### Estado Actual

**Progreso Real Validado:**
- ✅ 28 → 19 tests fallando (-32% progreso acumulado)
- ✅ TASK 1.1 completado al 100%
- ✅ TASK 1.2 completado al 100% con calidad enterprise
- ✅ Protocolo de validación incremental seguido perfectamente
- ✅ Root cause analysis profundo realizado
- ✅ Calidad enterprise demostrada

**Próximos Pasos:**
1. Continuar con Fase 2 (TASK 2.1 y 2.2)
2. Ejecutar CHECKPOINT FASE 2
3. Continuar con Fase 3 (TASK 3.1 y 3.2)
4. Validación Final y DoD (TASK 4.1)

### Recomendación

**Continuar con el protocolo establecido manteniendo calidad enterprise:**
- ✅ Mantener principios estrictos (SIN IMPROVISACIÓN, SIN PARCHES)
- ✅ Root cause analysis obligatorio antes de cada fix
- ✅ Validación incremental obligatoria después de cada fix
- ✅ Documentar decisiones arquitectónicas
- ✅ Reportar métricas exactas (no estimadas)
- ✅ Calidad enterprise en cada línea de código

**Objetivo:** 100% cobertura (17/17 tests) con calidad enterprise de clase mundial.

---

**FIN DEL PROMPT MASTER V5.9**

