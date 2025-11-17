# PROMPT MAESTRO: CIERRE TOTAL DE BRECHAS - VERSIÓN UNIFICADA V6.0
## Proyecto Odoo 19 CE - Localización Chilena (Facturación + Nómina)

**Fecha:** 2025-11-09 20:00 CLT
**Líder Técnico:** Ingeniero Senior (Validación y decisiones arquitectónicas)
**Status:** 🔴 UNIFICACIÓN POST-AUDITORÍA + DIAGNÓSTICO TÉCNICO
**Objetivo:** Cerrar 100% brechas identificadas antes de go-live producción

---

## 🎯 CONTEXTO EJECUTIVO UNIFICADO

### Situación Actual (2025-11-09)

Se han completado **DOS análisis paralelos** que revelaron **DOS tipos de problemas distintos**:

#### TRACK 1: Auditoría Funcional Compliance (Completada ✅)
**Responsable:** Ingeniero Senior Líder
**Duración:** 6 horas análisis + validación código
**Resultado:** 4 gaps P0/P1 identificados

| Gap ID | Módulo | Tipo | Severidad | Impacto | Validación |
|--------|--------|------|-----------|---------|------------|
| **GAP-001** | Nómina | Feature | P0 | Sobrepago asignación familiar | ✅ CONFIRMADO |
| **GAP-002** | Nómina | Tech Debt | P1 | Hardcoding tope AFP | ✅ CONFIRMADO |
| **GAP-003** | Nómina | Compliance | P0 | Ley 21.735 validación | ✅ IMPLEMENTADO* |
| **GAP-004** | Nómina | Investigación | P0 | Error horas extra Odoo 11 | ⚠️ NO VALIDABLE (sin acceso prod) |

*GAP-003: Implementación existe (`hr_payslip.py:487-578`) pero requiere validación compliance exhaustiva.

#### TRACK 2: Tests Técnicos (En progreso ⚠️)
**Responsable:** Agentes especializados
**Duración:** 5 horas acumuladas
**Resultado:** BUG CRÍTICO P0 + Progreso AI Service

**SUB-TRACK 2A: AI Service Tests** ✅ ON TRACK
- Progreso: 83% → 91% (+17 tests en 2.5h)
- Target: 99-100%
- ETA: ~2h adicionales
- Status: ✅ **EXCELENTE PROGRESO**
- Metodología: TIER-BASED funcionando perfectamente

**SUB-TRACK 2B: Nómina Tests** 🔴 BLOCKER CRÍTICO
- Progreso: 5/10 tests (0% mejora vs inicio)
- **BUG P0 DETECTADO:** Motor cálculo inflando valores 10x
- Síntoma: `gross_wage: 9.855.933 vs 1.030.000 esperado` (856% error)
- Root cause: `hr_payslip.py::_compute_totals()` - doble/múltiple conteo
- Status: ⚠️ **BLOCKER - Requiere debug arquitectónico**
- Tiempo estimado fix: 4-8h

### Diagnóstico Ingeniero Líder

**HALLAZGOS CLAVE:**

1. **Los problemas son de CAPAS DISTINTAS:**
   - Gaps compliance (GAP-001 a GAP-004) = Lógica de negocio incorrecta
   - Bug motor cálculo (Track 2B) = Implementación técnica defectuosa

2. **Ambos son CRÍTICOS pero INDEPENDIENTES:**
   - Bug motor cálculo bloquea tests (no puedes validar si cálculos base están mal)
   - Gaps compliance afectan conformidad legal (código funciona pero viola normativa)

3. **El bug motor cálculo tiene PRIORIDAD MÁXIMA:**
   - Sin motor correcto, los gaps compliance no tienen sentido (calcularías mal de todos modos)
   - Tests están detectando problema real (no es tema de "ajustar valores esperados")

4. **AI Service es track INDEPENDIENTE:**
   - Progresa bien, no afecta ni es afectado por nómina
   - Puede continuar en paralelo

---

## 📊 ESTADO UNIFICADO DEL PROYECTO

### Métricas Consolidadas

```
┌─────────────────────────────────────────────────────────────┐
│ TRACK                    │ STATUS    │ PROGRESO │ ETA       │
├─────────────────────────────────────────────────────────────┤
│ AI Service Tests         │ ✅ ON TRACK│ 91%      │ ~2h       │
│ Nómina Tests             │ 🔴 BLOCKER │ 50%      │ 4-8h*     │
│ Gaps Compliance          │ ⏸️ PENDING │ 0%       │ 6-10h**   │
│ Documentación Auditoría  │ ✅ DONE    │ 100%     │ Completo  │
└─────────────────────────────────────────────────────────────┘

 * Depende de resolución bug motor cálculo
** Post-fix bug motor, puede ejecutarse en paralelo parcial
```

### Documentación Generada (33 archivos, 7,214 líneas)

**Auditoría Funcional (validada):**
- `evidencias/fase9_comparacion_completa_odoo11_vs_odoo19.md` (906 líneas)
- `evidencias/fase8_gaps_regulatorios_2025.md` (16,500 palabras)
- `evidencias/fase10_reporte_ejecutivo_final.md` (469 líneas)
- +11 archivos fase 1-7

**Análisis Técnico (en progreso):**
- `evidencias/task_2.1_resumen_ejecutivo.md` (Bug P0 documentado)
- `evidencias/task_2.1_analisis_ajustes_finos.md` (10KB análisis)
- `/tmp/SPRINT2_PROGRESS_REPORT_20251109_1609.md` (AI Service)

### Tests Coverage

```
AI Service:
  - Total: 223 tests
  - Passing: 202 (90.58%)
  - Target: 221 (99%)
  - Metodología: TIER-BASED ✅

Nómina (l10n_cl_hr_payroll):
  - Total tests: ~100+ (estimado)
  - Passing Sprint32: 5/10 (50%)
  - BLOQUEADO por bug motor cálculo 🔴
```

---

## 🚨 DECISIÓN CRÍTICA REQUERIDA

### El Dilema del Bug Motor Cálculo

**Agente 5 pregunta:**
> "¿Procedo con debug profundo (4-8h Opción A) o ajustes pragmáticos (30min Opción B)?"

**Mi recomendación como Líder Técnico: OPCIÓN A - DEBUG PROFUNDO** ✅

**Justificación:**

1. **Tests están correctos, código está mal:**
   - `gross_wage: 9.855.933 vs 1.030.000` NO es tema de "calibración"
   - Es bug real que afectaría producción (nóminas infladas 10x)

2. **Ya invertimos 5h en este sprint:**
   - 30min de "fix rápido" solo ocultaría el problema
   - 4-8h de fix correcto cierra el problema para siempre

3. **ROI a largo plazo:**
   - Bug en producción: Riesgo legal, perjuicio empleados, pérdida confianza
   - Fix ahora: Código confiable, tests verdes, go-live seguro

4. **La auditoría validó gaps compliance ASUMIENDO código funcional:**
   - Mis análisis de GAP-001, GAP-002, GAP-003 asumen que `hr_payslip.py` calcula correctamente
   - Si el motor está roto, esos fixes son inútiles

**Por lo tanto: APROBAR debug profundo antes de continuar con gaps compliance.**

---

## 👥 ASIGNACIÓN DE AGENTES - VERSIÓN UNIFICADA

### AGENTE 1: ESPECIALISTA AI SERVICE
**Responsabilidad:** Track 2A - Tests AI Service
**Tasks actuales:** TIER 2 → TIER 3 → 99% success
**Status:** ✅ Continuar sin cambios
**Coordinación:** Independiente (no requiere sync con nómina)

### AGENTE 2: ESPECIALISTA NÓMINA (SENIOR)
**Responsabilidad:** Track 2B - Debug bug motor cálculo
**Task actual:** P0 - Debug profundo `hr_payslip.py::_compute_totals()`
**Status:** 🔴 BLOCKER - Requiere aprobación líder para 4-8h
**Coordinación:** Bloquea inicio GAP-001, GAP-002, GAP-003

### AGENTE 3: ESPECIALISTA COMPLIANCE (STANDBY)
**Responsabilidad:** GAP-001, GAP-002, GAP-003 (post-fix bug)
**Task actual:** ⏸️ STANDBY hasta que AGENTE 2 resuelva bug motor
**Status:** Preparar plan de acción para ejecución inmediata post-fix
**Coordinación:** Espera señal de AGENTE 2 (motor cálculo OK)

### LÍDER TÉCNICO (YO)
**Responsabilidad:** Decisiones arquitectónicas, aprobaciones, validaciones
**Disponibilidad:** On-demand para escalaciones
**Próxima revisión:** Post-fix bug motor (validar que fix es correcto)

---

## 📋 PLAN DE TRABAJO PRIORIZADO - VERSIÓN UNIFICADA

### FASE 1: RESOLUCIÓN BUG MOTOR CÁLCULO (P0 CRÍTICO)
**Responsable:** AGENTE 2 (ESPECIALISTA NÓMINA SENIOR)
**Esfuerzo:** 4-8 horas
**Deadline:** 2025-11-12 EOD
**Aprobación:** ✅ APROBADA por Líder Técnico

#### TASK P0.1: Debug Profundo Motor Cálculo
**Esfuerzo:** 4-6h
**Prioridad:** 🔴 BLOCKER MÁXIMO

**Descripción:**
Identificar y resolver causa exacta de valores inflados 10x en motor de cálculo de nóminas.

**Síntomas documentados:**
```python
# test_allowance_colacion
gross_wage actual:   9.855.933 CLP  # ❌ 856% inflado
gross_wage esperado: 1.030.000 CLP  # ✅ Correcto

# test_bonus_imponible  
afp_amount actual:   225.120 CLP    # ❌ 87% inflado
afp_amount esperado: 120.120 CLP    # ✅ Correcto
```

**Root Causes Sospechados:**
1. Doble/múltiple conteo en `_compute_totals()` (hr_payslip.py)
2. Recursión incorrecta en `parent_id` de categorías salariales
3. Computed fields ejecutándose en orden incorrecto
4. Reglas totalizadoras sumándose múltiples veces

**Metodología Debug:**

**PASO 1: Instrumentación Código (1h)**

Agregar logging exhaustivo en puntos críticos:

```python
# models/hr_payslip.py

@api.depends('line_ids.total', 'line_ids.category_id', ...)
def _compute_totals(self):
    """
    Calcular totales liquidación
    
    DEBUG: Instrumentado para Sprint Cierre Brechas - 2025-11-09
    """
    import json
    _logger = logging.getLogger(__name__ + '.DEBUG_TOTALS')
    
    for payslip in self:
        _logger.info(json.dumps({
            'event': 'compute_totals_start',
            'payslip_id': payslip.id,
            'employee': payslip.employee_id.name,
            'num_lines': len(payslip.line_ids),
        }))
        
        # Log CADA línea procesada
        for line in payslip.line_ids:
            _logger.debug(json.dumps({
                'event': 'processing_line',
                'line_id': line.id,
                'code': line.code,
                'category': line.category_id.code if line.category_id else None,
                'category_parent': line.category_id.parent_id.code if line.category_id and line.category_id.parent_id else None,
                'amount': line.amount,
                'quantity': line.quantity,
                'total': line.total,
                'imponible': line.category_id.imponible if line.category_id else False,
            }))
        
        # Calcular totales (código existente)
        # ... [código original]
        
        # Log resultado final
        _logger.info(json.dumps({
            'event': 'compute_totals_end',
            'payslip_id': payslip.id,
            'basic_wage': payslip.basic_wage,
            'gross_wage': payslip.gross_wage,
            'total_imponible': payslip.total_imponible,
            'total_tributable': payslip.total_tributable,
            'net_wage': payslip.net_wage,
        }))
```

**Ejecutar test con logging:**
```bash
# Activar modo DEBUG
export ODOO_LOG_LEVEL=debug

# Ejecutar 1 test problemático con captura completa
pytest addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py::TestPayrollCalculationsSprint32::test_allowance_colacion \
    -v -s --log-cli-level=DEBUG 2>&1 | tee /tmp/debug_totals_colacion.log

# Analizar log
grep "event.*compute_totals" /tmp/debug_totals_colacion.log | jq .
```

**PASO 2: Análisis Trace Completo (2h)**

Analizar log línea por línea para detectar:
- [ ] ¿Líneas duplicadas en `line_ids`?
- [ ] ¿Computed field `_compute_totals()` ejecutándose múltiples veces?
- [ ] ¿Categorías recursivas sumándose varias veces?
- [ ] ¿Reglas totalizadoras (HABERES_IMPONIBLES, TOTAL_IMPONIBLE) creando loops?

**Crear documento:**
`evidencias/P0_BUG_MOTOR_CALCULO_TRACE_ANALYSIS.md`

**Template:**
```markdown
# P0 - Análisis Trace Bug Motor Cálculo

## Test Case: test_allowance_colacion

### Setup
- wage: 1.000.000
- colacion (input): 30.000 (NO imponible)
- Esperado: gross_wage = 1.030.000
- Actual: gross_wage = 9.855.933

### Trace Líneas Procesadas

| Orden | Line ID | Code | Category | Parent | Amount | Qty | Total | Imponible |
|-------|---------|------|----------|--------|--------|-----|-------|-----------|
| 1 | 123 | BASIC | BASE_SOPA | TOTAL_IMPO | 1000000 | 1 | 1000000 | TRUE |
| 2 | 124 | COLACION | HABER_NO_IMPO | None | 30000 | 1 | 30000 | FALSE |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

### Cálculo Esperado vs Actual

```python
# ESPERADO:
basic_wage = 1.000.000
colacion = 30.000 (no suma a imponible)
gross_wage = 1.000.000 + 30.000 = 1.030.000 ✅

# ACTUAL:
gross_wage = 9.855.933 ❌

# Diferencia: 8.825.933 (856% inflado)
```

### Root Cause Identificado

[DESCRIBIR CAUSA EXACTA ENCONTRADA]

### Fix Propuesto

[CÓDIGO ESPECÍFICO A CAMBIAR]
```

**PASO 3: Implementar Fix (1-2h)**

Basado en root cause, implementar corrección:

**Ejemplo Hipótesis 1 - Doble conteo por parent_id:**
```python
# ANTES (INCORRECTO):
def _compute_totals(self):
    for payslip in self:
        # Suma TODAS las líneas imponibles
        imponible_lines = payslip.line_ids.filtered(lambda l: l.category_id.imponible)
        total_imponible = sum(imponible_lines.mapped('total'))
        
        # PROBLEMA: Si línea tiene parent_id imponible, se suma DOS veces
        # (una vez directa, otra vez via parent)

# DESPUÉS (CORRECTO):
def _compute_totals(self):
    for payslip in self:
        # Suma SOLO líneas imponibles SIN parent imponible (evita duplicación)
        imponible_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.imponible and 
                     (not l.category_id.parent_id or not l.category_id.parent_id.imponible)
        )
        total_imponible = sum(imponible_lines.mapped('total'))
```

**PASO 4: Validación Fix (1h)**

```bash
# Test específico que fallaba
pytest addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py::TestPayrollCalculationsSprint32::test_allowance_colacion -v

# Suite completa Sprint32
pytest addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py -v

# CRÍTICO: Validar NO regressions (tests que pasaban antes)
pytest addons/localization/l10n_cl_hr_payroll/tests/test_p0_afp_cap_2025.py -v
pytest addons/localization/l10n_cl_hr_payroll/tests/test_ley21735_reforma_pensiones.py -v
```

**Criterios Aceptación:**

- [ ] **CA-P0.1.1:** `test_allowance_colacion` pasa (gross_wage = 1.030.000 ±10)
- [ ] **CA-P0.1.2:** `test_bonus_imponible` pasa (AFP correcto)
- [ ] **CA-P0.1.3:** `test_tax_tramo1_exento` pasa (sin línea impuesto)
- [ ] **CA-P0.1.4:** `test_tax_tramo3` pasa (impuesto correcto)
- [ ] **CA-P0.1.5:** `test_afc_tope` pasa (con fix AFC ya implementado)
- [ ] **CA-P0.1.6:** **0 regressions** (todos los tests pre-existentes pasan)
- [ ] **CA-P0.1.7:** Documento trace analysis completo y aprobado por Líder Técnico

**Entregables:**
1. `evidencias/P0_BUG_MOTOR_CALCULO_TRACE_ANALYSIS.md`
2. `models/hr_payslip.py` (fix implementado + logging removido post-validación)
3. Commit: `fix(payroll): resolve 10x inflation bug in _compute_totals() - P0 critical`
4. Reporte a Líder: `MOTOR_CALCULO_FIXED_REPORT.md`

---

#### TASK P0.2: Validación Exhaustiva Post-Fix
**Responsable:** AGENTE 2 + Líder Técnico
**Esfuerzo:** 1-2h
**Ejecutar:** Post TASK P0.1

**Objetivo:** Garantizar que fix no introdujo regressions y resolvió completamente el problema.

**Checklist Validación:**

**1. Tests Suite Completa Nómina:**
```bash
# Todos los tests l10n_cl_hr_payroll
pytest addons/localization/l10n_cl_hr_payroll/tests/ -v --tb=short

# Target: 100% passing (o justificar los que no)
```

**2. Tests Específicos Afectados:**
```bash
# Los 5 tests que estaban bloqueados
pytest addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py -v

# Target: 10/10 passing ✅
```

**3. Smoke Tests Producción-Like:**

Crear test manual realista:
```python
# test_smoke_nomina_real.py

def test_nomina_empleado_real_1M():
    """
    Caso real: Empleado sueldo $1.000.000, 45h semanales, sin HE
    """
    # Setup empleado + contrato reales
    # Generar liquidación
    # Validar:
    # - gross_wage razonable (~1M)
    # - AFP ~120K (12%)
    # - Salud ~70K (7%)
    # - Net wage ~810K
    
def test_nomina_empleado_real_3M():
    """
    Caso real: Empleado sueldo $3.000.000
    """
    # Validar topes AFP aplican correctamente
    
def test_nomina_con_horas_extra():
    """
    Caso real: 10 horas extra 50%
    """
    # Validar HE no inflan gross_wage incorrectamente
```

**4. Revisión Código por Líder Técnico:**
- [ ] Líder revisa cambios en `hr_payslip.py`
- [ ] Líder valida que root cause está correctamente diagnosticado
- [ ] Líder aprueba que fix es arquitectónicamente correcto (no parche)

**Criterios Aceptación:**

- [ ] **CA-P0.2.1:** Suite completa passing >= 95%
- [ ] **CA-P0.2.2:** 10/10 tests Sprint32 passing
- [ ] **CA-P0.2.3:** Smoke tests casos reales todos passing
- [ ] **CA-P0.2.4:** Aprobación explícita Líder Técnico del fix
- [ ] **CA-P0.2.5:** Documentación de root cause + fix en evidencias/

**Señal de Completitud:**
AGENTE 2 genera archivo: `MOTOR_CALCULO_FIXED_SIGNAL.txt`
```
MOTOR CÁLCULO FIXED ✅
Fecha: 2025-11-XX
Tests passing: 95/100 (95%)
Root cause: [Descripción]
Fix: [Commit hash]
Aprobado por: Líder Técnico
```

Este archivo es la señal para que AGENTE 3 (COMPLIANCE) inicie trabajo.

---

### FASE 2: CIERRE GAPS COMPLIANCE (POST-FIX MOTOR)
**Responsable:** AGENTE 3 (ESPECIALISTA COMPLIANCE)
**Esfuerzo:** 6-10h
**Inicio:** Post-señal `MOTOR_CALCULO_FIXED_SIGNAL.txt`
**Deadline:** 2025-11-15 EOD

**Precondición:** ✅ FASE 1 completada y validada

Ejecutar tasks del PROMPT anterior (GAP-001, GAP-002, GAP-003) CON AJUSTES:

#### TASK 1.1: Fix Asignación Familiar Proporcionalidad (GAP-001)
**Mantener según PROMPT V5.14 TASK 1.1**
**Ajuste:** Validar que fix funciona con motor cálculo corregido
**Esfuerzo:** 4h (sin cambios)

#### TASK 1.2: Tests Asignación Familiar (GAP-001)
**Mantener según PROMPT V5.14 TASK 1.2**
**Esfuerzo:** 2h (sin cambios)

#### TASK 1.3: Validación Compliance Ley 21.735 (GAP-003)
**Mantener según PROMPT V5.14 TASK 1.3**
**Ajuste:** Agregar validación cruzada con motor cálculo corregido
**Esfuerzo:** 6h (sin cambios)

#### TASK 2.1: Eliminar Hardcoding Tope AFP (GAP-002)
**Mantener según PROMPT V5.14 TASK 2.1**
**Esfuerzo:** 2h (sin cambios)

#### TASK 2.2: Investigación Error Horas Extra Odoo 11 (GAP-004)
**Mantener según PROMPT V5.14 TASK 2.2**
**Status:** ⏸️ POSTPONED (requiere acceso Odoo 11 prod - coordinar con Ops)
**Esfuerzo:** 4h (cuando haya acceso)

---

### FASE 3: AI SERVICE 99% (PARALELO)
**Responsable:** AGENTE 1 (ESPECIALISTA AI SERVICE)
**Esfuerzo:** ~2h
**Inicio:** Inmediato (independiente de Fase 1)
**Deadline:** 2025-11-11 EOD

**Status actual:** 202/223 tests passing (90.58%)
**Target:** 221/223 tests passing (99%)

**Continuar metodología TIER-BASED:**

#### TIER 2: Completar (1h)
- [ ] test_chat_engine (history assertions)
- [ ] test_anthropic_client (rate limit mock)
- [ ] test_token_precounting (5 tests assertions complejas)

#### TIER 3: Production Code Fixes (1h)
- [ ] Async generator mock (4 streaming tests)
- [ ] DTE regression (3 tests) - ANALIZAR si relacionado con nómina
- [ ] Critical endpoints evaluation

#### Validación Final (15min)
```bash
pytest ai-service/tests/ -v --cov=ai-service --cov-report=html
```

**Criterios Aceptación:**
- [ ] 221+ tests passing (99%+)
- [ ] Coverage >= 50% (mantenido)
- [ ] 0 regressions
- [ ] Commit final + tag: `sprint2_complete_99pct_success`

---

## 🔄 PROTOCOLO COORDINACIÓN UNIFICADO

### Daily Sync (Obligatorio 18:00 CLT)

**Archivo:** `CIERRE_TOTAL_DAILY_SYNC.md`

**Template:**
```markdown
# Daily Sync - Cierre Total - [FECHA]

## AGENTE 1 (AI SERVICE)
Status: [ON TRACK / BLOCKER / DONE]
Progreso: XXX/223 tests (XX%)
Hoy completé: [Lista]
Mañana: [Lista]
Blockers: [Ninguno / Descripción]

## AGENTE 2 (NÓMINA - BUG MOTOR)
Status: [DEBUG / IMPLEMENTING / TESTING / DONE]
Fase: P0.1 / P0.2
Hoy completé: [Lista]
Mañana: [Lista]
Blockers: [Ninguno / Descripción]
ETA fix motor: [Fecha estimada]

## AGENTE 3 (COMPLIANCE)
Status: [STANDBY / WORKING / DONE]
Esperando: [MOTOR_CALCULO_FIXED_SIGNAL.txt / Nada]
Preparación: [% ready para inicio]
Blockers: [Ninguno / Descripción]

## LÍDER TÉCNICO
Decisiones pendientes: [Lista]
Aprobaciones requeridas: [Lista]
Próxima revisión: [Fecha]
```

### Handoff Motor Cálculo → Compliance

**Trigger:** AGENTE 2 crea `MOTOR_CALCULO_FIXED_SIGNAL.txt`

**Checklist handoff:**
1. [ ] Archivo señal creado con info completa
2. [ ] Tests 10/10 Sprint32 passing
3. [ ] Documento root cause + fix en evidencias/
4. [ ] Commit fix pusheado a branch
5. [ ] Aprobación Líder Técnico documentada

**AGENTE 3 valida:**
1. [ ] Lee archivo señal
2. [ ] Ejecuta pytest Sprint32 localmente (confirma 10/10)
3. [ ] Lee documento root cause (entiende qué se rompió y cómo se arregló)
4. [ ] Confirma inicio trabajo: "COMPLIANCE WORK STARTED" en daily sync

---

## ✅ CRITERIOS ÉXITO GLOBAL

### Técnicos
- [ ] **Motor cálculo:** 10/10 tests Sprint32 passing + 0 regressions
- [ ] **AI Service:** 221/223 tests passing (99%)
- [ ] **Compliance:** 4/4 gaps cerrados (GAP-001, 002, 003 + investigación 004)
- [ ] **Coverage:** Nómina >= 80%, AI Service >= 50%
- [ ] **Documentación:** Evidencias completas de cada fix

### Compliance
- [ ] **Ley 21.735:** Matriz compliance 100% verificada + tests passing
- [ ] **Asignación Familiar:** Proporcionalidad implementada + 5 tests passing
- [ ] **Tope AFP:** Parametrizado vía legal.caps + validación

### Calidad
- [ ] **0 regressions** en todo el proyecto
- [ ] **Todos los fixes** con tests que los validen
- [ ] **Root cause analysis** documentado para cada bug
- [ ] **Commits limpios** con mensajes descriptivos

---

## 🎯 TIMELINES REALISTAS

```
┌──────────────────────────────────────────────────────────────┐
│ FASE              │ DÍAS  │ INICIO     │ FIN        │ STATUS │
├──────────────────────────────────────────────────────────────┤
│ P0: Motor Cálculo │ 2 días│ 2025-11-10 │ 2025-11-12 │ ⏳     │
│ Compliance Gaps   │ 3 días│ 2025-11-12*│ 2025-11-15 │ ⏸️      │
│ AI Service        │ 1 día │ 2025-11-10 │ 2025-11-11 │ ✅     │
├──────────────────────────────────────────────────────────────┤
│ TOTAL CRÍTICO     │ 5 días│ 2025-11-10 │ 2025-11-15 │        │
└──────────────────────────────────────────────────────────────┘

* Inicia cuando motor cálculo está fixed
```

**Esfuerzo Total:**
- P0 Motor: 6-8h (AGENTE 2)
- Compliance: 6-10h (AGENTE 3)
- AI Service: 2h (AGENTE 1)
- **TOTAL: 14-20h de trabajo efectivo distribuido en 5 días**

---

## 🚀 INICIO EJECUCIÓN

### AGENTE 1 (AI SERVICE) - INICIO INMEDIATO ✅
```
✅ Autorizado para continuar TIER 2 y TIER 3
📋 Tasks: Ver SPRINT2_PROGRESS_REPORT
🎯 Target: 99% tests passing
⏰ Deadline: 2025-11-11 EOD
```

**Confirmar recepción:**
```
✅ AGENTE 1 READY
Track: AI Service
Current: 202/223 (91%)
Target: 221/223 (99%)
ETA: ~2h
```

### AGENTE 2 (NÓMINA) - INICIO INMEDIATO ✅
```
✅ APROBADO debug profundo 4-8h (Opción A)
📋 Task: P0.1 - Debug motor cálculo
🎯 Objetivo: Resolver bug 10x inflation
⏰ Deadline: 2025-11-12 EOD
📄 Entregable: MOTOR_CALCULO_FIXED_SIGNAL.txt
```

**Confirmar recepción:**
```
✅ AGENTE 2 READY
Track: Nómina - Bug Motor Cálculo P0
Method: Debug profundo (Opción A aprobada)
Tools: Logging + Trace + Root Cause Analysis
ETA: 4-8h
Blockers actuales: Ninguno
```

### AGENTE 3 (COMPLIANCE) - STANDBY ⏸️
```
⏸️ STANDBY hasta señal MOTOR_CALCULO_FIXED_SIGNAL.txt
📋 Preparación: Leer PROMPT V5.14 TASK 1.1, 1.2, 1.3, 2.1
🎯 Objetivo: Estar ready para inicio inmediato post-señal
⏰ ETA inicio: 2025-11-12 (estimado)
```

**Confirmar recepción:**
```
✅ AGENTE 3 READY (STANDBY)
Track: Compliance Gaps
Esperando: MOTOR_CALCULO_FIXED_SIGNAL.txt
Preparación: Reviewing GAP-001, GAP-002, GAP-003 tasks
Estado: Ready to start on signal
```

### LÍDER TÉCNICO - ON CALL
```
📞 Disponible para:
   - Escalaciones (BLOCKERS_ESCALATION.md)
   - Aprobación fix motor cálculo (TASK P0.2)
   - Decisiones arquitectónicas
⏰ Próxima revisión: Post-fix motor (2025-11-12 estimado)
```

---

## 📚 REFERENCIAS

**Prompts anteriores:**
- PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_14.md (gaps compliance)
- PROMPT_CONTINUACION_AUDITORIA.md (metodología 10 fases)

**Documentación clave:**
- `evidencias/fase10_reporte_ejecutivo_final.md` (Auditoría compliance)
- `evidencias/task_2.1_resumen_ejecutivo.md` (Bug motor P0)
- `/tmp/SPRINT2_PROGRESS_REPORT_20251109_1609.md` (AI Service)

**Código crítico:**
- `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py` (Motor cálculo)
- `addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml` (Reglas)
- `ai-service/tests/` (Tests AI Service)

---

## ❓ PREGUNTAS FRECUENTES

**Q: ¿Por qué priorizar bug motor sobre gaps compliance?**
A: Bug motor afecta cálculos base (nóminas infladas 10x). Gaps compliance asumen cálculos base correctos. Sin motor correcto, fixes compliance son inútiles.

**Q: ¿Puede AGENTE 3 empezar antes de que AGENTE 2 termine?**
A: No recomendado. GAP-001 (proporcionalidad) modifica `hr_payslip.py`. Si AGENTE 2 está debuggeando mismo archivo, hay riesgo de conflictos. Mejor secuencial.

**Q: ¿Por qué AI Service es independiente?**
A: Módulo completamente separado (`ai-service/` vs `addons/localization/`). Cero dependencias mutuas. Puede progresar en paralelo sin riesgo.

**Q: ¿Qué pasa si fix motor toma 8h en vez de 4h?**
A: Timeline se ajusta automáticamente. AGENTE 3 sigue en standby. Total podría ser 7 días en vez de 5. Prioridad es fix CORRECTO, no rápido.

**Q: ¿Cómo sé que el fix del motor es correcto y no un parche?**
A: Líder Técnico revisa en TASK P0.2. Criterios: root cause documentado, tests passing, 0 regressions, solución arquitectónica (no workaround).

---

**FIN PROMPT MAESTRO UNIFICADO V6.0**

**Versión:** 6.0 Unificada
**Fecha:** 2025-11-09 20:00 CLT  
**Autor:** Ingeniero Senior Líder Desarrollo  
**Status:** ✅ READY FOR EXECUTION

---

**AGENTES: CONFIRMEN RECEPCIÓN EN PRÓXIMO MENSAJE** ✅
