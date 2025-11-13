# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (FINAL)
## Estado Actual Validado | Orquestación de Sub-Agentes | Máxima Precisión

**Versión:** 4.2 (Final)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (63% completado → 100% objetivo)  
**Base:** PROMPT_CONTINUACION_SPRINT2.md + Análisis Log Agente  
**Progreso Actual:** 4.5h de 7.5h (142/155 tests pasando - 92%)

---

## 📊 ESTADO ACTUAL VALIDADO

### ✅ Tareas Completadas (63% del SPRINT 2)

**TASK 2.1:** `compute_sheet()` wrapper ✅
- Commit: `c48b7e70`
- Tests resueltos: +15
- Estado: COMPLETADO

**TASK 2.2:** `employer_reforma_2025` campo computed ✅
- Commit: `c48b7e70` (combinado)
- Tests resueltos: +24
- Estado: COMPLETADO

**TASK 2.3:** Migración `_sql_constraints` → `@api.constrains` ✅
- Commit: `a542ab88`
- Archivos migrados: 9 modelos
- Tests resueltos: +6
- Warnings eliminados: 9
- Estado: COMPLETADO

**TASK 2.4:** Validación Integración Previred ✅
- Commit: `9fa6b5d7`
- Método `_compute_employer_reforma_2025()` implementado correctamente
- Cálculo directo: 1% del sueldo para contratos >= 2025-01-01
- Exportación Previred incluye campo `employer_reforma_2025`
- Validaciones Previred funcionando (AFP, indicadores, Reforma 2025, RUT)
- Tests Previred pasando: 8/8 ✅
- Estado: COMPLETADO

**Total Trabajo Completado:** 4.5 horas

---

## ⚠️ ESTADO DE TESTS ACTUAL

### Métricas Validadas

**Tests Totales:** 155  
**Tests Pasando:** ~142 (92%)  
**Tests Fallando:** 13 errores

**Desglose de Errores:**

| Test Suite | Errores | Causa Raíz Identificada | Prioridad |
|------------|---------|------------------------|-----------|
| `test_ley21735_reforma_pensiones` | 5 | Indicadores económicos faltantes en setup | P1 |
| `test_payslip_totals` | 4 | Diferencias en cálculos (precision/rounding) | P1 |
| `test_payslip_validations` | 3 | Contratos superpuestos / Mensajes de error | P2 |
| `test_payroll_calculation_p1` | 1 | Campo 'month' → 'period' (ya corregido) | P1 |

**Total Errores:** 13

---

## 🎯 OBJETIVO: COMPLETAR SPRINT 2 (100% Cobertura)

### Tareas Pendientes (3 horas restantes)

**TASK 2.5:** Configurar Multi-Company (1h) → +2 tests → 99%  
**TASK 2.6:** Corregir Tests Fallando (1h) → +13 tests → 100%  
**TASK 2.7:** Validación Final y DoD (1h) → Validación completa

**Objetivo Final:** 155/155 tests pasando (100% cobertura)

---

## 👥 ORQUESTACIÓN DE SUB-AGENTES ESPECIALIZADOS

### Equipo de Agentes Disponibles

| Agente | Modelo | Especialización | Tools | Config File |
|--------|--------|-----------------|-------|-------------|
| `@odoo-dev` | o1-mini | Desarrollo Odoo 19 CE, localización chilena | Code, Search, Read | `.claude/agents/odoo-dev.md` |
| `@test-automation` | o1-mini | Testing automatizado, CI/CD, análisis de tests | Code, Test, Coverage, Analysis | `.claude/agents/test-automation.md` |
| `@dte-compliance` | o1-mini | Cumplimiento SII, validación DTE, compliance legal | Read-only, Validation | `.claude/agents/dte-compliance.md` |
| `@docker-devops` | o1-mini | Docker, despliegues producción | Docker, CI/CD | `.claude/agents/docker-devops.md` |

### Asignación de Agentes por Tarea

```yaml
TASK_2_5_MULTI_COMPANY:
  primary: "@odoo-dev"
  support: ["@test-automation"]
  duration: "1 hora"
  focus: "ir.rules multi-company, company_id fields"

TASK_2_6_FIX_TESTS:
  primary: "@test-automation"
  support: ["@odoo-dev"]
  duration: "1 hora"
  focus: "Análisis sistemático y corrección de 13 errores"

TASK_2_7_FINAL_VALIDATION:
  primary: "@odoo-dev"
  support: ["@test-automation", "@dte-compliance"]
  duration: "1 hora"
  focus: "Validación completa, DoD, reportes finales"
```

---

## 📋 TASK 2.5: CONFIGURAR MULTI-COMPANY (1h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P2 - MEDIA  
**Estimación:** 1 hora

### Contexto

**Problema Identificado:**
- 2 tests fallando relacionados con multi-company
- Configuración multi-company puede requerir ajustes

### Objetivo

Configurar correctamente multi-company para que los tests pasen.

### Tareas Específicas

#### 1. Validar ir.rules Multi-Company (30min)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/security/multi_company_rules.xml`

**Validaciones Requeridas:**

1. **Verificar Existencia de Archivo:**
   ```bash
   ls -la addons/localization/l10n_cl_hr_payroll/security/multi_company_rules.xml
   ```

2. **Validar Reglas Correctas:**
   - Verificar que las reglas restringen acceso por `company_id`
   - Validar que los modelos principales tienen reglas multi-company:
     - `hr.payslip`
     - `hr.contract`
     - `hr.employee`
     - `hr.afp`
     - `hr.isapre`
     - `hr.economic.indicators`

3. **Validar Sintaxis XML:**
   ```bash
   xmllint --noout addons/localization/l10n_cl_hr_payroll/security/multi_company_rules.xml
   ```

**Evidencia Requerida:**
- Archivo `multi_company_rules.xml` validado
- Lista de modelos con reglas multi-company
- Log de validación XML

#### 2. Validar Configuración company_id (30min)

**Archivos:** Modelos principales

**Validaciones Requeridas:**

1. **Verificar Campos company_id:**
   ```bash
   # Buscar campos company_id en modelos
   grep -r "company_id.*=.*fields" addons/localization/l10n_cl_hr_payroll/models/ | grep -v "__pycache__"
   ```

2. **Validar Defaults Correctos:**
   - Verificar que los defaults de `company_id` son correctos
   - Validar que se obtiene de contexto o usuario:
     ```python
     company_id = fields.Many2one(
         'res.company',
         string='Company',
         default=lambda self: self.env.company
     )
     ```

3. **Validar Tests Multi-Company:**
   ```bash
   # Ejecutar tests multi-company específicos
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestMultiCompany \
       --log-level=test
   ```

**Evidencia Requerida:**
- Lista de modelos con `company_id`
- Validación de defaults
- Log de tests multi-company

### DoD TASK 2.5

- ✅ ir.rules multi-company configuradas correctamente
- ✅ Campos `company_id` presentes y con defaults correctos
- ✅ Tests multi-company pasando (2 tests resueltos)
- ✅ Cobertura: 144/155 (93%)

### Commit Message

```
fix(l10n_cl_hr_payroll): configure multi-company support

- Validate ir.rules multi-company correct
- Validate company_id fields and defaults
- Resolves 2 tests related to multi-company

Tests Resolved: 2
Coverage: 144/155 (93%)
Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md TASK 2.5
```

---

## 📋 TASK 2.6: CORREGIR TESTS FALLANDO (1h)

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 1 hora

### Contexto

**Errores Identificados:** 13 errores en 4 test suites

**Desglose:**
- `test_ley21735_reforma_pensiones`: 5 errores
- `test_payslip_totals`: 4 errores
- `test_payslip_validations`: 3 errores
- `test_payroll_calculation_p1`: 1 error (ya corregido parcialmente)

### Objetivo

Corregir sistemáticamente los 13 errores para alcanzar 100% de cobertura.

### Tareas Específicas

#### 1. Análisis Sistemático de Errores (20min)

**Agente:** `@test-automation`

**Proceso:**

1. **Ejecutar Tests con Log Detallado:**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=test \
       2>&1 | tee evidencias/sprint2_tests_errors.log
   ```

2. **Categorizar Errores:**
   - **Categoría A:** Setup/Teardown issues (indicadores económicos faltantes)
   - **Categoría B:** Cálculos/Precision issues (diferencias en totales)
   - **Categoría C:** Validaciones/Mensajes issues (contratos superpuestos)
   - **Categoría D:** Otros issues

3. **Generar Reporte de Análisis:**
   ```markdown
   # Análisis de Errores - SPRINT 2
   
   ## Categoría A: Setup Issues (5 errores)
   - test_ley21735_reforma_pensiones: Indicadores económicos faltantes
   - Solución: Agregar indicadores en setUp() o setUpClass()
   
   ## Categoría B: Cálculos (4 errores)
   - test_payslip_totals: Diferencias en precision/rounding
   - Solución: Ajustar precision o usar Decimal para cálculos
   
   ## Categoría C: Validaciones (3 errores)
   - test_payslip_validations: Contratos superpuestos / Mensajes
   - Solución: Ajustar validaciones o mensajes esperados
   
   ## Categoría D: Otros (1 error)
   - test_payroll_calculation_p1: Campo 'period' ya corregido
   - Solución: Validar que corrección funciona
   ```

**Evidencia Requerida:**
- Log completo de errores
- Reporte de análisis categorizado
- Plan de corrección por categoría

#### 2. Corregir Categoría A: Setup Issues (15min)

**Agente:** `@odoo-dev` con soporte `@test-automation`

**Archivos a Modificar:**
- `tests/test_ley21735_reforma_pensiones.py`

**Correcciones Requeridas:**

1. **Agregar Indicadores Económicos en setUp:**
   ```python
   def setUp(self):
       super().setUp()
       
       # Crear indicadores económicos si no existen
       self.indicadores = self.env['hr.economic.indicators'].create({
           'period': date(2025, 8, 1),  # Vigencia Ley 21.735
           'uf': 37500.00,
           'utm': 65000.00,
           'uta': 780000.00,
           'minimum_wage': 500000.00
       })
   ```

2. **Validar que Tests Usan Indicadores:**
   - Verificar que todos los tests asignan `indicadores_id` a payslip
   - Validar que los tests pasan con indicadores

**Evidencia Requerida:**
- Archivo de test modificado
- Tests pasando (5 tests resueltos)

#### 3. Corregir Categoría B: Cálculos (15min)

**Agente:** `@odoo-dev` con soporte `@test-automation`

**Archivos a Modificar:**
- `tests/test_payslip_totals.py`
- `models/hr_payslip.py` (si necesario)

**Correcciones Requeridas:**

1. **Analizar Diferencias en Cálculos:**
   - Identificar qué totales están fallando
   - Verificar precision/rounding issues

2. **Ajustar Precision o Cálculos:**
   ```python
   # Si es issue de precision:
   from decimal import Decimal
   total = Decimal(str(amount1)) + Decimal(str(amount2))
   
   # Si es issue de rounding:
   total = round(amount1 + amount2, 2)
   ```

**Evidencia Requerida:**
- Archivos modificados
- Tests pasando (4 tests resueltos)

#### 4. Corregir Categoría C: Validaciones (10min)

**Agente:** `@odoo-dev` con soporte `@test-automation`

**Archivos a Modificar:**
- `tests/test_payslip_validations.py`
- `models/hr_payslip.py` (si necesario)

**Correcciones Requeridas:**

1. **Analizar Mensajes de Error:**
   - Identificar qué mensajes están fallando
   - Verificar si son contratos superpuestos o mensajes incorrectos

2. **Ajustar Validaciones o Mensajes:**
   - Corregir lógica de validación si es necesario
   - Ajustar mensajes esperados en tests

**Evidencia Requerida:**
- Archivos modificados
- Tests pasando (3 tests resueltos)

### DoD TASK 2.6

- ✅ Análisis sistemático de errores completado
- ✅ Categoría A corregida (5 tests)
- ✅ Categoría B corregida (4 tests)
- ✅ Categoría C corregida (3 tests)
- ✅ Categoría D validada (1 test)
- ✅ Todos los tests pasando (155/155)
- ✅ Cobertura: 155/155 (100%)

### Commit Message

```
fix(l10n_cl_hr_payroll): resolve 13 failing tests - 100% coverage

- Fix setup issues: Add economic indicators in test_ley21735_reforma_pensiones
- Fix calculation issues: Adjust precision/rounding in test_payslip_totals
- Fix validation issues: Adjust validations/messages in test_payslip_validations
- Fix field issue: Validate 'period' field correction in test_payroll_calculation_p1

Tests Resolved: 13
Coverage: 155/155 (100%)
Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md TASK 2.6
```

---

## 📋 TASK 2.7: VALIDACIÓN FINAL Y DoD (1h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`, `@dte-compliance`  
**Prioridad:** P0 - CRÍTICA  
**Estimación:** 1 hora

### Contexto

**Estado Actual:**
- Cobertura: 155/155 (100%) ✅
- Tests pasando: 155/155 ✅
- Objetivo: Validar DoD completo (5/5 criterios)

### Objetivo

Validar que todos los criterios del DoD se cumplen y generar reportes finales.

### Tareas Específicas

#### 1. Ejecutar Todos los Tests (15min)

**Agente:** `@test-automation`

**Comando:**
```bash
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll \
    --log-level=test \
    2>&1 | tee evidencias/sprint2_tests_final.log
```

**Validaciones:**
- ✅ Todos los tests pasando (155/155)
- ✅ Sin errores en log
- ✅ Sin warnings

#### 2. Generar Reporte de Cobertura (15min)

**Agente:** `@test-automation`

**Comando:**
```bash
# Generar reporte de cobertura
docker-compose run --rm odoo coverage run --source=addons/localization/l10n_cl_hr_payroll \
    -m odoo -c /etc/odoo/odoo.conf -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll

docker-compose run --rm odoo coverage report -m > evidencias/sprint2_coverage_report.txt
docker-compose run --rm odoo coverage xml -o evidencias/sprint2_coverage_report.xml
```

**Validaciones:**
- ✅ Cobertura >= 90%
- ✅ Reporte generado correctamente

#### 3. Validar Instalabilidad (10min)

**Agente:** `@odoo-dev`

**Comando:**
```bash
docker-compose run --rm odoo odoo -d odoo19 \
    -i l10n_cl_hr_payroll \
    --stop-after-init \
    --log-level=error \
    2>&1 | tee evidencias/sprint2_installation.log
```

**Validaciones:**
- ✅ Módulo instalable sin errores
- ✅ Estado: `installed`
- ✅ Sin errores en log

#### 4. Validar Warnings (10min)

**Agente:** `@odoo-dev`

**Comando:**
```bash
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll \
    --log-level=warn \
    2>&1 | grep -i "warning\|deprecated" | tee evidencias/sprint2_warnings.log
```

**Validaciones:**
- ✅ Sin warnings de Odoo 19
- ✅ Sin mensajes deprecated

#### 5. Generar Reporte DoD Completo (10min)

**Agente:** `@odoo-dev` con soporte `@test-automation`

**Archivo:** `evidencias/sprint2_dod_report.md`

**Contenido Requerido:**

```markdown
# 📋 SPRINT 2 - Definition of Done (DoD) Report

**Fecha:** 2025-11-09
**Sprint:** SPRINT 2 - Cierre Total de Brechas
**Módulo:** l10n_cl_hr_payroll
**Versión:** 19.0.1.0.0

## Criterios Obligatorios

| # | Criterio | Estado | Evidencia |
|---|----------|--------|-----------|
| 1 | Tests Pasando (155/155) | ✅ | sprint2_tests_final.log |
| 2 | Cobertura Código (>= 90%) | ✅ | sprint2_coverage_report.xml |
| 3 | Instalabilidad (sin errores) | ✅ | sprint2_installation.log |
| 4 | Sin Warnings Odoo 19 | ✅ | sprint2_warnings.log |
| 5 | DoD Completo (5/5) | ✅ | Este reporte |

**DoD Score:** 5/5 (100%) ✅

## Métricas Finales

- Tests Pasando: 155/155 (100%)
- Cobertura: XX% (>= 90%)
- Warnings: 0
- Errores: 0
- Commits: X commits estructurados

## Tareas Completadas

- ✅ TASK 2.1: compute_sheet() wrapper
- ✅ TASK 2.2: employer_reforma_2025 campo computed
- ✅ TASK 2.3: Migración _sql_constraints
- ✅ TASK 2.4: Validación Previred
- ✅ TASK 2.5: Configuración Multi-Company
- ✅ TASK 2.6: Corrección Tests Fallando
- ✅ TASK 2.7: Validación Final y DoD

## Conclusiones

SPRINT 2 completado exitosamente. Todos los criterios del DoD cumplidos.
100% de cobertura de tests alcanzada.
```

### DoD TASK 2.7

- ✅ Todos los tests pasando (155/155)
- ✅ Cobertura >= 90%
- ✅ Módulo instalable sin errores
- ✅ Sin warnings Odoo 19
- ✅ DoD completo (5/5 criterios)

### Commit Message

```
feat(l10n_cl_hr_payroll): complete SPRINT 2 - 100% test coverage achieved

- All tests passing (155/155)
- Code coverage >= 90%
- Module installable without errors
- Zero Odoo 19 warnings
- DoD complete (5/5 criteria)

Tests: 155/155 (100%)
Coverage: XX% (>= 90%)
Warnings: 0
DoD: 5/5 ✅

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md SPRINT 2
```

---

## 🚨 PROTOCOLO DE EJECUCIÓN

### Paso a Paso

1. **Validar Estado Actual:**
   ```bash
   # Verificar branch
   git branch --show-current  # Debe ser: feat/cierre_total_brechas_profesional
   
   # Verificar commits anteriores
   git log --oneline -5
   # Debe mostrar: 9fa6b5d7, a542ab88, c48b7e70
   ```

2. **Ejecutar TASK 2.5:** Configurar Multi-Company
   - Agente: `@odoo-dev` con soporte `@test-automation`
   - Duración: 1 hora
   - Objetivo: +2 tests → 144/155 (93%)

3. **Ejecutar TASK 2.6:** Corregir Tests Fallando
   - Agente: `@test-automation` con soporte `@odoo-dev`
   - Duración: 1 hora
   - Objetivo: +13 tests → 155/155 (100%)

4. **Ejecutar TASK 2.7:** Validación Final y DoD
   - Agente: `@odoo-dev` con soporte `@test-automation`, `@dte-compliance`
   - Duración: 1 hora
   - Objetivo: Validación completa y DoD

**Después de cada TASK:**
- Ejecutar tests relacionados
- Validar cobertura
- Generar commit estructurado
- Reportar progreso

---

## 📊 PROYECCIÓN FINAL

### Cobertura Esperada

| Fase | Tests | Cobertura | Tiempo |
|------|-------|-----------|--------|
| **Actual** | 142/155 | 92% | 4.5h |
| **Tras TASK 2.5** | 144/155 | 93% | +1h |
| **Tras TASK 2.6** | 155/155 | 100% | +1h |
| **Final (TASK 2.7)** | 155/155 | 100% | +1h |

**Total Restante:** 3 horas

---

## 🎯 EJEMPLOS DE INVOCACIÓN

### Invocación para TASK 2.5

```
@odoo-dev ejecuta TASK 2.5 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md

Contexto:
- Branch: feat/cierre_total_brechas_profesional
- Progreso: 63% completado (4.5h de 7.5h)
- Cobertura actual: 92% (142/155 tests)
- Commits anteriores: 9fa6b5d7, a542ab88, c48b7e70

Tarea:
- Validar ir.rules multi-company
- Validar configuración company_id en modelos
- Ejecutar tests multi-company

Knowledge Base:
- .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md
- .codex/ANALISIS_PROFUNDO_LOG_AGENTE_SPRINT2.md

DoD:
- ir.rules configuradas correctamente
- 2 tests pasando
- Cobertura: 144/155 (93%)

Soporte:
- @test-automation para validación tests
```

### Invocación para TASK 2.6

```
@test-automation ejecuta TASK 2.6 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md

Contexto:
- Branch: feat/cierre_total_brechas_profesional
- Progreso: 73% completado (5.5h de 7.5h)
- Cobertura actual: 93% (144/155 tests)
- Errores identificados: 13 errores en 4 test suites

Tarea:
- Análisis sistemático de 13 errores
- Corregir Categoría A: Setup issues (5 tests)
- Corregir Categoría B: Cálculos (4 tests)
- Corregir Categoría C: Validaciones (3 tests)
- Validar Categoría D: Otros (1 test)

Knowledge Base:
- .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md
- evidencias/sprint2_tests_errors.log

DoD:
- Todos los tests pasando (155/155)
- Cobertura: 155/155 (100%)

Soporte:
- @odoo-dev para correcciones de código
```

### Invocación para TASK 2.7

```
@odoo-dev ejecuta TASK 2.7 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md

Contexto:
- Branch: feat/cierre_total_brechas_profesional
- Progreso: 87% completado (6.5h de 7.5h)
- Cobertura actual: 100% (155/155 tests)
- Objetivo: Validación final y DoD completo

Tarea:
- Ejecutar todos los tests (155/155)
- Generar reporte de cobertura
- Validar instalabilidad
- Validar warnings
- Generar reporte DoD completo

Knowledge Base:
- .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4_2.md

DoD:
- Todos los criterios cumplidos (5/5)
- Reportes generados
- SPRINT 2 completado

Soporte:
- @test-automation para ejecución tests y cobertura
- @dte-compliance para validación compliance legal
```

---

## ✅ CONCLUSIÓN

**Estado:** READY FOR EXECUTION

**Progreso Actual:** 63% completado (92% cobertura)

**Tareas Pendientes:** 3 tareas (3 horas)

**Objetivo Final:** 100% cobertura (155/155 tests) + DoD completo

**Riesgo:** 🟢 BAJO - On track para 100%

**Orquestación:** Sub-agentes especializados asignados por tarea

---

**FIN DEL PROMPT MASTER V4.2**

