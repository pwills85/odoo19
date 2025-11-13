# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS V4
## Análisis Validado | Estimaciones Corregidas | Quick Wins Identificados

**Versión:** 4.0  
**Fecha:** 2025-11-09  
**Estado:** READY FOR EXECUTION  
**Base:** Análisis Profundo SPRINT 1 Ejecución + Validación Crítica  
**Esfuerzo Estimado:** 7.5 horas (~1 día) vs 32h originales  
**Cobertura Objetivo:** 155/155 tests (100%)

---

## 📊 RESUMEN EJECUTIVO

### Estado Actual Validado

**SPRINT 1 Completado:** 98% (4/5 DoD criteria) ✅

**Módulo:** `l10n_cl_hr_payroll`
- **Estado:** `installed` ✅
- **Versión:** `19.0.1.0.0`
- **Tests Actuales:** 96/155 pasando (62%)

**Hallazgos Críticos Validados:**

| Hallazgo | Prioridad | Estimación Original | Estimación Corregida | Tests Afectados |
|----------|-----------|-------------------|---------------------|----------------|
| `compute_sheet()` naming | P1 | 16h (P0) | **30min** ⚡ | 15 tests |
| `employer_reforma_2025` campo | P1 | 4h | **1h** ⚡ | 24 tests |
| `_sql_constraints` deprecated | P1 | 2h | **2h** ✅ | 6 tests |
| Previred integration | P1 | 3h | **1h** | 10 tests |
| Multi-company | P2 | 2h | **1h** | 2 tests |
| Vista search | P2 | 4h | **1h** (defer) | - |

**Total Esfuerzo:** 7.5 horas (~1 día) vs 32h originales

**Quick Wins Identificados:**
- ⚡ Fix 1: `compute_sheet()` wrapper → Resuelve 15 tests (30min)
- ⚡ Fix 2: Campo `employer_reforma_2025` → Resuelve 24 tests (1h)
- **Total Quick Wins:** 39 tests resueltos en 1.5 horas (25% del total)

---

## 🎯 OBJETIVOS DEL CIERRE TOTAL

### Objetivo General

Cerrar todas las brechas identificadas en SPRINT 1 para alcanzar **100% de cobertura de tests** (155/155) y **cumplimiento total de DoD** (5/5 criterios).

### Objetivos Específicos

**OBJ-1:** Resolver naming issue `compute_sheet()` → 15 tests  
**OBJ-2:** Agregar campo computed `employer_reforma_2025` → 24 tests  
**OBJ-3:** Migrar `_sql_constraints` a `@api.constrains` → 6 tests + 9 warnings  
**OBJ-4:** Validar integración Previred → 10 tests  
**OBJ-5:** Configurar multi-company → 2 tests  
**OBJ-6:** Investigar vista search (si crítico) → Defer si no crítico  
**OBJ-7:** Alcanzar 100% cobertura tests (155/155)  
**OBJ-8:** Cumplir DoD completo (5/5 criterios)  
**OBJ-9:** Eliminar todos los warnings de Odoo 19  
**OBJ-10:** Validar instalabilidad sin errores

---

## 👥 ORQUESTACIÓN DE AGENTES ESPECIALIZADOS

### Equipo de Agentes Disponibles

| Agente | Modelo | Especialización | Tools | Config File |
|--------|--------|-----------------|-------|-------------|
| `@odoo-dev` | o1-mini | Desarrollo Odoo 19 CE, localización chilena | Code, Search, Read | `.claude/agents/odoo-dev.md` |
| `@dte-compliance` | o1-mini | Cumplimiento SII, validación DTE | Read-only, Validation | `.claude/agents/dte-compliance.md` |
| `@test-automation` | o1-mini | Testing automatizado, CI/CD | Code, Test, Coverage | `.claude/agents/test-automation.md` |
| `@docker-devops` | o1-mini | Docker, despliegues producción | Docker, CI/CD | `.claude/agents/docker-devops.md` |
| `@ai-fastapi-dev` | o1-mini | Microservicios AI, FastAPI | Code, API | `.claude/agents/ai-fastapi-dev.md` |

### Base de Conocimiento Compartida

**Archivos Críticos (CONSULTAR ANTES DE EJECUTAR):**

1. `.claude/agents/knowledge/sii_regulatory_context.md`
   - Contexto regulatorio SII
   - Validaciones DTE
   - Ley 21.735 (Reforma Pensiones 2025)

2. `.claude/agents/knowledge/odoo19_patterns.md`
   - Patrones Odoo 19 CE
   - Pure Python `libs/` pattern
   - `@api.constrains` vs `_sql_constraints`

3. `.claude/agents/knowledge/project_architecture.md`
   - Arquitectura EERGYGROUP
   - Decisiones arquitectónicas
   - Módulos y dependencias

4. `.codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md`
   - Hallazgos consolidados
   - Soluciones propuestas
   - Priorización

5. `.codex/ANALISIS_PROFUNDO_LOG_AGENTE_SPRINT1_EJECUCION.md`
   - Análisis validado de SPRINT 1
   - Correcciones de estimaciones
   - Quick wins identificados

**⚠️ OBLIGATORIO:** Consultar estos archivos ANTES de ejecutar cualquier tarea.

---

### Asignación de Agentes por Sprint

```yaml
SPRINT_2_QUICK_FIXES:
  primary: "@odoo-dev"
  support: ["@test-automation"]
  duration: "1.5 horas"
  tasks:
    - compute_sheet wrapper
    - employer_reforma_2025 campo computed

SPRINT_2_MIGRATION:
  primary: "@odoo-dev"
  support: ["@test-automation"]
  duration: "2 horas"
  tasks:
    - _sql_constraints migration

SPRINT_2_VALIDATION:
  primary: "@odoo-dev"
  support: ["@test-automation", "@dte-compliance"]
  duration: "2 horas"
  tasks:
    - Previred integration validation
    - Multi-company configuration

SPRINT_2_FINAL:
  primary: "@odoo-dev"
  support: ["@test-automation"]
  duration: "2 horas"
  tasks:
    - Vista search investigation (si crítico)
    - Final validation
    - DoD verification
```

---

### Protocolo de Coordinación

**Roles:**

1. **Senior Engineer (Coordinador):**
   - Valida hallazgos antes de ejecución
   - Revisa estimaciones y prioridades
   - Aprueba cambios críticos
   - Valida DoD final

2. **Agente Principal (`@odoo-dev`):**
   - Ejecuta tareas de desarrollo
   - Coordina con agentes de soporte
   - Genera evidencias estructuradas
   - Reporta progreso al coordinador

3. **Agentes de Soporte:**
   - `@test-automation`: Ejecuta tests, valida cobertura
   - `@dte-compliance`: Valida compliance legal (read-only)
   - `@docker-devops`: Valida despliegue (si aplica)

**Handoff Entre Agentes:**

1. Agente principal completa tarea
2. Genera evidencia estructurada
3. Solicita validación a agente de soporte
4. Agente de soporte valida y reporta
5. Coordinador aprueba y autoriza siguiente tarea

---

## 📋 ESTRUCTURA DE SPRINT 2

### SPRINT 2: Cierre Total de Brechas (7.5 horas)

**Objetivo:** Resolver todas las brechas identificadas para alcanzar 100% cobertura.

**Timeline:**
- **Día 1 (4.5h):** Quick fixes + Migration → 91% coverage
- **Día 2 (3h):** Validation + Final → 100% coverage

---

### TASK 2.1: Quick Fix - compute_sheet() Wrapper (30min) ⚡

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P1 - Quick Win  
**Estimación:** 30 minutos

**Problema Identificado:**
- Tests llaman a `payslip.compute_sheet()` pero método es `action_compute_sheet()`
- Método `action_compute_sheet()` existe y está completo (línea 658)
- Naming issue, NO bloqueador crítico

**Solución:**

**Archivo:** `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`

**Agregar después de `action_compute_sheet()` (línea 706):**

```python
def compute_sheet(self):
    """
    Wrapper para compatibilidad con tests y estándares Odoo
    
    En Odoo estándar, compute_sheet() es el método principal.
    action_compute_sheet() es el método de acción desde UI.
    Este wrapper permite ambos usos.
    
    Returns:
        bool: True si cálculo exitoso
    """
    return self.action_compute_sheet()
```

**Tests a Validar:**
- `test_ley21735_reforma_pensiones.py` (8 tests)
- `test_apv_calculation.py` (3 tests)
- `test_payroll_calculation_p1.py` (2 tests)
- `test_lre_generation.py` (2 tests)

**DoD TASK 2.1:**
- ✅ Método `compute_sheet()` agregado
- ✅ Tests pasando (15 tests resueltos)
- ✅ Sin errores en log
- ✅ Cobertura: 111/155 (72%)

**Evidencia Requerida:**
- Log de ejecución tests
- Captura de cobertura actualizada
- Commit con mensaje estructurado

**Commit Message:**
```
fix(l10n_cl_hr_payroll): add compute_sheet() wrapper for test compatibility

- Add wrapper method compute_sheet() that calls action_compute_sheet()
- Resolves naming issue: tests call compute_sheet() but method is action_compute_sheet()
- Quick fix: 30 minutes, resolves 15 tests

Tests Resolved: 15
Coverage: 111/155 (72%)
Ref: .codex/ANALISIS_PROFUNDO_LOG_AGENTE_SPRINT1_EJECUCION.md
```

---

### TASK 2.2: Quick Fix - Campo employer_reforma_2025 (1h) ⚡

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`, `@dte-compliance`  
**Prioridad:** P1 - Quick Win  
**Estimación:** 1 hora

**Problema Identificado:**
- Campo `employer_reforma_2025` se usa en código pero NO está definido
- Campos base existen: `employer_cuenta_individual_ley21735`, `employer_seguro_social_ley21735`
- Campo total existe: `employer_total_ley21735`
- Falta campo alias `employer_reforma_2025` para compatibilidad

**Evidencia de Uso:**
- Línea 570: `if not payslip.employer_reforma_2025`
- Línea 1794: `if not self.employer_reforma_2025`
- Línea 1875: `empleador_reforma = int(self.employer_reforma_2025)`

**Solución:**

**Archivo:** `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`

**Agregar después de `employer_total_ley21735` (línea 250):**

```python
# Campo alias para compatibilidad con tests y código existente
employer_reforma_2025 = fields.Monetary(
    string='Aporte Empleador Reforma 2025',
    compute='_compute_employer_reforma_2025_alias',
    store=True,
    currency_field='currency_id',
    readonly=True,
    help='Alias para employer_total_ley21735 - Compatibilidad con tests y código existente. '
         'Ley 21.735 Art. 2° - Total aporte empleador (0.1% + 0.9% = 1%). '
         'Vigencia: Desde 01-08-2025'
)

@api.depends('employer_total_ley21735')
def _compute_employer_reforma_2025_alias(self):
    """
    Alias computed field para compatibilidad con tests y código existente
    
    Mapea employer_total_ley21735 a employer_reforma_2025 para mantener
    compatibilidad con código que usa el nombre corto.
    """
    for payslip in self:
        payslip.employer_reforma_2025 = payslip.employer_total_ley21735
```

**Tests a Validar:**
- `test_ley21735_reforma_pensiones.py` (10 tests)
- `test_previred_integration.py` (9 tests relacionados)
- `test_payslip_validations.py` (5 tests)

**DoD TASK 2.2:**
- ✅ Campo `employer_reforma_2025` agregado
- ✅ Método `_compute_employer_reforma_2025_alias()` implementado
- ✅ Tests pasando (24 tests resueltos)
- ✅ Código existente funciona correctamente
- ✅ Cobertura: 135/155 (87%)

**Evidencia Requerida:**
- Log de ejecución tests
- Validación de código existente (líneas 570, 1794, 1875)
- Captura de cobertura actualizada
- Commit con mensaje estructurado

**Commit Message:**
```
fix(l10n_cl_hr_payroll): add employer_reforma_2025 computed field alias

- Add computed field employer_reforma_2025 as alias for employer_total_ley21735
- Resolves compatibility issue: field used in code but not defined
- Quick fix: 1 hour, resolves 24 tests

Tests Resolved: 24
Coverage: 135/155 (87%)
Ref: .codex/ANALISIS_PROFUNDO_LOG_AGENTE_SPRINT1_EJECUCION.md
```

---

### TASK 2.3: Migrar _sql_constraints a @api.constrains (2h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P1  
**Estimación:** 2 horas

**Problema Identificado:**
- `_sql_constraints` deprecado desde Odoo 17
- 9 warnings en log
- 1 test fallando por constraint
- Requiere migración a `@api.constrains`

**Archivos a Auditar:**

```bash
# Buscar todos los _sql_constraints en el módulo
grep -r "_sql_constraints" addons/localization/l10n_cl_hr_payroll/models/
```

**Archivos Probables:**
- `models/hr_economic_indicators.py` (confirmado en análisis)
- Otros modelos con constraints

**Solución:**

**ANTES (Odoo 17 y anteriores):**
```python
_sql_constraints = [
    ('unique_code', 'UNIQUE(code)', 'El código debe ser único'),
    ('check_amount', 'CHECK(amount > 0)', 'El monto debe ser mayor a 0'),
]
```

**DESPUÉS (Odoo 19 CE):**
```python
@api.constrains('code')
def _check_unique_code(self):
    """Validar que el código sea único"""
    for record in self:
        if self.search_count([('code', '=', record.code), ('id', '!=', record.id)]):
            raise ValidationError(_('El código debe ser único'))

@api.constrains('amount')
def _check_amount(self):
    """Validar que el monto sea mayor a 0"""
    for record in self:
        if record.amount <= 0:
            raise ValidationError(_('El monto debe ser mayor a 0'))
```

**DoD TASK 2.3:**
- ✅ Todos los `_sql_constraints` migrados a `@api.constrains`
- ✅ Tests pasando (6 tests resueltos)
- ✅ Sin warnings en log
- ✅ Cobertura: 141/155 (91%)

**Evidencia Requerida:**
- Lista de archivos modificados
- Log sin warnings
- Tests pasando
- Commit con mensaje estructurado

**Commit Message:**
```
refactor(l10n_cl_hr_payroll): migrate _sql_constraints to @api.constrains

- Migrate all _sql_constraints to @api.constrains decorators (Odoo 19 CE)
- Remove deprecated _sql_constraints pattern
- Resolves 9 warnings + 1 test failing

Tests Resolved: 6
Coverage: 141/155 (91%)
Ref: .claude/agents/knowledge/odoo19_patterns.md
```

---

### TASK 2.4: Validar Integración Previred (1h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`, `@dte-compliance`  
**Prioridad:** P1  
**Estimación:** 1 hora

**Problema Identificado:**
- 10 tests fallando relacionados con Previred
- Depende de campo `employer_reforma_2025` (TASK 2.2)
- Depende de método `compute_sheet()` (TASK 2.1)

**Validaciones Requeridas:**

1. **Validar Exportación Previred:**
   - Archivo 105 campos generado correctamente
   - Campo `employer_reforma_2025` incluido
   - Formato válido según especificación Previred

2. **Validar Validaciones Previred:**
   - Bloquea sin AFP configurado
   - Bloquea sin indicadores económicos
   - Bloquea sin Reforma 2025 calculada
   - Bloquea sin RUT trabajador

**Tests a Validar:**
- `test_previred_integration.py` (10 tests)

**DoD TASK 2.4:**
- ✅ Exportación Previred funcionando
- ✅ Validaciones Previred funcionando
- ✅ Tests pasando (10 tests resueltos)
- ✅ Cobertura: 151/155 (97%)

**Evidencia Requerida:**
- Log de ejecución tests
- Ejemplo de archivo Previred generado
- Captura de cobertura actualizada
- Commit con mensaje estructurado

**Commit Message:**
```
fix(l10n_cl_hr_payroll): validate Previred integration

- Validate Previred export includes employer_reforma_2025 field
- Validate Previred validations block correctly
- Resolves 10 tests (depends on TASK 2.1 and TASK 2.2)

Tests Resolved: 10
Coverage: 151/155 (97%)
Ref: .claude/agents/knowledge/sii_regulatory_context.md
```

---

### TASK 2.5: Configurar Multi-Company (1h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P2  
**Estimación:** 1 hora

**Problema Identificado:**
- 2 tests fallando relacionados con multi-company
- Configuración multi-company puede requerir ajustes

**Validaciones Requeridas:**

1. **Validar ir.rules:**
   - Reglas multi-company correctas
   - Acceso restringido por compañía

2. **Validar Configuración:**
   - Campos `company_id` presentes
   - Defaults correctos

**Tests a Validar:**
- Tests multi-company (2 tests)

**DoD TASK 2.5:**
- ✅ Multi-company configurado correctamente
- ✅ Tests pasando (2 tests resueltos)
- ✅ Cobertura: 153/155 (99%)

**Evidencia Requerida:**
- Log de ejecución tests
- Validación de ir.rules
- Commit con mensaje estructurado

---

### TASK 2.6: Investigar Vista Search (1h - Opcional)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P2 - Defer si no crítico  
**Estimación:** 1 hora

**Problema Identificado:**
- Vista search `hr.payslip` bloqueada en SPRINT 1
- RNG validation falla con sintaxis Odoo 19 correcta
- No crítico para funcionalidad core

**Decisión:**
- Si no crítico para tests → Defer a SPRINT 3
- Si crítico → Investigar y corregir

**DoD TASK 2.6:**
- ✅ Decisión tomada (defer o corregir)
- ✅ Si corregido: Tests pasando
- ✅ Cobertura: 155/155 (100%) si corregido

---

### TASK 2.7: Validación Final y DoD (1h)

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P0 - Crítico  
**Estimación:** 1 hora

**Validaciones Requeridas:**

1. **Ejecutar Todos los Tests:**
   ```bash
   docker exec odoo19_app odoo \
       -c /etc/odoo/odoo.conf \
       -d odoo19 \
       --test-enable \
       --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=test
   ```

2. **Validar Cobertura:**
   - Objetivo: 155/155 tests pasando (100%)
   - Verificar cobertura de código >= 90%

3. **Validar Instalabilidad:**
   ```bash
   docker exec odoo19_app odoo \
       -c /etc/odoo/odoo.conf \
       -d odoo19 \
       -i l10n_cl_hr_payroll \
       --stop-after-init \
       --log-level=error
   ```

4. **Validar Warnings:**
   - Sin warnings de Odoo 19
   - Sin errores en log

5. **Validar DoD:**
   - 5/5 criterios cumplidos

**DoD TASK 2.7:**
- ✅ Todos los tests pasando (155/155)
- ✅ Cobertura >= 90%
- ✅ Módulo instalable sin errores
- ✅ Sin warnings
- ✅ DoD completo (5/5 criterios)

**Evidencia Requerida:**
- Log completo de tests
- Reporte de cobertura
- Log de instalación
- Reporte DoD completo

---

## 📋 DEFINITION OF DONE (DoD) - SPRINT 2

### Criterios Obligatorios

| # | Criterio | Descripción | Validación |
|---|----------|-------------|------------|
| **1** | Tests Pasando | 155/155 tests pasando (100%) | Log de tests |
| **2** | Cobertura Código | >= 90% cobertura | Reporte cobertura |
| **3** | Instalabilidad | Módulo instalable sin errores | Log instalación |
| **4** | Sin Warnings | Sin warnings Odoo 19 | Log sin warnings |
| **5** | DoD Completo | 5/5 criterios cumplidos | Reporte DoD |

**DoD SPRINT 2:** 5/5 criterios deben cumplirse

---

## 🚨 PROTOCOLO DE EJECUCIÓN

### Paso a Paso

1. **Validar Pre-requisitos:**
   ```bash
   # Verificar branch correcto
   git branch --show-current  # Debe ser: feat/cierre_total_brechas_profesional
   
   # Verificar módulo instalado
   docker exec odoo19_app odoo shell -d odoo19 -c "self.env['ir.module.module'].search([('name', '=', 'l10n_cl_hr_payroll')]).state"
   # Debe retornar: 'installed'
   ```

2. **Ejecutar TASK 2.1:** Quick Fix compute_sheet() wrapper
3. **Ejecutar TASK 2.2:** Quick Fix employer_reforma_2025 campo
4. **Ejecutar TASK 2.3:** Migrar _sql_constraints
5. **Ejecutar TASK 2.4:** Validar Previred
6. **Ejecutar TASK 2.5:** Configurar Multi-company
7. **Ejecutar TASK 2.6:** Investigar Vista Search (opcional)
8. **Ejecutar TASK 2.7:** Validación Final y DoD

**Después de cada TASK:**
- Ejecutar tests relacionados
- Validar cobertura
- Generar commit estructurado
- Reportar progreso al coordinador

---

## 📊 MÉTRICAS Y SEGUIMIENTO

### Proyección de Cobertura

| Fase | Tests Resueltos | Cobertura | Tiempo |
|------|-----------------|-----------|--------|
| **Inicial** | 96/155 | 62% | - |
| **TASK 2.1** | +15 tests | 72% | 30min |
| **TASK 2.2** | +24 tests | 87% | 1h |
| **TASK 2.3** | +6 tests | 91% | 2h |
| **TASK 2.4** | +10 tests | 97% | 1h |
| **TASK 2.5** | +2 tests | 99% | 1h |
| **TASK 2.6** | +2 tests (si crítico) | 100% | 1h |
| **TASK 2.7** | Validación | 100% | 1h |

**Total:** 7.5 horas (~1 día)

---

## 🎯 EJEMPLOS DE INVOCACIÓN

### Invocación para TASK 2.1

```
@odoo-dev ejecuta TASK 2.1 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4.md

Contexto:
- Branch: feat/cierre_total_brechas_profesional
- Módulo: l10n_cl_hr_payroll (installed)
- Tests actuales: 96/155 (62%)

Tarea:
- Agregar método wrapper compute_sheet() en hr_payslip.py
- Validar con @test-automation
- Generar commit estructurado

Knowledge Base:
- .codex/ANALISIS_PROFUNDO_LOG_AGENTE_SPRINT1_EJECUCION.md
- .claude/agents/knowledge/odoo19_patterns.md

DoD:
- Método agregado
- 15 tests pasando
- Cobertura: 111/155 (72%)

Soporte:
- @test-automation para validación tests
```

### Invocación para TASK 2.2

```
@odoo-dev ejecuta TASK 2.2 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V4.md

Contexto:
- Branch: feat/cierre_total_brechas_profesional
- Módulo: l10n_cl_hr_payroll (installed)
- Tests actuales: 111/155 (72%) - después de TASK 2.1

Tarea:
- Agregar campo computed employer_reforma_2025 en hr_payslip.py
- Validar con @test-automation y @dte-compliance
- Generar commit estructurado

Knowledge Base:
- .codex/ANALISIS_PROFUNDO_LOG_AGENTE_SPRINT1_EJECUCION.md
- .claude/agents/knowledge/sii_regulatory_context.md

DoD:
- Campo agregado
- 24 tests pasando
- Cobertura: 135/155 (87%)

Soporte:
- @test-automation para validación tests
- @dte-compliance para validación compliance legal
```

---

## 🚨 MANEJO DE ERRORES

### Si Tests Fallan

1. **Analizar error específico:**
   - Revisar log detallado
   - Identificar causa raíz
   - Consultar knowledge base

2. **Corregir y re-validar:**
   - Aplicar corrección
   - Ejecutar tests nuevamente
   - Validar cobertura

3. **Si error persiste:**
   - Documentar error
   - Reportar al coordinador
   - Solicitar soporte de agentes especializados

### Si Instalación Falla

1. **Verificar dependencias:**
   ```bash
   docker exec odoo19_app odoo shell -d odoo19 -c "self.env['ir.module.module'].search([('name', 'in', ['base', 'hr', 'account', 'l10n_cl'])]).mapped('state')"
   ```

2. **Verificar sintaxis:**
   ```bash
   python3 -m py_compile addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
   ```

3. **Si error persiste:**
   - Documentar error
   - Reportar al coordinador
   - Revisar logs detallados

---

## 📦 ENTREGABLES FINALES

### Archivos de Código

1. `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`
   - Método `compute_sheet()` agregado
   - Campo `employer_reforma_2025` agregado
   - Métodos `_compute_employer_reforma_2025_alias()` agregado

2. Otros archivos modificados según TASKs

### Evidencias

1. `evidencias/sprint2_tests_final.log` - Log completo de tests
2. `evidencias/sprint2_coverage_report.xml` - Reporte de cobertura
3. `evidencias/sprint2_dod_report.md` - Reporte DoD completo

### Commits

1. Commit TASK 2.1: compute_sheet() wrapper
2. Commit TASK 2.2: employer_reforma_2025 campo
3. Commit TASK 2.3: _sql_constraints migration
4. Commit TASK 2.4: Previred validation
5. Commit TASK 2.5: Multi-company configuration
6. Commit TASK 2.6: Vista search (si aplica)
7. Commit TASK 2.7: Final validation

---

## ✅ CONCLUSIÓN

**Estado:** READY FOR EXECUTION

**Quick Wins Identificados:**
- ⚡ TASK 2.1: 30min → 15 tests resueltos
- ⚡ TASK 2.2: 1h → 24 tests resueltos
- **Total Quick Wins:** 39 tests en 1.5 horas

**Esfuerzo Total:** 7.5 horas (~1 día)

**Cobertura Objetivo:** 155/155 tests (100%)

**DoD Objetivo:** 5/5 criterios cumplidos

---

**FIN DEL PROMPT MASTER V4**

