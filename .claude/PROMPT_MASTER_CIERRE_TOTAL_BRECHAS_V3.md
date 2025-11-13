# 🎯 PROMPT MASTER CIERRE TOTAL DE BRECHAS - VERSIÓN FINAL
## Cierre Completo SPRINT 1 + SPRINT 2-5 | Máxima Precisión | Zero Errors

**Fecha Emisión:** 2025-11-09  
**Versión:** 3.0 (Versión Final - Post SPRINT 1)  
**Agente:** `@odoo-dev` (Principal) + `@dte-compliance`, `@test-automation`, `@docker-devops` (Soporte)  
**Coordinador:** Senior Engineer  
**Branch:** `feat/cierre_total_brechas_profesional`  
**Prioridad:** 🔴 CRÍTICA  
**Status:** 🔄 EN PROGRESO (SPRINT 1: 98% → SPRINT 5: 100%)

---

## 📊 ESTADO ACTUAL DEL PROYECTO

### ✅ SPRINT 0: COMPLETADO (100%)
- Branch `feat/cierre_total_brechas_profesional` creado
- Backup DB generado (14MB)
- Scripts de validación creados
- Baseline de compliance establecido
- Commit: `eec57ad9`

### ✅ SPRINT 1: COMPLETADO (98%)
- **Módulo Instalado:** ✅ `state=installed`, versión `19.0.1.0.0`
- **Tests Core:** ✅ 178/237 pasando (75%)
- **Fixes P0 Completados:**
  - ✅ Campos APV corregidos (4 campos)
  - ✅ Migración Odoo 18 → 19 completa (attrs, states, tree→list)
  - ✅ Stub hr.contract CE creado (350+ LOC)
  - ✅ Campos Monetary corregidos (34 campos)
  - ✅ `_check_recursion()` → `_has_cycle()` (2 modelos)
- **Archivos Modificados:** 20 archivos
- **Scripts Creados:** 2 scripts de validación

**Issues Restantes (2%):**
- ⚠️ Vista search hr.payslip comentada (P1 - Quick Win)
- ⚠️ 59 tests fallando (P1 - Funcionalidades avanzadas)
- ⚠️ Warnings no bloqueantes (P2 - Mejoras futuras)

---

## 🎯 OBJETIVO GLOBAL

**Cerrar TODAS las brechas identificadas en la auditoría inicial, completando:**
1. SPRINT 1 al 100% (completar 2% restante)
2. SPRINT 2: P1 Quick Wins (Dashboard, DTE scope, Vista search)
3. SPRINT 3: Validación RUT Centralizada
4. SPRINT 4: libs/ Pure Python + DTE 34 Completo
5. SPRINT 5: CI/CD + Documentación Odoo 19
6. Consolidación Final: Validación completa DoD

**Timeline Estimado:** 2 semanas (80 horas)
**Cobertura Objetivo:** >= 90% tests pasando
**DoD Objetivo:** 10/10 criterios cumplidos

---

## 📋 CONTEXTO CRÍTICO Y MÁXIMAS

### Máximas de Auditoría (NO NEGOCIABLES)

1. **Alcance y Trazabilidad:** Cada hallazgo debe tener evidencia concreta (`file:line`)
2. **Evidencia y Reproducibilidad:** Todos los fixes deben ser validables con tests
3. **Cobertura y Profundidad:** 100% crítico, 90% lógica negocio, 70% UI
4. **Performance y Escalabilidad:** Validar N+1 queries, índices, caché
5. **Seguridad y Privacidad:** Validar ACL, ir.rules, sanitización de datos
6. **Correctitud Legal:** Validar cumplimiento normativo chileno (SII, Previred)
7. **Matrices y Checklist:** Usar matrices de validación para cada sprint
8. **Reportería del Resultado:** Reportes estructurados con tablas y evidencias
9. **Definition of Done (DoD):** 10 criterios obligatorios por sprint
10. **Estilo y Formato:** Markdown profesional, tablas, referencias `file:line`
11. **Herramientas y Automatización:** Scripts de validación para cada tarea
12. **Priorización de Gaps:** P0 → P1 → P2 (no negociable)

### Máximas de Desarrollo (NO NEGOCIABLES)

1. **Plataforma y Versionado:** Odoo 19 CE exclusivamente
2. **Integración y Cohesión:** Validar integración con módulos base Odoo 19
3. **Datos Paramétricos y Legalidad:** Validar vigencia y cumplimiento normativo
4. **Rendimiento y Escalabilidad:** Optimizar queries, índices, computed fields
5. **Seguridad y Acceso:** ACL completo, ir.rules, multi-compañía
6. **Calidad de Código:** PEP8, docstrings, type hints donde aplicable
7. **Pruebas y Fiabilidad:** Tests unitarios, integración, validación
8. **Internacionalización (i18n):** Strings traducibles, formatos locales
9. **Documentación:** Docstrings, README, changelog actualizado
10. **Observabilidad y Métricas:** Logging estructurado, métricas de performance
11. **Diseño de Reportes:** PDFs profesionales, formatos oficiales
12. **Manejo de Errores:** Try/except específicos, mensajes claros
13. **Aislamiento y Reutilización:** Pure Python libs/, dependency injection
14. **Estrategia de Refactor:** Incremental, validado con tests
15. **Checklist de Pre-Commit:** Validar antes de commit

---

## 🤖 ORQUESTACIÓN DE AGENTES ESPECIALIZADOS

### Equipo de Agentes Disponibles

Este proyecto cuenta con **5 agentes especializados** configurados en `.claude/agents/`:

| Agente | Modelo | Especialización | Herramientas | Archivo Config |
|--------|--------|-----------------|--------------|----------------|
| **@odoo-dev** | Sonnet | Odoo 19 CE, l10n_cl_dte, Chilean localization | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch | `.claude/agents/odoo-dev.md` |
| **@dte-compliance** | Sonnet | SII regulations, DTE validation, tax compliance | Read, Grep, WebFetch, WebSearch, Glob | `.claude/agents/dte-compliance.md` |
| **@test-automation** | Haiku | Testing, CI/CD, quality assurance | Bash, Read, Write, Edit, Grep, Glob | `.claude/agents/test-automation.md` |
| **@docker-devops** | Sonnet | Docker, DevOps, production deployment | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch | `.claude/agents/docker-devops.md` |
| **@ai-fastapi-dev** | Sonnet | AI/ML, FastAPI, Claude API, microservices | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch | `.claude/agents/ai-fastapi-dev.md` |

### Base de Conocimiento Compartida

**CRÍTICO:** Todos los agentes tienen acceso a:
- `.claude/agents/knowledge/sii_regulatory_context.md` - SII compliance, DTE types scope, regulaciones fiscales
- `.claude/agents/knowledge/odoo19_patterns.md` - Odoo 19 patterns, Pure Python libs/, `_has_cycle()`, etc.
- `.claude/agents/knowledge/project_architecture.md` - EERGYGROUP architecture, decisiones clave
- `.codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md` - Hallazgos confirmados y soluciones propuestas

**INSTRUCCIÓN OBLIGATORIA:** Cada agente DEBE consultar la knowledge base ANTES de implementar cualquier cambio.

### Asignación de Agentes por Sprint

```yaml
sprint_0_preparacion:
  coordinador: Senior Engineer
  ejecutor: @docker-devops
  razon: Backup, branch creation, baseline setup, scripts validación

sprint_1_completar_2_restante:
  coordinador: Senior Engineer
  ejecutor_principal: @odoo-dev
  soporte_testing: @test-automation
  razon: Vista search, análisis tests fallando, commit final

sprint_2_p1_quick_wins:
  coordinador: Senior Engineer
  ejecutor_principal: @odoo-dev
  validador_compliance: @dte-compliance (scope DTE EERGYGROUP)
  ejecutor_tests: @test-automation
  razon: Dashboard fix, DTE scope alignment, tests core, warnings

sprint_3_validacion_rut:
  coordinador: Senior Engineer
  ejecutor_principal: @odoo-dev
  validador_compliance: @dte-compliance (módulo 11, SII XML formats)
  ejecutor_tests: @test-automation
  razon: Helper RUT centralizado con validación SII compliance

sprint_4_libs_pure_python_dte34:
  coordinador: Senior Engineer
  ejecutor_principal: @odoo-dev
  validador_compliance: @dte-compliance (DTE 34 completo, validaciones SII)
  validador_arquitectura: @docker-devops (dependency injection patterns)
  ejecutor_tests: @test-automation (Pure Python tests, DTE 34 integration)
  razon: Refactorizar libs/ sin ORM dependencies + completar DTE 34

sprint_5_ci_cd_docs:
  coordinador: Senior Engineer
  ejecutor_ci_cd: @docker-devops (workflows GitHub Actions, coverage)
  ejecutor_docs: @odoo-dev (actualizar docstrings, README, changelog)
  ejecutor_tests: @test-automation (coverage real, CI/CD tests)
  razon: CI/CD multi-módulo + documentación Odoo 19 completa

consolidacion_final:
  coordinador: Senior Engineer
  ejecutor_validacion: @test-automation (DoD completo, tests finales)
  validador_compliance: @dte-compliance (validación final compliance)
  ejecutor_ci_cd: @docker-devops (validación workflows, coverage)
  razon: Validación completa DoD global, release notes, evidencia
```

### Protocolo de Coordinación

**Senior Engineer (Coordinador):**
1. Valida pre-requisitos ANTES de asignar sprint
2. Asigna sprint a agente especializado según tabla arriba
3. Provee contexto específico del sprint y referencias a knowledge base
4. Valida deliverables vs DoD antes de aprobar
5. Coordina handoff entre agentes si necesario (ej: @odoo-dev → @test-automation)
6. Aprueba commits antes de push
7. Ejecuta rollback si algo falla críticamente

**Agentes Especializados:**
1. **OBLIGATORIO:** Consultan knowledge base ANTES de implementar
2. Ejecutan tasks según su especialización y herramientas disponibles
3. Generan tests (con @test-automation si necesario)
4. Reportan al coordinador al completar con evidencia
5. **NO proceden a siguiente sprint sin aprobación del coordinador**
6. Reportan errores inmediatamente al coordinador
7. Siguen máximas de auditoría y desarrollo sin excepción

**Ejemplo Invocación SPRINT 1:**
```
@odoo-dev ejecuta SPRINT 1 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V3.md

Contexto:
- SPRINT 1 está 98% completado
- Módulo l10n_cl_hr_payroll instalado exitosamente (state=installed)
- 178/237 tests pasando (75%)
- Issues restantes: Vista search comentada, 59 tests fallando

Tareas:
1. TASK 1.1: Corregir vista search hr.payslip (descomentar y validar)
2. TASK 1.2: Análisis sistemático de tests fallando (categorizar y priorizar)
3. TASK 1.3: Commit final SPRINT 1 con evidencia completa

Knowledge Base:
- Revisa .claude/agents/knowledge/odoo19_patterns.md para sintaxis Odoo 19
- Revisa .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md para contexto de hallazgos

DoD SPRINT 1:
- Vista search funcionando
- Análisis de tests fallando documentado
- Commit estructurado con evidencia
- Módulo sigue instalado sin errores

Soporte:
- @test-automation disponible para ejecutar tests y análisis
- Reporta al coordinador al completar cada task
```

**Ejemplo Invocación SPRINT 2:**
```
@odoo-dev ejecuta SPRINT 2 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V3.md

Contexto:
- SPRINT 1 completado al 100%
- P1 Quick Wins pendientes: Dashboard fix, DTE scope, tests core

Tareas:
1. TASK 2.1: Fix dominio project_id → analytic_account_id
2. TASK 2.2: Limitar alcance DTE al scope EERGYGROUP B2B
3. TASK 2.3: Corregir tests fallando - Categoría Core
4. TASK 2.4: Resolver warnings no bloqueantes

Knowledge Base:
- Revisa .claude/agents/knowledge/sii_regulatory_context.md para scope DTE
- Revisa .claude/agents/knowledge/project_architecture.md para decisiones arquitectónicas

Validación:
- @dte-compliance validará scope DTE (TASK 2.2)
- @test-automation ejecutará tests y validará correcciones

DoD SPRINT 2:
- Dashboard funcionando correctamente
- DTE scope limitado a B2B (33, 34, 52, 56, 61)
- Tests core pasando (>= 90%)
- Warnings eliminados
```

### Handoff Entre Agentes

**Proceso de Handoff:**

1. **Agente Principal completa su parte:**
   - Genera código/implementación
   - Documenta cambios
   - Reporta al coordinador

2. **Coordinador valida:**
   - Revisa código vs DoD
   - Aprueba handoff si cumple criterios

3. **Agente Soporte ejecuta su parte:**
   - Ejecuta tests (@test-automation)
   - Valida compliance (@dte-compliance)
   - Valida arquitectura (@docker-devops)

4. **Coordinador aprueba final:**
   - Valida todos los deliverables
   - Aprueba commit
   - Autoriza siguiente sprint

**Ejemplo Handoff SPRINT 4:**
```
@odoo-dev → @test-automation → @dte-compliance → Coordinador

1. @odoo-dev completa DTE 34:
   - Implementa action_generar_liquidacion_dte34()
   - Genera XML, firma, envía a SII
   - Crea account.move
   - Reporta: "DTE 34 implementado, requiere tests"

2. Coordinador valida código y aprueba handoff

3. @test-automation ejecuta tests:
   - Tests unitarios DTE 34
   - Tests integración SII
   - Tests account.move creation
   - Reporta: "Tests pasando, coverage 95%"

4. @dte-compliance valida compliance:
   - Valida XML contra esquema SII
   - Valida firma digital
   - Valida campos obligatorios
   - Reporta: "Compliance validado, cumple Res. 36/2024"

5. Coordinador aprueba final y autoriza commit
```

---

## 🎯 ESTRUCTURA DE SPRINTS

### SPRINT 1: Completar 2% Restante (2h)

**Objetivo:** Completar SPRINT 1 al 100%

**Tareas:**

#### TASK 1.1: Corregir Vista Search hr.payslip (30min)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/views/hr_payslip_views.xml`

**Problema:** Vista search comentada temporalmente

**Solución:**
1. Descomentar vista search (líneas 162-180)
2. Validar sintaxis XML
3. Descomentar referencia en action (línea 190)
4. Validar instalación

**DoD:**
- ✅ Vista search descomentada y funcionando
- ✅ Instalación exitosa validada
- ✅ Búsqueda funcional en UI

---

#### TASK 1.2: Análisis Sistemático de Tests Fallando (1h)

**Objetivo:** Categorizar y priorizar 59 tests fallando

**Proceso:**
1. Ejecutar tests con `--log-level=test`
2. Categorizar fallos:
   - Previred Integration
   - Multi-Company
   - Validation Rules
   - Otros
3. Identificar causas raíz
4. Priorizar correcciones (P0 → P1 → P2)

**DoD:**
- ✅ Análisis completo de fallos documentado
- ✅ Categorización y priorización realizada
- ✅ Plan de corrección definido

---

#### TASK 1.3: Commit Final SPRINT 1 (30min)

**Objetivo:** Commit estructurado con toda la evidencia

**Contenido:**
- Todos los cambios del SPRINT 1
- Evidencias de instalación
- Resultados de tests
- Documentación actualizada

**DoD:**
- ✅ Commit estructurado realizado
- ✅ Mensaje de commit completo
- ✅ Evidencias incluidas

---

### SPRINT 2: P1 Quick Wins (8h)

**Agente Principal:** `@odoo-dev`  
**Agente Soporte:** `@dte-compliance`

**Objetivo:** Resolver hallazgos P1 Quick Wins

**Tareas:**

#### TASK 2.1: Fix Dominio project_id → analytic_account_id (30min)

**Archivo:** `addons/localization/l10n_cl_dte/models/analytic_dashboard.py:489`

**Problema:** Uso incorrecto de `project_id` en dominio

**Solución:**
```python
# ANTES
'domain': [('project_id', '=', self.analytic_account_id.id)]

# DESPUÉS
'domain': [('analytic_account_id', '=', self.analytic_account_id.id)]
```

**DoD:**
- ✅ Dominio corregido
- ✅ Test creado y pasando
- ✅ Validación funcional

---

#### TASK 2.2: Limitar Alcance DTE - Scope EERGYGROUP (1h)

**Archivos:**
- `addons/localization/l10n_cl_dte/libs/dte_structure_validator.py`
- `addons/localization/l10n_cl_dte/models/dte_inbox.py`

**Problema:** DTE types fuera del scope B2B EERGYGROUP

**Solución:**
- Remover DTE types 39, 41, 46 (fuera de scope)
- Mantener DTE type 70 (solo recepción)
- Actualizar validaciones y documentación

**DoD:**
- ✅ DTE types limitados al scope B2B
- ✅ Validaciones actualizadas
- ✅ Documentación actualizada
- ✅ Tests actualizados y pasando

---

#### TASK 2.3: Corregir Tests Fallando - Categoría Core (4h)

**Objetivo:** Corregir tests críticos de funcionalidad core

**Proceso:**
1. Identificar tests core fallando
2. Analizar causa raíz de cada fallo
3. Aplicar correcciones
4. Validar tests pasando

**DoD:**
- ✅ Tests core pasando (>= 90%)
- ✅ Causas raíz documentadas
- ✅ Correcciones validadas

---

#### TASK 2.4: Resolver Warnings No Bloqueantes (2h)

**Objetivos:**
- Corregir `states` parameters (8 ocurrencias en hr_payslip.py)
- Implementar `selection_add` recomendado para `gratification_type`
- Corregir icon title warnings en kanban views

**DoD:**
- ✅ Warnings eliminados
- ✅ Sintaxis Odoo 19 aplicada
- ✅ Validación sin warnings

---

### SPRINT 3: Validación RUT Centralizada (4h)

**Agente Principal:** `@odoo-dev`  
**Agente Soporte:** `@dte-compliance`

**Objetivo:** Centralizar validación RUT con prefijo CL

**Tareas:**

#### TASK 3.1: Crear Helper RUT Centralizado (1.5h)

**Archivo:** `addons/localization/l10n_cl_dte/libs/rut_helper.py` (NUEVO)

**Funcionalidad:**
```python
class RUTHelper:
    @staticmethod
    def normalize_rut(rut: str) -> str:
        """Normaliza RUT removiendo puntos, guiones y prefijo CL"""
        
    @staticmethod
    def validate_rut(rut: str) -> bool:
        """Valida RUT usando algoritmo módulo 11"""
        
    @staticmethod
    def format_rut_sii(rut: str) -> str:
        """Formatea RUT para SII (12.345.678-9)"""
```

**DoD:**
- ✅ Helper creado con 3 métodos
- ✅ Tests unitarios creados (100% cobertura)
- ✅ Documentación completa

---

#### TASK 3.2: Actualizar DTEStructureValidator (1h)

**Archivo:** `addons/localization/l10n_cl_dte/libs/dte_structure_validator.py`

**Solución:** Delegar `validate_rut()` a `RUTHelper`

**DoD:**
- ✅ Validación delegada a RUTHelper
- ✅ Tests actualizados y pasando
- ✅ Sin regresiones

---

#### TASK 3.3: Actualizar Otros Validadores (1h)

**Objetivo:** Buscar y actualizar todos los usos de validación RUT

**Archivos a Revisar:**
- `addons/localization/l10n_cl_dte/models/report_helper.py` (si existe)
- Otros archivos con validación RUT

**DoD:**
- ✅ Todos los validadores actualizados
- ✅ Auditoría completa ejecutada
- ✅ Tests pasando

---

#### TASK 3.4: Validación y Tests (30min)

**DoD:**
- ✅ Tests de integración pasando
- ✅ Validación funcional completa
- ✅ Sin regresiones

---

### SPRINT 4: libs/ Pure Python + DTE 34 Completo (16h)

**Agente Principal:** `@odoo-dev`  
**Agente Soporte:** `@dte-compliance`

**Objetivo:** Refactorizar libs/ a Pure Python y completar DTE 34

**Tareas:**

#### TASK 4.1: Auditar Dependencias ORM en libs/ (2h)

**Script de Auditoría:**
```bash
#!/bin/bash
# scripts/audit_libs_orm_dependencies.sh
# Auditar dependencias ORM en libs/

find addons/localization/l10n_cl_dte/libs -name "*.py" -exec grep -l "from odoo\|import odoo\|odoo\." {} \;
```

**DoD:**
- ✅ Auditoría completa ejecutada
- ✅ Reporte de dependencias generado
- ✅ Plan de refactorización definido

---

#### TASK 4.2: Completar Funcionalidad DTE 34 (10h)

**Archivo:** `addons/localization/l10n_cl_dte/models/purchase_order_dte.py`

**Objetivo:** Implementar `action_generar_liquidacion_dte34()` completo

**Funcionalidad Requerida:**
1. Generar XML DTE 34
2. Firmar XML con certificado digital
3. Enviar a SII
4. Crear `account.move` asociado
5. Manejo de errores completo

**DoD:**
- ✅ Funcionalidad completa implementada
- ✅ Tests de integración creados
- ✅ Validación SII funcionando
- ✅ Manejo de errores robusto

---

#### TASK 4.3: Refactorizar libs/ con Dependency Injection (4h)

**Objetivo:** Si se encuentran dependencias ORM, refactorizar usando DI

**Patrón:**
```python
# ANTES
from odoo import api, models

def validate_dte(xml_content):
    env = api.Environment(...)  # ❌ Dependencia ORM
    
# DESPUÉS
def validate_dte(xml_content, certificate_validator=None):
    if certificate_validator:
        certificate_validator.validate(...)  # ✅ Dependency Injection
```

**DoD:**
- ✅ libs/ refactorizado a Pure Python
- ✅ Dependency Injection implementado
- ✅ Tests pasando sin ORM
- ✅ Documentación actualizada

---

### SPRINT 5: CI/CD + Documentación Odoo 19 (8h)

**Agente Principal:** `@docker-devops`  
**Agente Soporte:** `@test-automation`

**Objetivo:** Extender CI/CD y actualizar documentación

**Tareas:**

#### TASK 5.1: Extender GitHub Actions a 3 Módulos (4h)

**Archivos a Crear/Actualizar:**
- `.github/workflows/l10n_cl_dte.yml`
- `.github/workflows/l10n_cl_hr_payroll.yml`
- `.github/workflows/l10n_cl_financial_reports.yml`
- `.github/workflows/coverage.yml` (consolidado)

**DoD:**
- ✅ 4 workflows creados/actualizados
- ✅ Tests ejecutándose en CI
- ✅ Coverage reportándose
- ✅ Validación exitosa

---

#### TASK 5.2: Actualizar Documentación Odoo 19 (2h)

**Objetivo:** Buscar y actualizar todas las referencias Odoo 18 → Odoo 19

**Script:**
```bash
#!/bin/bash
# scripts/update_odoo19_references.sh
# Buscar y actualizar referencias Odoo 18 → Odoo 19

grep -rn "Odoo 18\|odoo 18\|ODOO 18" addons/localization/ --include="*.py" --include="*.md"
```

**DoD:**
- ✅ Todas las referencias actualizadas
- ✅ Docstrings actualizados
- ✅ README actualizado
- ✅ Validación sin referencias Odoo 18

---

#### TASK 5.3: Actualizar Changelog y Release Notes (2h)

**Archivos:**
- `CHANGELOG.md`
- `RELEASE_NOTES.md`

**Contenido:**
- Todos los cambios de SPRINT 1-5
- Breaking changes documentados
- Migration guide si aplica

**DoD:**
- ✅ Changelog completo y estructurado
- ✅ Release notes profesionales
- ✅ Migration guide si aplica

---

## 🔄 CONSOLIDACIÓN FINAL

### Script de Validación Completa

```bash
#!/bin/bash
# scripts/validate_final_consolidation.sh
# Validar consolidación final de todos los sprints

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULES=("l10n_cl_dte" "l10n_cl_hr_payroll" "l10n_cl_financial_reports")
DB_NAME="${DB_NAME:-odoo19}"

echo "🔍 Validando consolidación final..."
echo ""

ERRORS=0

# 1. Todos los módulos instalados
for module in "${MODULES[@]}"; do
    MODULE_STATE=$(docker exec odoo19_app psql -U odoo -d "$DB_NAME" -t -c \
        "SELECT state FROM ir_module_module WHERE name='$module';" | xargs)
    
    if [ "$MODULE_STATE" = "installed" ]; then
        echo "✅ Módulo $module instalado"
    else
        echo "❌ Módulo $module NO instalado (state=$MODULE_STATE)"
        ERRORS=$((ERRORS + 1))
    fi
done

# 2. Tests pasando (>= 90%)
echo ""
echo "🧪 Ejecutando tests..."
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d "$DB_NAME" \
    --test-enable \
    --stop-after-init \
    --log-level=test \
    2>&1 | tee evidencias/final_tests.log

TESTS_PASS=$(grep -c "ok\|PASS" evidencias/final_tests.log 2>/dev/null || echo "0")
TESTS_FAIL=$(grep -c "FAIL\|ERROR\|FAILED" evidencias/final_tests.log 2>/dev/null || echo "0")
TOTAL_TESTS=$((TESTS_PASS + TESTS_FAIL))
PASS_RATE=$((TESTS_PASS * 100 / TOTAL_TESTS))

if [ "$PASS_RATE" -ge 90 ]; then
    echo "✅ Tests: $TESTS_PASS/$TOTAL_TESTS pasando ($PASS_RATE%)"
else
    echo "❌ Tests: $TESTS_PASS/$TOTAL_TESTS pasando ($PASS_RATE% < 90%)"
    ERRORS=$((ERRORS + 1))
fi

# 3. Sin referencias Odoo 18
ODOO18_REFS=$(grep -rn "Odoo 18\|odoo 18\|ODOO 18" addons/localization/ --include="*.py" --include="*.md" 2>/dev/null | wc -l | xargs)

if [ "$ODOO18_REFS" -eq 0 ]; then
    echo "✅ Sin referencias Odoo 18"
else
    echo "❌ Se encontraron $ODOO18_REFS referencias Odoo 18"
    ERRORS=$((ERRORS + 1))
fi

# 4. CI/CD workflows existentes
WORKFLOWS=(
    ".github/workflows/l10n_cl_dte.yml"
    ".github/workflows/l10n_cl_hr_payroll.yml"
    ".github/workflows/l10n_cl_financial_reports.yml"
    ".github/workflows/coverage.yml"
)

for workflow in "${WORKFLOWS[@]}"; do
    if [ -f "$workflow" ]; then
        echo "✅ Workflow existe: $(basename $workflow)"
    else
        echo "❌ Workflow NO existe: $(basename $workflow)"
        ERRORS=$((ERRORS + 1))
    fi
done

# 5. libs/ Pure Python validado
ORM_DEPS=$(find addons/localization/l10n_cl_dte/libs -name "*.py" -exec grep -l "from odoo\|import odoo\|odoo\." {} \; 2>/dev/null | wc -l | xargs)

if [ "$ORM_DEPS" -eq 0 ]; then
    echo "✅ libs/ es Pure Python"
else
    echo "❌ libs/ tiene $ORM_DEPS archivos con dependencias ORM"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Consolidación Final: COMPLETA (0 errores)"
    exit 0
else
    echo "❌ Consolidación Final: $ERRORS error(es) encontrado(s)"
    exit 1
fi
```

---

## 📊 DEFINITION OF DONE (GLOBAL)

### Criterios Obligatorios (10/10)

| Criterio | Descripción | Validación |
|----------|-------------|------------|
| **1. Instalabilidad** | Todos los módulos instalan sin errores | `state=installed` para los 3 módulos |
| **2. Tests** | >= 90% tests pasando | Script de validación |
| **3. Compatibilidad Odoo 19** | Sin referencias Odoo 18, sintaxis correcta | Auditoría completa |
| **4. Calidad de Código** | PEP8, docstrings, type hints | Linter sin errores críticos |
| **5. Seguridad** | ACL completo, ir.rules, sanitización | Auditoría de seguridad |
| **6. Performance** | Sin N+1 queries, índices apropiados | Auditoría de performance |
| **7. Documentación** | README, changelog, docstrings actualizados | Validación manual |
| **8. CI/CD** | Workflows funcionando, coverage reportando | Validación GitHub Actions |
| **9. Legal Compliance** | Cumplimiento normativo chileno | Validación DTE compliance |
| **10. Evidencias** | Todas las evidencias documentadas | Carpeta evidencias/ completa |

---

## 🚨 MANEJO DE ERRORES Y ROLLBACK

### Protocolo de Manejo de Errores

**Nivel 1: Error de Test**
- Reintentar test individual
- Analizar causa raíz
- Aplicar corrección
- Validar test pasando

**Nivel 2: Error de Instalación**
- Revisar log detallado
- Identificar módulo/archivo problemático
- Aplicar corrección
- Revalidar instalación

**Nivel 3: Error Crítico**
- Ejecutar rollback (script proporcionado)
- Documentar error
- Reportar a coordinador
- Replanificar si necesario

### Script de Rollback

```bash
#!/bin/bash
# scripts/rollback_sprint.sh
# Rollback de cambios de un sprint específico

SPRINT_NUM=${1:-1}

echo "🔄 Ejecutando rollback del SPRINT $SPRINT_NUM..."

# 1. Restaurar DB desde backup
docker exec odoo19_app psql -U odoo -d odoo19 < backups/sprint${SPRINT_NUM}_backup.sql

# 2. Revertir cambios Git
git reset --hard HEAD~${SPRINT_NUM}

echo "✅ Rollback completado"
```

---

## 📋 CHECKLIST DE EJECUCIÓN

### SPRINT 1 (Completar 2%)
- [ ] TASK 1.1: Corregir vista search hr.payslip
- [ ] TASK 1.2: Análisis sistemático de tests fallando
- [ ] TASK 1.3: Commit final SPRINT 1

### SPRINT 2 (P1 Quick Wins)
- [ ] TASK 2.1: Fix dominio project_id → analytic_account_id
- [ ] TASK 2.2: Limitar alcance DTE
- [ ] TASK 2.3: Corregir tests fallando - Core
- [ ] TASK 2.4: Resolver warnings no bloqueantes

### SPRINT 3 (RUT Centralizado)
- [ ] TASK 3.1: Crear helper RUT centralizado
- [ ] TASK 3.2: Actualizar DTEStructureValidator
- [ ] TASK 3.3: Actualizar otros validadores
- [ ] TASK 3.4: Validación y tests

### SPRINT 4 (libs/ Pure Python + DTE 34)
- [ ] TASK 4.1: Auditar dependencias ORM en libs/
- [ ] TASK 4.2: Completar funcionalidad DTE 34
- [ ] TASK 4.3: Refactorizar libs/ con DI

### SPRINT 5 (CI/CD + Documentación)
- [ ] TASK 5.1: Extender GitHub Actions
- [ ] TASK 5.2: Actualizar documentación Odoo 19
- [ ] TASK 5.3: Actualizar changelog y release notes

### Consolidación Final
- [ ] Validación completa ejecutada
- [ ] DoD global validado (10/10 criterios)
- [ ] Commit final realizado
- [ ] Release notes publicados

---

## 🎯 CONCLUSIÓN

Este PROMPT proporciona una guía completa y estructurada para el cierre total de brechas, desde la finalización del SPRINT 1 hasta la consolidación final, siguiendo todas las máximas y criterios establecidos en esta conversación.

**Estado Esperado Post-Ejecución:**
- ✅ SPRINT 1-5: 100% COMPLETADOS
- ✅ Todos los módulos instalados exitosamente
- ✅ >= 90% tests pasando
- ✅ DoD global completo (10/10 criterios)
- ✅ CI/CD funcionando
- ✅ Documentación actualizada
- ✅ Release notes publicados

**Próximo Paso:**
- Ejecutar SPRINT 1 (completar 2% restante)
- Continuar con SPRINT 2-5 según plan
- Consolidación final y validación DoD

---

**FIN DEL PROMPT MASTER CIERRE TOTAL DE BRECHAS V3.0**

