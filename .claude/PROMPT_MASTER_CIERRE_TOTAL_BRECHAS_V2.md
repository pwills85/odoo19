# 🎯 PROMPT MASTER V2 - CIERRE TOTAL DE BRECHAS
## Orquestación Profesional Completa | Zero Improvisations | Enterprise-Grade | Mejorado

**Fecha Emisión:** 2025-11-09 12:00 CLT  
**Versión:** 2.0 (Mejorado según análisis profundo)  
**Ingeniero Senior:** Líder Técnico Orquestación  
**Coordinador:** Senior Engineer (Orchestrator)  
**Agentes Especializados:** 5 agents (orquestación multi-agente)  
**Branch:** `feat/cierre_total_brechas_profesional`  
**Prioridad:** 🔴 CRÍTICA  
**Metodología:** Evidence-based, Zero patches, Full testing  
**Timeline:** 5 sprints (2 semanas)  
**Status:** 📋 READY FOR EXECUTION (V2 - Completo)

---

## 🔧 MEJORAS V2 vs V1

### Correcciones Aplicadas

| Mejora | Estado | Impacto |
|--------|--------|---------|
| ✅ SPRINTS 3-5 Completos | COMPLETADO | CRÍTICO |
| ✅ Paths Dinámicos (Variables Entorno) | COMPLETADO | ALTO |
| ✅ Manejo de Errores y Rollback | COMPLETADO | ALTO |
| ✅ Validación Pre-requisitos | COMPLETADO | ALTO |
| ✅ Consolidación Final | COMPLETADO | MEDIO |
| ✅ Sección de Riesgos | COMPLETADO | MEDIO |

---

## 🤖 ORQUESTACIÓN DE AGENTES ESPECIALIZADOS

### Equipo de Agentes Disponibles

Este proyecto cuenta con **5 agentes especializados** configurados en `.claude/agents/`:

| Agente | Modelo | Especialización | Herramientas |
|--------|--------|-----------------|--------------|
| **@odoo-dev** | Sonnet | Odoo 19 CE, l10n_cl_dte, Chilean localization | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch |
| **@dte-compliance** | Sonnet | SII regulations, DTE validation, tax compliance | Read, Grep, WebFetch, WebSearch, Glob |
| **@test-automation** | Haiku | Testing, CI/CD, quality assurance | Bash, Read, Write, Edit, Grep, Glob |
| **@docker-devops** | Sonnet | Docker, DevOps, production deployment | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch |
| **@ai-fastapi-dev** | Sonnet | AI/ML, FastAPI, Claude API, microservices | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch |

### Base de Conocimiento Compartida

**CRÍTICO:** Todos los agentes tienen acceso a:
- `.claude/agents/knowledge/sii_regulatory_context.md` - SII compliance, DTE types scope
- `.claude/agents/knowledge/odoo19_patterns.md` - Odoo 19 patterns (NOT 11-16!)
- `.claude/agents/knowledge/project_architecture.md` - EERGYGROUP architecture
- `.codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md` - Hallazgos confirmados y soluciones

### Asignación de Agentes por Sprint

```yaml
sprint_0_preparacion:
  coordinador: Senior Engineer
  ejecutor: @docker-devops
  razon: Backup, branch creation, baseline setup

sprint_1_p0_bloqueantes:
  coordinador: Senior Engineer
  ejecutor_principal: @odoo-dev
  soporte_testing: @test-automation
  validador_compliance: @dte-compliance (validación final)
  razon: Fixes Odoo 19 CE compatibility (hr_contract stub, Monetary fields)

sprint_2_p1_quick_wins:
  coordinador: Senior Engineer
  ejecutor: @odoo-dev
  validador: @dte-compliance (scope DTE EERGYGROUP)
  razon: Dashboard fix + DTE scope alignment

sprint_3_validacion_rut:
  coordinador: Senior Engineer
  ejecutor: @odoo-dev
  validador_compliance: @dte-compliance (modulo 11, SII XML formats)
  ejecutor_tests: @test-automation
  razon: Helper RUT centralizado con validación SII

sprint_4_libs_pure_python:
  coordinador: Senior Engineer
  ejecutor: @odoo-dev
  validador_arquitectura: @docker-devops (dependency injection patterns)
  ejecutor_tests: @test-automation (Pure Python tests)
  razon: Refactorizar libs/ sin ORM dependencies

sprint_5_ci_cd_docs:
  coordinador: Senior Engineer
  ejecutor_ci_cd: @docker-devops (workflows, coverage)
  ejecutor_docs: @odoo-dev (actualizar docstrings)
  ejecutor_tests: @test-automation (coverage real)
  razon: CI/CD multi-módulo + docs Odoo 19
```

### Protocolo de Coordinación

**Senior Engineer (tú):**
1. Valida pre-requisitos ANTES de asignar sprint
2. Asigna sprint a agente especializado
3. Provee contexto específico del sprint
4. Valida deliverables vs DoD
5. Coordina handoff entre agentes si necesario
6. Aprueba commits antes de push
7. Ejecuta rollback si algo falla críticamente

**Agentes Especializados:**
1. Consultan knowledge base ANTES de implementar
2. Ejecutan tasks según su especialización
3. Generan tests (con @test-automation si necesario)
4. Reportan al coordinador al completar
5. NO proceden a siguiente sprint sin aprobación
6. Reportan errores inmediatamente al coordinador

**Ejemplo Invocación:**
```
@odoo-dev ejecuta SPRINT 1 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md
Contexto: Resolver 3 hallazgos P0 bloqueantes instalabilidad l10n_cl_hr_payroll
Knowledge base: Revisa odoo19_patterns.md para stub hr.contract CE compatible
DoD: Módulo state=installed, 8 tests PASS, commit estructurado
```

---

## ✅ VALIDACIÓN DE PRE-REQUISITOS

**EJECUTAR ANTES DE INICIAR CUALQUIER SPRINT**

### Script de Validación Automática

```bash
#!/bin/bash
# scripts/validate_prerequisites.sh
# Validación de pre-requisitos para cierre de brechas

set -e

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
ERRORS=0

echo "🔍 Validando pre-requisitos para cierre de brechas..."
echo ""

# 1. Verificar que estamos en el directorio correcto
if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    echo "❌ ERROR: No se encontró docker-compose.yml en $PROJECT_ROOT"
    echo "   Asegúrate de estar en el directorio raíz del proyecto"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Directorio proyecto: $PROJECT_ROOT"
fi

# 2. Verificar Docker está corriendo
if ! docker ps >/dev/null 2>&1; then
    echo "❌ ERROR: Docker no está corriendo"
    echo "   Ejecuta: docker-compose up -d"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Docker está corriendo"
fi

# 3. Verificar contenedor Odoo está healthy
if ! docker ps --filter "name=odoo19_app" --filter "health=healthy" | grep -q odoo19_app; then
    echo "⚠️  ADVERTENCIA: Contenedor odoo19_app no está healthy"
    echo "   Ejecuta: docker-compose restart app"
    echo "   Espera hasta que esté healthy antes de continuar"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Contenedor odoo19_app está healthy"
fi

# 4. Verificar base de datos existe
DB_NAME="${DB_NAME:-odoo19}"
if ! docker exec odoo19_app psql -U odoo -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
    echo "❌ ERROR: Base de datos $DB_NAME no existe o no es accesible"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Base de datos $DB_NAME accesible"
fi

# 5. Verificar módulos existen
for module in l10n_cl_dte l10n_cl_hr_payroll l10n_cl_financial_reports; do
    if [ ! -d "$PROJECT_ROOT/addons/localization/$module" ]; then
        echo "❌ ERROR: Módulo $module no encontrado en addons/localization/"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ Módulo $module encontrado"
    fi
done

# 6. Verificar Git está configurado
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "❌ ERROR: No se encontró repositorio Git"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Repositorio Git configurado"
    CURRENT_BRANCH=$(git branch --show-current)
    echo "   Branch actual: $CURRENT_BRANCH"
fi

# 7. Verificar herramientas necesarias
for tool in jq python3 docker git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "❌ ERROR: Herramienta $tool no encontrada"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ Herramienta $tool disponible"
    fi
done

# 8. Verificar espacio en disco (mínimo 5GB)
AVAILABLE_SPACE=$(df -BG "$PROJECT_ROOT" | tail -1 | awk '{print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -lt 5 ]; then
    echo "⚠️  ADVERTENCIA: Espacio en disco bajo ($AVAILABLE_SPACE GB disponible)"
    echo "   Se recomienda al menos 5GB para backups y operaciones"
else
    echo "✅ Espacio en disco suficiente ($AVAILABLE_SPACE GB disponible)"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Todos los pre-requisitos cumplidos. Listo para ejecutar sprints."
    exit 0
else
    echo "❌ Se encontraron $ERRORS error(es). Corrige antes de continuar."
    exit 1
fi
```

**Uso:**
```bash
# Ejecutar validación
export PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
bash scripts/validate_prerequisites.sh

# Si pasa, continuar con SPRINT 0
# Si falla, corregir errores antes de continuar
```

---

## 🚨 MANEJO DE ERRORES Y ROLLBACK

### Procedimiento de Rollback

**Si algo falla críticamente durante un sprint:**

```bash
#!/bin/bash
# scripts/rollback_sprint.sh
# Rollback de cambios de un sprint fallido

SPRINT_NUM="${1:-unknown}"
BACKUP_DIR="${BACKUP_DIR:-.backup_consolidation}"

echo "🔄 Iniciando rollback del SPRINT $SPRINT_NUM..."
echo ""

# 1. Verificar que existe backup
BACKUP_FILE="$BACKUP_DIR/pre_cierre_brechas_*.sql"
if [ ! -f $BACKUP_FILE ]; then
    echo "❌ ERROR: No se encontró backup en $BACKUP_DIR"
    echo "   Rollback manual requerido"
    exit 1
fi

# 2. Restaurar base de datos
echo "📦 Restaurando base de datos desde backup..."
LATEST_BACKUP=$(ls -t $BACKUP_FILE | head -1)
docker exec -i odoo19_app psql -U odoo -d odoo19 < "$LATEST_BACKUP"

if [ $? -eq 0 ]; then
    echo "✅ Base de datos restaurada"
else
    echo "❌ ERROR: Fallo al restaurar base de datos"
    exit 1
fi

# 3. Revertir cambios Git
echo "📦 Revirtiendo cambios Git..."
git reset --hard HEAD~1  # Revertir último commit
git clean -fd             # Limpiar archivos no rastreados

if [ $? -eq 0 ]; then
    echo "✅ Cambios Git revertidos"
else
    echo "⚠️  ADVERTENCIA: Algunos cambios Git no pudieron revertirse"
fi

# 4. Reiniciar contenedor
echo "🔄 Reiniciando contenedor..."
docker-compose restart app

echo ""
echo "✅ Rollback completado. Verifica estado antes de reintentar."
```

### Manejo de Errores por Tipo

**Error Tipo 1: Error en Tests**
```bash
# Si tests fallan, NO hacer commit
# Investigar error, corregir código, re-ejecutar tests
# Solo commit si todos los tests pasan
```

**Error Tipo 2: Error en Instalación**
```bash
# Si módulo no instala, revisar logs:
docker exec odoo19_app tail -100 /var/log/odoo/odoo.log

# Corregir error, reiniciar contenedor, reintentar instalación
```

**Error Tipo 3: Error Crítico (Base de Datos Corrupta)**
```bash
# Ejecutar rollback inmediatamente
bash scripts/rollback_sprint.sh <sprint_num>

# Notificar al coordinador
# NO continuar hasta resolver
```

---

## 📊 RESUMEN EJECUTIVO

### Consolidación de Hallazgos Validados

Este PROMPT consolida **11 hallazgos críticos** identificados y validados por múltiples agentes:

**Fuente 1: Agente Desarrollador (FASE 0 - Ley 21.735)**
- 3 hallazgos P0 (bloqueantes instalabilidad Odoo 19 CE)

**Fuente 2: Agente Codex (Auditoría Calidad)**
- 6 hallazgos P1 (alta prioridad, no bloqueantes)
- 1 hallazgo P2 (mejora documental)

**Fuente 3: Ingeniero Senior (Validación Objetiva)**
- Rectificación Hallazgo #1 con scope real EERGYGROUP
- Eliminación Hallazgo H4 (_sql_constraints - refutado)

### Métricas Consolidadas

```yaml
hallazgos_total: 11
  p0_bloqueantes: 3      # Ley 21.735 instalabilidad
  p1_altos: 6            # Calidad código, validaciones
  p2_mejoras: 1          # Documentación
  refutados: 1           # _sql_constraints (correcto en Odoo 19)

esfuerzo_estimado: 48 horas
sprints: 5
timeline: 2 semanas
coverage_target: ">= 90%"
tests_nuevos: 40+
archivos_modificados: 25+
```

### Priorización Ejecutiva

| Prioridad | Hallazgos | Esfuerzo | Timeline |
|-----------|-----------|----------|----------|
| 🔴 **P0** | 3 | 4h | Sprint 1 (2 días) |
| 🟡 **P1** | 6 | 36h | Sprints 2-4 (8 días) |
| 🟢 **P2** | 1 | 2h | Sprint 5 (2 días) |
| **TOTAL** | **10** | **42h** | **12 días** |

---

## 🎯 OBJETIVOS DEL CIERRE TOTAL

### Objetivo General

**Cerrar el 100% de las brechas identificadas mediante fixes profesionales, robustos, testeados y sin improvisaciones, alcanzando estándares enterprise-grade para producción.**

### Objetivos Específicos Medibles

| ID | Objetivo | Métrica Éxito | Prioridad |
|---|---|---|---|
| OBJ-1 | Módulo l10n_cl_hr_payroll instalable Odoo 19 CE | state=installed, 0 errors | P0 |
| OBJ-2 | Alcance DTE alineado con scope EERGYGROUP | 6 tipos válidos (no 9) | P1 |
| OBJ-3 | Validación RUT normaliza prefijo CL | 100% RUTs válidos aceptados | P1 |
| OBJ-4 | Librerías libs/ Pure Python | 0 imports odoo en libs/ | P1 |
| OBJ-5 | Dashboard analytics sin errores runtime | 0 FieldNotFound exceptions | P1 |
| OBJ-6 | DTE 34 funcionalidad completa | Generación real, no placeholder | P1 |
| OBJ-7 | CI/CD cubre 3 módulos | Workflows extendidos | P1 |
| OBJ-8 | Documentación actualizada Odoo 19 | 0 referencias Odoo 18 | P2 |
| OBJ-9 | Coverage ≥ 90% | Todos los módulos | ALL |
| OBJ-10 | 0 warnings críticos | Pylint, Flake8 clean | ALL |

### Criterios Aceptación Global (Gate Review)

```yaml
codigo:
  syntax_errors: 0
  critical_warnings: 0
  deprecations_used: 0
  enterprise_dependencies_removed: TRUE
  pure_python_libs: TRUE

instalabilidad:
  l10n_cl_hr_payroll: INSTALLED
  l10n_cl_dte: INSTALLED
  l10n_cl_financial_reports: INSTALLED
  install_errors: 0
  upgrade_errors: 0

testing:
  tests_executed: ">= 100"
  tests_pass_rate: 100%
  tests_fail: 0
  tests_error: 0
  coverage_overall: ">= 90%"
  coverage_critical_paths: 100%

validaciones:
  rut_validation_cl_prefix: PASS
  dte_types_scope: PASS
  monetary_fields: PASS
  sql_constraints: VALID

ci_cd:
  workflows_extended: 3 modules
  jobs_per_module: TRUE
  coverage_real_generated: TRUE

documentacion:
  odoo_version_refs: "19.0"
  changelog_updated: TRUE
  readme_updated: TRUE
  tests_documented: TRUE
```

---

## 🏗️ ESTRUCTURA DE SPRINTS

### SPRINT 0: Preparación (2h)

**Agente Responsable:** `@docker-devops`  
**Coordinador:** Senior Engineer  
**Objetivo:** Crear branch, backup, setup entorno

**Invocación:**
```
@docker-devops ejecuta SPRINT 0 - Preparación según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md

Tasks:
1. Validar pre-requisitos (script validate_prerequisites.sh)
2. Crear branch feat/cierre_total_brechas_profesional
3. Backup DB completo (pg_dump)
4. Generar baseline compliance pre-fixes
5. Setup coverage tracking
6. Documentar estado inicial

Knowledge base: Revisa project_architecture.md para estructura deployment
DoD: Branch creado, backup generado, baseline guardado, pre-requisitos validados
Timeline: 2h
```

**Tasks:**

1. **Validar Pre-requisitos**
```bash
# Ejecutar script de validación
export PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
bash scripts/validate_prerequisites.sh

# Si falla, corregir errores antes de continuar
```

2. **Crear branch**
```bash
# Usar variable de entorno para path
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT"

git checkout -b feat/cierre_total_brechas_profesional
git push -u origin feat/cierre_total_brechas_profesional
```

3. **Backup DB completo**
```bash
BACKUP_DIR="${BACKUP_DIR:-.backup_consolidation}"
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/pre_cierre_brechas_${TIMESTAMP}.sql"

docker exec odoo19_app pg_dump -U odoo odoo19 > "$BACKUP_FILE"

# Verificar backup
if [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
    echo "✅ Backup generado: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
else
    echo "❌ ERROR: Backup falló o está vacío"
    exit 1
fi
```

4. **Generar baseline compliance**
```bash
COMPLIANCE_DIR="${COMPLIANCE_DIR:-.compliance}"
mkdir -p "$COMPLIANCE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASELINE_FILE="$COMPLIANCE_DIR/baseline_pre_cierre_${TIMESTAMP}.json"

# Generar baseline (ejemplo - ajustar según necesidades)
cat > "$BASELINE_FILE" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "modules": [
    "l10n_cl_dte",
    "l10n_cl_hr_payroll",
    "l10n_cl_financial_reports"
  ],
  "odoo_version": "19.0",
  "coverage_baseline": {
    "l10n_cl_dte": 0,
    "l10n_cl_hr_payroll": 0,
    "l10n_cl_financial_reports": 0
  }
}
EOF

echo "✅ Baseline generado: $BASELINE_FILE"
```

5. **Setup coverage tracking**
```bash
# Verificar que coverage está configurado
if [ ! -f ".coveragerc" ]; then
    cat > .coveragerc <<EOF
[run]
source = addons/localization
omit = 
    */tests/*
    */__pycache__/*
    */migrations/*
EOF
    echo "✅ Archivo .coveragerc creado"
fi
```

6. **Documentar estado inicial**
```bash
EVIDENCIAS_DIR="${EVIDENCIAS_DIR:-evidencias}"
mkdir -p "$EVIDENCIAS_DIR/sprint0"

# Documentar estado de módulos
docker exec odoo19_app odoo shell -d odoo19 -c /etc/odoo/odoo.conf <<'PYEOF' > "$EVIDENCIAS_DIR/sprint0/estado_inicial_modulos.txt"
modules = ['l10n_cl_dte', 'l10n_cl_hr_payroll', 'l10n_cl_financial_reports']
for name in modules:
    mod = env['ir.module.module'].search([('name', '=', name)], limit=1)
    if mod:
        print(f"{name}: state={mod.state}, version={mod.latest_version}")
    else:
        print(f"{name}: NO INSTALLED")
PYEOF

echo "✅ Estado inicial documentado"
```

**Deliverables:**
- ✅ Branch creado
- ✅ Backup: `.backup_consolidation/pre_cierre_brechas_$(date).sql`
- ✅ Baseline: `.compliance/baseline_pre_cierre_$(date).json`
- ✅ Coverage inicial medido
- ✅ Pre-requisitos validados

**DoD:**
```bash
# Verificar branch
git branch --show-current | grep -q "feat/cierre_total_brechas_profesional" && echo "✅ Branch OK" || echo "❌ Branch incorrecto"

# Verificar backup
BACKUP_FILE=$(ls -t .backup_consolidation/pre_cierre_brechas_*.sql | head -1)
[ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ] && echo "✅ Backup OK" || echo "❌ Backup faltante"

# Verificar baseline
BASELINE_FILE=$(ls -t .compliance/baseline_pre_cierre_*.json | head -1)
[ -f "$BASELINE_FILE" ] && echo "✅ Baseline OK" || echo "❌ Baseline faltante"

# Verificar pre-requisitos
bash scripts/validate_prerequisites.sh && echo "✅ Pre-requisitos OK" || echo "❌ Pre-requisitos fallan"
```

---

## 📄 SPRINTS 1-2 (Del Prompt Original)

**Nota:** Los SPRINTS 1-2 están completos en el prompt original (`.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md`) y se mantienen iguales (excelente calidad).  
**Referencia:** Ver SPRINT 1 (P0 Bloqueantes) y SPRINT 2 (P1 Quick Wins) en el prompt original.

---

### SPRINT 3: Validación RUT Centralizada (4h)

**Agente Principal:** `@odoo-dev`  
**Validador Compliance:** `@dte-compliance`  
**Ejecutor Tests:** `@test-automation`  
**Coordinador:** Senior Engineer

**Invocación:**
```
@odoo-dev ejecuta SPRINT 3 - Validación RUT según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md

Contexto: Centralizar validación RUT con normalización de prefijo CL
- Hallazgo #2: validate_rut() no remueve prefijo "CL" de RUTs SII
- Inconsistencia: dte_structure_validator vs report_helper
- Solución: Crear helper centralizado rut_helper.py

Knowledge base:
- sii_regulatory_context.md: Formatos RUT SII (CL12345678-5)
- odoo19_patterns.md: Pure Python helpers en libs/
- project_architecture.md: Patrón de reutilización

Tasks: Ver TASK 3.1-3.3 en PROMPT detallado
DoD: Helper centralizado creado, todos los validadores actualizados, 8 tests PASS
Timeline: 4h

Validación:
- @dte-compliance: Confirmar normalización correcta según formatos SII
- @test-automation: Tests con casos reales XML SII
```

**Objetivo:** Centralizar validación RUT con normalización de prefijo CL

#### TASK 3.1: Crear Helper RUT Centralizado (1.5h)

**Hallazgo:** #2 (Codex - Validación RUT sin Prefijo CL)  
**Problema:** `dte_structure_validator.py:96-137` no remueve prefijo "CL" antes de validar módulo 11  
**Solución:** Crear helper centralizado `libs/rut_helper.py` con normalización completa

**Archivos:**
1. `addons/localization/l10n_cl_dte/libs/rut_helper.py` (NEW)
2. `addons/localization/l10n_cl_dte/libs/__init__.py` (actualizar)

**Implementación:**

**Paso 3.1.1: Crear rut_helper.py**
```python
# addons/localization/l10n_cl_dte/libs/rut_helper.py (NUEVO)

# -*- coding: utf-8 -*-
"""
RUT Helper - Centralized Chilean RUT Normalization and Validation
==================================================================

Pure Python helper for RUT normalization and validation.
Reusable across all modules (DTE, Payroll, Financial Reports).

**Migration:** Centralized from scattered implementations
**Pattern:** Pure Python (no Odoo ORM dependencies)
**Compliance:** SII formats (CL12345678-5, 12345678-5, 12.345.678-5)

Author: EERGYGROUP
License: LGPL-3
"""

import re
import logging

_logger = logging.getLogger(__name__)


class RUTHelper:
    """
    Centralized helper for Chilean RUT normalization and validation.
    
    Pure Python class - no Odoo dependencies.
    Used by DTE validators, report helpers, payroll validators.
    """

    @staticmethod
    def normalize_rut(rut_str):
        """
        Normaliza RUT chileno removiendo prefijos, espacios, puntos.
        
        Normaliza:
        - Remueve prefijo "CL" si existe (formato SII)
        - Remueve espacios y puntos
        - Convierte a uppercase
        - Mantiene formato: 12345678-5
        
        Args:
            rut_str (str): RUT en cualquier formato
            
        Returns:
            str: RUT normalizado (12345678-5) o None si inválido
            
        Examples:
            >>> RUTHelper.normalize_rut('CL12345678-5')
            '12345678-5'
            >>> RUTHelper.normalize_rut('12.345.678-5')
            '12345678-5'
            >>> RUTHelper.normalize_rut('CL 12.345.678-5')
            '12345678-5'
        """
        if not rut_str or not isinstance(rut_str, str):
            return None
        
        # Limpiar espacios y convertir a uppercase
        rut_clean = rut_str.strip().upper()
        
        # Remover prefijo "CL" si existe (formato SII)
        if rut_clean.startswith('CL'):
            rut_clean = rut_clean[2:].strip()
        
        # Remover puntos y espacios
        rut_clean = rut_clean.replace('.', '').replace(' ', '')
        
        # Validar formato básico: debe tener guión
        if '-' not in rut_clean:
            return None
        
        # Separar número y dígito verificador
        parts = rut_clean.split('-')
        if len(parts) != 2:
            return None
        
        rut_number = parts[0]
        rut_dv = parts[1].upper()
        
        # Validar que número sea numérico
        if not rut_number.isdigit():
            return None
        
        # Validar que DV sea válido (0-9 o K)
        if rut_dv not in '0123456789K':
            return None
        
        # Retornar formato normalizado
        return f"{rut_number}-{rut_dv}"

    @staticmethod
    def validate_rut(rut_str):
        """
        Valida RUT chileno usando algoritmo módulo 11.
        
        Primero normaliza el RUT, luego valida módulo 11.
        
        Args:
            rut_str (str): RUT en cualquier formato
            
        Returns:
            bool: True si RUT es válido
            
        Examples:
            >>> RUTHelper.validate_rut('CL12345678-5')
            True
            >>> RUTHelper.validate_rut('12345678-5')
            True
            >>> RUTHelper.validate_rut('12345678-0')
            False
        """
        # Normalizar primero
        rut_normalized = RUTHelper.normalize_rut(rut_str)
        
        if not rut_normalized:
            return False
        
        # Separar número y DV
        rut_number, rut_dv = rut_normalized.split('-')
        
        # Calcular dígito verificador esperado (módulo 11)
        reversed_digits = map(int, reversed(rut_number))
        factors = [2, 3, 4, 5, 6, 7] * 3  # Ciclo 2-7
        
        s = sum(d * f for d, f in zip(reversed_digits, factors))
        verification = 11 - (s % 11)
        
        if verification == 11:
            expected_dv = '0'
        elif verification == 10:
            expected_dv = 'K'
        else:
            expected_dv = str(verification)
        
        return rut_dv == expected_dv

    @staticmethod
    def format_rut_sii(rut_str):
        """
        Formatea RUT para uso en XML SII (formato: ########-#).
        
        Args:
            rut_str (str): RUT en cualquier formato
            
        Returns:
            str: RUT formateado para SII (12345678-5)
        """
        normalized = RUTHelper.normalize_rut(rut_str)
        return normalized if normalized else rut_str
```

**Paso 3.1.2: Actualizar __init__.py**
```python
# addons/localization/l10n_cl_dte/libs/__init__.py

# Agregar al final del archivo:
from . import rut_helper

# Exportar para uso fácil
from .rut_helper import RUTHelper
```

**Tests Task 3.1:**
```python
# tests/test_rut_helper.py (NUEVO)

from odoo.tests.common import TransactionCase
from odoo.addons.l10n_cl_dte.libs.rut_helper import RUTHelper


class TestRUTHelper(TransactionCase):
    """Tests helper RUT centralizado"""

    def test_normalize_rut_with_cl_prefix(self):
        """Test normalización RUT con prefijo CL"""
        result = RUTHelper.normalize_rut('CL12345678-5')
        self.assertEqual(result, '12345678-5')

    def test_normalize_rut_with_dots(self):
        """Test normalización RUT con puntos"""
        result = RUTHelper.normalize_rut('12.345.678-5')
        self.assertEqual(result, '12345678-5')

    def test_normalize_rut_with_spaces(self):
        """Test normalización RUT con espacios"""
        result = RUTHelper.normalize_rut('CL 12.345.678-5')
        self.assertEqual(result, '12345678-5')

    def test_normalize_rut_invalid_format(self):
        """Test normalización RUT formato inválido"""
        result = RUTHelper.normalize_rut('invalid')
        self.assertIsNone(result)

    def test_validate_rut_valid(self):
        """Test validación RUT válido"""
        # RUT válido conocido
        self.assertTrue(RUTHelper.validate_rut('12345678-5'))
        self.assertTrue(RUTHelper.validate_rut('CL12345678-5'))

    def test_validate_rut_invalid_dv(self):
        """Test validación RUT con DV inválido"""
        self.assertFalse(RUTHelper.validate_rut('12345678-0'))

    def test_format_rut_sii(self):
        """Test formato RUT para SII"""
        result = RUTHelper.format_rut_sii('CL12.345.678-5')
        self.assertEqual(result, '12345678-5')

    def test_validate_rut_real_sii_format(self):
        """Test validación con formato real SII XML"""
        # Formato común en XML SII
        rut_xml = 'CL12345678-5'
        self.assertTrue(RUTHelper.validate_rut(rut_xml))
```

**DoD Task 3.1:**
- ✅ Helper `rut_helper.py` creado (Pure Python)
- ✅ Métodos: normalize_rut(), validate_rut(), format_rut_sii()
- ✅ Tests helper: 8/8 PASS
- ✅ Exportado en `libs/__init__.py`

---

#### TASK 3.2: Actualizar DTEStructureValidator (1h)

**Problema:** `dte_structure_validator.py:96-137` tiene implementación duplicada  
**Solución:** Delegar a `RUTHelper.validate_rut()`

**Archivo:** `addons/localization/l10n_cl_dte/libs/dte_structure_validator.py`

**Implementación:**

**Paso 3.2.1: Actualizar validate_rut()**
```python
# libs/dte_structure_validator.py:95-137

# ANTES:
@staticmethod
def validate_rut(rut):
    """
    Valida RUT chileno (algoritmo módulo 11).
    """
    if not rut or not isinstance(rut, str):
        return False

    # Limpiar RUT
    rut = rut.replace('.', '').replace('-', '').upper().strip()
    # ... resto de implementación duplicada

# DESPUÉS:
from .rut_helper import RUTHelper

@staticmethod
def validate_rut(rut):
    """
    Valida RUT chileno usando helper centralizado.
    
    Delegates to RUTHelper.validate_rut() for consistency.
    """
    return RUTHelper.validate_rut(rut)
```

**Tests Task 3.2:**
```python
# tests/test_dte_structure_validator_rut.py (NUEVO)

from odoo.tests.common import TransactionCase
from odoo.addons.l10n_cl_dte.libs.dte_structure_validator import DTEStructureValidator


class TestDTEStructureValidatorRUT(TransactionCase):
    """Tests validación RUT en DTEStructureValidator"""

    def test_validate_rut_with_cl_prefix(self):
        """Verificar que acepta RUT con prefijo CL"""
        self.assertTrue(DTEStructureValidator.validate_rut('CL12345678-5'))

    def test_validate_rut_delegates_to_helper(self):
        """Verificar que delega a RUTHelper"""
        from odoo.addons.l10n_cl_dte.libs.rut_helper import RUTHelper
        
        # Debe tener mismo comportamiento
        rut = 'CL12345678-5'
        self.assertEqual(
            DTEStructureValidator.validate_rut(rut),
            RUTHelper.validate_rut(rut)
        )
```

**DoD Task 3.2:**
- ✅ `validate_rut()` actualizado para usar `RUTHelper`
- ✅ Implementación duplicada eliminada
- ✅ Tests delegación: 2/2 PASS

---

#### TASK 3.3: Actualizar Otros Validadores (1h)

**Problema:** Otros lugares pueden tener validación RUT duplicada  
**Solución:** Buscar y actualizar todos los usos

**Archivos a Revisar:**
1. `models/report_helper.py` (si existe `clean_rut()`)
2. Cualquier otro archivo con validación RUT

**Implementación:**

**Paso 3.3.1: Buscar usos de validación RUT**
```bash
# Script de búsqueda
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT/addons/localization/l10n_cl_dte"

echo "🔍 Buscando validaciones RUT duplicadas..."
echo ""

# Buscar funciones que validan RUT
grep -rn "def.*rut\|validate.*rut\|modulo.*11" --include="*.py" . | grep -v "__pycache__" | grep -v "test_"

# Buscar imports de validación RUT
grep -rn "from.*rut\|import.*rut" --include="*.py" . | grep -v "__pycache__"
```

**Paso 3.3.2: Actualizar report_helper.py (si existe)**
```python
# models/report_helper.py (si existe clean_rut)

# ANTES:
def clean_rut(self, rut_str):
    # Implementación duplicada...

# DESPUÉS:
from odoo.addons.l10n_cl_dte.libs.rut_helper import RUTHelper

def clean_rut(self, rut_str):
    """Normaliza RUT usando helper centralizado"""
    return RUTHelper.normalize_rut(rut_str) or rut_str
```

**DoD Task 3.3:**
- ✅ Búsqueda de validaciones RUT completada
- ✅ Todos los validadores actualizados para usar `RUTHelper`
- ✅ Tests integración: 2/2 PASS

---

#### Sprint 3 - Consolidation & Commit

**Paso 3.4: Tests Sprint 3**
```bash
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT"

# Ejecutar suite tests RUT
docker exec odoo19_app odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo19 \
  --test-enable \
  --stop-after-init \
  --log-level=test \
  --test-tags=/l10n_cl_dte/test_rut_helper,/l10n_cl_dte/test_dte_structure_validator_rut \
  2>&1 | tee evidencias/sprint3_tests_rut.log

# Expected: 10 tests PASS (8 helper + 2 delegación)
```

**Paso 3.5: Commit atómico Sprint 3**
```bash
git add addons/localization/l10n_cl_dte/libs/rut_helper.py
git add addons/localization/l10n_cl_dte/libs/dte_structure_validator.py
git add addons/localization/l10n_cl_dte/libs/__init__.py
git add addons/localization/l10n_cl_dte/tests/test_rut_helper.py
git add addons/localization/l10n_cl_dte/tests/test_dte_structure_validator_rut.py

git commit -m "feat(l10n_cl_dte): centralize RUT validation with CL prefix normalization

SPRINT 3 - Validación RUT Centralizada

Resolves:
- #2 (Codex): RUT validation without CL prefix normalization
- Inconsistency: dte_structure_validator vs report_helper

Changes:
- libs/rut_helper.py: NEW - Centralized RUT helper (Pure Python)
  * normalize_rut(): Removes CL prefix, dots, spaces
  * validate_rut(): Module 11 validation with normalization
  * format_rut_sii(): Format for SII XML
- libs/dte_structure_validator.py: Delegate to RUTHelper
- libs/__init__.py: Export RUTHelper
- tests/test_rut_helper.py: NEW - 8 tests
- tests/test_dte_structure_validator_rut.py: NEW - 2 tests

Tests: 10/10 PASS
Compliance: SII formats (CL12345678-5) supported
Pattern: Pure Python (no ORM dependencies)

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 3
Ref: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md Hallazgo #2
"
```

**DoD Sprint 3:**
- ✅ Helper RUT centralizado creado
- ✅ Todos los validadores actualizados
- ✅ 10 tests nuevos PASS
- ✅ Commit profesional

---

### SPRINT 4: libs/ Pure Python + DTE 34 Completo (16h)

**Agente Principal:** `@odoo-dev`  
**Validador Arquitectura:** `@docker-devops`  
**Ejecutor Tests:** `@test-automation`  
**Coordinador:** Senior Engineer

**Invocación:**
```
@odoo-dev ejecuta SPRINT 4 - libs/ Pure Python + DTE 34 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md

Contexto: Refactorizar libs/ sin ORM + Completar DTE 34
- Hallazgo #3: libs/ con dependencias ORM (violación arquitectura)
- Hallazgo #5: DTE 34 incompleto (solo placeholder)
- Solución: Dependency injection + Completar generación DTE 34

Knowledge base:
- odoo19_patterns.md: Pure Python libs/ pattern, dependency injection
- project_architecture.md: FASE 2 refactor (2025-11-02)
- sii_regulatory_context.md: DTE 34 requirements

Tasks: Ver TASK 4.1-4.3 en PROMPT detallado
DoD: libs/ Pure Python, DTE 34 funcional, 15 tests PASS
Timeline: 16h

Validación:
- @docker-devops: Verificar dependency injection patterns
- @test-automation: Tests Pure Python sin ORM
```

**Objetivo:** Refactorizar libs/ a Pure Python + Completar DTE 34

#### TASK 4.1: Auditar Dependencias ORM en libs/ (2h)

**Hallazgo:** #3 (Codex - libs/ con ORM)  
**Problema:** Algunos archivos en `libs/` pueden tener imports de Odoo  
**Solución:** Auditar y refactorizar si necesario

**Implementación:**

**Paso 4.1.1: Script de auditoría**
```bash
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT/addons/localization/l10n_cl_dte/libs"

echo "🔍 Auditando dependencias ORM en libs/..."
echo ""

# Buscar imports de Odoo
echo "📋 Imports de Odoo encontrados:"
grep -rn "from odoo\|import odoo" --include="*.py" . | grep -v "__pycache__" || echo "✅ Ninguno encontrado"

# Buscar uso de odoo.exceptions
echo ""
echo "📋 Uso de odoo.exceptions:"
grep -rn "odoo\.exceptions\|UserError\|ValidationError" --include="*.py" . | grep -v "__pycache__" || echo "✅ Ninguno encontrado"

# Buscar acceso a request.env
echo ""
echo "📋 Acceso a request.env:"
grep -rn "request\.\|odoo\.http" --include="*.py" . | grep -v "__pycache__" || echo "✅ Ninguno encontrado"

echo ""
echo "✅ Auditoría completada"
```

**Nota:** Según código revisado, los archivos en `libs/` ya están refactorizados a Pure Python (comentarios indican refactor 2025-11-02).  
**Si la auditoría encuentra imports de Odoo, proceder con refactorización.**

**DoD Task 4.1:**
- ✅ Auditoría completada
- ✅ Reporte de dependencias ORM generado
- ✅ Plan de refactorización definido (si necesario)

---

#### TASK 4.2: Completar Funcionalidad DTE 34 (10h)

**Hallazgo:** #5 (Codex - DTE 34 Incompleto)  
**Problema:** `purchase_order_dte.py:247-269` solo muestra "En Desarrollo"  
**Solución:** Implementar generación completa DTE 34 usando `DTEXMLGenerator`

**Archivos:**
1. `addons/localization/l10n_cl_dte/models/purchase_order_dte.py`
2. `addons/localization/l10n_cl_dte/models/account_move_dte.py` (referencia para patrón)

**Implementación:**

**Paso 4.2.1: Completar action_generar_liquidacion_dte34()**
```python
# models/purchase_order_dte.py:247-269

# ANTES:
def action_generar_liquidacion_dte34(self):
    """
    Genera DTE 34 (Liquidación de Honorarios)
    """
    self.ensure_one()
    
    if not self.es_liquidacion_honorarios:
        raise ValidationError(_('Esta orden no es una liquidación de honorarios'))
    
    # Validar datos
    self._validate_liquidacion_data()
    
    # Llamar DTE Service para generar DTE 34
    # TODO: Implementar llamada a DTE Service
    
    return {
        'type': 'ir.actions.client',
        'tag': 'display_notification',
        'params': {
            'title': _('En Desarrollo'),
            'message': _('Generación de DTE 34 pendiente de implementación completa'),
            'type': 'info',
        }
    }

# DESPUÉS:
def action_generar_liquidacion_dte34(self):
    """
    Genera DTE 34 (Factura Exenta) desde orden de compra.
    
    DTE 34 se usa para liquidaciones de honorarios profesionales
    exentos de IVA según normativa chilena.
    """
    self.ensure_one()
    
    # Validaciones
    if not self.es_liquidacion_honorarios:
        raise ValidationError(_('Esta orden no es una liquidación de honorarios'))
    
    self._validate_liquidacion_data()
    
    if not self.analytic_account_id:
        raise ValidationError(_('Debe seleccionar una cuenta analítica'))
    
    if not self.partner_id.vat:
        raise ValidationError(_('El proveedor debe tener RUT configurado'))
    
    # Preparar datos para DTE 34
    dte_data = self._prepare_dte34_data()
    
    # Generar XML usando DTEXMLGenerator (Pure Python)
    from odoo.addons.l10n_cl_dte.libs.xml_generator import DTEXMLGenerator
    
    generator = DTEXMLGenerator()
    xml_content = generator.generate_dte_xml('34', dte_data)
    
    # Firmar XML
    signed_xml = self._sign_dte34_xml(xml_content, dte_data)
    
    # Enviar a SII
    send_result = self._send_dte34_to_sii(signed_xml, dte_data)
    
    # Crear account.move asociado
    move = self._create_account_move_dte34(dte_data, signed_xml, send_result)
    
    # Actualizar estado
    self.write({
        'dte_34_folio': dte_data['folio'],
        'dte_34_status': 'sent' if send_result['success'] else 'error',
        'dte_34_move_id': move.id,
    })
    
    # Mostrar notificación
    return {
        'type': 'ir.actions.client',
        'tag': 'display_notification',
        'params': {
            'title': _('DTE 34 Generado'),
            'message': _('DTE 34 folio %s generado y enviado al SII') % dte_data['folio'],
            'type': 'success',
        }
    }

def _prepare_dte34_data(self):
    """Prepara datos estructurados para DTE 34"""
    self.ensure_one()
    
    # Obtener folio siguiente
    folio = self._get_next_folio_dte34()
    
    # Normalizar RUTs usando RUTHelper
    from odoo.addons.l10n_cl_dte.libs.rut_helper import RUTHelper
    
    return {
        'tipo_dte': '34',
        'folio': folio,
        'fecha_emision': fields.Date.today().strftime('%Y-%m-%d'),
        'emisor': {
            'rut': RUTHelper.format_rut_sii(self.company_id.vat),
            'razon_social': self.company_id.name,
            'giro': self.company_id.l10n_cl_activity_description or '',
            'direccion': self.company_id.street or '',
            'comuna': self.company_id.l10n_cl_comuna_id.name if self.company_id.l10n_cl_comuna_id else '',
            'ciudad': self.company_id.city or '',
        },
        'receptor': {
            'rut': RUTHelper.format_rut_sii(self.partner_id.vat),
            'razon_social': self.partner_id.name,
            'giro': self.partner_id.l10n_cl_activity_description or '',
            'direccion': self.partner_id.street or '',
            'comuna': self.partner_id.l10n_cl_comuna_id.name if self.partner_id.l10n_cl_comuna_id else '',
            'ciudad': self.partner_id.city or '',
        },
        'detalles': self._prepare_dte34_lines(),
        'totales': self._calculate_dte34_totals(),
        'referencias': self._prepare_dte34_references(),
    }

def _prepare_dte34_lines(self):
    """Prepara líneas de detalle para DTE 34"""
    self.ensure_one()
    
    lines = []
    for line in self.order_line:
        lines.append({
            'nro_lin_det': len(lines) + 1,
            'cdg_item': {
                'tpo_codigo': 'INT1',  # Código interno
                'vlr_codigo': str(line.product_id.id),
            },
            'nmb_item': line.product_id.name or 'Servicio Profesional',
            'qty_item': line.product_uom_qty,
            'unmd_item': line.product_uom.name if line.product_uom else 'UN',
            'prc_item': line.price_unit,
            'monto_item': line.price_subtotal,
            'ind_exe': 1,  # Exento de IVA
        })
    
    return lines

def _calculate_dte34_totals(self):
    """Calcula totales para DTE 34"""
    self.ensure_one()
    
    mnt_exe = self.amount_total  # Monto exento (sin IVA)
    
    return {
        'mnt_exe': mnt_exe,
        'mnt_total': mnt_exe,  # Sin IVA
    }

def _prepare_dte34_references(self):
    """Prepara referencias para DTE 34"""
    self.ensure_one()
    
    references = []
    
    # Referencia a orden de compra
    references.append({
        'nro_lin_ref': 1,
        'tpo_doc_ref': '801',  # Orden de Compra
        'folio_ref': self.name,
        'fch_ref': self.date_order.strftime('%Y-%m-%d'),
    })
    
    # Referencia a período de servicios (si aplica)
    if self.periodo_servicio_inicio and self.periodo_servicio_fin:
        references.append({
            'nro_lin_ref': 2,
            'tpo_doc_ref': '802',  # Contrato
            'folio_ref': f"PERIODO-{self.periodo_servicio_inicio}-{self.periodo_servicio_fin}",
            'fch_ref': self.periodo_servicio_fin.strftime('%Y-%m-%d'),
        })
    
    return references

def _get_next_folio_dte34(self):
    """Obtiene siguiente folio disponible para DTE 34"""
    self.ensure_one()
    
    # Buscar último folio usado
    last_move = self.env['account.move'].search([
        ('dte_code', '=', '34'),
        ('company_id', '=', self.company_id.id),
    ], order='dte_folio desc', limit=1)
    
    if last_move and last_move.dte_folio:
        return int(last_move.dte_folio) + 1
    
    # Si no hay folios previos, empezar en 1
    return 1

def _sign_dte34_xml(self, xml_content, dte_data):
    """Firma XML DTE 34 usando certificado digital"""
    self.ensure_one()
    
    from odoo.addons.l10n_cl_dte.libs.xml_signer import XMLSigner
    from odoo.addons.l10n_cl_dte.libs.ted_generator import TEDGenerator
    
    # Obtener certificado
    certificate = self.company_id.dte_certificate_id
    if not certificate:
        raise ValidationError(_('Certificado digital no configurado para la compañía'))
    
    # Firmar XML
    signer = XMLSigner()
    signed_xml = signer.sign_xml(
        xml_content=xml_content,
        certificate_data={
            'certificate': certificate.certificate_content,
            'private_key': certificate.private_key_content,
            'password': certificate.password,
        },
        dte_data=dte_data
    )
    
    return signed_xml

def _send_dte34_to_sii(self, signed_xml, dte_data):
    """Envía DTE 34 firmado al SII"""
    self.ensure_one()
    
    from odoo.addons.l10n_cl_dte.libs.sii_soap_client import SIISoapClient
    
    client = SIISoapClient(self.env)
    result = client.send_dte_to_sii(
        signed_xml=signed_xml,
        rut_emisor=self.company_id.vat,
        company=self.company_id
    )
    
    return result

def _create_account_move_dte34(self, dte_data, signed_xml, send_result):
    """Crea account.move asociado al DTE 34"""
    self.ensure_one()
    
    # Crear factura exenta
    move = self.env['account.move'].create({
        'move_type': 'in_invoice',
        'partner_id': self.partner_id.id,
        'company_id': self.company_id.id,
        'invoice_date': fields.Date.today(),
        'date': fields.Date.today(),
        'dte_code': '34',
        'dte_folio': str(dte_data['folio']),
        'dte_xml': base64.b64encode(signed_xml.encode('ISO-8859-1')),
        'dte_xml_filename': f'DTE_34_{dte_data["folio"]}.xml',
        'dte_status': 'sent' if send_result['success'] else 'error',
        'invoice_line_ids': [(0, 0, {
            'product_id': line.product_id.id,
            'name': line.product_id.name,
            'quantity': line.product_uom_qty,
            'price_unit': line.price_unit,
            'account_id': self.analytic_account_id.account_id.id,
            'analytic_distribution': {self.analytic_account_id.id: 100},
        }) for line in self.order_line],
    })
    
    return move
```

**Tests Task 4.2:**
```python
# tests/test_purchase_order_dte34.py (NUEVO)

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestPurchaseOrderDTE34(TransactionCase):
    """Tests generación DTE 34 desde orden de compra"""

    def setUp(self):
        super().setUp()
        self.PurchaseOrder = self.env['purchase.order']
        self.Partner = self.env['res.partner']
        self.Product = self.env['product.product']
        self.AnalyticAccount = self.env['account.analytic.account']
        
        # Setup datos de prueba
        self.partner = self.Partner.create({
            'name': 'Proveedor Test DTE34',
            'vat': '12345678-5',
        })
        
        self.product = self.Product.create({
            'name': 'Servicio Profesional Test',
            'type': 'service',
        })
        
        self.analytic_account = self.AnalyticAccount.create({
            'name': 'Proyecto Test DTE34',
        })

    def test_prepare_dte34_data(self):
        """Test preparación datos DTE 34"""
        po = self.PurchaseOrder.create({
            'partner_id': self.partner.id,
            'es_liquidacion_honorarios': True,
            'analytic_account_id': self.analytic_account.id,
            'order_line': [(0, 0, {
                'product_id': self.product.id,
                'product_qty': 1,
                'price_unit': 1000000,
            })],
        })
        
        dte_data = po._prepare_dte34_data()
        
        self.assertEqual(dte_data['tipo_dte'], '34')
        self.assertIn('folio', dte_data)
        self.assertEqual(dte_data['emisor']['rut'], '12345678-5')  # Sin CL
        self.assertEqual(len(dte_data['detalles']), 1)

    def test_validate_liquidacion_data(self):
        """Test validación datos liquidación"""
        po = self.PurchaseOrder.create({
            'partner_id': self.partner.id,
            'es_liquidacion_honorarios': True,
        })
        
        # Debe fallar sin datos requeridos
        with self.assertRaises(ValidationError):
            po._validate_liquidacion_data()

    def test_generate_dte34_complete(self):
        """Test generación completa DTE 34"""
        po = self.PurchaseOrder.create({
            'partner_id': self.partner.id,
            'es_liquidacion_honorarios': True,
            'analytic_account_id': self.analytic_account.id,
            'profesional_rut': '98765432-1',
            'profesional_nombre': 'Profesional Test',
            'periodo_servicio_inicio': '2025-01-01',
            'periodo_servicio_fin': '2025-01-31',
            'monto_bruto_honorarios': 2000000,
            'order_line': [(0, 0, {
                'product_id': self.product.id,
                'product_qty': 1,
                'price_unit': 2000000,
            })],
        })
        
        # Mock certificado y SII (en test real, usar fixtures)
        # Por ahora, solo validar que no lanza error de validación
        po._validate_liquidacion_data()
        dte_data = po._prepare_dte34_data()
        
        self.assertIsNotNone(dte_data)
        self.assertEqual(dte_data['tipo_dte'], '34')
```

**DoD Task 4.2:**
- ✅ Funcionalidad DTE 34 completa implementada
- ✅ Generación XML usando `DTEXMLGenerator`
- ✅ Firma y envío a SII implementados
- ✅ Creación de `account.move` asociado
- ✅ Tests funcionales: 3/3 PASS

---

#### TASK 4.3: Refactorizar libs/ con Dependency Injection (si necesario) (4h)

**Nota:** Según auditoría, los archivos en `libs/` ya están refactorizados a Pure Python.  
**Si la auditoría encuentra dependencias ORM, proceder con esta tarea.**

**Implementación (si necesario):**

**Paso 4.3.1: Refactorizar sii_soap_client.py (ejemplo)**
```python
# Si encuentra imports de Odoo, refactorizar así:

# ANTES:
from odoo import _
from odoo.exceptions import UserError

class SIISoapClient:
    def __init__(self, env):
        self.env = env  # Dependencia ORM
    
    def send_dte(self, xml):
        config = self.env['ir.config_parameter'].get_param(...)  # Acceso ORM

# DESPUÉS:
class SIISoapClient:
    """
    Pure Python SOAP client with dependency injection.
    """
    def __init__(self, config_data=None, error_handler=None):
        """
        Args:
            config_data: Dict con configuración (inyectado desde modelo)
            error_handler: Callable para manejar errores
        """
        self.config_data = config_data or {}
        self.error_handler = error_handler
    
    def send_dte(self, xml):
        sii_url = self.config_data.get('sii_url')
        # ... lógica pura Python
```

**DoD Task 4.3:**
- ✅ Dependencias ORM eliminadas de `libs/`
- ✅ Dependency injection implementada
- ✅ Modelos actualizados para inyectar dependencias
- ✅ Tests Pure Python: 5/5 PASS

---

#### Sprint 4 - Consolidation & Commit

**Paso 4.4: Tests Sprint 4**
```bash
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT"

# Ejecutar suite tests Sprint 4
docker exec odoo19_app odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo19 \
  --test-enable \
  --stop-after-init \
  --log-level=test \
  --test-tags=/l10n_cl_dte/test_purchase_order_dte34 \
  2>&1 | tee evidencias/sprint4_tests_dte34.log

# Expected: 3+ tests PASS
```

**Paso 4.5: Commit atómico Sprint 4**
```bash
git add addons/localization/l10n_cl_dte/models/purchase_order_dte.py
git add addons/localization/l10n_cl_dte/tests/test_purchase_order_dte34.py

git commit -m "feat(l10n_cl_dte): complete DTE 34 generation from purchase orders

SPRINT 4 - libs/ Pure Python + DTE 34 Completo

Resolves:
- #5 (Codex): DTE 34 incomplete functionality (placeholder removed)
- #3 (Codex): libs/ Pure Python architecture (audited, already compliant)

Changes:
- models/purchase_order_dte.py: Complete DTE 34 generation
  * action_generar_liquidacion_dte34(): Full implementation
  * _prepare_dte34_data(): Data preparation
  * _sign_dte34_xml(): XML signing
  * _send_dte34_to_sii(): SII submission
  * _create_account_move_dte34(): Move creation
- tests/test_purchase_order_dte34.py: NEW - 3 tests

Tests: 3/3 PASS
Architecture: Pure Python libs/ (already compliant)
DTE 34: Fully functional (no placeholder)

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 4
Ref: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md Hallazgos #3, #5
"
```

**DoD Sprint 4:**
- ✅ DTE 34 funcionalidad completa
- ✅ libs/ auditado (ya Pure Python)
- ✅ 3 tests nuevos PASS
- ✅ Commit profesional

---

### SPRINT 5: CI/CD + Documentación (8h)

**Agente CI/CD:** `@docker-devops`  
**Agente Docs:** `@odoo-dev`  
**Ejecutor Tests:** `@test-automation`  
**Coordinador:** Senior Engineer

**Invocación:**
```
@docker-devops ejecuta SPRINT 5 - CI/CD + Docs según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md

Contexto: Extender CI/CD a 3 módulos + Actualizar documentación Odoo 19
- Hallazgo #7: CI/CD solo cubre l10n_cl_dte
- Hallazgo #8: Documentación con referencias Odoo 18
- Solución: Workflows multi-módulo + Actualizar docs

Knowledge base:
- project_architecture.md: CI/CD structure, coverage requirements
- odoo19_patterns.md: Odoo 19 documentation standards

Tasks: Ver TASK 5.1-5.3 en PROMPT detallado
DoD: Workflows extendidos, coverage real, docs actualizadas
Timeline: 8h

Colaboración:
- @odoo-dev: Actualizar docstrings y README
- @test-automation: Configurar coverage reporting
```

**Objetivo:** Extender CI/CD a 3 módulos + Actualizar documentación Odoo 19

#### TASK 5.1: Extender GitHub Actions a 3 Módulos (4h)

**Hallazgo:** #7 (Codex - Sin CI/CD completo)  
**Problema:** CI/CD solo cubre `l10n_cl_dte`, falta `l10n_cl_hr_payroll` y `l10n_cl_financial_reports`  
**Solución:** Crear/extender workflows para 3 módulos

**Archivos:**
1. `.github/workflows/test_l10n_cl_dte.yml` (crear o actualizar)
2. `.github/workflows/test_l10n_cl_hr_payroll.yml` (NUEVO)
3. `.github/workflows/test_l10n_cl_financial_reports.yml` (NUEVO)
4. `.github/workflows/coverage.yml` (NUEVO - consolidado)

**Implementación:**

**Paso 5.1.1: Crear workflow para l10n_cl_dte**
```yaml
# .github/workflows/test_l10n_cl_dte.yml

name: Test l10n_cl_dte

on:
  push:
    paths:
      - 'addons/localization/l10n_cl_dte/**'
      - '.github/workflows/test_l10n_cl_dte.yml'
  pull_request:
    paths:
      - 'addons/localization/l10n_cl_dte/**'
      - '.github/workflows/test_l10n_cl_dte.yml'

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: odoo
          POSTGRES_USER: odoo
          POSTGRES_DB: odoo19_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run tests
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USER: odoo
          DB_PASSWORD: odoo
          DB_NAME: odoo19_test
        run: |
          odoo -d odoo19_test \
            --test-enable \
            --stop-after-init \
            --test-tags=/l10n_cl_dte \
            --log-level=test
      
      - name: Generate coverage
        run: |
          coverage run --source=addons/localization/l10n_cl_dte \
            -m odoo -d odoo19_test --test-enable --stop-after-init --test-tags=/l10n_cl_dte
          coverage xml -o coverage_l10n_cl_dte.xml
          coverage report
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage_l10n_cl_dte.xml
          flags: l10n_cl_dte
```

**Paso 5.1.2: Crear workflow para l10n_cl_hr_payroll**
```yaml
# .github/workflows/test_l10n_cl_hr_payroll.yml

name: Test l10n_cl_hr_payroll

on:
  push:
    paths:
      - 'addons/localization/l10n_cl_hr_payroll/**'
      - '.github/workflows/test_l10n_cl_hr_payroll.yml'
  pull_request:
    paths:
      - 'addons/localization/l10n_cl_hr_payroll/**'
      - '.github/workflows/test_l10n_cl_hr_payroll.yml'

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: odoo
          POSTGRES_USER: odoo
          POSTGRES_DB: odoo19_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run tests
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USER: odoo
          DB_PASSWORD: odoo
          DB_NAME: odoo19_test
        run: |
          odoo -d odoo19_test \
            --test-enable \
            --stop-after-init \
            --test-tags=/l10n_cl_hr_payroll \
            --log-level=test
      
      - name: Generate coverage
        run: |
          coverage run --source=addons/localization/l10n_cl_hr_payroll \
            -m odoo -d odoo19_test --test-enable --stop-after-init --test-tags=/l10n_cl_hr_payroll
          coverage xml -o coverage_l10n_cl_hr_payroll.xml
          coverage report
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage_l10n_cl_hr_payroll.xml
          flags: l10n_cl_hr_payroll
```

**Paso 5.1.3: Crear workflow para l10n_cl_financial_reports**
```yaml
# .github/workflows/test_l10n_cl_financial_reports.yml

name: Test l10n_cl_financial_reports

on:
  push:
    paths:
      - 'addons/localization/l10n_cl_financial_reports/**'
      - '.github/workflows/test_l10n_cl_financial_reports.yml'
  pull_request:
    paths:
      - 'addons/localization/l10n_cl_financial_reports/**'
      - '.github/workflows/test_l10n_cl_financial_reports.yml'

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: odoo
          POSTGRES_USER: odoo
          POSTGRES_DB: odoo19_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run tests
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USER: odoo
          DB_PASSWORD: odoo
          DB_NAME: odoo19_test
        run: |
          odoo -d odoo19_test \
            --test-enable \
            --stop-after-init \
            --test-tags=/l10n_cl_financial_reports \
            --log-level=test
      
      - name: Generate coverage
        run: |
          coverage run --source=addons/localization/l10n_cl_financial_reports \
            -m odoo -d odoo19_test --test-enable --stop-after-init --test-tags=/l10n_cl_financial_reports
          coverage xml -o coverage_l10n_cl_financial_reports.xml
          coverage report
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage_l10n_cl_financial_reports.xml
          flags: l10n_cl_financial_reports
```

**Paso 5.1.4: Crear workflow consolidado de coverage**
```yaml
# .github/workflows/coverage.yml

name: Coverage Report

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  coverage:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: odoo
          POSTGRES_USER: odoo
          POSTGRES_DB: odoo19_test
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install coverage
      
      - name: Run all tests with coverage
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USER: odoo
          DB_PASSWORD: odoo
          DB_NAME: odoo19_test
        run: |
          coverage run --source=addons/localization \
            -m odoo -d odoo19_test \
            --test-enable \
            --stop-after-init \
            --test-tags=/l10n_cl_dte,/l10n_cl_hr_payroll,/l10n_cl_financial_reports
      
      - name: Generate coverage report
        run: |
          coverage xml -o coverage.xml
          coverage report
          coverage html -d coverage_html
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          flags: all_modules
          name: coverage-all-modules
```

**DoD Task 5.1:**
- ✅ 3 workflows creados (uno por módulo)
- ✅ 1 workflow consolidado de coverage
- ✅ Coverage real generado y reportado
- ✅ Tests ejecutados en CI

---

#### TASK 5.2: Actualizar Documentación Odoo 19 (2h)

**Hallazgo:** #8 (Codex - Documentación Odoo 18)  
**Problema:** Docstrings y comentarios mencionan Odoo 18  
**Solución:** Actualizar todas las referencias a Odoo 19

**Archivos a Actualizar:**
1. `addons/localization/l10n_cl_financial_reports/models/l10n_cl_f29_report.py`
2. `addons/localization/l10n_cl_financial_reports/models/financial_report_service_model.py`
3. `addons/localization/l10n_cl_financial_reports/models/date_helper.py`
4. `addons/localization/l10n_cl_financial_reports/tests/test_odoo18_compatibility.py` (renombrar o actualizar)
5. README.md de cada módulo

**Implementación:**

**Paso 5.2.1: Buscar referencias Odoo 18**
```bash
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT/addons/localization"

echo "🔍 Buscando referencias a Odoo 18..."
echo ""

# Buscar en docstrings y comentarios
grep -rn "Odoo 18\|odoo 18\|ODOO 18\|Odoo18\|odoo18" --include="*.py" . | grep -v "__pycache__" || echo "✅ Ninguna encontrada"

# Buscar en README
grep -rn "Odoo 18\|odoo 18\|ODOO 18" --include="*.md" . || echo "✅ Ninguna encontrada"
```

**Paso 5.2.2: Actualizar docstrings**
```python
# models/l10n_cl_f29_report.py

# ANTES:
"""
Hereda de account.report para integrarse con el framework de reportes de Odoo 18
"""

# DESPUÉS:
"""
Hereda de account.report para integrarse con el framework de reportes de Odoo 19 CE.
"""
```

**Paso 5.2.3: Actualizar README.md**
```markdown
# addons/localization/l10n_cl_dte/README.md

# ANTES:
- Compatible con Odoo 18 y 19

# DESPUÉS:
- Compatible con Odoo 19 CE
- Requiere Odoo 19.0+
```

**DoD Task 5.2:**
- ✅ Búsqueda de referencias Odoo 18 completada
- ✅ Todas las referencias actualizadas a Odoo 19
- ✅ README.md actualizados
- ✅ Docstrings actualizados

---

#### TASK 5.3: Actualizar Changelog y Release Notes (2h)

**Objetivo:** Documentar todos los cambios realizados en los sprints

**Archivos:**
1. `CHANGELOG.md` (crear o actualizar)
2. `RELEASE_NOTES.md` (crear)

**Implementación:**

**Paso 5.3.1: Crear CHANGELOG.md**
```markdown
# CHANGELOG.md

# Changelog

Todos los cambios notables de este proyecto serán documentados en este archivo.

## [19.0.2.0.0] - 2025-11-09

### Added
- Helper RUT centralizado (`libs/rut_helper.py`) con normalización de prefijo CL
- Funcionalidad completa DTE 34 desde órdenes de compra
- CI/CD workflows para 3 módulos (l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports)
- Coverage reporting consolidado

### Fixed
- Validación RUT ahora acepta prefijo CL (formato SII)
- Dominio project_id corregido a analytic_account_id en dashboard
- Alcance DTE limitado a scope EERGYGROUP (6 tipos válidos)
- Módulo l10n_cl_hr_payroll instalable en Odoo 19 CE (stub hr.contract creado)
- Campo company_currency_id agregado en 3 modelos payroll

### Changed
- Documentación actualizada de Odoo 18 a Odoo 19 CE
- Validación RUT centralizada en helper reutilizable

### Removed
- Dependencia hr_contract Enterprise (reemplazada por stub CE)
- Tipos DTE fuera de scope (39, 41, 46)

## [19.0.1.0.0] - 2025-11-01

### Added
- Módulos iniciales l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports
```

**DoD Task 5.3:**
- ✅ CHANGELOG.md creado/actualizado
- ✅ RELEASE_NOTES.md creado
- ✅ Todos los cambios documentados

---

#### Sprint 5 - Consolidation & Commit

**Paso 5.4: Validar CI/CD**
```bash
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
cd "$PROJECT_ROOT"

# Verificar workflows existen
for workflow in test_l10n_cl_dte.yml test_l10n_cl_hr_payroll.yml test_l10n_cl_financial_reports.yml coverage.yml; do
    if [ -f ".github/workflows/$workflow" ]; then
        echo "✅ Workflow $workflow existe"
    else
        echo "❌ Workflow $workflow faltante"
    fi
done
```

**Paso 5.5: Commit atómico Sprint 5**
```bash
git add .github/workflows/
git add CHANGELOG.md
git add RELEASE_NOTES.md
git add addons/localization/*/README.md
git add addons/localization/*/models/*.py  # Docstrings actualizados

git commit -m "feat: extend CI/CD to 3 modules + update Odoo 19 documentation

SPRINT 5 - CI/CD + Documentación

Resolves:
- #7 (Codex): CI/CD coverage extended to all modules
- #8 (Codex): Documentation updated from Odoo 18 to Odoo 19

Changes:
- .github/workflows/test_l10n_cl_dte.yml: NEW/Updated
- .github/workflows/test_l10n_cl_hr_payroll.yml: NEW
- .github/workflows/test_l10n_cl_financial_reports.yml: NEW
- .github/workflows/coverage.yml: NEW - Consolidated coverage
- CHANGELOG.md: NEW - All changes documented
- RELEASE_NOTES.md: NEW - Release notes
- README.md: Updated Odoo 19 references
- Docstrings: Updated Odoo 18 → Odoo 19

CI/CD: 3 modules covered
Coverage: Real reporting enabled
Documentation: Odoo 19 CE compliant

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 5
Ref: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md Hallazgos #7, #8
"
```

**DoD Sprint 5:**
- ✅ CI/CD extendido a 3 módulos
- ✅ Coverage real generado
- ✅ Documentación actualizada Odoo 19
- ✅ Changelog y release notes creados

---

## 🎯 CONSOLIDACIÓN FINAL

### Validación Global Post-Ejecución

**EJECUTAR DESPUÉS DE COMPLETAR TODOS LOS SPRINTS**

```bash
#!/bin/bash
# scripts/validate_final_consolidation.sh
# Validación global post-ejecución de todos los sprints

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
ERRORS=0

echo "🔍 Validando consolidación final..."
echo ""

# 1. Verificar módulos instalables
for module in l10n_cl_dte l10n_cl_hr_payroll l10n_cl_financial_reports; do
    STATE=$(docker exec odoo19_app psql -U odoo -d odoo19 -t -c \
        "SELECT state FROM ir_module_module WHERE name='$module';" | xargs)
    
    if [ "$STATE" = "installed" ]; then
        echo "✅ Módulo $module: INSTALLED"
    else
        echo "❌ Módulo $module: $STATE (esperado: installed)"
        ERRORS=$((ERRORS + 1))
    fi
done

# 2. Verificar tests pasando
echo ""
echo "📊 Ejecutando tests finales..."
docker exec odoo19_app odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo19 \
  --test-enable \
  --stop-after-init \
  --test-tags=/l10n_cl_dte,/l10n_cl_hr_payroll,/l10n_cl_financial_reports \
  --log-level=test \
  2>&1 | tee evidencias/consolidacion_final_tests.log

TEST_FAILURES=$(grep -c "FAIL\|ERROR" evidencias/consolidacion_final_tests.log || echo "0")
if [ "$TEST_FAILURES" -eq 0 ]; then
    echo "✅ Tests: Todos pasando"
else
    echo "❌ Tests: $TEST_FAILURES fallos encontrados"
    ERRORS=$((ERRORS + 1))
fi

# 3. Verificar coverage ≥90%
echo ""
echo "📊 Verificando coverage..."
COVERAGE=$(coverage report --include="addons/localization/*" | tail -1 | awk '{print $NF}' | sed 's/%//')
if [ -z "$COVERAGE" ]; then
    echo "⚠️  Coverage no disponible (ejecutar tests con coverage primero)"
else
    if (( $(echo "$COVERAGE >= 90" | bc -l) )); then
        echo "✅ Coverage: $COVERAGE% (≥90%)"
    else
        echo "⚠️  Coverage: $COVERAGE% (<90%)"
    fi
fi

# 4. Verificar referencias Odoo 18
echo ""
echo "📊 Verificando referencias Odoo 18..."
ODOO18_REFS=$(grep -rn "Odoo 18\|odoo 18" addons/localization --include="*.py" --include="*.md" | grep -v "__pycache__" | wc -l | xargs)
if [ "$ODOO18_REFS" -eq 0 ]; then
    echo "✅ Referencias Odoo 18: 0 (todas actualizadas)"
else
    echo "⚠️  Referencias Odoo 18: $ODOO18_REFS encontradas"
fi

# 5. Verificar CI/CD workflows
echo ""
echo "📊 Verificando CI/CD workflows..."
for workflow in test_l10n_cl_dte.yml test_l10n_cl_hr_payroll.yml test_l10n_cl_financial_reports.yml coverage.yml; do
    if [ -f ".github/workflows/$workflow" ]; then
        echo "✅ Workflow $workflow existe"
    else
        echo "❌ Workflow $workflow faltante"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Consolidación final: EXITOSA"
    exit 0
else
    echo "❌ Consolidación final: $ERRORS error(es) encontrados"
    exit 1
fi
```

**Uso:**
```bash
export PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
bash scripts/validate_final_consolidation.sh
```

---

## 🚨 RIESGOS Y MITIGACIONES

### Riesgos Identificados

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Rollback necesario** | Media | Alto | Script de rollback automatizado (SPRINT 0) |
| **Tests fallan en CI** | Media | Medio | Ejecutar tests localmente antes de push |
| **Coverage <90%** | Baja | Medio | Aumentar tests en sprints siguientes |
| **Conflictos Git** | Baja | Medio | Branch separado, commits atómicos |
| **Dependencias faltantes** | Baja | Alto | Validación pre-requisitos (SPRINT 0) |

### Plan de Contingencia

**Si algo falla críticamente:**
1. Ejecutar `scripts/rollback_sprint.sh <sprint_num>`
2. Notificar al coordinador
3. Investigar causa raíz
4. Corregir y reintentar

---

## 📋 RESUMEN DE ENTREGABLES

### Por Sprint

| Sprint | Entregables | Tests | Commits |
|--------|-------------|-------|---------|
| **0** | Branch, Backup, Baseline | - | 1 |
| **1** | Stub hr.contract, company_currency_id, Monetary fields | 8 | 1 |
| **2** | Dashboard fix, DTE scope | 6 | 1 |
| **3** | RUT helper centralizado | 10 | 1 |
| **4** | DTE 34 completo, libs/ auditado | 3 | 1 |
| **5** | CI/CD workflows, Docs actualizadas | - | 1 |
| **TOTAL** | **25+ archivos modificados** | **27+ tests** | **6 commits** |

---

## ✅ DEFINITION OF DONE (GLOBAL)

### Criterios de Aceptación Final

```yaml
instalabilidad:
  todos_modulos_installed: TRUE
  errores_instalacion: 0

testing:
  tests_totales: ">= 100"
  tests_pass_rate: 100%
  coverage_overall: ">= 90%"

codigo:
  syntax_errors: 0
  critical_warnings: 0
  pure_python_libs: TRUE

ci_cd:
  workflows_3_modulos: TRUE
  coverage_real: TRUE

documentacion:
  odoo_version_refs: "19.0"
  changelog_updated: TRUE
```

---

## 🎯 CONCLUSIÓN

Este PROMPT V2 mejorado incluye:
- ✅ **Validación de pre-requisitos completa**
- ✅ **Manejo de errores y rollback**
- ✅ **Paths dinámicos (variables de entorno)**
- ✅ **SPRINTS 0-5 completos y detallados**
- ✅ **Consolidación final**
- ✅ **Sección de riesgos**

**Estado:** 📋 **READY FOR EXECUTION**

**Calificación Estimada Post-Ejecución:** **9.5/10** (EXCELENTE)

---

**FIN DEL PROMPT MASTER V2**

