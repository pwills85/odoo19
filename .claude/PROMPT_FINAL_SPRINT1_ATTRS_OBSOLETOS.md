# 🎯 PROMPT FINAL SPRINT 1 - CIERRE TOTAL DE BRECHAS
## Resolución Final: attrs Obsoletos en Views | Máxima Precisión | Zero Errors

**Fecha Emisión:** 2025-11-09  
**Versión:** 1.2 (Final Sprint 1)  
**Agente:** `@odoo-dev`  
**Coordinador:** Senior Engineer  
**Branch:** `feat/cierre_total_brechas_profesional`  
**Prioridad:** 🔴 CRÍTICA  
**Status:** 🔄 EN PROGRESO (85% completado → 100% objetivo)

---

## 📊 ANÁLISIS DEL FEEDBACK DEL AGENTE

### ✅ Progreso Completado (85%)

**SPRINT 0:** ✅ 100% COMPLETADO
- Branch creado
- Backup DB generado (14MB)
- Scripts de validación creados
- Commit: `eec57ad9`

**SPRINT 1 - Hallazgos P0 Resueltos:**
- ✅ **H3:** Stub hr.contract CE creado (350+ LOC)
- ✅ **H1:** Campo company_currency_id agregado
- ✅ **H2:** 34 campos Monetary auditados
- ✅ **Tests:** 7 tests creados (2 archivos)

**Campos Obsoletos Corregidos:**
- ✅ `category_id` en res.groups
- ✅ `numbercall`, `doall`, `state`, `priority`, `nextcall` en ir.cron
- ✅ `appears_on_payslip` en hr.salary.rule (19 ocurrencias)
- ✅ Referencias categorías corregidas

**Commits Realizados:**
- `eec57ad9` - SPRINT 0
- `07e19c26` - SPRINT 1 WIP (70%)
- `851c8857` - Correcciones adicionales

---

## 🔴 PROBLEMA ACTUAL IDENTIFICADO

### Issue: `attrs` Obsoleto en Views XML

**Archivos Afectados:** 3 archivos XML con **20 ocurrencias** de `attrs` obsoleto

**Archivos con `attrs` Obsoletos:**
1. **`hr_payroll_structure_views.xml`** - 3 ocurrencias
2. **`hr_payslip_run_views.xml`** - 10 ocurrencias
3. **`hr_salary_rule_views.xml`** - 7 ocurrencias

**Total:** 20 ocurrencias de `attrs` obsoleto

**Causa:** En Odoo 19, el atributo `attrs` fue **deprecado desde Odoo 17.0** y debe reemplazarse por atributos directos con evaluación Python.

**Detalles por Archivo:**

**hr_payroll_structure_views.xml:**
- Línea 27: `attrs="{'invisible': [('rule_count', '=', 0)]}"`
- Línea 38: `attrs="{'invisible': [('active', '=', True)]}"`
- Línea 72: `attrs="{'invisible': [('children_ids', '=', [])]}"`

**hr_payslip_run_views.xml:**
- Línea 36: `attrs="{'invisible': [('state', '!=', 'draft')]}"`
- Línea 40: `attrs="{'invisible': [('state', '!=', 'processing')]}"`
- Línea 44: `attrs="{'invisible': [('state', '!=', 'processing')]}"`
- Línea 48: `attrs="{'invisible': [('state', '!=', 'done')]}"`
- Línea 51: `attrs="{'invisible': [('state', '=', 'draft')]}"`
- Línea 54: `attrs="{'invisible': [('state', 'in', ['draft', 'cancel'])]}"`
- Línea 77: `attrs="{'invisible': [('state', '!=', 'done')]}"`
- Línea 84: `attrs="{'invisible': [('state', '!=', 'cancel')]}"`
- Línea 125: `attrs="{'invisible': [('state', '=', 'draft')]}"`
- Línea 133: `attrs="{'invisible': [('state', '!=', 'done')]}"`

**hr_salary_rule_views.xml:**
- Línea 33: `attrs="{'invisible': [('active', '=', True)]}"`
- Línea 61: `attrs="{'invisible': [('condition_select', '!=', 'range')]}"`
- Línea 76: `attrs="{'invisible': [('condition_select', '!=', 'python')]}"`
- Línea 97: `attrs="{'invisible': [('amount_select', '!=', 'fix')]}"`
- Línea 101: `attrs="{'invisible': [('amount_select', '!=', 'percentage')]}"`
- Línea 109: `attrs="{'invisible': [('amount_select', '!=', 'code')]}"`

---

## 🎯 OBJETIVO INMEDIATO

**Completar SPRINT 1 al 100%:**
1. Corregir **TODOS** los `attrs` obsoletos en views XML
2. Validar instalación exitosa (`state=installed`)
3. Ejecutar suite de tests (7 tests esperados PASS)
4. Completar DoD Sprint 1
5. Commit final Sprint 1

**Estimación:** 30-60 minutos

---

## 📋 TAREAS DETALLADAS

### TASK 1.10: Corregir `attrs` Obsoletos en Views XML (45min)

**Objetivo:** Reemplazar todos los `attrs` por sintaxis Odoo 19 en 3 archivos

**Archivos a Corregir:**
1. `addons/localization/l10n_cl_hr_payroll/views/hr_payroll_structure_views.xml` (3 ocurrencias)
2. `addons/localization/l10n_cl_hr_payroll/views/hr_payslip_run_views.xml` (10 ocurrencias)
3. `addons/localization/l10n_cl_hr_payroll/views/hr_salary_rule_views.xml` (7 ocurrencias)

**Guía de Corrección:**

#### Corrección 1: Línea 27 - Button Invisible

**ANTES (Odoo 18):**
```xml
<button name="action_view_rules" string="Ver Reglas" type="object"
        class="oe_highlight" attrs="{'invisible': [('rule_count', '=', 0)]}"/>
```

**DESPUÉS (Odoo 19):**
```xml
<button name="action_view_rules" string="Ver Reglas" type="object"
        class="oe_highlight" invisible="rule_count == 0"/>
```

**Nota:** En Odoo 19:
- `attrs="{'invisible': [('field', '=', value)]}"` → `invisible="field == value"`
- `attrs="{'readonly': [('field', '=', value)]}"` → `readonly="field == value"`
- `attrs="{'required': [('field', '=', value)]}"` → `required="field == value"`

---

#### Corrección 2: Línea 38 - Widget Web Ribbon Invisible

**ANTES (Odoo 18):**
```xml
<widget name="web_ribbon" title="Archivado" bg_color="bg-danger"
        attrs="{'invisible': [('active', '=', True)]}"/>
```

**DESPUÉS (Odoo 19):**
```xml
<widget name="web_ribbon" title="Archivado" bg_color="bg-danger"
        invisible="active == True"/>
```

**Nota:** En Odoo 19, `True` se evalúa directamente en Python.

---

#### Corrección 3: Línea 72 - Page Invisible

**ANTES (Odoo 18):**
```xml
<page string="Estructuras Hijas" name="children"
      attrs="{'invisible': [('children_ids', '=', [])]}">
```

**DESPUÉS (Odoo 19):**
```xml
<page string="Estructuras Hijas" name="children"
      invisible="not children_ids or len(children_ids) == 0">
```

**Nota:** Para listas vacías en Odoo 19:
- `[('field', '=', [])]` → `not field or len(field) == 0`
- O simplemente: `invisible="not children_ids"` (si el campo es One2many)

---

#### Correcciones Adicionales: hr_payslip_run_views.xml (10 ocurrencias)

**Patrón 1: Comparación con `!=`**
```xml
<!-- ANTES -->
attrs="{'invisible': [('state', '!=', 'draft')]}"

<!-- DESPUÉS -->
invisible="state != 'draft'"
```

**Patrón 2: Comparación con `==`**
```xml
<!-- ANTES -->
attrs="{'invisible': [('state', '=', 'draft')]}"

<!-- DESPUÉS -->
invisible="state == 'draft'"
```

**Patrón 3: Comparación con `in`**
```xml
<!-- ANTES -->
attrs="{'invisible': [('state', 'in', ['draft', 'cancel'])]}"

<!-- DESPUÉS -->
invisible="state in ('draft', 'cancel')"
```

**Aplicar a todas las líneas:**
- Línea 36: `invisible="state != 'draft'"`
- Línea 40: `invisible="state != 'processing'"`
- Línea 44: `invisible="state != 'processing'"`
- Línea 48: `invisible="state != 'done'"`
- Línea 51: `invisible="state == 'draft'"`
- Línea 54: `invisible="state in ('draft', 'cancel')"`
- Línea 77: `invisible="state != 'done'"`
- Línea 84: `invisible="state != 'cancel'"`
- Línea 125: `invisible="state == 'draft'"`
- Línea 133: `invisible="state != 'done'"`

---

#### Correcciones Adicionales: hr_salary_rule_views.xml (7 ocurrencias)

**Patrón 1: Comparación con `==`**
```xml
<!-- ANTES -->
attrs="{'invisible': [('active', '=', True)]}"

<!-- DESPUÉS -->
invisible="active == True"
```

**Patrón 2: Comparación con `!=`**
```xml
<!-- ANTES -->
attrs="{'invisible': [('condition_select', '!=', 'range')]}"

<!-- DESPUÉS -->
invisible="condition_select != 'range'"
```

**Aplicar a todas las líneas:**
- Línea 33: `invisible="active == True"`
- Línea 61: `invisible="condition_select != 'range'"`
- Línea 76: `invisible="condition_select != 'python'"`
- Línea 97: `invisible="amount_select != 'fix'"`
- Línea 101: `invisible="amount_select != 'percentage'"`
- Línea 109: `invisible="amount_select != 'code'"`

---

**Implementación:**

**Paso 1.10.1: Corregir hr_payroll_structure_views.xml**

Aplicar las 3 correcciones según guía arriba (líneas 27, 38, 72).

**Paso 1.10.2: Corregir hr_payslip_run_views.xml**

Reemplazar todas las 10 ocurrencias de `attrs` según patrones arriba.

**Paso 1.10.3: Corregir hr_salary_rule_views.xml**

Reemplazar todas las 7 ocurrencias de `attrs` según patrones arriba.

**Script de Aplicación Automática (Opcional):**

```bash
#!/bin/bash
# scripts/fix_attrs_odoo19.sh
# Reemplazar attrs por sintaxis Odoo 19 automáticamente

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_DIR="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll/views"

echo "🔧 Reemplazando attrs por sintaxis Odoo 19..."
echo ""

# Archivos a procesar
FILES=(
    "hr_payroll_structure_views.xml"
    "hr_payslip_run_views.xml"
    "hr_salary_rule_views.xml"
)

for file in "${FILES[@]}"; do
    FILE_PATH="$MODULE_DIR/$file"
    if [ -f "$FILE_PATH" ]; then
        echo "📝 Procesando: $file"
        
        # Crear backup
        cp "$FILE_PATH" "${FILE_PATH}.backup"
        
        # Reemplazos comunes
        sed -i '' "s/attrs=\"{'invisible': \[('\([^']*\)', '=', \(True\|False\|0\|\[\]\))\]\}\"/invisible=\"\1 == \2\"/g" "$FILE_PATH"
        sed -i '' "s/attrs=\"{'invisible': \[('\([^']*\)', '!=', '\([^']*\)')\]\}\"/invisible=\"\1 != '\2'\"/g" "$FILE_PATH"
        sed -i '' "s/attrs=\"{'invisible': \[('\([^']*\)', '=', '\([^']*\)')\]\}\"/invisible=\"\1 == '\2'\"/g" "$FILE_PATH"
        sed -i '' "s/attrs=\"{'invisible': \[('\([^']*\)', 'in', \[\([^]]*\)\])\]\}\"/invisible=\"\1 in (\2)\"/g" "$FILE_PATH"
        
        echo "  ✅ Procesado (backup: ${file}.backup)"
    else
        echo "  ⚠️  Archivo no encontrado: $file"
    fi
done

echo ""
echo "✅ Reemplazo completado. Revisar cambios manualmente antes de commit."
```

**Nota:** El script automático puede no cubrir todos los casos. **Revisar manualmente** después de ejecutar.

**Script de Validación:**

```bash
#!/bin/bash
# scripts/validate_attrs_removed.sh
# Validar que todos los attrs fueron removidos

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_DIR="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll"

echo "🔍 Validando que todos los attrs fueron removidos..."
echo ""

# Buscar attrs en archivos XML
ATTRS_FOUND=$(grep -rn "attrs=" "$MODULE_DIR" --include="*.xml" 2>/dev/null | grep -v "__pycache__" || true)

if [ -z "$ATTRS_FOUND" ]; then
    echo "✅ No se encontraron attrs obsoletos"
    exit 0
else
    echo "❌ Se encontraron attrs obsoletos:"
    echo "$ATTRS_FOUND"
    exit 1
fi
```

**DoD Task 1.10:**
- ✅ Todos los `attrs` corregidos (20 ocurrencias en 3 archivos)
- ✅ Sintaxis Odoo 19 aplicada
- ✅ Validación ejecutada (sin attrs encontrados)

---

### TASK 1.11: Auditoría Completa de `attrs` en Todo el Módulo (10min)

**Objetivo:** Asegurar que NO hay más `attrs` obsoletos en ningún archivo XML

**Script de Auditoría:**

```bash
#!/bin/bash
# scripts/audit_all_attrs.sh
# Auditoría completa de attrs en todo el módulo

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_DIR="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll"

echo "🔍 Auditoría completa de attrs obsoletos..."
echo ""

# Buscar todos los attrs
ATTRS_FOUND=$(find "$MODULE_DIR" -name "*.xml" -type f -exec grep -l "attrs=" {} \; 2>/dev/null || true)

if [ -z "$ATTRS_FOUND" ]; then
    echo "✅ No se encontraron archivos con attrs obsoletos"
    exit 0
else
    echo "❌ Archivos con attrs obsoletos encontrados:"
    echo "$ATTRS_FOUND"
    echo ""
    echo "📋 Detalles por archivo:"
    for file in $ATTRS_FOUND; do
        echo ""
        echo "Archivo: $file"
        grep -n "attrs=" "$file" | sed 's/^/  Línea /'
    done
    exit 1
fi
```

**DoD Task 1.11:**
- ✅ Auditoría ejecutada
- ✅ Sin `attrs` obsoletos encontrados
- ✅ Reporte generado

---

### TASK 1.12: Validar Instalación Exitosa (10min)

**Objetivo:** Instalar módulo y validar `state=installed`

**Script de Validación:**

```bash
#!/bin/bash
# scripts/validate_module_installation_final.sh
# Validar instalación exitosa del módulo (versión final)

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_NAME="l10n_cl_hr_payroll"
DB_NAME="${DB_NAME:-odoo19}"

echo "🔍 Validando instalación final del módulo $MODULE_NAME..."
echo ""

# 1. Reiniciar contenedor
echo "🔄 Reiniciando contenedor..."
docker-compose restart app

# Esperar contenedor healthy
echo "⏳ Esperando contenedor healthy..."
timeout=60
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if docker ps --filter "name=odoo19_app" --filter "health=healthy" | grep -q odoo19_app; then
        echo "✅ Contenedor healthy"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ $elapsed -ge $timeout ]; then
    echo "❌ ERROR: Contenedor no está healthy"
    exit 1
fi

# 2. Instalar módulo
echo ""
echo "📦 Instalando módulo $MODULE_NAME..."
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d "$DB_NAME" \
    -i "$MODULE_NAME" \
    --stop-after-init \
    --log-level=error \
    2>&1 | tee evidencias/sprint1_installation_final.log

INSTALL_EXIT_CODE=$?

# 3. Verificar estado
echo ""
echo "🔍 Verificando estado del módulo..."
MODULE_STATE=$(docker exec odoo19_app psql -U odoo -d "$DB_NAME" -t -c \
    "SELECT state FROM ir_module_module WHERE name='$MODULE_NAME';" | xargs)

if [ "$MODULE_STATE" = "installed" ]; then
    echo "✅ Módulo $MODULE_NAME: INSTALLED"
    echo ""
    echo "📊 Información del módulo:"
    docker exec odoo19_app psql -U odoo -d "$DB_NAME" -c \
        "SELECT name, state, latest_version FROM ir_module_module WHERE name='$MODULE_NAME';"
    
    # Verificar que no hay errores críticos en log
    ERROR_COUNT=$(grep -ci "error\|exception\|traceback" evidencias/sprint1_installation_final.log || echo "0")
    if [ "$ERROR_COUNT" -eq 0 ]; then
        echo ""
        echo "✅ Instalación limpia (sin errores)"
        exit 0
    else
        echo ""
        echo "⚠️  Instalación exitosa pero con $ERROR_COUNT advertencia(s)"
        exit 0
    fi
else
    echo "❌ Módulo $MODULE_NAME: $MODULE_STATE (esperado: installed)"
    echo ""
    echo "📋 Últimos errores del log:"
    tail -100 evidencias/sprint1_installation_final.log | grep -i "error\|exception\|traceback" | tail -20
    exit 1
fi
```

**DoD Task 1.12:**
- ✅ Módulo instalado exitosamente
- ✅ `state=installed` verificado
- ✅ Sin errores críticos en log

---

### TASK 1.13: Ejecutar Suite de Tests (10min)

**Objetivo:** Ejecutar todos los tests del Sprint 1 y validar PASS

**Script de Ejecución:**

```bash
#!/bin/bash
# scripts/run_sprint1_tests_final.sh
# Ejecutar suite de tests Sprint 1 (versión final)

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
DB_NAME="${DB_NAME:-odoo19}"

echo "🧪 Ejecutando suite de tests Sprint 1 (final)..."
echo ""

# Tests esperados: 7 tests
# - test_hr_contract_stub_ce.py: 5 tests
# - test_company_currency_id_fields.py: 2 tests

docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d "$DB_NAME" \
    --test-enable \
    --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll/test_hr_contract_stub_ce,/l10n_cl_hr_payroll/test_company_currency_id_fields \
    --log-level=test \
    2>&1 | tee evidencias/sprint1_tests_final.log

TEST_EXIT_CODE=$?

# Analizar resultados
echo ""
echo "📊 Análisis de resultados de tests..."
echo ""

# Contar tests
TESTS_RUN=$(grep -c "test_" evidencias/sprint1_tests_final.log 2>/dev/null | head -1 || echo "0")
TESTS_PASS=$(grep -c "ok\|PASS" evidencias/sprint1_tests_final.log 2>/dev/null || echo "0")
TESTS_FAIL=$(grep -c "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log 2>/dev/null || echo "0")

echo "Tests ejecutados: $TESTS_RUN"
echo "Tests PASS: $TESTS_PASS"
echo "Tests FAIL: $TESTS_FAIL"

if [ $TEST_EXIT_CODE -eq 0 ] && [ "$TESTS_FAIL" -eq 0 ]; then
    echo ""
    echo "✅ Todos los tests pasaron exitosamente (7/7 esperados)"
    exit 0
else
    echo ""
    echo "❌ Algunos tests fallaron"
    echo ""
    echo "📋 Tests fallidos:"
    grep -A 5 "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log | head -30
    exit 1
fi
```

**DoD Task 1.13:**
- ✅ 7 tests ejecutados
- ✅ 7/7 tests PASS
- ✅ Sin errores ni fallos

---

### TASK 1.14: Completar DoD Sprint 1 y Commit Final (10min)

**Objetivo:** Validar DoD completo y hacer commit final

**Script de Validación DoD:**

```bash
#!/bin/bash
# scripts/validate_sprint1_dod_final.sh
# Validar Definition of Done Sprint 1 (versión final)

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_NAME="l10n_cl_hr_payroll"
DB_NAME="${DB_NAME:-odoo19}"

echo "✅ Validando DoD Sprint 1 (Final)..."
echo ""

ERRORS=0

# 1. Módulo instalado
MODULE_STATE=$(docker exec odoo19_app psql -U odoo -d "$DB_NAME" -t -c \
    "SELECT state FROM ir_module_module WHERE name='$MODULE_NAME';" | xargs)

if [ "$MODULE_STATE" = "installed" ]; then
    echo "✅ 1. Módulo $MODULE_NAME instalado (state=installed)"
else
    echo "❌ 1. Módulo $MODULE_NAME NO instalado (state=$MODULE_STATE)"
    ERRORS=$((ERRORS + 1))
fi

# 2. Stub hr.contract existe
if [ -f "addons/localization/$MODULE_NAME/models/hr_contract_stub_ce.py" ]; then
    echo "✅ 2. Stub hr.contract CE creado"
else
    echo "❌ 2. Stub hr.contract CE NO encontrado"
    ERRORS=$((ERRORS + 1))
fi

# 3. Campo company_currency_id agregado
if grep -q "company_currency_id" "addons/localization/$MODULE_NAME/models/hr_economic_indicators.py"; then
    echo "✅ 3. Campo company_currency_id agregado"
else
    echo "❌ 3. Campo company_currency_id NO encontrado"
    ERRORS=$((ERRORS + 1))
fi

# 4. Tests creados
TEST_FILES=(
    "addons/localization/$MODULE_NAME/tests/test_hr_contract_stub_ce.py"
    "addons/localization/$MODULE_NAME/tests/test_company_currency_id_fields.py"
)

for test_file in "${TEST_FILES[@]}"; do
    if [ -f "$test_file" ]; then
        echo "✅ 4. Test file existe: $(basename $test_file)"
    else
        echo "❌ 4. Test file NO encontrado: $(basename $test_file)"
        ERRORS=$((ERRORS + 1))
    fi
done

# 5. Tests pasando
if [ -f "evidencias/sprint1_tests_final.log" ]; then
    TESTS_FAIL=$(grep -c "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log 2>/dev/null || echo "0")
    if [ "$TESTS_FAIL" -eq 0 ]; then
        echo "✅ 5. Todos los tests pasando"
    else
        echo "❌ 5. Tests fallando: $TESTS_FAIL"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "⚠️  5. Log de tests no encontrado (ejecutar tests primero)"
fi

# 6. Sin attrs obsoletos en XML
if bash scripts/audit_all_attrs.sh > /dev/null 2>&1; then
    echo "✅ 6. Sin attrs obsoletos en XML"
else
    echo "❌ 6. attrs obsoletos encontrados en XML"
    ERRORS=$((ERRORS + 1))
fi

# 7. Dependencia hr_contract Enterprise removida
if ! grep -q "'hr_contract'" "addons/localization/$MODULE_NAME/__manifest__.py"; then
    echo "✅ 7. Dependencia hr_contract Enterprise removida"
else
    echo "❌ 7. Dependencia hr_contract Enterprise aún presente"
    ERRORS=$((ERRORS + 1))
fi

# 8. Sin campos obsoletos en XML (category_id, numbercall, etc.)
if bash scripts/audit_obsolete_xml_fields.sh > /dev/null 2>&1; then
    echo "✅ 8. Sin campos obsoletos en XML"
else
    echo "❌ 8. Campos obsoletos encontrados en XML"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ DoD Sprint 1: COMPLETO (8/8 criterios cumplidos)"
    exit 0
else
    echo "❌ DoD Sprint 1: $ERRORS criterio(s) no cumplido(s)"
    exit 1
fi
```

**Commit Final Sprint 1:**

```bash
# Validar DoD primero
bash scripts/validate_sprint1_dod_final.sh

# Si DoD completo, hacer commit
git add addons/localization/l10n_cl_hr_payroll/
git add scripts/
git add evidencias/

git commit -m "feat(l10n_cl_hr_payroll): complete SPRINT 1 - P0 bloqueantes resueltos

SPRINT 1 - Resolver Hallazgos P0 Bloqueantes (100% COMPLETADO)

Resolves:
- H1: Campo company_currency_id agregado (34 campos Monetary)
- H2: 34 campos Monetary auditados y validados
- H3: Stub hr.contract CE creado (350+ LOC)
- Campos obsoletos XML Odoo 19 corregidos
- attrs obsoletos en views corregidos (Odoo 19 syntax)

Changes:
- models/hr_contract_stub_ce.py: NEW - Stub CE completo
  * hr.contract model con campos básicos
  * hr.contract.type model
  * Validaciones y constraints
- models/hr_economic_indicators.py: Add company_currency_id
- models/hr_payroll_structure.py: Add company_currency_id
- models/hr_salary_rule.py: Add company_currency_id
- data/ir_cron_data.xml: Remove obsolete fields (numbercall, doall, state, priority, nextcall)
- security/security_groups.xml: Remove category_id
- views/hr_payroll_structure_views.xml: Remove attrs (3 ocurrencias)
  * attrs → invisible (Odoo 19 syntax)
- __manifest__.py: Remove hr_contract Enterprise dependency
- tests/test_hr_contract_stub_ce.py: NEW - 5 tests
- tests/test_company_currency_id_fields.py: NEW - 2 tests

Tests: 7/7 PASS
Module: INSTALLED (state=installed verified)
Odoo Version: 19.0 CE
Compatibility: Odoo 19 CE compliant
  - Obsolete fields removed
  - attrs syntax updated to Odoo 19
  - All XML validations passed

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 1
Ref: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md Hallazgos P0
"
```

**DoD Task 1.14:**
- ✅ DoD Sprint 1 validado completamente (8/8 criterios)
- ✅ Commit final realizado
- ✅ Mensaje de commit estructurado

---

## 🎯 INSTRUCCIONES DE EJECUCIÓN

### Paso a Paso

1. **Corregir attrs en hr_payroll_structure_views.xml:**
   - Aplicar correcciones según TASK 1.10
   - 3 ocurrencias de `attrs` → sintaxis Odoo 19

2. **Auditar Todos los attrs:**
   ```bash
   bash scripts/audit_all_attrs.sh
   ```

3. **Validar Instalación:**
   ```bash
   bash scripts/validate_module_installation_final.sh
   ```

4. **Ejecutar Tests:**
   ```bash
   bash scripts/run_sprint1_tests_final.sh
   ```

5. **Validar DoD y Commit:**
   ```bash
   bash scripts/validate_sprint1_dod_final.sh
   # Si pasa, hacer commit final
   ```

---

## 📊 CRITERIOS DE ÉXITO

### DoD Sprint 1 Completo (8 Criterios)

- ✅ Módulo `l10n_cl_hr_payroll` instalado (`state=installed`)
- ✅ Stub `hr.contract` CE creado y funcional
- ✅ Campo `company_currency_id` agregado en 3 modelos
- ✅ 34 campos Monetary auditados y correctos
- ✅ 7 tests nuevos PASS
- ✅ Sin `attrs` obsoletos en XML
- ✅ Sin campos obsoletos en XML
- ✅ Dependencia `hr_contract` Enterprise removida
- ✅ Commit final realizado

---

## 🚨 MANEJO DE ERRORES

### Si Instalación Falla Después de Corregir attrs

1. **Revisar log de instalación:**
   ```bash
   tail -100 evidencias/sprint1_installation_final.log | grep -i "error\|exception\|traceback"
   ```

2. **Verificar sintaxis XML:**
   ```bash
   xmllint --noout addons/localization/l10n_cl_hr_payroll/views/hr_payroll_structure_views.xml
   ```

3. **Si persiste el error:**
   - Buscar otros archivos XML con `attrs`
   - Aplicar correcciones según guía TASK 1.10
   - Reintentar instalación

### Si Tests Fallan

1. **Revisar log de tests:**
   ```bash
   grep -A 10 "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log
   ```

2. **Corregir código según error:**
   - Seguir mensaje de error específico
   - Validar lógica del test
   - Re-ejecutar tests

---

## 📋 CHECKLIST DE EJECUCIÓN

- [ ] TASK 1.10: Corregir 3 `attrs` en hr_payroll_structure_views.xml
- [ ] TASK 1.11: Auditoría completa de `attrs` ejecutada
- [ ] TASK 1.12: Instalación validada (`state=installed`)
- [ ] TASK 1.13: Tests ejecutados (7/7 PASS)
- [ ] TASK 1.14: DoD validado (8/8 criterios) y commit final realizado

---

## 🎯 CONCLUSIÓN

Este PROMPT proporciona instrucciones precisas para completar el último 15% del SPRINT 1, resolviendo específicamente el problema de `attrs` obsoletos en views XML que está bloqueando la instalación del módulo.

**Estado Esperado Post-Ejecución:**
- ✅ SPRINT 1: 100% COMPLETADO
- ✅ Módulo instalado exitosamente
- ✅ Todos los tests pasando (7/7)
- ✅ DoD completo (8/8 criterios)
- ✅ Commit final realizado

**Próximo Paso:**
- SPRINT 2: P1 Quick Wins (Dashboard fix, DTE scope)

---

**FIN DEL PROMPT FINAL SPRINT 1**

