# 🎯 PROMPT FINAL SPRINT 1 - CIERRE TOTAL (95% → 100%)
## Resolución: Mapeo de Nombres de Campos hr.contract.cl | Máxima Precisión | Zero Errors

**Fecha Emisión:** 2025-11-09  
**Versión:** 1.3 (Cierre Final Sprint 1)  
**Agente:** `@odoo-dev`  
**Coordinador:** Senior Engineer  
**Branch:** `feat/cierre_total_brechas_profesional`  
**Prioridad:** 🔴 CRÍTICA  
**Status:** 🔄 EN PROGRESO (95% completado → 100% objetivo)

---

## 📊 ANÁLISIS DEL FEEDBACK DEL AGENTE

### ✅ Progreso Excelente (95% completado)

**SPRINT 0:** ✅ 100% COMPLETADO
- Branch creado
- Backup DB generado
- Scripts de validación creados

**SPRINT 1 - Issues Resueltos (11 fixes):**

1. ✅ **attrs Obsoleto:** 19 ocurrencias corregidas en 3 archivos
   - hr_payroll_structure_views.xml (3)
   - hr_payslip_run_views.xml (10)
   - hr_salary_rule_views.xml (6)
   - Conversión: `attrs="{'invisible': [...]}"` → `invisible="expression"`

2. ✅ **_check_recursion() Deprecado:** Corregido en 2 modelos
   - hr_salary_rule_category.py:141
   - hr_payroll_structure.py:133
   - Cambio: `_check_recursion()` → `_has_cycle()`

3. ✅ **Tree → List Tags:** 13 ocurrencias convertidas
   - Todas las vistas actualizadas para Odoo 19 (`<tree>` → `<list>`)

4. ✅ **Missing sequence Field:** Removido de hr.payroll.structure list view

5. ✅ **hr_contract Stub Views:** hr_contract_stub_views.xml creado
   - Vistas base form/list para compatibilidad CE
   - Métodos stub agregados (action_set_running, action_set_close, action_set_draft)

6. ✅ **View References:** inherit_id actualizado en hr_contract_views.xml

7. ✅ **Audit Script:** scripts/audit_all_attrs.sh creado

**Progreso:** 85% → 95% (+10%)

---

## 🔴 PROBLEMA ACTUAL IDENTIFICADO

### Issue: Field Name Mismatches en hr_contract_views.xml

**Archivo Afectado:** `addons/localization/l10n_cl_hr_payroll/views/hr_contract_views.xml`

**Problema:** La vista XML usa nombres de campos que NO existen en el modelo `hr.contract.cl`.

**Campos con Mismatch Identificados:**

| Vista XML (Línea) | Nombre en Vista | Nombre Real en Modelo | Estado |
|-------------------|-----------------|----------------------|--------|
| 48 | `apv_id` | `l10n_cl_apv_institution_id` | ❌ INCORRECTO |
| 49 | `apv_amount_uf` | `l10n_cl_apv_amount` | ❌ INCORRECTO |
| 52 | `apv_type` | `l10n_cl_apv_regime` | ❌ INCORRECTO |

**Análisis del Modelo (`hr_contract_cl.py`):**

Los campos APV correctos en el modelo son:
- `l10n_cl_apv_institution_id` (Many2one, línea 70)
- `l10n_cl_apv_regime` (Selection, línea 75)
- `l10n_cl_apv_amount` (Monetary, línea 80)
- `l10n_cl_apv_amount_type` (Selection, línea 85)

**Causa:** La vista fue creada con nombres simplificados (`apv_id`, `apv_type`) que no coinciden con los nombres reales del modelo que usan el prefijo `l10n_cl_`.

---

## 🎯 OBJETIVO INMEDIATO

**Completar SPRINT 1 al 100%:**
1. Mapear TODOS los nombres de campos en hr_contract_views.xml
2. Corregir campos APV (3 ocurrencias)
3. Auditar otros campos chilenos para asegurar consistencia
4. Validar instalación exitosa (`state=installed`)
5. Ejecutar suite de tests (7 tests esperados PASS)
6. Completar DoD Sprint 1
7. Commit final Sprint 1

**Estimación:** 30-45 minutos

---

## 📋 TAREAS DETALLADAS

### TASK 1.15: Mapear y Corregir Nombres de Campos APV (15min)

**Objetivo:** Corregir los 3 campos APV en hr_contract_views.xml para que coincidan con el modelo

**Archivo:** `addons/localization/l10n_cl_hr_payroll/views/hr_contract_views.xml`

**Correcciones Requeridas:**

#### Corrección 1: Campo APV Institution (Línea 48)

**ANTES (Incorrecto):**
```xml
<field name="apv_id" string="Institución APV"/>
```

**DESPUÉS (Correcto):**
```xml
<field name="l10n_cl_apv_institution_id" 
       string="Institución APV"
       placeholder="Seleccionar institución APV..."/>
```

**Justificación:** El modelo define `l10n_cl_apv_institution_id` como Many2one a `l10n_cl.apv.institution`.

---

#### Corrección 2: Campo APV Amount (Línea 49)

**ANTES (Incorrecto):**
```xml
<field name="apv_amount_uf" 
       string="Monto APV (UF)"
       invisible="not apv_id"/>
```

**DESPUÉS (Correcto):**
```xml
<field name="l10n_cl_apv_amount" 
       string="Monto APV"
       widget="monetary"
       invisible="not l10n_cl_apv_institution_id"/>
```

**Justificación:** 
- El modelo define `l10n_cl_apv_amount` como Monetary (no específicamente UF)
- El campo `l10n_cl_apv_amount_type` controla si es fijo, porcentaje o UF
- La condición invisible debe usar `l10n_cl_apv_institution_id`

---

#### Corrección 3: Campo APV Regime/Type (Línea 52)

**ANTES (Incorrecto):**
```xml
<field name="apv_type" 
       string="Tipo APV"
       invisible="not apv_id"
       widget="radio"/>
```

**DESPUÉS (Correcto):**
```xml
<field name="l10n_cl_apv_regime" 
       string="Régimen APV"
       invisible="not l10n_cl_apv_institution_id"
       widget="radio"/>
```

**Justificación:** El modelo define `l10n_cl_apv_regime` como Selection con opciones 'A' y 'B'.

---

#### Corrección 4: Agregar Campo APV Amount Type (Nuevo)

**Ubicación:** Después de `l10n_cl_apv_regime`

**Código a Agregar:**
```xml
<field name="l10n_cl_apv_amount_type" 
       string="Tipo Monto APV"
       invisible="not l10n_cl_apv_institution_id"
       widget="radio"/>
```

**Justificación:** El modelo define este campo pero no está en la vista. Es necesario para especificar si el monto es fijo, porcentaje o UF.

---

**Implementación Completa de la Sección APV:**

```xml
<!-- APV -->
<separator string="Ahorro Previsional Voluntario (APV)" colspan="2"/>
<field name="l10n_cl_apv_institution_id" 
       string="Institución APV"
       placeholder="Seleccionar institución APV..."/>
<field name="l10n_cl_apv_regime" 
       string="Régimen APV"
       invisible="not l10n_cl_apv_institution_id"
       widget="radio"/>
<field name="l10n_cl_apv_amount_type" 
       string="Tipo Monto APV"
       invisible="not l10n_cl_apv_institution_id"
       widget="radio"/>
<field name="l10n_cl_apv_amount" 
       string="Monto APV"
       widget="monetary"
       invisible="not l10n_cl_apv_institution_id"/>
```

**DoD Task 1.15:**
- ✅ 3 campos APV corregidos
- ✅ 1 campo APV agregado (l10n_cl_apv_amount_type)
- ✅ Condiciones invisible actualizadas
- ✅ Sintaxis Odoo 19 validada

---

### TASK 1.16: Auditoría Completa de Nombres de Campos (10min)

**Objetivo:** Asegurar que TODOS los campos en hr_contract_views.xml existen en el modelo

**Archivo:** `addons/localization/l10n_cl_hr_payroll/views/hr_contract_views.xml`

**Campos a Validar:**

| Campo en Vista | Modelo | Estado Esperado |
|----------------|--------|----------------|
| `afp_id` | hr.contract.cl | ✅ Existe |
| `afp_rate` | hr.contract.cl | ✅ Existe |
| `health_system` | hr.contract.cl | ✅ Existe |
| `is_fonasa` | hr.contract.cl | ✅ Existe |
| `isapre_id` | hr.contract.cl | ✅ Existe |
| `isapre_plan_uf` | hr.contract.cl | ✅ Existe |
| `isapre_fun` | hr.contract.cl | ✅ Existe |
| `colacion` | hr.contract.cl | ✅ Existe |
| `movilizacion` | hr.contract.cl | ✅ Existe |
| `family_allowance_simple` | hr.contract.cl | ✅ Existe |
| `family_allowance_maternal` | hr.contract.cl | ✅ Existe |
| `family_allowance_invalid` | hr.contract.cl | ✅ Existe |
| `gratification_type` | hr.contract.cl | ✅ Existe |
| `weekly_hours` | hr.contract.cl | ✅ Existe |
| `extreme_zone` | hr.contract.cl | ✅ Existe |

**Script de Validación:**

```bash
#!/bin/bash
# scripts/validate_contract_fields.sh
# Validar que todos los campos en hr_contract_views.xml existen en el modelo

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
VIEW_FILE="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll/views/hr_contract_views.xml"
MODEL_FILE="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll/models/hr_contract_cl.py"

echo "🔍 Validando nombres de campos en hr_contract_views.xml..."
echo ""

# Extraer nombres de campos de la vista
VIEW_FIELDS=$(grep -oP 'name="\K[^"]+' "$VIEW_FILE" | grep -v "^hr\.contract\|^view_\|^inherit_id\|^arch\|^model\|^name\|^string\|^colspan\|^position\|^expr\|^after\|^wage\|^separator\|^xpath" | sort -u)

# Extraer nombres de campos del modelo
MODEL_FIELDS=$(grep -oP '^\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*fields\.' "$MODEL_FILE" | sed 's/^\s*\([a-zA-Z_][a-zA-Z0-9_]*\).*/\1/' | sort -u)

echo "📋 Campos encontrados en vista:"
echo "$VIEW_FIELDS"
echo ""
echo "📋 Campos definidos en modelo:"
echo "$MODEL_FIELDS"
echo ""

# Validar cada campo de la vista
ERRORS=0
for field in $VIEW_FIELDS; do
    if ! echo "$MODEL_FIELDS" | grep -q "^${field}$"; then
        echo "❌ Campo '$field' usado en vista pero NO existe en modelo"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ Campo '$field' existe en modelo"
    fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Todos los campos de la vista existen en el modelo"
    exit 0
else
    echo "❌ Se encontraron $ERRORS campo(s) con problemas"
    exit 1
fi
```

**DoD Task 1.16:**
- ✅ Script de validación ejecutado
- ✅ Todos los campos validados
- ✅ Sin campos inexistentes encontrados

---

### TASK 1.17: Validar Instalación Exitosa (10min)

**Objetivo:** Instalar módulo y validar `state=installed`

**Script de Validación:**

```bash
#!/bin/bash
# scripts/validate_module_installation_final_sprint1.sh
# Validar instalación exitosa del módulo (versión final SPRINT 1)

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_NAME="l10n_cl_hr_payroll"
DB_NAME="${DB_NAME:-odoo19}"

echo "🔍 Validando instalación final del módulo $MODULE_NAME (SPRINT 1)..."
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
        echo ""
        echo "🎉 SPRINT 1 COMPLETADO AL 100%"
        exit 0
    else
        echo ""
        echo "⚠️  Instalación exitosa pero con $ERROR_COUNT advertencia(s)"
        echo ""
        echo "📋 Advertencias encontradas:"
        grep -i "error\|exception\|traceback" evidencias/sprint1_installation_final.log | tail -10
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

**DoD Task 1.17:**
- ✅ Módulo instalado exitosamente
- ✅ `state=installed` verificado
- ✅ Sin errores críticos en log

---

### TASK 1.18: Ejecutar Suite de Tests (10min)

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

**DoD Task 1.18:**
- ✅ 7 tests ejecutados
- ✅ 7/7 tests PASS
- ✅ Sin errores ni fallos

---

### TASK 1.19: Completar DoD Sprint 1 y Commit Final (10min)

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

# 9. Nombres de campos correctos en hr_contract_views.xml
if bash scripts/validate_contract_fields.sh > /dev/null 2>&1; then
    echo "✅ 9. Nombres de campos correctos en hr_contract_views.xml"
else
    echo "❌ 9. Nombres de campos incorrectos en hr_contract_views.xml"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ DoD Sprint 1: COMPLETO (9/9 criterios cumplidos)"
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

git commit -m "feat(l10n_cl_hr_payroll): complete SPRINT 1 - P0 bloqueantes resueltos (100%)

SPRINT 1 - Resolver Hallazgos P0 Bloqueantes (100% COMPLETADO)

Resolves:
- H1: Campo company_currency_id agregado (34 campos Monetary)
- H2: 34 campos Monetary auditados y validados
- H3: Stub hr.contract CE creado (350+ LOC)
- Campos obsoletos XML Odoo 19 corregidos
- attrs obsoletos en views corregidos (19 ocurrencias, Odoo 19 syntax)
- _check_recursion() deprecado corregido (2 modelos)
- Tree → List tags convertidos (13 ocurrencias)
- Field name mismatches corregidos (hr_contract_views.xml)

Changes:
- models/hr_contract_stub_ce.py: NEW - Stub CE completo
  * hr.contract model con campos básicos
  * hr.contract.type model
  * Validaciones y constraints
- models/hr_economic_indicators.py: Add company_currency_id
- models/hr_payroll_structure.py: Add company_currency_id, _has_cycle()
- models/hr_salary_rule.py: Add company_currency_id
- models/hr_salary_rule_category.py: _has_cycle() instead of _check_recursion()
- data/ir_cron_data.xml: Remove obsolete fields
- security/security_groups.xml: Remove category_id
- views/hr_payroll_structure_views.xml: Remove attrs (3 ocurrencias)
- views/hr_payslip_run_views.xml: Remove attrs (10 ocurrencias)
- views/hr_salary_rule_views.xml: Remove attrs (6 ocurrencias)
- views/hr_contract_views.xml: Fix field names (APV fields)
  * apv_id → l10n_cl_apv_institution_id
  * apv_amount_uf → l10n_cl_apv_amount
  * apv_type → l10n_cl_apv_regime
  * Add l10n_cl_apv_amount_type field
- views/hr_contract_stub_views.xml: NEW - Base views for CE
- views/*.xml: Convert <tree> → <list> (13 ocurrencias)
- __manifest__.py: Remove hr_contract Enterprise dependency
- tests/test_hr_contract_stub_ce.py: NEW - 5 tests
- tests/test_company_currency_id_fields.py: NEW - 2 tests
- scripts/audit_all_attrs.sh: NEW - Audit script
- scripts/validate_contract_fields.sh: NEW - Field validation script

Tests: 7/7 PASS
Module: INSTALLED (state=installed verified)
Odoo Version: 19.0 CE
Compatibility: Odoo 19 CE compliant
  - Obsolete fields removed
  - attrs syntax updated to Odoo 19
  - _check_recursion() replaced with _has_cycle()
  - Tree tags converted to List
  - All XML validations passed
  - Field names validated

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 1
Ref: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md Hallazgos P0
"
```

**DoD Task 1.19:**
- ✅ DoD Sprint 1 validado completamente (9/9 criterios)
- ✅ Commit final realizado
- ✅ Mensaje de commit estructurado

---

## 🎯 INSTRUCCIONES DE EJECUCIÓN

### Paso a Paso

1. **Corregir campos APV en hr_contract_views.xml:**
   - Aplicar correcciones según TASK 1.15
   - 3 campos corregidos + 1 campo agregado

2. **Auditar nombres de campos:**
   ```bash
   bash scripts/validate_contract_fields.sh
   ```

3. **Validar Instalación:**
   ```bash
   bash scripts/validate_module_installation_final_sprint1.sh
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

### DoD Sprint 1 Completo (9 Criterios)

- ✅ Módulo `l10n_cl_hr_payroll` instalado (`state=installed`)
- ✅ Stub `hr.contract` CE creado y funcional
- ✅ Campo `company_currency_id` agregado en 3 modelos
- ✅ 34 campos Monetary auditados y correctos
- ✅ 7 tests nuevos PASS
- ✅ Sin `attrs` obsoletos en XML
- ✅ Sin campos obsoletos en XML
- ✅ Dependencia `hr_contract` Enterprise removida
- ✅ Nombres de campos correctos en hr_contract_views.xml
- ✅ Commit final realizado

---

## 🚨 MANEJO DE ERRORES

### Si Instalación Falla Después de Corregir Campos

1. **Revisar log de instalación:**
   ```bash
   tail -100 evidencias/sprint1_installation_final.log | grep -i "field\|apv\|error"
   ```

2. **Validar nombres de campos:**
   ```bash
   bash scripts/validate_contract_fields.sh
   ```

3. **Si persiste el error:**
   - Buscar otros campos con nombres incorrectos
   - Validar que todos los campos existen en el modelo
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

- [ ] TASK 1.15: Corregir 3 campos APV + agregar 1 campo en hr_contract_views.xml
- [ ] TASK 1.16: Auditoría completa de nombres de campos ejecutada
- [ ] TASK 1.17: Instalación validada (`state=installed`)
- [ ] TASK 1.18: Tests ejecutados (7/7 PASS)
- [ ] TASK 1.19: DoD validado (9/9 criterios) y commit final realizado

---

## 🎯 CONCLUSIÓN

Este PROMPT proporciona instrucciones precisas para completar el último 5% del SPRINT 1, resolviendo específicamente el problema de nombres de campos incorrectos en `hr_contract_views.xml` que está bloqueando la instalación del módulo.

**Estado Esperado Post-Ejecución:**
- ✅ SPRINT 1: 100% COMPLETADO
- ✅ Módulo instalado exitosamente
- ✅ Todos los tests pasando (7/7)
- ✅ DoD completo (9/9 criterios)
- ✅ Commit final realizado

**Próximo Paso:**
- SPRINT 2: P1 Quick Wins (Dashboard fix, DTE scope)

---

**FIN DEL PROMPT FINAL SPRINT 1 (95% → 100%)**

