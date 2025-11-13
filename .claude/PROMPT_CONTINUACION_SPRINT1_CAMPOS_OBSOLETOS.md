# 🎯 PROMPT CONTINUACIÓN SPRINT 1 - CIERRE TOTAL DE BRECHAS
## Resolución de Campos Obsoletos XML Odoo 19 | Máxima Precisión | Zero Errors

**Fecha Emisión:** 2025-11-09  
**Versión:** 1.1 (Continuación Sprint 1)  
**Agente:** `@odoo-dev`  
**Coordinador:** Senior Engineer  
**Branch:** `feat/cierre_total_brechas_profesional`  
**Prioridad:** 🔴 CRÍTICA  
**Status:** 🔄 EN PROGRESO (70% completado)

---

## 📊 ESTADO ACTUAL DEL SPRINT 1

### ✅ Progreso Completado (70%)

**Hallazgos Resueltos:**
1. ✅ **H3: Stub hr.contract CE creado** (300+ LOC)
   - Incluye `hr.contract.type`
   - Campo `contract_type_id` agregado
   - Validaciones y constraints completos
   - Commit: `07e19c26`

2. ✅ **H1: Campo company_currency_id agregado**
   - Soluciona 34 campos Monetary
   - Tests creados (2 tests)
   - Commit: `07e19c26`

3. ✅ **H2: 32 campos Monetary auditados**
   - Todos correctos con `currency_field` apropiado
   - Commit: `07e19c26`

4. ✅ **Compatibilidad Odoo 19:**
   - ✅ `category_id` removido de `security_groups.xml`
   - ✅ `numbercall` y `doall` removidos de `ir_cron_data.xml`
   - ✅ Dependencia `hr_contract` Enterprise removida

**Tests Creados:**
- `test_hr_contract_stub_ce.py` - 5 tests
- `test_company_currency_id_fields.py` - 2 tests
- **Total:** 7 tests nuevos

**Commits:**
- `eec57ad9` - SPRINT 0 completado
- `07e19c26` - SPRINT 1 WIP (70% completado)

---

## 🔴 PROBLEMA ACTUAL IDENTIFICADO

### Issue: Campos Obsoletos en Archivos XML

**Síntoma:**
- Módulo `l10n_cl_hr_payroll` **NO instala**
- Error al parsear `ir_cron_data.xml`
- Puede haber más campos obsoletos adicionales

**Campos Obsoletos Ya Corregidos:**
- ✅ `category_id` en `res.groups` (Odoo 19: usar `category` o eliminar)
- ✅ `numbercall` en `ir.cron` (Odoo 19: obsoleto, usar `interval_number` + `interval_type`)
- ✅ `doall` en `ir.cron` (Odoo 19: obsoleto)

**Campos Obsoletos Pendientes:**
- ⚠️ Posibles campos adicionales en `ir_cron_data.xml`
- ⚠️ Otros archivos XML pueden tener campos obsoletos

---

## 🎯 OBJETIVO INMEDIATO

**Completar SPRINT 1 con éxito:**
1. Identificar y corregir **TODOS** los campos obsoletos en XML
2. Validar instalación exitosa (`state=installed`)
3. Ejecutar suite de tests (7 tests esperados PASS)
4. Completar DoD Sprint 1
5. Commit final Sprint 1

---

## 📋 TAREAS DETALLADAS

### TASK 1.5: Auditoría Completa de Campos Obsoletos XML (30min)

**Objetivo:** Identificar TODOS los campos obsoletos en archivos XML del módulo

**Archivos a Auditar:**
1. `addons/localization/l10n_cl_hr_payroll/data/ir_cron_data.xml`
2. `addons/localization/l10n_cl_hr_payroll/security/security_groups.xml`
3. Cualquier otro archivo XML en el módulo

**Script de Auditoría:**

```bash
#!/bin/bash
# scripts/audit_obsolete_xml_fields.sh
# Auditoría completa de campos obsoletos Odoo 19

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_DIR="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll"

echo "🔍 Auditoría de campos obsoletos Odoo 19 en XML..."
echo ""

# Campos obsoletos conocidos Odoo 19
OBSOLETE_FIELDS=(
    "category_id"      # res.groups → usar category o eliminar
    "numbercall"       # ir.cron → usar interval_number + interval_type
    "doall"            # ir.cron → obsoleto
    "active"           # ir.cron → usar active field directamente
    "priority"         # ir.cron → usar priority directamente
    "user_id"          # ir.cron → usar user_id directamente
    "state"            # ir.cron → obsoleto
    "nextcall"         # ir.cron → calcular automáticamente
)

echo "📋 Buscando campos obsoletos en archivos XML..."
echo ""

ERRORS=0

for field in "${OBSOLETE_FIELDS[@]}"; do
    echo "🔍 Buscando campo obsoleto: $field"
    
    # Buscar en todos los XML
    MATCHES=$(grep -rn "\"$field\"" "$MODULE_DIR" --include="*.xml" 2>/dev/null | grep -v "__pycache__" || true)
    
    if [ -n "$MATCHES" ]; then
        echo "  ❌ ENCONTRADO:"
        echo "$MATCHES" | sed 's/^/    /'
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✅ No encontrado"
    fi
    echo ""
done

# Buscar patrones específicos de Odoo 19 incompatibles
echo "🔍 Buscando patrones incompatibles Odoo 19..."
echo ""

# Patrón: category_id en res.groups
if grep -rn "category_id" "$MODULE_DIR" --include="*.xml" | grep -q "res.groups\|model=\"res.groups\""; then
    echo "  ❌ category_id encontrado en res.groups"
    grep -rn "category_id" "$MODULE_DIR" --include="*.xml" | grep "res.groups\|model=\"res.groups\""
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ category_id no encontrado en res.groups"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Auditoría completada: No se encontraron campos obsoletos"
    exit 0
else
    echo "❌ Auditoría completada: $ERRORS campo(s) obsoleto(s) encontrado(s)"
    exit 1
fi
```

**DoD Task 1.5:**
- ✅ Script de auditoría ejecutado
- ✅ Todos los campos obsoletos identificados
- ✅ Reporte generado

---

### TASK 1.6: Corregir Campos Obsoletos Identificados (45min)

**Objetivo:** Corregir TODOS los campos obsoletos encontrados en la auditoría

**Guía de Corrección por Campo:**

#### 1. `category_id` en `res.groups`

**ANTES (Odoo 18):**
```xml
<record id="group_payroll_manager" model="res.groups">
    <field name="name">Payroll Manager</field>
    <field name="category_id" ref="base.module_category_human_resources"/>
</record>
```

**DESPUÉS (Odoo 19):**
```xml
<record id="group_payroll_manager" model="res.groups">
    <field name="name">Payroll Manager</field>
    <!-- category_id removido - Odoo 19 usa category directamente -->
    <!-- Si necesitas categoría, usar: -->
    <!-- <field name="category" ref="base.module_category_human_resources"/> -->
</record>
```

**Nota:** En Odoo 19, `category_id` fue reemplazado por `category` (Many2one directo).

---

#### 2. `numbercall` y `doall` en `ir.cron`

**ANTES (Odoo 18):**
```xml
<record id="ir_cron_update_economic_indicators" model="ir.cron">
    <field name="name">Update Economic Indicators</field>
    <field name="numbercall">1</field>
    <field name="doall">True</field>
    <field name="interval_number">1</field>
    <field name="interval_type">days</field>
</record>
```

**DESPUÉS (Odoo 19):**
```xml
<record id="ir_cron_update_economic_indicators" model="ir.cron">
    <field name="name">Update Economic Indicators</field>
    <!-- numbercall removido - Odoo 19 calcula automáticamente -->
    <!-- doall removido - Odoo 19 maneja automáticamente -->
    <field name="interval_number">1</field>
    <field name="interval_type">days</field>
    <!-- Si necesitas ejecutar una vez: -->
    <!-- <field name="active">True</field> -->
</record>
```

**Nota:** En Odoo 19:
- `numbercall` fue removido (se calcula automáticamente)
- `doall` fue removido (se maneja automáticamente)
- Usar solo `interval_number` y `interval_type`

---

#### 3. Otros Campos Obsoletos Comunes

**`state` en `ir.cron`:**
```xml
<!-- ANTES -->
<field name="state">code</field>

<!-- DESPUÉS -->
<!-- Remover completamente - Odoo 19 maneja automáticamente -->
```

**`nextcall` en `ir.cron`:**
```xml
<!-- ANTES -->
<field name="nextcall">2025-11-09 00:00:00</field>

<!-- DESPUÉS -->
<!-- Remover completamente - Odoo 19 calcula automáticamente -->
```

---

**Implementación:**

**Paso 1: Identificar archivos con campos obsoletos**
```bash
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_DIR="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll"

# Ejecutar auditoría
bash scripts/audit_obsolete_xml_fields.sh > evidencias/sprint1_audit_obsolete_fields.log 2>&1

# Revisar resultados
cat evidencias/sprint1_audit_obsolete_fields.log
```

**Paso 2: Corregir archivos identificados**

Para cada archivo con campos obsoletos:
1. Abrir archivo XML
2. Aplicar correcciones según guía arriba
3. Guardar archivo
4. Validar sintaxis XML

**Paso 3: Validar sintaxis XML**
```bash
# Validar sintaxis XML
for xml_file in $(find "$MODULE_DIR" -name "*.xml" -type f); do
    echo "Validando: $xml_file"
    xmllint --noout "$xml_file" 2>&1 || echo "  ❌ Error en $xml_file"
done
```

**DoD Task 1.6:**
- ✅ Todos los campos obsoletos corregidos
- ✅ Sintaxis XML validada
- ✅ Archivos guardados

---

### TASK 1.7: Validar Instalación Exitosa (15min)

**Objetivo:** Instalar módulo y validar `state=installed`

**Implementación:**

```bash
#!/bin/bash
# scripts/validate_module_installation.sh
# Validar instalación exitosa del módulo

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_NAME="l10n_cl_hr_payroll"
DB_NAME="${DB_NAME:-odoo19}"

echo "🔍 Validando instalación del módulo $MODULE_NAME..."
echo ""

# 1. Reiniciar contenedor para cargar cambios XML
echo "🔄 Reiniciando contenedor..."
docker-compose restart app

# Esperar a que contenedor esté healthy
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
    echo "❌ ERROR: Contenedor no está healthy después de $timeout segundos"
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
    2>&1 | tee evidencias/sprint1_installation.log

INSTALL_EXIT_CODE=$?

# 3. Verificar estado del módulo
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
    exit 0
else
    echo "❌ Módulo $MODULE_NAME: $MODULE_STATE (esperado: installed)"
    echo ""
    echo "📋 Últimos errores del log:"
    tail -50 evidencias/sprint1_installation.log | grep -i "error\|exception\|traceback" | tail -20
    exit 1
fi
```

**DoD Task 1.7:**
- ✅ Módulo instalado exitosamente
- ✅ `state=installed` verificado
- ✅ Sin errores en log de instalación

---

### TASK 1.8: Ejecutar Suite de Tests (15min)

**Objetivo:** Ejecutar todos los tests del Sprint 1 y validar PASS

**Implementación:**

```bash
#!/bin/bash
# scripts/run_sprint1_tests.sh
# Ejecutar suite de tests Sprint 1

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
DB_NAME="${DB_NAME:-odoo19}"

echo "🧪 Ejecutando suite de tests Sprint 1..."
echo ""

# Tests esperados:
# - test_hr_contract_stub_ce.py: 5 tests
# - test_company_currency_id_fields.py: 2 tests
# Total: 7 tests

docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d "$DB_NAME" \
    --test-enable \
    --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll/test_hr_contract_stub_ce,/l10n_cl_hr_payroll/test_company_currency_id_fields \
    --log-level=test \
    2>&1 | tee evidencias/sprint1_tests.log

TEST_EXIT_CODE=$?

# Analizar resultados
echo ""
echo "📊 Análisis de resultados de tests..."
echo ""

# Contar tests ejecutados
TESTS_RUN=$(grep -c "test_" evidencias/sprint1_tests.log | head -1 || echo "0")
TESTS_PASS=$(grep -c "ok" evidencias/sprint1_tests.log || echo "0")
TESTS_FAIL=$(grep -c "FAIL\|ERROR" evidencias/sprint1_tests.log || echo "0")

echo "Tests ejecutados: $TESTS_RUN"
echo "Tests PASS: $TESTS_PASS"
echo "Tests FAIL: $TESTS_FAIL"

if [ $TEST_EXIT_CODE -eq 0 ] && [ "$TESTS_FAIL" -eq 0 ]; then
    echo ""
    echo "✅ Todos los tests pasaron exitosamente"
    exit 0
else
    echo ""
    echo "❌ Algunos tests fallaron"
    echo ""
    echo "📋 Tests fallidos:"
    grep -A 5 "FAIL\|ERROR" evidencias/sprint1_tests.log | head -30
    exit 1
fi
```

**DoD Task 1.8:**
- ✅ 7 tests ejecutados
- ✅ 7/7 tests PASS
- ✅ Sin errores ni fallos

---

### TASK 1.9: Completar DoD Sprint 1 y Commit Final (15min)

**Objetivo:** Validar DoD completo y hacer commit final

**DoD Sprint 1 Checklist:**

```bash
#!/bin/bash
# scripts/validate_sprint1_dod.sh
# Validar Definition of Done Sprint 1

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_NAME="l10n_cl_hr_payroll"
DB_NAME="${DB_NAME:-odoo19}"

echo "✅ Validando DoD Sprint 1..."
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
if [ -f "evidencias/sprint1_tests.log" ]; then
    TESTS_FAIL=$(grep -c "FAIL\|ERROR" evidencias/sprint1_tests.log || echo "0")
    if [ "$TESTS_FAIL" -eq 0 ]; then
        echo "✅ 5. Todos los tests pasando"
    else
        echo "❌ 5. Tests fallando: $TESTS_FAIL"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "⚠️  5. Log de tests no encontrado (ejecutar tests primero)"
fi

# 6. Sin campos obsoletos en XML
if bash scripts/audit_obsolete_xml_fields.sh > /dev/null 2>&1; then
    echo "✅ 6. Sin campos obsoletos en XML"
else
    echo "❌ 6. Campos obsoletos encontrados en XML"
    ERRORS=$((ERRORS + 1))
fi

# 7. Dependencia hr_contract Enterprise removida
if ! grep -q "'hr_contract'" "addons/localization/$MODULE_NAME/__manifest__.py"; then
    echo "✅ 7. Dependencia hr_contract Enterprise removida"
else
    echo "❌ 7. Dependencia hr_contract Enterprise aún presente"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ DoD Sprint 1: COMPLETO"
    exit 0
else
    echo "❌ DoD Sprint 1: $ERRORS criterio(s) no cumplido(s)"
    exit 1
fi
```

**Commit Final Sprint 1:**

```bash
# Validar DoD primero
bash scripts/validate_sprint1_dod.sh

# Si DoD completo, hacer commit
git add addons/localization/l10n_cl_hr_payroll/
git add scripts/
git add evidencias/

git commit -m "feat(l10n_cl_hr_payroll): complete SPRINT 1 - P0 bloqueantes resueltos

SPRINT 1 - Resolver Hallazgos P0 Bloqueantes

Resolves:
- H1: Campo company_currency_id agregado (34 campos Monetary)
- H2: 32 campos Monetary auditados y validados
- H3: Stub hr.contract CE creado (300+ LOC)
- Campos obsoletos XML Odoo 19 corregidos

Changes:
- models/hr_contract_stub_ce.py: NEW - Stub CE completo
  * hr.contract model con campos básicos
  * hr.contract.type model
  * Validaciones y constraints
- models/hr_economic_indicators.py: Add company_currency_id
- models/hr_payroll_structure.py: Add company_currency_id
- models/hr_salary_rule.py: Add company_currency_id
- data/ir_cron_data.xml: Remove obsolete fields (numbercall, doall)
- security/security_groups.xml: Remove category_id
- __manifest__.py: Remove hr_contract Enterprise dependency
- tests/test_hr_contract_stub_ce.py: NEW - 5 tests
- tests/test_company_currency_id_fields.py: NEW - 2 tests

Tests: 7/7 PASS
Module: INSTALLED (state=installed verified)
Odoo Version: 19.0 CE
Compatibility: Odoo 19 CE compliant (obsolete fields removed)

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 1
Ref: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md Hallazgos P0
"
```

**DoD Task 1.9:**
- ✅ DoD Sprint 1 validado completamente
- ✅ Commit final realizado
- ✅ Mensaje de commit estructurado

---

## 🎯 INSTRUCCIONES DE EJECUCIÓN

### Paso a Paso

1. **Ejecutar Auditoría de Campos Obsoletos:**
   ```bash
   bash scripts/audit_obsolete_xml_fields.sh
   ```

2. **Corregir Campos Obsoletos Identificados:**
   - Seguir guía de corrección en TASK 1.6
   - Validar sintaxis XML después de cada corrección

3. **Validar Instalación:**
   ```bash
   bash scripts/validate_module_installation.sh
   ```

4. **Ejecutar Tests:**
   ```bash
   bash scripts/run_sprint1_tests.sh
   ```

5. **Validar DoD y Commit:**
   ```bash
   bash scripts/validate_sprint1_dod.sh
   # Si pasa, hacer commit final
   ```

---

## 📊 CRITERIOS DE ÉXITO

### DoD Sprint 1 Completo

- ✅ Módulo `l10n_cl_hr_payroll` instalado (`state=installed`)
- ✅ Stub `hr.contract` CE creado y funcional
- ✅ Campo `company_currency_id` agregado en 3 modelos
- ✅ 32 campos Monetary auditados y correctos
- ✅ 7 tests nuevos PASS
- ✅ Sin campos obsoletos en XML
- ✅ Dependencia `hr_contract` Enterprise removida
- ✅ Commit final realizado

---

## 🚨 MANEJO DE ERRORES

### Si Instalación Falla

1. **Revisar log de instalación:**
   ```bash
   tail -100 evidencias/sprint1_installation.log | grep -i "error\|exception\|traceback"
   ```

2. **Identificar campo obsoleto específico:**
   - Buscar en log el nombre del campo
   - Aplicar corrección según guía TASK 1.6
   - Reintentar instalación

3. **Si persiste el error:**
   - Reportar al coordinador con:
     - Log completo de instalación
     - Archivo XML específico con error
     - Campo obsoleto identificado

### Si Tests Fallan

1. **Revisar log de tests:**
   ```bash
   grep -A 10 "FAIL\|ERROR" evidencias/sprint1_tests.log
   ```

2. **Corregir código según error:**
   - Seguir mensaje de error específico
   - Validar lógica del test
   - Re-ejecutar tests

---

## 📋 CHECKLIST DE EJECUCIÓN

- [ ] TASK 1.5: Auditoría campos obsoletos ejecutada
- [ ] TASK 1.6: Campos obsoletos corregidos
- [ ] TASK 1.7: Instalación validada (`state=installed`)
- [ ] TASK 1.8: Tests ejecutados (7/7 PASS)
- [ ] TASK 1.9: DoD validado y commit final realizado

---

## 🎯 CONCLUSIÓN

Este PROMPT proporciona instrucciones precisas para completar el SPRINT 1 con éxito, resolviendo específicamente el problema de campos obsoletos en XML que está bloqueando la instalación del módulo.

**Estado Esperado Post-Ejecución:**
- ✅ SPRINT 1: 100% COMPLETADO
- ✅ Módulo instalado exitosamente
- ✅ Todos los tests pasando
- ✅ DoD completo
- ✅ Commit final realizado

**Próximo Paso:**
- SPRINT 2: P1 Quick Wins (Dashboard fix, DTE scope)

---

**FIN DEL PROMPT CONTINUACIÓN SPRINT 1**

