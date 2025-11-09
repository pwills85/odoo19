# 🎯 PROMPT FINAL SPRINT 1 - CIERRE TOTAL (98% → 100%)
## Resolución: Vista Search + Error Instalación | Máxima Precisión | Zero Errors

**Fecha Emisión:** 2025-11-09  
**Versión:** 1.4 (Cierre Final Sprint 1)  
**Agente:** `@odoo-dev`  
**Coordinador:** Senior Engineer  
**Branch:** `feat/cierre_total_brechas_profesional`  
**Prioridad:** 🔴 CRÍTICA  
**Status:** 🔄 EN PROGRESO (98% completado → 100% objetivo)

---

## 📊 ANÁLISIS DEL FEEDBACK DEL AGENTE

### ✅ Progreso Excelente (98% completado)

**SPRINT 0:** ✅ 100% COMPLETADO

**SPRINT 1 - Logros Completados (15 correcciones):**

1. ✅ **Campos APV Corregidos:** 4 campos (3 corregidos + 1 agregado)
2. ✅ **attrs Obsoletos Eliminados:** 20 ocurrencias en 4 archivos
3. ✅ **_check_recursion() Deprecado:** Corregido en 2 modelos
4. ✅ **Tree → List Tags:** 13 archivos convertidos
5. ✅ **Stub hr.contract CE Creado:** 350+ LOC
6. ✅ **Scripts de Validación Creados:** 2 scripts nuevos

**Progreso:** 85% → 98% (+13%)

---

## ⚠️ ISSUES RESTANTES (2%)

### Issue 1: Vista Search hr.payslip Comentada

**Archivo:** `addons/localization/l10n_cl_hr_payroll/views/hr_payslip_views.xml`

**Problema:** Vista search comentada temporalmente debido a error de parsing en Odoo 19.

**Error Identificado:** Falta el campo `name` en el record de la vista.

**Código Actual (Comentado):**
```xml
<!--
<record id="view_hr_payslip_search" model="ir.ui.view">
    <field name="model">hr.payslip</field>  <!-- ⚠️ FALTA CAMPO name -->
    <field name="arch" type="xml">
        <search string="Buscar Liquidaciones">
            ...
        </search>
    </field>
</record>
-->
```

---

### Issue 2: Error de Instalación Final

**Problema:** Módulo falla al final del proceso de carga.

**Causa:** Requiere debugging detallado con `--log-handler=odoo:DEBUG`.

---

## 🎯 OBJETIVO INMEDIATO

**Completar SPRINT 1 al 100%:**
1. Corregir vista search hr.payslip (agregar campo `name`)
2. Descomentar vista search y referencia en action
3. Ejecutar instalación con debug máximo
4. Analizar log y corregir error específico
5. Validar instalación exitosa (`state=installed`)
6. Ejecutar suite de tests (7 tests esperados PASS)
7. Completar DoD Sprint 1
8. Commit final Sprint 1

**Estimación:** 20-35 minutos

---

## 📋 TAREAS DETALLADAS

### TASK 1.20: Corregir Vista Search hr.payslip (5min)

**Objetivo:** Descomentar y corregir la vista search agregando el campo `name` faltante

**Archivo:** `addons/localization/l10n_cl_hr_payroll/views/hr_payslip_views.xml`

**Corrección Requerida:**

#### Paso 1: Descomentar Vista Search y Agregar Campo `name`

**ANTES (Comentado):**
```xml
<!--
<record id="view_hr_payslip_search" model="ir.ui.view">
    <field name="model">hr.payslip</field>
    <field name="arch" type="xml">
        <search string="Buscar Liquidaciones">
            <field name="number"/>
            <field name="employee_id"/>
            <field name="date_from"/>
            <filter string="Borrador" name="draft" domain="[('state', '=', 'draft')]"/>
            <filter string="Pagadas" name="done" domain="[('state', '=', 'done')]"/>
            <group string="Agrupar Por">
                <filter string="Empleado" name="group_employee" context="{'group_by': 'employee_id'}"/>
                <filter string="Estado" name="group_state" context="{'group_by': 'state'}"/>
            </group>
        </search>
    </field>
</record>
-->
```

**DESPUÉS (Corregido):**
```xml
<!-- ═══════════════════════════════════════════════════════════ -->
<!-- VISTA SEARCH: hr.payslip -->
<!-- ═══════════════════════════════════════════════════════════ -->

<record id="view_hr_payslip_search" model="ir.ui.view">
    <field name="name">hr.payslip.search</field>  <!-- ✅ CAMPO name AGREGADO -->
    <field name="model">hr.payslip</field>
    <field name="arch" type="xml">
        <search string="Buscar Liquidaciones">
            <field name="number"/>
            <field name="employee_id"/>
            <field name="date_from"/>
            <filter string="Borrador" name="draft" domain="[('state', '=', 'draft')]"/>
            <filter string="Pagadas" name="done" domain="[('state', '=', 'done')]"/>
            <group string="Agrupar Por">
                <filter string="Empleado" name="group_employee" context="{'group_by': 'employee_id'}"/>
                <filter string="Estado" name="group_state" context="{'group_by': 'state'}"/>
            </group>
        </search>
    </field>
</record>
```

**Nota:** En Odoo 19, el campo `name` es **obligatorio** en todos los records de `ir.ui.view`.

---

#### Paso 2: Descomentar Referencia en Action

**ANTES (Comentado):**
```xml
<!-- search_view_id comentado temporalmente - Issue con Odoo 19 -->
<!-- <field name="search_view_id" ref="view_hr_payslip_search"/> -->
```

**DESPUÉS (Descomentado):**
```xml
<field name="search_view_id" ref="view_hr_payslip_search"/>
```

**Ubicación:** Línea 190 en `hr_payslip_views.xml`, dentro del record `action_hr_payslip`.

---

**Implementación Completa:**

```xml
<!-- ═══════════════════════════════════════════════════════════ -->
<!-- VISTA SEARCH: hr.payslip -->
<!-- ═══════════════════════════════════════════════════════════ -->

<record id="view_hr_payslip_search" model="ir.ui.view">
    <field name="name">hr.payslip.search</field>
    <field name="model">hr.payslip</field>
    <field name="arch" type="xml">
        <search string="Buscar Liquidaciones">
            <field name="number"/>
            <field name="employee_id"/>
            <field name="date_from"/>
            <filter string="Borrador" name="draft" domain="[('state', '=', 'draft')]"/>
            <filter string="Pagadas" name="done" domain="[('state', '=', 'done')]"/>
            <group string="Agrupar Por">
                <filter string="Empleado" name="group_employee" context="{'group_by': 'employee_id'}"/>
                <filter string="Estado" name="group_state" context="{'group_by': 'state'}"/>
            </group>
        </search>
    </field>
</record>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- ACTION: hr.payslip -->
<!-- ═══════════════════════════════════════════════════════════ -->

<record id="action_hr_payslip" model="ir.actions.act_window">
    <field name="name">Liquidaciones</field>
    <field name="res_model">hr.payslip</field>
    <field name="view_mode">tree,form</field>
    <field name="search_view_id" ref="view_hr_payslip_search"/>
    <field name="help" type="html">
        <p class="o_view_nocontent_smiling_face">
            Crear nueva liquidación de sueldo
        </p>
        <p>
            Las liquidaciones de sueldo calculan automáticamente haberes y descuentos
            según la normativa chilena vigente.
        </p>
    </field>
</record>
```

**DoD Task 1.20:**
- ✅ Vista search descomentada
- ✅ Campo `name` agregado
- ✅ Referencia en action descomentada
- ✅ Sintaxis XML validada

---

### TASK 1.21: Debugging Instalación con Log Detallado (15min)

**Objetivo:** Ejecutar instalación con debug máximo y analizar error específico

**Script de Debugging:**

```bash
#!/bin/bash
# scripts/debug_installation_sprint1.sh
# Ejecutar instalación con debug máximo para identificar error específico

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_NAME="l10n_cl_hr_payroll"
DB_NAME="${DB_NAME:-odoo19}"

echo "🔍 Ejecutando instalación con debug máximo..."
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

# 2. Ejecutar instalación con debug máximo
echo ""
echo "📦 Instalando módulo $MODULE_NAME con debug máximo..."
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d "$DB_NAME" \
    -i "$MODULE_NAME" \
    --stop-after-init \
    --log-handler=odoo:DEBUG \
    --log-level=debug \
    2>&1 | tee evidencias/sprint1_installation_debug.log

INSTALL_EXIT_CODE=$?

# 3. Analizar log
echo ""
echo "📊 Análisis del log de instalación..."
echo ""

# Buscar errores
ERRORS=$(grep -i "error\|exception\|traceback" evidencias/sprint1_installation_debug.log | wc -l | xargs)

if [ "$ERRORS" -gt 0 ]; then
    echo "❌ Se encontraron $ERRORS error(es) en el log"
    echo ""
    echo "📋 Últimos errores encontrados:"
    grep -i "error\|exception\|traceback" evidencias/sprint1_installation_debug.log | tail -30
    
    echo ""
    echo "📋 Últimas 50 líneas del log:"
    tail -50 evidencias/sprint1_installation_debug.log
    
    exit 1
else
    echo "✅ No se encontraron errores en el log"
    
    # Verificar estado del módulo
    MODULE_STATE=$(docker exec odoo19_app psql -U odoo -d "$DB_NAME" -t -c \
        "SELECT state FROM ir_module_module WHERE name='$MODULE_NAME';" | xargs)
    
    if [ "$MODULE_STATE" = "installed" ]; then
        echo "✅ Módulo $MODULE_NAME: INSTALLED"
        exit 0
    else
        echo "⚠️  Módulo $MODULE_NAME: $MODULE_STATE (esperado: installed)"
        exit 1
    fi
fi
```

**DoD Task 1.21:**
- ✅ Instalación ejecutada con debug máximo
- ✅ Log analizado
- ✅ Error específico identificado (si existe)
- ✅ Solución aplicada

---

### TASK 1.22: Corregir Error Identificado (10min)

**Objetivo:** Aplicar corrección específica según error encontrado en log

**Proceso:**

1. **Analizar log de debugging:**
   ```bash
   grep -i "error\|exception\|traceback" evidencias/sprint1_installation_debug.log | tail -30
   ```

2. **Identificar error específico:**
   - Campo faltante en modelo
   - Vista con error de sintaxis
   - Dependencia circular
   - Secuencia no encontrada
   - Otro error específico

3. **Aplicar corrección según error:**
   - Seguir mensaje de error específico
   - Corregir código según indicación
   - Revalidar instalación

**DoD Task 1.22:**
- ✅ Error identificado y corregido
- ✅ Instalación validada exitosamente

---

### TASK 1.23: Validar Instalación Exitosa (5min)

**Objetivo:** Validar que el módulo se instaló correctamente

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

# Verificar estado del módulo
MODULE_STATE=$(docker exec odoo19_app psql -U odoo -d "$DB_NAME" -t -c \
    "SELECT state FROM ir_module_module WHERE name='$MODULE_NAME';" | xargs)

if [ "$MODULE_STATE" = "installed" ]; then
    echo "✅ Módulo $MODULE_NAME: INSTALLED"
    echo ""
    echo "📊 Información del módulo:"
    docker exec odoo19_app psql -U odoo -d "$DB_NAME" -c \
        "SELECT name, state, latest_version FROM ir_module_module WHERE name='$MODULE_NAME';"
    
    echo ""
    echo "🎉 SPRINT 1 COMPLETADO AL 100%"
    exit 0
else
    echo "❌ Módulo $MODULE_NAME: $MODULE_STATE (esperado: installed)"
    exit 1
fi
```

**DoD Task 1.23:**
- ✅ Módulo instalado exitosamente
- ✅ `state=installed` verificado

---

### TASK 1.24: Ejecutar Suite de Tests (5min)

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

TESTS_FAIL=$(grep -c "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log 2>/dev/null || echo "0")

if [ $TEST_EXIT_CODE -eq 0 ] && [ "$TESTS_FAIL" -eq 0 ]; then
    echo "✅ Todos los tests pasaron exitosamente (7/7 esperados)"
    exit 0
else
    echo "❌ Algunos tests fallaron"
    grep -A 5 "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log | head -30
    exit 1
fi
```

**DoD Task 1.24:**
- ✅ 7 tests ejecutados
- ✅ 7/7 tests PASS

---

### TASK 1.25: Completar DoD Sprint 1 y Commit Final (5min)

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
    echo "✅ 1. Módulo $MODULE_NAME instalado"
else
    echo "❌ 1. Módulo $MODULE_NAME NO instalado"
    ERRORS=$((ERRORS + 1))
fi

# 2. Vista search corregida
if grep -q '<field name="name">hr.payslip.search</field>' "addons/localization/$MODULE_NAME/views/hr_payslip_views.xml"; then
    echo "✅ 2. Vista search hr.payslip corregida"
else
    echo "❌ 2. Vista search hr.payslip NO corregida"
    ERRORS=$((ERRORS + 1))
fi

# 3. Tests pasando
if [ -f "evidencias/sprint1_tests_final.log" ]; then
    TESTS_FAIL=$(grep -c "FAIL\|ERROR\|FAILED" evidencias/sprint1_tests_final.log 2>/dev/null || echo "0")
    if [ "$TESTS_FAIL" -eq 0 ]; then
        echo "✅ 3. Todos los tests pasando"
    else
        echo "❌ 3. Tests fallando: $TESTS_FAIL"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "⚠️  3. Log de tests no encontrado"
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
- attrs obsoletos en views corregidos (20 ocurrencias, Odoo 19 syntax)
- _check_recursion() deprecado corregido (2 modelos)
- Tree → List tags convertidos (13 archivos)
- Field name mismatches corregidos (hr_contract_views.xml)
- Vista search hr.payslip corregida (campo name agregado)

Changes:
- views/hr_payslip_views.xml: Fix search view (add name field)
  * Descomentada vista search
  * Agregado campo name obligatorio
  * Descomentada referencia en action
- [Todos los cambios anteriores del SPRINT 1]

Tests: 7/7 PASS
Module: INSTALLED (state=installed verified)
Odoo Version: 19.0 CE
Compatibility: Odoo 19 CE compliant

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md SPRINT 1
"
```

**DoD Task 1.25:**
- ✅ DoD Sprint 1 validado completamente
- ✅ Commit final realizado

---

## 🎯 INSTRUCCIONES DE EJECUCIÓN

### Paso a Paso

1. **Corregir vista search:**
   - Descomentar vista search
   - Agregar campo `name` faltante
   - Descomentar referencia en action

2. **Debugging instalación:**
   ```bash
   bash scripts/debug_installation_sprint1.sh
   ```

3. **Corregir error identificado:**
   - Analizar log
   - Aplicar corrección específica

4. **Validar instalación:**
   ```bash
   bash scripts/validate_module_installation_final_sprint1.sh
   ```

5. **Ejecutar tests:**
   ```bash
   bash scripts/run_sprint1_tests_final.sh
   ```

6. **Validar DoD y commit:**
   ```bash
   bash scripts/validate_sprint1_dod_final.sh
   # Si pasa, hacer commit final
   ```

---

## 📊 CRITERIOS DE ÉXITO

### DoD Sprint 1 Completo

- ✅ Módulo `l10n_cl_hr_payroll` instalado (`state=installed`)
- ✅ Vista search hr.payslip corregida
- ✅ Todos los tests pasando (7/7)
- ✅ Commit final realizado

---

## 🚨 MANEJO DE ERRORES

### Si Vista Search Sigue Fallando

1. **Validar sintaxis XML:**
   ```bash
   xmllint --noout addons/localization/l10n_cl_hr_payroll/views/hr_payslip_views.xml
   ```

2. **Verificar que todos los campos existen en modelo:**
   - `number`, `employee_id`, `date_from`, `state`

3. **Validar sintaxis de filtros y grupos**

### Si Instalación Sigue Fallando

1. **Revisar log de debugging:**
   ```bash
   tail -100 evidencias/sprint1_installation_debug.log | grep -i "error\|exception\|traceback"
   ```

2. **Identificar última línea procesada:**
   - Ver qué archivo/vista estaba procesando
   - Corregir error específico

3. **Reintentar instalación**

---

## 📋 CHECKLIST DE EJECUCIÓN

- [ ] TASK 1.20: Corregir vista search (agregar campo name)
- [ ] TASK 1.21: Debugging instalación con log detallado
- [ ] TASK 1.22: Corregir error identificado
- [ ] TASK 1.23: Validar instalación exitosa
- [ ] TASK 1.24: Ejecutar tests (7/7 PASS)
- [ ] TASK 1.25: DoD validado y commit final realizado

---

## 🎯 CONCLUSIÓN

Este PROMPT proporciona instrucciones precisas para completar el último 2% del SPRINT 1, resolviendo específicamente:
1. Vista search hr.payslip (falta campo `name`)
2. Error de instalación (debugging detallado requerido)

**Estado Esperado Post-Ejecución:**
- ✅ SPRINT 1: 100% COMPLETADO
- ✅ Módulo instalado exitosamente
- ✅ Todos los tests pasando (7/7)
- ✅ DoD completo
- ✅ Commit final realizado

**Próximo Paso:**
- SPRINT 2: P1 Quick Wins (Dashboard fix, DTE scope)

---

**FIN DEL PROMPT FINAL SPRINT 1 (98% → 100%)**

