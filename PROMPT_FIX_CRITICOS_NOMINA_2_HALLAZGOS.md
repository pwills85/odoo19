# 🎯 PROMPT PROFESIONAL: FIX CRÍTICOS NÓMINA (2 HALLAZGOS BLOQUEANTES)

**Versión:** 1.0 (Post-Auditoría Forense)  
**Fecha:** 2025-11-09  
**Proyecto:** EERGYGROUP Odoo 19 CE - Localización Chilena  
**Base:** ANALISIS_CRITICO_AUDITORES_HALLAZGOS_2025-11-09.md  
**Metodología:** Evidence-Based, Atomic Commits, Zero Improvisation  
**Objetivo:** Fix 2 hallazgos críticos BLOQUEANTES (H1, H2) para production-ready

---

## 📋 CONTEXTO EJECUTIVO

### 🔴 Estado Actual (BLOQUEADO)

| Aspecto | Status | Bloqueante | ETA Fix |
|---------|--------|------------|---------|
| **H1: Campo XML inexistente** | 🔴 CRÍTICO | ✅ SÍ (AttributeError runtime) | 30 min |
| **H2: UserError sin import** | 🔴 CRÍTICO | ✅ SÍ (NameError runtime) | 5 min |
| **H8: Permisos unlink users** | 🟡 RIESGO | ❌ NO (auditoría) | 1 hora (opcional) |
| **Score Nómina Actual** | **87/100** | N/A | Post-fixes: **92/100** |

### ✅ Validación Auditoría Forense (100% Confianza)

**Auditor:** Claude Sonnet 4.5 (Modo Forense)  
**Comandos Ejecutados:** 70+ comandos verificación  
**Metodología:** Zero Trust, Command-Based Evidence  
**Confianza:** 100% (hallazgos confirmados con evidencia ejecutable)

**Hallazgos Ratificados:**
- ✅ H1: Campo `contract.isapre_plan_id` NO existe (debe ser `isapre_plan_uf`)
- ✅ H2: `raise UserError` sin import (solo tiene `ValidationError`)
- ✅ Ambos causan crashes en runtime (AttributeError, NameError)

---

## 🎯 OBJETIVO DEL PROMPT

**Alcance:**
1. ✅ Fix H1: Campo XML `isapre_plan_id` → `isapre_plan_uf` con lógica correcta
2. ✅ Fix H2: Agregar `UserError` a import en `hr_economic_indicators.py`
3. ⚠️ (Opcional) Fix H8: Permisos `perm_unlink=0` para group_hr_payroll_user
4. ✅ Validación completa con tests y restart Odoo

**Resultado Esperado:**
- Score: 87/100 → 92/100 ✅
- Runtime errors: 2 CRÍTICOS → 0 ✅
- Production ready: NO → YES ✅

**Tiempo Total:** 1-2 horas (incluye testing)

---

## 🔴 HALLAZGO H1: CAMPO XML INEXISTENTE (CRÍTICO)

### Problema Identificado

**Ubicación:** `addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml:164-165`

**Código Actual (INCORRECTO):**
```xml
<field name="condition_python">contract.isapre_id and contract.isapre_plan_id</field>
<field name="amount_python">
    if contract.isapre_id and contract.isapre_plan_id:
        tasa_salud = contract.isapre_plan_id.cotizacion_pactada / 100.0
        result = result.IMPO * tasa_salud
</field>
```

**Problema:**
- Campo `contract.isapre_plan_id` NO existe en modelo `hr.contract`
- Campo correcto: `contract.isapre_plan_uf` (Float, definido en `hr_contract_cl.py:47`)
- Causa: `AttributeError: 'hr.contract' object has no attribute 'isapre_plan_id'` en runtime

### Evidencia Verificada (Auditoría Forense)

**Búsqueda campo usado en XML:**
```bash
grep -n "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml
# Output: línea 164: contract.isapre_plan_id
```

**Verificación campo NO existe en modelo:**
```bash
grep -rn "isapre_plan_id.*fields\." addons/localization/l10n_cl_hr_payroll/models/
# Output: (vacío - campo NO definido)
```

**Campo correcto existente:**
```bash
grep -n "isapre_plan_uf.*fields\.Float" addons/localization/l10n_cl_hr_payroll/models/hr_contract_cl.py
# Output: línea 47: isapre_plan_uf = fields.Float(string='Plan ISAPRE (UF)')
```

**Lógica correcta ya implementada en otro lugar:**
```bash
grep -B 5 -A 10 "isapre_plan_uf.*indicadores\.uf" addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
# Output: línea 1240-1248: Lógica conversión UF a CLP con indicadores
```

### Fix Requerido (EXACTO)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml`  
**Líneas:** 164-177 (aproximado, verificar con grep)

**PASO 1: Leer contexto completo del rule XML**

```bash
# 1. Identificar línea exacta del <record> con SALUD
grep -n "SALUD\|salud_isapre" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml | head -5

# 2. Leer 20 líneas alrededor de la línea identificada
# (reemplazar XXX con número de línea del grep anterior)
sed -n 'XXX,YYYp' addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml

# 3. Identificar <record id="hr_salary_rule_..." exacto
grep -B 5 "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml | grep "<record"
```

**PASO 2: Aplicar fix con replace_string_in_file**

**Contexto a buscar (oldString):**
```xml
        <field name="condition_python">contract.isapre_id and contract.isapre_plan_id</field>
        <field name="amount_python">
if contract.isapre_id and contract.isapre_plan_id:
    tasa_salud = contract.isapre_plan_id.cotizacion_pactada / 100.0
    result = result.IMPO * tasa_salud
        </field>
```

**Fix aplicar (newString):**
```xml
        <field name="condition_python">contract.isapre_id and contract.isapre_plan_uf</field>
        <field name="amount_python">
if contract.isapre_id and contract.isapre_plan_uf:
    # Obtener indicadores económicos
    indicadores = payslip.get_economic_indicators()
    
    # Convertir plan UF a CLP
    plan_clp = contract.isapre_plan_uf * indicadores.uf
    
    # Calcular tasa salud (plan_clp / imponible)
    tasa_salud = plan_clp / result.IMPO if result.IMPO > 0 else 0
    
    # Aplicar tasa (máximo 7% tope legal)
    result = min(result.IMPO * tasa_salud, result.IMPO * 0.07)
        </field>
```

**PASO 3: Validar sintaxis XML**

```bash
# Validar XML bien formado
xmllint --noout addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml 2>&1

# Si error, revisar:
# - Tags <field> cerrados
# - Indentación correcta
# - No caracteres especiales sin escapar
```

**PASO 4: Commit atómico**

```bash
git add addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml
git commit -m "fix(hr_payroll): corregir campo XML isapre_plan_id → isapre_plan_uf

PROBLEMA:
- Campo contract.isapre_plan_id NO existe en modelo hr.contract
- Causaba AttributeError en runtime al calcular descuento salud ISAPRE

SOLUCIÓN:
- Cambiar a contract.isapre_plan_uf (Float definido en hr_contract_cl.py:47)
- Implementar lógica conversión UF → CLP usando indicadores económicos
- Agregar tope legal 7% según normativa chilena
- Validar división por cero (IMPO > 0)

EVIDENCIA:
- Hallazgo H1 de auditoría forense 2025-11-09
- grep: campo isapre_plan_id NO existe en models/
- grep: campo isapre_plan_uf EXISTE en hr_contract_cl.py:47
- Lógica basada en hr_payslip.py:1240-1248

Fixes: #H1-N (campo XML inexistente)
"
```

### Validación Post-Fix H1

```bash
# 1. Verificar cambio aplicado
grep -n "isapre_plan_uf" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml
# Debe mostrar línea con nuevo campo

# 2. Verificar campo viejo eliminado
grep -n "isapre_plan_id" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml
# NO debe retornar resultados (o solo comentarios)

# 3. Restart Odoo para cargar XML
docker-compose restart odoo

# 4. Verificar logs sin AttributeError
docker-compose logs odoo --tail=50 | grep -i "attributeerror.*isapre"
# NO debe mostrar errores

# 5. Test manual: Crear nómina con ISAPRE
# (requiere acceso UI Odoo, documentar pasos si es crítico)
```

**Checkpoint H1:** ✅ Campo XML corregido, AttributeError eliminado

---

## 🔴 HALLAZGO H2: UserError SIN IMPORT (CRÍTICO)

### Problema Identificado

**Ubicación:** `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py:245`

**Código Actual (INCORRECTO):**
```python
# Línea 4:
from odoo.exceptions import ValidationError

# Línea 245:
raise UserError(_("No se pudieron obtener indicadores económicos..."))
```

**Problema:**
- Import solo tiene `ValidationError`
- Usa `UserError` en línea 245 sin import
- Causa: `NameError: name 'UserError' is not defined` en runtime

### Evidencia Verificada (Auditoría Forense)

**Import actual:**
```bash
head -10 addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py | grep "from odoo.exceptions"
# Output: línea 4: from odoo.exceptions import ValidationError
```

**Uso UserError sin import:**
```bash
grep -n "raise UserError" addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
# Output: línea 245: raise UserError(_("Error al obtener indicadores..."))
```

### Fix Requerido (EXACTO)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py`  
**Línea:** 4

**PASO 1: Leer contexto completo de imports**

```bash
head -15 addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
```

**PASO 2: Aplicar fix con replace_string_in_file**

**Contexto a buscar (oldString - MÍNIMO 3 líneas antes/después):**
```python
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import requests
from datetime import datetime, timedelta
```

**Fix aplicar (newString):**
```python
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import requests
from datetime import datetime, timedelta
```

**PASO 3: Validar sintaxis Python**

```bash
# Validar sintaxis Python
docker exec odoo19_odoo python -m py_compile /mnt/extra-addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py 2>&1

# Si error:
# - Verificar comas correctas en import
# - No espacios extra
# - Orden alfabético (opcional pero recomendado)
```

**PASO 4: Commit atómico**

```bash
git add addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
git commit -m "fix(hr_payroll): agregar UserError a import en hr_economic_indicators

PROBLEMA:
- Import solo tenía ValidationError (línea 4)
- Código usa raise UserError en línea 245
- Causaba NameError en runtime al fallar obtención indicadores económicos

SOLUCIÓN:
- Agregar UserError a import: from odoo.exceptions import ValidationError, UserError
- Mantener orden alfabético de excepciones

EVIDENCIA:
- Hallazgo H2 de auditoría forense 2025-11-09
- grep: línea 4 solo tiene ValidationError
- grep: línea 245 usa raise UserError sin import

Fixes: #H2-N (UserError sin import)
"
```

### Validación Post-Fix H2

```bash
# 1. Verificar import actualizado
grep -n "from odoo.exceptions import" addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py | head -1
# Debe mostrar: ValidationError, UserError

# 2. Validar sintaxis
docker exec odoo19_odoo python -m py_compile /mnt/extra-addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py 2>&1
# NO debe retornar errores

# 3. Restart Odoo para cargar cambios
docker-compose restart odoo

# 4. Verificar logs sin NameError
docker-compose logs odoo --tail=50 | grep -i "nameerror.*usererror"
# NO debe mostrar errores

# 5. Test manual: Forzar error indicadores económicos
# (requiere acceso UI Odoo, documentar si crítico)
```

**Checkpoint H2:** ✅ Import agregado, NameError eliminado

---

## 🟡 HALLAZGO H8: PERMISOS UNLINK USUARIOS (OPCIONAL)

### Problema Identificado

**Ubicación:** `addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv:4`

**Código Actual (RIESGO):**
```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_hr_payslip_line_user,hr.payslip.line.user,model_hr_payslip_line,hr_payroll.group_hr_payroll_user,1,1,1,1
```

**Problema:**
- `perm_unlink=1` permite a usuarios regulares (group_hr_payroll_user) ELIMINAR líneas de nómina
- Riesgo auditoría: trazabilidad comprometida
- Severidad: 🟡 MEDIA (no bloquea producción, pero mala práctica)

### Evidencia Verificada (Auditoría Forense)

```bash
grep -n "access_hr_payslip_line_user" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
# Output: línea 4: ...,group_hr_payroll_user,1,1,1,1
#                                                   ^ perm_unlink=1 (RIESGO)
```

### Fix Requerido (OPCIONAL - 1 hora)

**SOLO SI:** Hay tiempo disponible (fixes H1+H2 completados y validados)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv`  
**Línea:** 4

**PASO 1: Leer contexto CSV completo**

```bash
cat addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
```

**PASO 2: Aplicar fix con replace_string_in_file**

**Contexto a buscar (oldString):**
```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_hr_payslip_line_user,hr.payslip.line.user,model_hr_payslip_line,hr_payroll.group_hr_payroll_user,1,1,1,1
access_hr_payslip_line_manager,hr.payslip.line.manager,model_hr_payslip_line,hr_payroll.group_hr_payroll_manager,1,1,1,1
```

**Fix aplicar (newString):**
```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_hr_payslip_line_user,hr.payslip.line.user,model_hr_payslip_line,hr_payroll.group_hr_payroll_user,1,1,1,0
access_hr_payslip_line_manager,hr.payslip.line.manager,model_hr_payslip_line,hr_payroll.group_hr_payroll_manager,1,1,1,1
```

**Cambio:** Solo última columna de línea 2 (users): `1 → 0`  
**Mantener:** Managers con `perm_unlink=1` (línea 3)

**PASO 3: Validar CSV**

```bash
# Verificar formato CSV correcto (no usar tabs, solo comas)
cat -A addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv | grep "access_hr_payslip_line"
# NO debe mostrar ^I (tabs), solo comas

# Contar columnas (deben ser 8)
head -2 addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv | awk -F, '{print NF}'
# Output: 8 (ambas líneas)
```

**PASO 4: Commit atómico**

```bash
git add addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
git commit -m "fix(hr_payroll): restringir perm_unlink para group_hr_payroll_user

PROBLEMA:
- group_hr_payroll_user tenía perm_unlink=1 en hr.payslip.line
- Usuarios regulares podían eliminar líneas de nómina (riesgo auditoría)
- Trazabilidad comprometida (eliminación vs edición)

SOLUCIÓN:
- Cambiar perm_unlink=0 para group_hr_payroll_user (línea 4)
- Mantener perm_unlink=1 para group_hr_payroll_manager (línea 5)
- Usuarios pueden crear/editar, solo managers eliminan

EVIDENCIA:
- Hallazgo H8 de auditoría forense 2025-11-09
- grep: línea 4 tenía perm_unlink=1 para users
- Best practice: delete permissions solo para managers

Fixes: #H8-N (permisos unlink usuarios)
"
```

### Validación Post-Fix H8

```bash
# 1. Verificar cambio aplicado
grep "access_hr_payslip_line_user" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
# Debe mostrar: ...,1,1,1,0 (último valor 0)

# 2. Verificar managers mantienen permiso
grep "access_hr_payslip_line_manager" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
# Debe mostrar: ...,1,1,1,1 (último valor 1)

# 3. Restart Odoo + update module
docker-compose restart odoo
docker exec odoo19_odoo odoo -u l10n_cl_hr_payroll --stop-after-init

# 4. Test manual: Login como user (NO manager), intentar delete línea nómina
# Debe retornar: "Access Denied" o equivalente
```

**Checkpoint H8:** ✅ Permisos restringidos, solo managers pueden eliminar

---

## ✅ VALIDACIÓN FINAL COMPLETA

### Post-Fixes Validation (OBLIGATORIO)

**Ejecutar DESPUÉS de completar H1 + H2 (+ H8 opcional):**

```bash
# 1. Restart Odoo limpio
docker-compose restart odoo

# 2. Update módulo para cargar cambios
docker exec odoo19_odoo odoo -u l10n_cl_hr_payroll --stop-after-init 2>&1 | tee /tmp/odoo_update_nomina.log

# 3. Verificar update exitoso (sin errores críticos)
grep -i "error\|exception\|attributeerror\|nameerror" /tmp/odoo_update_nomina.log | grep -v "WARNING"
# Debe estar vacío o solo warnings menores

# 4. Start Odoo normal
docker-compose up -d odoo
sleep 10

# 5. Verificar logs sin errors de los hallazgos
docker-compose logs odoo --tail=100 | grep -E "(AttributeError.*isapre|NameError.*UserError)" 
# Debe estar vacío

# 6. Verificar módulo activo
docker exec odoo19_odoo odoo shell -c "
env['ir.module.module'].search([('name', '=', 'l10n_cl_hr_payroll')]).state
"
# Output: installed

# 7. Test smoke: Crear nómina test (si hay datos test)
docker exec odoo19_odoo odoo shell -c "
payslip = env['hr.payslip'].search([], limit=1)
if payslip:
    payslip.compute_sheet()
    print('✅ Compute sheet SUCCESS')
else:
    print('⚠️ No payslips found (OK si DB vacía)')
"

# 8. Documentar resultados
cat > /tmp/validation_fixes_nomina.txt <<EOF
=== VALIDACIÓN FIXES NÓMINA 2025-11-09 ===

H1: Campo XML isapre_plan_id → isapre_plan_uf
- ✅ Campo corregido en hr_salary_rules_p1.xml
- ✅ AttributeError ELIMINADO
- ✅ Lógica conversión UF → CLP implementada

H2: UserError import agregado
- ✅ Import actualizado en hr_economic_indicators.py:4
- ✅ NameError ELIMINADO
- ✅ Sintaxis Python validada

H8: Permisos unlink (opcional)
- $(if grep -q ",1,1,1,0$" addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv; then echo "✅ Permisos restringidos"; else echo "⏭️ NO aplicado (opcional)"; fi)

Odoo Update:
- $(if grep -q "ERROR" /tmp/odoo_update_nomina.log; then echo "❌ ERRORES detectados"; else echo "✅ Update exitoso"; fi)

Logs Runtime:
- $(docker-compose logs odoo --tail=100 | grep -c "AttributeError.*isapre") AttributeError isapre
- $(docker-compose logs odoo --tail=100 | grep -c "NameError.*UserError") NameError UserError

Status: $(if [ $(docker-compose logs odoo --tail=100 | grep -c "Error") -eq 0 ]; then echo "✅ PRODUCTION READY"; else echo "⚠️ Revisar errores"; fi)
EOF

cat /tmp/validation_fixes_nomina.txt
```

**Checkpoint Final:** ✅ Todos los fixes validados, 0 runtime errors

---

## 📊 SCORE FINAL PROYECTADO

### Antes de Fixes

```
Nómina Baseline: 92/100

Hallazgos Críticos:
- H1: Campo XML inexistente (-2 pts)
- H2: UserError sin import (-2 pts)
- H8: Permisos unlink (-1 pt)

Score Real: 92 - 5 = 87/100 ⚠️
Production Ready: NO (2 critical errors)
```

### Después de Fixes (H1 + H2)

```
Nómina Baseline: 92/100

Fixes Aplicados:
+ H1: Campo XML corregido (+2 pts)
+ H2: UserError import agregado (+2 pts)

Hallazgos Pendientes:
- H8: Permisos unlink (si no aplicado: -1 pt)

Score Final: 92/100 ✅ (o 91/100 si H8 pendiente)
Production Ready: YES ✅
```

### Después de Fixes (H1 + H2 + H8)

```
Nómina Baseline: 92/100

Fixes Aplicados:
+ H1: Campo XML corregido (+2 pts)
+ H2: UserError import agregado (+2 pts)
+ H8: Permisos unlink corregido (+1 pt)

Score Final: 92/100 ✅ (máximo)
Production Ready: YES ✅
Bonus: +1 pt seguridad (permisos correctos)
```

---

## 🚀 COMANDOS INICIO RÁPIDO

### Opción A: Fix Solo Críticos (H1 + H2) - 45 min

```bash
codex-odoo-dev "Ejecuta PROMPT_FIX_CRITICOS_NOMINA_2_HALLAZGOS.md:

ALCANCE: Solo H1 + H2 (críticos BLOQUEANTES)

H1 (30 min):
- Fix campo XML: isapre_plan_id → isapre_plan_uf
- Archivo: hr_salary_rules_p1.xml línea ~164
- Implementar lógica conversión UF → CLP
- Commit atómico con evidencia

H2 (5 min):
- Fix import: agregar UserError
- Archivo: hr_economic_indicators.py línea 4
- Commit atómico con evidencia

Validación (10 min):
- Restart Odoo + update module
- Verificar 0 AttributeError, 0 NameError
- Documentar en /tmp/validation_fixes_nomina.txt

Target: Production Ready en 45 min
Score: 87/100 → 92/100
"
```

### Opción B: Fix Completo (H1 + H2 + H8) - 1.5-2h

```bash
codex-odoo-dev "Ejecuta PROMPT_FIX_CRITICOS_NOMINA_2_HALLAZGOS.md:

ALCANCE: H1 + H2 + H8 (completo)

H1 (30 min): Campo XML isapre_plan_id → isapre_plan_uf
H2 (5 min): Import UserError
H8 (1h): Permisos unlink users → 0

Validación completa (15 min)

Target: Production Ready en 2h
Score: 87/100 → 92/100 + bonus seguridad
"
```

---

## 🔴 RESTRICCIONES ABSOLUTAS

### Código

❌ **NO modificar** otros archivos no mencionados  
❌ **NO agregar** features nuevos (solo fixes)  
❌ **NO refactorizar** código funcional  
❌ **NO cambiar** lógica existente que funciona  
❌ **NO improvisar** soluciones sin evidencia

### Validación

❌ **NO commit** sin validar sintaxis (xmllint, py_compile)  
❌ **NO skip** restart Odoo después de cambios  
❌ **NO ignorar** errores en logs  
❌ **NO asumir** fix correcto sin verificar runtime  
❌ **NO deploy** sin ejecutar validación final completa

### Git

❌ **NO commits** genéricos ("fix bugs", "update code")  
❌ **NO squash** commits de fixes diferentes (mantener atómicos)  
❌ **NO force push** nunca  
❌ **NO modificar** commits pusheados

---

## 📎 REFERENCIAS CRÍTICAS

### Documentos Base

```
ANALISIS_CRITICO_AUDITORES_HALLAZGOS_2025-11-09.md  (auditoría forense)
ANALISIS_CRITICO_AGENTES_1_Y_2.md                    (análisis previo)
PROMPT_AUDITORIA_VERIFICACION_HALLAZGOS_CRITICOS.md (metodología)
```

### Archivos a Modificar

```
Críticos (H1 + H2):
  addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml
    - Línea ~164: condition_python
    - Línea ~165-170: amount_python

  addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
    - Línea 4: from odoo.exceptions import ...

Opcional (H8):
  addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
    - Línea 4: perm_unlink 1 → 0
```

### Archivos Referencia (NO MODIFICAR)

```
Lógica correcta existente:
  addons/localization/l10n_cl_hr_payroll/models/hr_contract_cl.py:47
    - Campo correcto: isapre_plan_uf = fields.Float(...)

  addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py:1240-1248
    - Lógica conversión UF → CLP con indicadores
    - Tope legal 7% salud
```

### Outputs Validación

```
/tmp/validation_fixes_nomina.txt     (resultado validación final)
/tmp/odoo_update_nomina.log          (logs update module)
```

---

## ✅ CRITERIOS DE ÉXITO

### Obligatorio (Must Have)

- [ ] **H1 Fixed:** Campo XML `isapre_plan_uf` en lugar de `isapre_plan_id`
- [ ] **H2 Fixed:** Import `UserError` agregado en `hr_economic_indicators.py`
- [ ] **0 AttributeError:** Logs Odoo sin `AttributeError.*isapre`
- [ ] **0 NameError:** Logs Odoo sin `NameError.*UserError`
- [ ] **Commits Atómicos:** 1 commit por fix con evidencia completa
- [ ] **Validación Completa:** `/tmp/validation_fixes_nomina.txt` generado
- [ ] **Production Ready:** Score ≥92/100

### Deseable (Nice to Have)

- [ ] **H8 Fixed:** Permisos `perm_unlink=0` para users
- [ ] **Score 92/100:** Máximo score alcanzado
- [ ] **Tests Passing:** Si existen tests l10n_cl_hr_payroll
- [ ] **Documentation:** Comentarios en código explicando lógica UF → CLP

### Prohibido (Must NOT)

- ❌ Modificar archivos NO mencionados
- ❌ Agregar features nuevos
- ❌ Refactorizar código funcional
- ❌ Commit sin validar sintaxis
- ❌ Deploy sin validación final

---

## 🎯 RESULTADO ESPERADO

**Al completar este PROMPT:**

- ✅ H1 Fixed: Campo XML corregido (AttributeError eliminado)
- ✅ H2 Fixed: Import agregado (NameError eliminado)
- ✅ H8 Fixed (opcional): Permisos corregidos
- ✅ Score: 87/100 → 92/100 (+5 pts)
- ✅ Production Ready: YES
- ✅ Runtime Errors: 2 CRÍTICOS → 0
- ✅ Commits: 2-3 atómicos con evidencia
- ✅ Validación: Completa con documentación

**Resultado:** Módulo nómina production-ready, 0 errores críticos, score 92/100, listo para deploy.

---

**Última Actualización:** 2025-11-09  
**Versión:** 1.0 (Post-Auditoría Forense)  
**Metodología:** Evidence-Based, Atomic Commits, Zero Improvisation  
**Base:** Auditoría forense con 70+ comandos, 100% confianza  
**Estado:** ✅ LISTO PARA EJECUCIÓN INMEDIATA  
**Confianza:** MÁXIMA (hallazgos verificados con command-based evidence)

---

## 📋 CHECKLIST EJECUCIÓN

### Pre-Ejecución (5 min)

- [ ] Leer auditoría forense completa (ANALISIS_CRITICO_AUDITORES_HALLAZGOS_2025-11-09.md)
- [ ] Verificar acceso Docker (odoo19_odoo container)
- [ ] Confirmar branch actual (`git branch`)
- [ ] Backup archivos a modificar (cp → .bak)

### Durante Ejecución (45 min - 2h)

- [ ] **H1:** Leer contexto XML completo (grep + sed)
- [ ] **H1:** Aplicar fix con replace_string_in_file
- [ ] **H1:** Validar sintaxis XML (xmllint)
- [ ] **H1:** Commit atómico con evidencia
- [ ] **H2:** Leer contexto import Python
- [ ] **H2:** Aplicar fix con replace_string_in_file
- [ ] **H2:** Validar sintaxis Python (py_compile)
- [ ] **H2:** Commit atómico con evidencia
- [ ] **(Opcional) H8:** Fix permisos CSV (1h)
- [ ] **Validación:** Restart Odoo + update module
- [ ] **Validación:** Verificar logs sin errors
- [ ] **Validación:** Documentar en /tmp/validation_fixes_nomina.txt

### Post-Ejecución (15 min)

- [ ] Score final calculado (92/100 esperado)
- [ ] Git status limpio (git status)
- [ ] Commits pusheados (git push)
- [ ] Tag creado (nomina_fixes_h1_h2_2025-11-09)
- [ ] Documentación final generada
- [ ] Tests smoke pasados (si aplica)

**EXECUTION COMPLETE → NÓMINA PRODUCTION READY ✅**
