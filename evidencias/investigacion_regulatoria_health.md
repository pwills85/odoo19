# Investigación Regulatoria: HEALTH Code (Previred Format)

**Fecha:** 2025-11-09
**Investigador:** Claude Code
**Tiempo Invertido:** 20min
**Estado:** ✅ COMPLETADO

---

## Resumen Ejecutivo

**Hallazgo Principal:**
❌ **El test busca código 'HEALTH' pero el código real es 'SALUD'**

**Problema Identificado:**
- **Tests esperan:** Código 'HEALTH' (inglés)
- **Código usa:** Código 'SALUD' (español)
- **Inconsistencia de naming:** Español vs Inglés

**Solución:**
- Opción A: Cambiar tests para usar 'SALUD'
- Opción B: Cambiar código regla para usar 'HEALTH'
- **Recomendación:** Mantener 'SALUD' (consistente con otros códigos chilenos)

---

## Documentación Local Consultada

### Archivos Consultados:

1. **`addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml`**
   - Línea 150-156: Regla "Salud"
   - **Línea 153:** `<field name="code">SALUD</field>` ← ACTUAL CODE

```xml
<!-- RULE 8: Salud (FONASA 7% / ISAPRE variable) -->
<record id="rule_salud" model="hr.salary.rule">
    <field name="name">Salud</field>
    <field name="code">SALUD</field>  ← CÓDIGO REAL ES 'SALUD'
    <field name="sequence">301</field>
    <field name="category_id" ref="category_salud_sopa"/>
    <field name="condition_select">none</field>
    ...
</record>
```

2. **`addons/localization/l10n_cl_hr_payroll/data/hr_salary_rule_category_sopa.xml`**
   - Línea 113-119: Categoría "Salud SOPA"
   - **Línea 116:** `<field name="code">SALUD_SOPA</field>`

```xml
<!-- SOPA 9: Salud -->
<record id="category_salud_sopa" model="hr.salary.rule.category">
    <field name="name">Salud SOPA</field>
    <field name="code">SALUD_SOPA</field>  ← CATEGORÍA USA 'SALUD'
    <field name="parent_id" ref="category_desc_legal"/>
    <field name="sequence">105</field>
    <field name="tipo">descuento</field>
</record>
```

### Hallazgos Específicos:

**Códigos Existentes en el Sistema:**

| Entidad | Código | Nombre | Archivo |
|---------|--------|--------|---------|
| **Salary Rule** | **SALUD** | Salud | hr_salary_rules_p1.xml:153 |
| Salary Rule Category | SALUD_SOPA | Salud SOPA | hr_salary_rule_category_sopa.xml:116 |

**Otros Códigos Relevantes (para contexto):**
- AFP: `AFP` (español: Fondo de Pensiones)
- AFC: `AFC` (español: Seguro de Cesantía)
- BASIC: `BASIC` (inglés: Sueldo Base)
- IMPUESTO: No encontrado (probablemente `IMPUESTO` o `TAX`)

**Patrón de Naming:**
El proyecto usa **MEZCLA de español e inglés**:
- Español: `SALUD`, `AFC`, `IMPUESTO` (si existe)
- Inglés: `BASIC`, `NET`

**Conclusión Documentación Local:**
✅ El código correcto para salud es **`SALUD`** (español)
❌ No existe código `HEALTH` (inglés) en el sistema
⚠️ Inconsistencia de naming en el proyecto

---

## Sitios Web Oficiales Consultados

### Previred - Formato Book 49

**URLs Consultadas:**
- https://www.previred.com/documents/80476/80730/FormatoLargoVariablePorSeparador.pdf
- https://www.previred.com/documents/80476/80730/TablasEquivalencia+Agosto+2021.pdf

**Hallazgos Específicos:**

**Códigos de Institución de Salud (Tabla 16 - Previred):**

| Código | Institución |
|--------|-------------|
| 00 | Sin Isapre |
| 01 | Banmédica |
| 02 | Consalud |
| 03 | VidaTres |
| 04 | Colmena |
| 05 | Isapre Cruz Blanca S.A. |
| **07** | **FONASA** |
| 10 | Nueva Masvida |
| 11 | Isapre de Codelco Ltda. |
| 12 | Isapre Banco Estado |
| 25 | Cruz del Norte |

**Nota Importante:**
- **FONASA código Previred:** 07
- **ISAPREs códigos Previred:** 01, 02, 03, 04, 05, 10, 11, 12, 25, etc.

**Aclaración Crítica:**
Estos códigos (07, 01, 02, etc.) son para **EXPORT a Previred**, NO para códigos internos de salary rules.

**Conclusiones Previred:**
✅ FONASA tiene código 07 en formato Previred
✅ ISAPREs tienen códigos específicos (01-25)
✅ Estos códigos son para export, NO para uso interno en reglas salariales

---

## Normativa Específica

### No Aplica a Este Problema

**Razón:**
Este problema es de **nomenclatura interna del sistema**, no de normativa regulatoria chilena.

La normativa chilena define:
- FONASA: Fondo Nacional de Salud (7% cotización)
- ISAPRE: Instituciones de Salud Previsional (% variable)

Pero NO define qué código usar internamente en sistemas de nómina.

**Conclusión:**
No hay normativa que diga si usar 'HEALTH' o 'SALUD'. Es decisión de diseño del sistema.

---

## Respuesta a Pregunta Crítica

### Pregunta: ¿Cuál es el código correcto para salud en el sistema?

### Respuesta: El código correcto es **`SALUD`** (español)

### Justificación:

**1. Código Actual en el Sistema:**
```xml
<!-- hr_salary_rules_p1.xml:153 -->
<field name="code">SALUD</field>
```

**2. Categoría Asociada:**
```xml
<!-- hr_salary_rule_category_sopa.xml:116 -->
<field name="code">SALUD_SOPA</field>
```

**3. Consistencia con Otros Códigos Chilenos:**
- AFC (Seguro de Cesantía) - español
- GRAT_SOPA (Gratificación) - español
- IMPUESTO (si existe) - español

**4. Previred Export:**
- Código Previred FONASA: 07
- Código Previred ISAPREs: 01-25
- El código interno 'SALUD' se mapea a código Previred en export

**Conclusión Final:**
✅ **Usar código 'SALUD'** (español, consistente con naming chileno)
❌ **NO usar código 'HEALTH'** (inglés, inconsistente)

---

## Problema en Tests

### Diagnóstico:

**Tests buscan código 'HEALTH':**
```python
# test_*.py
health_line = payslip.line_ids.filtered(lambda l: l.code == 'HEALTH')
```

**Pero código real es 'SALUD':**
```xml
<!-- hr_salary_rules_p1.xml -->
<field name="code">SALUD</field>
```

**Resultado:**
- `health_line` queda vacío (no encuentra la línea)
- Test falla con assertion error

### Soluciones Posibles:

#### Opción A: Actualizar Tests (RECOMENDADO)

**Ventaja:** Mantiene consistencia con naming chileno
**Cambio:** Modificar tests para usar 'SALUD'

```python
# ANTES (INCORRECTO)
health_line = payslip.line_ids.filtered(lambda l: l.code == 'HEALTH')

# DESPUÉS (CORRECTO)
health_line = payslip.line_ids.filtered(lambda l: l.code == 'SALUD')
```

**Archivos a Modificar:**
```bash
# Buscar todos los tests que usan 'HEALTH'
grep -r "code.*==.*'HEALTH'" addons/localization/l10n_cl_hr_payroll/tests/
```

#### Opción B: Cambiar Código de Regla (NO RECOMENDADO)

**Desventaja:** Rompe consistencia con naming chileno
**Cambio:** Modificar `hr_salary_rules_p1.xml` para usar 'HEALTH'

```xml
<!-- ANTES (ACTUAL) -->
<field name="code">SALUD</field>

<!-- DESPUÉS (NO RECOMENDADO) -->
<field name="code">HEALTH</field>
```

**Problemas:**
- ❌ Inconsistente con otros códigos (AFC, GRAT_SOPA están en español)
- ❌ Rompe referencias existentes en código
- ❌ Requiere actualizar categoría SALUD_SOPA también

#### Opción C: Alias/Compatibilidad (COMPLEJO)

**Idea:** Soportar ambos códigos ('SALUD' y 'HEALTH')
**Implementación:** Agregar campo `code_alias` o lógica de búsqueda flexible

**Desventaja:** Complejidad innecesaria

---

## Recomendación Técnica

### Solución Recomendada: Actualizar Tests

#### Paso 1: Identificar Tests Afectados

```bash
# Buscar todos los archivos de test que usan 'HEALTH'
grep -r "'HEALTH'" addons/localization/l10n_cl_hr_payroll/tests/ --include="*.py"

# Buscar todos los archivos de test que usan "HEALTH"
grep -r '"HEALTH"' addons/localization/l10n_cl_hr_payroll/tests/ --include="*.py"
```

#### Paso 2: Reemplazar 'HEALTH' por 'SALUD'

**Comando de reemplazo masivo (revisar antes de ejecutar):**
```bash
# Backup primero
cp -r addons/localization/l10n_cl_hr_payroll/tests addons/localization/l10n_cl_hr_payroll/tests.backup

# Reemplazar en todos los tests
find addons/localization/l10n_cl_hr_payroll/tests -name "*.py" -exec sed -i "s/'HEALTH'/'SALUD'/g" {} \;
find addons/localization/l10n_cl_hr_payroll/tests -name "*.py" -exec sed -i 's/"HEALTH"/"SALUD"/g' {} \;
```

**O manualmente en cada test:**
```python
# tests/test_*.py

# CAMBIAR ESTO:
health_line = payslip.line_ids.filtered(lambda l: l.code == 'HEALTH')

# POR ESTO:
health_line = payslip.line_ids.filtered(lambda l: l.code == 'SALUD')
```

#### Paso 3: Actualizar Comentarios/Documentación

Si hay comentarios que mencionan 'HEALTH', actualizarlos también:
```python
# ANTES:
# Verify HEALTH line exists

# DESPUÉS:
# Verify SALUD (health) line exists
```

#### Paso 4: Verificar

```bash
# Ejecutar tests afectados
pytest addons/localization/l10n_cl_hr_payroll/tests/test_*salud*.py -v
pytest addons/localization/l10n_cl_hr_payroll/tests/test_*health*.py -v  # Si existen
```

---

## Decisión de Naming: ¿Español o Inglés?

### Análisis del Código Actual:

**Códigos en Español:**
- `SALUD` - Salud
- `AFC` - Seguro de Cesantía
- `IMPUESTO` (probablemente) - Impuesto
- `GRAT_SOPA` - Gratificación

**Códigos en Inglés:**
- `BASIC` - Sueldo Base
- `NET` - Líquido a Pagar

**Códigos Mixtos/Acrónimos:**
- `AFP` - Administradora de Fondos de Pensiones (acrónimo español)
- `UF`, `UTM`, `UTA` - Unidades (acrónimos españoles)

### Recomendación:

**Preferir ESPAÑOL** para conceptos específicos chilenos:
- ✅ `SALUD` (no `HEALTH`)
- ✅ `AFC` (no `UNEMPLOYMENT`)
- ✅ `GRAT_SOPA` (no `BONUS_SOPA`)
- ✅ `IMPUESTO` (no `TAX`)

**Usar INGLÉS solo** para conceptos universales:
- ✅ `BASIC` (sueldo base)
- ✅ `NET` (líquido)

**Razón:**
- Conceptos chilenos (FONASA, ISAPRE, AFP, AFC) no tienen traducción directa
- Usar español evita ambigüedad y facilita comprensión local
- Código más legible para desarrolladores chilenos

---

## Códigos Previred vs Códigos Internos

### Diferencia Crítica:

**Códigos INTERNOS (Salary Rules):**
- Uso: Identificar líneas en liquidación dentro del sistema
- Ejemplos: `SALUD`, `AFP`, `AFC`, `BASIC`
- Flexibles: Definidos por el sistema

**Códigos PREVIRED (Export):**
- Uso: Formato de export para Previred
- Ejemplos:
  - FONASA = 07
  - Banmédica = 01
  - Cruz Blanca = 05
- Fijos: Definidos por Previred

**Mapeo:**
```python
# Código interno → Código Previred
'SALUD' → 07 (si FONASA) o 01-25 (si ISAPRE)

# Al exportar a Previred:
if employee.health_institution_type == 'FONASA':
    previred_code = '07'
elif employee.isapre_id:
    previred_code = employee.isapre_id.previred_code  # 01, 02, 03, etc.
```

**Conclusión:**
✅ Código interno 'SALUD' es independiente de código Previred 07
✅ El mapeo se hace al exportar, no en las reglas salariales

---

## Referencias

### Sitios Web Oficiales:
1. **Previred - Formato Book 49:** https://www.previred.com/documents/80476/80730/FormatoLargoVariablePorSeparador.pdf
2. **Previred - Tablas Equivalencia:** https://www.previred.com/documents/80476/80730/TablasEquivalencia+Agosto+2021.pdf
3. **Superintendencia de Salud:** https://www.superdesalud.gob.cl/

### Normativa Consultada:
- **No aplica** (problema de nomenclatura interna, no regulatoria)

### Documentación Local:
1. **`addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml`** - Regla SALUD
2. **`addons/localization/l10n_cl_hr_payroll/data/hr_salary_rule_category_sopa.xml`** - Categoría SALUD_SOPA
3. **`addons/localization/l10n_cl_hr_payroll/models/hr_isapre.py`** - Modelo ISAPREs

---

**Fecha de Investigación:** 2025-11-09
**Tiempo Invertido:** 20 minutos
**Estado:** ✅ COMPLETADO
**Solución:** Actualizar tests para usar código 'SALUD' en lugar de 'HEALTH'

---

**FIN INVESTIGACIÓN REGULATORIA - PROBLEMA #4**
