# Root Cause Analysis: total_imponible Inflado

**Fecha:** 2025-11-09
**Fase:** 1 - Root Cause Analysis
**Problema:** total_imponible ~8M vs ~1M esperado
**Sprint:** 2 - Cierre Total de Brechas

---

## 🔴 ROOT CAUSE IDENTIFICADO: DOBLE/TRIPLE CONTEO DE TOTALIZADORES

### Síntomas Observados

**Tests Fallando:**
1. `test_bonus_imponible`: total_imponible = 8.387.975 (esperado: 1.050.000) - Diferencia: +7.3M
2. `test_allowance_colacion`: total_imponible = 8.148.631 (esperado: 1.000.000) - Diferencia: +7.1M

**Patrón:** El total_imponible está aproximadamente 7-8x más grande de lo esperado.

---

## 🔍 Investigación

### Método `_compute_totals()` (hr_payslip.py:344-348)

```python
# Total Imponible (base AFP/Salud)
imponible_lines = payslip.line_ids.filtered(
    lambda l: l.category_id and l.category_id.imponible == True
)
payslip.total_imponible = sum(imponible_lines.mapped('total'))
```

**Lógica:** Suma TODAS las líneas de la liquidación cuya categoría tenga `imponible=True`.

### Problema: Reglas Totalizadoras con `imponible=True`

**Reglas Salariales Afectadas:**

#### 1. HABERES_IMPONIBLES (hr_salary_rules_p1.xml:24-37)
```xml
<record id="rule_total_haberes_imponibles" model="hr.salary.rule">
    <field name="code">HABERES_IMPONIBLES</field>
    <field name="category_id" ref="category_haber_imponible"/>  <!-- ❌ imponible=True -->
    <field name="amount_python_compute">
result = sum([line.total for line in payslip.line_ids if line.category_id.imponible and line.total > 0])
    </field>
</record>
```

- **Categoría:** `category_haber_imponible` (IMPO)
- **Flags:** `imponible=True`, `tributable=True`, `afecta_gratificacion=True`
- **Problema:** Es un TOTALIZADOR que calcula la suma de líneas imponibles, pero su categoría tiene `imponible=True`, causando que SE SUME A SÍ MISMO

#### 2. TOTAL_IMPONIBLE (hr_salary_rules_p1.xml:57-69)
```xml
<record id="rule_total_imponible" model="hr.salary.rule">
    <field name="code">TOTAL_IMPONIBLE</field>
    <field name="category_id" ref="category_base"/>  <!-- ❌ imponible=True -->
    <field name="amount_python_compute">
result = categories.HABERES_IMPONIBLES
    </field>
</record>
```

- **Categoría:** `category_base` (BASE)
- **Flags:** `imponible=True`, `tributable=True`, `afecta_gratificacion=True`
- **Problema:** Copia el valor de HABERES_IMPONIBLES, pero su categoría tiene `imponible=True`, causando OTRO DOBLE CONTEO

---

## 📊 Secuencia de Cálculo (Ejemplo)

**Liquidación de Test:** Sueldo 1M + Bono 50K

### Paso 1: Reglas Base (Secuencia 10-99)
| Código | Categoría | Imponible | Monto | Descripción |
|--------|-----------|-----------|-------|-------------|
| BASIC | BASE_SOPA | ✓ True | 1.000.000 | Sueldo base |
| BONO_PROD | BONO_IMPONIBLE_SOPA | ✓ True | 50.000 | Bono producción |

**Subtotal líneas reales:** 1.050.000

### Paso 2: Totalizadores (Secuencia 100-299)
| Código | Categoría | Imponible | Monto | Descripción |
|--------|-----------|-----------|-------|-------------|
| HABERES_IMPONIBLES | IMPO | ❌ True | 1.050.000 | Suma de líneas imponibles |
| TOTAL_IMPONIBLE | BASE | ❌ True | 1.050.000 | Copia de HABERES_IMPONIBLES |

### Paso 3: Cálculo de `total_imponible` por `_compute_totals()`

```python
imponible_lines = payslip.line_ids.filtered(lambda l: l.category_id.imponible == True)
# Líneas seleccionadas:
# - BASIC: 1.000.000 (✓ correcto)
# - BONO_PROD: 50.000 (✓ correcto)
# - HABERES_IMPONIBLES: 1.050.000 (❌ totalizador, no debería sumarse)
# - TOTAL_IMPONIBLE: 1.050.000 (❌ totalizador, no debería sumarse)

total_imponible = 1.000.000 + 50.000 + 1.050.000 + 1.050.000
                = 3.150.000  # ❌ Triple conteo!
```

**Nota:** En la práctica, el valor es aún mayor (~8M) porque hay más reglas totalizadoras con el mismo problema.

---

## ✅ SOLUCIÓN IDENTIFICADA

### Cambiar Categorías de Reglas Totalizadoras

Las reglas `HABERES_IMPONIBLES` y `TOTAL_IMPONIBLE` NO deben tener categorías con `imponible=True`. Deben usar una categoría de tipo "totalizador" que NO afecte cálculos.

**Categoría Correcta Ya Existe:**
```xml
<!-- category_total_imponible (TOTAL_IMPO) -->
<record id="category_total_imponible" model="hr.salary.rule.category">
    <field name="code">TOTAL_IMPO</field>
    <field name="tipo">totalizador</field>
    <!-- NO tiene imponible=True -->
    <!-- NO tiene tributable=True -->
</record>
```

**Cambios Necesarios:**

1. **HABERES_IMPONIBLES:** Cambiar categoría de `category_haber_imponible` → `category_total_imponible`
2. **TOTAL_IMPONIBLE:** Cambiar categoría de `category_base` → `category_total_imponible`

### Impacto Esperado

**Antes:**
```
total_imponible = BASIC + BONO + HABERES_IMPONIBLES + TOTAL_IMPONIBLE
                = 1M + 50K + 1.05M + 1.05M
                = 3.15M (sin contar otras reglas)
```

**Después:**
```
total_imponible = BASIC + BONO
                = 1M + 50K
                = 1.05M ✓
```

---

## 🔗 Referencias

- **Archivo Categorías:** `data/hr_salary_rule_category_base.xml`
- **Archivo Reglas:** `data/hr_salary_rules_p1.xml`
- **Método Cálculo:** `models/hr_payslip.py:312-372` (_compute_totals)
- **Tests Afectados:** `tests/test_calculations_sprint32.py`

---

## 📝 Normativa (No Aplica - Problema Técnico)

Este es un problema técnico de implementación, NO regulatorio. El método de cálculo y las categorías son correctos según normativa chilena. Solo hay un error de doble conteo en reglas totalizadoras.

---

**Documentado por:** Claude Code
**Referencia:** PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_13.md - Fase 1 - Problema #1
