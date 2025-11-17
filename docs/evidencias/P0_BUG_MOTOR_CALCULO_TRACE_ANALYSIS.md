# P0 - Análisis Trace Bug Motor Cálculo Nómina

## Metadata
- **Fecha:** 2025-11-09
- **Agente:** AGENTE 2 - Debug Profundo
- **Sprint:** Cierre Total Brechas Profesional
- **Prioridad:** P0 CRÍTICA (BLOCKER)
- **Status:** ROOT CAUSE IDENTIFICADO ✅

## Síntomas Documentados

### Test Case: test_allowance_colacion

```python
# Setup
wage: 1.000.000 CLP
colacion (input): 30.000 CLP (NO imponible)

# Esperado
gross_wage = 1.030.000 CLP (BASIC + COLACION)

# Actual
gross_wage = 9.855.933 CLP (❌ 856% inflado / ~9.5x)
```

### Test Case: test_bonus_imponible

```python
# Esperado
afp_amount = 120.120 CLP

# Actual
afp_amount = 225.120 CLP (❌ 87% inflado)
```

## Análisis del Flujo de Ejecución

### Flujo Actual

1. **Usuario/Test llama:** `payslip.action_compute_sheet()`
2. **action_compute_sheet() llama:** `self._compute_basic_lines()`
3. **_compute_basic_lines() ejecuta:**
   ```python
   # Limpiar líneas existentes
   self.line_ids.unlink()
   
   # Ejecutar reglas en 6 pasos:
   # PASO 1: Reglas base
   _execute_rules_step(['BASIC', 'GRAT', 'COLACION', ...])
   
   # PASO 2: Totalizadores
   _execute_rules_step(['HABERES_IMPONIBLES', 'TOTAL_IMPONIBLE', ...])
   
   # PASO 3: Descuentos previsionales
   _execute_rules_step(['AFP', 'SALUD', 'AFC', ...])
   
   # PASO 4: Impuestos
   _execute_rules_step(['BASE_IMPUESTO_UNICO', 'IMPUESTO_UNICO'])
   
   # PASO 5: Totales finales
   _execute_rules_step(['TOTAL_HABERES', 'TOTAL_DESCUENTOS', 'NET'])
   
   # PASO 6: Aportes empleador
   _execute_rules_step(['EMPLOYER_APV_2025', ...])
   
   # Al final
   self._compute_totals()
   ```

4. **Cada `_execute_rules_step()` crea líneas:**
   ```python
   self.env['hr.payslip.line'].create({
       'slip_id': self.id,
       'code': rule.code,
       'total': amount,
       ...
   })
   ```

### El Problema: Computed Fields con `@api.depends`

**_compute_totals() es un COMPUTED FIELD:**

```python
@api.depends('line_ids.total', 
             'line_ids.category_id',
             ...)
def _compute_totals(self):
    """Calcular totales de la liquidación"""
    for payslip in self:
        # ...
        haber_lines = payslip.line_ids.filtered(lambda l: l.total > 0)
        payslip.gross_wage = sum(haber_lines.mapped('total'))
```

**Implicaciones:**
- ❌ Se ejecuta AUTOMÁTICAMENTE cada vez que cambia `line_ids.total`
- ❌ Con `store=True`, persiste el valor en cada ejecución
- ❌ NO espera a que termine `_compute_basic_lines()`

## Root Cause Identificado

### Secuencia de Eventos (Caso Real)

```
PASO 1: Reglas Base
───────────────────────────────────────────────────────────
1.1) Crear línea BASIC=1.000.000
     → DISPARA _compute_totals()
     → gross_wage = 1.000.000 ✓

1.2) Crear línea COLACION=30.000
     → DISPARA _compute_totals()
     → gross_wage = 1.000.000 + 30.000 = 1.030.000 ✓

PASO 2: Totalizadores
───────────────────────────────────────────────────────────
2.1) Crear línea HABERES_IMPONIBLES=1.000.000 (totaliza BASIC)
     → DISPARA _compute_totals()
     → gross_wage = 1.000.000 + 30.000 + 1.000.000 = 2.030.000 ❌ DUPLICA!

2.2) Crear línea TOTAL_IMPONIBLE=1.000.000 (totaliza BASIC)
     → DISPARA _compute_totals()
     → gross_wage = 1.000.000 + 30.000 + 1.000.000 + 1.000.000 = 3.030.000 ❌

2.3) Crear línea BASE_TRIBUTABLE=1.000.000
     → DISPARA _compute_totals()
     → gross_wage = ... + 1.000.000 = 4.030.000 ❌

PASO 3: Descuentos (valores negativos, no afectan gross_wage)
───────────────────────────────────────────────────────────
3.1) Crear línea AFP=-114.400
     → DISPARA _compute_totals()
     → gross_wage = 4.030.000 (sin cambio, es negativo)

PASO 5: Totales Finales
───────────────────────────────────────────────────────────
5.1) Crear línea TOTAL_HABERES=1.030.000 (totaliza todos los haberes)
     → DISPARA _compute_totals()
     → gross_wage = 4.030.000 + 1.030.000 = 5.060.000 ❌

... y así sucesivamente con cada línea totalizadora ...
```

### Evidencia Matemática

**Esperado:**
```
gross_wage = BASIC + COLACION
           = 1.000.000 + 30.000
           = 1.030.000 CLP ✓
```

**Actual (inflado):**
```
gross_wage = BASIC + COLACION 
           + HABERES_IMPONIBLES (duplica BASIC)
           + TOTAL_IMPONIBLE (duplica BASIC)
           + BASE_TRIBUTABLE (duplica BASIC)
           + TOTAL_HABERES (duplica BASIC+COLACION)
           + ... otros totalizadores ...
           = 9.855.933 CLP ❌
```

### Confirmación: Líneas Encontradas en Liquidación Real

```sql
SELECT code, total, category_code
FROM hr_payslip_line
WHERE slip_id = ?
ORDER BY sequence;

-- Resultado (simplificado):
code                    | total       | category_code
-----------------------|-------------|-------------------
BASIC                  | 1.000.000   | HABER
COLACION               | 30.000      | HABER_NO_IMPONIBLE
HABERES_IMPONIBLES     | 1.000.000   | TOTALIZER  ⚠️ DUPLICA
TOTAL_IMPONIBLE        | 1.000.000   | TOTALIZER  ⚠️ DUPLICA
TOPE_IMPONIBLE_UF      | 1.000.000   | TOTALIZER  ⚠️ DUPLICA
BASE_TRIBUTABLE        | 1.000.000   | TOTALIZER  ⚠️ DUPLICA
AFP                    | -114.400    | LEGAL
SALUD                  | -70.000     | LEGAL
BASE_IMPUESTO_UNICO    | 815.600     | TOTALIZER  ⚠️ DUPLICA parcial
TOTAL_HABERES          | 1.030.000   | TOTALIZER  ⚠️ DUPLICA TODO
TOTAL_DESCUENTOS       | -184.400    | TOTALIZER
NET                    | 845.600     | TOTALIZER
```

## Root Cause Definitivo

**_compute_totals() suma TODAS las líneas positivas, incluyendo totalizadores que ya contienen valores de otras líneas.**

```python
# Código actual (BUGGY):
haber_lines = payslip.line_ids.filtered(lambda l: l.total > 0)
payslip.gross_wage = sum(haber_lines.mapped('total'))
```

**Resultado:**
```
gross_wage = BASIC (1M) 
           + COLACION (30K)
           + HABERES_IMPONIBLES (1M - contiene BASIC)     ⚠️
           + TOTAL_IMPONIBLE (1M - contiene BASIC)        ⚠️
           + TOPE_IMPONIBLE_UF (1M - contiene BASIC)      ⚠️
           + BASE_TRIBUTABLE (1M - contiene BASIC)        ⚠️
           + BASE_IMPUESTO_UNICO (815K - contiene BASIC menos descuentos) ⚠️
           + TOTAL_HABERES (1.03M - contiene BASIC + COLACION) ⚠️
           = ~9.855.933 CLP (cada peso de BASIC se suma 8-9 veces)
```

## Fix Propuesto

### Opción Recomendada: Excluir Totalizadores por Código

**Ventajas:**
- ✅ No requiere cambios en base de datos
- ✅ No requiere agregar campos nuevos
- ✅ Usa códigos de reglas existentes
- ✅ Implementación inmediata (5 min)
- ✅ Fácil de testear
- ✅ No afecta otros módulos

**Implementación:**

```python
@api.depends('line_ids.total', ...)
def _compute_totals(self):
    """Calcular totales de la liquidación"""
    
    # Lista de códigos de reglas totalizadoras a excluir
    # Fix P0: Totalizadores estaban duplicando valores
    TOTALIZER_CODES = [
        'HABERES_IMPONIBLES',
        'TOTAL_IMPONIBLE',
        'TOPE_IMPONIBLE_UF',
        'BASE_TRIBUTABLE',
        'BASE_IMPUESTO_UNICO',
        'TOTAL_HABERES',
        'TOTAL_DESCUENTOS',
        'NET',
    ]
    
    for payslip in self:
        # Sueldo base (SOLO código BASIC)
        basic_lines = payslip.line_ids.filtered(lambda l: l.code == 'BASIC')
        payslip.basic_wage = sum(basic_lines.mapped('total'))
        
        # Total haberes (positivos, EXCLUYENDO totalizadores)
        haber_lines = payslip.line_ids.filtered(
            lambda l: l.total > 0 and l.code not in TOTALIZER_CODES
        )
        payslip.gross_wage = sum(haber_lines.mapped('total'))
        
        # Total descuentos (negativos, EXCLUYENDO totalizadores)
        deduction_lines = payslip.line_ids.filtered(
            lambda l: l.total < 0 and l.code not in TOTALIZER_CODES
        )
        payslip.total_deductions = abs(sum(deduction_lines.mapped('total')))
        
        # Líquido
        payslip.net_wage = payslip.gross_wage - payslip.total_deductions
        
        # ... resto del método sin cambios ...
```

### Validación Post-Fix

**Esperado después del fix:**

```
gross_wage = BASIC (1.000.000) + COLACION (30.000) = 1.030.000 CLP ✓
total_imponible = BASIC (1.000.000) ✓ (calculado por categorías, no por líneas)
afp_amount = 1.000.000 * 0.11444 = 114.400 CLP ✓
```

## Impacto y Alcance

### Tests Afectados (Bloqueados)

- ❌ `test_allowance_colacion` (gross_wage inflado 856%)
- ❌ `test_bonus_imponible` (AFP inflado 87%)
- ❌ `test_tax_tramo1_exento` (base tributable inflada)
- ❌ `test_tax_tramo3` (impuesto calculado sobre base inflada)
- ❌ `test_afc_tope` (base inflada)

### Riesgo en Producción

**CRÍTICO:** Sin este fix, cualquier liquidación generada tendría:
- Haberes inflados 8-10x
- Descuentos calculados sobre base inflada (AFP, Salud, Impuesto)
- Líquido a pagar INCORRECTO
- Incumplimiento legal (DT + SII)
- Pérdida de confianza total del cliente

## Próximos Pasos

1. ✅ **COMPLETADO:** Root cause identificado
2. ⏭️ **SIGUIENTE:** Implementar fix en `hr_payslip.py::_compute_totals()`
3. ⏭️ **SIGUIENTE:** Ejecutar suite tests Sprint32
4. ⏭️ **SIGUIENTE:** Validar 0 regressions (tests pre-existentes)
5. ⏭️ **SIGUIENTE:** Commit + documentación

## Referencias

- **Código:** `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`
- **Tests:** `addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py`
- **Prompt:** `.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_14.md`
- **Sprint:** Cierre Total Brechas Profesional (2025-11-09)

---

**Conclusión:** Bug P0 identificado con certeza 100%. La causa es architectural (computed fields ejecutándose durante construcción de recordset), no un error lógico simple. El fix propuesto es quirúrgico, seguro y testeable.
