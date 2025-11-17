# 🚨 PROBLEMA CRÍTICO: API Antigua en Tests

**Fecha:** 2025-11-09
**Sprint:** SPRINT 2 - Cierre Total de Brechas
**Prioridad:** P0 - BLOQUEANTE
**Afecta:** ~30 tests (más de lo esperado en PROMPT MASTER V5)

---

## 📊 RESUMEN EJECUTIVO

Durante la validación del estado actual de tests, se detectó un problema crítico NO contemplado en el PROMPT MASTER V5:

**Múltiples archivos de tests están usando API antigua (campos eliminados) que no existe en los modelos actualizados.**

**Impacto:**
- ~30 tests fallando (vs ~14 esperados)
- Tests bloqueados en setUpClass (no pueden ni iniciar)
- Afecta 3-4 archivos de tests principales

---

## 🔍 ANÁLISIS DETALLADO

### Modelos Afectados

#### 1. `hr.economic.indicators`

**API ANTIGUA (NO EXISTE):**
```python
{
    'month': 1,
    'year': 2025,
    'uf': 37800.00,
    ...
}
```

**API ACTUAL (CORRECTA):**
```python
{
    'period': date(2025, 1, 1),  # ✅ Campo Date único
    'uf': 37800.00,
    ...
}
```

**Campo Real:**
- `period` (Date) - Primer día del mes

---

#### 2. `l10n_cl.legal.caps`

**API ANTIGUA (NO EXISTE):**
```python
{
    'year': 2025,
    'tope_imponible_afp_uf': 81.6,
    'tope_imponible_ips_uf': 81.6,
    'tope_apv_mensual_uf': 50.0,
    'tope_apv_anual_uf': 600.0,
}
```

**API ACTUAL (CORRECTA):**
```python
# Para AFP tope imponible
{
    'code': 'AFP_IMPONIBLE_CAP',
    'amount': 81.6,
    'unit': 'uf',
    'valid_from': date(2025, 1, 1),
}

# Para APV tope mensual
{
    'code': 'APV_CAP_MONTHLY',
    'amount': 50.0,
    'unit': 'uf',
    'valid_from': date(2025, 1, 1),
}
```

**Campos Reales:**
- `code` (Selection) - Código del tope
- `amount` (Float) - Valor
- `unit` (Selection) - Unidad (uf/utm/clp/percent)
- `valid_from` (Date) - Fecha inicio vigencia
- `valid_until` (Date) - Fecha fin vigencia (opcional)

**Códigos Disponibles:**
- `'APV_CAP_MONTHLY'` - APV Tope Mensual
- `'APV_CAP_ANNUAL'` - APV Tope Anual
- `'AFC_CAP'` - AFC Tope Imponible
- `'AFP_IMPONIBLE_CAP'` - AFP Tope Imponible
- `'GRATIFICATION_CAP'` - Gratificación Tope Legal

---

#### 3. `hr.tax.bracket`

**API ANTIGUA (NO EXISTE):**
```python
{
    'year': 2025,
    'from_amount': 0.00,
    'to_amount': 916380.00,
    'rate': 0.0,
    'fixed_amount': 0.0,
}
```

**API ACTUAL (CORRECTA):**
```python
{
    'tramo': 1,
    'desde': 0.0,        # en UTM, NO en CLP
    'hasta': 13.89,      # en UTM, NO en CLP
    'tasa': 0.0,
    'rebaja': 0.0,
    'vigencia_desde': date(2025, 1, 1),
}
```

**Campos Reales:**
- `tramo` (Integer) - Número de tramo (1-8)
- `desde` (Float) - Límite inferior en **UTM**
- `hasta` (Float) - Límite superior en **UTM**
- `tasa` (Float) - Tasa de impuesto (%)
- `rebaja` (Float) - Factor de rebaja en **UTM**
- `vigencia_desde` (Date) - Fecha inicio vigencia
- `vigencia_hasta` (Date) - Fecha fin vigencia (opcional)

**IMPORTANTE:** Los valores son en UTM, NO en CLP

---

## 📂 ARCHIVOS AFECTADOS

### Tests con API Antigua

| Archivo | Problema | Tests Afectados | Prioridad |
|---------|----------|-----------------|-----------|
| `test_payroll_calculation_p1.py` | setUpClass falla (legal.caps + tax.bracket) | ~15+ | P0 |
| `test_payroll_caps_dynamic.py` | Usa 'month'/'year' en economic.indicators | ~3 | P0 |
| `fixtures_p0_p1.py` | Helper usa API antigua | N/A (afecta otros) | P0 |
| `test_ley21735_reforma_pensiones.py` (prob.) | Por confirmar | ~6 | P1 |

**Total Estimado:** 25-30 tests bloqueados

---

## 🎯 PROPUESTA DE SOLUCIÓN

### Opción A: Corrección Manual de Tests (RECOMENDADA)

**Ventajas:**
- ✅ Solución arquitectónicamente correcta
- ✅ Siguiendo principios "SIN PARCHES"
- ✅ Tests actualizados a API correcta
- ✅ Mantenible a largo plazo

**Desventajas:**
- ⏱️ Requiere 1-2h adicionales
- 📝 Múltiples archivos a modificar

**Estimación:** 1-2 horas

---

### Opción B: Implementar Compatibilidad Retroactiva en Modelos

**NO RECOMENDADA** - Viola principio "SIN PARCHES"

---

## 📋 PLAN DE CORRECCIÓN (OPCIÓN A)

### TASK ADICIONAL: Corregir API Antigua en Tests (1-2h)

**Prioridad:** P0 - BLOQUEANTE
**Debe ejecutarse ANTES de:** TASK 2.6B Parte 2

#### Sub-tareas:

1. **Corregir test_payroll_calculation_p1.py (30min)**
   - Actualizar creación de `l10n_cl.legal.caps` (4 registros → códigos)
   - Actualizar creación de `hr.tax.bracket` (convertir CLP → UTM)
   - Validar setUpClass funciona

2. **Corregir test_payroll_caps_dynamic.py (15min)**
   - Actualizar creación de `hr.economic.indicators` (month/year → period)
   - Validar tests pasan

3. **Corregir fixtures_p0_p1.py (20min)**
   - Actualizar helpers compartidos
   - Validar no rompe otros tests

4. **Validar test_ley21735_reforma_pensiones.py (15min)**
   - Verificar si tiene mismo problema
   - Corregir si es necesario

5. **Validación completa (10min)**
   - Ejecutar todos los tests
   - Validar ~14 errores reales (no 30)

**Total:** 1.5 horas

---

## 🔄 IMPACTO EN PROMPT MASTER V5

### Actualización de Timeline

| Fase Actual | Duración Original | Duración Actualizada | Motivo |
|-------------|-------------------|----------------------|--------|
| **NUEVA: Corrección API** | - | **1.5h** | Problema crítico detectado |
| TASK 2.6B Parte 2 | 45min | 45min | - |
| TASK 2.6C | 30min | 30min | - |
| TASK 2.5 | 1-2h | 1-2h | - |
| TASK 2.7 | 30min | 30min | - |
| **TOTAL** | **2.5-3.5h** | **4-5h** | +1.5h |

---

## ✅ DECISIÓN REQUERIDA

**Pregunta al usuario:**

> He detectado un problema crítico NO contemplado en el PROMPT MASTER V5:
> ~30 tests están usando API antigua (campos eliminados) que no existe en los modelos.
>
> **Opciones:**
>
> A) **Corregir tests ahora** (+1.5h, solución correcta, siguiendo principios)
> B) **Solicitar más información** (revisar historial de commits/documentación)
> C) **Otra estrategia** (especificar)
>
> **Recomendación:** Opción A - Corregir tests siguiendo principios del PROMPT

---

## 📊 EVIDENCIA

**Archivos de Referencia:**
- Modelos actualizados:
  - `/addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py:26` (campo `period`)
  - `/addons/localization/l10n_cl_hr_payroll/models/l10n_cl_legal_caps.py:30-56` (campos `code`, `amount`, `unit`, `valid_from`)
  - `/addons/localization/l10n_cl_hr_payroll/models/hr_tax_bracket.py:28-71` (campos `tramo`, `desde`, `hasta`, `tasa`, `vigencia_desde`)

**Tests con API Correcta (ejemplos):**
- `/addons/localization/l10n_cl_hr_payroll/tests/test_apv_calculation.py` ✅
- `/addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py` ✅

**Tests con API Antigua (requieren corrección):**
- `/addons/localization/l10n_cl_hr_payroll/tests/test_payroll_calculation_p1.py:52-78` ❌
- `/addons/localization/l10n_cl_hr_payroll/tests/test_payroll_caps_dynamic.py:62-78` ❌

---

**FIN DEL REPORTE**
