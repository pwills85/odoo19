# RESUMEN EJECUTIVO - AUDITORÍA NÓMINA CHILENA

**Fecha:** 2025-11-06
**Módulo:** `l10n_cl_hr_payroll` v19.0.1.0.0
**Estado:** ⚠️ RIESGO MEDIO-ALTO - NO USAR EN PRODUCCIÓN
**Compliance Score:** 40% (6/15 requisitos normativos OK)

---

## HALLAZGOS CRÍTICOS (5 BLOQUEANTES P0)

### 1. IMPUESTO ÚNICO - TRAMOS HARDCODED ❌

**Problema:** Valores en pesos, no actualizables según UTA
```python
# ❌ INCORRECTO (archivo: models/hr_payslip.py:1185)
TRAMOS = [(0, 816_822, 0.0, 0), ...]  # Valores fijos 2025
```

**Impacto:**
- ERROR cálculo cuando UTA cambie (enero 2026)
- ILEGAL: Retención incorrecta = multas SII
- Afecta 100% trabajadores con impuesto

**Normativa:** Art. 43 Ley Renta, Circular N°62 SII

**Fix:** Calcular dinámicamente basado en UTA de `hr.economic.indicators`

---

### 2. EXPORTACIÓN PREVIRED - NO IMPLEMENTADA ❌

**Problema:** Wizard no existe, solo declarado
```python
# ❌ models/hr_payslip_run.py:311
'res_model': 'previred.export.wizard',  # NO EXISTE
```

**Impacto:**
- BLOQUEANTE: Empresa NO puede declarar cotizaciones mensuales
- MULTAS: $8,000 - $2,400,000 por mes sin declarar
- Afecta 100% trabajadores (AFP, Salud, AFC)

**Normativa:** DFL 251 Art. 19, Circular 1556 Previred

**Fix:** Crear wizard que genere archivo TXT 105 campos

---

### 3. FINIQUITOS - NO IMPLEMENTADOS ❌

**Problema:** Funcionalidad solo mencionada en manifest, no existe código

**Impacto:**
- BLOQUEANTE OPERACIONAL: No se pueden procesar desvinculaciones
- Cálculo manual = errores = demandas laborales
- Afecta operación RRHH completa

**Normativa:** Art. 162-163 CT, Art. 73 CT

**Fix:** Crear modelo `hr.payslip.settlement` con cálculos:
- Indemnización años servicio (tope 11 años)
- Indemnización aviso previo
- Vacaciones proporcionales
- Sueldo proporcional

---

### 4. ASIGNACIÓN FAMILIAR - VALORES HARDCODED ⚠️

**Problema:** Montos fijos en código, no desde indicadores económicos
```python
# ❌ models/hr_salary_rule_asignacion_familiar.py:135
monto_simple = 15268  # Hardcoded
```

**Impacto:**
- ERROR cuando DFL 150 actualice montos (anual)
- Trabajadores pierden dinero o empresa sobre-paga
- Afecta ~30% trabajadores con cargas

**Normativa:** DFL 150 (1981), Decreto Ministerio Trabajo

**Fix:** Usar campos ya existentes en `hr.economic.indicators`

---

### 5. TOPES AFP/CESANTÍA - VALORES DESACTUALIZADOS ⚠️

**Problema:**
- AFP: 83.1 UF (correcto: 87.8 UF desde 2024)
- Cesantía: 120.2 UF (correcto: 131.3 UF)

**Impacto:**
- SOBRE-DESCUENTO trabajadores con sueldo alto
- Afecta ~5-10% trabajadores (sueldos > $3,000,000)

**Normativa:** DL 3500 Art. 16, Ley 19.728 Art. 10

**Fix:** Actualizar constantes + script migración datos

---

## INCUMPLIMIENTOS NORMATIVOS (P1)

1. **Horas extras:** No valida tope 2h diarias / 10h semanales (Art. 31 CT)
2. **Gratificación:** No calcula proporcionalidad meses trabajados (Art. 50 CT)
3. **Cargas familiares:** No valida edad hijos / certificados (DFL 150)
4. **Integración Payroll-Service:** Prometida pero NO implementada

---

## MATRIZ RIESGOS

| Riesgo | Probabilidad | Impacto | Urgencia |
|--------|--------------|---------|----------|
| Multa SII retención incorrecta | MEDIA | ALTO | 🔴 CRÍTICA |
| Multa Previred no declarar | ALTA | ALTO | 🔴 CRÍTICA |
| Demanda laboral finiquito | MEDIA | MEDIO | 🟠 ALTA |
| Error cálculo nómina masivo | BAJA | CRÍTICO | 🟡 MEDIA |

---

## RECOMENDACIÓN FINAL

### NO USAR EN PRODUCCIÓN SIN COMPLETAR FASE 1

**Fase 1 - CRÍTICO (80-120 hrs, 2-3 semanas):**

1. ✅ Implementar cálculo impuesto dinámico (UTA)
2. ✅ Implementar wizard export Previred (105 campos)
3. ✅ Actualizar topes AFP/Cesantía
4. ✅ Desconfiguar asignación familiar

**Resultado Fase 1:** Compliance 60% → 75%

**Fase 2 - ALTO RIESGO (100-140 hrs, 3-4 semanas):**

5. ✅ Implementar finiquitos completos
6. ✅ Validar proporcionalidad gratificación
7. ✅ Validar cargas familiares (edad, certificados)
8. ✅ Validar topes horas extras

**Resultado Fase 2:** Compliance 75% → 90%

---

## MÉTRICAS CÓDIGO

| Métrica | Valor | Estado |
|---------|-------|--------|
| Líneas código | 4,256 | ✅ OK |
| Tests | 159 LOC (3 archivos) | ⚠️ INSUFICIENTE |
| Modelos | 17 | ✅ OK |
| Cobertura tests | ~20% | ⚠️ BAJA (objetivo 80%) |
| TODO/FIXME | 12 | ⚠️ PENDIENTES |

---

## PRÓXIMOS PASOS INMEDIATOS

### SEMANA 1-2: FIXES CRÍTICOS

```bash
# 1. Crear modelo tabla impuesto
touch models/hr_tax_bracket.py
# Migrar valores hardcoded a registros BD

# 2. Crear wizard Previred
touch wizards/previred_export_wizard.py
touch wizards/previred_export_wizard_views.xml
# Implementar generación archivo TXT

# 3. Actualizar topes
# models/hr_economic_indicators.py:
# afp_limit: 83.1 → 87.8
# Cesantía: 120.2 → 131.3

# 4. Desconfiguar asignación familiar
# Refactorizar _compute_family_allowance_lines()
# Usar indicators.asignacion_familiar_amount_a/b/c
```

### SEMANA 3-4: FINIQUITOS

```bash
# 5. Crear modelo finiquito
touch models/hr_payslip_settlement.py
touch views/hr_payslip_settlement_views.xml
touch wizards/finiquito_wizard.py
# Implementar cálculos Art. 162-163 CT
```

---

## RECURSOS NECESARIOS

- **1 dev senior Python/Odoo** (Fase 1 + Fase 2)
- **1 QA con conocimiento normativa chilena** (testing compliance)
- **Acceso abogado laboral** (consultas edge cases)
- **Previred test account** (validar export)

**Inversión total:** 280-400 hrs (~2-3 meses @ 1 FTE)

---

## CONTACTO

**Auditoría realizada por:** Claude Code (Anthropic)
**Revisión recomendada:** Post Fase 1 (3 semanas)
**Documento completo:** `AUDITORIA_NOMINA_CHILENA_EXHAUSTIVA_2025-11-06.md`

---

**ÚLTIMA ACTUALIZACIÓN:** 2025-11-06
