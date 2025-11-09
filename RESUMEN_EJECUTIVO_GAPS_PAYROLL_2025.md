# RESUMEN EJECUTIVO - GAPS NÓMINA CHILE 2025

**Módulo:** `l10n_cl_hr_payroll`
**Fecha Análisis:** 2025-11-08
**Estado Actual:** 78% completo (estimado)
**Riesgo General:** 🔴 ALTO

---

## 🎯 HALLAZGOS CLAVE

### Estado por Feature

| Feature | Implementado | Gap | Esfuerzo | Criticidad |
|---------|--------------|-----|----------|------------|
| **Reforma 2025 (1% adicional)** | 20% | 80% | 10h | 🔴 CRÍTICO |
| **Previred Export** | 0% | 100% | 13h | 🔴 CRÍTICO |
| **Tope AFP 87.8 UF** | 60% | 40% | 3h | 🟠 ALTO |
| **LRE 105 Campos** | 28% | 72% | 12h | 🟠 ALTO |
| **Indicadores Económicos** | 90% | 10% | 3h | 🟡 BAJO |
| **TOTAL** | **~75%** | **~25%** | **41h** | **🔴 ALTO** |

---

## 📋 TOP 5 GAPS PRIORITARIOS

### 1️⃣ REFORMA PREVISIONAL 2025 - 🔴 P0 CRÍTICO

**Problema:**
Falta implementar cotización adicional empleador 1.0% (vigente enero 2025):
- 0.1% → Cuenta Individual
- 0.9% → SSP/FAPP

**Impacto Legal:**
- Multas SII hasta 20 UTM/trabajador
- Previred rechaza declaración
- Incumplimiento Ley 21.XXX

**Archivos a Modificar:**
- `models/hr_salary_rule_aportes_empleador.py` (campos + métodos)
- `data/hr_salary_rules_reforma_2025.xml` (reglas salariales)
- `wizards/hr_lre_wizard.py` (exportación)
- `views/hr_payslip_views.xml` (UI)

**Esfuerzo:** 10 horas
**Deadline:** 2025-01-15

---

### 2️⃣ WIZARD PREVIRED - 🔴 P0 CRÍTICO

**Problema:**
El modelo `previred.export.wizard` NO EXISTE.
Botón "Exportar Previred" arroja error al presionar.

**Error Actual:**
```python
# models/hr_payslip_run.py línea 358
return {
    'res_model': 'previred.export.wizard',  # ← MODELO NO EXISTE
}
# ValueError: Model 'previred.export.wizard' does not exist
```

**Impacto Legal:**
- Imposible declarar mensualmente a Previred
- Multa 2 UTM/día atraso (~$120.000/día)
- Trabajadores sin cobertura AFP/Salud

**Archivos a Crear:**
- `wizards/previred_export_wizard.py` (modelo completo)
- `wizards/previred_export_wizard_views.xml` (vista form)
- `models/hr_afp.py` (agregar campo `previred_code`)
- `models/hr_isapre.py` (agregar campo `previred_code`)

**Esfuerzo:** 13 horas
**Deadline:** 2025-01-15

---

### 3️⃣ TOPE AFP INCONSISTENTE - 🟠 P0 ALTO

**Problema:**
Valor correcto 2025: **87.8 UF**
Implementación actual: **83.1 UF** (XML) vs **87.8 UF** (comentarios)

**Inconsistencias Detectadas:**

| Archivo | Línea | Valor | Estado |
|---------|-------|-------|--------|
| `data/l10n_cl_legal_caps_2025.xml` | 52 | 83.1 | ❌ INCORRECTO |
| `models/hr_salary_rule_aportes_empleador.py` | 202 | 87.8 (hardcoded) | ⚠️ HARDCODED |
| `models/hr_economic_indicators.py` | 62 | 83.1 (default) | ❌ INCORRECTO |
| `models/hr_payslip.py` | 647 | 87.8 (comentario) | ⚠️ COMENTARIO |

**Impacto:**
- Descuentos AFP incorrectos
- Base imponible errónea (SIS, AFC)
- Previred rechaza por topes incorrectos

**Solución:**
1. XML: cambiar 83.1 → 87.8
2. Eliminar hardcoding línea 202
3. Usar método dinámico `get_cap('AFP_IMPONIBLE_CAP', date)`

**Esfuerzo:** 3 horas
**Deadline:** 2025-01-15

---

### 4️⃣ LRE 105 CAMPOS - 🟠 P1 ALTO

**Problema:**
LRE actual genera **29 campos** de **105 requeridos** (28%).
Faltan **76 campos** (secciones C-H).

**Implementación Actual:**
```python
# wizards/hr_lre_wizard.py
def _get_csv_header(self):
    columns = [
        # ✅ Sección A: Empresa (10 campos)
        # ✅ Sección B: Trabajador (19 campos)
        # ❌ Sección C: Remuneraciones (15 campos) - FALTA
        # ❌ Sección D: Descuentos (12 campos) - FALTA
        # ❌ Sección E: Voluntarios (8 campos) - FALTA
        # ❌ Sección F: No Imponibles (10 campos) - FALTA
        # ❌ Sección G: Otros (18 campos) - FALTA
        # ❌ Sección H: Aportes Empleador (13 campos) - FALTA
    ]
```

**Impacto:**
- Portal Mi DT rechaza CSV incompleto
- Multas DT hasta 60 UTM
- Incumplimiento Art. 62 CT

**Solución:**
1. Crear ~30 reglas salariales XML faltantes
2. Actualizar wizard para generar 105 campos
3. Validaciones formato DT

**Esfuerzo:** 12 horas
**Deadline:** 2025-02-28

---

### 5️⃣ INDICADORES ECONÓMICOS - 🟡 P2 BAJO

**Problema:**
Default `afp_limit = 83.1` debe ser `87.8`
Validaciones import podrían mejorar

**Solución:**
1. Cambiar default a 87.8
2. Agregar validaciones rangos
3. Dashboard gráfico (enhancement)

**Esfuerzo:** 3 horas
**Deadline:** 2025-06-30

---

## 📊 RESUMEN ESFUERZO

### Por Prioridad

| Prioridad | Gaps | Esfuerzo | Deadline |
|-----------|------|----------|----------|
| **P0** | 3 | **26h** | **2025-01-15** |
| **P1** | 1 | **12h** | 2025-02-28 |
| **P2** | 1 | **3h** | 2025-06-30 |
| **TOTAL** | **5** | **41h** | **~2 semanas** |

### Por Tipo Trabajo

| Tipo | Horas | % |
|------|-------|---|
| Python (modelos/wizards) | 22h | 54% |
| XML (reglas/vistas) | 12h | 29% |
| Tests | 7h | 17% |
| **TOTAL** | **41h** | **100%** |

---

## 🚀 ROADMAP RECOMENDADO

### Sprint 1: P0 - Compliance (26h) - Deadline 2025-01-15

**Semana 1 (16h):**
- Día 1-2: Reforma 2025 (10h)
- Día 3-4: Previred wizard parte 1 (6h)

**Semana 2 (10h):**
- Día 5-6: Previred wizard parte 2 (7h)
- Día 7: Tope AFP 87.8 UF (3h)

**Entregables:**
- ✅ Reforma 2025 calculando
- ✅ Previred exportando
- ✅ Tope AFP corregido
- ✅ Tests 100% pasando

### Sprint 2: P1 - LRE Completo (12h) - Deadline 2025-02-28

**Semana 3:**
- Día 1-2: Reglas salariales (4h)
- Día 3-4: Wizard 105 campos (4h)
- Día 5-7: Validaciones + docs (4h)

**Entregables:**
- ✅ LRE 105 campos completo
- ✅ Validaciones DT
- ✅ Tests >90%

### Sprint 3: P2 - Mejoras (3h) - Deadline 2025-06-30

**Semana 4:**
- Dashboard indicadores (2h)
- Validaciones import (1h)

---

## ⚠️ RIESGOS LEGALES

### Sin P0 Cerrado (antes 2025-01-15)

| Riesgo | Impacto Económico | Probabilidad |
|--------|-------------------|--------------|
| Multa SII Reforma 2025 | 20 UTM/trabajador (~$1.200.000) | 🔴 ALTA |
| Multa Previred atraso | 2 UTM/día (~$120.000/día) | 🔴 ALTA |
| Multa DT (LRE) | Hasta 60 UTM (~$3.600.000) | 🟠 MEDIA |
| Trabajadores sin cobertura | Demandas laborales | 🟠 MEDIA |
| **TOTAL ESTIMADO** | **>$5.000.000** | **🔴 ALTA** |

### Con P0 Cerrado

- ✅ 100% compliance legal
- ✅ Declaraciones automáticas
- ✅ Auditoría completa
- ✅ Riesgo eliminado

---

## 📋 CHECKLIST ACCIÓN INMEDIATA

### Esta Semana (P0 Crítico)

- [ ] **AHORA:** Aprobar roadmap Sprint 1
- [ ] **Hoy:** Asignar desarrollador senior (26h disponibles)
- [ ] **Mañana:** Branch `feature/compliance-2025`
- [ ] **Esta semana:** Iniciar Reforma 2025

### Próximas 2 Semanas

- [ ] **Semana 1:** Reforma 2025 + Previred (parte 1)
- [ ] **Semana 2:** Previred (parte 2) + Tope AFP
- [ ] **2025-01-15:** Deploy a producción
- [ ] **2025-01-20:** Smoke test primera declaración

### Siguiente Mes

- [ ] **Febrero:** Sprint 2 LRE 105 campos
- [ ] **2025-02-28:** Deploy LRE completo

---

## 🎯 CRITERIOS ÉXITO P0

### Técnicos

- ✅ Campo `aporte_reforma_2025_total` existe
- ✅ Calcula 1.0% sobre imponible (0.1% CI + 0.9% SSP)
- ✅ Wizard `previred.export.wizard` existe
- ✅ Genera archivo TXT 105 campos
- ✅ Validación RUT módulo 11 funciona
- ✅ Tope AFP = 87.8 UF (sin hardcoding)
- ✅ Suite tests pasa 100%

### Funcionales

- ✅ Liquidación muestra reforma 2025 en pantalla
- ✅ Botón "Exportar Previred" genera archivo
- ✅ Archivo Previred carga en portal web (test manual)
- ✅ Cálculos AFP usan tope correcto

### Legales

- ✅ Cumplimiento Ley Reforma Previsional
- ✅ Formato Previred oficial
- ✅ Tope AFP según Superintendencia Pensiones

---

## 📞 PRÓXIMOS PASOS

1. **Inmediato:** Presentar análisis a stakeholders
2. **Hoy:** Aprobar roadmap y presupuesto
3. **Mañana:** Asignar recursos
4. **Esta semana:** Kickoff Sprint 1

---

## 📚 DOCUMENTOS RELACIONADOS

- **Análisis Completo:** `GAP_ANALYSIS_L10N_CL_HR_PAYROLL_2025_COMPLIANCE.md`
- **Documentación Técnica:** `addons/localization/l10n_cl_hr_payroll/README.md`
- **Estado P0/P1:** `addons/localization/l10n_cl_hr_payroll/README_P0_P1_GAPS_CLOSED.md`
- **Especificación LRE:** `addons/localization/l10n_cl_hr_payroll/wizards/LRE_105_CAMPOS_ESPECIFICACION.md`

---

**FIN RESUMEN EJECUTIVO**

**Recomendación:** Iniciar Sprint 1 INMEDIATAMENTE (deadline 2025-01-15)
