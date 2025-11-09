# Resumen Ejecutivo - Auditoría Regulatoria Nómina Chile

**Fecha:** 2025-11-07
**Módulo:** `l10n_cl_hr_payroll` v19.0.1.0.0
**Estado:** 🟡 REQUIERE AJUSTES CRÍTICOS

---

## Veredicto

El módulo de nómina chilena tiene una **arquitectura sólida y parametrizada** que cumple la mayoría de requisitos legales. Sin embargo, se identificaron **3 brechas críticas P0** que deben corregirse antes de producción.

### Hallazgos Resumen

| Severidad | Cantidad | Esfuerzo Corrección | Riesgo Legal |
|-----------|----------|---------------------|--------------|
| **P0 (CRÍTICO)** | 3 | 9 horas (~1 día) | 🔴 ALTO |
| **P1 (ALTO)** | 5 | 9.5 horas (~1 día) | 🟡 MEDIO |
| **P2 (MEDIO)** | 4 | 4 horas | 🟢 BAJO |
| **P3 (BAJO)** | 2 | 2 horas | ⚪ NINGUNO |

**Total esfuerzo corrección:** ~24.5 horas (~3 días)

---

## Brechas Críticas P0 (URGENTE)

### P0-1: Tope AFP Inconsistente

**Problema:** Data XML tiene 81.6 UF, normativa 2025 requiere 83.1 UF

**Impacto:** Descuentos AFP incorrectos para sueldos > $3.1M

**Corrección:**
```xml
<!-- data/l10n_cl_legal_caps_2025.xml:54 -->
<field name="amount">83.1</field>  <!-- Era 81.6 -->
```

**Esfuerzo:** 10 minutos

---

### P0-2: Export LRE Incompleto

**Problema:** Wizard genera 29 campos, DT requiere 105 campos

**Impacto:** Rechazo archivo Dirección del Trabajo

**Campos faltantes críticos:**
- Datos personales (sexo, fecha nacimiento, nacionalidad)
- Contrato (fecha ingreso, tipo, jornada)
- Previsión (% AFP, % Salud, plan ISAPRE)
- Aportes empleador (AFC, mutual, CCAF, SIS)
- Movimientos (licencias, vacaciones, permisos)

**Esfuerzo:** 8 horas

---

### P0-3: Falta Reglas Multi-Compañía

**Problema:** Sin reglas `ir.rule` para aislamiento datos

**Impacto:** Violación privacidad (Ley 19.628), usuarios ven liquidaciones otras compañías

**Corrección:** Agregar 3 reglas en `security/security_groups.xml`

**Esfuerzo:** 1 hora

---

## Fortalezas Identificadas

✅ **Parametrización completa:**
- Topes legales con vigencias (`l10n_cl.legal.caps`)
- Tramos impuesto únicos parametrizados (8 tramos 2025)
- UF/UTM centralizados (`hr.economic.indicators`)

✅ **Cálculos correctos:**
- AFP usa `total_imponible` (no solo `wage`)
- Salud FONASA/ISAPRE correcto
- Seguro Cesantía (AFC) trabajador + empleador
- Impuesto Único con rebaja por cargas
- APV Régimen A/B con topes

✅ **Reforma SOPA 2025 implementada:**
- Fecha corte 1 agosto 2025
- Aporte empleador progresivo (1% 2025 → 6% 2030)
- 9 categorías SOPA con flags

✅ **Testing robusto:**
- 11 suites, 53 tests, ~2,734 líneas
- Cobertura ~75% estimada

✅ **Audit trail completo:**
- Mail tracking (`mail.thread`)
- Campos `computed_date`, `computed_by`
- Workflow estados

✅ **ACL definidos:**
- 36 reglas acceso
- 2 grupos (user, manager)

✅ **i18n implementado:**
- `es_CL.po`, `en_US.po`
- Uso `_()` en código

---

## Brechas Altas P1 (Prioritarias)

### P1-1: Falta Snapshot Indicadores JSON

Guardar indicadores económicos en JSON para auditoría histórica (Art. 54 CT)

**Esfuerzo:** 1 hora

---

### P1-2: Cobertura Tests Incompleta

Falta tests para:
- Reforma SOPA 2025 (fecha corte, aportes)
- Multicompañía (aislamiento)
- Impuesto único zona extrema
- Gratificación proporcional
- Finiquito completo

**Esfuerzo:** 4 horas

---

### P1-3: i18n Incompleto

Strings hardcoded en wizard LRE sin `_()`

**Esfuerzo:** 2 horas

---

### P1-4: Hardcoding Valores Legislativos

Tasas legales hardcoded (7% FONASA, 0.6% AFC, etc.)

**Recomendación:** Parametrizar en `l10n_cl.legal.caps`

**Esfuerzo:** 2 horas

---

### P1-5: Falta Validación Vigencias Solapadas

Sin constraint para detectar topes con vigencias duplicadas

**Esfuerzo:** 30 min

---

## Riesgos Legales

| Brecha | Normativa Afectada | Consecuencia | Probabilidad |
|--------|-------------------|--------------|--------------|
| P0-1 (Tope AFP) | Ley 20.255 Art. 17 | Multa SII + descuentos incorrectos | ALTA |
| P0-2 (LRE 105) | DT - Obligación mensual | Rechazo archivo + multa DT | ALTA |
| P0-3 (Multi-compañía) | Ley 19.628 (Privacidad) | Multa UAF + demandas | MEDIA |
| P1-1 (Snapshot) | Art. 54 CT (7 años) | Multa fiscalización DT | BAJA |

---

## Plan Acción Recomendado

### Sprint 3.1 (URGENTE - 1 día)

1. ✅ Corregir tope AFP 83.1 UF (P0-1) - 10 min
2. ✅ Agregar reglas multi-compañía (P0-3) - 1 hora
3. ✅ Tests validación P0-1 y P0-3 - 2 horas

**Entregable:** Módulo sin brechas críticas

---

### Sprint 3.2 (ALTA - 2 días)

1. 🔄 Implementar LRE 105 campos (P0-2) - 8 horas
2. 🔄 Agregar snapshot indicadores (P1-1) - 1 hora
3. 🔄 Tests cobertura LRE + snapshot - 2 horas

**Entregable:** Export LRE completo + auditoría histórica

---

### Sprint 3.3 (MEDIA - 2 días)

1. 🔄 Parametrizar tasas legales (P1-4) - 2 horas
2. 🔄 Completar i18n wizard (P1-3) - 2 horas
3. 🔄 Tests SOPA 2025 (P1-2) - 4 horas
4. 🔄 Validar vigencias (P1-5) - 30 min

**Entregable:** Código robusto y mantenible

---

## Métricas Calidad

| Métrica | Valor Actual | Objetivo | Estado |
|---------|-------------|----------|--------|
| Cobertura tests | ~75% | 85% | 🟡 |
| Brechas P0 | 3 | 0 | 🔴 |
| Brechas P1 | 5 | 0 | 🟡 |
| i18n completitud | ~90% | 100% | 🟡 |
| Topes parametrizados | 7/10 | 10/10 | 🟡 |
| LRE campos | 29/105 | 105/105 | 🔴 |

---

## Recomendaciones Estratégicas

### Inmediato (Pre-Producción)

1. **Corregir P0** antes de cualquier despliegue
2. **Revisar con Legal** especificación LRE completa
3. **Validar con usuario clave** casos prueba propuestos

### Corto Plazo (1-2 meses)

1. **Completar P1** para robustez producción
2. **Crear knowledge base** en `ai-service/knowledge/nomina/`
3. **Automatizar scraping** indicadores Previred/SII

### Mediano Plazo (3-6 meses)

1. **Implementar Finiquito** completo (indemnizaciones)
2. **Integrar con contabilidad** (asientos automáticos)
3. **Dashboard nómina** para RRHH

---

## Archivos Críticos Revisados

```
addons/localization/l10n_cl_hr_payroll/
├── models/
│   ├── hr_payslip.py              (1,500 líneas) ✅
│   ├── hr_economic_indicators.py  (350 líneas) ✅
│   ├── hr_tax_bracket.py          (250 líneas) ✅
│   ├── l10n_cl_legal_caps.py      (150 líneas) ✅
│   └── hr_salary_rule.py          (332 líneas) ✅
├── wizards/
│   └── hr_lre_wizard.py           (368 líneas) ⚠️ INCOMPLETO
├── data/
│   ├── l10n_cl_legal_caps_2025.xml     ⚠️ Tope AFP 81.6 vs 83.1
│   ├── hr_tax_bracket_2025.xml         ✅ 8 tramos correctos
│   └── hr_salary_rule_category_*.xml   ✅ 13 base + 9 SOPA
├── security/
│   ├── ir.model.access.csv        ✅ 36 reglas
│   └── security_groups.xml        ⚠️ Falta ir.rule
├── tests/
│   └── (11 suites, 53 tests)      ✅ Buena cobertura base
└── i18n/
    ├── es_CL.po                   ✅
    └── en_US.po                   ✅
```

---

## Aprobación Producción

### Criterios Go/No-Go

| Criterio | Estado | Bloqueante |
|----------|--------|------------|
| ✅ Cálculos AFP correctos | PENDIENTE P0-1 | **SÍ** |
| ✅ Export LRE completo | PENDIENTE P0-2 | **SÍ** |
| ✅ Seguridad multi-compañía | PENDIENTE P0-3 | **SÍ** |
| ✅ Tests P0 pasando | PENDIENTE | **SÍ** |
| ⚠️ Snapshot auditoría | PENDIENTE P1-1 | NO |
| ⚠️ i18n completo | PENDIENTE P1-3 | NO |

### Veredicto Final

**NO LISTO PARA PRODUCCIÓN** hasta corregir P0

**Tiempo estimado disponibilidad producción:** 3-5 días

---

## Contacto

**Para consultas técnicas:**
- Revisar informe completo: `AUDITORIA_REGULATORIA_NOMINA_CHILE_2025-11-07.md`
- Datasets prueba incluidos en Sección 7
- Tests propuestos en Sección 6.2

**Para consultas legales:**
- Referencias normativas: Anexo A del informe completo
- Fuentes oficiales: Anexo B del informe completo

---

**Fin del Resumen Ejecutivo**
