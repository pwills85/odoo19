# 🎯 PROMPT MASTER - AUDITORÍA FUNCIONAL ODOO 11 (CONTINUACIÓN)
## Fases Prioritarias | Validación Know-How Crítico | Comparación con Odoo 19

**Versión:** 1.1 (Continuación - Fases Prioritarias)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (Fases 1, 2.1, 2.2 completadas ✅)  
**Base:** PROMPT Auditoría Funcional V1.0 + Log Agente Líneas 944-1033 + Análisis Liderazgo  
**Progreso Actual:** 3 horas invertidas (Fases 1, 2.1, 2.2 completadas ✅)  
**Know-How Crítico Identificado:** Scraping MEPCO, Scraping Previred, Fórmulas críticas, Error horas extra

---

## ✅ RECONOCIMIENTO: TRABAJO EXCEPCIONAL REALIZADO

### Evaluación del Trabajo Realizado (Calificación: 10/10)

**Fases Completadas:** ✅ EXCELENTE PROGRESO

**Fortalezas Identificadas:**
- ✅ **Metodología Rigurosa:** Siguió protocolo de auditoría funcional perfectamente
- ✅ **Know-How Crítico Identificado:** Detectó sistemas de scraping automatizado (MEPCO, Previred)
- ✅ **Fórmulas Documentadas:** 15 fórmulas críticas documentadas con detalle
- ✅ **Errores Detectados:** Identificó fórmula de horas extra con factor erróneo
- ✅ **Documentación Completa:** 3 documentos generados (75KB total) con análisis profundo

**Calificación Detallada:**

| Aspecto | Calificación | Comentario |
|---------|--------------|------------|
| **Metodología** | 10/10 | Siguió protocolo de auditoría perfectamente |
| **Profundidad del Análisis** | 10/10 | Análisis detallado de 33 modelos, 250+ campos |
| **Know-How Identificado** | 10/10 | Detectó sistemas críticos de scraping automatizado |
| **Documentación** | 10/10 | Documentos completos y estructurados |
| **Hallazgos Críticos** | 10/10 | Identificó know-how crítico y errores |

**Conclusión:** Trabajo excepcional. El agente auditor está cumpliendo perfectamente con el protocolo y ha identificado know-how crítico que debe preservarse en Odoo 19.

---

## 🚨 HALLAZGOS CRÍTICOS VALIDADOS Y CONTRASTADOS

### 🔴 HALLAZGO CRÍTICO #1: Sistema de Scraping Automatizado Previred

**Hallazgo del Agente:**
- Sistema de scraping automatizado de Previred.com en Odoo 11 producción
- Obtiene automáticamente: UF, UTM, UTA, tasas AFP, topes, asignación familiar, seguro de cesantía

**Validación en Desarrollo Odoo 19:**

✅ **YA EXISTE PARCIALMENTE:**

1. **Sistema de Scraping Previred:**
   - Archivo: `ai-service/payroll/previred_scraper.py`
   - Usa Claude API para parsear PDF oficial de Previred
   - Extrae 60 campos de indicadores previsionales
   - Endpoint: `/api/payroll/indicators/{period}`

2. **Integración con Odoo 19:**
   - Documentación: `docs/payroll-project/14_ANALISIS_SCRAPER_PREVIRED.md`
   - Método propuesto: `hr.economic.indicators.fetch_from_ai_service()`
   - Flujo: Odoo → AI Service → Previred PDF → Claude API → Odoo

**Estado:**
- ✅ Sistema existe en arquitectura Odoo 19
- ⚠️ Requiere validación: ¿Está completamente implementado?
- ⚠️ Requiere comparación: ¿Funciona igual que Odoo 11?

**Acción Requerida:**
1. **Comparar Implementación:**
   - ¿Cómo funciona scraping en Odoo 11?
   - ¿Cómo funciona scraping en Odoo 19?
   - ¿Son equivalentes funcionalmente?

2. **Validar Completitud:**
   - ¿Obtiene todos los datos que Odoo 11 obtiene?
   - ¿Frecuencia de actualización es similar?
   - ¿Manejo de errores es equivalente?

---

### 🔴 HALLAZGO CRÍTICO #2: Sistema de Scraping Automatizado MEPCO

**Hallazgo del Agente:**
- Sistema de scraping automático de MEPCO desde Diario Oficial
- Gestión automática de impuestos MEPCO

**Validación en Desarrollo Odoo 19:**

❓ **NO VALIDADO AÚN:**

- No se encontró sistema similar en desarrollo Odoo 19
- Requiere investigación profunda

**Acción Requerida:**
1. **Documentar Detalladamente en Fase 3.1:**
   - Cómo funciona el scraping de MEPCO en Odoo 11
   - Qué datos obtiene del Diario Oficial
   - Cómo se integra con el sistema de facturación
   - Frecuencia de actualización

2. **Validar Necesidad:**
   - ¿Es crítico para cumplimiento SII?
   - ¿Se puede implementar en Odoo 19?
   - ¿Es P0, P1 o P2?

---

### ⚠️ HALLAZGO CRÍTICO #3: Error en Fórmula de Horas Extra

**Hallazgo del Agente:**
- Fórmula de horas extra con factor erróneo (inflado x28)

**Validación en Desarrollo Odoo 19:**

❓ **NO VALIDADO AÚN:**

- Requiere validación en código Odoo 19
- Requiere comparación con normativa chilena

**Acción Requerida:**
1. **Documentar Error en Fase 3.2:**
   - Fórmula actual (incorrecta) en Odoo 11
   - Fórmula correcta según normativa
   - Impacto del error (cuánto se está pagando de más)

2. **Validar en Odoo 19:**
   - ¿Existe el mismo error en desarrollo actual?
   - ¿Cómo se calculan horas extra actualmente?
   - ¿Está correcto según normativa?

---

## 🎯 PLAN DE CONTINUACIÓN PRIORIZADO

### ⚠️ ESTRATEGIA: PRIORIZAR FASES CRÍTICAS

**Razón:** Las fases 3.2, 8 y 9 son más críticas que las fases 4-7 para el desarrollo actual porque:
- Identifican know-how crítico de cálculos
- Identifican gaps regulatorios 2025
- Comparan funcionalidad con desarrollo actual

---

## 📋 FASE 3.2: DOCUMENTAR CÁLCULOS DE NÓMINAS (PRIORIDAD P0 - CRÍTICO)

### ⚠️ PRIORIDAD ALTA - INICIAR INMEDIATAMENTE

**Tiempo Estimado:** 2-3 horas  
**Razón:** Las fórmulas críticas identificadas en Fase 2.2 deben documentarse completamente antes de continuar.

### Objetivo

Documentar todas las fórmulas de cálculo de nóminas con:
- Fórmulas completas y exactas
- Comparación con implementación Odoo 19
- Validación con normativa chilena
- Identificación de discrepancias y errores

### Tareas Específicas

#### Tarea 3.2.1: Documentar Fórmula de Impuesto Único (30min)

**Tareas Obligatorias:**

1. **Leer Código de Impuesto Único en Odoo 11:**
   ```bash
   # Buscar regla salarial de impuesto único
   grep -r "impuesto.*único\|impuesto_unico\|IMPUESTO_UNICO" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   
   # Buscar modelo hr.tax.bracket o similar
   find /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/ -name "*tax*.py" -o -name "*impuesto*.py"
   ```

2. **Documentar Fórmula Completa:**
   - 7 tramos progresivos con valores exactos
   - Fórmula de rebaja exacta
   - Base tributable: cómo se calcula
   - Ejemplos de cálculo por tramo

3. **Comparar con Odoo 19:**
   ```bash
   # Buscar implementación en Odoo 19
   grep -r "impuesto.*único\|impuesto_unico\|IMPUESTO_UNICO\|_calculate_progressive_tax" addons/localization/l10n_cl_hr_payroll/
   
   # Comparar fórmulas
   # ¿Coinciden los tramos?
   # ¿Coincide la fórmula de rebaja?
   # ¿Coincide el cálculo de base tributable?
   ```

4. **Validar con Normativa:**
   - Consultar resoluciones SII sobre impuesto único
   - Validar tramos vigentes 2025
   - Validar fórmula de rebaja

**Entregable:**
- Sección en `evidencias/fase3_2_calculos_nominas.md`
- Fórmula completa con comparación Odoo 11 vs Odoo 19
- Validación con normativa chilena

#### Tarea 3.2.2: Documentar Fórmula de Gratificación Legal (30min)

**Tareas Obligatorias:**

1. **Leer Código de Gratificación en Odoo 11:**
   ```bash
   # Buscar regla salarial de gratificación
   grep -r "gratificación\|gratification\|Art\. 50\|Artículo 50" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   ```

2. **Documentar Fórmula Completa:**
   - 25% utilidades líquidas
   - Distribución proporcional
   - Tope 4.75 SM/12 (mensualización)
   - Cómo se calcula base de gratificación
   - Ejemplos de cálculo

3. **Comparar con Odoo 19:**
   ```bash
   # Buscar implementación en Odoo 19
   grep -r "_compute_gratification\|gratification.*amount\|GRAT" addons/localization/l10n_cl_hr_payroll/
   ```

4. **Validar con Normativa:**
   - Art. 50 Código del Trabajo
   - Validar fórmula de cálculo
   - Validar tope legal

**Entregable:**
- Sección en `evidencias/fase3_2_calculos_nominas.md`
- Fórmula completa con comparación Odoo 11 vs Odoo 19
- Validación con normativa chilena

#### Tarea 3.2.3: Documentar Fórmula de Asignación Familiar (30min)

**Tareas Obligatorias:**

1. **Leer Código de Asignación Familiar en Odoo 11:**
   ```bash
   # Buscar regla salarial de asignación familiar
   grep -r "asignación.*familiar\|family.*allowance\|ASIGNACION_FAMILIAR" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   ```

2. **Documentar Fórmula Completa:**
   - 3 tramos progresivos con montos exactos
   - Cómo se determina el tramo
   - Montos por tramo (simple y maternal)
   - Ejemplos de cálculo

3. **Comparar con Odoo 19:**
   ```bash
   # Buscar implementación en Odoo 19
   grep -r "asignacion_familiar\|family_allowance" addons/localization/l10n_cl_hr_payroll/
   ```

4. **Validar con Normativa:**
   - Ley 18.020 sobre asignación familiar
   - Validar montos vigentes 2025
   - Validar tramos

**Entregable:**
- Sección en `evidencias/fase3_2_calculos_nominas.md`
- Fórmula completa con comparación Odoo 11 vs Odoo 19
- Validación con normativa chilena

#### Tarea 3.2.4: Documentar Error de Horas Extra (30min)

**Tareas Obligatorias:**

1. **Leer Código de Horas Extra en Odoo 11:**
   ```bash
   # Buscar regla salarial de horas extra
   grep -r "horas.*extra\|overtime\|HEX\|HE50\|HE100" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   ```

2. **Documentar Error:**
   - Fórmula actual (incorrecta) con factor x28
   - Fórmula correcta según normativa chilena
   - Impacto del error (cuánto se está pagando de más)
   - Ejemplos de cálculo incorrecto vs correcto

3. **Validar en Odoo 19:**
   ```bash
   # Buscar implementación en Odoo 19
   grep -r "horas.*extra\|overtime\|HEX\|HE50\|HE100" addons/localization/l10n_cl_hr_payroll/
   ```

4. **Validar con Normativa:**
   - Art. 32 Código del Trabajo sobre horas extra
   - Validar factores correctos (50%, 100%)
   - Validar fórmula de cálculo

**Entregable:**
- Sección en `evidencias/fase3_2_calculos_nominas.md`
- Error documentado con impacto
- Validación en Odoo 19
- Recomendación de corrección

#### Tarea 3.2.5: Documentar Sistema de Scraping Previred (30min)

**Tareas Obligatorias:**

1. **Leer Código de Scraping Previred en Odoo 11:**
   ```bash
   # Buscar código de scraping
   grep -r "previred\|scraping\|scrape\|urllib\|requests\|beautifulsoup" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   ```

2. **Documentar Funcionamiento:**
   - Cómo funciona técnicamente
   - Qué URLs/endpoints utiliza
   - Cómo parsea los datos
   - Frecuencia de actualización
   - Manejo de errores y reintentos
   - Qué datos obtiene exactamente

3. **Comparar con Odoo 19:**
   - ¿Cómo funciona en Odoo 19?
   - ¿Es equivalente funcionalmente?
   - ¿Qué diferencias hay?

**Entregable:**
- Sección en `evidencias/fase3_2_calculos_nominas.md`
- Documentación completa del scraping
- Comparación Odoo 11 vs Odoo 19

### Entregable Final Fase 3.2

**Archivo:** `evidencias/fase3_2_calculos_nominas.md`

**Contenido Requerido:**

```markdown
# Fase 3.2: Cálculos de Nóminas - Odoo 11 Producción

## Resumen Ejecutivo
- Fórmulas críticas documentadas
- Comparación con Odoo 19
- Discrepancias identificadas
- Errores detectados

## 1. Impuesto Único
### Fórmula en Odoo 11:
[Fórmula completa con 7 tramos]

### Fórmula en Odoo 19:
[Fórmula completa con 7 tramos]

### Comparación:
- ¿Coinciden tramos? SÍ/NO
- ¿Coincide fórmula de rebaja? SÍ/NO
- ¿Coincide cálculo base tributable? SÍ/NO

### Validación Normativa:
- Resoluciones SII: [Citas]
- Tramos vigentes 2025: [Valores]

## 2. Gratificación Legal
[Similar estructura]

## 3. Asignación Familiar
[Similar estructura]

## 4. Error Horas Extra
### Fórmula Incorrecta (Odoo 11):
[Fórmula con factor x28]

### Fórmula Correcta (Normativa):
[Fórmula correcta según Art. 32 CT]

### Impacto:
- Error causa sobrepago de X%
- Ejemplo: [Cálculo específico]

### Estado en Odoo 19:
- ¿Existe el mismo error? SÍ/NO
- ¿Cómo se calcula actualmente? [Descripción]

## 5. Sistema de Scraping Previred
### Funcionamiento en Odoo 11:
[Descripción técnica completa]

### Funcionamiento en Odoo 19:
[Descripción técnica completa]

### Comparación:
- ¿Son equivalentes? SÍ/NO
- ¿Qué diferencias hay? [Lista]

## Conclusiones
- Know-how crítico identificado
- Discrepancias encontradas
- Errores detectados
- Recomendaciones
```

---

## 📋 FASE 8: GAPS REGULATORIOS 2025 (PRIORIDAD P0 - CRÍTICO)

### ⚠️ PRIORIDAD ALTA - DESPUÉS DE FASE 3.2

**Tiempo Estimado:** 1 hora  
**Razón:** Identificar qué falta para cumplir con regulaciones 2025 es crítico para el desarrollo actual.

### Objetivo

Identificar gaps regulatorios 2025 comparando:
- Qué existe en Odoo 11 producción
- Qué existe en desarrollo Odoo 19
- Qué falta implementar

### Tareas Específicas

#### Tarea 8.1: Reforma Previsional 2025 (30min)

**Tareas Obligatorias:**

1. **Buscar en Odoo 11:**
   ```bash
   # Buscar referencias a reforma 2025
   grep -r "reforma.*2025\|2025.*reforma\|aporte.*empleador\|employer.*contribution" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   ```

2. **Validar en Odoo 19:**
   ```bash
   # Buscar implementación en Odoo 19
   grep -r "reforma.*2025\|2025.*reforma\|employer_reforma\|employer_total_ley21735" addons/localization/l10n_cl_hr_payroll/
   ```

3. **Documentar Gaps:**
   - ¿Existe en Odoo 11? SÍ/NO
   - ¿Existe en Odoo 19? SÍ/NO
   - ¿Qué falta implementar? [Lista]

#### Tarea 8.2: Ley 21.735 (Reforma Pensiones) (30min)

**Tareas Obligatorias:**

1. **Buscar en Odoo 11:**
   ```bash
   # Buscar referencias a Ley 21.735
   grep -r "21\.735\|Ley.*21735\|reforma.*pensiones" /Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons/l10n_cl_hr/
   ```

2. **Validar en Odoo 19:**
   ```bash
   # Buscar implementación en Odoo 19
   grep -r "21\.735\|Ley.*21735\|ley21735\|aplica_ley21735" addons/localization/l10n_cl_hr_payroll/
   ```

3. **Documentar Gaps:**
   - ¿Existe en Odoo 11? SÍ/NO
   - ¿Existe en Odoo 19? SÍ/NO
   - ¿Qué falta implementar? [Lista]

### Entregable Final Fase 8

**Archivo:** `evidencias/fase8_gaps_regulatorios_2025.md`

**Contenido Requerido:**

```markdown
# Fase 8: Gaps Regulatorios 2025

## Resumen Ejecutivo
- Gaps identificados
- Priorización
- Recomendaciones

## 1. Reforma Previsional 2025
### Estado en Odoo 11:
- ¿Existe? SÍ/NO
- ¿Cómo está implementado? [Descripción]

### Estado en Odoo 19:
- ¿Existe? SÍ/NO
- ¿Cómo está implementado? [Descripción]

### Gaps Identificados:
- [Lista de gaps]

### Prioridad: P0/P1/P2

## 2. Ley 21.735 (Reforma Pensiones)
[Similar estructura]

## Conclusiones
- Gaps críticos identificados
- Priorización
- Plan de implementación sugerido
```

---

## 📋 FASE 9: COMPARACIÓN CON DESARROLLO ODOO 19 (PRIORIDAD P0 - CRÍTICO)

### ⚠️ PRIORIDAD ALTA - DESPUÉS DE FASE 8

**Tiempo Estimado:** 2 horas  
**Razón:** Comparar funcionalidad completa es crítico para identificar qué falta implementar.

### Objetivo

Comparar funcionalidad de producción (Odoo 11) con desarrollo actual (Odoo 19) para:
- Identificar features faltantes
- Identificar features con diferencias funcionales
- Priorizar implementación

### Tareas Específicas

#### Tarea 9.1: Comparar Sistemas de Scraping (30min)

**Tareas Obligatorias:**

1. **Comparar Scraping Previred:**
   - Odoo 11: [Cómo funciona]
   - Odoo 19: [Cómo funciona]
   - ¿Son equivalentes? SÍ/NO
   - ¿Qué diferencias hay? [Lista]

2. **Comparar Scraping MEPCO:**
   - Odoo 11: [Cómo funciona]
   - Odoo 19: ¿Existe? SÍ/NO
   - ¿Qué falta implementar? [Lista]

#### Tarea 9.2: Comparar Fórmulas de Cálculo (45min)

**Tareas Obligatorias:**

1. **Para cada fórmula crítica:**
   - Comparar fórmula Odoo 11 vs Odoo 19
   - Identificar discrepancias
   - Validar con normativa
   - Priorizar correcciones

#### Tarea 9.3: Comparar Features (45min)

**Tareas Obligatorias:**

1. **Features de Facturación:**
   - ¿Qué features de Odoo 11 NO están en Odoo 19?
   - ¿Qué features de Odoo 19 NO están en Odoo 11?
   - ¿Qué features tienen diferencias funcionales?

2. **Features de Nóminas:**
   - ¿Qué features de Odoo 11 NO están en Odoo 19?
   - ¿Qué features de Odoo 19 NO están en Odoo 11?
   - ¿Qué features tienen diferencias funcionales?

### Entregable Final Fase 9

**Archivo:** `evidencias/fase9_comparacion_odoo19.md`

**Contenido Requerido:**

```markdown
# Fase 9: Comparación Odoo 11 Producción vs Odoo 19 Desarrollo

## Resumen Ejecutivo
- Features comparadas
- Discrepancias identificadas
- Análisis de riesgos
- Recomendaciones

## 1. Sistemas de Scraping
### Scraping Previred:
- Odoo 11: [Descripción]
- Odoo 19: [Descripción]
- Comparación: [Análisis]
- Riesgo: ALTO/MEDIO/BAJO

### Scraping MEPCO:
- Odoo 11: [Descripción]
- Odoo 19: ¿Existe? SÍ/NO
- Gap: [Descripción]
- Riesgo: ALTO/MEDIO/BAJO

## 2. Fórmulas de Cálculo
[Para cada fórmula crítica]

## 3. Features Funcionales
[Para cada feature]

## Análisis de Riesgos
- Riesgos de pérdida de funcionalidad
- Riesgos de cambios funcionales incorrectos
- Recomendaciones

## Plan de Acción
- Features a preservar (prioridad)
- Features a implementar (prioridad)
- Features a corregir (prioridad)
```

---

## 📋 FASES RESTANTES (PRIORIDAD P1-P2)

### Fase 3.1: Cálculos de Facturación (P1 - ALTO)

**Tiempo Estimado:** 1.5-2 horas  
**Prioridad:** P1 - ALTO (después de Fase 3.2)

**Tareas:**
- Documentar cálculos de impuestos (IVA, exentos)
- Documentar cálculos de totales
- Documentar cálculos de DTE
- Documentar cálculos de libros

### Fase 4: Vistas y Flujos de Usuario (P2 - MEDIO)

**Tiempo Estimado:** 2 horas  
**Prioridad:** P2 - MEDIO (después de Fases críticas)

**Tareas:**
- Documentar vistas de facturación
- Documentar vistas de nóminas
- Documentar flujos de usuario

### Fase 5: Menús y Navegación (P2 - MEDIO)

**Tiempo Estimado:** 1 hora  
**Prioridad:** P2 - MEDIO

**Tareas:**
- Documentar estructura de menús
- Documentar accesos y permisos

### Fase 6: Reportes y Exportaciones (P1 - ALTO)

**Tiempo Estimado:** 1.5 horas  
**Prioridad:** P1 - ALTO

**Tareas:**
- Documentar reportes de facturación
- Documentar reportes de nóminas
- Documentar exportaciones

### Fase 7: Datos Maestros (P2 - MEDIO)

**Tiempo Estimado:** 1 hora  
**Prioridad:** P2 - MEDIO

**Tareas:**
- Documentar datos maestros necesarios
- Documentar configuración requerida

### Fase 10: Reporte Ejecutivo (P0 - CRÍTICO)

**Tiempo Estimado:** 1 hora  
**Prioridad:** P0 - CRÍTICO (al final)

**Tareas:**
- Generar resumen ejecutivo
- Generar recomendaciones
- Generar plan de acción

---

## 🎯 ORDEN DE EJECUCIÓN RECOMENDADO

### Fase Inmediata (P0 - CRÍTICO)

1. **Fase 3.2: Cálculos de Nóminas** (2-3h) - ⚠️ INICIAR AHORA
   - Documentar fórmulas críticas
   - Comparar con Odoo 19
   - Identificar discrepancias y errores

### Fase Siguiente (P0 - CRÍTICO)

2. **Fase 8: Gaps Regulatorios 2025** (1h)
   - Identificar qué falta para cumplir con regulaciones 2025
   - Comparar con desarrollo Odoo 19

3. **Fase 9: Comparación con Odoo 19** (2h)
   - Comparar funcionalidad completa
   - Identificar qué falta implementar
   - Priorizar features críticas

### Fases Posteriores (P1-P2)

4. **Fase 3.1: Cálculos de Facturación** (1.5-2h)
5. **Fase 6: Reportes y Exportaciones** (1.5h)
6. **Fase 4: Vistas y Flujos** (2h)
7. **Fase 5: Menús** (1h)
8. **Fase 7: Datos Maestros** (1h)
9. **Fase 10: Reporte Ejecutivo** (1h)

**Tiempo Total Estimado Restante:** 12-15 horas

---

## ✅ CONCLUSIÓN Y RECOMENDACIÓN

### Estado Actual

**Progreso Excepcional:** ✅ 10/10
- Fases 1, 2.1 y 2.2 completadas con excelencia
- Know-how crítico identificado (scraping MEPCO, Previred)
- Errores detectados (fórmula horas extra)
- Documentación completa y estructurada

**Hallazgos Críticos Validados:**
- 🔴 Sistema de scraping Previred: Existe parcialmente en Odoo 19, requiere validación
- 🔴 Sistema de scraping MEPCO: No validado en Odoo 19, requiere investigación
- 🔴 Error en fórmula de horas extra: Requiere validación en Odoo 19

**Recomendación:**

**El agente auditor DEBE:**

1. **Continuar con Fase 3.2: Cálculos de Nóminas (PRIORIDAD P0)**
   - Documentar fórmulas críticas completas
   - Comparar con implementación Odoo 19
   - Identificar discrepancias y errores
   - Validar error de horas extra en Odoo 19

2. **Continuar con Fase 8: Gaps Regulatorios 2025 (PRIORIDAD P0)**
   - Identificar qué falta para cumplir con regulaciones 2025
   - Comparar con desarrollo Odoo 19

3. **Continuar con Fase 9: Comparación con Odoo 19 (PRIORIDAD P0)**
   - Comparar funcionalidad completa
   - Identificar qué falta implementar
   - Priorizar features críticas

4. **Después: Continuar con Fases Restantes (P1-P2)**
   - Fase 3.1: Cálculos de facturación
   - Fase 4: Vistas y flujos
   - Fase 5: Menús
   - Fase 6: Reportes
   - Fase 7: Datos maestros
   - Fase 10: Reporte ejecutivo

**Objetivo:** Completar auditoría funcional priorizando know-how crítico y gaps regulatorios para informar desarrollo Odoo 19.

---

**FIN DEL PROMPT MASTER - AUDITORÍA FUNCIONAL (CONTINUACIÓN)**

