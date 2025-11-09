# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (V5.12)
## Fase 0: Investigación Regulatoria | Protocolo Ejecutivo | Sin Improvisación

**Versión:** 5.12 (Fase 0: Investigación Regulatoria - Protocolo Ejecutivo)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (Fase 0 iniciando - Investigación Regulatoria)  
**Base:** PROMPT V5.11 + Log Agente Líneas 539-573 + Reconocimiento de Protocolo  
**Progreso Actual:** 5.5 horas invertidas  
**Estado Real Validado:** 19 tests fallando (28 → 19 = -32% progreso acumulado ✅)

---

## ✅ RECONOCIMIENTO: COMPROMISO CON PROTOCOLO VALIDADO

### Evaluación del Entendimiento del Agente (Calificación: 10/10)

**Análisis del Agente (Líneas 539-573):** ✅ EXCELENTE COMPRENSIÓN

**Fortalezas Identificadas:**
- ✅ **Reconocimiento del Problema:** Identificó correctamente la improvisación sin validación regulatoria
- ✅ **Comprensión del Root Cause:** Entendió que el problema es falta de investigación regulatoria, no técnico
- ✅ **Compromiso con Protocolo:** Se comprometió a seguir Fase 0: Investigación Regulatoria completa
- ✅ **Preguntas Críticas Identificadas:** Identificó correctamente las 4 preguntas críticas a responder
- ✅ **Listo para Proceder:** Confirmó estar listo para iniciar Fase 0

**Calificación Detallada:**

| Aspecto | Calificación | Comentario |
|---------|--------------|------------|
| **Entendimiento del Problema** | 10/10 | Identificó correctamente improvisación sin validación |
| **Comprensión del Protocolo** | 10/10 | Entendió Fase 0 completa y sus pasos |
| **Compromiso** | 10/10 | Se comprometió explícitamente a seguir protocolo |
| **Preguntas Críticas** | 10/10 | Identificó correctamente las 4 preguntas críticas |
| **Disposición** | 10/10 | Listo para proceder con investigación regulatoria |

**Conclusión:** El agente ha entendido perfectamente el problema y está comprometido con el protocolo correcto. Proceder con Fase 0: Investigación Regulatoria.

---

## 🎯 INSTRUCCIONES PARA FASE 0: INVESTIGACIÓN REGULATORIA

### ⚠️ PROTOCOLO OBLIGATORIO - SIN EXCEPCIONES

**El agente DEBE seguir este protocolo paso a paso, sin saltar ningún paso.**

---

## 📋 FASE 0: INVESTIGACIÓN REGULATORIA (1.5h) - OBLIGATORIA

### Problema #1: total_imponible Mal Calculado (Gratificación Legal)

**Tiempo Estimado:** 30min  
**Prioridad:** P0 - CRÍTICA

#### Paso 0.1.1: Consultar Documentación Local (10min)

**Tareas Obligatorias:**

1. **Leer Documentación Regulatoria Completa:**
   ```bash
   # Leer contexto regulatorio SII
   cat .claude/agents/knowledge/sii_regulatory_context.md
   
   # Leer estructura salarial Chile
   cat docs/payroll-project/20_ESTRUCTURA_SALARIAL_CHILE.md
   
   # Buscar referencias a gratificación en código
   grep -r "gratificación\|gratification\|Art\. 50\|Artículo 50" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   
   # Buscar referencias a base imponible
   grep -r "base imponible\|total_imponible\|imponible.*AFP" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   ```

2. **Documentar Hallazgos:**
   - ¿Qué dice la documentación local sobre gratificación legal?
   - ¿Qué dice sobre base imponible AFP?
   - ¿Hay referencias específicas a Art. 50 CT?
   - ¿Qué conceptos deben incluirse en base imponible?

**Entregable Parcial:**
- Notas sobre hallazgos en documentación local
- Referencias específicas encontradas

#### Paso 0.1.2: Investigar en Sitios Web Oficiales (15min)

**Tareas Obligatorias:**

1. **SII (Servicio de Impuestos Internos):**
   - **URL:** https://www.sii.cl
   - **Búsquedas Específicas:**
     - "gratificación legal imponible AFP"
     - "base imponible AFP gratificación"
     - "Art. 50 Código del Trabajo base imponible"
     - "conceptos imponibles AFP Chile"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

2. **DT (Dirección del Trabajo):**
   - **URL:** https://www.dt.gob.cl
   - **Búsquedas Específicas:**
     - "Artículo 50 gratificación legal"
     - "gratificación legal base imponible previsional"
     - "gratificación afecta AFP Salud"
     - "cálculo gratificación legal imponible"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

3. **SP (Superintendencia de Pensiones):**
   - **URL:** https://www.spensiones.cl
   - **Búsquedas Específicas:**
     - "gratificación afecta base imponible AFP"
     - "conceptos imponibles AFP"
     - "base imponible AFP 2025"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

4. **Previred:**
   - **URL:** https://www.previred.cl
   - **Búsquedas Específicas:**
     - "gratificación formato Book 49"
     - "gratificación base imponible Previred"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

**Entregable Parcial:**
- URLs consultadas con capturas o citas
- Conclusiones de cada sitio web
- Referencias específicas encontradas

#### Paso 0.1.3: Validar con Normativa Específica (10min)

**Tareas Obligatorias:**

1. **Art. 50 Código del Trabajo:**
   - Leer Art. 50 completo
   - Buscar interpretaciones oficiales
   - **Pregunta Crítica:** ¿La gratificación legal es imponible para AFP/Salud según Art. 50?

2. **DFL 150 (Ley de AFP):**
   - Buscar definición de base imponible AFP
   - Buscar qué conceptos afectan base imponible
   - **Pregunta Crítica:** ¿La gratificación debe incluirse en base imponible AFP según DFL 150?

3. **Resoluciones SII:**
   - Buscar resoluciones sobre base imponible
   - Buscar resoluciones sobre gratificación
   - **Pregunta Crítica:** ¿Qué dice SII sobre gratificación y base imponible?

**Entregable Parcial:**
- Citas específicas de normativa
- Referencias a artículos, leyes, resoluciones
- Conclusiones basadas en normativa

#### Paso 0.1.4: Documentar Hallazgos (5min)

**Entregable Final Problema #1:**
- Archivo: `evidencias/investigacion_regulatoria_total_imponible.md`
- Formato requerido:

```markdown
# Investigación Regulatoria: total_imponible (Gratificación Legal)

## Resumen Ejecutivo
- Hallazgo principal según normativa chilena
- ¿Gratificación legal ES o NO ES imponible para AFP/Salud?
- Cómo debe calcularse total_imponible según normativa

## Documentación Local Consultada
### Archivos Consultados:
- `.claude/agents/knowledge/sii_regulatory_context.md`
- `docs/payroll-project/20_ESTRUCTURA_SALARIAL_CHILE.md`
- [Otros archivos consultados]

### Hallazgos Específicos:
- [Citas específicas de documentación local]
- [Referencias encontradas en código]

## Sitios Web Oficiales Consultados
### SII (Servicio de Impuestos Internos)
- **URLs Consultadas:**
  - [URL 1] - [Hallazgo específico]
  - [URL 2] - [Hallazgo específico]
- **Conclusiones:** [Qué dice SII sobre gratificación y base imponible]

### DT (Dirección del Trabajo)
- **URLs Consultadas:**
  - [URL 1] - [Hallazgo específico]
  - [URL 2] - [Hallazgo específico]
- **Conclusiones:** [Qué dice DT sobre Art. 50 y base imponible]

### SP (Superintendencia de Pensiones)
- **URLs Consultadas:**
  - [URL 1] - [Hallazgo específico]
- **Conclusiones:** [Qué dice SP sobre gratificación y base imponible AFP]

### Previred
- **URLs Consultadas:**
  - [URL 1] - [Hallazgo específico]
- **Conclusiones:** [Qué dice Previred sobre gratificación en formato Book 49]

## Normativa Específica
### Art. 50 Código del Trabajo
- **Cita Específica:** [Texto completo del artículo o cita relevante]
- **Interpretación:** [Cómo se interpreta en relación a base imponible]
- **Conclusión:** [¿Gratificación es imponible según Art. 50?]

### DFL 150 (Ley de AFP)
- **Cita Específica:** [Cita relevante sobre base imponible]
- **Interpretación:** [Qué conceptos deben incluirse en base imponible]
- **Conclusión:** [¿Gratificación debe incluirse según DFL 150?]

### Resoluciones SII
- **Resolución:** [Número y fecha]
- **Cita Específica:** [Cita relevante]
- **Conclusión:** [Qué dice SII sobre gratificación y base imponible]

## Respuesta a Pregunta Crítica
**Pregunta:** ¿La gratificación legal (Art. 50 CT) es imponible para AFP/Salud?

**Respuesta:** [SÍ/NO con justificación completa basada en investigación]

**Justificación:**
- [Cita 1 de normativa]
- [Cita 2 de sitio web oficial]
- [Cita 3 de documentación local]
- [Conclusión final]

## Recomendación Técnica
**Cómo debe implementarse según normativa:**
- [Descripción técnica de cómo debe calcularse total_imponible]
- [Qué conceptos deben incluirse]
- [Qué conceptos deben excluirse]
- [Referencias normativas que respaldan la implementación]

## Referencias
- [Lista completa de URLs consultadas]
- [Lista completa de normativa consultada]
- [Lista completa de documentación local consultada]
```

**Criterios de Validación:**
- ✅ Incluye resumen ejecutivo con respuesta clara
- ✅ Incluye URLs consultadas con hallazgos específicos
- ✅ Incluye citas específicas de normativa
- ✅ Responde pregunta crítica con justificación completa
- ✅ Incluye recomendación técnica basada en normativa
- ✅ Incluye referencias completas

---

### Problema #2: AFC Sin Tope Aplicado

**Tiempo Estimado:** 20min  
**Prioridad:** P1 - ALTA

#### Paso 0.2.1: Consultar Documentación Local (5min)

**Tareas Obligatorias:**

1. **Buscar Referencias a AFC:**
   ```bash
   # Buscar referencias a AFC en código
   grep -r "AFC\|afc\|cesantía\|seguro.*cesantía" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   
   # Buscar referencias a tope AFC
   grep -r "120\.2\|tope.*AFC\|AFC.*tope" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   ```

2. **Documentar Hallazgos:**
   - ¿Qué dice la documentación local sobre AFC?
   - ¿Qué dice sobre tope 120.2 UF?
   - ¿Cómo se aplica el tope según documentación local?

#### Paso 0.2.2: Investigar en Sitios Web Oficiales (10min)

**Tareas Obligatorias:**

1. **SP (Superintendencia de Pensiones):**
   - **URL:** https://www.spensiones.cl
   - **Búsquedas Específicas:**
     - "tope AFC 120.2 UF"
     - "seguro de cesantía tope imponible"
     - "AFC base imponible tope legal"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

2. **SII (Servicio de Impuestos Internos):**
   - **URL:** https://www.sii.cl
   - **Búsquedas Específicas:**
     - "seguro de cesantía tope imponible"
     - "AFC base imponible"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

#### Paso 0.2.3: Validar con Normativa Específica (5min)

**Tareas Obligatorias:**

1. **Normativa sobre Seguro de Cesantía:**
   - Buscar normativa sobre tope AFC
   - Buscar cómo se aplica el tope
   - **Pregunta Crítica:** ¿Cuál es el tope legal AFC vigente en 2025 y cómo se aplica?

#### Paso 0.2.4: Documentar Hallazgos (5min)

**Entregable Final Problema #2:**
- Archivo: `evidencias/investigacion_regulatoria_afc_tope.md`
- Mismo formato que Problema #1
- **Pregunta Crítica a Responder:** ¿Cuál es el tope legal AFC vigente en 2025 y cómo se aplica?

---

### Problema #3: Impuesto Único Mal Calculado

**Tiempo Estimado:** 20min  
**Prioridad:** P1 - ALTA

#### Paso 0.3.1: Consultar Documentación Local (5min)

**Tareas Obligatorias:**

1. **Buscar Referencias a Impuesto Único:**
   ```bash
   # Buscar referencias a impuesto único
   grep -r "impuesto único\|impuesto_unico\|IMPUESTO_UNICO\|base tributable\|base_tributable" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   ```

2. **Documentar Hallazgos:**
   - ¿Qué dice la documentación local sobre base tributable?
   - ¿Qué dice sobre cálculo de impuesto único?
   - ¿Qué descuentos se restan de base tributable?

#### Paso 0.3.2: Investigar en Sitios Web Oficiales (10min)

**Tareas Obligatorias:**

1. **SII (Servicio de Impuestos Internos):**
   - **URL:** https://www.sii.cl
   - **Búsquedas Específicas:**
     - "base tributable impuesto único"
     - "cálculo impuesto único tramos"
     - "gratificación afecta base tributable"
     - "descuentos base tributable impuesto único"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

#### Paso 0.3.3: Validar con Normativa Específica (5min)

**Tareas Obligatorias:**

1. **Normativa sobre Impuesto Único:**
   - Buscar normativa sobre base tributable
   - Buscar sobre tramos de impuesto único
   - **Pregunta Crítica:** ¿Cómo se calcula base tributable correctamente según normativa?

#### Paso 0.3.4: Documentar Hallazgos (5min)

**Entregable Final Problema #3:**
- Archivo: `evidencias/investigacion_regulatoria_impuesto_unico.md`
- Mismo formato que Problema #1
- **Pregunta Crítica a Responder:** ¿Cómo se calcula base tributable correctamente según normativa?

---

### Problema #4: Línea HEALTH No Existe

**Tiempo Estimado:** 20min  
**Prioridad:** P2 - MEDIA

#### Paso 0.4.1: Consultar Documentación Local (5min)

**Tareas Obligatorias:**

1. **Buscar Referencias a Salud en Previred:**
   ```bash
   # Buscar referencias a salud en código
   grep -r "HEALTH\|SALUD\|FONASA\|ISAPRE\|salud" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   
   # Buscar referencias a Previred
   grep -r "Previred\|previred\|Book.*49" addons/localization/l10n_cl_hr_payroll/ --include="*.py" --include="*.md"
   ```

2. **Documentar Hallazgos:**
   - ¿Qué código usa el código actual para salud?
   - ¿Qué dice la documentación sobre formato Previred?

#### Paso 0.4.2: Investigar en Sitios Web Oficiales (10min)

**Tareas Obligatorias:**

1. **Previred:**
   - **URL:** https://www.previred.cl
   - **Búsquedas Específicas:**
     - "formato Book 49 códigos"
     - "salud código Book 49"
     - "formato Previred Book 49 especificación"
   - **Documentar:** URLs consultadas, citas específicas, conclusiones

#### Paso 0.4.3: Validar con Normativa Específica (5min)

**Tareas Obligatorias:**

1. **Especificación Técnica Previred:**
   - Buscar especificación técnica Book 49
   - Buscar códigos de salud
   - **Pregunta Crítica:** ¿Cuál es el código correcto para salud en Previred?

#### Paso 0.4.4: Documentar Hallazgos (5min)

**Entregable Final Problema #4:**
- Archivo: `evidencias/investigacion_regulatoria_health.md`
- Mismo formato que Problema #1
- **Pregunta Crítica a Responder:** ¿Cuál es el código correcto para salud en Previred?

---

## ✅ CRITERIOS DE VALIDACIÓN FASE 0

### Checklist Obligatorio Antes de Continuar

**Para cada problema investigado:**

- [ ] ¿Se consultó documentación local completa?
- [ ] ¿Se investigó en sitios web oficiales chilenos?
- [ ] ¿Se validó con normativa específica?
- [ ] ¿Se documentaron hallazgos con citas específicas?
- [ ] ¿Se generó archivo de investigación regulatoria?
- [ ] ¿Se respondió pregunta crítica con justificación completa?
- [ ] ¿Se incluyó recomendación técnica basada en normativa?
- [ ] ¿Se incluyeron referencias completas (URLs, normativa, documentación)?

**Si alguna respuesta es NO:** ⚠️ COMPLETAR antes de continuar.

---

## 📊 REPORTE DE PROGRESO FASE 0

### Al Finalizar Fase 0, Generar Reporte Consolidado

**Archivo:** `evidencias/fase0_investigacion_regulatoria_consolidado.md`

**Contenido:**
- Resumen ejecutivo de los 4 problemas investigados
- Respuestas a las 4 preguntas críticas
- Recomendaciones técnicas consolidadas
- Referencias completas
- Próximos pasos (Fase 1: Análisis Root Cause con Normativa)

---

## 🎯 PRÓXIMOS PASOS DESPUÉS DE FASE 0

### Fase 1: Análisis Root Cause con Normativa (1h)

**Solo DESPUÉS de completar Fase 0:**

1. **Re-analizar cada problema con normativa validada:**
   - Comparar implementación actual vs normativa validada
   - Identificar discrepancias específicas
   - Documentar root cause real basado en normativa

2. **Validar soluciones propuestas:**
   - ¿La solución propuesta cumple con normativa validada?
   - ¿Hay otras consideraciones normativas?
   - ¿La solución es completa según normativa?

### Fase 2: Implementación con Normativa Validada (1-1.5h)

**Solo DESPUÉS de completar Fase 0 y Fase 1:**

1. **Implementar soluciones validadas con normativa:**
   - Cada fix debe tener referencia a normativa
   - Código debe incluir comentarios con citas normativas
   - Validar que solución cumple con normativa

2. **Documentar decisiones normativas:**
   - Por qué se implementó de esta manera
   - Qué normativa lo respalda
   - Referencias específicas

### Fase 3: Validación Incremental (15min)

**Igual que antes, pero con validación normativa adicional:**

1. **Checkpoint DESPUÉS:**
   - Ejecutar tests
   - Validar que cálculos coinciden con normativa
   - Documentar evidencia

2. **Commit Estructurado con Referencias Normativas:**
   - Incluir referencias a normativa en commit
   - Incluir URLs de sitios web oficiales consultados
   - Incluir citas específicas de normativa

---

## ✅ CONCLUSIÓN Y RECOMENDACIÓN

### Estado Actual

**Reconocimiento del Agente:** ✅ EXCELENTE
- Entendió correctamente el problema de improvisación
- Se comprometió a seguir protocolo de investigación regulatoria
- Identificó correctamente las preguntas críticas
- Está listo para proceder con Fase 0

**Recomendación:**

**El agente DEBE:**

1. **INICIAR Fase 0: Investigación Regulatoria AHORA**
2. **Seguir protocolo paso a paso sin saltar ningún paso**
3. **Generar entregables completos para cada problema**
4. **NO implementar ningún fix hasta completar Fase 0**
5. **Validar cada solución con normativa antes de implementar**

**Tiempo Estimado Fase 0:** 1.5 horas (30min + 20min + 20min + 20min)

**Objetivo:** Asegurar que todas las soluciones cumplan con normativa chilena y no sean improvisaciones técnicas.

---

**FIN DEL PROMPT MASTER V5.12**

