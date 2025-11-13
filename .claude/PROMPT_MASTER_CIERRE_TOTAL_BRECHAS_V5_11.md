# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (V5.11)
## Investigación Regulatoria Primero | Sin Improvisación | Calidad Enterprise

**Versión:** 5.11 (Investigación Regulatoria Primero - Sin Improvisación)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (TASK 2.1 bloqueado - requiere investigación regulatoria)  
**Base:** PROMPT V5.10 + Log Agente Líneas 894-1033 + Análisis de Improvisación  
**Progreso Actual:** 5.5 horas invertidas  
**Estado Real Validado:** 19 tests fallando (28 → 19 = -32% progreso acumulado ✅)

---

## ⚠️ ANÁLISIS CRÍTICO: DETECCIÓN DE IMPROVISACIÓN

### Evaluación del Trabajo Realizado (Calificación: 7/10)

**TASK 2.1 Estado Actual:** ⚠️ BLOQUEADO POR IMPROVISACIÓN

**Problemas Identificados:**

1. **❌ IMPROVISACIÓN DETECTADA:**
   - El agente implementó fixes sin investigar normativa chilena primero
   - Asumió que gratificación NO debe ser imponible sin verificar normativa
   - No consultó documentación regulatoria disponible
   - No investigó en sitios web oficiales chilenos

2. **❌ PROBLEMA ARQUITECTÓNICO NO RESUELTO:**
   - Cambió `GRAT_SOPA.imponible=False` pero tests siguen fallando
   - `total_imponible` todavía incluye ~7M adicionales
   - No investigó si hay otras líneas con `imponible=True` que causan el problema
   - No verificó si la gratificación según normativa chilena DEBE o NO ser imponible

3. **❌ FALTA DE INVESTIGACIÓN REGULATORIA:**
   - No consultó Art. 50 Código del Trabajo sobre gratificación
   - No consultó normativa SII sobre base imponible
   - No consultó documentación regulatoria local disponible
   - No investigó en sitios web oficiales chilenos

**Calificación Detallada:**

| Aspecto | Calificación | Comentario |
|---------|--------------|------------|
| **Análisis Root Cause** | 8/10 | Identificó problemas correctamente |
| **Implementación Técnica** | 7/10 | Implementó fixes pero sin validar normativa |
| **Investigación Regulatoria** | 2/10 | ❌ NO investigó normativa antes de implementar |
| **Documentación** | 6/10 | Documentó código pero no normativa |
| **Protocolo Seguido** | 5/10 | ❌ Improvisó en lugar de investigar primero |

**Conclusión:** El agente está improvisando soluciones técnicas sin entender completamente la normativa chilena. Esto es CRÍTICO y debe corregirse inmediatamente.

---

## 🚫 PRINCIPIO FUNDAMENTAL: SIN IMPROVISACIÓN - INVESTIGACIÓN REGULATORIA PRIMERO

### ⚠️ REGLA CRÍTICA #1: INVESTIGACIÓN REGULATORIA OBLIGATORIA

**ANTES de implementar CUALQUIER fix relacionado con:**
- Cálculos de nóminas (AFP, Salud, AFC, Impuesto Único, Gratificación)
- Base imponible vs base tributable
- Topes legales
- Porcentajes y tasas
- Validaciones funcionales

**OBLIGATORIO:**

1. **Investigar Documentación Regulatoria Local:**
   ```bash
   # Buscar documentación regulatoria disponible
   find . -name "*regulatory*.md" -o -name "*normativa*.md" -o -name "*sii*.md"
   ```

2. **Investigar en Sitios Web Oficiales Chilenos:**
   - **SII (Servicio de Impuestos Internos):** https://www.sii.cl
   - **DT (Dirección del Trabajo):** https://www.dt.gob.cl
   - **SP (Superintendencia de Pensiones):** https://www.spensiones.cl
   - **Previred:** https://www.previred.cl

3. **Consultar Normativa Específica:**
   - Código del Trabajo (Art. 50 sobre gratificación)
   - DFL 150 (Ley de AFP)
   - Ley 21.735 (Reforma Pensiones 2025)
   - Resoluciones SII sobre base imponible

4. **Validar con Conocimiento Base:**
   - `.claude/agents/knowledge/sii_regulatory_context.md`
   - Documentación regulatoria disponible en el proyecto

**PROHIBIDO:**
- ❌ Implementar fixes sin investigar normativa primero
- ❌ Asumir cómo funciona la normativa chilena
- ❌ Improvisar soluciones técnicas sin validar normativa
- ❌ Cambiar cálculos sin entender normativa completa

---

## 📚 FUENTES DE INVESTIGACIÓN REGULATORIA

### Documentación Regulatoria Local Disponible

**Rutas de Documentación:**
```
.claude/agents/knowledge/
├── sii_regulatory_context.md          # Contexto regulatorio SII y DTE
├── odoo19_patterns.md                  # Patrones Odoo 19 (técnico)
└── project_architecture.md             # Arquitectura del proyecto

docs/
├── regulatory/                         # Documentación regulatoria (si existe)
└── payroll-project/                    # Documentación de nóminas
```

**Archivos Críticos a Consultar:**
- `.claude/agents/knowledge/sii_regulatory_context.md` - Contexto regulatorio completo
- Documentación de normativa chilena en el proyecto
- Referencias a Art. 50 CT, DFL 150, Ley 21.735

### Sitios Web Oficiales Chilenos

**1. SII (Servicio de Impuestos Internos):**
- **URL:** https://www.sii.cl
- **Búsquedas Relevantes:**
  - "Base imponible AFP"
  - "Gratificación legal imponible"
  - "Base tributable impuesto único"
  - "DTE base imponible"

**2. DT (Dirección del Trabajo):**
- **URL:** https://www.dt.gob.cl
- **Búsquedas Relevantes:**
  - "Gratificación legal Art. 50"
  - "Gratificación imponible AFP"
  - "Base imponible previsional"
  - "Cálculo gratificación legal"

**3. SP (Superintendencia de Pensiones):**
- **URL:** https://www.spensiones.cl
- **Búsquedas Relevantes:**
  - "Tope imponible AFP"
  - "Base imponible AFP 2025"
  - "Gratificación afecta AFP"

**4. Previred:**
- **URL:** https://www.previred.cl
- **Búsquedas Relevantes:**
  - "Base imponible Previred"
  - "Gratificación en Previred"
  - "Formato Book 49"

### Normativa Específica a Consultar

**1. Código del Trabajo - Art. 50:**
- Gratificación legal: 25% utilidades líquidas
- Tope: 4.75 IMM
- Distribución proporcional
- **CRÍTICO:** ¿Gratificación es imponible para AFP/Salud?

**2. DFL 150 (Ley de AFP):**
- Base imponible AFP
- Tope imponible AFP (87.8 UF)
- **CRÍTICO:** ¿Qué conceptos afectan base imponible AFP?

**3. Ley 21.735 (Reforma Pensiones 2025):**
- Aporte empleador 1%
- Vigencia desde 01-08-2025
- **CRÍTICO:** ¿Cómo afecta a base imponible?

**4. Resoluciones SII:**
- Base imponible para impuesto único
- Base tributable
- **CRÍTICO:** ¿Gratificación afecta base tributable?

---

## 🔍 PROTOCOLO DE INVESTIGACIÓN REGULATORIA OBLIGATORIO

### Fase 0: Investigación Regulatoria (OBLIGATORIA ANTES DE IMPLEMENTAR)

**Para cada problema identificado, seguir este protocolo:**

#### Paso 0.1: Consultar Documentación Local (15min)

**Tareas:**
1. Leer `.claude/agents/knowledge/sii_regulatory_context.md` completo
2. Buscar documentación regulatoria en `docs/`
3. Buscar referencias a normativa específica en código existente
4. Documentar hallazgos en `evidencias/investigacion_regulatoria_[problema].md`

**Comandos:**
```bash
# Leer documentación regulatoria disponible
cat .claude/agents/knowledge/sii_regulatory_context.md

# Buscar referencias a normativa en código
grep -r "Art\.\|DFL\|Ley\|normativa\|regulatoria" addons/localization/l10n_cl_hr_payroll/

# Buscar documentación regulatoria
find . -name "*regulatory*.md" -o -name "*normativa*.md"
```

#### Paso 0.2: Investigar en Sitios Web Oficiales (30min)

**Tareas:**
1. Buscar en SII sobre base imponible y gratificación
2. Buscar en DT sobre gratificación legal Art. 50
3. Buscar en SP sobre base imponible AFP
4. Buscar en Previred sobre formato y base imponible
5. Documentar hallazgos con URLs y citas específicas

**Búsquedas Específicas para Problema #1 (total_imponible):**
- "Gratificación legal imponible AFP Chile"
- "Art. 50 Código del Trabajo gratificación base imponible"
- "Gratificación afecta base imponible AFP SII"
- "Base imponible AFP qué conceptos incluye"

**Búsquedas Específicas para Problema #2 (AFC tope):**
- "Tope AFC 120.2 UF Chile 2025"
- "Seguro de cesantía tope imponible"
- "AFC base imponible tope legal"

**Búsquedas Específicas para Problema #3 (Impuesto único):**
- "Base tributable impuesto único Chile"
- "Gratificación afecta base tributable impuesto único"
- "Cálculo base tributable impuesto único SII"

**Búsquedas Específicas para Problema #4 (HEALTH):**
- "Código salud Previred"
- "Formato Book 49 Previred salud"

#### Paso 0.3: Validar con Normativa Específica (15min)

**Tareas:**
1. Leer Art. 50 Código del Trabajo completo
2. Leer DFL 150 sobre base imponible AFP
3. Leer Ley 21.735 sobre reforma pensiones
4. Leer resoluciones SII relevantes
5. Documentar citas específicas con referencias

**Documentación a Consultar:**
- Art. 50 CT: Gratificación legal
- DFL 150: Base imponible AFP
- Ley 21.735: Reforma pensiones 2025
- Resoluciones SII: Base tributable impuesto único

#### Paso 0.4: Documentar Hallazgos (15min)

**Entregable Obligatorio:**
- Archivo: `evidencias/investigacion_regulatoria_[problema].md`
- Contenido:
  - Resumen ejecutivo de hallazgos
  - Citaciones específicas de normativa
  - URLs de sitios web oficiales consultados
  - Conclusiones sobre cómo debe funcionar según normativa
  - Referencias a artículos, leyes, resoluciones específicas

**Formato:**
```markdown
# Investigación Regulatoria: [Problema]

## Resumen Ejecutivo
- Hallazgo principal según normativa chilena
- Cómo debe funcionar según normativa

## Documentación Local Consultada
- Archivos consultados
- Hallazgos específicos

## Sitios Web Oficiales Consultados
- SII: [URL] - [Hallazgo]
- DT: [URL] - [Hallazgo]
- SP: [URL] - [Hallazgo]
- Previred: [URL] - [Hallazgo]

## Normativa Específica
- Art. 50 CT: [Cita específica]
- DFL 150: [Cita específica]
- Ley 21.735: [Cita específica]
- Resoluciones SII: [Cita específica]

## Conclusiones
- Cómo debe funcionar según normativa
- Qué cambios son necesarios
- Referencias específicas
```

---

## 📋 TASK 2.1 REINICIAR: PROTOCOLO CORREGIDO

### ⚠️ INSTRUCCIÓN CRÍTICA: REINICIAR CON INVESTIGACIÓN REGULATORIA

**El agente DEBE:**

1. **DETENER implementación actual**
2. **REINICIAR con Fase 0: Investigación Regulatoria**
3. **NO implementar ningún fix hasta completar investigación regulatoria**
4. **Validar cada solución propuesta con normativa chilena**

### Fase 0: Investigación Regulatoria (OBLIGATORIA - 1.5h)

#### Problema #1: total_imponible Mal Calculado

**Investigación Requerida:**

1. **Consultar Documentación Local (15min):**
   - Leer `.claude/agents/knowledge/sii_regulatory_context.md`
   - Buscar referencias a gratificación y base imponible
   - Buscar documentación sobre Art. 50 CT

2. **Investigar en Sitios Web Oficiales (30min):**
   - **SII:** Buscar "gratificación legal imponible AFP"
   - **DT:** Buscar "Art. 50 gratificación base imponible"
   - **SP:** Buscar "gratificación afecta base imponible AFP"
   - **Previred:** Buscar "gratificación formato Book 49"

3. **Validar con Normativa Específica (15min):**
   - Leer Art. 50 CT completo
   - Leer DFL 150 sobre base imponible AFP
   - Leer resoluciones SII sobre base imponible

4. **Documentar Hallazgos (15min):**
   - Generar `evidencias/investigacion_regulatoria_total_imponible.md`
   - Incluir citas específicas y URLs
   - Concluir: ¿Gratificación DEBE o NO ser imponible según normativa?

**Preguntas Críticas a Responder:**
- ¿La gratificación legal (Art. 50 CT) es imponible para AFP/Salud?
- ¿Qué conceptos DEBEN incluirse en base imponible AFP según DFL 150?
- ¿Qué dice SII sobre base imponible y gratificación?
- ¿Qué dice Previred sobre gratificación en formato Book 49?

#### Problema #2: AFC Sin Tope Aplicado

**Investigación Requerida:**

1. **Consultar Documentación Local (15min):**
   - Buscar referencias a AFC y tope 120.2 UF
   - Buscar documentación sobre seguro de cesantía

2. **Investigar en Sitios Web Oficiales (30min):**
   - **SP:** Buscar "tope AFC 120.2 UF"
   - **SII:** Buscar "seguro de cesantía tope imponible"
   - **Previred:** Buscar "AFC formato Book 49"

3. **Validar con Normativa Específica (15min):**
   - Leer normativa sobre seguro de cesantía
   - Leer resoluciones sobre tope AFC

4. **Documentar Hallazgos (15min):**
   - Generar `evidencias/investigacion_regulatoria_afc_tope.md`
   - Incluir citas específicas y URLs
   - Concluir: ¿Cuál es el tope correcto y cómo se aplica?

**Preguntas Críticas a Responder:**
- ¿Cuál es el tope legal AFC vigente en 2025?
- ¿El tope es 120.2 UF o diferente?
- ¿Cómo se aplica el tope: antes o después del cálculo?
- ¿Qué dice la normativa sobre cálculo AFC?

#### Problema #3: Impuesto Único Mal Calculado

**Investigación Requerida:**

1. **Consultar Documentación Local (15min):**
   - Buscar referencias a impuesto único y base tributable
   - Buscar documentación sobre cálculo impuesto único

2. **Investigar en Sitios Web Oficiales (30min):**
   - **SII:** Buscar "base tributable impuesto único"
   - **SII:** Buscar "cálculo impuesto único tramos"
   - **SII:** Buscar "gratificación afecta base tributable"

3. **Validar con Normativa Específica (15min):**
   - Leer normativa sobre impuesto único
   - Leer resoluciones SII sobre base tributable
   - Leer sobre tramos de impuesto único

4. **Documentar Hallazgos (15min):**
   - Generar `evidencias/investigacion_regulatoria_impuesto_unico.md`
   - Incluir citas específicas y URLs
   - Concluir: ¿Cómo se calcula base tributable correctamente?

**Preguntas Críticas a Responder:**
- ¿Qué conceptos DEBEN incluirse en base tributable?
- ¿La gratificación afecta base tributable?
- ¿Cómo se calculan los tramos de impuesto único?
- ¿Qué descuentos se restan de base tributable?

#### Problema #4: Línea HEALTH No Existe

**Investigación Requerida:**

1. **Consultar Documentación Local (15min):**
   - Buscar referencias a código salud en Previred
   - Buscar documentación sobre formato Book 49

2. **Investigar en Sitios Web Oficiales (30min):**
   - **Previred:** Buscar "formato Book 49 códigos"
   - **Previred:** Buscar "salud código Book 49"
   - **SII:** Buscar "formato Previred Book 49"

3. **Validar con Normativa Específica (15min):**
   - Leer especificación técnica Previred Book 49
   - Leer sobre códigos de salud

4. **Documentar Hallazgos (15min):**
   - Generar `evidencias/investigacion_regulatoria_health.md`
   - Incluir citas específicas y URLs
   - Concluir: ¿Cuál es el código correcto para salud?

**Preguntas Críticas a Responder:**
- ¿Cuál es el código correcto para salud en Previred?
- ¿Es 'HEALTH', 'SALUD', 'FONASA', 'ISAPRE'?
- ¿Qué dice la especificación técnica Previred?

---

### Fase 1: Análisis Root Cause con Normativa (1h)

**Solo DESPUÉS de completar Fase 0:**

1. **Re-analizar cada problema con normativa validada:**
   - Comparar implementación actual vs normativa
   - Identificar discrepancias
   - Documentar root cause real basado en normativa

2. **Validar soluciones propuestas:**
   - ¿La solución propuesta cumple con normativa?
   - ¿Hay otras consideraciones normativas?
   - ¿La solución es completa según normativa?

---

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

---

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

## 🎯 CRITERIOS DE VALIDACIÓN

### Antes de Implementar Cualquier Fix

**Checklist Obligatorio:**

- [ ] ¿Se consultó documentación regulatoria local?
- [ ] ¿Se investigó en sitios web oficiales chilenos?
- [ ] ¿Se validó con normativa específica (Art. 50 CT, DFL 150, Ley 21.735)?
- [ ] ¿Se documentaron hallazgos con citas específicas?
- [ ] ¿Se generó archivo de investigación regulatoria?
- [ ] ¿La solución propuesta cumple con normativa validada?
- [ ] ¿Se incluyen referencias normativas en código?

**Si alguna respuesta es NO:** ⚠️ DETENER e investigar primero.

---

## 📊 PROYECCIÓN ACTUALIZADA

### Tiempo Estimado con Investigación Regulatoria

| Fase | Tiempo | Descripción |
|------|--------|-------------|
| **Fase 0** | 1.5h | Investigación regulatoria obligatoria |
| **Fase 1** | 1h | Análisis root cause con normativa |
| **Fase 2** | 1-1.5h | Implementación con normativa validada |
| **Fase 3** | 15min | Validación incremental |
| **Total** | **3.75-4.25h** | Tiempo realista con investigación regulatoria |

**Tiempo Total TASK 2.1:** 3.75-4.25h (vs 2-3h original sin investigación)

---

## ✅ CONCLUSIÓN Y RECOMENDACIÓN

### Estado Actual

**Problema Crítico Identificado:**
- ❌ El agente está improvisando soluciones sin investigar normativa chilena
- ❌ Implementó fixes que pueden no cumplir con normativa
- ❌ No consultó documentación regulatoria disponible
- ❌ No investigó en sitios web oficiales chilenos

**Solución:**
- ✅ REINICIAR TASK 2.1 con Fase 0: Investigación Regulatoria
- ✅ NO implementar ningún fix hasta completar investigación
- ✅ Validar cada solución con normativa chilena
- ✅ Documentar todas las referencias normativas

### Recomendación

**El agente DEBE:**

1. **DETENER implementación actual**
2. **REINICIAR con Fase 0: Investigación Regulatoria**
3. **Seguir protocolo de investigación regulatoria obligatorio**
4. **NO implementar ningún fix hasta completar investigación**
5. **Validar cada solución con normativa chilena antes de implementar**

**Objetivo:** Asegurar que todas las soluciones cumplan con normativa chilena y no sean improvisaciones técnicas.

---

**FIN DEL PROMPT MASTER V5.11**

