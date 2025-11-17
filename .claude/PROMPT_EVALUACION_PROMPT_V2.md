# 🔍 PROMPT DE EVALUACIÓN: PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md

**Fecha Emisión:** 2025-11-09  
**Evaluador:** Agente Especializado (Odoo Dev / DTE Compliance / Test Automation / Docker DevOps)  
**Objetivo:** Evaluar calidad, completitud y viabilidad del PROMPT V2  
**Archivo a Evaluar:** `.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md`  
**Contexto:** Prompt maestro para cierre total de brechas identificadas en auditorías Odoo 19 CE

---

## 🎯 INSTRUCCIONES PARA EL AGENTE EVALUADOR

**IMPORTANTE**: Este es un ejercicio de evaluación de calidad de un PROMPT de trabajo. Debes:
1. ✅ Leer completamente el PROMPT V2 antes de evaluar
2. ✅ Aplicar criterios objetivos y medibles
3. ✅ Proporcionar evidencia concreta (referencias a secciones específicas)
4. ✅ Distinguir entre problemas críticos vs mejoras sugeridas
5. ✅ Considerar viabilidad práctica de ejecución
6. ✅ Evaluar alineación con máximas establecidas

**CONTEXTO DEL PROYECTO**:
- Módulos custom Odoo 19 CE: `l10n_cl_dte`, `l10n_cl_hr_payroll`, `l10n_cl_financial_reports`
- Hallazgos validados: 10 brechas (3 P0, 6 P1, 1 P2)
- Máximas establecidas: `docs/prompts_desarrollo/MAXIMAS_AUDITORIA.md`, `MAXIMAS_DESARROLLO.md`
- Agentes especializados: 5 agentes configurados en `.claude/agents/`

---

## 📋 TAREA DE EVALUACIÓN

### Objetivo

Evaluar la calidad, completitud, claridad y viabilidad del PROMPT V2 para cierre total de brechas, identificando:
1. **Fortalezas** del prompt (qué está bien hecho)
2. **Debilidades** del prompt (qué puede mejorarse)
3. **Problemas críticos** (qué bloquea o dificulta la ejecución)
4. **Oportunidades de mejora** (sugerencias concretas)
5. **Alineación con máximas** (cumplimiento de estándares establecidos)

### Archivo a Evaluar

**Ruta:** `.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V2.md`

**Leer completamente antes de evaluar.**

---

## 📊 CRITERIOS DE EVALUACIÓN

### 1. Estructura y Organización (20%)

**Sub-criterios:**
- ✅ Claridad de secciones y organización lógica
- ✅ Flujo de información coherente
- ✅ Navegabilidad y facilidad de referencia
- ✅ Consistencia en formato y estilo

**Preguntas a responder:**
- ¿El prompt está bien estructurado?
- ¿Es fácil encontrar información específica?
- ¿Las secciones están ordenadas lógicamente?
- ¿Hay redundancias o información duplicada?

**Escala:** 1-10 (10 = Excelente estructura)

---

### 2. Claridad y Precisión de Instrucciones (25%)

**Sub-criterios:**
- ✅ Instrucciones claras y sin ambigüedades
- ✅ Ejemplos de código precisos y ejecutables
- ✅ Comandos bash correctos y probados
- ✅ Referencias a archivos y líneas específicas

**Preguntas a responder:**
- ¿Las instrucciones son claras para un agente?
- ¿Los ejemplos de código son correctos?
- ¿Los comandos bash funcionarían sin modificación?
- ¿Las referencias a archivos son precisas?

**Escala:** 1-10 (10 = Instrucciones perfectamente claras)

---

### 3. Completitud (20%)

**Sub-criterios:**
- ✅ Todos los SPRINTS están completos (0-5)
- ✅ Todas las TASKS están detalladas
- ✅ DoD (Definition of Done) definido para cada sprint
- ✅ Tests requeridos especificados
- ✅ Commits estructurados incluidos

**Preguntas a responder:**
- ¿Faltan SPRINTS o TASKS?
- ¿Están todos los DoD definidos?
- ¿Faltan tests o validaciones?
- ¿Hay información incompleta?

**Escala:** 1-10 (10 = 100% completo)

---

### 4. Viabilidad Técnica (15%)

**Sub-criterios:**
- ✅ Soluciones propuestas son técnicamente viables
- ✅ Código de ejemplo es correcto para Odoo 19 CE
- ✅ Scripts bash son ejecutables
- ✅ Dependencias y pre-requisitos están claros
- ✅ Orden de ejecución es lógico

**Preguntas a responder:**
- ¿Las soluciones propuestas funcionarían en Odoo 19 CE?
- ¿El código de ejemplo es correcto?
- ¿Los scripts bash tienen errores?
- ¿Faltan dependencias o pre-requisitos?

**Escala:** 1-10 (10 = Totalmente viable técnicamente)

---

### 5. Alineación con Máximas (10%)

**Sub-criterios:**
- ✅ Referencias explícitas a máximas establecidas
- ✅ Cumplimiento con MAXIMAS_AUDITORIA.md
- ✅ Cumplimiento con MAXIMAS_DESARROLLO.md
- ✅ Cumplimiento con CONTEXTO_GLOBAL_MODULOS.md

**Preguntas a responder:**
- ¿El prompt referencia las máximas establecidas?
- ¿Las soluciones cumplen con las máximas?
- ¿Hay violaciones de máximas en el prompt?

**Escala:** 1-10 (10 = Perfecta alineación)

---

### 6. Manejo de Errores y Robustez (10%)

**Sub-criterios:**
- ✅ Validación de pre-requisitos incluida
- ✅ Procedimientos de rollback definidos
- ✅ Manejo de errores por tipo
- ✅ Plan de contingencia incluido

**Preguntas a responder:**
- ¿Hay validación de pre-requisitos?
- ¿Existe procedimiento de rollback?
- ¿Se manejan diferentes tipos de errores?
- ¿Hay plan de contingencia?

**Escala:** 1-10 (10 = Manejo de errores excelente)

---

## 📊 FORMATO DEL REPORTE DE EVALUACIÓN

### 1. Resumen Ejecutivo

**Calificación General:** X.X/10 - [CALIFICACIÓN VERBAL]

**Desglose de Calificación:**

| Criterio | Peso | Puntos Obtenidos | Calificación | Comentario Breve |
|----------|------|------------------|-------------|------------------|
| Estructura y Organización | 20% | X.X/10 | **X.X** | [Comentario] |
| Claridad y Precisión | 25% | X.X/10 | **X.X** | [Comentario] |
| Completitud | 20% | X.X/10 | **X.X** | [Comentario] |
| Viabilidad Técnica | 15% | X.X/10 | **X.X** | [Comentario] |
| Alineación con Máximas | 10% | X.X/10 | **X.X** | [Comentario] |
| Manejo de Errores | 10% | X.X/10 | **X.X** | [Comentario] |

**Calificación Ponderada Final:** X.X/10

---

### 2. Fortalezas Identificadas

**Listar las fortalezas principales del prompt:**

1. **Fortaleza #1**: [Descripción]
   - **Evidencia**: Referencia específica (ej: "SPRINT 3, TASK 3.1, línea X")
   - **Impacto**: Alto/Medio/Bajo

2. **Fortaleza #2**: [Descripción]
   - **Evidencia**: [Referencia]
   - **Impacto**: [Alto/Medio/Bajo]

[... continuar con todas las fortalezas identificadas ...]

---

### 3. Debilidades Identificadas

**Listar las debilidades principales del prompt:**

1. **Debilidad #1**: [Descripción]
   - **Evidencia**: Referencia específica (ej: "SPRINT 4, TASK 4.2, línea X")
   - **Impacto**: Alto/Medio/Bajo
   - **Sugerencia de Mejora**: [Sugerencia concreta]

2. **Debilidad #2**: [Descripción]
   - **Evidencia**: [Referencia]
   - **Impacto**: [Alto/Medio/Bajo]
   - **Sugerencia de Mejora**: [Sugerencia]

[... continuar con todas las debilidades identificadas ...]

---

### 4. Problemas Críticos (Bloqueantes)

**Listar problemas que bloquean o dificultan significativamente la ejecución:**

1. **Problema Crítico #1**: [Descripción]
   - **Evidencia**: Referencia específica
   - **Impacto**: 🔴 CRÍTICO - Bloquea ejecución
   - **Solución Propuesta**: [Solución concreta]

2. **Problema Crítico #2**: [Descripción]
   - **Evidencia**: [Referencia]
   - **Impacto**: 🔴 CRÍTICO
   - **Solución Propuesta**: [Solución]

[... continuar con todos los problemas críticos ...]

---

### 5. Análisis Detallado por Criterio

#### 5.1 Estructura y Organización

**Calificación:** X.X/10

**Análisis:**
- [Análisis detallado de la estructura]
- [Fortalezas específicas]
- [Debilidades específicas]
- [Referencias a secciones específicas]

**Ejemplos de Evidencia:**
- ✅ Fortaleza: "SPRINT 0 claramente definido con 6 tasks numeradas"
- ⚠️ Debilidad: "SPRINT 1-2 referencian prompt original sin incluir contenido"

---

#### 5.2 Claridad y Precisión de Instrucciones

**Calificación:** X.X/10

**Análisis:**
- [Análisis detallado de claridad]
- [Ejemplos de código evaluados]
- [Comandos bash verificados]
- [Referencias a archivos verificadas]

**Ejemplos de Evidencia:**
- ✅ Fortaleza: "Código Python en TASK 3.1 es sintácticamente correcto"
- ⚠️ Debilidad: "Comando bash en línea X tiene error de sintaxis: [error específico]"

---

#### 5.3 Completitud

**Calificación:** X.X/10

**Análisis:**
- [Verificación de SPRINTS completos]
- [Verificación de TASKS completas]
- [Verificación de DoD]
- [Verificación de tests]

**Checklist de Completitud:**

| Elemento | Estado | Notas |
|----------|--------|-------|
| SPRINT 0 | ✅ Completo / ⚠️ Incompleto | [Notas] |
| SPRINT 1 | ✅ Completo / ⚠️ Incompleto | [Notas] |
| SPRINT 2 | ✅ Completo / ⚠️ Incompleto | [Notas] |
| SPRINT 3 | ✅ Completo / ⚠️ Incompleto | [Notas] |
| SPRINT 4 | ✅ Completo / ⚠️ Incompleto | [Notas] |
| SPRINT 5 | ✅ Completo / ⚠️ Incompleto | [Notas] |
| Validación Pre-requisitos | ✅ Completo / ⚠️ Incompleto | [Notas] |
| Manejo de Errores | ✅ Completo / ⚠️ Incompleto | [Notas] |
| Consolidación Final | ✅ Completo / ⚠️ Incompleto | [Notas] |

---

#### 5.4 Viabilidad Técnica

**Calificación:** X.X/10

**Análisis:**
- [Evaluación técnica de soluciones]
- [Verificación de código Odoo 19 CE]
- [Verificación de scripts bash]
- [Verificación de dependencias]

**Ejemplos de Verificación Técnica:**

1. **Código Python - TASK 3.1 (rut_helper.py)**:
   - ✅ Sintaxis correcta
   - ✅ Imports válidos
   - ✅ Lógica de módulo 11 correcta
   - ⚠️ [Si hay problema]: [Descripción del problema]

2. **Script Bash - SPRINT 0 (backup)**:
   - ✅ Comando `pg_dump` correcto
   - ✅ Variables de entorno bien usadas
   - ⚠️ [Si hay problema]: [Descripción]

---

#### 5.5 Alineación con Máximas

**Calificación:** X.X/10

**Análisis:**
- [Verificación de referencias a máximas]
- [Cumplimiento con MAXIMAS_AUDITORIA.md]
- [Cumplimiento con MAXIMAS_DESARROLLO.md]
- [Cumplimiento con CONTEXTO_GLOBAL_MODULOS.md]

**Checklist de Máximas:**

| Máxima | Referenciada | Cumplida | Evidencia |
|--------|--------------|-----------|-----------|
| Correctitud Legal | ✅ / ❌ | ✅ / ❌ | [Referencia] |
| Arquitectura Pure Python | ✅ / ❌ | ✅ / ❌ | [Referencia] |
| Testing Completo | ✅ / ❌ | ✅ / ❌ | [Referencia] |
| Integración Odoo 19 CE | ✅ / ❌ | ✅ / ❌ | [Referencia] |
| ... | ... | ... | ... |

---

#### 5.6 Manejo de Errores y Robustez

**Calificación:** X.X/10

**Análisis:**
- [Evaluación de validación pre-requisitos]
- [Evaluación de procedimientos rollback]
- [Evaluación de manejo de errores]
- [Evaluación de plan de contingencia]

**Checklist de Robustez:**

| Elemento | Estado | Calidad | Notas |
|----------|--------|---------|-------|
| Script validate_prerequisites.sh | ✅ / ❌ | Alta/Media/Baja | [Notas] |
| Script rollback_sprint.sh | ✅ / ❌ | Alta/Media/Baja | [Notas] |
| Manejo Error Tipo 1 (Tests) | ✅ / ❌ | Alta/Media/Baja | [Notas] |
| Manejo Error Tipo 2 (Instalación) | ✅ / ❌ | Alta/Media/Baja | [Notas] |
| Manejo Error Tipo 3 (DB Corrupta) | ✅ / ❌ | Alta/Media/Baja | [Notas] |
| Plan de Contingencia | ✅ / ❌ | Alta/Media/Baja | [Notas] |

---

### 6. Oportunidades de Mejora

**Listar sugerencias concretas de mejora:**

1. **Mejora #1**: [Descripción]
   - **Prioridad**: Alta/Media/Baja
   - **Esfuerzo**: Alto/Medio/Bajo
   - **Impacto Esperado**: [Descripción]
   - **Implementación Sugerida**: [Pasos concretos]

2. **Mejora #2**: [Descripción]
   - **Prioridad**: [Alta/Media/Baja]
   - **Esfuerzo**: [Alto/Medio/Bajo]
   - **Impacto Esperado**: [Descripción]
   - **Implementación Sugerida**: [Pasos]

[... continuar con todas las mejoras sugeridas ...]

---

### 7. Comparación con Prompt Original (V1)

**Si tienes acceso al prompt original, compara:**

| Aspecto | Prompt V1 | Prompt V2 | Mejora |
|---------|-----------|-----------|--------|
| SPRINTS Completos | X/5 | X/5 | +X |
| Validación Pre-requisitos | ✅ / ❌ | ✅ / ❌ | [Mejora] |
| Manejo de Errores | ✅ / ❌ | ✅ / ❌ | [Mejora] |
| Paths Dinámicos | ✅ / ❌ | ✅ / ❌ | [Mejora] |
| Consolidación Final | ✅ / ❌ | ✅ / ❌ | [Mejora] |
| Calificación General | X.X/10 | X.X/10 | +X.X |

---

### 8. Recomendaciones Finales

**Recomendación Principal:**

[Recomendación principal basada en la evaluación]

**Recomendaciones Secundarias:**

1. [Recomendación 1]
2. [Recomendación 2]
3. [Recomendación 3]

**Veredicto Final:**

- ✅ **APROBADO SIN CAMBIOS**: El prompt está listo para ejecución
- ⚠️ **APROBADO CON MEJORAS MENORES**: El prompt es ejecutable pero requiere mejoras
- ❌ **NO APROBADO - REQUIERE CAMBIOS**: El prompt tiene problemas críticos que deben resolverse

---

## 🎯 CRITERIOS DE EVALUACIÓN ESPECÍFICOS

### Verificaciones Técnicas Obligatorias

**Debes verificar:**

1. ✅ **Sintaxis de código Python**: ¿Todos los ejemplos de código Python son sintácticamente correctos?
2. ✅ **Sintaxis de scripts Bash**: ¿Todos los scripts bash son ejecutables?
3. ✅ **Referencias a archivos**: ¿Las rutas de archivos son correctas?
4. ✅ **Referencias a líneas**: ¿Las referencias a líneas específicas son precisas?
5. ✅ **Comandos Docker**: ¿Los comandos docker son correctos para el entorno?
6. ✅ **Variables de entorno**: ¿Las variables de entorno están bien definidas?
7. ✅ **Dependencias**: ¿Se mencionan todas las dependencias necesarias?
8. ✅ **Tests**: ¿Los tests propuestos son ejecutables?

### Verificaciones de Contenido Obligatorias

**Debes verificar:**

1. ✅ **SPRINTS completos**: ¿Todos los SPRINTS 0-5 están completos?
2. ✅ **TASKS completas**: ¿Todas las TASKS tienen implementación detallada?
3. ✅ **DoD definido**: ¿Cada SPRINT tiene DoD claro?
4. ✅ **Tests especificados**: ¿Cada TASK tiene tests propuestos?
5. ✅ **Commits estructurados**: ¿Cada SPRINT tiene commit estructurado?
6. ✅ **Validación pre-requisitos**: ¿Existe script de validación?
7. ✅ **Manejo de errores**: ¿Existen procedimientos de rollback?
8. ✅ **Consolidación final**: ¿Existe script de validación final?

---

## ⚠️ RESTRICCIONES

- ❌ NO modifiques el PROMPT V2 (solo evalúa)
- ❌ NO asumas funcionalidades que no están documentadas
- ✅ SOLO evalúa y reporta
- ✅ PROPORCIONA evidencia concreta (referencias específicas)
- ✅ DISTINGUE entre problemas críticos vs mejoras sugeridas

---

## 📝 INSTRUCCIONES FINALES

1. **Lee completamente** el PROMPT V2 antes de evaluar
2. **Aplica criterios objetivos** y medibles
3. **Proporciona evidencia concreta** para cada hallazgo
4. **Genera el reporte completo** siguiendo el formato especificado
5. **Guarda el reporte** como `EVALUACION_PROMPT_V2_[NOMBRE_AGENTE]_[FECHA].md`

---

## 🚀 COMENZAR EVALUACIÓN

**HORA DE INICIO**: [Registra aquí]

Procede con la evaluación completa del PROMPT V2 siguiendo todos los criterios y formato especificados.

---

**Nota**: Este prompt está diseñado para evaluar la calidad del PROMPT V2 como herramienta de trabajo. La evaluación debe ser objetiva, basada en evidencia concreta, y proporcionar recomendaciones accionables.

