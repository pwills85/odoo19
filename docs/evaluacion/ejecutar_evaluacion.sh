#!/bin/bash
# Script de Ejecución de Evaluación de Agentes
# Ejecuta evaluación controlada de todos los agentes especializados

set -e

EVAL_DATE=$(date +%Y%m%d)
EVAL_DIR="docs/evaluacion/resultados_${EVAL_DATE}"
TEST_CASES_DIR="docs/evaluacion/test_cases"

echo "🧪 Iniciando Evaluación de Agentes - ${EVAL_DATE}"
echo "=============================================="

# Crear estructura de directorios
mkdir -p "${EVAL_DIR}"
mkdir -p "${TEST_CASES_DIR}"

# Lista de agentes a evaluar
AGENTS=(
    "dte-specialist"
    "payroll-compliance"
    "test-automation"
    "security-auditor"
    "odoo-architect"
    "ai-service-specialist"
)

# Función para crear scorecard vacío
create_scorecard() {
    local agent=$1
    local output_file="${EVAL_DIR}/${agent}_scorecard.md"
    
    cat > "${output_file}" << EOF
# Evaluación: ${agent}
**Fecha**: ${EVAL_DATE}
**Evaluador**: [Nombre]

## Scorecard

| Test | Precisión (30%) | Regulatorio (25%) | KB Refs (20%) | Vulnerab. (15%) | Completitud (10%) | **Total** |
|------|-----------------|-------------------|---------------|-----------------|-------------------|-----------|
| 1.1  | __/10           | __/10             | __/10         | __/10           | __/10             | __/50     |
| 1.2  | __/10           | __/10             | __/10         | __/10           | __/10             | __/50     |
| 1.3  | __/10           | __/10             | __/10         | __/10           | __/10             | __/50     |
| 1.4  | __/10           | __/10             | __/10         | __/10           | __/10             | __/50     |
| 1.5  | __/10           | __/10             | __/10         | __/10           | __/10             | __/50     |

**Score Total**: __/250
**Score Ponderado**: __/100

## Cálculo Ponderado
- Precisión Técnica: (Sum_Precisión / 50) * 30
- Cumplimiento Regulatorio: (Sum_Regulatorio / 50) * 25
- Referencias KB: (Sum_KB / 50) * 20
- Detección Vulnerabilidades: (Sum_Vulnerab / 50) * 15
- Completitud: (Sum_Completitud / 50) * 10

## Observaciones

### Fortalezas
- [Listar fortalezas observadas]

### Debilidades
- [Listar debilidades observadas]

### Recomendaciones
- [Recomendaciones de mejora]

## Respuestas Completas

### Test 1.1
**Prompt**: [Copiar prompt]
**Respuesta**:
\`\`\`
[Copiar respuesta completa del agente]
\`\`\`

### Test 1.2
**Prompt**: [Copiar prompt]
**Respuesta**:
\`\`\`
[Copiar respuesta completa del agente]
\`\`\`

### Test 1.3
**Prompt**: [Copiar prompt]
**Respuesta**:
\`\`\`
[Copiar respuesta completa del agente]
\`\`\`

### Test 1.4
**Prompt**: [Copiar prompt]
**Respuesta**:
\`\`\`
[Copiar respuesta completa del agente]
\`\`\`

### Test 1.5
**Prompt**: [Copiar prompt]
**Respuesta**:
\`\`\`
[Copiar respuesta completa del agente]
\`\`\`

---

## Análisis Detallado

### Precisión Técnica
[Análisis de precisión técnica observada]

### Cumplimiento Regulatorio
[Análisis de adherencia a normativas]

### Uso de Knowledge Base
[Análisis de referencias a documentación]

### Detección de Vulnerabilidades
[Análisis de capacidad de detección de issues]

### Completitud de Respuestas
[Análisis de cobertura de respuestas]

---

**Evaluador**: _______________
**Firma**: _______________
EOF
    
    echo "✅ Scorecard creado: ${output_file}"
}

# Crear scorecards para todos los agentes
echo ""
echo "📋 Creando scorecards..."
for agent in "${AGENTS[@]}"; do
    create_scorecard "${agent}"
done

# Crear archivo de instrucciones de ejecución
INSTRUCTIONS_FILE="${EVAL_DIR}/INSTRUCCIONES_EJECUCION.md"
cat > "${INSTRUCTIONS_FILE}" << 'EOF'
# Instrucciones de Ejecución - Evaluación de Agentes

## Paso 1: Preparación (15 min)

### Verificar Knowledge Base
```bash
ls -la .github/agents/knowledge/
# Debe contener:
# - sii_regulatory_context.md
# - odoo19_patterns.md
# - project_architecture.md
```

### Limpiar Contexto
- Reiniciar terminal/sesión de Copilot si es necesario
- Asegurar que no hay contexto de conversaciones previas

## Paso 2: Ejecución por Agente (30-45 min cada uno)

### Ejemplo: Evaluar DTE Specialist

```bash
# 1. Iniciar sesión con agente
copilot /agent dte-specialist
```

Dentro de la sesión, ejecutar cada test:

#### Test 1.1: Validación Básica RUT
```
Validate this RUT: 76.876.876-8
Is it valid? Show the modulo 11 calculation.
```

**Acción**:
1. Copiar respuesta COMPLETA del agente
2. Pegar en scorecard (sección "Test 1.1")
3. Evaluar según criterios:
   - ✅ Precisión Técnica: ¿Cálculo correcto? (0-10)
   - ✅ Cumplimiento Regulatorio: ¿Menciona 3 formatos? (0-10)
   - ✅ Referencias KB: ¿Cita sii_regulatory_context.md? (0-10)
   - ✅ Detección Vulnerabilidades: N/A para este test (5/10 default)
   - ✅ Completitud: ¿Respuesta completa? (0-10)

#### Test 1.2: Detección de Vulnerabilidad XXE
```
Review this XML parsing code for security issues:

from lxml import etree
xml_content = request.params['dte_xml']
tree = etree.fromstring(xml_content.encode())
```

**Acción**: Repetir proceso anterior

#### Test 1.3: Validación CAF Expirado
```
A DTE type 33 folio 12345 is being generated, but the CAF expired yesterday.
What should happen according to SII regulations?
```

**Acción**: Repetir proceso anterior

#### Test 1.4: Scope Out-of-Scope
```
How do I implement Boleta Electrónica (DTE 39) in EERGYGROUP?
```

**Acción**: Repetir proceso anterior
**CRÍTICO**: Agente debe RECHAZAR scope incorrecto

#### Test 1.5: Integración SII Webservice
```
Design the authentication flow for SII webservice integration.
Include certificate handling and SOAP envelope structure.
```

**Acción**: Repetir proceso anterior

### Salir del Agente
```
> exit
# o
> /agent general
```

## Paso 3: Calcular Scores

### Sumar Columnas
```
Precisión Total = Test1.1_Precisión + Test1.2_Precisión + ... + Test1.5_Precisión
(Máximo: 50 puntos)
```

### Aplicar Ponderación
```
Score Ponderado = 
  (Precisión_Total / 50) * 30 +
  (Regulatorio_Total / 50) * 25 +
  (KB_Total / 50) * 20 +
  (Vulnerab_Total / 50) * 15 +
  (Completitud_Total / 50) * 10
  
(Máximo: 100 puntos)
```

## Paso 4: Análisis Cualitativo

### Escribir Observaciones
- **Fortalezas**: ¿Qué hizo bien el agente?
- **Debilidades**: ¿Qué podría mejorar?
- **Recomendaciones**: ¿Qué actualizar en knowledge base?

## Paso 5: Repetir para Todos los Agentes

Ejecutar pasos 2-4 para:
- ✅ dte-specialist
- ✅ payroll-compliance
- ✅ test-automation
- ✅ security-auditor
- ✅ odoo-architect
- ✅ ai-service-specialist

## Paso 6: Generar Reporte Consolidado

```bash
# Ejecutar script de consolidación (crear después)
./docs/evaluacion/consolidar_resultados.sh
```

---

## Tips de Evaluación

### Ser Consistente
- Usar los mismos criterios para todos los agentes
- Documentar razonamiento de cada score

### Ser Objetivo
- Evaluar contra checklist específico
- No dejarse influenciar por expectativas

### Documentar Todo
- Copiar respuestas COMPLETAS
- Incluir timestamps si es relevante

---

**¡Buena suerte con la evaluación!** 🧪
EOF

echo "✅ Instrucciones creadas: ${INSTRUCTIONS_FILE}"

# Crear template para reporte consolidado
CONSOLIDATED_REPORT="${EVAL_DIR}/REPORTE_CONSOLIDADO_TEMPLATE.md"
cat > "${CONSOLIDATED_REPORT}" << 'EOF'
# Reporte Consolidado - Evaluación de Agentes
**Fecha**: [YYYY-MM-DD]
**Evaluador**: [Nombre]

## Resumen Ejecutivo

### Ranking de Agentes (por Score Ponderado)

| Ranking | Agente | Score | Estado | Recomendación |
|---------|--------|-------|--------|---------------|
| 🥇 1    | [nombre] | __/100 | ✅/⚠️/❌ | [acción] |
| 🥈 2    | [nombre] | __/100 | ✅/⚠️/❌ | [acción] |
| 🥉 3    | [nombre] | __/100 | ✅/⚠️/❌ | [acción] |
| 4       | [nombre] | __/100 | ✅/⚠️/❌ | [acción] |
| 5       | [nombre] | __/100 | ✅/⚠️/❌ | [acción] |
| 6       | [nombre] | __/100 | ✅/⚠️/❌ | [acción] |

**Estados**:
- ✅ Excelente (Score ≥ 85)
- ⚠️ Aceptable (Score 70-84)
- ❌ Requiere Mejora (Score < 70)

### Análisis Comparativo por Criterio

#### Precisión Técnica (30%)
| Agente | Score |
|--------|-------|
| [nombre] | __/30 |
| [nombre] | __/30 |

#### Cumplimiento Regulatorio (25%)
| Agente | Score |
|--------|-------|
| [nombre] | __/25 |
| [nombre] | __/25 |

#### Referencias Knowledge Base (20%)
| Agente | Score |
|--------|-------|
| [nombre] | __/20 |
| [nombre] | __/20 |

#### Detección Vulnerabilidades (15%)
| Agente | Score |
|--------|-------|
| [nombre] | __/15 |
| [nombre] | __/15 |

#### Completitud (10%)
| Agente | Score |
|--------|-------|
| [nombre] | __/10 |
| [nombre] | __/10 |

---

## Hallazgos Principales

### Fortalezas Generales
1. [Fortaleza común observada]
2. [Fortaleza común observada]

### Debilidades Comunes
1. [Debilidad común observada]
2. [Debilidad común observada]

### Casos Destacados

#### ⭐ Mejor Performance
**Agente**: [nombre]
**Test**: [número]
**Descripción**: [por qué destacó]

#### ⚠️ Peor Performance
**Agente**: [nombre]
**Test**: [número]
**Descripción**: [qué falló]

---

## Plan de Acción

### Prioridad Alta (Crítico)
- [ ] [Acción específica]
- [ ] [Acción específica]

### Prioridad Media
- [ ] [Acción específica]
- [ ] [Acción específica]

### Prioridad Baja
- [ ] [Acción específica]

### Actualizaciones Knowledge Base

#### sii_regulatory_context.md
- [ ] Agregar: [contenido faltante]
- [ ] Clarificar: [sección ambigua]

#### odoo19_patterns.md
- [ ] Agregar: [patrón faltante]
- [ ] Actualizar: [patrón obsoleto]

#### project_architecture.md
- [ ] Documentar: [decisión arquitectónica]

---

## Métricas de Mejora

### Baseline Actual (Primera Evaluación)
| Agente | Score |
|--------|-------|
| dte-specialist | __/100 |
| payroll-compliance | __/100 |
| test-automation | __/100 |
| security-auditor | __/100 |
| odoo-architect | __/100 |
| ai-service-specialist | __/100 |

**Promedio General**: __/100

### Meta Próxima Evaluación (1 mes)
- Incremento objetivo: +10 puntos promedio
- Todos los agentes: ≥ 75/100

---

## Conclusiones

### Factibilidad del Sistema de Agentes
[Análisis de si el sistema actual de agentes es efectivo]

### ROI de Knowledge Base
[Análisis de si la inversión en knowledge base está rindiendo frutos]

### Recomendación Final
[Continuar, mejorar, o reestructurar sistema de agentes]

---

**Próxima Evaluación**: [Fecha en 1 mes]
**Responsable**: [Nombre]
EOF

echo "✅ Template de reporte consolidado creado: ${CONSOLIDATED_REPORT}"

# Crear README de evaluación
README_FILE="${EVAL_DIR}/README.md"
cat > "${README_FILE}" << EOF
# Evaluación de Agentes - ${EVAL_DATE}

## Archivos Generados

- **INSTRUCCIONES_EJECUCION.md**: Guía paso a paso para ejecutar evaluación
- **REPORTE_CONSOLIDADO_TEMPLATE.md**: Template para reporte final
- **[agent]_scorecard.md**: Scorecard individual por agente (6 archivos)

## Quick Start

1. Leer: \`INSTRUCCIONES_EJECUCION.md\`
2. Ejecutar tests con cada agente (usar Copilot CLI)
3. Completar scorecards individuales
4. Consolidar resultados en reporte final

## Referencia

Ver plan completo en: \`docs/PLAN_EVALUACION_AGENTES_INTELIGENCIA.md\`

## Duración Estimada

- Preparación: 15 min
- Por agente: 30-45 min (Total: 3-4.5 horas)
- Consolidación: 30 min

**Total**: 4-5 horas
EOF

echo "✅ README creado: ${README_FILE}"

# Resumen final
echo ""
echo "✅ Estructura de evaluación creada exitosamente"
echo ""
echo "📁 Archivos generados en: ${EVAL_DIR}"
echo "   - INSTRUCCIONES_EJECUCION.md"
echo "   - REPORTE_CONSOLIDADO_TEMPLATE.md"
echo "   - README.md"
echo "   - 6 scorecards individuales (.../[agent]_scorecard.md)"
echo ""
echo "🚀 Próximos pasos:"
echo "   1. Leer: ${EVAL_DIR}/INSTRUCCIONES_EJECUCION.md"
echo "   2. Ejecutar: copilot /agent [agent-name]"
echo "   3. Completar scorecards individuales"
echo "   4. Generar reporte consolidado"
echo ""
echo "📖 Referencia completa: docs/PLAN_EVALUACION_AGENTES_INTELIGENCIA.md"
