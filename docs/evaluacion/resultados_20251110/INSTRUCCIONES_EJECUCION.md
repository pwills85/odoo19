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
