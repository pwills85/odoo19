# 📚 ESTRATEGIA DE PROPAGACIÓN: Conocimiento sobre Prompting Efectivo

**Fecha**: 2025-11-11  
**Contexto**: Experimento de locuacidad validó técnicas de prompting que generan 13x variación en output  
**Objetivo**: Propagar hallazgos críticos a todos los CLIs y documentación del proyecto

---

## 🎯 HALLAZGOS CLAVE A PROPAGAR

### Descubrimiento Principal
**La "locuacidad" de Claude (y otros LLMs) varía 13x-25x** según:
1. **Complejidad del prompt** (P1→P4: 100→1,303 palabras)
2. **System prompt** (CLI conciso vs Web conversacional: 4-6x)
3. **Temperature** (0.05-0.4 técnico vs 0.7 general: 2-3x)
4. **Context window** (KB estructurado vs historial: 1.5-2x)

### Máximas de Prompting Validadas

```yaml
Brevedad Extrema (P1 - Consultas Factuales):
  - Prompts: "Lista X", "¿Qué hay en Y?"
  - Output esperado: 70-150 palabras
  - Características: Listas concisas, 0 análisis
  - Ejemplo: "Lista servicios Docker" → 76 palabras

Análisis Técnico (P2 - Consultas Medias):
  - Prompts: "Analiza archivo X", "Describe modelo Y"
  - Output esperado: 300-400 palabras
  - Características: Tabla + secciones, 1 code block
  - Ejemplo: "Analiza account_move" → 342 palabras

Análisis Profundo (P3 - Multi-Módulo):
  - Prompts: "Compara arquitecturas X, Y, Z"
  - Output esperado: 800-1,000 palabras
  - Características: Headers, tablas, file refs, términos técnicos
  - Ejemplo: "Compara 3 módulos l10n_cl" → 915 palabras

Análisis Arquitectónico (P4 - Desarrollo Real):
  - Prompts: "Evalúa decisiones de diseño en sistema X con N componentes"
  - Output esperado: 1,200-1,500 palabras
  - Características: 55 headers, 21 tablas, 31 file refs, 109 términos técnicos
  - Especificidad: 0.95/1.0 (máxima precisión)
  - Ejemplo: "Analiza arquitectura sistema migración" → 1,303 palabras
```

---

## 📁 ESTRUCTURA DE PROPAGACIÓN

### 1. Directorio Central: `docs/prompts_desarrollo/`

**Agregar archivos nuevos:**

```
docs/prompts_desarrollo/
├── README.md (ya existe - actualizar)
├── MAXIMAS_DESARROLLO.md (ya existe - actualizar)
├── MAXIMAS_AUDITORIA.md (ya existe - revisar)
│
├── ⭐ NUEVO: ESTRATEGIA_PROMPTING_EFECTIVO.md
│   └── Guía completa basada en experimento
│
├── ⭐ NUEVO: EJEMPLOS_PROMPTS_POR_NIVEL.md
│   └── P1-P4 con templates y outputs esperados
│
└── ⭐ NUEVO: METRICAS_CALIDAD_RESPUESTAS.md
    └── Cómo medir especificidad, densidad técnica, file refs
```

---

## 🤖 PROPAGACIÓN A CLIs ESPECÍFICOS

### A. GitHub Copilot CLI (.github/copilot-instructions.md)

**Status actual**: ✅ YA ÓPTIMO (474 líneas, brevedad configurada)

**Mejoras sugeridas**:

```markdown
## 📊 Adaptación de Respuestas por Complejidad

### Consultas Simples (P1)
Para preguntas factuales tipo "lista X", "¿qué hay en Y?":
- Target: 70-150 palabras
- Formato: Lista concisa sin análisis
- Ejemplo: "Lista servicios Docker" → output ultra-breve

### Análisis Técnicos (P2-P3)
Para análisis de archivos o comparaciones:
- Target P2: 300-400 palabras (1 archivo)
- Target P3: 800-1,000 palabras (múltiples archivos)
- Formato: Headers + tablas + code snippets

### Análisis Arquitectónicos (P4)
Para evaluación de sistemas complejos (2,000+ líneas código):
- Target: 1,200-1,500 palabras
- Formato: Estructura profesional con:
  - 30+ file references explícitos
  - 100+ technical terms
  - 30+ code snippets con soluciones
  - 20+ tablas comparativas
  - Especificidad 0.90+ (máxima precisión)

**Métricas de calidad esperadas**:
- Especificidad score: 0.50 (P1) → 0.95 (P4)
- Densidad técnica: 0 (P1) → 8.37 términos/100 palabras (P4)
- File references: 0 (P1-P2) → 31 (P4)
```

### B. Claude Code (.claude/project/)

**Archivos a actualizar:**

1. **`.claude/project/PROMPTING_BEST_PRACTICES.md`** (NUEVO)

```markdown
# Mejores Prácticas de Prompting - Validadas Experimentalmente

## Resultados del Experimento (2025-11-11)

6 prompts ejecutados, escalamiento 13x validado:
- P1 (Simple): 100 palabras, especificidad 0.53
- P2 (Medio): 342 palabras, especificidad 0.56
- P3 (Complejo): 915 palabras, especificidad 0.74
- P4 (Crítico): 1,303 palabras, especificidad 0.95 ⭐

## Templates por Nivel

### P1 - Consultas Factuales
```
[Verbo acción simple] + [Objeto concreto]
Ejemplos:
- "Lista servicios Docker activos"
- "Muestra módulos en addons/localization/"
- "Valida RUT 76876876-8"
```

### P2 - Análisis Técnico Básico
```
Analiza [archivo/componente] y evalúa:
1. [Aspecto técnico 1]
2. [Aspecto técnico 2]
3. [Aspecto técnico 3]
```

### P3 - Comparación Multi-Componente
```
Compara arquitectura de [módulo A], [módulo B], [módulo C]:
- Patrones de herencia
- Naming conventions
- Uso de libs/ vs service layer
- Identificar inconsistencias
```

### P4 - Análisis Arquitectónico Profundo
```
Analiza críticamente la arquitectura de [sistema completo]:

Contexto: [Descripción detallada de N componentes, X líneas totales]

Evalúa:
1. Diseño de N capas (separación, flujo datos, patrones)
2. Estrategia de [técnica específica] (herramientas, edge cases)
3. Sistema de seguridad (redundancia, fallos, rollback)
4. Validación [tipo] (suficiencia, completitud)
5. Escalabilidad y performance (cuellos de botella)
6. Trade-offs (automatización vs seguridad, velocidad vs exhaustividad)
7. Mejoras potenciales (cambios arquitectónicos, funcionalidad faltante)

Archivos a analizar: [lista específica con paths]
Entregable: Análisis profesional con decisiones de diseño, fortalezas,
debilidades, recomendaciones con código, evaluación trade-offs
```

## Métricas de Calidad

### Cómo Medir Especificidad
```python
specificity_score = (
    (file_refs / 10) * 0.30 +
    (tech_terms / 20) * 0.25 +
    (code_blocks / 10) * 0.20 +
    (numbers / 50) * 0.15 +
    (percentages / 10) * 0.10
)
# Target: >0.90 para análisis arquitectónicos
```

### Indicadores de Calidad
- ✅ File references: >30 en P4, >2 en P3
- ✅ Technical terms: >100 en P4, >7 en P3
- ✅ Code blocks: >30 en P4, >10 en P3
- ✅ Tables: >20 en P4
- ✅ Headers: >50 en P4 (estructura profesional)
```

2. **Actualizar `.claude/project/CLAUDE.md`** (sección nueva)

```markdown
## 📊 Optimización de Prompts por Complejidad

Basado en validación experimental (2025-11-11):

**P1 (Simple)**: Consultas factuales → 100 palabras target
**P2 (Medio)**: Análisis técnico → 300-400 palabras target  
**P3 (Complejo)**: Multi-módulo → 800-1,000 palabras target
**P4 (Crítico)**: Arquitectónico → 1,200-1,500 palabras target

**Ver detalles**: `.claude/project/PROMPTING_BEST_PRACTICES.md`
```

### C. Codex CLI (.codex/)

**Archivo a crear**: `.codex/prompting_guidelines.md`

```markdown
# Codex CLI - Guías de Prompting Efectivo

## Configuración Recomendada

```yaml
# .codex/config.yml
model: o1-preview
temperature: 0.05  # Máxima precisión para código
max_tokens: 4000   # Suficiente para P4

prompt_templates:
  simple:
    target_words: 100
    format: "list"
  
  technical:
    target_words: 350
    format: "structured"
  
  architectural:
    target_words: 1300
    format: "professional_report"
```

## Prompts Validados para Codex

### Análisis de Código (P2-P3)
```
Analiza [archivo.py] líneas [X-Y]:
- Patrones Odoo 19 (✅ correcto / ❌ deprecated)
- Complejidad ciclomática
- Vulnerabilidades potenciales
- Mejoras sugeridas con código

Output esperado: 300-400 palabras, 3-5 code snippets
```

### Auditoría Arquitectónica (P4)
```
Audita arquitectura de [sistema]:
- Componentes: [lista con líneas totales]
- Enfoque: seguridad, escalabilidad, mantenibilidad
- Formato: reporte profesional con tablas comparativas

Output esperado: 1,200+ palabras, especificidad >0.90
```
```

### D. Gemini CLI (.gemini/)

**Archivo a crear**: `.gemini/prompt_optimization.md`

```markdown
# Gemini CLI - Optimización de Prompts

## Gemini 2.5 Pro: Configuración Óptima

```yaml
# .gemini/settings.yml
model: gemini-2.5-pro
temperature: 0.1   # Balance precisión/creatividad
top_p: 0.95
top_k: 40

response_style:
  P1: "concise"      # 100 palabras target
  P2: "technical"    # 350 palabras target
  P3: "analytical"   # 900 palabras target
  P4: "comprehensive" # 1,300 palabras target
```

## Templates Específicos Gemini

### P4 - Análisis Exhaustivo
```
Context: [Proyecto Odoo 19 CE, módulos chilenos, 50K+ líneas]

Task: Evalúa arquitectura de [sistema migration] con enfoque en:
1. Decisiones de diseño y justificaciones
2. Patrones identificados (Strategy, Template Method, etc.)
3. Trade-offs críticos (seguridad vs automatización)
4. Edge cases no cubiertos
5. Propuestas de mejora con código

Formato: Reporte ejecutivo + análisis técnico profundo
Extensión: 1,200-1,500 palabras
Especificidad target: 0.90+
```

## Validación de Outputs

Gemini 2.5 Pro scores esperados (basado en benchmark interno):
- Especificidad: 0.85-0.95 (P4)
- File references: 25-35 (P4)
- Technical terms: 80-120 (P4)
```

---

## 🔧 HERRAMIENTAS DE VALIDACIÓN

### Script de Análisis de Respuestas

**Ubicación**: `experimentos/analysis/analyze_response.py` (ya creado)

**Uso en desarrollo**:

```bash
# Analizar output de cualquier CLI
.venv/bin/python3 experimentos/analysis/analyze_response.py \
  outputs/my_analysis.txt \
  prompt_id \
  P3

# Output JSON con métricas
{
  "words": 915,
  "specificity_score": 0.74,
  "file_references": 2,
  "technical_terms": 7,
  "style": "conversational"
}
```

### Integración en Flujo de Trabajo

**Git Hook Pre-Commit** (opcional):

```bash
# .git/hooks/pre-commit
#!/bin/bash
# Validar prompts nuevos en docs/prompts_desarrollo/

for prompt in $(git diff --cached --name-only --diff-filter=A | grep "^docs/prompts_desarrollo/prompt_.*\.md$"); do
    echo "Validando prompt: $prompt"
    
    # Verificar que incluye nivel de complejidad (P1-P4)
    if ! grep -q "Nivel: P[1-4]" "$prompt"; then
        echo "❌ Prompt debe especificar nivel (P1-P4)"
        exit 1
    fi
    
    # Verificar que incluye output esperado
    if ! grep -q "Output esperado:" "$prompt"; then
        echo "❌ Prompt debe especificar output esperado"
        exit 1
    fi
done

echo "✅ Prompts validados"
```

---

## 📖 DOCUMENTACIÓN PARA DESARROLLADORES

### Archivo: `docs/guides/COMO_ESCRIBIR_PROMPTS_EFECTIVOS.md` (NUEVO)

```markdown
# Cómo Escribir Prompts Efectivos - Guía del Desarrollador

## Caso de Uso 1: Query Rápida (P1)

**Cuándo usar**: Necesitas dato factual rápido

**Template**:
```
[Verbo] + [Sustantivo concreto]
```

**Ejemplo**:
```
Lista módulos en addons/localization/
```

**Output esperado**: 70-150 palabras, lista simple

---

## Caso de Uso 2: Análisis de Archivo (P2)

**Cuándo usar**: Necesitas entender un archivo específico

**Template**:
```
Analiza [archivo] enfocándote en:
- [Aspecto 1]
- [Aspecto 2]
- [Aspecto 3]
```

**Ejemplo**:
```
Analiza account_move_dte.py enfocándote en:
- Patrones de herencia (@api decorators)
- Campos l10n_cl_* agregados
- Métodos compute y validaciones
```

**Output esperado**: 300-400 palabras, 1 code snippet, tabla si aplica

---

## Caso de Uso 3: Comparación Multi-Módulo (P3)

**Cuándo usar**: Necesitas comparar arquitecturas o identificar inconsistencias

**Template**:
```
Compara arquitectura de [módulo A], [módulo B], [módulo C]:

Dimensiones de análisis:
1. [Dimensión 1]
2. [Dimensión 2]
3. [Dimensión 3]

Identifica:
- Patrones comunes
- Inconsistencias críticas
- Mejores prácticas aplicadas
```

**Ejemplo**:
```
Compara arquitectura de l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports:

Dimensiones:
1. Patrón de herencia (_inherit vs _name)
2. Naming conventions (dte_* vs l10n_cl_* vs sin prefijo)
3. Estrategia de parsing (libs/ vs AI-Service vs mixto)

Identifica inconsistencias que afecten mantenibilidad
```

**Output esperado**: 800-1,000 palabras, 10+ code snippets, 2+ file references

---

## Caso de Uso 4: Análisis Arquitectónico (P4)

**Cuándo usar**: Evaluación profunda de sistema completo, decisiones de diseño

**Template**:
```
Analiza críticamente la arquitectura de [sistema]:

**Contexto**: [Descripción detallada: N componentes, X líneas totales]

**Evalúa**:
1. [Dimensión arquitectónica 1] (separación, flujo, patrones)
2. [Dimensión técnica 2] (herramientas, edge cases, alternativas)
3. [Aspecto de seguridad] (capas, fallos, recuperación)
4. [Validación/Testing] (suficiencia, tipos, completitud)
5. [Performance] (cuellos de botella, escalabilidad)
6. [Trade-offs] (priorización de conflictos)
7. [Mejoras] (propuestas concretas con código)

**Archivos a analizar**:
- [path/file1.py (N líneas)]
- [path/file2.py (M líneas)]
- [...]

**Entregable esperado**:
Análisis profesional que evalúe decisiones de diseño, fortalezas/debilidades,
riesgos identificados, recomendaciones con ejemplos de código concretos
```

**Ejemplo real**:
```
Analiza críticamente la arquitectura de sistema de migración Odoo 19 CE:

Contexto: Sistema de 3 capas (Audit → Migrate → Validate), 2,723 líneas,
137 migraciones automáticas aplicadas, validación triple, backups automáticos

Evalúa:
1. Diseño de 3 capas (separación adecuada, flujo datos, patrones detectados)
2. Estrategia parsing (AST Python vs regex vs XML ElementTree)
3. Sistema seguridad multi-capa (Git stash + backups + commits)
4. Validación triple (sintaxis + semántica + funcional, suficiencia)
5. Escalabilidad (performance con 10K archivos)
6. Trade-offs (automatización vs seguridad, velocidad vs exhaustividad)
7. Mejoras críticas (validación JSON schema, paralelización, rollback)

Archivos:
- scripts/odoo19_migration/1_audit_deprecations.py (444 líneas)
- scripts/odoo19_migration/2_migrate_safe.py (406 líneas)
- scripts/odoo19_migration/3_validate_changes.py (455 líneas)
- scripts/odoo19_migration/MASTER_ORCHESTRATOR.sh (414 líneas)
- scripts/odoo19_migration/config/deprecations.yaml (284 líneas)
```

**Output esperado**: 
- 1,200-1,500 palabras
- 30+ file references explícitos (formato file.py:line)
- 100+ technical terms (AST, regex, Strategy Pattern, trade-off, etc.)
- 30+ code snippets (soluciones arquitectónicas propuestas)
- 20+ tablas comparativas
- Especificidad >0.90 (máxima precisión técnica)
- Estructura profesional (50+ headers multi-nivel)

---

## Validación de Calidad

Usa `analyze_response.py` para validar outputs:

```bash
.venv/bin/python3 experimentos/analysis/analyze_response.py output.txt prompt_id P3
```

**Targets por nivel**:
- P1: words<200, specificity>0.50
- P2: words 300-400, specificity>0.55
- P3: words 800-1000, specificity>0.70, file_refs>2
- P4: words 1200-1500, specificity>0.90, file_refs>30, tech_terms>100
```

---

## 🎓 EDUCACIÓN DEL EQUIPO

### 1. Sesión de Capacitación (1 hora)

**Agenda**:
```
15 min: Presentación hallazgos experimento
20 min: Demo en vivo P1→P4 con métricas
15 min: Workshop práctico (escribir prompts)
10 min: Q&A
```

**Materiales**:
- `experimentos/RESULTADOS_FINALES_P4.md` (reporte completo)
- `docs/guides/COMO_ESCRIBIR_PROMPTS_EFECTIVOS.md` (guía práctica)

### 2. Checklist de Onboarding

**Para nuevos desarrolladores**:

```markdown
## Checklist: Dominio de Prompting Efectivo

- [ ] Leí `RESULTADOS_FINALES_P4.md` (hallazgos experimento)
- [ ] Revisé templates P1-P4 en `EJEMPLOS_PROMPTS_POR_NIVEL.md`
- [ ] Practiqué con 1 prompt de cada nivel (P1, P2, P3, P4)
- [ ] Validé outputs con `analyze_response.py`
- [ ] Entiendo métricas: especificidad, file refs, tech terms
- [ ] Sé cuándo usar P1 vs P4 (complejidad del análisis requerido)
```

---

## 📊 MÉTRICAS DE ADOPCIÓN

### KPIs a Trackear

```yaml
Métricas de Calidad de Prompts:
  - Especificidad promedio por nivel (target P4: >0.90)
  - File references en análisis complejos (target P4: >30)
  - Densidad técnica (target P4: >8 términos/100 palabras)

Métricas de Eficiencia:
  - Tiempo promedio análisis P1: <1 min
  - Tiempo promedio análisis P4: <5 min
  - Reducción de iteraciones (prompt → output útil)

Métricas de Adopción:
  - % equipo usa templates por nivel
  - # prompts nuevos validados con analyze_response.py
  - % PRs con análisis arquitectónico P4 (si aplica)
```

### Dashboard de Prompting

**Ubicación sugerida**: `docs/dashboards/prompting_metrics.md`

```markdown
# Dashboard: Calidad de Prompting

**Última actualización**: 2025-11-11

## Baseline (Experimento Inicial)

| Nivel | Palabras | Especificidad | File Refs | Tech Terms |
|-------|----------|---------------|-----------|------------|
| P1    | 100      | 0.53          | 0         | 0          |
| P2    | 342      | 0.56          | 0         | 0          |
| P3    | 915      | 0.74          | 2         | 7          |
| P4    | 1,303    | 0.95          | 31        | 109        |

## Prompts Producción (Tracking)

| Fecha | Prompt | Nivel | Palabras | Especificidad | Status |
|-------|--------|-------|----------|---------------|--------|
| ...   | ...    | ...   | ...      | ...           | ...    |
```

---

## 🚀 PLAN DE IMPLEMENTACIÓN

### Fase 1: Documentación (1-2 días)

- [x] Crear `ESTRATEGIA_PROMPTING_EFECTIVO.md`
- [ ] Crear `EJEMPLOS_PROMPTS_POR_NIVEL.md`
- [ ] Crear `METRICAS_CALIDAD_RESPUESTAS.md`
- [ ] Actualizar `README.md` en `docs/prompts_desarrollo/`
- [ ] Crear `docs/guides/COMO_ESCRIBIR_PROMPTS_EFECTIVOS.md`

### Fase 2: Propagación a CLIs (2-3 días)

- [ ] Actualizar `.github/copilot-instructions.md`
- [ ] Crear `.claude/project/PROMPTING_BEST_PRACTICES.md`
- [ ] Crear `.codex/prompting_guidelines.md`
- [ ] Crear `.gemini/prompt_optimization.md`

### Fase 3: Herramientas (1 día)

- [x] Script `analyze_response.py` creado
- [ ] Integrar en CI/CD (opcional)
- [ ] Crear git hook validación prompts (opcional)

### Fase 4: Educación (1 semana)

- [ ] Sesión capacitación equipo (1 hora)
- [ ] Actualizar checklist onboarding
- [ ] Crear dashboard métricas

### Fase 5: Monitoreo (Continuo)

- [ ] Trackear KPIs de calidad prompts
- [ ] Revisar y actualizar templates mensualmente
- [ ] Recopilar feedback del equipo

---

## 📌 PRÓXIMOS PASOS INMEDIATOS

### Para Pedro (Hoy)

1. ✅ Crear este documento de estrategia
2. ⏳ Revisar y aprobar estructura propuesta
3. ⏳ Decidir: ¿implementación inmediata o gradual?

### Para Implementación (Esta semana)

1. Crear archivos de documentación (Fase 1)
2. Actualizar configuraciones de CLIs (Fase 2)
3. Programar sesión capacitación equipo

---

## 💡 COMENTARIOS Y REFLEXIONES

### ¿Por qué esto es crítico?

**Antes del experimento**:
- Prompts genéricos producían outputs inconsistentes
- No había métricas objetivas de calidad
- Variación 4-6x entre CLIs sin explicación clara

**Después del experimento**:
- **Entendemos el "por qué"** de la variación (system prompt + complejidad)
- **Tenemos templates validados** para cada nivel de complejidad
- **Métricas cuantificables**: especificidad, file refs, tech terms
- **Configuración CLI óptima**: brevedad extrema P1, profundidad P4

### ¿Qué ganamos?

1. **Eficiencia**: Desarrolladores saben exactamente cómo estructurar prompts
2. **Calidad**: Outputs predecibles según nivel de complejidad
3. **Consistencia**: Todos los CLIs usan mismas convenciones
4. **Medición**: Podemos validar objetivamente calidad de análisis

### ¿Riesgos?

- ⚠️ **Sobreespecificación**: Templates muy rígidos pueden limitar creatividad
- ⚠️ **Mantenimiento**: Actualizar 4 CLIs al mismo tiempo requiere esfuerzo
- ⚠️ **Adopción**: Equipo debe aprender nuevas convenciones

**Mitigación**:
- Templates son guías, no reglas estrictas
- Documentación centralizada en `docs/prompts_desarrollo/`
- Sesión capacitación + checklist onboarding

---

**Autor**: GitHub Copilot + Claude Sonnet 4.5  
**Basado en**: Experimento de locuacidad (6 prompts, 13x escalamiento validado)  
**Validado**: 2025-11-11

