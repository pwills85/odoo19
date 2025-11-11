# Checklist de Calidad P4 (Lite + Deep)

**Versión:** 1.0.0  
**Propósito:** Validar formato y profundidad de análisis generados por prompts P4  
**Uso:** Auto-validación durante generación + revisión post-generación

---

## 🎯 Cómo Usar este Checklist

### Durante Generación (Agente AI)

Antes de entregar el análisis, verificar TODOS los criterios:
- **Formato (obligatorio):** Sin estos, análisis inválido
- **Profundidad (calidad):** Sin estos, análisis superficial

### Post-Generación (Revisor Humano)

```bash
# Validación automática (Fase 4 - TODO)
.venv/bin/python3 scripts/validate_prompt_output.py \
  --input audit_output.md \
  --level P4-Deep \
  --checklist templates/checklist_calidad_p4.md

# Validación manual
cat templates/checklist_calidad_p4.md
```

---

## ✅ CRITERIOS DE FORMATO (Obligatorio)

Estos criterios son **binarios**: se cumplen o no. Sin ellos, el análisis es **inválido**.

### P4-Lite (Auditoría Ejecutiva)

- [ ] **Progreso visible:** Plan explícito con "Paso i/N" + anuncios + cierres
- [ ] **Cobertura completa:** Todas las áreas (A-F) con evidencias
- [ ] **Referencias válidas:** ≥10 referencias formato `ruta.py:línea[-línea]`
- [ ] **Verificaciones reproducibles:** ≥3 comandos (grep/pytest/curl)
  - [ ] ≥1 verificación P0 (crítica: seguridad, data loss)
  - [ ] ≥1 verificación P1 (alta: performance, availability)
  - [ ] ≥1 verificación P2 (media: mantenibilidad)
- [ ] **Riesgos clasificados:** P0/P1/P2 con justificación de prioridad
- [ ] **Recomendaciones accionables:** Snippet ANTES/DESPUÉS + impacto esperado
- [ ] **Resumen ejecutivo:** ≤150 palabras con hallazgos clave
- [ ] **Longitud:** 900-1,200 palabras (±20% solo si justificado)

### P4-Deep (Auditoría Arquitectónica)

- [ ] **Progreso visible:** Plan explícito con "Paso i/N" + anuncios + cierres
- [ ] **Cobertura completa:** Todas las áreas (A-J) con evidencias
- [ ] **Referencias válidas:** ≥30 referencias formato `ruta.py:línea[-línea]`
- [ ] **Verificaciones reproducibles:** ≥6 comandos (≥1 por área A-F)
  - [ ] ≥1 verificación P0 (crítica)
  - [ ] ≥2 verificación P1 (alta)
  - [ ] ≥3 verificación P2 (media)
- [ ] **Riesgos clasificados:** P0/P1/P2 con justificación de prioridad
- [ ] **Recomendaciones estructuradas:** Template completo (Problema, Solución, Impacto)
- [ ] **Resumen ejecutivo:** ≤200 palabras con hallazgos clave
- [ ] **Longitud:** 1,200-1,500 palabras (±15% solo si justificado)

---

## 🎓 CRITERIOS DE PROFUNDIDAD (Calidad Técnica)

Estos criterios miden **calidad** del análisis. Sin ellos, análisis es **superficial**.

### P4-Lite (Auditoría Ejecutiva)

- [ ] **Términos técnicos:** ≥60 términos (arquitectura, patrones, CVEs, compliance)
  - Ejemplos: "singleton", "dependency injection", "N+1 query", "OWASP A03", "SQL injection"
- [ ] **Snippets de código:** ≥8 bloques de código real del proyecto
  - Formato: ```python con ruta.py:línea en comentario
- [ ] **Trade-offs evaluados:** ≥2 conflictos técnicos analizados
  - Formato: "Opción A vs B", "Pro: X | Contra: Y"
- [ ] **Tablas comparativas:** ≥2 tablas markdown
  - Ejemplos: "Antes vs Después", "Opción A vs Opción B", "Módulo X vs Módulo Y"
- [ ] **Anti-patterns identificados:** ≥2 con evidencia `file:line`
  - Ejemplos: "Global mutable state", "God class", "Hardcoded credentials"
- [ ] **Best practices reconocidas:** ≥3 aplicadas correctamente
  - Ejemplos: "DI bien implementado", "Tests con AsyncMock", "CORS configurado"
- [ ] **Especificidad:** ≥0.80 (calculado con analyze_response.py)
  - Métrica: ratio de palabras técnicas específicas vs genéricas

### P4-Deep (Auditoría Arquitectónica)

- [ ] **Términos técnicos:** ≥80 términos (arquitectura, patrones, CVEs, compliance)
- [ ] **Snippets de código:** ≥15 bloques de código real del proyecto
- [ ] **Trade-offs evaluados:** ≥3 conflictos técnicos analizados con pros/contras
- [ ] **Tablas comparativas:** ≥5 tablas markdown (métricas, opciones, estados)
- [ ] **Anti-patterns identificados:** ≥3 con evidencia `file:line` y solución
- [ ] **Best practices reconocidas:** ≥5 aplicadas correctamente con justificación
- [ ] **Especificidad:** ≥0.85 (calculado con analyze_response.py)
- [ ] **Diagramas/Esquemas:** ≥1 diagrama ASCII o descripción estructural
  - Ejemplos: "Flujo de datos", "Arquitectura de capas", "Secuencia de llamadas"
- [ ] **Métricas cuantitativas:** ≥10 números específicos
  - Ejemplos: "2,016 LOC", "86% coverage", "90% cost reduction", "51 tests"

---

## 🔍 CRITERIOS DE VERIFICABILIDAD (Clave P4)

Estos criterios distinguen P4 de P1-P3: **evidencia reproducible obligatoria**.

### Verificaciones Reproducibles

Cada verificación DEBE cumplir:

- [ ] **Comando específico:** grep/pytest/curl/wc con parámetros exactos
- [ ] **Hallazgo esperado:** Qué debería mostrar si todo está correcto
- [ ] **Problema si falla:** Impacto del problema (justifica P0/P1/P2)
- [ ] **Cómo corregir:** Acción concreta para resolver

**Ejemplo válido:**

```markdown
### Verificación V1: API Keys No Hardcoded (P0)

**Comando:**
```bash
grep -rn "api_key.*=.*\"" ai-service/ --exclude-dir=tests
```

**Hallazgo esperado:** Sin resultados (0 hardcoded keys)

**Problema si falla:** CRITICAL - Exposición de credenciales en repo

**Cómo corregir:** Usar environment variables + ir.config_parameter
```

**Ejemplo inválido:**

```markdown
### Verificación V1: Seguridad (P0)

Verificar que no hay problemas de seguridad.
```

❌ Problema: No es reproducible, no hay comando, no especifica qué buscar.

---

## 📏 CRITERIOS DE INCERTIDUMBRE (Innovación P4)

Datos inciertos DEBEN marcarse explícitamente:

- [ ] **Marca "NO VERIFICADO":** Datos sin fuente confiable
- [ ] **Explica cómo verificar:** Comando/métrica/log específico
- [ ] **Rango probable (opcional):** Estimación con nivel de confianza

**Ejemplo válido:**

```markdown
"86% test coverage" **[NO VERIFICADO, CONFIANZA: MEDIA]**
- Estimación basada en: 51 tests para 2 módulos clave
- Probable range: 75-90% (si anthropic_client + chat_engine son 60% codebase)
- Verificar con: `pytest ai-service/ --cov --cov-report=term-missing`
```

**Ejemplo inválido:**

```markdown
El módulo tiene buena cobertura de tests.
```

❌ Problema: No cuantifica, no marca incertidumbre, no explica cómo verificar.

---

## 🎯 CRITERIOS DE RECOMENDACIONES (Accionabilidad)

Cada recomendación DEBE cumplir:

### P4-Lite

- [ ] **Prioridad clara:** P0/P1/P2 con justificación
- [ ] **Área identificada:** [A-F]
- [ ] **Problema específico:** Anti-pattern con evidencia `ruta.py:línea`
- [ ] **Solución propuesta:** Snippet ANTES/DESPUÉS
- [ ] **Impacto esperado:** Métrica + riesgo mitigado + esfuerzo

### P4-Deep

- [ ] **Template estructurado completo:**
  - Título breve
  - Prioridad P0/P1/P2
  - Área [A-J]
  - Problema (1-2 líneas con `file:line`)
  - Solución (snippet ANTES + DESPUÉS con comentarios)
  - Impacto esperado (métrica, riesgo, esfuerzo, trade-off)

**Ejemplo válido (P4-Deep):**

```markdown
### Recomendación R2: Refactorizar Singleton Global (P1)

**Prioridad:** P1  
**Área:** A (Arquitectura)

**Problema:**
Global mutable state en `ai-service/main.py:145-150` impide testing y crea race conditions.

**Solución propuesta:**
```python
# ANTES (ai-service/main.py:145-150)
_orchestrator = None
def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator

# DESPUÉS (dependency injection + lru_cache)
from functools import lru_cache
from fastapi import Depends

@lru_cache()
def get_orchestrator() -> Orchestrator:
    return Orchestrator()

# Uso en endpoint
@app.post("/api/validate")
async def validate(orch: Orchestrator = Depends(get_orchestrator)):
    ...
```

**Impacto esperado:**
- Métrica: Testability +300% (DI permite mock fácil en tests)
- Riesgo mitigado: Thread-safety (global mutable state eliminado)
- Esfuerzo: 2-3 horas (refactor 14 endpoints)
- Trade-off: Ninguno (DI es best practice sin downsides)
```

---

## 📊 VALIDACIÓN AUTOMÁTICA (Fase 4 - TODO)

Script `validate_prompt_output.py` verificará:

### Métricas Cuantitativas

```python
# Contar referencias
refs_count = len(re.findall(r'\w+\.py:\d+(-\d+)?', content))
assert refs_count >= 10  # P4-Lite
assert refs_count >= 30  # P4-Deep

# Contar verificaciones
verifications = len(re.findall(r'### Verificación V\d+:', content))
assert verifications >= 3  # P4-Lite
assert verifications >= 6  # P4-Deep

# Contar términos técnicos
tech_terms = count_technical_terms(content, TECH_VOCABULARY)
assert tech_terms >= 60  # P4-Lite
assert tech_terms >= 80  # P4-Deep

# Contar snippets código
code_blocks = len(re.findall(r'```python', content))
assert code_blocks >= 8   # P4-Lite
assert code_blocks >= 15  # P4-Deep

# Contar tablas
tables = len(re.findall(r'^\|.*\|$', content, re.MULTILINE))
assert tables >= 2  # P4-Lite (mínimo 2 filas por tabla)
assert tables >= 5  # P4-Deep

# Calcular especificidad
specificity = analyze_response.calculate_specificity(content)
assert specificity >= 0.80  # P4-Lite
assert specificity >= 0.85  # P4-Deep
```

### Validación Estructural

```python
# Verificar estructura de progreso
assert re.search(r'Paso \d+/\d+:', content)
assert re.search(r'Completado \d+/\d+:', content)

# Verificar áreas cubiertas
for area in ['A)', 'B)', 'C)', 'D)', 'E)', 'F)']:
    assert area in content

# P4-Deep: verificar áreas G-J
if level == 'P4-Deep':
    for area in ['G)', 'H)', 'I)', 'J)']:
        assert area in content

# Verificar clasificación P0/P1/P2
assert re.search(r'\(P0\)', content)
assert re.search(r'\(P1\)', content)
assert re.search(r'\(P2\)', content)
```

---

## 🚀 Uso Práctico

### Ejemplo: Validar Output P4-Deep

```bash
# 1. Generar análisis
copilot -p "$(cat modulos/p4_deep_l10n_cl_dte.md)" > output.md

# 2. Validación automática (Fase 4 - TODO)
.venv/bin/python3 scripts/validate_prompt_output.py \
  --input output.md \
  --level P4-Deep \
  --checklist templates/checklist_calidad_p4.md

# 3. Validación manual
# Abrir checklist y marcar cada ítem
code templates/checklist_calidad_p4.md

# 4. Métricas detalladas
.venv/bin/python3 experimentos/analysis/analyze_response.py \
  output.md \
  audit_dte \
  P4-Deep
```

### Tabla Resumen de Validación

| Criterio | Target Lite | Target Deep | Actual | Status |
|----------|-------------|-------------|--------|--------|
| Referencias | ≥10 | ≥30 | [COMPLETAR] | [ ] |
| Verificaciones | ≥3 | ≥6 | [COMPLETAR] | [ ] |
| Términos técnicos | ≥60 | ≥80 | [COMPLETAR] | [ ] |
| Snippets código | ≥8 | ≥15 | [COMPLETAR] | [ ] |
| Tablas | ≥2 | ≥5 | [COMPLETAR] | [ ] |
| Especificidad | ≥0.80 | ≥0.85 | [COMPLETAR] | [ ] |
| Palabras | 900-1,200 | 1,200-1,500 | [COMPLETAR] | [ ] |

---

## 📖 Referencias

- **Estrategia completa:** `docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`
- **Template P4-Lite:** `docs/prompts_desarrollo/templates/prompt_p4_lite_template.md`
- **Template P4-Deep:** `docs/prompts_desarrollo/templates/prompt_p4_deep_template.md` (TODO)
- **Feedback metodológico:** `experimentos/FEEDBACK_AGENTE_MEJORADOR_PROMPTS.txt`

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-11  
**Mantenedor:** Pedro Troncoso (@pwills85)
