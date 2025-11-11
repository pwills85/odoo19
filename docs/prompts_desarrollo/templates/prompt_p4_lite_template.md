# Prompt P4-Lite: Auditoría Ejecutiva de Módulo Odoo 19 CE

**Versión:** 1.0.0  
**Nivel:** P4-Lite (Auditoría Ejecutiva / Compliance)  
**Target Output:** 900-1,200 palabras (±20% si justificas)  
**Tiempo estimado:** 3-5 minutos generación

---

## 📋 Objetivo

Auditar el módulo **[MODULE_NAME]** de EERGYGROUP (Odoo 19 CE) y entregar hallazgos verificables con recomendaciones priorizadas P0/P1/P2 listas para revisión ejecutiva o auditoría de compliance.

---

## 🔄 Reglas de Progreso (Preamble Obligatorio)

1. **Reformula el objetivo** en 1-2 líneas (confirma que entendiste)
2. **Plan de 4-6 pasos** con estructura "Paso i/N: [descripción]"
3. **Anuncia cada paso** cuando comiences: "Ejecutando Paso i/N..."
4. **Cierra cada paso** con resumen: "Completado Paso i/N: [logros clave]"
5. **Cierre final** con:
   - Cobertura de áreas (A-F) vs requisitos
   - Métricas cumplidas (refs, verificaciones, palabras)
   - Próximos pasos recomendados

---

## 📊 Contexto del Módulo

### Información Base

| Métrica | Valor |
|---------|-------|
| **Módulo** | [MODULE_NAME] (ej: l10n_cl_dte, l10n_cl_hr_payroll) |
| **Stack** | Odoo 19 CE + Python 3.11 + PostgreSQL 16 |
| **Archivos Python** | [NUM_FILES] archivos |
| **LOC principal** | [MAIN_FILE] con [NUM_LINES] líneas |
| **Tests** | [NUM_TESTS] tests ([COVERAGE]% coverage estimado) |
| **Dependencias** | [NUM_DEPS] dependencias externas |
| **Integraciones** | [INTEGRATIONS] (ej: SII, Previred, APIs) |

### Rutas Clave a Analizar

```
addons/localization/[MODULE_NAME]/
├── models/
│   ├── [main_model].py ([NUM_LINES] LOC)
│   └── [secondary_models].py
├── views/
│   └── [views].xml
├── security/
│   └── ir.model.access.csv
├── data/
│   └── [master_data].xml
├── wizards/
│   └── [wizards].py
├── reports/
│   └── [reports].py
└── tests/
    └── test_[module].py ([NUM_TESTS] tests)
```

**Archivos foco obligatorios:**
- `[MAIN_MODEL_PATH]` (modelo principal)
- `[INTEGRATION_PATH]` (integración externa)
- `[SECURITY_PATH]` (ir.model.access.csv)
- `[TEST_PATH]` (tests/)

---

## 🎯 Áreas de Evaluación (A-F)

Analiza TODAS estas áreas con sub-bullets mínimos por cada una:

### A) Arquitectura FastAPI / Odoo y Modularidad

- Separación de responsabilidades (routes/models/services vs models/views/controllers)
- Uso de herencia Odoo (`_inherit`, mixins, `@api.model`)
- Dependency injection vs singletons globales
- Riesgos del monolito (archivos >1,000 LOC)

### B) Validaciones y Compliance (SII/Previred/Labor Code)

- Validaciones de negocio (`@api.constrains`)
- Cumplimiento normativo (SII Resolution 80/2014, Previred Circular 1/2018)
- Manejo de estados (draft, validated, accepted, rejected)
- Gestión de errores de integraciones externas (SOAP, APIs)

### C) Seguridad y Protección de Datos

- Gestión de credenciales (API keys, tokens) - NO hardcoded
- CORS y rate limiting
- PII y GDPR en logs (si aplicable)
- Permisos Odoo (ir.model.access.csv, record rules)
- Validación de entrada (Pydantic validators, Odoo fields)

### D) Testing y Cobertura

- Coverage actual (% líneas cubiertas)
- Gaps identificados (módulos sin tests)
- pytest markers (unit, integration, slow)
- Mocks y fixtures para integraciones externas

### E) Observabilidad y Monitoreo

- Logging (structlog JSON, níveis de severidad)
- Health checks (/health, /ready, /live o equivalente Odoo)
- Métricas (Prometheus, Odoo logging)
- Tracing distribuido (OpenTelemetry, APM) - ¿presente?

### F) Rendimiento y Escalabilidad

- Consultas ORM (N+1 queries, prefetch)
- Redis/cache usage (si aplicable)
- SPOF (Single Points of Failure) identificados
- Degradación graceful ante fallos

---

## 📏 Requisitos de Salida (OBLIGATORIO)

### Formato

- **Longitud:** 900-1,200 palabras (±20% solo si justificas)
- **Referencias válidas:** ≥10 con formato `ruta.py:línea[-línea]`
  - Ejemplo: `addons/localization/l10n_cl_dte/models/account_move.py:145-150`
- **Estructura:** Markdown con headers H2 (##) por área (A-F)

### Verificaciones Reproducibles (≥3)

**OBLIGATORIO:** Incluir AL MENOS:
- **≥1 verificación P0** (crítica: seguridad, data loss, compliance crítico)
- **≥1 verificación P1** (alta: performance, availability, compliance medio)
- **≥1 verificación P2** (media: code quality, mantenibilidad)

**Formato de verificación:**

```markdown
### Verificación V1: [Título] (P0/P1/P2)

**Comando:**
```bash
[comando reproducible: grep, pytest, curl, etc.]
```

**Hallazgo esperado:**
[Qué debería mostrar si todo está correcto]

**Problema si falla:**
[Impacto del problema - justifica prioridad P0/P1/P2]

**Cómo corregir:**
[Acción concreta para resolver]
```

### Datos NO VERIFICADOS

Si encuentras datos inciertos (ej: "90% cost reduction" sin métrica de origen):
1. Marca como **[NO VERIFICADO]**
2. Explica cómo verificar (comando/métrica/log)
3. OPCIONAL: Proporciona rango probable con nivel de confianza

**Ejemplo:**
```markdown
"86% test coverage" **[NO VERIFICADO, CONFIANZA: MEDIA]**
- Estimación basada en: 51 tests para 2 módulos clave
- Probable range: 75-90% (si anthropic_client + chat_engine son 60% codebase)
- Verificar con: `pytest addons/localization/[MODULE]/ --cov --cov-report=term-missing`
```

### Recomendaciones Accionables

Cada recomendación DEBE incluir:
1. **Snippet mínimo** (código real del proyecto - ANTES)
2. **Solución propuesta** (código mejorado - DESPUÉS)
3. **Impacto esperado** (métrica, riesgo mitigado, esfuerzo)

**Formato:**

```markdown
### Recomendación R1: [Título breve] (P0/P1/P2)

**Área:** [A-F]

**Problema:**
[1-2 líneas del anti-pattern identificado con referencia `ruta.py:línea`]

**Solución propuesta:**
```python
# ANTES (anti-pattern en addons/.../models/xxx.py:145-150)
_orchestrator = None  # Global singleton
def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator

# DESPUÉS (propuesta con dependency injection)
from functools import lru_cache
from odoo import api

@lru_cache()
def get_orchestrator():
    return Orchestrator()
```

**Impacto esperado:**
- Métrica: Testability +300% (DI permite mock fácil)
- Riesgo mitigado: Thread-safety issues con global mutable state
- Esfuerzo: 2-3 horas (refactor 14 endpoints/methods)
```

---

## 🚫 Restricciones

- **Solo lectura:** No modificar archivos del proyecto
- **Sin secretos:** No exponer API keys, passwords, tokens reales
- **Sin llamadas externas:** No hacer requests reales a SII, Previred, etc.
- **Evidencia verificable:** Toda afirmación crítica debe tener verificación reproducible

---

## ✅ Checklist de Aceptación (Auto-Validación)

Antes de entregar, verifica:

**Formato (obligatorio):**
- [ ] Progreso visible (plan + "Paso i/N" + cierres)
- [ ] Cobertura A-F con evidencias
- [ ] ≥10 referencias a archivo válidas (`ruta.py:línea`)
- [ ] ≥3 verificaciones reproducibles (≥1 P0 + ≥1 P1 + ≥1 P2)
- [ ] Riesgos clasificados P0/P1/P2 con justificación
- [ ] Recomendaciones con snippet + impacto esperado
- [ ] Resumen ejecutivo claro (≤150 palabras)

**Profundidad (calidad técnica):**
- [ ] Términos técnicos: ≥60 (arquitectura, patrones, CVEs, compliance)
- [ ] Snippets de código: ≥8 (código real del proyecto)
- [ ] Trade-offs evaluados: ≥2 (conflictos técnicos analizados)
- [ ] Tablas comparativas: ≥2 (antes/después u opción A vs B)
- [ ] Anti-patterns identificados: ≥2 (con evidencia file:line)
- [ ] Best practices reconocidas: ≥3

---

## 🎓 Ejemplo de Output Esperado (Estructura)

```markdown
# Auditoría Ejecutiva: [MODULE_NAME]

## Objetivo Reformulado
[1-2 líneas confirmando entendimiento]

## Plan de Ejecución
Paso 1/5: Análisis de arquitectura y modularidad
Paso 2/5: Validación de compliance y seguridad
...

---

## Ejecutando Paso 1/5: Análisis de Arquitectura

[Análisis detallado del área A con referencias específicas]

### Hallazgos Clave (Área A)
- [Hallazgo 1 con ruta.py:línea]
- [Hallazgo 2 con ruta.py:línea]

**Completado Paso 1/5:** Identificadas 3 mejoras de arquitectura (2 P1, 1 P2)

---

## Ejecutando Paso 2/5: Validación de Compliance

[Análisis detallado del área B]

### Verificación V1: API Keys No Hardcoded (P0)

**Comando:**
```bash
grep -rn "api_key.*=.*\"" addons/localization/[MODULE]/ --exclude-dir=tests
```

**Hallazgo esperado:** Sin resultados (0 hardcoded keys)
**Problema si falla:** CRITICAL - Exposición de credenciales en repo
**Cómo corregir:** Usar environment variables + Odoo ir.config_parameter

...

---

## Recomendaciones Priorizadas

### Recomendación R1: Refactorizar main.py monolítico (P1)
[Detalles con snippet ANTES/DESPUÉS + impacto]

### Recomendación R2: Añadir tests de integración SII (P1)
[Detalles...]

### Recomendación R3: Implementar circuit breaker (P2)
[Detalles...]

---

## Resumen Ejecutivo (≤150 palabras)

[Resumen de hallazgos, métricas de calidad, próximos pasos]

## Cobertura vs Requisitos

- Áreas analizadas: A-F (100%)
- Referencias: 12 válidas (target: ≥10) ✅
- Verificaciones: 4 (1 P0 + 2 P1 + 1 P2) ✅
- Palabras: 1,050 (target: 900-1,200) ✅

## Próximos Pasos Recomendados

1. Ejecutar verificaciones V1-V4 para validar hallazgos
2. Priorizar recomendaciones P0 y P1 para próximo sprint
3. Actualizar roadmap con esfuerzos estimados (8-12 horas total)
```

---

## 🚀 Cómo Usar este Prompt

### Personalizar Contexto

1. **Reemplazar placeholders:**
   - `[MODULE_NAME]` → nombre real del módulo (ej: l10n_cl_dte)
   - `[NUM_FILES]`, `[NUM_LINES]`, `[NUM_TESTS]` → métricas reales
   - `[MAIN_MODEL_PATH]` → ruta real al modelo principal

2. **Actualizar rutas clave:**
   - Listar archivos específicos a analizar
   - Incluir integraciones externas relevantes

3. **Ajustar áreas foco:**
   - Si módulo NO tiene integraciones externas, reducir peso de área B
   - Si módulo crítico de seguridad, aumentar peso de área C

### Ejecutar con Copilot CLI

```bash
# Reemplazar [MODULE_NAME] en template
sed 's/\[MODULE_NAME\]/l10n_cl_dte/g' templates/prompt_p4_lite_template.md > /tmp/prompt_dte.md

# Ejecutar
copilot -p "$(cat /tmp/prompt_dte.md)" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_dte_lite_$(date +%Y%m%d_%H%M%S).md
```

### Validar Output

```bash
# Medir métricas
.venv/bin/python3 experimentos/analysis/analyze_response.py \
  experimentos/outputs/audit_dte_lite_*.md \
  audit_dte_lite \
  P4-Lite

# Verificar checklist manualmente
cat templates/checklist_calidad_p4.md
```

---

## 📖 Referencias

- **Guía completa:** `docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`
- **Checklist validación:** `docs/prompts_desarrollo/templates/checklist_calidad_p4.md`
- **Feedback metodológico:** `experimentos/FEEDBACK_AGENTE_MEJORADOR_PROMPTS.txt`

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-11  
**Mantenedor:** Pedro Troncoso (@pwills85)
