# Estrategia de Orquestación v1.1 "LEAN" - Fire and Forget + File Polling

**Versión:** 1.1.0
**Fecha:** 2025-11-13
**Mejoras sobre:** v1.0.0 (Orquestación Clásica)
**Ahorro de Tokens:** ~80% en Phase 2 (Auditorías)

---

## 🎯 Problema Resuelto

### v1.0.0 (Orquestación Clásica) - ❌ Token Waste

```python
# Comportamiento v1.0:
1. Lanzar CLI agents en background
2. Esperar 30-60s
3. Leer logs con BashOutput (múltiples veces) ← ❌ 40K tokens
4. Parsear outputs yo mismo ← ❌ 20K tokens
5. Generar reportes yo mismo ← ❌ 25K tokens
6. Consolidar yo mismo ← ❌ 15K tokens

TOTAL Phase 2: ~112K tokens (56% del budget de 200K)
RIESGO: "Conversation compaction" + context loss
```

### v1.1.0 (Orquestación LEAN) - ✅ Token Efficient

```python
# Comportamiento v1.1:
1. Crear prompts autónomos con permisos full ← 2K tokens
2. Lanzar CLI agents en background (fire and forget) ← 2K tokens
3. Polling de archivos (NO leer logs) ← 1K tokens
4. Leer SOLO resúmenes (head -50) ← 16K tokens (4 reportes × 4K)
5. Consolidación delegada a Task tool ← 500 tokens (solo resumen)

TOTAL Phase 2: ~21K tokens (10.5% del budget)
AHORRO: 112K - 21K = 91K tokens (81% reducción)
```

---

## 📐 Arquitectura v1.1

### Principio: "Orchestrator as Coordinator, NOT Worker"

```
┌─────────────────────────────────────────────────────────────┐
│ Claude Code (Orchestrator Maestro) - Token Budget: 120K    │
│ ───────────────────────────────────────────────────────────│
│ Responsabilidades:                                          │
│ 1. ✅ Crear prompts estratégicos (< 2K tokens cada uno)    │
│ 2. ✅ Lanzar CLI agents (background)                        │
│ 3. ✅ Polling archivos (wait_for_audit_reports.sh)         │
│ 4. ✅ Leer resúmenes (head -50, ~4K tokens cada uno)       │
│ 5. ✅ Tomar decisiones estratégicas (continuar/abortar)    │
│ 6. ❌ NO leer logs completos                                │
│ 7. ❌ NO parsear outputs                                    │
│ 8. ❌ NO generar reportes (delegar)                         │
└─────────────────────────────────────────────────────────────┘
                  │
                  ├─────────────> CLI Agent 1 (Copilot)
                  │                ├─ Lee código completo
                  │                ├─ Analiza (autonomía total)
                  │                ├─ Escribe reporte en archivo
                  │                └─ Retorna resumen breve
                  │
                  ├─────────────> CLI Agent 2 (Copilot)
                  │                └─ (mismo flujo)
                  │
                  ├─────────────> CLI Agent 3 (Copilot)
                  │                └─ (mismo flujo)
                  │
                  └─────────────> CLI Agent 4 (Copilot)
                                   └─ (mismo flujo)
```

---

## 🔥 "Fire and Forget + File Polling" Pattern

### Paso 1: Crear Prompts Autónomos

```markdown
# Características de prompts v1.1:
1. **Tarea específica** - "Audita backend ai-service"
2. **Permisos explícitos** - "Full access a proyecto, full write permisos"
3. **Ruta output** - "Escribe reporte en: docs/prompts/06_outputs/AUDIT_X.md"
4. **Formato esperado** - "Score + Top 3 findings"
5. **Autonomía total** - "NO pedir confirmación para reads/writes autorizados"
6. **Output breve** - "Retorna resumen <300 tokens al finalizar"
```

**Ejemplo de Prompt v1.1:**
```markdown
# CONTEXTO
Lee PRIMERO: docs/prompts/00_knowledge_base/CLI_AGENTS_SYSTEM_CONTEXT.md (tu rol y permisos)

# TAREA
Audita backend del microservicio ai-service.

**Módulo:** /Users/pedro/Documents/odoo19/ai-service/
**Enfoque:** Python quality, FastAPI patterns, error handling, architecture

# PERMISOS (Pre-Autorizados - NO pedir confirmación)
- ✅ Full access lectura a TODO el proyecto
- ✅ Full write access a: docs/prompts/06_outputs/**/*.md
- ✅ Ejecutar comandos análisis (grep, find, wc, tree, cat)
- ✅ NO pedir confirmación para reads/análisis/writes en rutas autorizadas

# OUTPUT
**Archivo:** docs/prompts/06_outputs/2025-11/AUDIT_BACKEND_AI_SERVICE_V2_2025-11-13.md

**Formato:**
```markdown
**Score:** X/100
**Fecha:** 2025-11-13
**Auditor:** Copilot CLI (GPT-4o)

## Top 3 Findings
[P1] Finding 1 (file.py:123)
[P2] Finding 2 (file.py:456)
[P3] Finding 3 (file.py:789)

[... resto del reporte detallado ...]
```

**Stdout (retornar al finalizar):**
```
✅ Auditoría completada
Score: X/100
Top finding: [P1] Description
Reporte: AUDIT_BACKEND_AI_SERVICE_V2_2025-11-13.md
```

# RESTRICCIONES
- ❌ NO modificar código (solo auditar)
- ❌ NO crear nuevos módulos
- ⏱️  Target: < 5 minutos ejecución
```

### Paso 2: Lanzar CLI Agents (Fire and Forget)

```bash
# ✅ BUENO: Fire and forget con output file
copilot --allow-all-tools --allow-all-paths \
    -p "$(cat .tmp_prompt_backend.md)" \
    2>&1 | tee /tmp/audit_backend_v2.log &

# NO esperar, NO leer logs, continuar lanzando siguientes
```

### Paso 3: File Polling (NO Log Reading)

```bash
# ✅ BUENO: Esperar archivos con helper script
./docs/prompts/08_scripts/wait_for_audit_reports.sh \
    "docs/prompts/06_outputs/2025-11" \
    300 \
    10 \
    "AUDIT_BACKEND_AI_SERVICE_V2_2025-11-13.md" \
    "AUDIT_SECURITY_AI_SERVICE_V2_2025-11-13.md" \
    "AUDIT_TESTS_AI_SERVICE_V2_2025-11-13.md" \
    "AUDIT_PERFORMANCE_AI_SERVICE_V2_2025-11-13.md"

# Script hace polling cada 10s durante 5min
# Retorna cuando 4/4 reportes estén listos
# Muestra progress: "2/4 reports ready..."
```

### Paso 4: Leer SOLO Resúmenes (Token Efficient)

```bash
# ✅ BUENO: Leer solo primeras 50 líneas (contiene score + top findings)
head -50 docs/prompts/06_outputs/2025-11/AUDIT_BACKEND_AI_SERVICE_V2_2025-11-13.md

# Extrae:
# - Score: X/100
# - Top 3 findings (P1/P2/P3)
# - NO leer detalles completos (están en archivo para usuario)
```

---

## 📊 Token Budget Comparison

| Fase | v1.0.0 (Clásico) | v1.1.0 (LEAN) | Ahorro |
|------|-----------------|---------------|--------|
| **Phase 1: Discovery** | 15K | 15K | 0K (ya eficiente) |
| **Phase 2: Audit 4 dimensiones** | 112K | 21K | **91K (81%)** |
| **Phase 3: Consolidate** | 15K | 3K | 12K (80%) |
| **Phase 4-7: Iterate** | 50K | 35K | 15K (30%) |
| **TOTAL** | 192K | 74K | **118K (61%)** |
| **% Budget usado** | 96% ⚠️ | 37% ✅ | -59% |

**Conclusión:** v1.1.0 usa **menos de la mitad** de tokens vs v1.0.0, eliminando riesgo de "conversation compaction".

---

## 🎓 Lecciones Aprendidas

### v1.0.0 Mistakes

1. ❌ **Leer logs repetidamente** - BashOutput consumía 2K tokens por lectura × 3 veces × 4 agents = 24K
2. ❌ **Parsear yo mismo** - Análisis manual de outputs consumía 20K tokens
3. ❌ **Generar reportes yo mismo** - Escritura de 4 reportes consumía 25K tokens
4. ❌ **NO usar Task tool** - Consolidación manual consumía 15K tokens
5. ❌ **NO confiar en CLI agents** - Matar procesos y hacer trabajo yo mismo

### v1.1.0 Best Practices

1. ✅ **File polling, not log reading** - Ahorra 24K tokens
2. ✅ **Delegate parsing** - CLI agents parsean, yo leo resúmenes (-20K tokens)
3. ✅ **Delegate report writing** - CLI agents escriben, yo leo heads (-25K tokens)
4. ✅ **Use Task tool** - Sub-agents consolidan (-15K tokens)
5. ✅ **Trust CLI agents** - Darles autonomía total con permisos explícitos

---

## 🚀 Próximas Mejoras (v1.2.0)

1. **Streaming Progress** - CLI agents reportan progress vía files temporales
   ```bash
   /tmp/audit_backend_progress.txt:
   "Phase 1/5: Discovery... 20% done"
   ```

2. **Parallel Task Tool** - Usar Task tool también para auditorías (no solo consolidación)
   ```python
   Task(subagent_type="general-purpose", prompt="Audita backend...", output_file="...")
   # Task tool maneja todo: lectura, análisis, escritura
   ```

3. **Budget Tracking** - Tracking preciso de tokens usados por fase
   ```python
   budget_tracker = {
       "Phase 1": 15K,
       "Phase 2": 21K,
       "Phase 3": 3K,
       "TOTAL": 39K / 200K (19.5%)
   }
   ```

4. **Retry Logic** - Si CLI agent falla, re-lanzar automáticamente con modelo alternativo
   ```python
   if not file_exists(output_file):
       # Retry con modelo diferente
       launch_cli("gemini", prompt, output_file)  # Gemini más barato
   ```

---

## 📝 Checklist Implementación v1.1

- [x] Actualizar CLI_AGENTS_SYSTEM_CONTEXT.md con autonomía escritura
- [x] Crear wait_for_audit_reports.sh helper script
- [x] Documentar estrategia v1.1.0 (este archivo)
- [ ] Re-ejecutar auditoría 360° con v1.1.0
- [ ] Medir ahorro real de tokens
- [ ] Validar que reportes tienen misma calidad
- [ ] Commit mejoras al repo

---

**Autor:** Claude Code Sonnet 4.5 (Orchestrator Maestro)
**Basado en:** Análisis post-mortem de orquestación v1.0.0 (2025-11-13)
**Feedback:** Usuario identificó token waste crítico
