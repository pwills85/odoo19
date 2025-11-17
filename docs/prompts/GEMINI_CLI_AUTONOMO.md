# 🤖 Google Gemini CLI - Modo Autónomo

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Autor:** Pedro Troncoso (@pwills85) + Claude Sonnet 4.5  
**Propósito:** Documentar uso autónomo de Gemini CLI para tareas complejas hasta su finalización

---

## 🎯 ¿Qué es el Modo Autónomo de Gemini CLI?

Google Gemini CLI puede ejecutar **tareas complejas de forma autónoma**, con **3 modos de aprobación configurables**, ejecutando múltiples comandos, leyendo/escribiendo archivos y generando reportes completos **hasta dar correcto término a la tarea**.

**Diferencia clave vs Copilot CLI:**
- **✅ Gemini:** 3 modos aprobación (default, auto_edit, yolo) + sandbox + output JSON nativo
- **⚠️ Copilot:** 1 modo autónomo (-d) menos flexible

**Ventajas sobre Copilot:**
| Característica | Copilot CLI | Gemini CLI |
|----------------|-------------|------------|
| Modos aprobación | 1 (-d) | 3 (default/auto_edit/yolo) |
| Sandbox | No | Sí (-s) |
| Output JSON | No nativo | Sí (--output-format json) |
| Modelos | 1 (GPT-4) | 3 (flash-lite/flash/pro) |
| Context window | 128K | 1-2M tokens |
| Costo | $$$$ | $ (76% más barato) |

---

## 📦 Instalación y Configuración

### Requisitos Previos

- **Cuenta:** Google AI Studio / Vertex AI
- **Node.js:** ≥ v18
- **npm:** ≥ v9
- **API Key:** Google AI Studio

### Instalación

```bash
# Instalar Gemini CLI globalmente
npm install -g @google/gemini-cli

# Verificar instalación
gemini --version
# Output: 0.14.0

# Autenticar (primera vez)
gemini
# Sigue instrucciones OAuth en navegador
```

### Verificar Autenticación

```bash
# Probar comando simple
gemini "¿Cuál es la capital de Chile?"
# Output: La capital de Chile es Santiago.

# Verificar credenciales cacheadas
ls -la ~/.gemini/
# Debe existir: credentials.json
```

---

## 🚀 Modos de Operación

### 1. Modo Default (Aprobación Manual)

**Uso:** Desarrollo interactivo, exploración, tareas sensibles

```bash
# Iniciar sesión interactiva
gemini

# O prompt directo (solicita aprobación en cada tool call)
gemini "Audita módulo l10n_cl_dte contra checklist Odoo 19"

# Gemini solicita aprobación en cada comando
Gemini: Voy a ejecutar:
  read_file("addons/localization/l10n_cl_dte/models/account_move.py")
¿Aprobar? (y/n): y

[Ejecuta comando, muestra resultados]

Gemini: Siguiente comando:
  run_terminal_cmd("grep -rn 't-esc' addons/localization/l10n_cl_dte/")
¿Aprobar? (y/n): y

[... continúa hasta completar tarea ...]
```

**Ventajas:**
- ✅ Control total sobre cada acción
- ✅ Seguro para operaciones destructivas
- ✅ Aprendizaje de comandos ejecutados

**Desventajas:**
- ❌ Lento para tareas largas (20-50 aprobaciones)
- ❌ Requiere atención constante
- ❌ NO puede ejecutarse en CI/CD

---

### 2. Modo Auto-Edit (Semi-Autónomo) ⭐ RECOMENDADO

**Uso:** Balance entre control y velocidad - **ideal para desarrollo**

```bash
# Auto-aprueba ediciones de código, pregunta para el resto
gemini --approval-mode auto_edit "Audita y corrige deprecaciones Odoo 19 en l10n_cl_dte"

# Comportamiento:
# ✅ Auto-aprueba: read_file, write, search_replace
# ❌ Pregunta: run_terminal_cmd (git, rm, docker, etc.)
```

**Ejemplo ejecución:**

```bash
$ gemini --approval-mode auto_edit "Reemplaza todas las ocurrencias de t-esc por t-out en views/"

Gemini: Leyendo archivos views/*.xml ... ✓ (auto-aprobado)
Gemini: Aplicando cambios en views/account_move_views.xml ... ✓ (auto-aprobado)
Gemini: 12 archivos modificados ✓ (auto-aprobado)

Gemini: Quiero ejecutar tests de validación:
  pytest addons/localization/l10n_cl_dte/tests/
¿Aprobar? (y/n): y

[Ejecuta tests, muestra resultados]

✅ Tarea completada: 12 archivos actualizados, tests passing.
```

**Ventajas:**
- ✅ Rápido para ediciones de código (auto-aprueba)
- ✅ Seguro para comandos shell (pregunta)
- ✅ Balance óptimo control/velocidad
- ✅ Ideal para ciclos autónomos con restricciones

**Configuración recomendada orquestador:**
```yaml
nivel_autonomia: semi_autonomous
gemini_approval_mode: auto_edit  # ← Mapeo directo
```

---

### 3. Modo YOLO (100% Autónomo) 🚀

**Uso:** Tareas repetitivas, CI/CD, auditorías read-only, alta confianza

```bash
# YOLO = You Only Live Once (auto-aprueba TODO sin preguntar)
gemini --yolo "Audita módulo ai_service y genera reporte JSON"

# O equivalente con --approval-mode
gemini --approval-mode yolo "Audita módulo ai_service"
```

**Ejemplo ejecución:**

```bash
$ gemini --yolo "Lista archivos .sh en lib/ y cuenta cuántos hay"

YOLO mode is enabled. All tool calls will be automatically approved.
Loaded cached credentials.

[Ejecuta list_dir automáticamente]
[Ejecuta conteo automáticamente]

En el directorio lib/ hay 4 archivos .sh.

✅ Tarea completada en 2.6s (0 aprobaciones solicitadas)
```

**Ventajas:**
- ✅ **Máxima velocidad** (sin intervención humana)
- ✅ Ideal para **CI/CD pipelines**
- ✅ Perfecto para **auditorías read-only**
- ✅ Reproducible y automatizable

**Desventajas:**
- ⚠️ **Sin control** sobre acciones destructivas
- ⚠️ Requiere alta confianza en prompt
- ⚠️ Usar **SOLO** con restricciones claras

**Configuración recomendada orquestador:**
```yaml
nivel_autonomia: full_autonomous
gemini_approval_mode: yolo  # ← 100% autónomo
restricciones:
  - "NO eliminar archivos"
  - "NO modificar __manifest__.py"
  - "NO ejecutar git push"
```

---

## 🔒 Modo Sandbox (Ejecución Segura)

**Propósito:** Ejecutar código con **restricciones de seguridad** (prevenir daños)

```bash
# Ejecutar en sandbox (macOS seatbelt profile: permissive-open)
gemini --sandbox "Prueba crear archivo test.txt con texto 'Hola'"

# Output:
using macos seatbelt (profile: permissive-open) ...
Error: Tool "write_file" not found in registry (bloqueado por sandbox)
```

**Características sandbox:**
- ✅ Bloquea herramientas destructivas (write_file, delete_file)
- ✅ Permite lectura (read_file, list_dir, grep)
- ✅ Bloquea modificaciones git (.git/)
- ✅ Ideal para auditorías sin riesgo

**Uso recomendado:**

```bash
# Auditoría 100% segura (read-only)
gemini --sandbox --yolo "Audita módulo l10n_cl_dte y genera reporte"

# Combinación poderosa:
# - --sandbox: Sin modificaciones
# - --yolo: Sin aprobaciones
# = Auditoría rápida y segura ✓
```

**Configuración orquestador:**
```yaml
fases:
  auditoria_inicial:
    sandbox: true        # Read-only, seguro
    approval_mode: yolo  # Rápido
    
  cerrar_brecha:
    sandbox: false       # Necesita modificar código
    approval_mode: auto_edit  # Control ediciones
```

---

## 🎨 Selección de Modelos

### Modelos Disponibles (3)

| Modelo | Velocidad | Latencia | Context | Costo | Uso Recomendado |
|--------|-----------|----------|---------|-------|-----------------|
| **gemini-2.5-flash-lite** | ⚡⚡⚡ | ~3.4s | 1M | $ | Validaciones rápidas |
| **gemini-2.5-flash** | ⚡⚡ | ~2.6s | 1M | $$ | Balance óptimo (80% tareas) |
| **gemini-2.5-pro** | 🐌 | ~40s | 2M | $$$$ | Razonamiento profundo |

### Cómo Seleccionar Modelo

```bash
# Por defecto (auto-selección)
gemini "tu prompt"

# Flash (recomendado para mayoría)
gemini -m gemini-2.5-flash "cierra brechas P0"

# Pro (análisis profundo)
gemini -m gemini-2.5-pro "auditoría P4-Deep completa"

# Flash-lite (ultra rápido)
gemini -m gemini-2.5-flash-lite "valida sintaxis XML"
```

### Estrategia por Fase (Orquestador)

```yaml
# config/ai_service.yml (Gemini optimizado)

gemini_config:
  modelo_default: gemini-2.5-flash
  
  modelos_por_fase:
    auditoria_inicial:
      modelo: gemini-2.5-pro        # Análisis profundo
      justificacion: "P4-Deep requiere razonamiento complejo"
      latencia_esperada: 40s
      
    identificar_brechas:
      modelo: gemini-2.5-flash      # Balance
      justificacion: "Priorización no requiere extrema profundidad"
      latencia_esperada: 3s
      
    cerrar_brecha_simple:
      modelo: gemini-2.5-flash      # Rápido
      criterio: "complejidad == 'baja' OR tipo == 'regex'"
      latencia_esperada: 3s
      
    cerrar_brecha_compleja:
      modelo: gemini-2.5-pro        # Profundo
      criterio: "complejidad == 'alta' OR tipo == 'arquitectonico'"
      latencia_esperada: 40s
      
    validacion_final:
      modelo: gemini-2.5-pro        # Exhaustiva
      justificacion: "Decisión final crítica"
      latencia_esperada: 40s
      
    consolidacion:
      modelo: gemini-2.5-flash-lite # Ultra rápido
      justificacion: "Solo agregar resultados"
      latencia_esperada: 3s
```

**Ahorro estimado:**
- Usar `flash` en vez de `pro` siempre: **$0.60 → $0.20** (67% ahorro)
- Estrategia mixta (80% flash, 20% pro): **$0.60 → $0.25** (58% ahorro) ✅

---

## 📊 Output Formats (Machine-Readable)

### 1. Text (Default - Legible Humanos)

```bash
gemini "Resume qué es Odoo"
# Output:
# Odoo es un conjunto de aplicaciones de gestión empresarial
# de código abierto...
```

**Uso:** Reportes markdown, lectura humana

---

### 2. JSON (Estructurado - Parsing Automático) ⭐

```bash
gemini --output-format json "Lista 3 países más poblados Sudamérica"

# Output:
{
  "response": "Los 3 países más poblados son:\n1. Brasil...",
  "stats": {
    "models": {
      "gemini-2.5-flash": {
        "api": {
          "totalRequests": 1,
          "totalLatencyMs": 2562
        },
        "tokens": {
          "prompt": 1406,
          "candidates": 45,
          "total": 1451
        }
      }
    },
    "tools": {
      "totalCalls": 1,
      "byName": {
        "google_web_search": { "count": 1, "success": 1 }
      }
    }
  }
}
```

**Uso:**
- ✅ Parsing automático resultados
- ✅ Extracción métricas (tokens, latencia)
- ✅ Integración CI/CD
- ✅ Dashboard en tiempo real

**Ejemplo parsing:**

```bash
# Extraer solo la respuesta
gemini --output-format json "prompt" | jq -r '.response'

# Extraer tokens usados
gemini --output-format json "prompt" | jq '.stats.models | to_entries[0].value.tokens.total'

# Extraer herramientas usadas
gemini --output-format json "prompt" | jq '.stats.tools.byName | keys[]'
```

---

### 3. Stream JSON (Eventos Real-Time) 🔥

```bash
gemini --output-format stream-json "Explica brevemente Odoo"

# Output (streaming):
{"type":"init","session_id":"ec6bd35c-...","model":"auto"}
{"type":"message","role":"user","content":"Explica..."}
{"type":"message","role":"assistant","content":"Odoo es...","delta":true}
{"type":"message","role":"assistant","content":"...empresarial","delta":true}
{"type":"result","status":"success","stats":{...}}
```

**Uso:**
- ✅ Progress bars en tiempo real
- ✅ Feedback usuario (% completado)
- ✅ Streaming responses largas
- ✅ Monitoring ejecuciones

**Ejemplo consumo streaming:**

```bash
gemini --output-format stream-json "prompt largo" | while IFS= read -r line; do
    type=$(echo "$line" | jq -r '.type')
    case "$type" in
        "init")
            echo "🚀 Iniciando..."
            ;;
        "message")
            role=$(echo "$line" | jq -r '.role')
            if [ "$role" = "assistant" ]; then
                echo -n "."  # Progress dot
            fi
            ;;
        "result")
            echo ""
            echo "✅ Completado"
            ;;
    esac
done
```

---

## 🔧 Allowed Tools (Whitelist)

**Propósito:** Restringir herramientas disponibles (seguridad + control)

```bash
# Solo lectura (auditoría segura)
gemini --allowed-tools read_file,list_dir,grep "audita sin modificar"

# Solo edición archivos (sin shell)
gemini --allowed-tools read_file,write,search_replace "corrige código"

# Completo (desarrollo)
gemini --allowed-tools read_file,write,run_terminal_cmd "desarrolla feature"
```

### Herramientas Disponibles

| Tool | Descripción | Riesgo |
|------|-------------|--------|
| `read_file` | Leer archivos | Bajo ✅ |
| `list_dir` | Listar directorios | Bajo ✅ |
| `search_file_content` | Buscar en archivos | Bajo ✅ |
| `grep` | Búsqueda regex | Bajo ✅ |
| `write` | Escribir archivos | Medio ⚠️ |
| `search_replace` | Reemplazar texto | Medio ⚠️ |
| `run_terminal_cmd` | Ejecutar shell | Alto 🔴 |
| `delete_file` | Eliminar archivos | Alto 🔴 |

### Configuración por Modificación Código

```yaml
# config/ai_service.yml

allowed_tools_por_modo:
  solo_generar:  # Sin modificar nada
    - read_file
    - list_dir
    - search_file_content
    - grep
    - codebase_search
    
  solo_fixes_simples:  # Regex/formateo
    - read_file
    - write
    - search_replace
    - run_terminal_cmd  # Solo black, isort, pytest
    
  con_restricciones:  # Desarrollo completo
    - read_file
    - write
    - search_replace
    - run_terminal_cmd
    # Excluir: delete_file, git (controlado por restricciones)
```

**Uso orquestador:**

```bash
# Mapear modificacion_codigo → allowed_tools
case "$MODIFICACION_CODIGO" in
    "solo_generar")
        ALLOWED_TOOLS="read_file,list_dir,grep,search_file_content"
        ;;
    "solo_fixes_simples")
        ALLOWED_TOOLS="read_file,write,search_replace,run_terminal_cmd"
        ;;
    "con_restricciones")
        ALLOWED_TOOLS="read_file,write,search_replace,run_terminal_cmd"
        ;;
esac

gemini --allowed-tools "$ALLOWED_TOOLS" "$PROMPT"
```

---

## 🎯 Casos de Uso Prácticos

### Caso 1: Auditoría P4-Deep (Segura + Rápida)

```bash
gemini \
  --model gemini-2.5-pro \
  --approval-mode yolo \
  --sandbox \
  --output-format json \
  --allowed-tools read_file,grep,list_dir \
  "$(cat docs/prompts/09_ciclos_autonomos/prompts/tipo_a_cierre_brechas/01_auditoria_inicial.md)

Contexto:
- Módulo: ai_service
- Sesión: $SESSION_ID
" > outputs/auditoria_ai_service.json

# Características:
# ✅ Pro: Análisis profundo
# ✅ YOLO: Sin aprobaciones (rápido)
# ✅ Sandbox: Sin modificaciones (seguro)
# ✅ JSON: Machine-readable
# ✅ Read-only tools: Solo lectura
# ⏱️ Tiempo: ~40s
```

---

### Caso 2: Cierre Brechas (Semi-Autónomo)

```bash
gemini \
  --model gemini-2.5-flash \
  --approval-mode auto_edit \
  --output-format json \
  --allowed-tools read_file,write,search_replace,run_terminal_cmd \
  "$(cat docs/prompts/09_ciclos_autonomos/prompts/tipo_a_cierre_brechas/03_cerrar_brecha.md)

Contexto:
- Brecha: P0-001 (t-esc deprecated)
- Archivo: views/account_move_views.xml
- Modificación permitida: con_restricciones
- Intento: 1/5
" > outputs/fix_P0_001.json

# Características:
# ✅ Flash: Rápido (2.6s)
# ✅ Auto-edit: Auto-aprueba edits, pregunta shell
# ✅ JSON: Parsing automático
# ✅ Tools: Permite modificar código
# ⏱️ Tiempo: ~3s + aprobaciones manuales
```

---

### Caso 3: Validación Final (Exhaustiva)

```bash
gemini \
  --model gemini-2.5-pro \
  --approval-mode default \
  --sandbox \
  --output-format json \
  "$(cat docs/prompts/09_ciclos_autonomos/prompts/tipo_a_cierre_brechas/04_validacion_final.md)

Contexto:
- Módulo: ai_service
- Auditoría inicial: outputs/auditoria_ai_service.json
- Criterios éxito: $(cat config/ai_service.yml | yq .criterios_exito)
" > outputs/validacion_final_ai_service.json

# Características:
# ✅ Pro: Validación exhaustiva
# ✅ Default: Aprobación manual (control)
# ✅ Sandbox: Sin modificar (validar estado)
# ✅ JSON: Métricas estructuradas
# ⏱️ Tiempo: ~40s + aprobaciones
```

---

### Caso 4: CI/CD Pipeline (100% Autónomo)

```bash
#!/bin/bash
# .github/workflows/audit_compliance.sh

set -e

MODULE=$1
SESSION_ID=$(date +%Y%m%d_%H%M%S)

echo "🔍 Auditando módulo: $MODULE"

gemini \
  --model gemini-2.5-flash \
  --yolo \
  --sandbox \
  --output-format json \
  --allowed-tools read_file,grep,list_dir,search_file_content \
  "Audita módulo $MODULE contra checklist Odoo 19 CE.
  
  Genera reporte JSON con:
  - compliance_P0 (%)
  - compliance_P1 (%)
  - brechas_detectadas (lista)
  - tests_coverage (%)
  - score_general (0-100)
  
  Módulo: addons/localization/$MODULE/" \
  > "outputs/${SESSION_ID}_audit_${MODULE}.json"

# Validar resultado
COMPLIANCE_P0=$(jq -r '.compliance_P0' "outputs/${SESSION_ID}_audit_${MODULE}.json")

if [ "$COMPLIANCE_P0" -lt 95 ]; then
    echo "❌ FALLO: Compliance P0 < 95% ($COMPLIANCE_P0%)"
    exit 1
else
    echo "✅ ÉXITO: Compliance P0 = $COMPLIANCE_P0%"
fi
```

---

## 🔄 Integración Orquestador (v1.1)

### Actualización `lib/execution_engine.sh`

```bash
#!/bin/bash
# lib/execution_engine.sh (actualizado para Gemini CLI)

ejecutar_fase_auditoria_inicial() {
    local fase="Auditoría Inicial"
    log_message INFO "Iniciando $fase con Gemini CLI"
    
    # Configuración Gemini
    local modelo=$(obtener_modelo_fase "auditoria_inicial")
    local approval_mode=$(mapear_nivel_autonomia)
    local allowed_tools="read_file,grep,list_dir,search_file_content,run_terminal_cmd"
    
    local prompt_file="$PROMPTS_DIR/tipo_a_cierre_brechas/01_auditoria_inicial.md"
    local prompt_content=$(cat "$prompt_file")
    local contexto="Módulo: $MODULO_TARGET\nSesión: $SESSION_ID"
    
    log_message DEBUG "Ejecutando con modelo: $modelo (approval: $approval_mode)"
    
    # Ejecutar con Gemini CLI
    local output=$(gemini \
        --model "$modelo" \
        --approval-mode "$approval_mode" \
        --sandbox \
        --output-format json \
        --allowed-tools "$allowed_tools" \
        --include-directories "addons/localization/$MODULO_TARGET" \
        "$prompt_content

Contexto:
$contexto" 2>&1)
    
    local exit_code=$?
    
    # Guardar resultado
    local resultado_file="$OUTPUTS_DIR/${SESSION_ID}_auditoria_inicial.json"
    echo "$output" > "$resultado_file"
    
    if [ $exit_code -eq 0 ]; then
        log_message SUCCESS "$fase completada exitosamente"
        
        # Extraer métricas (JSON nativo)
        AUDIT_COMPLIANCE_P0=$(jq -r '.compliance.P0' "$resultado_file" 2>/dev/null || echo "0")
        AUDIT_COMPLIANCE_P1=$(jq -r '.compliance.P1' "$resultado_file" 2>/dev/null || echo "0")
        
        log_message INFO "Compliance: P0=$AUDIT_COMPLIANCE_P0% P1=$AUDIT_COMPLIANCE_P1%"
        
        return 0
    else
        log_message ERROR "$fase falló (código: $exit_code)"
        handle_fase_failure "$fase" "$output"
        return 1
    fi
}

# Mapear nivel autonomía → approval mode Gemini
mapear_nivel_autonomia() {
    case "$NIVEL_AUTONOMIA" in
        "full_autonomous")
            echo "yolo"
            ;;
        "semi_autonomous")
            echo "auto_edit"
            ;;
        "critical_approval")
            echo "default"
            ;;
        *)
            echo "default"
            ;;
    esac
}

# Obtener modelo según fase
obtener_modelo_fase() {
    local fase=$1
    
    # Leer de config YAML (con yq)
    local modelo=$(yq eval ".gemini_config.modelos_por_fase.$fase.modelo" "$CONFIG_FILE" 2>/dev/null)
    
    # Fallback a default
    if [ -z "$modelo" ] || [ "$modelo" = "null" ]; then
        modelo=$(yq eval ".gemini_config.modelo_default" "$CONFIG_FILE" 2>/dev/null)
    fi
    
    # Fallback final
    if [ -z "$modelo" ] || [ "$modelo" = "null" ]; then
        modelo="gemini-2.5-flash"
    fi
    
    echo "$modelo"
}
```

---

## 📚 Comandos Quick Reference

```bash
# ═══════════════════════════════════════════════════════════════
# GEMINI CLI - QUICK REFERENCE
# ═══════════════════════════════════════════════════════════════

# Instalación
npm install -g @google/gemini-cli
gemini --version

# Prompt simple
gemini "tu pregunta"

# Con modelo específico
gemini -m gemini-2.5-flash "prompt"
gemini -m gemini-2.5-pro "análisis profundo"
gemini -m gemini-2.5-flash-lite "validación rápida"

# Output formats
gemini --output-format text "prompt"      # Default
gemini --output-format json "prompt"      # Machine-readable
gemini --output-format stream-json "prompt"  # Real-time

# Approval modes
gemini "prompt"                              # Default (pregunta)
gemini --approval-mode auto_edit "prompt"    # Semi-autónomo
gemini --yolo "prompt"                       # 100% autónomo
gemini --approval-mode yolo "prompt"         # Equivalente

# Sandbox (seguro)
gemini --sandbox "prompt"
gemini -s "prompt"

# Allowed tools (restricción)
gemini --allowed-tools read_file,grep "prompt"

# Debug mode
gemini --debug "prompt"
gemini -d "prompt"

# Include directories (contexto)
gemini --include-directories dir1,dir2 "prompt"

# Combinaciones poderosas
gemini -m gemini-2.5-pro --yolo --sandbox -o json "audit"
gemini -m gemini-2.5-flash --approval-mode auto_edit "fix"
gemini -m gemini-2.5-flash-lite --yolo -o json "validate"

# Extensiones
gemini --list-extensions
gemini -l

# Help
gemini --help
gemini -h
```

---

## 🆚 Comparación: Gemini CLI vs Copilot CLI

| Característica | Copilot CLI | Gemini CLI | Ganador |
|----------------|-------------|------------|---------|
| **Modos aprobación** | 1 (-d) | 3 (default/auto_edit/yolo) | ✅ Gemini |
| **Sandbox** | No | Sí (-s) | ✅ Gemini |
| **Output JSON** | No nativo | Sí (--output-format) | ✅ Gemini |
| **Stream JSON** | No | Sí (--output-format stream-json) | ✅ Gemini |
| **Modelos** | 1 (GPT-4) | 3 (lite/flash/pro) | ✅ Gemini |
| **Context window** | 128K | 1-2M tokens | ✅ Gemini |
| **Allowed tools** | No | Sí (--allowed-tools) | ✅ Gemini |
| **Debug mode** | No explícito | Sí (-d) | ✅ Gemini |
| **Include dirs** | No | Sí (--include-directories) | ✅ Gemini |
| **Costo** | $$$$ | $ (76% cheaper) | ✅ Gemini |
| **Velocidad flash** | N/A | 2.6s | ✅ Gemini |
| **Madurez** | Más estable | Más nuevo | ⚖️ Empate |

**Score:** Gemini CLI **11-1** Copilot CLI

**Recomendación:** ✅ **Migrar a Gemini CLI en v1.1** (Diciembre 2025)

---

## 🎓 Best Practices

### ✅ DO (Hacer)

1. **Usar approval-mode según contexto:**
   - `default`: Tareas sensibles, aprendizaje
   - `auto_edit`: Desarrollo productivo (80% casos)
   - `yolo`: CI/CD, auditorías read-only

2. **Combinar sandbox + yolo para auditorías:**
   ```bash
   gemini --sandbox --yolo -o json "audita módulo"
   # = Rápido + Seguro ✓
   ```

3. **Seleccionar modelo apropiado:**
   - `flash`: 80% tareas (default)
   - `pro`: Auditorías, validaciones, diseño
   - `flash-lite`: Validaciones ultra-rápidas

4. **Usar output JSON para parsing:**
   ```bash
   gemini -o json "prompt" | jq -r '.response'
   ```

5. **Restringir tools según necesidad:**
   ```bash
   gemini --allowed-tools read_file,grep "audit"
   # = Solo lectura, seguro
   ```

### ❌ DON'T (Evitar)

1. **NO usar yolo sin restricciones claras:**
   ```bash
   # ❌ MAL
   gemini --yolo "haz lo que sea necesario"
   
   # ✅ BIEN
   gemini --yolo --sandbox --allowed-tools read_file,grep "audita"
   ```

2. **NO usar pro para tareas simples:**
   ```bash
   # ❌ MAL (15x más lento, 12x más caro)
   gemini -m gemini-2.5-pro "cuenta archivos .sh"
   
   # ✅ BIEN
   gemini -m gemini-2.5-flash-lite "cuenta archivos .sh"
   ```

3. **NO ignorar output format:**
   ```bash
   # ❌ MAL (difícil parsing)
   result=$(gemini "análisis" | grep "score")
   
   # ✅ BIEN
   score=$(gemini -o json "análisis" | jq -r '.score')
   ```

4. **NO mezclar allowed-tools con modificación:**
   ```bash
   # ❌ MAL (inconsistente)
   gemini --allowed-tools read_file,grep --approval-mode yolo "corrige código"
   # ^ Sin write tool, no puede corregir
   
   # ✅ BIEN
   gemini --allowed-tools read_file,write,search_replace --approval-mode auto_edit "corrige"
   ```

---

## 📖 Referencias

- **Gemini CLI Docs:** https://geminicli.com/docs/
- **Gemini API:** https://ai.google.dev/gemini-api/docs
- **Modelos Gemini:** https://ai.google.dev/gemini-api/docs/models
- **Orquestador:** `/docs/prompts/09_ciclos_autonomos/README.md`
- **Copilot CLI:** `/docs/prompts/COPILOT_CLI_AUTONOMO.md`

---

## 🤝 Soporte

- **GitHub Issues:** https://github.com/eergygroup/odoo19ce/issues
- **Email:** pwills85@gmail.com
- **Slack:** #odoo-desarrollo (interno EERGYGROUP)

---

**🚀 Gemini CLI - El sucesor natural de Copilot CLI para ciclos autónomos**

_Documentación v1.0.0 - 2025-11-12_

