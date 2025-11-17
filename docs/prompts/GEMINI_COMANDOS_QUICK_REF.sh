#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# 🚀 GEMINI CLI - COMANDOS QUICK REFERENCE
# ═══════════════════════════════════════════════════════════════════════════
# Versión: 1.0.0
# Fecha: 2025-11-12
# Autor: Pedro Troncoso (@pwills85) + Claude Sonnet 4.5
# Propósito: Referencia rápida comandos Gemini CLI para orquestador
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# INSTALACIÓN Y SETUP
# ═══════════════════════════════════════════════════════════════════════════

# Instalar globalmente
npm install -g @google/gemini-cli

# Verificar versión
gemini --version
# Output: 0.14.0

# Verificar instalación
which gemini
# Output: /opt/homebrew/bin/gemini (macOS) o /usr/local/bin/gemini (Linux)

# Autenticar (primera vez)
gemini
# > Sigue instrucciones OAuth en navegador

# Verificar credenciales
ls -la ~/.gemini/
# Debe existir: credentials.json

# ═══════════════════════════════════════════════════════════════════════════
# COMANDOS BÁSICOS
# ═══════════════════════════════════════════════════════════════════════════

# Prompt simple (posicional)
gemini "¿Cuál es la capital de Chile?"

# Modo interactivo
gemini
# > [Inicia sesión interactiva]

# Help
gemini --help
gemini -h

# Versión
gemini --version
gemini -v

# ═══════════════════════════════════════════════════════════════════════════
# MODELOS (3 DISPONIBLES)
# ═══════════════════════════════════════════════════════════════════════════

# Flash-lite (ultra rápido - 3.4s)
gemini -m gemini-2.5-flash-lite "validación simple"

# Flash (balance - 2.6s) ⭐ RECOMENDADO
gemini -m gemini-2.5-flash "análisis estándar"

# Pro (profundo - 40s)
gemini -m gemini-2.5-pro "auditoría P4-Deep"

# Auto-selección (default)
gemini "prompt"  # Selecciona modelo automáticamente

# ═══════════════════════════════════════════════════════════════════════════
# MODOS DE APROBACIÓN (3 OPCIONES)
# ═══════════════════════════════════════════════════════════════════════════

# 1. Default (pregunta siempre)
gemini "audita módulo"
gemini --approval-mode default "audita módulo"

# 2. Auto-edit (semi-autónomo) ⭐ RECOMENDADO
gemini --approval-mode auto_edit "corrige código"
# Auto-aprueba: read, write, search_replace
# Pregunta: run_terminal_cmd, git, docker

# 3. YOLO (100% autónomo)
gemini --yolo "audita módulo"
gemini --approval-mode yolo "audita módulo"
gemini -y "audita módulo"
# Auto-aprueba: TODO sin preguntar

# ═══════════════════════════════════════════════════════════════════════════
# SANDBOX MODE (EJECUCIÓN SEGURA)
# ═══════════════════════════════════════════════════════════════════════════

# Ejecutar en sandbox (restricciones)
gemini --sandbox "audita sin modificar"
gemini -s "audita sin modificar"

# Combinación poderosa: sandbox + yolo
gemini --sandbox --yolo "audita módulo"
# = Rápido + Seguro (read-only) ✓

# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATS (3 OPCIONES)
# ═══════════════════════════════════════════════════════════════════════════

# 1. Text (default - legible humanos)
gemini "explica Odoo"
gemini --output-format text "explica Odoo"
gemini -o text "explica Odoo"

# 2. JSON (estructurado - parsing) ⭐ RECOMENDADO CI/CD
gemini --output-format json "audita módulo"
gemini -o json "audita módulo"

# Ejemplo parsing JSON
gemini -o json "análisis" | jq -r '.response'
gemini -o json "análisis" | jq '.stats.models | keys[]'
gemini -o json "análisis" | jq '.stats.tools.totalCalls'

# 3. Stream JSON (real-time)
gemini --output-format stream-json "tarea larga"
gemini -o stream-json "tarea larga"

# Ejemplo consumo streaming
gemini -o stream-json "prompt" | while IFS= read -r line; do
    type=$(echo "$line" | jq -r '.type')
    case "$type" in
        "init") echo "🚀 Iniciando..." ;;
        "message") echo -n "." ;;
        "result") echo "✅ Completado" ;;
    esac
done

# ═══════════════════════════════════════════════════════════════════════════
# ALLOWED TOOLS (WHITELIST)
# ═══════════════════════════════════════════════════════════════════════════

# Solo lectura (auditoría segura)
gemini --allowed-tools read_file,list_dir,grep "audita sin modificar"

# Solo edición (sin shell commands)
gemini --allowed-tools read_file,write,search_replace "corrige código"

# Desarrollo completo
gemini --allowed-tools read_file,write,run_terminal_cmd "desarrolla feature"

# Ejemplos específicos
gemini --allowed-tools read_file,grep,search_file_content "busca patrón"
gemini --allowed-tools read_file,write,search_replace,run_terminal_cmd "fix completo"

# ═══════════════════════════════════════════════════════════════════════════
# DEBUG MODE
# ═══════════════════════════════════════════════════════════════════════════

# Activar debug (logs detallados)
gemini --debug "prompt"
gemini -d "prompt"

# Debug + output JSON
gemini -d -o json "análisis"

# ═══════════════════════════════════════════════════════════════════════════
# INCLUDE DIRECTORIES (CONTEXTO)
# ═══════════════════════════════════════════════════════════════════════════

# Incluir directorios específicos
gemini --include-directories addons/localization/l10n_cl_dte "audita DTE"

# Múltiples directorios
gemini --include-directories dir1,dir2,dir3 "análisis"
gemini --include-directories dir1 --include-directories dir2 "análisis"

# ═══════════════════════════════════════════════════════════════════════════
# EXTENSIONES
# ═══════════════════════════════════════════════════════════════════════════

# Listar extensiones disponibles
gemini --list-extensions
gemini -l

# Usar extensiones específicas
gemini --extensions ext1,ext2 "prompt"
gemini -e ext1,ext2 "prompt"

# ═══════════════════════════════════════════════════════════════════════════
# COMBINACIONES PODEROSAS
# ═══════════════════════════════════════════════════════════════════════════

# Auditoría rápida y segura (CI/CD)
gemini \
  -m gemini-2.5-flash \
  --yolo \
  --sandbox \
  -o json \
  --allowed-tools read_file,grep,list_dir \
  "audita módulo ai_service"

# Cierre brechas semi-autónomo
gemini \
  -m gemini-2.5-flash \
  --approval-mode auto_edit \
  -o json \
  --allowed-tools read_file,write,search_replace \
  "cierra brechas P0 en views/"

# Validación exhaustiva con control
gemini \
  -m gemini-2.5-pro \
  --approval-mode default \
  --sandbox \
  -o json \
  "valida compliance final"

# Análisis profundo con contexto específico
gemini \
  -m gemini-2.5-pro \
  --yolo \
  -o json \
  --include-directories addons/localization/l10n_cl_dte \
  "auditoría P4-Deep DTE"

# ═══════════════════════════════════════════════════════════════════════════
# CASOS DE USO ORQUESTADOR
# ═══════════════════════════════════════════════════════════════════════════

# FASE 1: Auditoría Inicial
gemini \
  -m gemini-2.5-pro \
  --yolo \
  --sandbox \
  -o json \
  --allowed-tools read_file,grep,list_dir,search_file_content,run_terminal_cmd \
  --include-directories "addons/localization/$MODULO" \
  "$(cat prompts/tipo_a_cierre_brechas/01_auditoria_inicial.md)
  
Contexto:
- Módulo: $MODULO
- Sesión: $SESSION_ID
" > outputs/auditoria_${MODULO}.json

# FASE 2: Identificar Brechas
gemini \
  -m gemini-2.5-flash \
  --yolo \
  -o json \
  --allowed-tools read_file,grep,search_file_content \
  "$(cat prompts/tipo_a_cierre_brechas/02_identificar_brechas.md)
  
Contexto:
- Módulo: $MODULO
- Auditoría: outputs/auditoria_${MODULO}.json
" > outputs/brechas_${MODULO}.json

# FASE 3: Cerrar Brecha (Simple)
gemini \
  -m gemini-2.5-flash \
  --approval-mode auto_edit \
  -o json \
  --allowed-tools read_file,write,search_replace \
  "$(cat prompts/tipo_a_cierre_brechas/03_cerrar_brecha.md)
  
Contexto:
- Brecha: P0-001
- Tipo: regex_simple
- Intento: 1/5
" > outputs/fix_P0_001.json

# FASE 3: Cerrar Brecha (Compleja)
gemini \
  -m gemini-2.5-pro \
  --approval-mode auto_edit \
  -o json \
  --allowed-tools read_file,write,search_replace,run_terminal_cmd \
  "$(cat prompts/tipo_a_cierre_brechas/03_cerrar_brecha.md)
  
Contexto:
- Brecha: P0-005
- Tipo: refactor_arquitectonico
- Intento: 2/5
" > outputs/fix_P0_005.json

# FASE 4: Validación Final
gemini \
  -m gemini-2.5-pro \
  --yolo \
  --sandbox \
  -o json \
  --allowed-tools read_file,grep,run_terminal_cmd \
  "$(cat prompts/tipo_a_cierre_brechas/04_validacion_final.md)
  
Contexto:
- Módulo: $MODULO
- Auditoría inicial: outputs/auditoria_${MODULO}.json
- Criterios: $(cat config/${MODULO}.yml | yq .criterios_exito)
" > outputs/validacion_${MODULO}.json

# FASE 5: Consolidación
gemini \
  -m gemini-2.5-flash-lite \
  --yolo \
  -o text \
  "$(cat prompts/tipo_a_cierre_brechas/05_consolidacion.md)
  
Contexto:
- Módulo: $MODULO
- Sesión: $SESSION_ID
- Resultados: outputs/${SESSION_ID}_*.json
" > outputs/reporte_consolidado_${MODULO}.md

# ═══════════════════════════════════════════════════════════════════════════
# CI/CD PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

# Script CI/CD completo
#!/bin/bash
set -e

MODULE=$1
SESSION_ID=$(date +%Y%m%d_%H%M%S)

echo "🔍 Auditando módulo: $MODULE"

# Auditar
gemini \
  -m gemini-2.5-flash \
  --yolo \
  --sandbox \
  -o json \
  --allowed-tools read_file,grep,list_dir \
  "Audita módulo $MODULE contra checklist Odoo 19 CE compliance.
  
  Genera JSON con:
  - compliance_P0 (%)
  - compliance_P1 (%)
  - brechas_detectadas (lista)
  - score_general (0-100)
  
  Módulo: addons/localization/$MODULE/" \
  > "outputs/${SESSION_ID}_audit_${MODULE}.json"

# Validar resultado
COMPLIANCE_P0=$(jq -r '.compliance_P0' "outputs/${SESSION_ID}_audit_${MODULE}.json")

if [ "$COMPLIANCE_P0" -lt 95 ]; then
    echo "❌ FALLO: Compliance P0 < 95% ($COMPLIANCE_P0%)"
    exit 1
fi

echo "✅ ÉXITO: Compliance P0 = $COMPLIANCE_P0%"

# ═══════════════════════════════════════════════════════════════════════════
# UTILIDADES COMUNES
# ═══════════════════════════════════════════════════════════════════════════

# Extraer respuesta de JSON
gemini -o json "prompt" | jq -r '.response'

# Extraer tokens usados
gemini -o json "prompt" | jq '.stats.models | to_entries[0].value.tokens.total'

# Extraer latencia
gemini -o json "prompt" | jq '.stats.models | to_entries[0].value.api.totalLatencyMs'

# Extraer herramientas usadas
gemini -o json "prompt" | jq '.stats.tools.byName | keys[]'

# Contar tool calls
gemini -o json "prompt" | jq '.stats.tools.totalCalls'

# Verificar éxito
gemini -o json "prompt" | jq -r '.stats.tools.totalSuccess'

# ═══════════════════════════════════════════════════════════════════════════
# TROUBLESHOOTING
# ═══════════════════════════════════════════════════════════════════════════

# Error autenticación
# Error: No authentication information found
# Solución:
gemini  # Iniciar y seguir OAuth

# Error modelo no encontrado
# Error: Model not found
# Solución: Usar modelos disponibles (flash-lite, flash, pro)

# Error sandbox
# Error: Tool "write_file" not found in registry
# Esperado: Sandbox bloquea write tools

# Error timeout
# Error: Request timeout
# Solución: Usar modelo más rápido (flash en vez de pro)

# ═══════════════════════════════════════════════════════════════════════════
# BEST PRACTICES
# ═══════════════════════════════════════════════════════════════════════════

# ✅ HACER:
# 1. Usar flash para 80% tareas (balance)
# 2. Usar pro solo para análisis profundo
# 3. Combinar sandbox + yolo para auditorías
# 4. Usar output JSON para CI/CD
# 5. Restringir tools según necesidad

# ❌ EVITAR:
# 1. Usar pro para tareas simples (15x más lento)
# 2. Usar yolo sin restricciones claras
# 3. Ignorar output format (dificulta parsing)
# 4. No combinar sandbox con modificaciones
# 5. Mixing allowed-tools incorrectamente

# ═══════════════════════════════════════════════════════════════════════════
# REFERENCIAS
# ═══════════════════════════════════════════════════════════════════════════

# Documentación completa:
# /docs/prompts/GEMINI_CLI_AUTONOMO.md

# Orquestador:
# /docs/prompts/09_ciclos_autonomos/README.md

# Configuración módulos:
# /docs/prompts/09_ciclos_autonomos/config/*.yml

# ═══════════════════════════════════════════════════════════════════════════
# FIN QUICK REFERENCE
# ═══════════════════════════════════════════════════════════════════════════

