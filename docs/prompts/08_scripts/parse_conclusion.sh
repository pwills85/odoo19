#!/bin/bash
# parse_conclusion.sh - Parsea CONCLUSIÓN de Claude (3 líneas esperadas)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROPÓSITO:
#   Parsear output minimalista de Claude y extraer decisión estratégica.
#   Validación estricta de formato y valores permitidos.
#
# USO:
#   source ./parse_conclusion.sh <CONCLUSION_FILE>
#   # Variables exportadas: CMO_DECISION, CMO_REASON, CMO_NEXT_ACTION
#
# EJEMPLO:
#   source ./parse_conclusion.sh /tmp/conclusion_3.txt
#   echo "Decision: $CMO_DECISION"
#   echo "Next action: $CMO_NEXT_ACTION"
#
# OUTPUT:
#   Variables de entorno exportadas para el caller
#
# AUTOR: Pedro Troncoso + Claude Code
# FECHA: 2025-11-13
# VERSIÓN: 2.1.0
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ════════════════════════════════════════════════════════════════

CONCLUSION_FILE="${1:?Error: CONCLUSION_FILE required. Usage: source $0 <conclusion_file>}"

# Colores para logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ════════════════════════════════════════════════════════════════
# FUNCIONES UTILIDAD
# ════════════════════════════════════════════════════════════════

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    case "$level" in
        ERROR)
            echo -e "${RED}[ERROR]${NC} $timestamp $message" >&2
            ;;
        SUCCESS)
            echo -e "${GREEN}[OK]${NC} $timestamp $message"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARN]${NC} $timestamp $message"
            ;;
        *)
            echo "[INFO] $timestamp $message"
            ;;
    esac
}

# ════════════════════════════════════════════════════════════════
# VALIDACIÓN DE ARCHIVO
# ════════════════════════════════════════════════════════════════

if [ ! -f "$CONCLUSION_FILE" ]; then
    log ERROR "CONCLUSION_FILE not found: $CONCLUSION_FILE"
    return 1 2>/dev/null || exit 1
fi

if [ ! -s "$CONCLUSION_FILE" ]; then
    log ERROR "CONCLUSION_FILE is empty: $CONCLUSION_FILE"
    return 1 2>/dev/null || exit 1
fi

# ════════════════════════════════════════════════════════════════
# PARSING DE CAMPOS
# ════════════════════════════════════════════════════════════════

# Parsear DECISION (campo obligatorio)
DECISION=$(grep -i "^DECISION:" "$CONCLUSION_FILE" | head -1 | cut -d: -f2- | xargs)

# Parsear REASON (campo opcional pero recomendado)
REASON=$(grep -i "^REASON:" "$CONCLUSION_FILE" | head -1 | cut -d: -f2- | xargs)

# Parsear NEXT_ACTION (campo obligatorio si DECISION=continue)
NEXT_ACTION=$(grep -i "^NEXT_ACTION:" "$CONCLUSION_FILE" | head -1 | cut -d: -f2- | xargs)

# ════════════════════════════════════════════════════════════════
# VALIDACIÓN DE CAMPOS OBLIGATORIOS
# ════════════════════════════════════════════════════════════════

if [ -z "$DECISION" ]; then
    log ERROR "DECISION field missing in CONCLUSION_FILE"
    log ERROR "Expected format:"
    log ERROR "  DECISION: [continue|stop|escalate]"
    log ERROR "  REASON: [one sentence]"
    log ERROR "  NEXT_ACTION: [action_name]"
    return 1 2>/dev/null || exit 1
fi

# ════════════════════════════════════════════════════════════════
# VALIDACIÓN DE VALORES PERMITIDOS
# ════════════════════════════════════════════════════════════════

# Normalizar DECISION (lowercase)
DECISION=$(echo "$DECISION" | tr '[:upper:]' '[:lower:]')

case "$DECISION" in
    "continue")
        log SUCCESS "Valid DECISION: continue"
        
        # Si DECISION=continue, NEXT_ACTION es obligatorio
        if [ -z "$NEXT_ACTION" ]; then
            log ERROR "NEXT_ACTION required when DECISION=continue"
            log ERROR "Valid actions: close_gaps_p0, close_gaps_p1, enhance, test, re_audit"
            return 1 2>/dev/null || exit 1
        fi
        
        # Normalizar NEXT_ACTION (lowercase)
        NEXT_ACTION=$(echo "$NEXT_ACTION" | tr '[:upper:]' '[:lower:]')
        
        # Validar NEXT_ACTION contra valores permitidos
        case "$NEXT_ACTION" in
            "close_gaps_p0"|"close_gaps_p1"|"enhance"|"test"|"re_audit"|"develop")
                log SUCCESS "Valid NEXT_ACTION: $NEXT_ACTION"
                ;;
            *)
                log ERROR "Invalid NEXT_ACTION: $NEXT_ACTION"
                log ERROR "Allowed: [close_gaps_p0|close_gaps_p1|enhance|test|re_audit|develop]"
                return 1 2>/dev/null || exit 1
                ;;
        esac
        ;;
    
    "stop")
        log SUCCESS "Valid DECISION: stop"
        # NEXT_ACTION no es necesario para stop
        ;;
    
    "escalate")
        log SUCCESS "Valid DECISION: escalate"
        # NEXT_ACTION no es necesario para escalate
        ;;
    
    *)
        log ERROR "Invalid DECISION: $DECISION"
        log ERROR "Allowed: [continue|stop|escalate]"
        return 1 2>/dev/null || exit 1
        ;;
esac

# ════════════════════════════════════════════════════════════════
# EXPORTAR VARIABLES
# ════════════════════════════════════════════════════════════════

export CMO_DECISION="$DECISION"
export CMO_REASON="$REASON"
export CMO_NEXT_ACTION="$NEXT_ACTION"

# Logging de resultado
log INFO "Parsed CONCLUSION successfully:"
log INFO "  DECISION: $CMO_DECISION"
if [ -n "$CMO_REASON" ]; then
    log INFO "  REASON: $CMO_REASON"
fi
if [ -n "$CMO_NEXT_ACTION" ]; then
    log INFO "  NEXT_ACTION: $CMO_NEXT_ACTION"
fi

# ════════════════════════════════════════════════════════════════
# VALIDACIÓN DE CONSISTENCIA
# ════════════════════════════════════════════════════════════════

# Validar que REASON no esté vacío (warning, no error)
if [ -z "$CMO_REASON" ]; then
    log WARNING "REASON field is empty. Recommended to provide rationale."
fi

# Validar que REASON no sea demasiado largo (> 200 chars)
if [ -n "$CMO_REASON" ] && [ ${#CMO_REASON} -gt 200 ]; then
    log WARNING "REASON is too long (${#CMO_REASON} chars). Keep it concise (< 200 chars)."
fi

# Éxito
return 0 2>/dev/null || exit 0
