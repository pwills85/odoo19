#!/bin/bash
# generate_consigna.sh - Genera CONSIGNA para Claude (contexto mínimo)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROPÓSITO:
#   Generar input para Claude con contexto MÍNIMO (10-15 líneas máximo)
#   para evitar token overload y compaction.
#
# USO:
#   ./generate_consigna.sh <STATE_FILE> <OUTPUT_FILE>
#
# EJEMPLO:
#   ./generate_consigna.sh /tmp/state.json /tmp/consigna_3.txt
#
# OUTPUT:
#   Archivo de texto plano con métricas clave (200 tokens máximo)
#
# AUTOR: Pedro Troncoso + Claude Code
# FECHA: 2025-11-13
# VERSIÓN: 2.1.0
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ════════════════════════════════════════════════════════════════

STATE_FILE="${1:?Error: STATE_FILE required. Usage: $0 <state_file> <output_file>}"
OUTPUT_FILE="${2:?Error: OUTPUT_FILE required. Usage: $0 <state_file> <output_file>}"

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
# VALIDACIÓN
# ════════════════════════════════════════════════════════════════

if [ ! -f "$STATE_FILE" ]; then
    log ERROR "STATE_FILE not found: $STATE_FILE"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    log ERROR "jq is required but not installed"
    exit 1
fi

# ════════════════════════════════════════════════════════════════
# LECTURA DE ESTADO
# ════════════════════════════════════════════════════════════════

ITERATION=$(jq -r '.iteration' "$STATE_FILE")
PREVIOUS_SCORE=$(jq -r '.previous_score' "$STATE_FILE")
CURRENT_SCORE=$(jq -r '.current_score' "$STATE_FILE")
TARGET_SCORE=$(jq -r '.target_score' "$STATE_FILE")
GAPS_P0=$(jq -r '.gaps_p0_open' "$STATE_FILE")
GAPS_P1=$(jq -r '.gaps_p1_open' "$STATE_FILE")
BUDGET_USED=$(jq -r '.budget_used_usd' "$STATE_FILE")
BUDGET_TOTAL=$(jq -r '.budget_total_usd' "$STATE_FILE")
TIME_ELAPSED=$(jq -r '.time_elapsed' "$STATE_FILE")

# Calcular métricas derivadas
SCORE_DELTA=$((CURRENT_SCORE - PREVIOUS_SCORE))
BUDGET_REMAINING=$(echo "$BUDGET_TOTAL - $BUDGET_USED" | bc -l)
PROGRESS_PERCENT=$(echo "scale=1; ($CURRENT_SCORE * 100) / $TARGET_SCORE" | bc -l)

# ════════════════════════════════════════════════════════════════
# CONTEXTO ESTRATÉGICO
# ════════════════════════════════════════════════════════════════

get_strategic_context() {
    local gaps_p0=$1
    local gaps_p1=$2
    local budget_remaining=$3
    local score_delta=$4
    local current_score=$5
    local target_score=$6
    
    # Prioridad 1: P0 gaps críticos
    if [ "$gaps_p0" -gt 0 ]; then
        if (( $(echo "$budget_remaining > 1.0" | bc -l) )); then
            echo "PRIORITY: P0 gaps exist ($gaps_p0). Budget allows closure."
            return
        else
            echo "CRITICAL: P0 gaps exist ($gaps_p0) but budget LOW. Evaluate carefully."
            return
        fi
    fi
    
    # Prioridad 2: Score stagnation
    if [ "$score_delta" -le 0 ]; then
        echo "WARNING: Score stagnation (delta: $score_delta). Consider different approach."
        return
    fi
    
    # Prioridad 3: Close to target
    local gap_to_target=$((target_score - current_score))
    if [ "$gap_to_target" -le 5 ]; then
        echo "NEAR TARGET: Only $gap_to_target points to goal. Final push."
        return
    fi
    
    # Prioridad 4: P1 gaps con budget suficiente
    if [ "$gaps_p1" -gt 0 ] && (( $(echo "$budget_remaining > 2.0" | bc -l) )); then
        echo "OPPORTUNITY: P1 gaps ($gaps_p1) and good budget. Consider P1 closure."
        return
    fi
    
    # Prioridad 5: Budget crítico
    if (( $(echo "$budget_remaining < 0.5" | bc -l) )); then
        echo "BUDGET CRITICAL: Only \$${budget_remaining} remaining. Consider stopping."
        return
    fi
    
    # Default: Standard iteration
    echo "STANDARD: Progress normal. Evaluate next action based on metrics."
}

STRATEGIC_CONTEXT=$(get_strategic_context "$GAPS_P0" "$GAPS_P1" "$BUDGET_REMAINING" "$SCORE_DELTA" "$CURRENT_SCORE" "$TARGET_SCORE")

# ════════════════════════════════════════════════════════════════
# GENERACIÓN DE CONSIGNA
# ════════════════════════════════════════════════════════════════

cat > "$OUTPUT_FILE" <<EOF
ITERATION: $ITERATION
PREVIOUS_SCORE: $PREVIOUS_SCORE
CURRENT_SCORE: $CURRENT_SCORE
TARGET_SCORE: $TARGET_SCORE
SCORE_DELTA: $SCORE_DELTA
PROGRESS: ${PROGRESS_PERCENT}%
GAPS_P0_OPEN: $GAPS_P0
GAPS_P1_OPEN: $GAPS_P1
BUDGET_USED: ${BUDGET_USED} USD
BUDGET_REMAINING: ${BUDGET_REMAINING} USD
BUDGET_TOTAL: ${BUDGET_TOTAL} USD
TIME_ELAPSED: $TIME_ELAPSED

QUESTION: Continue iterating or stop?
OPTIONS: [continue|stop|escalate]

STRATEGIC_CONTEXT:
$STRATEGIC_CONTEXT
EOF

# ════════════════════════════════════════════════════════════════
# VALIDACIÓN DE OUTPUT
# ════════════════════════════════════════════════════════════════

LINE_COUNT=$(wc -l < "$OUTPUT_FILE")
CHAR_COUNT=$(wc -c < "$OUTPUT_FILE")
ESTIMATED_TOKENS=$(echo "$CHAR_COUNT / 4" | bc)  # Rough estimation: 4 chars = 1 token

log SUCCESS "CONSIGNA generated: $OUTPUT_FILE"
log INFO "Lines: $LINE_COUNT | Chars: $CHAR_COUNT | Est. tokens: ~$ESTIMATED_TOKENS"

# Validar que no excedemos límite de tokens
if [ "$ESTIMATED_TOKENS" -gt 300 ]; then
    log WARNING "CONSIGNA exceeds 300 tokens target (current: $ESTIMATED_TOKENS)"
fi

# Validar que archivo no está vacío
if [ ! -s "$OUTPUT_FILE" ]; then
    log ERROR "Generated CONSIGNA is empty"
    exit 1
fi

exit 0
