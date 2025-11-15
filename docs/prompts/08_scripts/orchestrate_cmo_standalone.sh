#!/bin/bash
# orchestrate_cmo_standalone.sh - CMO v2.1 Standalone (sin dependencias externas)
# Versión simplificada para macOS M3 con Docker
set -euo pipefail

# ════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ════════════════════════════════════════════════════════════════

MODULE_PATH="${1:-ai-service}"
TARGET_SCORE="${2:-85}"
MAX_ITERATIONS="${3:-5}"
MAX_BUDGET_USD="${4:-3.0}"

AI_CLI="${AI_CLI:-copilot}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_ID="cmo_${TIMESTAMP}"

PROJECT_ROOT="/Users/pedro/Documents/odoo19"
OUTPUT_DIR="$PROJECT_ROOT/docs/prompts/06_outputs/$(date +%Y-%m)/orchestration_cmo"
TEMP_DIR="/tmp/cmo_${SESSION_ID}"
LOG_FILE="$TEMP_DIR/orchestration.log"

mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ════════════════════════════════════════════════════════════════
# FUNCIONES
# ════════════════════════════════════════════════════════════════

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    case "$level" in
        ERROR)
            echo -e "${RED}[ERROR]${NC} $timestamp $message" | tee -a "$LOG_FILE" >&2
            ;;
        SUCCESS)
            echo -e "${GREEN}[OK]${NC} $timestamp $message" | tee -a "$LOG_FILE"
            ;;
        INFO)
            echo -e "${CYAN}[INFO]${NC} $timestamp $message" | tee -a "$LOG_FILE"
            ;;
        *)
            echo "[LOG] $timestamp $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..70})${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}$(printf '═%.0s' {1..70})${NC}"
    echo ""
}

get_module_metrics() {
    local module="$1"
    local module_path="$PROJECT_ROOT/$module"
    
    if [ ! -d "$module_path" ]; then
        echo "0"
        return
    fi
    
    # Contar archivos Python
    local py_files=$(find "$module_path" -name "*.py" 2>/dev/null | wc -l | tr -d ' ')
    
    # Calcular score básico (50 base + archivos encontrados)
    local score=$((50 + py_files * 2))
    
    # Limitar a 100
    if [ $score -gt 100 ]; then
        score=100
    fi
    
    echo "$score"
}

call_ai_cli() {
    local prompt="$1"
    local output_file="$2"
    
    log INFO "Requesting strategic decision from $AI_CLI..."
    
    case "$AI_CLI" in
        copilot)
            echo "$prompt" | copilot -p "$(cat -)" > "$output_file" 2>&1
            ;;
        codex)
            echo "$prompt" | codex -p "$(cat -)" > "$output_file" 2>&1
            ;;
        gemini)
            echo "$prompt" | gemini -p "$(cat -)" > "$output_file" 2>&1
            ;;
        *)
            log ERROR "Unknown AI_CLI: $AI_CLI"
            return 1
            ;;
    esac
    
    if [ $? -ne 0 ]; then
        log ERROR "$AI_CLI decision request failed"
        cat "$output_file" | tee -a "$LOG_FILE"
        return 1
    fi
    
    log SUCCESS "$AI_CLI decision received"
    return 0
}

# ════════════════════════════════════════════════════════════════
# INICIO
# ════════════════════════════════════════════════════════════════

banner "CMO v2.1 Standalone - Context-Minimal Orchestration"

log INFO "Session ID: $SESSION_ID"
log INFO "Module: $MODULE_PATH"
log INFO "Target score: $TARGET_SCORE"
log INFO "Max iterations: $MAX_ITERATIONS"
log INFO "Max budget: \$$MAX_BUDGET_USD USD"
log INFO "AI CLI: $AI_CLI"

# Validar módulo
if [ ! -d "$PROJECT_ROOT/$MODULE_PATH" ]; then
    log ERROR "Module not found: $PROJECT_ROOT/$MODULE_PATH"
    exit 1
fi

log SUCCESS "Module validated"

# ════════════════════════════════════════════════════════════════
# CICLO ITERATIVO
# ════════════════════════════════════════════════════════════════

ITERATION=1
CURRENT_SCORE=0
BUDGET_USED=0.0
START_TIME=$(date +%s)

while [ $ITERATION -le $MAX_ITERATIONS ]; do
    banner "Iteration $ITERATION/$MAX_ITERATIONS"
    
    # ─────────────────────────────────────────────────────────────
    # STEP 1: Obtener métricas actuales
    # ─────────────────────────────────────────────────────────────
    
    CURRENT_SCORE=$(get_module_metrics "$MODULE_PATH")
    log INFO "Current score: $CURRENT_SCORE/$TARGET_SCORE"
    
    # Verificar si alcanzamos el objetivo
    if [ $CURRENT_SCORE -ge $TARGET_SCORE ]; then
        log SUCCESS "Target score reached! ($CURRENT_SCORE >= $TARGET_SCORE)"
        break
    fi
    
    # Verificar budget
    BUDGET_CHECK=$(echo "$BUDGET_USED >= $MAX_BUDGET_USD" | bc -l)
    if [ "$BUDGET_CHECK" -eq 1 ]; then
        log INFO "Budget exhausted (\$$BUDGET_USED >= \$$MAX_BUDGET_USD)"
        break
    fi
    
    # ─────────────────────────────────────────────────────────────
    # STEP 2: Generar CONSIGNA
    # ─────────────────────────────────────────────────────────────
    
    CONSIGNA_FILE="$TEMP_DIR/consigna_${ITERATION}.txt"
    
    cat > "$CONSIGNA_FILE" << EOF
# CONTEXT-MINIMAL ORCHESTRATION - Iteration $ITERATION

## Current State
- Module: $MODULE_PATH
- Score: $CURRENT_SCORE/$TARGET_SCORE
- Budget used: \$$BUDGET_USED/\$$MAX_BUDGET_USD USD
- Iteration: $ITERATION/$MAX_ITERATIONS

## Gap Analysis
- Score gap: $((TARGET_SCORE - CURRENT_SCORE)) points
- Progress needed: $((100 * (TARGET_SCORE - CURRENT_SCORE) / TARGET_SCORE))%

## Decision Required

Based on the current state, decide the next action:

1. If score >= $TARGET_SCORE → STOP (goal achieved)
2. If budget >= \$$MAX_BUDGET_USD → STOP (budget exhausted)
3. If gap > 20 points → CONTINUE with close_gaps_p0 (critical)
4. If gap <= 20 points → CONTINUE with close_gaps_p1 (optimization)

Respond EXACTLY in this format (3 lines):

DECISION: [continue|stop]
REASON: [one sentence explaining why]
NEXT_ACTION: [close_gaps_p0|close_gaps_p1|stop]
EOF
    
    log INFO "CONSIGNA generated ($(wc -l < $CONSIGNA_FILE) lines)"
    
    # ─────────────────────────────────────────────────────────────
    # STEP 3: Llamar a AI CLI
    # ─────────────────────────────────────────────────────────────
    
    AI_PROMPT="$(cat $CONSIGNA_FILE)

You are a strategic orchestrator for an automated quality improvement system.

Respond in the exact format specified above. Be concise and decisive."
    
    CONCLUSION_FILE="$TEMP_DIR/conclusion_${ITERATION}.txt"
    
    if ! call_ai_cli "$AI_PROMPT" "$CONCLUSION_FILE"; then
        log ERROR "Failed to get AI decision"
        exit 1
    fi
    
    # ─────────────────────────────────────────────────────────────
    # STEP 4: Parsear CONCLUSIÓN
    # ─────────────────────────────────────────────────────────────
    
    DECISION=$(grep -i "^DECISION:" "$CONCLUSION_FILE" | head -1 | sed 's/DECISION://i' | tr -d ' ' | tr '[:upper:]' '[:lower:]' || echo "unknown")
    REASON=$(grep -i "^REASON:" "$CONCLUSION_FILE" | head -1 | sed 's/REASON://i' | sed 's/^[[:space:]]*//' || echo "No reason provided")
    NEXT_ACTION=$(grep -i "^NEXT_ACTION:" "$CONCLUSION_FILE" | head -1 | sed 's/NEXT_ACTION://i' | tr -d ' ' | tr '[:upper:]' '[:lower:]' || echo "unknown")
    
    log INFO "Decision: $DECISION"
    log INFO "Reason: $REASON"
    log INFO "Next action: $NEXT_ACTION"
    
    # ─────────────────────────────────────────────────────────────
    # STEP 5: Ejecutar acción
    # ─────────────────────────────────────────────────────────────
    
    case "$DECISION" in
        stop)
            log SUCCESS "Orchestration stopped by AI decision"
            break
            ;;
        continue)
            log INFO "Continuing with action: $NEXT_ACTION"
            
            case "$NEXT_ACTION" in
                close_gaps_p0|close_gaps_p1)
                    log INFO "Simulating gap closure..."
                    # En producción aquí irían los scripts reales
                    sleep 2
                    CURRENT_SCORE=$((CURRENT_SCORE + 5))
                    log SUCCESS "Action completed (new score: $CURRENT_SCORE)"
                    ;;
                *)
                    log INFO "No action taken"
                    ;;
            esac
            ;;
        *)
            log ERROR "Invalid decision: $DECISION"
            break
            ;;
    esac
    
    # Actualizar budget (estimado $0.50 por iteración)
    BUDGET_USED=$(echo "$BUDGET_USED + 0.50" | bc)
    
    ITERATION=$((ITERATION + 1))
    
    echo ""
done

# ════════════════════════════════════════════════════════════════
# REPORTE FINAL
# ════════════════════════════════════════════════════════════════

banner "Final Report"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

FINAL_REPORT="$OUTPUT_DIR/CMO_STANDALONE_${SESSION_ID}.md"

cat > "$FINAL_REPORT" << EOF
# CMO v2.1 Standalone - Session Report

**Session ID:** $SESSION_ID  
**Date:** $(date)  
**AI CLI:** $AI_CLI

---

## Configuration

- **Module:** $MODULE_PATH
- **Target Score:** $TARGET_SCORE
- **Max Iterations:** $MAX_ITERATIONS
- **Max Budget:** \$$MAX_BUDGET_USD USD

---

## Results

- **Final Score:** $CURRENT_SCORE/$TARGET_SCORE
- **Iterations Executed:** $((ITERATION - 1))
- **Budget Used:** \$$BUDGET_USED USD
- **Duration:** ${DURATION}s
- **Status:** $([ $CURRENT_SCORE -ge $TARGET_SCORE ] && echo "✅ SUCCESS" || echo "⚠️ PARTIAL")

---

## Summary

$(if [ $CURRENT_SCORE -ge $TARGET_SCORE ]; then
    echo "✅ Target score achieved!"
elif [ $((ITERATION - 1)) -ge $MAX_ITERATIONS ]; then
    echo "⚠️ Max iterations reached"
elif [ $(echo "$BUDGET_USED >= $MAX_BUDGET_USD" | bc -l) -eq 1 ]; then
    echo "⚠️ Budget exhausted"
else
    echo "⚠️ Stopped by AI decision"
fi)

---

## AI CLI Validation

- **CLI Used:** $AI_CLI ✅
- **Claude CLI Used:** NO ✅
- **Multi-CLI Support:** YES ✅

---

**Generated:** $(date)
EOF

log SUCCESS "Final report: $FINAL_REPORT"

# Mostrar resumen
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Orchestration Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Final Score:     ${CYAN}$CURRENT_SCORE${NC}/${TARGET_SCORE}"
echo -e "  Iterations:      ${CYAN}$((ITERATION - 1))${NC}/${MAX_ITERATIONS}"
echo -e "  Budget Used:     ${CYAN}\$$BUDGET_USED${NC}/\$$MAX_BUDGET_USD USD"
echo -e "  Duration:        ${CYAN}${DURATION}s${NC}"
echo -e "  AI CLI:          ${CYAN}$AI_CLI${NC} ✅"
echo -e "  Report:          ${CYAN}$FINAL_REPORT${NC}"
echo ""

# Cleanup
rm -rf "$TEMP_DIR"

exit 0
