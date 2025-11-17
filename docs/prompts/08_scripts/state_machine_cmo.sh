#!/bin/bash
# state_machine_cmo.sh - State Machine para Context-Minimal Orchestration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROPÓSITO:
#   Ejecutar acciones basadas en CONCLUSIÓN de Claude.
#   Lógica determinista 100% - misma decisión = misma acción.
#
# USO:
#   ./state_machine_cmo.sh <MODULE_PATH> <CONCLUSION_FILE> <STATE_FILE>
#
# EJEMPLO:
#   ./state_machine_cmo.sh ai-service /tmp/conclusion.txt /tmp/state.json
#
# AUTOR: Pedro Troncoso + Claude Code
# FECHA: 2025-11-13
# VERSIÓN: 2.1.0
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ════════════════════════════════════════════════════════════════

MODULE_PATH="${1:?Error: MODULE_PATH required}"
CONCLUSION_FILE="${2:?Error: CONCLUSION_FILE required}"
STATE_FILE="${3:?Error: STATE_FILE required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Directorios de scripts de fase
PHASE_DIR="$SCRIPT_DIR"

# Archivos de output
TEMP_DIR="/tmp/cmo_$(date +%s)"
mkdir -p "$TEMP_DIR"
GAPS_FILE="${TEMP_DIR}/gaps_closed.json"
FEATURES_FILE="${TEMP_DIR}/features.json"
TEST_FILE="${TEMP_DIR}/test_result.json"
AUDIT_FILE="${TEMP_DIR}/audit_result.json"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
        INFO)
            echo -e "${BLUE}[INFO]${NC} $timestamp $message"
            ;;
        *)
            echo "[LOG] $timestamp $message"
            ;;
    esac
}

# ════════════════════════════════════════════════════════════════
# PARSING DE CONCLUSIÓN
# ════════════════════════════════════════════════════════════════

# Source parse script para obtener variables CMO_*
source "$SCRIPT_DIR/parse_conclusion.sh" "$CONCLUSION_FILE"

if [ $? -ne 0 ]; then
    log ERROR "Failed to parse CONCLUSION_FILE"
    exit 1
fi

log INFO "State Machine activated with DECISION: $CMO_DECISION"

# ════════════════════════════════════════════════════════════════
# STATE MACHINE: DECISIÓN PRINCIPAL
# ════════════════════════════════════════════════════════════════

case "$CMO_DECISION" in
    "continue")
        log INFO "Decision: CONTINUE - Executing next action"
        
        # State machine secundaria: NEXT_ACTION
        case "$CMO_NEXT_ACTION" in
            "close_gaps_p0")
                log INFO "Action: Closing P0 gaps"
                
                if [ -f "$PHASE_DIR/phase_3_close_gaps.sh" ]; then
                    "$PHASE_DIR/phase_3_close_gaps.sh" "$MODULE_PATH" "P0" > "$GAPS_FILE"
                    
                    if [ $? -eq 0 ]; then
                        GAPS_CLOSED=$(jq -r '.gaps_closed // 0' "$GAPS_FILE" 2>/dev/null || echo "0")
                        log SUCCESS "P0 gaps closed: $GAPS_CLOSED"
                        
                        # Actualizar estado
                        update_state "action_executed" "close_gaps_p0" "$GAPS_CLOSED"
                    else
                        log ERROR "phase_3_close_gaps.sh failed"
                        update_state "action_failed" "close_gaps_p0" "0"
                        exit 1
                    fi
                else
                    log WARNING "phase_3_close_gaps.sh not found - using stub"
                    echo '{"status":"not_implemented","gaps_closed":0}' > "$GAPS_FILE"
                    update_state "action_skipped" "close_gaps_p0" "0"
                fi
                ;;
            
            "close_gaps_p1")
                log INFO "Action: Closing P1 gaps"
                
                if [ -f "$PHASE_DIR/phase_3_close_gaps.sh" ]; then
                    "$PHASE_DIR/phase_3_close_gaps.sh" "$MODULE_PATH" "P1" > "$GAPS_FILE"
                    
                    if [ $? -eq 0 ]; then
                        GAPS_CLOSED=$(jq -r '.gaps_closed // 0' "$GAPS_FILE" 2>/dev/null || echo "0")
                        log SUCCESS "P1 gaps closed: $GAPS_CLOSED"
                        update_state "action_executed" "close_gaps_p1" "$GAPS_CLOSED"
                    else
                        log ERROR "phase_3_close_gaps.sh failed"
                        update_state "action_failed" "close_gaps_p1" "0"
                        exit 1
                    fi
                else
                    log WARNING "phase_3_close_gaps.sh not found - using stub"
                    echo '{"status":"not_implemented","gaps_closed":0}' > "$GAPS_FILE"
                    update_state "action_skipped" "close_gaps_p1" "0"
                fi
                ;;
            
            "enhance")
                log INFO "Action: Enhancing module (Phase 4)"
                
                if [ -f "$PHASE_DIR/phase_4_enhance.sh" ]; then
                    "$PHASE_DIR/phase_4_enhance.sh" "$MODULE_PATH" > "$FEATURES_FILE"
                    
                    if [ $? -eq 0 ]; then
                        FEATURES_ADDED=$(jq -r '.features_added // 0' "$FEATURES_FILE" 2>/dev/null || echo "0")
                        log SUCCESS "Features added: $FEATURES_ADDED"
                        update_state "action_executed" "enhance" "$FEATURES_ADDED"
                    else
                        log ERROR "phase_4_enhance.sh failed"
                        update_state "action_failed" "enhance" "0"
                        exit 1
                    fi
                else
                    log WARNING "phase_4_enhance.sh not found - skipping"
                    echo '{"status":"not_implemented","features_added":0}' > "$FEATURES_FILE"
                    update_state "action_skipped" "enhance" "0"
                fi
                ;;
            
            "test")
                log INFO "Action: Running tests (Phase 6)"
                
                if [ -f "$PHASE_DIR/phase_6_test.sh" ]; then
                    "$PHASE_DIR/phase_6_test.sh" "$MODULE_PATH" > "$TEST_FILE"
                    
                    if [ $? -eq 0 ]; then
                        TESTS_PASSED=$(jq -r '.tests_passed // 0' "$TEST_FILE" 2>/dev/null || echo "0")
                        TESTS_FAILED=$(jq -r '.tests_failed // 0' "$TEST_FILE" 2>/dev/null || echo "0")
                        log SUCCESS "Tests: $TESTS_PASSED passed, $TESTS_FAILED failed"
                        update_state "action_executed" "test" "$TESTS_PASSED"
                    else
                        log ERROR "phase_6_test.sh failed"
                        update_state "action_failed" "test" "0"
                        exit 1
                    fi
                else
                    log WARNING "phase_6_test.sh not found - skipping"
                    echo '{"status":"not_implemented","tests_passed":0}' > "$TEST_FILE"
                    update_state "action_skipped" "test" "0"
                fi
                ;;
            
            "re_audit")
                log INFO "Action: Re-auditing module (Phase 2)"
                
                if [ -f "$PHASE_DIR/phase_2_parallel_audit.sh" ]; then
                    "$PHASE_DIR/phase_2_parallel_audit.sh" "$MODULE_PATH" > "$AUDIT_FILE"
                    
                    if [ $? -eq 0 ]; then
                        NEW_SCORE=$(jq -r '.average_score // 0' "$AUDIT_FILE" 2>/dev/null || echo "0")
                        log SUCCESS "Re-audit completed: Score $NEW_SCORE"
                        update_state "action_executed" "re_audit" "$NEW_SCORE"
                    else
                        log ERROR "phase_2_parallel_audit.sh failed"
                        update_state "action_failed" "re_audit" "0"
                        exit 1
                    fi
                else
                    log WARNING "phase_2_parallel_audit.sh not found - skipping"
                    echo '{"status":"not_implemented","average_score":0}' > "$AUDIT_FILE"
                    update_state "action_skipped" "re_audit" "0"
                fi
                ;;
            
            "develop")
                log INFO "Action: Developing features (Phase 5)"
                
                if [ -f "$PHASE_DIR/phase_5_develop.sh" ]; then
                    "$PHASE_DIR/phase_5_develop.sh" "$MODULE_PATH" > "$FEATURES_FILE"
                    
                    if [ $? -eq 0 ]; then
                        FEATURES_ADDED=$(jq -r '.features_added // 0' "$FEATURES_FILE" 2>/dev/null || echo "0")
                        log SUCCESS "Features developed: $FEATURES_ADDED"
                        update_state "action_executed" "develop" "$FEATURES_ADDED"
                    else
                        log ERROR "phase_5_develop.sh failed"
                        update_state "action_failed" "develop" "0"
                        exit 1
                    fi
                else
                    log WARNING "phase_5_develop.sh not found - skipping"
                    echo '{"status":"not_implemented","features_added":0}' > "$FEATURES_FILE"
                    update_state "action_skipped" "develop" "0"
                fi
                ;;
            
            *)
                log ERROR "Unknown NEXT_ACTION: $CMO_NEXT_ACTION"
                update_state "action_unknown" "$CMO_NEXT_ACTION" "0"
                exit 1
                ;;
        esac
        
        exit 0
        ;;
    
    "stop")
        log SUCCESS "Decision: STOP - Target reached or conditions met"
        log INFO "Reason: $CMO_REASON"
        
        # Actualizar estado final
        update_state "stopped" "target_reached" "final"
        
        exit 0
        ;;
    
    "escalate")
        log WARNING "Decision: ESCALATE - Human intervention required"
        log WARNING "Reason: $CMO_REASON"
        
        # Actualizar estado de escalación
        update_state "escalated" "human_required" "pending"
        
        # Exit code 2 para indicar escalación
        exit 2
        ;;
    
    *)
        log ERROR "Unknown DECISION: $CMO_DECISION"
        exit 1
        ;;
esac

# ════════════════════════════════════════════════════════════════
# FUNCIÓN: Actualizar Estado
# ════════════════════════════════════════════════════════════════

update_state() {
    local status="$1"
    local action="$2"
    local result="$3"
    
    # Leer estado actual
    local current_state=$(cat "$STATE_FILE")
    
    # Actualizar con jq
    local updated_state=$(echo "$current_state" | jq \
        --arg status "$status" \
        --arg action "$action" \
        --arg result "$result" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '.last_action = {
            status: $status,
            action: $action,
            result: $result,
            timestamp: $timestamp
        }')
    
    # Escribir estado actualizado
    echo "$updated_state" > "$STATE_FILE"
    
    log INFO "State updated: status=$status, action=$action, result=$result"
}
