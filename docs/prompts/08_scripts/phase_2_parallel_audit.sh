#!/bin/bash
# phase_2_parallel_audit.sh - Ejecuta auditorías en paralelo usando CLI agents
# Delega a ciclo_completo_auditoria_v2.sh existente

set -euo pipefail

MODULE_PATH="${1:?Error: MODULE_PATH requerido}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(cd "$SCRIPT_DIR/../06_outputs/$(date +%Y-%m)/auditorias" && pwd)"

MODULE_NAME=$(basename "$MODULE_PATH")

# Delegar a ciclo_completo_auditoria_v2.sh si existe
if [ -f "$SCRIPT_DIR/ciclo_completo_auditoria_v2.sh" ]; then
    echo "Ejecutando ciclo_completo_auditoria_v2.sh..." >&2
    "$SCRIPT_DIR/ciclo_completo_auditoria_v2.sh" "$MODULE_NAME" >/dev/null 2>&1 || true
    
    # Buscar reporte consolidado más reciente
    LATEST_REPORT=$(find "$OUTPUT_DIR" -name "AUDIT_CONSOLIDATED_*.md" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
    
    if [ -n "$LATEST_REPORT" ] && [ -f "$LATEST_REPORT" ]; then
        # Extraer scores del reporte
        BACKEND_SCORE=$(grep -oP 'Backend.*?:\s*\K\d+' "$LATEST_REPORT" | head -1 || echo "0")
        SECURITY_SCORE=$(grep -oP 'Security.*?:\s*\K\d+' "$LATEST_REPORT" | head -1 || echo "0")
        TESTS_SCORE=$(grep -oP 'Tests.*?:\s*\K\d+' "$LATEST_REPORT" | head -1 || echo "0")
        PERF_SCORE=$(grep -oP 'Performance.*?:\s*\K\d+' "$LATEST_REPORT" | head -1 || echo "0")
        
        # Calcular promedio
        TOTAL=$((BACKEND_SCORE + SECURITY_SCORE + TESTS_SCORE + PERF_SCORE))
        AVG=$((TOTAL / 4))
        
        # Extraer findings P0/P1
        P0_COUNT=$(grep -c '\[P0\]' "$LATEST_REPORT" || echo "0")
        P1_COUNT=$(grep -c '\[P1\]' "$LATEST_REPORT" || echo "0")
        
        # Output JSON
        cat <<EOF
{
  "average_score": $AVG,
  "backend_score": $BACKEND_SCORE,
  "security_score": $SECURITY_SCORE,
  "tests_score": $TESTS_SCORE,
  "performance_score": $PERF_SCORE,
  "p0_count": $P0_COUNT,
  "p1_count": $P1_COUNT,
  "findings": [],
  "source": "ciclo_completo_auditoria_v2",
  "report_path": "$LATEST_REPORT",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    else
        # Fallback si no se encuentra reporte
        echo "No se encontró reporte de auditoría" >&2
        cat <<EOF
{
  "average_score": 0,
  "error": "No audit report found",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    fi
else
    # Si no existe ciclo_completo_auditoria_v2.sh, fallback simple
    echo "ciclo_completo_auditoria_v2.sh no encontrado, usando fallback" >&2
    cat <<EOF
{
  "average_score": 50,
  "backend_score": 50,
  "security_score": 50,
  "tests_score": 50,
  "performance_score": 50,
  "findings": [],
  "source": "fallback_stub",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
fi
