#!/bin/bash
# wait_for_audit_reports.sh
# Helper script para polling de reportes de auditoría
# Parte del Sistema de Orquestación Multi-Agente v1.1

set -e

# Configuración
OUTPUT_DIR="${1:-docs/prompts/06_outputs/2025-11}"
TIMEOUT="${2:-300}"  # 5 minutos default
POLL_INTERVAL="${3:-10}"  # 10 segundos default

# Reportes esperados (pasados como argumentos adicionales o defaults)
shift 3 2>/dev/null || true
REPORTS=("$@")

if [ ${#REPORTS[@]} -eq 0 ]; then
    echo "❌ Error: No reports specified"
    echo "Usage: $0 <output_dir> <timeout> <poll_interval> <report1> <report2> ..."
    echo "Example: $0 docs/prompts/06_outputs/2025-11 300 10 AUDIT_BACKEND.md AUDIT_SECURITY.md"
    exit 1
fi

echo "📊 Waiting for ${#REPORTS[@]} audit reports..."
echo "   Output dir: $OUTPUT_DIR"
echo "   Timeout: ${TIMEOUT}s"
echo "   Poll interval: ${POLL_INTERVAL}s"
echo ""

elapsed=0
found_count=0

while [ $elapsed -lt $TIMEOUT ]; do
    found_count=0
    missing_reports=()

    for report in "${REPORTS[@]}"; do
        report_path="$OUTPUT_DIR/$report"
        if [ -f "$report_path" ]; then
            found_count=$((found_count + 1))
            echo "   ✅ $report ($(stat -f%z "$report_path" 2>/dev/null || echo "?" )bytes)"
        else
            missing_reports+=("$report")
        fi
    done

    if [ $found_count -eq ${#REPORTS[@]} ]; then
        echo ""
        echo "✅ All $found_count reports generated successfully!"
        echo ""
        echo "📄 Generated files:"
        for report in "${REPORTS[@]}"; do
            report_path="$OUTPUT_DIR/$report"
            size=$(stat -f%z "$report_path" 2>/dev/null || echo "?")
            lines=$(wc -l < "$report_path" 2>/dev/null || echo "?")
            echo "   - $report ($size bytes, $lines lines)"
        done
        exit 0
    fi

    if [ $elapsed -gt 0 ]; then
        echo -ne "\r⏳ Progress: $found_count/${#REPORTS[@]} reports ready... (${elapsed}s/${TIMEOUT}s)    "
    fi

    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
done

echo ""
echo ""
echo "⚠️  Timeout: Only $found_count/${#REPORTS[@]} reports generated after ${TIMEOUT}s"
echo ""
echo "❌ Missing reports:"
for report in "${missing_reports[@]}"; do
    echo "   - $report"
done
echo ""
echo "💡 Check CLI agent logs for errors:"
echo "   ls -lh /tmp/audit_*_output*.log"
exit 1
