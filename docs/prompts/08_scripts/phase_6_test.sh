#!/bin/bash
# phase_6_test.sh - Ejecutar tests del módulo
# Soporta pytest para Python, Odoo tests para módulos Odoo

set -euo pipefail

MODULE_PATH="${1:?Error: MODULE_PATH requerido}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

MODULE_NAME=$(basename "$MODULE_PATH")
TESTS_DIR="$MODULE_PATH/tests"
TEMP_OUTPUT="/tmp/test_${MODULE_NAME}_$$.txt"

# Detectar tipo de módulo y ejecutar tests correspondientes
if [ -f "$MODULE_PATH/__manifest__.py" ]; then
    # Módulo Odoo
    echo "Ejecutando Odoo tests para $MODULE_NAME..." >&2
    
    cd "$PROJECT_ROOT"
    docker compose exec odoo odoo-bin --test-enable \
        -i "$MODULE_NAME" \
        --test-tags "/${MODULE_NAME}" \
        --stop-after-init \
        -d odoo19_db \
        2>&1 > "$TEMP_OUTPUT" || true
    
    # Parsear resultados
    TESTS_PASSED=$(grep -c "test.*ok" "$TEMP_OUTPUT" || echo "0")
    TESTS_FAILED=$(grep -c "test.*FAIL" "$TEMP_OUTPUT" || echo "0")
    
elif [ -d "$TESTS_DIR" ]; then
    # Tests pytest
    echo "Ejecutando pytest en $TESTS_DIR..." >&2
    
    if [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
        # Dentro de Docker
        docker compose exec odoo pytest "$MODULE_PATH/tests/" \
            -v --tb=short \
            2>&1 > "$TEMP_OUTPUT" || true
    else
        # Host directo
        .venv/bin/pytest "$TESTS_DIR" -v --tb=short \
            2>&1 > "$TEMP_OUTPUT" || true
    fi
    
    # Parsear resultados pytest
    TESTS_PASSED=$(grep -oP '\d+(?= passed)' "$TEMP_OUTPUT" | head -1 || echo "0")
    TESTS_FAILED=$(grep -oP '\d+(?= failed)' "$TEMP_OUTPUT" | head -1 || echo "0")
    
    # Coverage si disponible
    COVERAGE=$(grep -oP 'TOTAL.*?\K\d+(?=%)' "$TEMP_OUTPUT" | head -1 || echo "0")
    
else
    echo "No tests directory found" >&2
    TESTS_PASSED=0
    TESTS_FAILED=0
    COVERAGE=0
fi

# Cleanup
rm -f "$TEMP_OUTPUT"

# Output JSON
cat <<EOF
{
  "tests_passed": $TESTS_PASSED,
  "tests_failed": $TESTS_FAILED,
  "coverage_percentage": ${COVERAGE:-0},
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
