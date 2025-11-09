#!/bin/bash

################################################################################
# Test Execution Script - FASE 0-1 (Odoo Native Tests)
################################################################################

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FASE="${1:-all}"
VERBOSE="${2:-}"

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================================================"
echo "🧪 TEST EXECUTION - FASE 0-1 (ODOO NATIVE)"
echo "================================================================================"
echo "Project Root: $PROJECT_ROOT"
echo "Fase: $FASE"
echo ""

# Función para ejecutar tests
run_fase_tests() {
    local fase=$1
    local modules=$2
    local description=$3

    echo "================================================================================"
    echo "📦 FASE $fase: $description"
    echo "================================================================================"
    echo ""

    for module in $modules; do
        echo "🔧 Ejecutando tests para: $module"
        echo "---"

        if [ "$VERBOSE" = "-v" ]; then
            docker-compose exec -T odoo odoo \
                -u "$module" \
                --test-enable \
                --stop-after-init \
                --log-level=test 2>&1
        else
            docker-compose exec -T odoo odoo \
                -u "$module" \
                --test-enable \
                --stop-after-init 2>&1 | grep -E "test_|passed|failed|ERROR|FAIL" || true
        fi

        echo ""
    done
}

# Ejecutar según FASE
case "$FASE" in
    0)
        run_fase_tests "0" "l10n_cl_hr_payroll" "Payroll P0-P1 Tests"
        ;;
    1)
        run_fase_tests "1" "l10n_cl_dte l10n_cl_financial_reports" "DTE 52 + Financial Reports Tests"
        ;;
    all)
        run_fase_tests "0" "l10n_cl_hr_payroll" "Payroll P0-P1 Tests"
        echo ""
        run_fase_tests "1" "l10n_cl_dte l10n_cl_financial_reports" "DTE 52 + Financial Reports Tests"
        ;;
    *)
        echo -e "${RED}Error: FASE debe ser 0, 1 o all${NC}"
        exit 1
        ;;
esac

echo ""
echo "================================================================================"
echo -e "${GREEN}✅ Test execution completado${NC}"
echo "================================================================================"
