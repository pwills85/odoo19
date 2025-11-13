#!/bin/bash
# Script de Validación Integración CE-Pro
# Autor: Technical Analysis Team
# Fecha: 2025-11-10
# Propósito: Validar compatibilidad stack existente con CE-Pro antes Fase 0.5

set -e

echo "🔬 VALIDACIÓN INTEGRACIÓN CE-PRO vs STACK EXISTENTE"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

WORKSPACE="/Users/pedro/Documents/odoo19"
REPORT_FILE="${WORKSPACE}/VALIDACION_CE_PRO_$(date +%Y%m%d_%H%M%S).txt"

# Función de logging
log_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    if [ "$status" == "PASS" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $test_name"
    elif [ "$status" == "FAIL" ]; then
        echo -e "${RED}❌ FAIL${NC}: $test_name"
    else
        echo -e "${YELLOW}⚠️  WARN${NC}: $test_name"
    fi
    
    echo "   Details: $details"
    echo "$test_name | $status | $details" >> "$REPORT_FILE"
}

# Test 1: Herencias account.report
echo "📋 Test 1: Validando herencias account.report..."
ACCOUNT_REPORT_INHERITS=$(grep -r "_inherit.*account\.report" \
    "$WORKSPACE/addons/localization/l10n_cl_financial_reports/models/" \
    --include="*.py" 2>/dev/null | wc -l | xargs)

if [ "$ACCOUNT_REPORT_INHERITS" -ge 2 ]; then
    log_result "Herencias account.report" "PASS" "Encontradas $ACCOUNT_REPORT_INHERITS herencias (F29, F22)"
else
    log_result "Herencias account.report" "FAIL" "Solo $ACCOUNT_REPORT_INHERITS herencias (esperadas ≥2)"
fi

# Test 2: Componentes OWL 2
echo ""
echo "🎨 Test 2: Validando componentes OWL 2..."
OWL_COMPONENTS=$(find "$WORKSPACE/addons/localization/l10n_cl_financial_reports/static/src" \
    -name "*.js" -exec grep -l "@odoo/owl" {} \; 2>/dev/null | wc -l | xargs)

TOTAL_JS_FILES=$(find "$WORKSPACE/addons/localization/l10n_cl_financial_reports/static/src" \
    -name "*.js" 2>/dev/null | wc -l | xargs)

OWL_PERCENTAGE=$(echo "scale=1; ($OWL_COMPONENTS / $TOTAL_JS_FILES) * 100" | bc)

if [ $(echo "$OWL_PERCENTAGE >= 80" | bc) -eq 1 ]; then
    log_result "Componentes OWL 2" "PASS" "$OWL_COMPONENTS/$TOTAL_JS_FILES archivos OWL ($OWL_PERCENTAGE%)"
else
    log_result "Componentes OWL 2" "WARN" "$OWL_COMPONENTS/$TOTAL_JS_FILES archivos OWL ($OWL_PERCENTAGE%) - Requiere migración"
fi

# Test 3: APIs REST custom
echo ""
echo "🌐 Test 3: Validando APIs REST custom..."
API_ENDPOINTS=$(grep -r "@http\.route\|api\.route" \
    "$WORKSPACE/addons/localization/l10n_cl_financial_reports/controllers/" \
    --include="*.py" 2>/dev/null | grep -c "/api/" | xargs)

if [ "$API_ENDPOINTS" -ge 15 ]; then
    log_result "APIs REST custom" "WARN" "Encontrados $API_ENDPOINTS endpoints /api/* - Requiere Gateway v2"
else
    log_result "APIs REST custom" "PASS" "Solo $API_ENDPOINTS endpoints - Conflicto bajo"
fi

# Test 4: Dependencias cruzadas
echo ""
echo "🔗 Test 4: Validando dependencias cruzadas..."
FINANCIAL_DEPENDS_DTE=$(grep -A 10 "depends.*=" \
    "$WORKSPACE/addons/localization/l10n_cl_financial_reports/__manifest__.py" | \
    grep -c "l10n_cl_dte" | xargs)

if [ "$FINANCIAL_DEPENDS_DTE" -ge 1 ]; then
    log_result "Dependencias cruzadas" "PASS" "financial_reports → l10n_cl_dte (integración confirmada)"
else
    log_result "Dependencias cruzadas" "FAIL" "financial_reports NO depende de l10n_cl_dte"
fi

# Test 5: CSS/SCSS branding
echo ""
echo "🎨 Test 5: Validando archivos CSS/SCSS branding..."
CSS_FILES=$(find "$WORKSPACE/addons/localization/eergygroup_branding/static" \
    -name "*.css" -o -name "*.scss" 2>/dev/null | wc -l | xargs)

if [ "$CSS_FILES" -ge 1 ]; then
    log_result "CSS Branding" "WARN" "Encontrados $CSS_FILES archivos CSS - Requiere refactor Phoenix"
else
    log_result "CSS Branding" "PASS" "Sin archivos CSS custom (compatible Phoenix)"
fi

# Test 6: Tests existentes
echo ""
echo "🧪 Test 6: Validando tests existentes..."
DTE_TESTS=$(find "$WORKSPACE/addons/localization/l10n_cl_dte/tests" \
    -name "*.py" 2>/dev/null | wc -l | xargs)
FINANCIAL_TESTS=$(find "$WORKSPACE/addons/localization/l10n_cl_financial_reports/tests" \
    -name "*.py" 2>/dev/null | wc -l | xargs)
PAYROLL_TESTS=$(find "$WORKSPACE/addons/localization/l10n_cl_hr_payroll/tests" \
    -name "*.py" 2>/dev/null | wc -l | xargs)

TOTAL_TESTS=$((DTE_TESTS + FINANCIAL_TESTS + PAYROLL_TESTS))

if [ "$TOTAL_TESTS" -ge 100 ]; then
    log_result "Tests existentes" "PASS" "$TOTAL_TESTS archivos test (DTE:$DTE_TESTS, Financial:$FINANCIAL_TESTS, Payroll:$PAYROLL_TESTS)"
else
    log_result "Tests existentes" "WARN" "Solo $TOTAL_TESTS archivos test (esperados ≥100)"
fi

# Test 7: LOC total módulos
echo ""
echo "📊 Test 7: Validando LOC totales..."
DTE_LOC=$(find "$WORKSPACE/addons/localization/l10n_cl_dte" -name "*.py" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
FINANCIAL_LOC=$(find "$WORKSPACE/addons/localization/l10n_cl_financial_reports" -name "*.py" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
PAYROLL_LOC=$(find "$WORKSPACE/addons/localization/l10n_cl_hr_payroll" -name "*.py" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')

TOTAL_LOC=$((DTE_LOC + FINANCIAL_LOC + PAYROLL_LOC))

if [ "$TOTAL_LOC" -ge 100000 ]; then
    log_result "LOC Total" "PASS" "$TOTAL_LOC líneas (DTE:$DTE_LOC, Financial:$FINANCIAL_LOC, Payroll:$PAYROLL_LOC)"
else
    log_result "LOC Total" "WARN" "Solo $TOTAL_LOC líneas (esperadas ≥100K)"
fi

# Test 8: Docker Compose Redis HA
echo ""
echo "🐳 Test 8: Validando Redis HA en docker-compose..."
REDIS_SENTINEL=$(grep -c "redis-sentinel" "$WORKSPACE/docker-compose.yml" 2>/dev/null | xargs)

if [ "$REDIS_SENTINEL" -ge 1 ]; then
    log_result "Redis HA" "PASS" "Redis Sentinel configurado (HA cluster)"
else
    log_result "Redis HA" "WARN" "Redis Sentinel NO configurado - Recomendar HA"
fi

# Test 9: PostgreSQL PITR
echo ""
echo "🗄️  Test 9: Validando PostgreSQL PITR config..."
PITR_CONFIG=$(grep -i "wal_level\|archive_mode" "$WORKSPACE/docker-compose.yml" 2>/dev/null | wc -l | xargs)

if [ "$PITR_CONFIG" -ge 1 ]; then
    log_result "PostgreSQL PITR" "PASS" "PITR configurado (WAL archiving)"
else
    log_result "PostgreSQL PITR" "FAIL" "PITR NO configurado - MANDATORIO para CE-Pro"
fi

# Test 10: Validar stack_integration.py
echo ""
echo "🔗 Test 10: Validando stack_integration.py..."
if [ -f "$WORKSPACE/addons/localization/l10n_cl_financial_reports/models/stack_integration.py" ]; then
    STACK_INTEGRATION_LOC=$(wc -l < "$WORKSPACE/addons/localization/l10n_cl_financial_reports/models/stack_integration.py")
    log_result "Stack Integration" "PASS" "Archivo stack_integration.py existe ($STACK_INTEGRATION_LOC LOC)"
else
    log_result "Stack Integration" "FAIL" "Archivo stack_integration.py NO existe - Crear antes Fase 0.5"
fi

# Resumen Final
echo ""
echo "=============================================="
echo "📊 RESUMEN VALIDACIÓN"
echo "=============================================="
echo ""

TOTAL_TESTS_RUN=10
PASS_COUNT=$(grep -c "| PASS |" "$REPORT_FILE" | xargs)
WARN_COUNT=$(grep -c "| WARN |" "$REPORT_FILE" | xargs)
FAIL_COUNT=$(grep -c "| FAIL |" "$REPORT_FILE" | xargs)

echo -e "${GREEN}✅ PASS: $PASS_COUNT/$TOTAL_TESTS_RUN${NC}"
echo -e "${YELLOW}⚠️  WARN: $WARN_COUNT/$TOTAL_TESTS_RUN${NC}"
echo -e "${RED}❌ FAIL: $FAIL_COUNT/$TOTAL_TESTS_RUN${NC}"
echo ""

# Veredicto final
if [ "$FAIL_COUNT" -eq 0 ] && [ "$WARN_COUNT" -le 3 ]; then
    echo -e "${GREEN}🎉 VEREDICTO: VIABLE - Stack compatible con CE-Pro${NC}"
    echo "Recomendación: Proceder con Fase 0.5 (Gateway API + OWL migration)"
    EXIT_CODE=0
elif [ "$FAIL_COUNT" -le 2 ]; then
    echo -e "${YELLOW}⚠️  VEREDICTO: VIABLE CON AJUSTES - Requiere refactorización${NC}"
    echo "Recomendación: Implementar mitigaciones antes Fase 1"
    EXIT_CODE=1
else
    echo -e "${RED}❌ VEREDICTO: NO VIABLE - Conflictos críticos${NC}"
    echo "Recomendación: Re-evaluar arquitectura CE-Pro"
    EXIT_CODE=2
fi

echo ""
echo "📄 Reporte completo: $REPORT_FILE"
echo ""

exit $EXIT_CODE

