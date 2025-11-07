#!/bin/bash
# CI Gate P0 - Verificación de Integridad Módulo l10n_cl_hr_payroll
# Este script DEBE pasar antes de merge

set -e

echo "═══════════════════════════════════════════════════════════"
echo "CI GATE P0 - Módulo l10n_cl_hr_payroll"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Contador de errores
ERRORS=0

echo "📋 Gate 1: Verificación de sintaxis Python..."
python3 -m py_compile addons/localization/l10n_cl_hr_payroll/models/*.py
python3 -m py_compile addons/localization/l10n_cl_hr_payroll/tests/*.py
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Gate 1: PASS${NC}"
else
    echo -e "${RED}❌ Gate 1: FAIL${NC}"
    ERRORS=$((ERRORS+1))
fi
echo ""

echo "📋 Gate 2: Verificación de naming integrity..."
echo "   Buscando referencias a campos obsoletos..."
LEGACY_FIELDS=$(grep -r "jornada_semanal\|ingreso_minimo" \
    addons/localization/l10n_cl_hr_payroll/models/ \
    --include="*.py" \
    | grep -v "# NO debe" \
    | grep -v "def _check" \
    | grep -v "test_" \
    || true)

if [ -z "$LEGACY_FIELDS" ]; then
    echo -e "${GREEN}✅ Gate 2: PASS - No hay campos obsoletos${NC}"
else
    echo -e "${RED}❌ Gate 2: FAIL - Campos obsoletos encontrados:${NC}"
    echo "$LEGACY_FIELDS"
    ERRORS=$((ERRORS+1))
fi
echo ""

echo "📋 Gate 3: Verificación de tramos hardcoded..."
HARDCODED_TRAMOS=$(grep -r "TRAMOS\s*=\s*\[" \
    addons/localization/l10n_cl_hr_payroll/models/ \
    --include="*.py" \
    || true)

if [ -z "$HARDCODED_TRAMOS" ]; then
    echo -e "${GREEN}✅ Gate 3: PASS - No hay tramos hardcoded${NC}"
else
    echo -e "${RED}❌ Gate 3: FAIL - Tramos hardcoded encontrados:${NC}"
    echo "$HARDCODED_TRAMOS"
    ERRORS=$((ERRORS+1))
fi
echo ""

echo "═══════════════════════════════════════════════════════════"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✅ CI GATE P0: TODOS LOS CHECKS PASARON${NC}"
    exit 0
else
    echo -e "${RED}❌ CI GATE P0: $ERRORS ERRORES ENCONTRADOS${NC}"
    echo ""
    echo "Fix los errores antes de continuar."
    exit 1
fi
