#!/bin/bash

# ============================================================
# AUDIT: Obsolete attrs in XML Views (Odoo 19 CE)
# ============================================================
# Busca sintaxis obsoleta attrs="{'...': [...]}" en archivos XML
# Odoo 19 requiere atributos directos: invisible="expr"
# ============================================================

set -e

MODULE_PATH="addons/localization/l10n_cl_hr_payroll"
SEARCH_PATTERN='attrs="'

echo "==========================================="
echo "AUDITORÍA: attrs obsoletos en vistas XML"
echo "==========================================="
echo ""
echo "Módulo: ${MODULE_PATH}"
echo "Patrón: ${SEARCH_PATTERN}"
echo ""

# Buscar en archivos XML
echo "📋 Buscando attrs obsoletos..."
echo ""

FOUND=0
if grep -r --include="*.xml" "${SEARCH_PATTERN}" "${MODULE_PATH}/views/" 2>/dev/null; then
    FOUND=1
    echo ""
    echo "❌ FALLÓ: Se encontraron attrs obsoletos"
    echo ""
    echo "Archivos con attrs obsoletos:"
    grep -rl --include="*.xml" "${SEARCH_PATTERN}" "${MODULE_PATH}/views/"
    echo ""
    echo "Total de ocurrencias:"
    grep -r --include="*.xml" "${SEARCH_PATTERN}" "${MODULE_PATH}/views/" | wc -l
    exit 1
else
    echo "✅ ÉXITO: No se encontraron attrs obsoletos"
    echo ""
    echo "Todos los archivos XML usan sintaxis Odoo 19:"
    echo "  - invisible=\"python_expression\""
    echo "  - readonly=\"python_expression\""
    echo "  - required=\"python_expression\""
    echo ""
fi

echo "==========================================="
echo "AUDITORÍA COMPLETADA"
echo "==========================================="

exit 0
