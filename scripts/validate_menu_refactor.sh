#!/bin/bash
#
# ═══════════════════════════════════════════════════════════════════════════
# SCRIPT DE VALIDACIÓN: Refactorización de Menús DTE
# ═══════════════════════════════════════════════════════════════════════════
#
# Propósito: Validar que la refactorización de menús fue exitosa
# Fecha: 2025-11-02
# Autor: EergyGroup Engineering Team
# Versión: 1.0
#
# Uso: ./scripts/validate_menu_refactor.sh [database_name]
# Ejemplo: ./scripts/validate_menu_refactor.sh TEST
#

set -e  # Exit on error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuración
DB_NAME=${1:-TEST}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  VALIDACIÓN: Refactorización de Menús DTE"
echo "═══════════════════════════════════════════════════════════════"
echo "Base de Datos: $DB_NAME"
echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Contador de pruebas
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=7

#
# TEST 1: Verificar que menús duplicados fueron eliminados
#
echo "${BOLD}[1/$TOTAL_TESTS]${NC} Verificando eliminación de menús duplicados..."

DUPLICATES=$(grep "menu_dte_invoices\|menu_dte_credit_notes\|menu_dte_guias_despacho\|menu_dte_honorarios" \
  "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml" 2>/dev/null | wc -l | tr -d ' ')

if [ "$DUPLICATES" -eq 0 ]; then
    echo "${GREEN}✅ PASS${NC}: Menús duplicados eliminados correctamente"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "${RED}❌ FAIL${NC}: Menús duplicados aún existen ($DUPLICATES ocurrencias)"
    echo "   Menús que deberían estar eliminados:"
    grep -n "menu_dte_invoices\|menu_dte_credit_notes\|menu_dte_guias_despacho\|menu_dte_honorarios" \
      "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml" 2>/dev/null || true
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

#
# TEST 2: Verificar que vistas mantienen herencia
#
echo ""
echo "${BOLD}[2/$TOTAL_TESTS]${NC} Verificando herencia de vistas..."

INHERITANCES=$(grep -c "inherit_id" "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/account_move_dte_views.xml" 2>/dev/null)

if [ "$INHERITANCES" -ge 3 ]; then
    echo "${GREEN}✅ PASS${NC}: Vistas mantienen herencia ($INHERITANCES encontradas)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "${RED}❌ FAIL${NC}: Herencia de vistas posiblemente rota (encontradas: $INHERITANCES, esperadas: ≥3)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

#
# TEST 3: Verificar sintaxis XML
#
echo ""
echo "${BOLD}[3/$TOTAL_TESTS]${NC} Validando sintaxis XML..."

if xmllint --noout "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml" 2>/dev/null; then
    echo "${GREEN}✅ PASS${NC}: Sintaxis XML válida"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "${RED}❌ FAIL${NC}: Sintaxis XML inválida"
    xmllint --noout "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml" 2>&1 || true
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

#
# TEST 4: Verificar que menús correctos siguen existiendo
#
echo ""
echo "${BOLD}[4/$TOTAL_TESTS]${NC} Verificando menús de funcionalidad nueva..."

REQUIRED_MENUS=(
    "menu_dte_inbox"
    "menu_l10n_cl_rcv_periods"
    "menu_dte_certificates"
    "menu_dte_caf"
    "menu_retencion_iue"
    "menu_boleta_honorarios"
    "menu_rcv_csv_import_wizard"
)

ALL_EXIST=true
MISSING_MENUS=""

for menu in "${REQUIRED_MENUS[@]}"; do
    if ! grep -q "id=\"$menu\"" "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml"; then
        ALL_EXIST=false
        MISSING_MENUS="$MISSING_MENUS\n   - $menu"
    fi
done

if [ "$ALL_EXIST" = true ]; then
    echo "${GREEN}✅ PASS${NC}: Todos los menús requeridos existen (${#REQUIRED_MENUS[@]} menús)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "${RED}❌ FAIL${NC}: Menús faltantes:$MISSING_MENUS"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

#
# TEST 5: Verificar comentario de arquitectura
#
echo ""
echo "${BOLD}[5/$TOTAL_TESTS]${NC} Verificando documentación inline..."

if grep -q "ARQUITECTURA DE MENÚS" "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml"; then
    echo "${GREEN}✅ PASS${NC}: Comentario de arquitectura presente"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "${RED}❌ FAIL${NC}: Comentario de arquitectura faltante"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

#
# TEST 6: Verificar que "Documentos Especiales" existe
#
echo ""
echo "${BOLD}[6/$TOTAL_TESTS]${NC} Verificando renombrado de sección..."

if grep -q 'name="Documentos Especiales"' "$PROJECT_ROOT/addons/localization/l10n_cl_dte/views/menus.xml"; then
    echo "${GREEN}✅ PASS${NC}: Sección \"Documentos Especiales\" existe"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "${RED}❌ FAIL${NC}: Sección \"Documentos Especiales\" no encontrada"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

#
# TEST 7: Intentar cargar módulo en base de datos
#
echo ""
echo "${BOLD}[7/$TOTAL_TESTS]${NC} Intentando cargar módulo en base de datos $DB_NAME..."

# Crear archivo temporal para log
TEMP_LOG=$(mktemp)

if docker-compose run --rm odoo odoo -c /etc/odoo/odoo.conf -d "$DB_NAME" \
  --log-level=error -u l10n_cl_dte --stop-after-init > "$TEMP_LOG" 2>&1; then

    # Verificar que no hay errores en el log
    if grep -i "error" "$TEMP_LOG" > /dev/null; then
        echo "${RED}❌ FAIL${NC}: Errores al cargar módulo"
        echo "${YELLOW}Errores encontrados:${NC}"
        grep -i "error" "$TEMP_LOG" | head -10
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo "${GREEN}✅ PASS${NC}: Módulo cargó sin errores"

        # Mostrar estadísticas
        if grep "Module l10n_cl_dte loaded" "$TEMP_LOG" > /dev/null; then
            LOAD_TIME=$(grep "Module l10n_cl_dte loaded" "$TEMP_LOG" | grep -oP '\\d+\\.\\d+s' | head -1)
            QUERIES=$(grep "Module l10n_cl_dte loaded" "$TEMP_LOG" | grep -oP '\\d+ queries' | head -1)
            echo "   Tiempo de carga: $LOAD_TIME"
            echo "   Queries ejecutadas: $QUERIES"
        fi

        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
else
    echo "${RED}❌ FAIL${NC}: Fallo al cargar módulo"
    echo "${YELLOW}Salida de docker-compose:${NC}"
    cat "$TEMP_LOG" | tail -20
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Limpiar archivo temporal
rm -f "$TEMP_LOG"

#
# RESUMEN FINAL
#
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  RESUMEN DE VALIDACIÓN"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Total de pruebas: $TOTAL_TESTS"
echo "${GREEN}Exitosas: $TESTS_PASSED${NC}"
echo "${RED}Fallidas: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "${GREEN}${BOLD}✅ VALIDACIÓN EXITOSA${NC}"
    echo ""
    echo "Siguiente paso: Validación manual"
    echo "1. Login a Odoo $DB_NAME"
    echo "2. Ir a: Contabilidad > Clientes > Invoices"
    echo "3. Verificar campos DTE aparecen"
    echo "4. Verificar que NO existen menús duplicados en 'DTE Chile'"
    echo ""
    exit 0
else
    echo "${RED}${BOLD}❌ VALIDACIÓN FALLIDA${NC}"
    echo ""
    echo "Se encontraron $TESTS_FAILED problema(s)."
    echo "Por favor revisa los errores arriba y corrige antes de continuar."
    echo ""
    exit 1
fi
