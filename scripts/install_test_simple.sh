#!/bin/bash
#
# Instalación Simple de Módulos en BD TEST
#

set -e

echo "═══════════════════════════════════════════════════════════════════════"
echo "  INSTALACIÓN DE MÓDULOS EN BD TEST"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

DB_NAME="TEST"
LOG_FILE="/tmp/odoo_install_$(date +%Y%m%d_%H%M%S).log"

echo "Base de datos: $DB_NAME"
echo "Log file: $LOG_FILE"
echo ""

# Stop Odoo
echo "[1/4] Deteniendo Odoo..."
docker-compose stop odoo

echo ""
echo "[2/4] Instalando módulos..."
echo "Comando: odoo -d $DB_NAME -i l10n_cl_dte,l10n_cl_dte_enhanced,eergygroup_branding --stop-after-init"
echo ""

# Run installation
docker-compose run --rm odoo \
    odoo -d $DB_NAME \
    -i l10n_cl_dte,l10n_cl_dte_enhanced,eergygroup_branding \
    --stop-after-init \
    2>&1 | tee $LOG_FILE

INSTALL_EXIT=$?

echo ""
echo "[3/4] Analizando logs..."

# Count errors (excluding expected messages)
ERRORS=$(grep -i "ERROR\|CRITICAL\|Traceback" $LOG_FILE | \
    grep -v "Some modules are not loaded" | \
    grep -v "database TEST does not exist" | \
    wc -l | tr -d ' ')

WARNINGS=$(grep -i "WARNING" $LOG_FILE | \
    grep -v "deprecated" | \
    grep -v "No" | \
    wc -l | tr -d ' ')

echo "Errores: $ERRORS"
echo "Warnings: $WARNINGS"

if [ "$ERRORS" -gt "0" ]; then
    echo ""
    echo "❌ ERRORES ENCONTRADOS:"
    grep -i "ERROR\|CRITICAL\|Traceback" $LOG_FILE | \
        grep -v "Some modules are not loaded" | \
        head -10
fi

echo ""
echo "[4/4] Reiniciando Odoo..."
docker-compose start odoo
sleep 3

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
if [ "$INSTALL_EXIT" -eq "0" ] && [ "$ERRORS" -eq "0" ]; then
    echo "✅ INSTALACIÓN EXITOSA"
    echo "   Errores: 0"
    echo "   Warnings: $WARNINGS"
else
    echo "❌ INSTALACIÓN CON ERRORES"
    echo "   Exit code: $INSTALL_EXIT"
    echo "   Errores: $ERRORS"
fi
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "Log: $LOG_FILE"

exit $INSTALL_EXIT
