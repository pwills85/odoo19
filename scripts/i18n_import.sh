#!/bin/bash
# Script para importar traducciones actualizadas
# Ubicación: /Users/pedro/Documents/odoo19/scripts/i18n_import.sh

set -e

BASE_PATH="/Users/pedro/Documents/odoo19/addons/localization"
DB_NAME="odoo19_production"
MODULES=("l10n_cl_dte" "l10n_cl_dte_eergygroup" "l10n_cl_dte_enhanced"
         "l10n_cl_hr_payroll" "l10n_cl_financial_reports")

echo "======================================"
echo "  i18n: Importar Traducciones"
echo "======================================"
echo ""

for MODULE in "${MODULES[@]}"; do
    PO_FILE="$BASE_PATH/$MODULE/i18n/es_CL.po"

    if [ -f "$PO_FILE" ]; then
        echo "► Importando: $MODULE"

        docker-compose exec -T odoo odoo \
            -c /etc/odoo/odoo.conf \
            -d "$DB_NAME" \
            --i18n-import="/mnt/extra-addons/localization/$MODULE/i18n/es_CL.po" \
            --language=es_CL \
            --modules="$MODULE" \
            --stop-after-init > /dev/null 2>&1

        echo "  ✓ $MODULE importado"
    else
        echo "⚠ Saltando $MODULE (no tiene es_CL.po)"
    fi
done

echo ""
echo "======================================"
echo "  IMPORTACIÓN COMPLETADA"
echo "======================================"
echo ""
echo "Reiniciando Odoo para aplicar cambios..."
docker-compose restart odoo
echo "✓ Listo"
