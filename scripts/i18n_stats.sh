#!/bin/bash
# Script para generar estadísticas de traducción por módulo
# Ubicación: /Users/pedro/Documents/odoo19/scripts/i18n_stats.sh

BASE_PATH="/Users/pedro/Documents/odoo19/addons/localization"
MODULES=("l10n_cl_dte" "l10n_cl_dte_eergygroup" "l10n_cl_dte_enhanced"
         "l10n_cl_hr_payroll" "l10n_cl_financial_reports")

echo "======================================"
echo "  i18n: Estadísticas de Traducción"
echo "======================================"
echo ""
printf "%-30s | %10s | %10s | %10s | %8s\n" "MÓDULO" "TRADUCIDAS" "FALTANTES" "FUZZY" "% COMPL"
echo "-----------------------------------------------------------------------"

for MODULE in "${MODULES[@]}"; do
    PO_FILE="$BASE_PATH/$MODULE/i18n/es_CL.po"

    if [ -f "$PO_FILE" ]; then
        STATS=$(msgfmt --statistics "$PO_FILE" 2>&1)

        TRANS=$(echo "$STATS" | grep -oE '[0-9]+ translated' | grep -oE '[0-9]+' || echo "0")
        UNTRANS=$(echo "$STATS" | grep -oE '[0-9]+ untranslated' | grep -oE '[0-9]+' || echo "0")
        FUZZY=$(echo "$STATS" | grep -oE '[0-9]+ fuzzy' | grep -oE '[0-9]+' || echo "0")

        TOTAL=$((TRANS + UNTRANS + FUZZY))
        if [ $TOTAL -gt 0 ]; then
            PERCENT=$((TRANS * 100 / TOTAL))
        else
            PERCENT=0
        fi

        printf "%-30s | %10d | %10d | %10d | %7d%%\n" "$MODULE" "$TRANS" "$UNTRANS" "$FUZZY" "$PERCENT"
    else
        printf "%-30s | %10s | %10s | %10s | %8s\n" "$MODULE" "-" "-" "-" "N/A"
    fi
done

echo ""
