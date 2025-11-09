#!/bin/bash
# Script de verificación rápida i18n
# Ubicación: /Users/pedro/Documents/odoo19/scripts/i18n_quick_check.sh

BASE_PATH="/Users/pedro/Documents/odoo19/addons/localization"

echo "═══════════════════════════════════════════════════════"
echo "  i18n Quick Check - Localización Chilena"
echo "═══════════════════════════════════════════════════════"
echo ""

# Función para verificar existencia de archivos i18n
check_i18n() {
    local module=$1
    local module_path="$BASE_PATH/$module"

    printf "%-30s | " "$module"

    if [ ! -d "$module_path/i18n" ]; then
        echo "❌ NO i18n/"
        return
    fi

    if [ -f "$module_path/i18n/es_CL.po" ]; then
        # Contar strings
        if command -v msgfmt &> /dev/null; then
            STATS=$(msgfmt --statistics "$module_path/i18n/es_CL.po" 2>&1)
            TRANS=$(echo "$STATS" | grep -oE '[0-9]+ translated' | grep -oE '[0-9]+' || echo "0")
            UNTRANS=$(echo "$STATS" | grep -oE '[0-9]+ untranslated' | grep -oE '[0-9]+' || echo "0")
            TOTAL=$((TRANS + UNTRANS))

            if [ $TOTAL -gt 0 ]; then
                PERCENT=$((TRANS * 100 / TOTAL))
                if [ $PERCENT -eq 100 ]; then
                    echo "✅ $PERCENT% ($TRANS/$TOTAL)"
                elif [ $PERCENT -ge 80 ]; then
                    echo "⚠️  $PERCENT% ($TRANS/$TOTAL)"
                else
                    echo "🔴 $PERCENT% ($TRANS/$TOTAL)"
                fi
            else
                echo "⚠️  es_CL.po vacío"
            fi
        else
            echo "✅ es_CL.po existe"
        fi
    else
        echo "❌ NO es_CL.po"
    fi
}

echo "MÓDULO                         | ESTADO"
echo "---------------------------------------------------------------"

check_i18n "l10n_cl_dte"
check_i18n "l10n_cl_dte_eergygroup"
check_i18n "l10n_cl_dte_enhanced"
check_i18n "l10n_cl_financial_reports"
check_i18n "l10n_cl_hr_payroll"

echo ""
echo "LEYENDA:"
echo "  ✅ = 100% traducido o configurado"
echo "  ⚠️  = 80-99% traducido o requiere revisión"
echo "  🔴 = < 80% traducido"
echo "  ❌ = Sin configurar i18n"
echo ""

# Verificar campos sin string= (quick sample)
echo "═══════════════════════════════════════════════════════"
echo "  Verificación Rápida: Campos sin string="
echo "═══════════════════════════════════════════════════════"
echo ""

for module in l10n_cl_dte l10n_cl_hr_payroll l10n_cl_financial_reports; do
    module_path="$BASE_PATH/$module"
    if [ -d "$module_path/models" ]; then
        COUNT=$(grep -r "fields\." "$module_path/models"/*.py 2>/dev/null | grep -v "string=" | grep -c "fields\.\(Char\|Selection\|Many2one\|Boolean\|Integer\)" || echo "0")
        if [ "$COUNT" -gt 0 ]; then
            printf "%-30s : ⚠️  %d campos sin string=\n" "$module" "$COUNT"
        else
            printf "%-30s : ✅ Todos los campos con string=\n" "$module"
        fi
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Para más detalles: cat /tmp/audit_i18n.txt"
echo "═══════════════════════════════════════════════════════"
