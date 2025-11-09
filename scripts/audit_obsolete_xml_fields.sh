#!/bin/bash
# scripts/audit_obsolete_xml_fields.sh
# Auditoría completa de campos obsoletos Odoo 19

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MODULE_DIR="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll"

echo "🔍 Auditoría de campos obsoletos Odoo 19 en XML..."
echo ""

# Campos obsoletos conocidos Odoo 19
OBSOLETE_FIELDS=(
    "category_id"      # res.groups → usar category o eliminar
    "numbercall"       # ir.cron → usar interval_number + interval_type
    "doall"            # ir.cron → obsoleto
    "active"           # ir.cron → usar active field directamente
    "priority"         # ir.cron → usar priority directamente
    "user_id"          # ir.cron → usar user_id directamente
    "state"            # ir.cron → obsoleto
    "nextcall"         # ir.cron → calcular automáticamente
)

echo "📋 Buscando campos obsoletos en archivos XML..."
echo ""

ERRORS=0

for field in "${OBSOLETE_FIELDS[@]}"; do
    echo "🔍 Buscando campo obsoleto: $field"

    # Buscar en todos los XML
    MATCHES=$(grep -rn "\"$field\"" "$MODULE_DIR" --include="*.xml" 2>/dev/null | grep -v "__pycache__" || true)

    if [ -n "$MATCHES" ]; then
        echo "  ❌ ENCONTRADO:"
        echo "$MATCHES" | sed 's/^/    /'
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✅ No encontrado"
    fi
    echo ""
done

# Buscar patrones específicos de Odoo 19 incompatibles
echo "🔍 Buscando patrones incompatibles Odoo 19..."
echo ""

# Patrón: category_id en res.groups
if grep -rn "category_id" "$MODULE_DIR" --include="*.xml" | grep -q "res.groups\|model=\"res.groups\""; then
    echo "  ❌ category_id encontrado en res.groups"
    grep -rn "category_id" "$MODULE_DIR" --include="*.xml" | grep "res.groups\|model=\"res.groups\""
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ category_id no encontrado en res.groups"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Auditoría completada: No se encontraron campos obsoletos"
    exit 0
else
    echo "❌ Auditoría completada: $ERRORS campo(s) obsoleto(s) encontrado(s)"
    exit 1
fi
