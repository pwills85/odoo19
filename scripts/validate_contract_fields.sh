#!/bin/bash
# scripts/validate_contract_fields.sh
# Validar que todos los campos en hr_contract_views.xml existen en el modelo

set -e

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
VIEW_FILE="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll/views/hr_contract_views.xml"
MODEL_FILE="$PROJECT_ROOT/addons/localization/l10n_cl_hr_payroll/models/hr_contract_cl.py"

echo "🔍 Validando nombres de campos en hr_contract_views.xml..."
echo ""

# Extraer nombres de campos de la vista (excluir campos no relevantes)
VIEW_FIELDS=$(grep -o 'name="[^"]*"' "$VIEW_FILE" | \
    sed 's/name="//; s/"$//' | \
    grep -v "^hr\.contract\|^view_\|^inherit_id\|^arch\|^model\|^name$\|^string\|^colspan\|^position\|^expr\|^after\|^wage\|^separator\|^xpath" | \
    sort -u)

# Extraer nombres de campos del modelo
MODEL_FIELDS=$(grep -E '^\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*fields\.' "$MODEL_FILE" | \
    sed 's/^[[:space:]]*\([a-zA-Z_][a-zA-Z0-9_]*\).*/\1/' | sort -u)

echo "📋 Campos en vista XML:"
echo "$VIEW_FIELDS" | while read field; do echo "  - $field"; done
echo ""

# Validar cada campo de la vista
ERRORS=0
echo "🔍 Validando campos contra modelo..."
for field in $VIEW_FIELDS; do
    # Saltar campos que son del stub base
    if [[ "$field" =~ ^(employee_id|contract_type_id|date_start|date_end|currency_id|company_id)$ ]]; then
        echo "✅ Campo '$field' (stub base, skip validation)"
        continue
    fi

    if ! echo "$MODEL_FIELDS" | grep -q "^${field}$"; then
        echo "❌ Campo '$field' usado en vista pero NO existe en modelo"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ Campo '$field' existe en modelo"
    fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ Todos los campos de la vista existen en el modelo"
    exit 0
else
    echo "❌ Se encontraron $ERRORS campo(s) con problemas"
    exit 1
fi
