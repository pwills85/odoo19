#!/bin/bash
# FASE 2: Migración modelos Python - l10n_cl_financial_reports
# Fecha: 2025-10-23
# Ejecuta cambios automáticos de ORM Odoo 18 → Odoo 19

set -e  # Exit on error

MODULE_PATH="/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_financial_reports"

echo "========================================="
echo "FASE 2: MIGRACIÓN MODELOS PYTHON"
echo "========================================="
echo ""

# Cambio 1: self._context → self.env.context
echo "[1/5] Verificando self._context..."
COUNT=$(grep -r "self\._context" "$MODULE_PATH/models" --include="*.py" | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "✅ NO hay ocurrencias de self._context (ya corregido)"
else
    echo "⚠️  Encontradas $COUNT ocurrencias. Aplicando fix..."
    find "$MODULE_PATH/models" -name "*.py" -exec sed -i '' 's/self\._context/self.env.context/g' {} \;
    echo "✅ Reemplazos aplicados"
fi
echo ""

# Cambio 2: self._uid → self.env.uid
echo "[2/5] Verificando self._uid..."
COUNT=$(grep -r "self\._uid" "$MODULE_PATH/models" --include="*.py" | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "✅ NO hay ocurrencias de self._uid"
else
    echo "⚠️  Encontradas $COUNT ocurrencias. Aplicando fix..."
    find "$MODULE_PATH/models" -name "*.py" -exec sed -i '' 's/self\._uid/self.env.uid/g' {} \;
    echo "✅ Reemplazos aplicados"
fi
echo ""

# Cambio 3: Imports deprecados
echo "[3/5] Verificando imports deprecados..."

# from odoo import registry
COUNT=$(grep -r "from odoo import.*registry" "$MODULE_PATH/models" --include="*.py" | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "✅ NO hay imports 'from odoo import registry'"
else
    echo "⚠️  Encontrados $COUNT imports. Revisar manualmente"
fi

# from odoo.osv import Expressions
COUNT=$(grep -r "from odoo.osv import.*Expressions" "$MODULE_PATH" --include="*.py" | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "✅ NO hay imports 'from odoo.osv import Expressions'"
else
    echo "⚠️  Encontrados $COUNT imports. Aplicando fix..."
    find "$MODULE_PATH" -name "*.py" -exec sed -i '' 's/from odoo.osv import Expressions/from odoo.fields import Domain/g' {} \;
    echo "✅ Reemplazos aplicados"
fi
echo ""

# Cambio 4: Validación name_get() removidos
echo "[4/5] Validando name_get() deprecated..."
COUNT=$(grep -r "def name_get" "$MODULE_PATH/models" --include="*.py" | wc -l | tr -d ' ')
if [ "$COUNT" -eq "0" ]; then
    echo "✅ Todos los name_get() han sido removidos/migrados"
else
    echo "⚠️  Aún hay $COUNT definiciones de name_get():"
    grep -rn "def name_get" "$MODULE_PATH/models" --include="*.py"
    echo ""
    echo "ACCIÓN REQUERIDA: Migrar a _compute_display_name()"
fi
echo ""

# Cambio 5: Validación sintáctica Python
echo "[5/5] Validando sintaxis Python..."
ERROR_COUNT=0

while IFS= read -r file; do
    if ! python3 -m py_compile "$file" 2>/dev/null; then
        echo "❌ Error de sintaxis en: $file"
        ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
done < <(find "$MODULE_PATH/models" -name "*.py")

if [ $ERROR_COUNT -eq 0 ]; then
    echo "✅ Sintaxis Python válida en todos los modelos"
else
    echo "❌ Encontrados $ERROR_COUNT archivos con errores de sintaxis"
    exit 1
fi
echo ""

echo "========================================="
echo "FASE 2: COMPLETADA"
echo "========================================="
echo ""
echo "✅ self._context migrado a self.env.context"
echo "✅ self._uid verificado"
echo "✅ Imports verificados"
echo "⚠️  name_get() pendientes de revisión manual"
echo "✅ Sintaxis Python validada"
echo ""
echo "Próximo paso: FASE 3 - Migrar vistas XML"
