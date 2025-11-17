#!/bin/bash
# Quick syntax check for v2.0 script
echo "🔍 Verificando sintaxis ciclo_completo_auditoria_v2.sh..."
bash -n /Users/pedro/Documents/odoo19/docs/prompts/08_scripts/ciclo_completo_auditoria_v2.sh
if [ $? -eq 0 ]; then
    echo "✅ Sintaxis válida"
else
    echo "❌ Errores de sintaxis detectados"
    exit 1
fi

# Count lines
echo ""
echo "📊 Estadísticas:"
wc -l /Users/pedro/Documents/odoo19/docs/prompts/08_scripts/ciclo_completo_auditoria_v2.sh
wc -l /Users/pedro/Documents/odoo19/docs/prompts/08_scripts/PERFORMANCE_IMPROVEMENTS.md
echo ""
echo "✅ Verificación completada"
