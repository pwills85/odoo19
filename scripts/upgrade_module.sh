#!/bin/bash
# Script para actualizar módulo Odoo 19
# Uso: ./upgrade_module.sh MODULE_NAME

MODULE="${1:-l10n_cl_hr_payroll}"
DB_NAME="${DB_NAME:-odoo19}"

echo "🔄 Actualizando módulo: $MODULE"
echo ""

# 1. Detener Odoo
echo "⏸️  Deteniendo Odoo..."
docker-compose stop odoo
sleep 3

# 2. Ejecutar upgrade
echo "📦 Ejecutando upgrade de $MODULE..."
docker run --rm \
  --network=odoo19_default \
  -v "/Users/pedro/Documents/odoo19/addons/localization:/mnt/extra-addons/localization" \
  -v "/Users/pedro/Documents/odoo19/odoo.conf:/etc/odoo/odoo.conf" \
  -e DB_HOST=odoo19_db \
  eergygroup/odoo19:chile-1.0.5 \
  odoo -c /etc/odoo/odoo.conf -d "$DB_NAME" -u "$MODULE" --stop-after-init --log-level=info 2>&1 | tail -100

EXIT_CODE=$?

# 3. Reiniciar Odoo
echo ""
echo "▶️  Reiniciando Odoo..."
docker-compose start odoo
sleep 10

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Módulo $MODULE actualizado correctamente"

    # Verificar estado
    docker exec odoo19_db psql -U odoo -d "$DB_NAME" -c \
      "SELECT name, state, latest_version FROM ir_module_module WHERE name='$MODULE';"
else
    echo "❌ Error al actualizar módulo (exit code: $EXIT_CODE)"
    exit 1
fi
