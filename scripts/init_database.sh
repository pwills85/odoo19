#!/bin/bash
# Script para inicializar base de datos Odoo con módulos base
# FASE 2: Instalabilidad Módulos

set -e

echo "=============================================================================="
echo "INICIANDO INSTALACIÓN DE BASE DE DATOS ODOO"
echo "=============================================================================="

# Detener servicio
echo "Deteniendo servicio Odoo..."
docker-compose -f /Users/pedro/Documents/odoo19/docker-compose.yml stop odoo

# Esperar a que pare completamente
sleep 5

# Ejecutar instalación
echo ""
echo "Instalando módulos base: base, web, l10n_cl..."
echo ""

docker-compose -f /Users/pedro/Documents/odoo19/docker-compose.yml run --rm \
  -e ODOO_EXTRA_ARGS="-i base,web,l10n_cl --stop-after-init --log-level=info --without-demo=all" \
  odoo

INSTALL_EXIT_CODE=$?

echo ""
echo "Código de salida instalación: $INSTALL_EXIT_CODE"
echo ""

# Reiniciar servicio
echo "Reiniciando servicio Odoo..."
docker-compose -f /Users/pedro/Documents/odoo19/docker-compose.yml up -d odoo

# Esperar a que arranque
sleep 10

# Verificar instalación
echo ""
echo "=============================================================================="
echo "VERIFICANDO INSTALACIÓN"
echo "=============================================================================="

docker exec -i odoo19_db psql -U odoo -d odoo19 -c "SELECT name, state FROM ir_module_module WHERE name IN ('base', 'web', 'l10n_cl');"

echo ""
echo "=============================================================================="
echo "INSTALACIÓN COMPLETADA"
echo "=============================================================================="

exit $INSTALL_EXIT_CODE
