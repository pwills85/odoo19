#!/bin/bash
# Script para configurar i18n en módulos sin traducción
# Ubicación: /Users/pedro/Documents/odoo19/scripts/i18n_phase1_setup.sh

set -e  # Exit on error

BASE_PATH="/Users/pedro/Documents/odoo19/addons/localization"
DB_NAME="odoo19_production"
MODULES=("l10n_cl_dte" "l10n_cl_hr_payroll")

echo "======================================"
echo "  i18n FASE 1: Setup Infraestructura"
echo "======================================"
echo ""

for MODULE in "${MODULES[@]}"; do
    echo "► Procesando módulo: $MODULE"

    # 1. Crear directorio i18n/
    I18N_DIR="$BASE_PATH/$MODULE/i18n"
    mkdir -p "$I18N_DIR"
    echo "  ✓ Directorio creado: $I18N_DIR"

    # 2. Exportar .pot
    echo "  → Exportando .pot..."
    docker-compose exec -T odoo odoo \
        -c /etc/odoo/odoo.conf \
        -d "$DB_NAME" \
        --i18n-export="/mnt/extra-addons/localization/$MODULE/i18n/$MODULE.pot" \
        --modules="$MODULE" \
        --stop-after-init > /dev/null 2>&1
    echo "  ✓ .pot exportado"

    # 3. Crear es_CL.po desde .pot
    cp "$I18N_DIR/$MODULE.pot" "$I18N_DIR/es_CL.po"

    # 4. Actualizar header es_CL.po
    sed -i.bak 's/Language: /Language: es_CL/' "$I18N_DIR/es_CL.po"
    sed -i.bak 's/Language-Team: /Language-Team: Spanish (Chile)/' "$I18N_DIR/es_CL.po"
    rm "$I18N_DIR/es_CL.po.bak" 2>/dev/null || true
    echo "  ✓ es_CL.po creado con headers correctos"

    # 5. Validar sintaxis
    if command -v msgfmt &> /dev/null; then
        msgfmt -c -o /dev/null "$I18N_DIR/es_CL.po" && echo "  ✓ Sintaxis .po válida"
    fi

    echo ""
done

echo "======================================"
echo "  FASE 1 COMPLETADA"
echo "======================================"
echo ""
echo "SIGUIENTE PASO:"
echo "1. Traducir manualmente es_CL.po (o usar herramienta POEdit)"
echo "2. Importar traducciones: ./scripts/i18n_import.sh"
echo ""
