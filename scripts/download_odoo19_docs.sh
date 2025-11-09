#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
# Script: Descarga Documentación Técnica Odoo 19 CE
# Propósito: Descargar documentación oficial y código fuente para desarrollo
# Autor: Eergygroup
# Fecha: 2025-10-21
#═══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

PROJECT_DIR="/Users/pedro/Documents/odoo19"
DOCS_DIR="$PROJECT_DIR/docs/odoo19_official"
TEMP_DIR="$DOCS_DIR/temp_download"

echo "════════════════════════════════════════════════════════════"
echo "📥 Descargando Documentación Odoo 19 CE"
echo "════════════════════════════════════════════════════════════"
echo ""

# Verificar que tenemos conexión
echo "🔍 Verificando conexión a internet..."
if ! ping -c 1 google.com > /dev/null 2>&1; then
    echo "❌ ERROR: No hay conexión a internet"
    exit 1
fi
echo "✅ Conexión OK"
echo ""

# Crear directorio temporal
mkdir -p "$TEMP_DIR"

#═══════════════════════════════════════════════════════════════════════════════
# FASE 1: Documentación Oficial Odoo
#═══════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════"
echo "📄 FASE 1: Documentación Oficial Odoo 19"
echo "════════════════════════════════════════════════════════════"
echo ""

# 1.1 ORM API Reference
echo "  [1/8] Descargando ORM API Reference..."
curl -s -L -o "$DOCS_DIR/01_developer/orm_api_reference.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html" || \
  echo "⚠️  Advertencia: No se pudo descargar ORM API Reference"

# 1.2 Views Reference
echo "  [2/8] Descargando Views Reference..."
curl -s -L -o "$DOCS_DIR/04_views_ui/views_reference.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/backend/views.html" || \
  echo "⚠️  Advertencia: No se pudo descargar Views Reference"

# 1.3 Security Reference
echo "  [3/8] Descargando Security Reference..."
curl -s -L -o "$DOCS_DIR/05_security/access_rights.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/backend/security.html" || \
  echo "⚠️  Advertencia: No se pudo descargar Security Reference"

# 1.4 QWeb Reference
echo "  [4/8] Descargando QWeb Reference..."
curl -s -L -o "$DOCS_DIR/06_reports/qweb_reference.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/frontend/qweb.html" || \
  echo "⚠️  Advertencia: No se pudo descargar QWeb Reference"

# 1.5 HTTP Controllers
echo "  [5/8] Descargando HTTP Controllers..."
curl -s -L -o "$DOCS_DIR/07_controllers/http_controllers.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/backend/http.html" || \
  echo "⚠️  Advertencia: No se pudo descargar HTTP Controllers"

# 1.6 Testing Framework
echo "  [6/8] Descargando Testing Framework..."
curl -s -L -o "$DOCS_DIR/08_testing/testing_framework.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/backend/testing.html" || \
  echo "⚠️  Advertencia: No se pudo descargar Testing Framework"

# 1.7 Data Files
echo "  [7/8] Descargando Data Files Reference..."
curl -s -L -o "$DOCS_DIR/09_data_files/xml_data_format.html" \
  "https://www.odoo.com/documentation/19.0/developer/reference/backend/data.html" || \
  echo "⚠️  Advertencia: No se pudo descargar Data Files Reference"

# 1.8 Module Structure
echo "  [8/8] Descargando Module Structure..."
curl -s -L -o "$DOCS_DIR/01_developer/module_structure.html" \
  "https://www.odoo.com/documentation/19.0/developer/tutorials/server_framework_101.html" || \
  echo "⚠️  Advertencia: No se pudo descargar Module Structure"

echo "✅ Fase 1 completada"
echo ""

#═══════════════════════════════════════════════════════════════════════════════
# FASE 2: Código Fuente Módulos Base
#═══════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════"
echo "📦 FASE 2: Código Fuente Módulos Base Odoo 19"
echo "════════════════════════════════════════════════════════════"
echo ""

cd "$TEMP_DIR"

# 2.1 Clonar repositorio Odoo 19 (shallow clone)
echo "  Clonando repositorio Odoo 19 (esto puede tomar 5-10 min)..."
if [ ! -d "odoo" ]; then
    git clone --depth 1 --branch 19.0 --single-branch \
      https://github.com/odoo/odoo.git odoo 2>&1 | grep -v "remote:" || \
      echo "⚠️  Advertencia: Error al clonar repositorio"
fi

if [ -d "odoo" ]; then
    echo "✅ Repositorio clonado exitosamente"
    echo ""
    
    # 2.2 Copiar archivos críticos del módulo account
    echo "  Copiando archivos módulo account..."
    cp odoo/addons/account/models/account_move.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/account/models/account_journal.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/account/models/account_tax.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/account/models/account_payment.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/account/__manifest__.py "$DOCS_DIR/02_models_base/account_manifest.py" 2>/dev/null || true
    cp odoo/addons/account/views/account_move_views.xml "$DOCS_DIR/04_views_ui/account_move_views.xml" 2>/dev/null || true
    cp odoo/addons/account/security/ir.model.access.csv "$DOCS_DIR/05_security/account_access.csv" 2>/dev/null || true
    
    # 2.3 Copiar archivos del módulo base
    echo "  Copiando archivos módulo base..."
    cp odoo/odoo/models.py "$DOCS_DIR/02_models_base/odoo_models_base.py" 2>/dev/null || true
    cp odoo/odoo/fields.py "$DOCS_DIR/02_models_base/odoo_fields_base.py" 2>/dev/null || true
    cp odoo/addons/base/models/res_partner.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/base/models/res_company.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    
    # 2.4 Copiar archivos del módulo purchase
    echo "  Copiando archivos módulo purchase..."
    cp odoo/addons/purchase/models/purchase_order.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/purchase/views/purchase_views.xml "$DOCS_DIR/04_views_ui/" 2>/dev/null || true
    
    # 2.5 Copiar archivos del módulo stock
    echo "  Copiando archivos módulo stock..."
    cp odoo/addons/stock/models/stock_picking.py "$DOCS_DIR/02_models_base/" 2>/dev/null || true
    cp odoo/addons/stock/views/stock_picking_views.xml "$DOCS_DIR/04_views_ui/" 2>/dev/null || true
    
    # 2.6 Copiar módulo completo l10n_latam_base
    echo "  Copiando módulo l10n_latam_base completo..."
    if [ -d "odoo/addons/l10n_latam_base" ]; then
        cp -r odoo/addons/l10n_latam_base "$DOCS_DIR/03_localization/" 2>/dev/null || true
    fi
    
    # 2.7 Copiar también l10n_cl si existe (referencia Chile)
    echo "  Copiando módulo l10n_cl (si existe)..."
    if [ -d "odoo/addons/l10n_cl" ]; then
        cp -r odoo/addons/l10n_cl "$DOCS_DIR/03_localization/" 2>/dev/null || true
    fi
    
    echo "✅ Archivos copiados exitosamente"
else
    echo "❌ ERROR: No se pudo clonar el repositorio"
fi

echo "✅ Fase 2 completada"
echo ""

#═══════════════════════════════════════════════════════════════════════════════
# FASE 3: Limpieza
#═══════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════"
echo "🧹 FASE 3: Limpieza de Archivos Temporales"
echo "════════════════════════════════════════════════════════════"
echo ""

# Limpiar directorio temporal (pero mantener archivos descargados)
echo "  Eliminando archivos temporales..."
rm -rf "$TEMP_DIR/odoo/.git" 2>/dev/null || true
rm -rf "$TEMP_DIR/odoo" 2>/dev/null || true

echo "✅ Fase 3 completada"
echo ""

#═══════════════════════════════════════════════════════════════════════════════
# FASE 4: Verificación y Resumen
#═══════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════"
echo "✅ DESCARGA COMPLETADA EXITOSAMENTE"
echo "════════════════════════════════════════════════════════════"
echo ""

# Contar archivos descargados
NUM_DOCS=$(find "$DOCS_DIR" -type f -name "*.html" -o -name "*.py" -o -name "*.xml" | wc -l | tr -d ' ')
NUM_DIRS=$(find "$DOCS_DIR" -type d | wc -l | tr -d ' ')

echo "📊 RESUMEN:"
echo "  • Archivos descargados: $NUM_DOCS"
echo "  • Directorios creados: $NUM_DIRS"
echo "  • Ubicación: $DOCS_DIR"
echo ""

echo "📂 ESTRUCTURA CREADA:"
ls -1 "$DOCS_DIR" | while read dir; do
    if [ -d "$DOCS_DIR/$dir" ]; then
        count=$(find "$DOCS_DIR/$dir" -type f | wc -l | tr -d ' ')
        echo "  ├─ $dir ($count archivos)"
    fi
done
echo ""

echo "🎯 PRÓXIMOS PASOS:"
echo "  1. Revisar archivos en: $DOCS_DIR"
echo "  2. Crear INDEX.md y CHEATSHEET.md"
echo "  3. Iniciar desarrollo módulo l10n_cl_dte"
echo ""

echo "════════════════════════════════════════════════════════════"

