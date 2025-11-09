#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Script de Validación de Dependencias - Imagen Odoo 19 CE
# ══════════════════════════════════════════════════════════════════════════════
# Autor: Cascade AI
# Fecha: 2025-10-24
# Descripción: Valida que todas las dependencias Python estén instaladas
#              correctamente en la imagen Docker de Odoo
# ══════════════════════════════════════════════════════════════════════════════

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Validación de Dependencias - Imagen Odoo 19 CE${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 1: Verificar que imagen existe
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[1/4]${NC} Verificando imagen Docker..."

if ! docker images | grep -q "eergygroup/odoo19"; then
    echo -e "${RED}✗ Imagen eergygroup/odoo19 no encontrada${NC}"
    echo -e "${YELLOW}  Ejecuta: docker-compose build odoo${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Imagen encontrada${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 2: Verificar dependencias l10n_cl_dte
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[2/4]${NC} Verificando dependencias l10n_cl_dte..."

DEPS_DTE=(
    "lxml"
    "requests"
    "OpenSSL:pyOpenSSL"
    "cryptography"
    "zeep"
    "pika"
)

FAILED=0

for dep in "${DEPS_DTE[@]}"; do
    IFS=':' read -r import_name package_name <<< "$dep"
    package_name=${package_name:-$import_name}
    
    if docker run --rm eergygroup/odoo19:v1 python3 -c "import ${import_name}" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${package_name}"
    else
        echo -e "  ${RED}✗${NC} ${package_name} - NO INSTALADO"
        FAILED=$((FAILED + 1))
    fi
done

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 3: Verificar dependencias l10n_cl_financial_reports
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[3/4]${NC} Verificando dependencias l10n_cl_financial_reports..."

DEPS_FINANCIAL=(
    "xlsxwriter"
    "dateutil:python-dateutil"
    "numpy"
    "sklearn:scikit-learn"
    "joblib"
    "jwt:PyJWT"
)

for dep in "${DEPS_FINANCIAL[@]}"; do
    IFS=':' read -r import_name package_name <<< "$dep"
    package_name=${package_name:-$import_name}
    
    if docker run --rm eergygroup/odoo19:v1 python3 -c "import ${import_name}" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${package_name}"
    else
        echo -e "  ${RED}✗${NC} ${package_name} - NO INSTALADO"
        FAILED=$((FAILED + 1))
    fi
done

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 4: Verificar dependencias compartidas
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[4/4]${NC} Verificando dependencias compartidas..."

DEPS_SHARED=(
    "phonenumbers"
    "reportlab"
    "pytest"
    "PIL:pillow"
    "qrcode"
)

for dep in "${DEPS_SHARED[@]}"; do
    IFS=':' read -r import_name package_name <<< "$dep"
    package_name=${package_name:-$import_name}
    
    if docker run --rm eergygroup/odoo19:v1 python3 -c "import ${import_name}" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${package_name}"
    else
        echo -e "  ${RED}✗${NC} ${package_name} - NO INSTALADO"
        FAILED=$((FAILED + 1))
    fi
done

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# RESUMEN
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ TODAS LAS DEPENDENCIAS INSTALADAS${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "La imagen Docker está lista para:"
    echo -e "  ${GREEN}✓${NC} l10n_cl_dte (Facturación Electrónica)"
    echo -e "  ${GREEN}✓${NC} l10n_cl_financial_reports (Reportes Financieros)"
    echo -e "  ${GREEN}✓${NC} l10n_cl_hr_payroll (Nómina)"
    echo ""
    exit 0
else
    echo -e "${RED}✗ ${FAILED} DEPENDENCIAS FALTANTES${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Solución:${NC}"
    echo -e "  1. Verificar que requirements-localization.txt esté completo"
    echo -e "  2. Rebuild de imagen: docker-compose build --no-cache odoo"
    echo -e "  3. Ejecutar este script nuevamente"
    echo ""
    exit 1
fi
