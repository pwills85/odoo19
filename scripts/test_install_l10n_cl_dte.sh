#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Script de Validación de Instalación - l10n_cl_dte
# ══════════════════════════════════════════════════════════════════════════════
# Autor: Cascade AI
# Fecha: 2025-10-24
# Descripción: Valida que el módulo l10n_cl_dte se pueda instalar sin errores
# ══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
DB_NAME="test_l10n_cl_dte_$(date +%Y%m%d_%H%M%S)"
LOG_DIR="./logs"
INSTALL_LOG="${LOG_DIR}/install_${DB_NAME}.log"
UPDATE_LOG="${LOG_DIR}/update_${DB_NAME}.log"

# Crear directorio de logs
mkdir -p "${LOG_DIR}"

echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test de Instalación - l10n_cl_dte${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 1: Verificar que servicios estén corriendo
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[1/7]${NC} Verificando servicios Docker..."

if ! docker-compose ps | grep -q "Up"; then
    echo -e "${RED}✗ Servicios no están corriendo. Ejecuta: docker-compose up -d${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Servicios Docker corriendo${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 2: Verificar conectividad a PostgreSQL
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[2/7]${NC} Verificando conectividad a PostgreSQL..."

if ! docker-compose exec -T db pg_isready -U odoo > /dev/null 2>&1; then
    echo -e "${RED}✗ PostgreSQL no está listo${NC}"
    exit 1
fi

echo -e "${GREEN}✓ PostgreSQL listo${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 3: Crear base de datos de prueba
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[3/7]${NC} Creando base de datos de prueba: ${DB_NAME}..."

docker-compose exec -T db psql -U odoo -c "CREATE DATABASE ${DB_NAME};" > /dev/null 2>&1 || {
    echo -e "${RED}✗ Error creando base de datos${NC}"
    exit 1
}

echo -e "${GREEN}✓ Base de datos creada${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 4: Instalar módulo
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[4/7]${NC} Instalando módulo l10n_cl_dte..."
echo -e "${BLUE}   Log: ${INSTALL_LOG}${NC}"

docker-compose exec -T odoo odoo \
    -c /etc/odoo/odoo.conf \
    -d "${DB_NAME}" \
    -i l10n_cl_dte \
    --stop-after-init \
    --log-level=info \
    > "${INSTALL_LOG}" 2>&1

# Verificar errores en log
if grep -qi "error\|traceback\|exception" "${INSTALL_LOG}"; then
    echo -e "${RED}✗ Errores encontrados durante instalación${NC}"
    echo -e "${RED}   Ver: ${INSTALL_LOG}${NC}"
    grep -i "error\|traceback" "${INSTALL_LOG}" | head -20
    exit 1
fi

echo -e "${GREEN}✓ Módulo instalado sin errores${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 5: Verificar warnings
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[5/7]${NC} Verificando warnings..."

WARNING_COUNT=$(grep -ci "warning" "${INSTALL_LOG}" || true)

if [ "${WARNING_COUNT}" -gt 0 ]; then
    echo -e "${YELLOW}⚠ ${WARNING_COUNT} warnings encontrados${NC}"
    grep -i "warning" "${INSTALL_LOG}" | head -10
else
    echo -e "${GREEN}✓ Sin warnings${NC}"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 6: Test de actualización
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[6/7]${NC} Probando actualización del módulo..."
echo -e "${BLUE}   Log: ${UPDATE_LOG}${NC}"

docker-compose exec -T odoo odoo \
    -c /etc/odoo/odoo.conf \
    -d "${DB_NAME}" \
    -u l10n_cl_dte \
    --stop-after-init \
    --log-level=info \
    > "${UPDATE_LOG}" 2>&1

# Verificar errores en log de actualización
if grep -qi "error\|traceback\|exception" "${UPDATE_LOG}"; then
    echo -e "${RED}✗ Errores encontrados durante actualización${NC}"
    echo -e "${RED}   Ver: ${UPDATE_LOG}${NC}"
    grep -i "error\|traceback" "${UPDATE_LOG}" | head -20
    exit 1
fi

echo -e "${GREEN}✓ Módulo actualizado sin errores${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PASO 7: Limpiar base de datos de prueba
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${YELLOW}[7/7]${NC} Limpiando base de datos de prueba..."

docker-compose exec -T db psql -U odoo -c "DROP DATABASE ${DB_NAME};" > /dev/null 2>&1 || {
    echo -e "${YELLOW}⚠ No se pudo eliminar base de datos de prueba${NC}"
}

echo -e "${GREEN}✓ Base de datos eliminada${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# RESUMEN
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ TODOS LOS TESTS PASARON${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Resumen:"
echo -e "  ${GREEN}✓${NC} Instalación exitosa"
echo -e "  ${GREEN}✓${NC} Actualización exitosa"
if [ "${WARNING_COUNT}" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} ${WARNING_COUNT} warnings (revisar logs)"
else
    echo -e "  ${GREEN}✓${NC} Sin warnings"
fi
echo ""
echo -e "Logs guardados en:"
echo -e "  - ${INSTALL_LOG}"
echo -e "  - ${UPDATE_LOG}"
echo ""
echo -e "${GREEN}El módulo l10n_cl_dte está listo para producción${NC}"
echo ""
