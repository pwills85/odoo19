#!/bin/bash
# -*- coding: utf-8 -*-
#
# Script de Instalación de Módulos en BD TEST - Odoo 19 CE
# =========================================================
#
# Instala l10n_cl_dte_enhanced y eergygroup_branding en base de datos TEST
# monitoreando errores y warnings en tiempo real.
#
# Author: EERGYGROUP - Ing. Pedro Troncoso Willz
# License: LGPL-3
#

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
DB_NAME="TEST"
ODOO_CONF="/etc/odoo/odoo.conf"
LOG_FILE="/tmp/odoo_install_$(date +%Y%m%d_%H%M%S).log"

echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  INSTALACIÓN DE MÓDULOS EN BD TEST - ODOO 19 CE${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Base de datos: ${BOLD}${DB_NAME}${NC}"
echo -e "${CYAN}Log file: ${BOLD}${LOG_FILE}${NC}"
echo ""

# Check database exists
echo -e "${BLUE}[1/6] Verificando base de datos TEST...${NC}"
DB_EXISTS=$(docker-compose exec -T db psql -U odoo -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")

if [ "$DB_EXISTS" != "1" ]; then
    echo -e "${RED}❌ Base de datos TEST no existe${NC}"
    echo -e "${YELLOW}Creando base de datos TEST...${NC}"
    docker-compose exec -T db psql -U odoo -c "CREATE DATABASE \"${DB_NAME}\";"
    echo -e "${GREEN}✅ Base de datos TEST creada${NC}"
else
    echo -e "${GREEN}✅ Base de datos TEST existe${NC}"
fi

echo ""

# Check if modules are already installed
echo -e "${BLUE}[2/6] Verificando estado de módulos...${NC}"

# Create temporary Python script to check module state
cat > /tmp/check_modules.py << 'EOF'
import sys
import psycopg2

db_name = sys.argv[1]

try:
    conn = psycopg2.connect(
        dbname=db_name,
        user='odoo',
        password='odoo',
        host='localhost',
        port='5432'
    )
    cur = conn.cursor()

    # Check if ir_module_module table exists
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'ir_module_module'
        );
    """)

    if not cur.fetchone()[0]:
        print("DATABASE_EMPTY")
        sys.exit(0)

    # Check modules
    for module in ['l10n_cl_dte_enhanced', 'eergygroup_branding']:
        cur.execute("""
            SELECT state FROM ir_module_module
            WHERE name = %s
        """, (module,))

        result = cur.fetchone()
        if result:
            print(f"{module}:{result[0]}")
        else:
            print(f"{module}:not_found")

    cur.close()
    conn.close()

except psycopg2.OperationalError:
    print("DATABASE_EMPTY")
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(1)
EOF

# Run check inside container
MODULE_STATUS=$(docker-compose exec -T db python3 /tmp/check_modules.py ${DB_NAME} 2>/dev/null || echo "DATABASE_EMPTY")

echo -e "${CYAN}Estado de módulos: ${MODULE_STATUS}${NC}"

# Determine installation command
if [[ "$MODULE_STATUS" == *"DATABASE_EMPTY"* ]] || [[ "$MODULE_STATUS" == *"not_found"* ]]; then
    INSTALL_MODE="install"
    ODOO_CMD="-i l10n_cl_dte,l10n_cl_dte_enhanced,eergygroup_branding"
    echo -e "${YELLOW}Modo: INSTALACIÓN (primera vez)${NC}"
else
    INSTALL_MODE="update"
    ODOO_CMD="-u l10n_cl_dte_enhanced,eergygroup_branding"
    echo -e "${YELLOW}Modo: ACTUALIZACIÓN${NC}"
fi

echo ""

# Stop Odoo if running (to avoid conflicts)
echo -e "${BLUE}[3/6] Preparando entorno...${NC}"
echo -e "${YELLOW}Deteniendo Odoo temporalmente...${NC}"
docker-compose stop odoo > /dev/null 2>&1 || true
echo -e "${GREEN}✅ Odoo detenido${NC}"

echo ""

# Run installation
echo -e "${BLUE}[4/6] Instalando/Actualizando módulos...${NC}"
echo -e "${CYAN}Comando: odoo -d ${DB_NAME} ${ODOO_CMD} --stop-after-init${NC}"
echo -e "${CYAN}Monitoreando logs en tiempo real...${NC}"
echo ""

# Run Odoo installation and capture output
docker-compose run --rm \
    -e DB_NAME=${DB_NAME} \
    odoo \
    odoo -c ${ODOO_CONF} -d ${DB_NAME} ${ODOO_CMD} --stop-after-init \
    2>&1 | tee ${LOG_FILE}

INSTALL_EXIT_CODE=${PIPESTATUS[0]}

echo ""

# Analyze logs
echo -e "${BLUE}[5/6] Analizando logs de instalación...${NC}"

# Count errors and warnings
ERROR_COUNT=$(grep -i "ERROR\|CRITICAL\|Exception\|Traceback" ${LOG_FILE} | grep -v "ERROR odoo.modules.loading: Some modules are not loaded" | wc -l | tr -d ' ')
WARNING_COUNT=$(grep -i "WARNING" ${LOG_FILE} | grep -v "No" | wc -l | tr -d ' ')

echo -e "${CYAN}Errores encontrados: ${ERROR_COUNT}${NC}"
echo -e "${CYAN}Warnings encontrados: ${WARNING_COUNT}${NC}"

# Display errors if any
if [ "$ERROR_COUNT" -gt "0" ]; then
    echo ""
    echo -e "${RED}${BOLD}❌ ERRORES DETECTADOS:${NC}"
    grep -i "ERROR\|CRITICAL\|Exception\|Traceback" ${LOG_FILE} | grep -v "ERROR odoo.modules.loading: Some modules are not loaded" | head -20
    echo ""
fi

# Display warnings if any
if [ "$WARNING_COUNT" -gt "0" ]; then
    echo ""
    echo -e "${YELLOW}${BOLD}⚠️  WARNINGS DETECTADOS:${NC}"
    grep -i "WARNING" ${LOG_FILE} | grep -v "No" | head -20
    echo ""
fi

echo ""

# Restart Odoo
echo -e "${BLUE}[6/6] Reiniciando Odoo...${NC}"
docker-compose start odoo > /dev/null 2>&1
sleep 3
echo -e "${GREEN}✅ Odoo reiniciado${NC}"

echo ""
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  RESUMEN DE INSTALACIÓN${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$INSTALL_EXIT_CODE" -eq "0" ] && [ "$ERROR_COUNT" -eq "0" ]; then
    echo -e "${GREEN}${BOLD}✅ INSTALACIÓN EXITOSA${NC}"
    echo -e "${GREEN}   - Exit code: 0${NC}"
    echo -e "${GREEN}   - Errores: 0${NC}"
    echo -e "${GREEN}   - Warnings: ${WARNING_COUNT}${NC}"
    echo ""
    echo -e "${CYAN}Los módulos han sido instalados correctamente en la BD TEST.${NC}"
    EXIT_STATUS=0
else
    echo -e "${RED}${BOLD}❌ INSTALACIÓN FALLIDA${NC}"
    echo -e "${RED}   - Exit code: ${INSTALL_EXIT_CODE}${NC}"
    echo -e "${RED}   - Errores: ${ERROR_COUNT}${NC}"
    echo -e "${RED}   - Warnings: ${WARNING_COUNT}${NC}"
    echo ""
    echo -e "${CYAN}Revise el log: ${LOG_FILE}${NC}"
    EXIT_STATUS=1
fi

echo ""
echo -e "${CYAN}Log completo guardado en: ${BOLD}${LOG_FILE}${NC}"
echo ""

exit $EXIT_STATUS
