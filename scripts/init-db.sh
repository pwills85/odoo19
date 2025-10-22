#!/bin/bash

# Database Initialization Script for Odoo 19 CE
# Uso: ./scripts/init-db.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}=== Odoo 19 CE Database Initialization ===${NC}"
echo "Project Directory: $PROJECT_DIR"
echo ""

# Load environment variables
if [ -f "$PROJECT_DIR/config/docker.env" ]; then
    echo -e "${GREEN}✓${NC} Loading environment variables"
    set -a
    source "$PROJECT_DIR/config/docker.env"
    set +a
else
    echo -e "${RED}✗${NC} config/docker.env not found"
    exit 1
fi

# Check if containers are running
if ! docker ps | grep -q "odoo19_app"; then
    echo -e "${RED}✗${NC} Odoo container is not running"
    echo "Please start containers with: docker-compose up -d"
    exit 1
fi

echo -e "${GREEN}✓${NC} Odoo container is running"
echo ""

# Wait for database to be ready
echo -e "${BLUE}Waiting for database to be ready...${NC}"
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec odoo19_db pg_isready -U "$ODOO_DB_USER" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Database is ready"
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}✗${NC} Database did not become ready in time"
    exit 1
fi

echo ""
echo -e "${YELLOW}Installing Chile localization modules...${NC}"
echo ""

# Install Chile localization modules
MODULES_TO_INSTALL="l10n_cl,l10n_cl_edi,l10n_cl_reports"

docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d "$ODOO_DB_NAME" \
    --addons-path=/opt/odoo/addons,/opt/odoo/server/addons \
    --init="$MODULES_TO_INSTALL" \
    --without-demo=all \
    --stop-after-init

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Modules installed successfully!${NC}"
    echo ""
    echo "Installed modules:"
    echo "  • l10n_cl - Contabilidad chilena"
    echo "  • l10n_cl_edi - Facturación electrónica"
    echo "  • l10n_cl_reports - Reportes tributarios"
    echo ""
else
    echo -e "${RED}✗ Module installation failed${NC}"
    exit 1
fi

echo -e "${YELLOW}Database initialization complete!${NC}"
echo ""
echo "Access Odoo at:"
echo -e "${BLUE}http://localhost:8069${NC}"
echo ""
echo "Credentials:"
echo "  Username: admin"
echo "  Password: admin"
