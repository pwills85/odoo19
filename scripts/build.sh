#!/bin/bash

# Build Script for Odoo 19 CE - Chile Localization
# Construye imagen personalizada desde archivos fuente GitHub
# Repositorio oficial: https://github.com/odoo/docker
# 
# Este script:
# 1. Verifica que los archivos de odoo-docker-base/19.0/ existan
# 2. Copia los archivos oficiales al contexto de build
# 3. Construye imagen personalizada para Chile
# 4. La imagen incluye scripts oficiales + personalización chilena

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ============================================================================
# VALIDACIONES INICIALES
# ============================================================================

echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC}  🏗️  Odoo 19 CE - Build Image from GitHub Sources (Chile Localization)       ${YELLOW}║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Proyecto: $PROJECT_DIR"
echo ""

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker no está instalado${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker disponible"

# Verificar que exista docker/Dockerfile
if [ ! -f "$PROJECT_DIR/docker/Dockerfile" ]; then
    echo -e "${RED}✗${NC} docker/Dockerfile no encontrado"
    exit 1
fi
echo -e "${GREEN}✓${NC} docker/Dockerfile encontrado"

# ============================================================================
# VERIFICAR ARCHIVOS DE GITHUB
# ============================================================================

ODOO_BASE_DIR="$PROJECT_DIR/odoo-docker-base/19.0"

echo ""
echo -e "${BLUE}─ Validando archivos descargados de GitHub${NC}"

# Archivos requeridos
REQUIRED_FILES=(
    "Dockerfile"
    "entrypoint.sh"
    "wait-for-psql.py"
    "odoo.conf"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$ODOO_BASE_DIR/$file" ]; then
        echo -e "${RED}✗${NC} Archivo faltante: $ODOO_BASE_DIR/$file"
        echo ""
        echo -e "${YELLOW}⚠ Solución: Ejecutar primero:${NC}"
        echo -e "${YELLOW}   git clone https://github.com/odoo/docker.git odoo-docker-base${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} $file"
done

# ============================================================================
# CARGAR VARIABLES DE ENTORNO
# ============================================================================

echo ""
echo -e "${BLUE}─ Cargando configuración${NC}"

if [ -f "$PROJECT_DIR/config/docker.env" ]; then
    echo -e "${GREEN}✓${NC} Cargando config/docker.env"
    set -a
    source "$PROJECT_DIR/config/docker.env"
    set +a
else
    echo -e "${YELLOW}⚠${NC} config/docker.env no encontrado, usando defaults"
fi

# Variables por defecto
ODOO_VERSION=${ODOO_VERSION:-19.0}
IMAGE_NAME=${IMAGE_NAME:-eergygroup/odoo19}
IMAGE_TAG=${IMAGE_TAG:-v1}
REGISTRY=${REGISTRY:-}

if [ -n "$REGISTRY" ]; then
    FULL_IMAGE_NAME="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
else
    FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"
fi

echo "  Versión: $ODOO_VERSION"
echo "  Imagen: $FULL_IMAGE_NAME"

# ============================================================================
# CONSTRUCCIÓN DE IMAGEN
# ============================================================================

echo ""
echo -e "${BLUE}─ Construyendo imagen Docker${NC}"
echo "  Context: $PROJECT_DIR"
echo "  Dockerfile: docker/Dockerfile"
echo ""

# Docker build con argumentos de build
docker build \
    --build-arg TARGETARCH="$(docker version --format '{{ .Server.Arch }}')" \
    --build-arg ODOO_RELEASE="20251021" \
    --build-arg ODOO_SHA="eeba5130e7d34caa1c8459df926f1a207c314857" \
    -t "$FULL_IMAGE_NAME" \
    -f docker/Dockerfile \
    . 2>&1

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${RED}✗ Error durante la construcción${NC}"
    exit 1
fi

# ============================================================================
# VERIFICACIÓN Y RESUMEN
# ============================================================================

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC}  ${GREEN}✓ Imagen construida exitosamente${NC}                                         ${YELLOW}║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Mostrar información de la imagen
echo "Detalles de la imagen:"
docker image ls | grep -E "REPOSITORY|$IMAGE_NAME" | head -2

echo ""
echo -e "${BLUE}📦 Imagen Lista:${NC}"
echo "   $FULL_IMAGE_NAME"
echo ""

# ============================================================================
# PRÓXIMOS PASOS
# ============================================================================

echo -e "${YELLOW}🚀 Próximos Pasos:${NC}"
echo ""
echo "  1. Iniciar servicios:"
echo -e "     ${YELLOW}docker-compose up -d${NC}"
echo ""
echo "  2. Esperar 30-40 segundos a que se inicie completamente"
echo ""
echo "  3. Verificar logs:"
echo -e "     ${YELLOW}docker-compose logs -f odoo${NC}"
echo ""
echo "  4. Acceder a Odoo:"
echo "     URL: http://localhost:8069"
echo "     BD: odoo"
echo "     Usuario: admin"
echo "     Contraseña: admin"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  ✓ Build completado. Listo para: ./scripts/manage.sh start                 ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════════╝${NC}"
