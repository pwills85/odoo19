#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Script de Build - Odoo 19 CE Chile Localization Image
# ══════════════════════════════════════════════════════════════════════════════
# Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
# Fecha: 2025-11-07
# Descripción: Build de imagen Docker Odoo 19 CE con localización chilena
# Versión: 1.0.4 (ML/Data Science support)
# ══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════════
IMAGE_NAME="eergygroup/odoo19"
IMAGE_TAG="chile-1.0.4"
DOCKER_CONTEXT="./odoo-docker"
TARGET_STAGE="chile"  # opciones: chile, development

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════
# FUNCIONES
# ═══════════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ═══════════════════════════════════════════════════════════════════════
# VALIDACIONES PREVIAS
# ═══════════════════════════════════════════════════════════════════════

log_info "Validando entorno..."

# Verificar que estamos en el directorio correcto
if [ ! -d "odoo-docker" ]; then
    log_error "Directorio odoo-docker no encontrado. Ejecutar desde raíz del proyecto."
    exit 1
fi

# Verificar que Docker está corriendo
if ! docker info > /dev/null 2>&1; then
    log_error "Docker no está corriendo. Iniciar Docker Desktop."
    exit 1
fi

log_success "Validaciones completadas"

# ═══════════════════════════════════════════════════════════════════════
# CLEANUP PREVIO (OPCIONAL)
# ═══════════════════════════════════════════════════════════════════════

read -p "¿Hacer cleanup de imágenes antiguas? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Limpiando imágenes antiguas..."

    # Eliminar imagen anterior si existe
    if docker images | grep -q "${IMAGE_NAME}.*chile-1.0.3"; then
        log_info "Eliminando imagen anterior: ${IMAGE_NAME}:chile-1.0.3"
        docker rmi "${IMAGE_NAME}:chile-1.0.3" || true
    fi

    # Eliminar imágenes dangling
    log_info "Eliminando imágenes dangling..."
    docker image prune -f

    log_success "Cleanup completado"
fi

# ═══════════════════════════════════════════════════════════════════════
# BUILD DE IMAGEN
# ═══════════════════════════════════════════════════════════════════════

log_info "═══════════════════════════════════════════════════════════"
log_info "Iniciando build de imagen Docker"
log_info "═══════════════════════════════════════════════════════════"
log_info "Imagen: ${IMAGE_NAME}:${IMAGE_TAG}"
log_info "Target: ${TARGET_STAGE}"
log_info "Context: ${DOCKER_CONTEXT}"
log_info "═══════════════════════════════════════════════════════════"
echo

# Build de la imagen con caché
log_info "Building image..."
docker build \
    --target "${TARGET_STAGE}" \
    --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
    --tag "${IMAGE_NAME}:latest" \
    --build-arg ODOO_VERSION="19.0" \
    --build-arg ODOO_RELEASE="20251021" \
    --file "${DOCKER_CONTEXT}/Dockerfile" \
    "${DOCKER_CONTEXT}"

BUILD_EXIT_CODE=$?

if [ $BUILD_EXIT_CODE -ne 0 ]; then
    log_error "Build falló con código de salida: $BUILD_EXIT_CODE"
    exit $BUILD_EXIT_CODE
fi

log_success "Build completado exitosamente"

# ═══════════════════════════════════════════════════════════════════════
# VERIFICACIÓN POST-BUILD
# ═══════════════════════════════════════════════════════════════════════

log_info "Verificando imagen..."

# Verificar que la imagen existe
if ! docker images | grep -q "${IMAGE_NAME}.*${IMAGE_TAG}"; then
    log_error "Imagen no encontrada después del build"
    exit 1
fi

# Mostrar info de la imagen
log_info "Información de la imagen:"
docker images "${IMAGE_NAME}:${IMAGE_TAG}"

# Verificar librerías Python (opcional)
log_info ""
log_info "Verificando librerías Python críticas..."
docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" \
    python3 -c "
import sys
libs = ['qrcode', 'reportlab', 'PIL', 'lxml', 'xmlsec', 'zeep', 'numpy', 'sklearn', 'joblib', 'jwt']
missing = []
for lib in libs:
    try:
        __import__(lib)
        print(f'✅ {lib}')
    except ImportError:
        print(f'❌ {lib}')
        missing.append(lib)

if missing:
    print(f'\n❌ Librerías faltantes: {missing}')
    sys.exit(1)
else:
    print('\n✅ Todas las librerías críticas disponibles')
"

VERIFY_EXIT_CODE=$?

if [ $VERIFY_EXIT_CODE -ne 0 ]; then
    log_error "Verificación de librerías falló"
    exit 1
fi

log_success "Verificación completada"

# ═══════════════════════════════════════════════════════════════════════
# REPORTLAB PDF417 TEST
# ═══════════════════════════════════════════════════════════════════════

log_info ""
log_info "Verificando soporte PDF417 (reportlab)..."
docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" \
    python3 -c "
from reportlab.graphics.barcode import createBarcodeDrawing
from reportlab.graphics import renderPM
from io import BytesIO

try:
    # Test PDF417 creation
    barcode = createBarcodeDrawing('PDF417', value='TEST', width=90, height=30)
    buffer = BytesIO()
    renderPM.drawToFile(barcode, buffer, fmt='PNG')
    print('✅ PDF417 barcode support confirmed')
    print('✅ reportlab version >= 4.0.0 working')
except Exception as e:
    print(f'❌ PDF417 test failed: {e}')
    import sys
    sys.exit(1)
"

PDF417_EXIT_CODE=$?

if [ $PDF417_EXIT_CODE -ne 0 ]; then
    log_error "Test de PDF417 falló"
    exit 1
fi

log_success "PDF417 support verificado"

# ═══════════════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ═══════════════════════════════════════════════════════════════════════

log_info ""
log_info "═══════════════════════════════════════════════════════════"
log_success "✅ BUILD COMPLETADO EXITOSAMENTE"
log_info "═══════════════════════════════════════════════════════════"
log_info "Imagen: ${IMAGE_NAME}:${IMAGE_TAG}"
log_info "También taggeada como: ${IMAGE_NAME}:latest"
log_info ""
log_info "Librerías actualizadas:"
log_info "  • reportlab 4.0.4+ (PDF417 support)"
log_info "  • qrcode 7.4.2+"
log_info "  • pillow 10.0.0+"
log_info "  • numpy 1.24.4 (numerical computing)"
log_info "  • scikit-learn 1.3.2 (ML models)"
log_info "  • joblib 1.3.2 (ML serialization)"
log_info "  • PyJWT 2.8.0 (JWT auth)"
log_info ""
log_info "Próximos pasos:"
log_info "  1. Rebuild stack: docker-compose up -d --build odoo"
log_info "  2. Actualizar módulo: docker-compose exec odoo odoo -u l10n_cl_dte"
log_info "  3. Test PDF Reports: Imprimir DTE desde Odoo UI"
log_info "═══════════════════════════════════════════════════════════"
echo

# ═══════════════════════════════════════════════════════════════════════
# OPCIÓN DE PUSH (OPCIONAL)
# ═══════════════════════════════════════════════════════════════════════

read -p "¿Push a Docker Hub? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Pushing imagen a Docker Hub..."

    docker push "${IMAGE_NAME}:${IMAGE_TAG}"
    docker push "${IMAGE_NAME}:latest"

    log_success "Imagen pushed a Docker Hub"
else
    log_info "Imagen disponible solo localmente"
fi

log_success "Script completado"
exit 0
