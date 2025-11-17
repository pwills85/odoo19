#!/bin/bash

###############################################################################
# Script de Limpieza y Reorganización del Proyecto Odoo19
# Fecha: 24 de octubre de 2025
# Descripción: Elimina archivos accidentales, cachés y reorganiza documentación
###############################################################################

set -e  # Salir en caso de error

PROJECT_ROOT="/Users/pedro/Documents/odoo19"
BACKUP_DATE=$(date +%Y-%m-%d_%H%M%S)

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SCRIPT DE LIMPIEZA - PROYECTO ODOO19${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""

###############################################################################
# FASE 1: ELIMINAR ARCHIVOS ACCIDENTALES
###############################################################################

echo -e "${YELLOW}▶ FASE 1: Eliminando archivos accidentales...${NC}"

ACCIDENTAL_FILES=(
    "--rm"
    "--stop-after-init"
    "-d"
    "-name"
    "-u"
    "-o"
    "0"
    "Total"
    "archivos"
    "docker-compose"
    "echo"
    "find"
    "l10n_cl_dte"
    "odoo"
    "odoo19"
    "run"
    "*test.py"
    "test:"
    "test*.py"
)

for file in "${ACCIDENTAL_FILES[@]}"; do
    if [ -e "$PROJECT_ROOT/$file" ]; then
        rm -f "$PROJECT_ROOT/$file"
        echo -e "${GREEN}  ✓ Eliminado: $file${NC}"
    fi
done

echo ""

###############################################################################
# FASE 2: LIMPIAR CACHÉS DE PYTHON
###############################################################################

echo -e "${YELLOW}▶ FASE 2: Eliminando cachés de Python...${NC}"

CACHE_COUNT=$(find "$PROJECT_ROOT/ai-service" -type d -name __pycache__ 2>/dev/null | wc -l)

if [ "$CACHE_COUNT" -gt 0 ]; then
    find "$PROJECT_ROOT/ai-service" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    echo -e "${GREEN}  ✓ Eliminadas $CACHE_COUNT carpetas de caché${NC}"
else
    echo -e "${GREEN}  ✓ No hay cachés que eliminar${NC}"
fi

echo ""

###############################################################################
# FASE 3: CREAR ESTRUCTURA DE BACKUP
###############################################################################

echo -e "${YELLOW}▶ FASE 3: Creando estructura de backup...${NC}"

DOCS_ARCHIVE="$PROJECT_ROOT/docs/ARCHIVE"
LOGS_ARCHIVE="$PROJECT_ROOT/backups/logs_archive_${BACKUP_DATE}"

mkdir -p "$DOCS_ARCHIVE"
echo -e "${GREEN}  ✓ Directorio creado: docs/ARCHIVE${NC}"

mkdir -p "$LOGS_ARCHIVE"
echo -e "${GREEN}  ✓ Directorio creado: backups/logs_archive_${BACKUP_DATE}${NC}"

echo ""

###############################################################################
# FASE 4: MOVER LOGS ANTIGUOS
###############################################################################

echo -e "${YELLOW}▶ FASE 4: Archivando logs antiguos...${NC}"

if [ -d "$PROJECT_ROOT/logs" ]; then
    LOGS_COUNT=$(find "$PROJECT_ROOT/logs" -maxdepth 1 -type f -name "*.log" 2>/dev/null | wc -l)
    
    if [ "$LOGS_COUNT" -gt 0 ]; then
        find "$PROJECT_ROOT/logs" -maxdepth 1 -type f -name "*.log" -exec mv {} "$LOGS_ARCHIVE/" \;
        echo -e "${GREEN}  ✓ Archivados $LOGS_COUNT archivos de log${NC}"
    else
        echo -e "${GREEN}  ✓ No hay logs que archivar${NC}"
    fi
fi

echo ""

###############################################################################
# FASE 5: MOVER DOCUMENTACIÓN A ARCHIVE (OPCIONAL - Requiere confirmación)
###############################################################################

echo -e "${YELLOW}▶ FASE 5: Documentación - Acción manual recomendada${NC}"
echo -e "${YELLOW}  Los siguientes archivos pueden ser movidos a docs/ARCHIVE/:${NC}"
echo ""

DOC_FILES=(
    "AI_AGENT_INSTRUCTIONS.md"
    "AUDITORIA_ODOO19_CAPACIDADES_NATIVAS.md"
    "AUDITORIA_README.txt"
    "CHANGELOG.md"
    "CLAUDE.md"
    "CONTRIBUTING.md"
    "CRITICAL_AUDIT_MICROSERVICE_FEATURES.md"
    "DTE_MICROSERVICE_TO_NATIVE_MIGRATION_COMPLETE.md"
    "EERGY_SERVICES_DETAILED_REPORT.md"
    "EERGY_SERVICES_EXECUTIVE_SUMMARY.txt"
    "EVALUACION_CONTEXTO_PROYECTO.md"
    "INDICE_AUDITORIA.md"
    "INTEGRATION_FIXES_COMPLETE.md"
    "METRICAS_STACK_DETALLADAS.txt"
    "MIGRATION_VALIDATION_SUMMARY.md"
    "PLAN_MIGRACION_COMPLETA_NATIVA.md"
    "PLAN_REORGANIZACION_SEGURA.md"
    "QUICK_START.md"
    "QUICK_START_NEXT_SESSION.md"
    "REORGANIZACION_COMPLETADA.md"
    "REORGANIZACION_FINAL.md"
    "RESUMEN_EJECUTIVO_AUDITORIA.md"
    "RESUMEN_PLAN_REORGANIZACION.md"
    "SPRINT1_COMPLETADO_100.md"
    "SPRINT1_DISASTER_RECOVERY_PROGRESS.md"
    "TEAM_ONBOARDING.md"
    "TESTING_MIGRATION_CHECKLIST.md"
)

for file in "${DOC_FILES[@]}"; do
    if [ -e "$PROJECT_ROOT/$file" ]; then
        echo "  mv $file docs/ARCHIVE/"
    fi
done

echo ""
echo -e "${YELLOW}  Para ejecutar estas migraciones, descomenta las líneas en este script${NC}"
echo ""

###############################################################################
# ASEGURAR .gitignore
###############################################################################

echo -e "${YELLOW}▶ FASE 6: Actualizando .gitignore...${NC}"

if ! grep -q "__pycache__" "$PROJECT_ROOT/.gitignore" 2>/dev/null; then
    echo "__pycache__/" >> "$PROJECT_ROOT/.gitignore"
    echo -e "${GREEN}  ✓ Agregado __pycache__/ a .gitignore${NC}"
else
    echo -e "${GREEN}  ✓ __pycache__/ ya está en .gitignore${NC}"
fi

echo ""

###############################################################################
# RESUMEN
###############################################################################

echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ LIMPIEZA COMPLETADA${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Resumen de cambios:"
echo "  ✓ Archivos accidentales: Eliminados"
echo "  ✓ Cachés de Python: Eliminados"
echo "  ✓ Estructura de backup: Creada"
echo "  ✓ Logs antiguos: Archivados en $LOGS_ARCHIVE"
echo "  ✓ .gitignore: Actualizado"
echo ""
echo -e "${YELLOW}Pasos manuales recomendados:${NC}"
echo "  1. Revisar docs/ARCHIVE/ después de crear"
echo "  2. Ejecutar: git add -A && git commit -m 'chore: cleanup project'"
echo "  3. Opcionalmente, mover documentación histórica a docs/ARCHIVE/"
echo ""
