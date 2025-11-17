#!/bin/bash

# Script de Orquestación Auditoría 360° Profunda - l10n_cl_dte
# Ejecuta auditoría completa combinando P4-Deep + P4-Infrastructure

set -e

MODULE="l10n_cl_dte"
DATE=$(date +%Y%m%d)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="docs/prompts/06_outputs/2025-11/auditorias"
PROMPT_FILE="docs/prompts/05_prompts_produccion/modulos/${MODULE}/AUDIT_DTE_360_PROFUNDA_20251112.md"

echo "🔬 Iniciando Auditoría 360° Profunda - ${MODULE}"
echo "Fecha: $(date)"
echo "=========================================="

# Verificar prompt existe
if [ ! -f "$PROMPT_FILE" ]; then
    echo "❌ Error: Prompt no encontrado: $PROMPT_FILE"
    exit 1
fi

# Verificar Docker funcionando
if ! docker compose ps | grep -q "odoo19_app.*healthy"; then
    echo "❌ Error: Servicio Odoo no está healthy"
    echo "Ejecuta: docker compose ps"
    exit 1
fi

# Crear directorio outputs si no existe
mkdir -p "$OUTPUT_DIR"

echo ""
echo "📋 Paso 1: Preparando entorno..."
echo "-----------------------------------"

# Verificar módulo instalado
echo "Verificando módulo ${MODULE} instalado..."
docker compose exec -T odoo odoo-bin -u ${MODULE} -d odoo19_db --stop-after-init 2>&1 | tail -5

echo ""
echo "✅ Entorno preparado"
echo ""

echo "📋 Paso 2: Ejecutando Auditoría 360° Profunda..."
echo "-----------------------------------"
echo "Prompt: $PROMPT_FILE"
echo "Output: ${OUTPUT_DIR}/AUDIT_DTE_360_PROFUNDA_${TIMESTAMP}.md"
echo ""

# Ejecutar con Copilot CLI (si disponible)
if command -v copilot &> /dev/null; then
    echo "🚀 Usando Copilot CLI..."
    copilot -p "$(cat $PROMPT_FILE)" \
        --allow-all-tools \
        --model claude-sonnet-4.5 \
        > "${OUTPUT_DIR}/AUDIT_DTE_360_PROFUNDA_${TIMESTAMP}.md" 2>&1
    
    EXIT_CODE=$?
elif command -v gemini &> /dev/null; then
    echo "🚀 Usando Gemini CLI..."
    gemini -p "$(cat $PROMPT_FILE)" \
        --mode auto_edit \
        --model flash-pro \
        > "${OUTPUT_DIR}/AUDIT_DTE_360_PROFUNDA_${TIMESTAMP}.md" 2>&1
    
    EXIT_CODE=$?
else
    echo "⚠️  No se encontró Copilot CLI ni Gemini CLI"
    echo "Por favor ejecuta manualmente:"
    echo ""
    echo "copilot -p \"\$(cat $PROMPT_FILE)\" --allow-all-tools > ${OUTPUT_DIR}/AUDIT_DTE_360_PROFUNDA_${TIMESTAMP}.md"
    echo ""
    exit 1
fi

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "✅ Auditoría completada exitosamente"
    echo ""
    echo "📊 Paso 3: Generando métricas y consolidación..."
    echo "-----------------------------------"
    
    # Generar matriz de hallazgos (extraer del reporte)
    echo "Generando matriz de hallazgos..."
    # TODO: Parsear reporte y generar CSV
    
    # Generar métricas JSON (extraer del reporte)
    echo "Generando métricas JSON..."
    # TODO: Parsear reporte y generar JSON
    
    echo ""
    echo "✅ Proceso completado"
    echo ""
    echo "📁 Archivos generados:"
    echo "  - Reporte: ${OUTPUT_DIR}/AUDIT_DTE_360_PROFUNDA_${TIMESTAMP}.md"
    echo "  - Matriz: ${OUTPUT_DIR}/MATRIZ_HALLAZGOS_DTE_${DATE}.csv (pendiente)"
    echo "  - Métricas: ${OUTPUT_DIR}/METRICAS_DTE_${DATE}.json (pendiente)"
    echo ""
else
    echo ""
    echo "❌ Error en ejecución (exit code: $EXIT_CODE)"
    echo "Revisa logs en: ${OUTPUT_DIR}/AUDIT_DTE_360_PROFUNDA_${TIMESTAMP}.md"
    exit $EXIT_CODE
fi

