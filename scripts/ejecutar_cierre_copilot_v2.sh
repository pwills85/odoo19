#!/bin/bash
# Script mejorado para ejecutar Copilot CLI con permisos completos
# Fecha: 2025-11-12
# Versión: 2.0 (con --allow-all-paths)

set -e

echo "🚀 EJECUCIÓN CIERRE TOTAL 8 BRECHAS - Copilot CLI v2.0"
echo "========================================================"
echo ""
echo "📋 Configuración:"
echo "  - Modelo: Claude Sonnet 4.5"
echo "  - Prompt: P3-Advanced (650 palabras)"
echo "  - Agentes: Multi-agent orchestration"
echo "  - Herramientas: Todas permitidas (--allow-all-tools)"
echo "  - Paths: Todos permitidos (--allow-all-paths)"
echo ""
echo "🎯 Objetivo: Cerrar 8 brechas pendientes (20-25h)"
echo ""
echo "📄 Cargando prompt..."
echo ""

# Cargar prompt
PROMPT_FILE="docs/prompts_desarrollo/cierre/PROMPT_P3_CIERRE_TOTAL_8_BRECHAS_20251112.md"

if [ ! -f "$PROMPT_FILE" ]; then
    echo "❌ ERROR: Archivo de prompt no encontrado: $PROMPT_FILE"
    exit 1
fi

echo "✅ Prompt cargado: $PROMPT_FILE"
echo ""
echo "🚀 Iniciando Copilot CLI con permisos completos..."
echo "   (--allow-all-paths: acceso a /mnt/extra-addons, .venv, etc.)"
echo ""
echo "---"
echo ""

# Ejecutar Copilot CLI con prompt + permisos completos
copilot \
  --model claude-sonnet-4.5 \
  --allow-all-tools \
  --allow-all-paths \
  --add-dir /mnt/extra-addons \
  --add-dir .venv \
  -p "$(cat $PROMPT_FILE)"

echo ""
echo "---"
echo ""
echo "✅ Ejecución completada"
echo ""
echo "📊 Revisar resultados en:"
echo "   - experimentos/outputs/CIERRE_TOTAL_8_BRECHAS_*.md"
echo "   - Git log: git log --oneline -10"
echo "   - Git diff: git diff --stat"
echo ""
