#!/bin/bash
# Script para ejecutar auditoría P4-Deep DTE con Copilot CLI
# Fecha: 2025-11-11
# Fase 4: Validación Empírica

set -e  # Exit on error

PROJECT_DIR="/Users/pedro/Documents/odoo19"
PROMPT_FILE="docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md"
OUTPUT_FILE="experimentos/auditoria_dte_$(date +%Y%m%d_%H%M%S).md"

echo "🚀 Iniciando auditoría P4-Deep DTE..."
echo "📂 Proyecto: $PROJECT_DIR"
echo "📄 Prompt: $PROMPT_FILE"
echo "📊 Output: $OUTPUT_FILE"
echo ""

cd "$PROJECT_DIR"

# Verificar que el prompt existe
if [ ! -f "$PROMPT_FILE" ]; then
    echo "❌ ERROR: Prompt no encontrado en $PROMPT_FILE"
    exit 1
fi

echo "✅ Prompt encontrado ($(wc -l < $PROMPT_FILE) líneas)"
echo ""

# Opción 1: Copilot CLI con archivo (si soporta --file)
echo "=== OPCIÓN 1: Copilot CLI con --file ==="
echo "Comando:"
echo "copilot chat --model claude-sonnet-4.5 \\"
echo "  --file $PROMPT_FILE \\"
echo "  --output $OUTPUT_FILE \\"
echo "  \"Ejecuta este prompt P4-Deep completo para auditar el módulo l10n_cl_dte. Sigue TODOS los pasos (1-7) incluyendo análisis inicial y verificaciones. Genera output en formato markdown con estructura especificada.\""
echo ""

# Opción 2: Copilot CLI con entrada stdin (más compatible)
echo "=== OPCIÓN 2: Copilot CLI con stdin (MÁS COMPATIBLE) ==="
echo "Comando:"
echo "cat $PROMPT_FILE | copilot chat --model claude-sonnet-4.5 > $OUTPUT_FILE"
echo ""

# Opción 3: Manual - Copiar a clipboard y pegar
echo "=== OPCIÓN 3: Manual con clipboard ==="
echo "1. Copiar prompt a clipboard:"
echo "   cat $PROMPT_FILE | pbcopy"
echo ""
echo "2. Iniciar sesión Copilot:"
echo "   copilot chat --model claude-sonnet-4.5"
echo ""
echo "3. Pegar prompt (Cmd+V) y esperar respuesta"
echo ""
echo "4. Copiar output completo a archivo:"
echo "   [Seleccionar todo] → Cmd+C → paste en $OUTPUT_FILE"
echo ""

echo "⚠️  NOTA: Si ninguna opción funciona, usar Claude Code CLI directamente:"
echo "   claude --model sonnet-4.5 < $PROMPT_FILE > $OUTPUT_FILE"
echo ""

echo "📋 Próximos pasos después de generar output:"
echo "1. Analizar métricas: ./experimentos/ANALIZAR_METRICAS_DTE.sh"
echo "2. Validar manualmente contra checklist"
echo "3. Ajustar template si necesario"
echo ""

# NO ejecutar automáticamente - requiere interacción con Copilot
# Usuario debe ejecutar manualmente una de las opciones
