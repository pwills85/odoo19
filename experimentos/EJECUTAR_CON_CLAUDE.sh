#!/bin/bash
# Script helper para ejecutar auditoría P4-Deep DTE con Claude Code
# Compatible con macOS (sin timeout)
# Fecha: 2025-11-11

set -e

PROJECT_DIR="/Users/pedro/Documents/odoo19"
PROMPT_FILE="docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md"
OUTPUT_FILE="experimentos/auditoria_dte_$(date +%Y%m%d_%H%M%S).md"

cd "$PROJECT_DIR"

echo "🚀 Ejecutando auditoría P4-Deep DTE con Claude Code..."
echo "📄 Prompt: $PROMPT_FILE ($(wc -l < $PROMPT_FILE) líneas)"
echo "📊 Output: $OUTPUT_FILE"
echo ""
echo "⏳ Esto puede tomar 5-10 minutos..."
echo ""

# Ejecutar Claude Code CLI con el prompt (usar modelo por defecto o especificar correctamente)
# Opciones válidas: claude-sonnet-4-20250514, claude-3-5-sonnet-20241022
if claude < "$PROMPT_FILE" > "$OUTPUT_FILE" 2>&1; then
    echo ""
    echo "✅ Auditoría completada exitosamente"
    echo ""
    
    # Mostrar estadísticas básicas
    OUTPUT_SIZE=$(wc -c < "$OUTPUT_FILE")
    OUTPUT_LINES=$(wc -l < "$OUTPUT_FILE")
    OUTPUT_WORDS=$(wc -w < "$OUTPUT_FILE")
    
    echo "📊 Estadísticas del output:"
    echo "   Tamaño: $OUTPUT_SIZE bytes"
    echo "   Líneas: $OUTPUT_LINES"
    echo "   Palabras: $OUTPUT_WORDS"
    echo ""
    
    if [ $OUTPUT_WORDS -ge 1000 ]; then
        echo "✅ Output parece completo (≥1000 palabras)"
        echo ""
        echo "📋 Próximos pasos:"
        echo "1. Analizar métricas: ./experimentos/ANALIZAR_METRICAS_DTE.sh $OUTPUT_FILE"
        echo "2. Revisar output: code $OUTPUT_FILE"
        echo "3. Validar contra checklist"
    else
        echo "⚠️  Output parece incompleto (<1000 palabras)"
        echo "   Revisar contenido: cat $OUTPUT_FILE"
    fi
else
    echo ""
    echo "❌ ERROR: Auditoría falló"
    echo "   Revisar log de error en: $OUTPUT_FILE"
    exit 1
fi
