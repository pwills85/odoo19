#!/bin/bash
# Formatea la salida de Codex para presentación profesional
# Uso: codex-format "prompt" [style]
# Estilos disponibles: dark, light, auto

set -e

PROMPT="$1"
STYLE="${2:-dark}"
TEMP_FILE=$(mktemp)

if [ -z "$PROMPT" ]; then
    echo "Uso: codex-format \"prompt\" [style]"
    echo "Estilos: dark, light, auto"
    exit 1
fi

# Limpiar archivo temporal al salir
trap "rm -f $TEMP_FILE" EXIT

# Ejecutar Codex y guardar último mensaje en archivo temporal
codex exec "$PROMPT" -o "$TEMP_FILE" >/dev/null 2>&1 || {
    # Si falla, intentar sin output file
    codex exec "$PROMPT" > "$TEMP_FILE" 2>/dev/null
}

# Leer el contenido del archivo
if [ -s "$TEMP_FILE" ]; then
    OUTPUT=$(cat "$TEMP_FILE")
else
    # Fallback: ejecutar normalmente
    OUTPUT=$(codex exec "$PROMPT" 2>/dev/null)
fi

# Si glow está instalado, usarlo para renderizado mejorado
if command -v glow &> /dev/null; then
    echo "$OUTPUT" | glow --style "$STYLE" 2>/dev/null || echo "$OUTPUT"
else
    # Si rich-cli está disponible, usarlo
    if command -v rich &> /dev/null; then
        echo "$OUTPUT" | rich --markdown 2>/dev/null || echo "$OUTPUT"
    else
        # Sin herramientas externas, solo mostrar salida con colores
        echo "$OUTPUT"
        echo ""
        echo "💡 Tip: Instala 'glow' para mejor renderizado: brew install glow"
    fi
fi

