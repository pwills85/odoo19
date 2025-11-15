#!/bin/bash
# Test simple CMO v2.1 - Validar multi-CLI sin dependencias complejas
set -euo pipefail

# Colores
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Test Simple CMO v2.1 - Validación Multi-CLI${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Configuración
AI_CLI="${AI_CLI:-copilot}"
TEMP_DIR="/tmp/cmo_test_$$"
mkdir -p "$TEMP_DIR"

echo -e "${GREEN}[1]${NC} AI CLI configurado: ${CYAN}$AI_CLI${NC}"
echo ""

# Generar CONSIGNA simple
CONSIGNA_FILE="$TEMP_DIR/consigna.txt"
cat > "$CONSIGNA_FILE" << 'EOF'
Análisis rápido del componente ai-service:

Métricas actuales:
- Score: 75/100
- Archivos Python: 8
- Tests: 4 pasando
- Coverage: 65%

**INSTRUCCIONES:**

Basado en estas métricas, toma una decisión estratégica:

1. Si score >= 85 → STOP
2. Si score < 85 → CONTINUE con close_gaps_p1

Responde EXACTAMENTE en este formato (3 líneas):

DECISION: [continue|stop]
REASON: [una frase corta explicando por qué]
NEXT_ACTION: [close_gaps_p1|test|stop]

Sé conciso y decisivo.
EOF

echo -e "${GREEN}[2]${NC} CONSIGNA generada ($(wc -l < $CONSIGNA_FILE) líneas)"
echo ""
echo -e "${CYAN}Contenido:${NC}"
head -8 "$CONSIGNA_FILE"
echo "..."
echo ""

# Construir prompt para AI CLI
AI_PROMPT="$(cat $CONSIGNA_FILE)

You are a strategic orchestrator for an automated quality improvement system.

Based on the metrics above, make a strategic decision.

Response format (EXACTLY 3 lines):
DECISION: [continue|stop]
REASON: [one sentence]
NEXT_ACTION: [close_gaps_p1|test|stop]

Be concise and decisive."

CONCLUSION_FILE="$TEMP_DIR/conclusion.txt"

echo -e "${GREEN}[3]${NC} Llamando a ${CYAN}$AI_CLI${NC} CLI..."
echo ""

# Llamar al CLI según configuración
case "$AI_CLI" in
    copilot)
        echo -e "${CYAN}Ejecutando: copilot -p \"<prompt>${NC}"
        echo "$AI_PROMPT" | copilot -p "$(cat -)" > "$CONCLUSION_FILE" 2>&1 || {
            echo -e "${RED}❌ Error llamando a Copilot CLI${NC}"
            echo ""
            echo "Output:"
            cat "$CONCLUSION_FILE"
            exit 1
        }
        ;;
    codex)
        echo -e "${CYAN}Ejecutando: codex -p \"<prompt>${NC}"
        echo "$AI_PROMPT" | codex -p "$(cat -)" > "$CONCLUSION_FILE" 2>&1 || {
            echo -e "${RED}❌ Error llamando a Codex CLI${NC}"
            exit 1
        }
        ;;
    gemini)
        echo -e "${CYAN}Ejecutando: gemini -p \"<prompt>${NC}"
        echo "$AI_PROMPT" | gemini -p "$(cat -)" > "$CONCLUSION_FILE" 2>&1 || {
            echo -e "${RED}❌ Error llamando a Gemini CLI${NC}"
            exit 1
        }
        ;;
    *)
        echo -e "${RED}❌ CLI desconocido: $AI_CLI${NC}"
        echo "Use: copilot, codex, o gemini"
        exit 1
        ;;
esac

echo -e "${GREEN}✅ Respuesta recibida de $AI_CLI${NC}"
echo ""

# Mostrar conclusión
echo -e "${GREEN}[4]${NC} CONCLUSIÓN del ${CYAN}$AI_CLI${NC}:"
echo ""
echo -e "${CYAN}─────────────────────────────────────────────────────${NC}"
cat "$CONCLUSION_FILE"
echo -e "${CYAN}─────────────────────────────────────────────────────${NC}"
echo ""

# Parsear decisión
DECISION=$(grep -i "^DECISION:" "$CONCLUSION_FILE" | head -1 | sed 's/DECISION://i' | tr -d ' ' | tr '[:upper:]' '[:lower:]' || echo "unknown")
REASON=$(grep -i "^REASON:" "$CONCLUSION_FILE" | head -1 | sed 's/REASON://i' | sed 's/^[[:space:]]*//' || echo "No reason provided")
NEXT_ACTION=$(grep -i "^NEXT_ACTION:" "$CONCLUSION_FILE" | head -1 | sed 's/NEXT_ACTION://i' | tr -d ' ' | tr '[:upper:]' '[:lower:]' || echo "unknown")

echo -e "${GREEN}[5]${NC} Decisión parseada:"
echo ""
echo -e "  Decision: ${CYAN}$DECISION${NC}"
echo -e "  Reason: ${CYAN}$REASON${NC}"
echo -e "  Next Action: ${CYAN}$NEXT_ACTION${NC}"
echo ""

# Validar
if [ "$DECISION" = "continue" ] || [ "$DECISION" = "stop" ]; then
    echo -e "${GREEN}✅ TEST EXITOSO${NC}"
    echo ""
    echo "Validaciones:"
    echo "  ✅ CLI $AI_CLI respondió correctamente"
    echo "  ✅ Formato de respuesta válido"
    echo "  ✅ Decisión parseada: $DECISION"
    echo "  ✅ NO se usó Claude CLI"
    echo ""
else
    echo -e "${RED}⚠️  Decisión no válida: $DECISION${NC}"
    echo ""
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
