#!/bin/bash
# quick_test_multi_cli.sh - Test rápido del orquestador con diferentes CLIs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 Multi-CLI Orchestrator Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Componente pequeño para testing rápido
COMPONENT="${1:-ai-service}"
TARGET_SCORE="${2:-85}"
MAX_ITER="${3:-2}"
MAX_BUDGET="${4:-1.0}"

echo ""
echo "📦 Componente: $COMPONENT"
echo "🎯 Target Score: $TARGET_SCORE"
echo "🔄 Max Iterations: $MAX_ITER"
echo "💰 Max Budget: \$${MAX_BUDGET} USD"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 1: Copilot (predeterminado)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Test 1: GitHub Copilot CLI (predeterminado)${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Verificar que copilot está instalado
if command -v copilot &> /dev/null; then
    echo -e "${GREEN}✅ Copilot CLI detectado${NC}"
    echo ""
    
    # Ejecutar con Copilot
    echo "Ejecutando: AI_CLI=copilot ./scripts/orchestrate_cmo.sh $COMPONENT $TARGET_SCORE $MAX_ITER $MAX_BUDGET"
    echo ""
    
    AI_CLI=copilot ./scripts/orchestrate_cmo.sh "$COMPONENT" "$TARGET_SCORE" "$MAX_ITER" "$MAX_BUDGET"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✅ Test Copilot: SUCCESS${NC}"
    else
        echo ""
        echo -e "${RED}❌ Test Copilot: FAILED${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Copilot CLI no detectado - SKIP${NC}"
    echo "Instalación: npm install -g @githubnext/github-copilot-cli"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 2: Codex (opcional)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Test 2: OpenAI Codex CLI (opcional)${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if command -v codex &> /dev/null; then
    echo -e "${GREEN}✅ Codex CLI detectado${NC}"
    echo ""
    
    # Confirmar con usuario
    read -p "¿Ejecutar test con Codex? (costo API) [y/N]: " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Ejecutando: AI_CLI=codex ./scripts/orchestrate_cmo.sh $COMPONENT $TARGET_SCORE $MAX_ITER $MAX_BUDGET"
        echo ""
        
        AI_CLI=codex ./scripts/orchestrate_cmo.sh "$COMPONENT" "$TARGET_SCORE" "$MAX_ITER" "$MAX_BUDGET"
        
        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${GREEN}✅ Test Codex: SUCCESS${NC}"
        else
            echo ""
            echo -e "${RED}❌ Test Codex: FAILED${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Test Codex SKIPPED (usuario)${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Codex CLI no detectado - SKIP${NC}"
    echo "Instalación: pip install codex-cli"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 3: Gemini (opcional)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Test 3: Google Gemini CLI (opcional)${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if command -v gemini &> /dev/null; then
    echo -e "${GREEN}✅ Gemini CLI detectado${NC}"
    echo ""
    
    # Confirmar con usuario
    read -p "¿Ejecutar test con Gemini? (costo API) [y/N]: " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Ejecutando: AI_CLI=gemini ./scripts/orchestrate_cmo.sh $COMPONENT $TARGET_SCORE $MAX_ITER $MAX_BUDGET"
        echo ""
        
        AI_CLI=gemini ./scripts/orchestrate_cmo.sh "$COMPONENT" "$TARGET_SCORE" "$MAX_ITER" "$MAX_BUDGET"
        
        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${GREEN}✅ Test Gemini: SUCCESS${NC}"
        else
            echo ""
            echo -e "${RED}❌ Test Gemini: FAILED${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Test Gemini SKIPPED (usuario)${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Gemini CLI no detectado - SKIP${NC}"
    echo "Instalación: pip install gemini-cli"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 4: CLI Inválido (debe fallar gracefully)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Test 4: CLI Inválido (negative test)${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo "Ejecutando: AI_CLI=invalid_cli ./scripts/orchestrate_cmo.sh $COMPONENT $TARGET_SCORE 1 $MAX_BUDGET"
echo ""
echo "Expected: ERROR: Unknown AI_CLI: invalid_cli"
echo ""

AI_CLI=invalid_cli ./scripts/orchestrate_cmo.sh "$COMPONENT" "$TARGET_SCORE" 1 "$MAX_BUDGET" 2>&1 | grep -i "unknown ai_cli" || true

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Test Invalid CLI: SUCCESS (falló correctamente)${NC}"
else
    echo ""
    echo -e "${RED}❌ Test Invalid CLI: FAILED (debería haber fallado)${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Resumen Final
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Resumen Final"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "📁 Logs disponibles:"
ls -lht logs/orchestrate_*.log 2>/dev/null | head -5 || echo "No hay logs recientes"

echo ""
echo "🔍 Ver CLI usado en última ejecución:"
echo "  grep 'Requesting strategic decision from' logs/orchestrate_*.log | tail -1"

echo ""
echo "📖 Documentación completa:"
echo "  cat scripts/AI_CLI_USAGE.md"

echo ""
echo -e "${GREEN}✅ Testing completado${NC}"
echo ""
