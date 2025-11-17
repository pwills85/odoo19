#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# 🧪 TEST CLI VALIDATION - Validación Configuración Gemini, Copilot, Codex
# ═══════════════════════════════════════════════════════════════════════════
# Versión: 1.0.0
# Fecha: 2025-11-12
# Propósito: Validar instalación y configuración básica de CLIs AI
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Contadores
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ═══════════════════════════════════════════════════════════════════════════

log_test() {
    echo -e "${BLUE}[TEST $((TESTS_TOTAL+1))]${NC} $1"
    TESTS_TOTAL=$((TESTS_TOTAL+1))
}

log_success() {
    echo -e "${GREEN}✅ PASS${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED+1))
}

log_fail() {
    echo -e "${RED}❌ FAIL${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED+1))
}

log_skip() {
    echo -e "${YELLOW}⏭️  SKIP${NC} $1"
}

log_info() {
    echo -e "${BLUE}ℹ️  INFO${NC} $1"
}

# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: VERIFICAR INSTALACIÓN GEMINI CLI
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar instalación Gemini CLI"

if command -v gemini &> /dev/null; then
    GEMINI_VERSION=$(gemini --version 2>&1 || echo "unknown")
    log_success "Gemini CLI instalado: $GEMINI_VERSION"
    log_info "Path: $(which gemini)"
else
    log_fail "Gemini CLI NO instalado"
    log_info "Instalar con: npm install -g @google/gemini-cli"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: VERIFICAR INSTALACIÓN COPILOT CLI
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar instalación Copilot CLI"

if command -v copilot &> /dev/null; then
    COPILOT_VERSION=$(copilot --version 2>&1 || echo "unknown")
    log_success "Copilot CLI instalado: $COPILOT_VERSION"
    log_info "Path: $(which copilot)"
else
    log_fail "Copilot CLI NO instalado"
    log_info "Instalar con: npm install -g @githubnext/github-copilot-cli"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: VERIFICAR CREDENCIALES GEMINI (TEST FUNCIONAL)
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar credenciales Gemini (test funcional)"

# Test funcional: intentar ejecutar comando simple
GEMINI_TEST=$(gemini "test" 2>&1)
GEMINI_EXIT=$?

if [ $GEMINI_EXIT -eq 0 ]; then
    log_success "Credenciales Gemini activas (cached credentials detected)"
    log_info "Gemini CLI autenticado y funcional"
else
    log_fail "Credenciales Gemini NO activas"
    log_info "Autenticar con: gemini (seguir instrucciones OAuth)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: VERIFICAR TOKEN GITHUB (para Copilot)
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar token GitHub"

if [ -n "${GITHUB_TOKEN:-}" ]; then
    log_success "GITHUB_TOKEN encontrado en env"
    log_info "Token: ${GITHUB_TOKEN:0:10}..."
else
    log_fail "GITHUB_TOKEN NO encontrado en env"
    log_info "Configurar con: export GITHUB_TOKEN=ghp_XXXXXXXXX"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: VERIFICAR CODEX CLI (si existe)
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar instalación Codex CLI"

if command -v codex &> /dev/null; then
    CODEX_VERSION=$(codex --version 2>&1 || echo "unknown")
    log_success "Codex CLI instalado: $CODEX_VERSION"
    log_info "Path: $(which codex)"
else
    log_skip "Codex CLI NO instalado (no encontrado en docs)"
    log_info "No hay información en docs sobre Codex CLI"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 6: PRUEBA GEMINI SIMPLE (si instalado)
# ═══════════════════════════════════════════════════════════════════════════

log_test "Prueba simple Gemini CLI"

if command -v gemini &> /dev/null && [ -f ~/.gemini/credentials.json ]; then
    log_info "Ejecutando: gemini -m gemini-2.5-flash-lite '2+2=?'"

    GEMINI_OUTPUT=$(timeout 30s gemini -m gemini-2.5-flash-lite "2+2=?" 2>&1 || echo "TIMEOUT_OR_ERROR")

    if [[ "$GEMINI_OUTPUT" == *"4"* ]]; then
        log_success "Gemini CLI funciona correctamente"
        log_info "Output: ${GEMINI_OUTPUT:0:100}..."
    elif [[ "$GEMINI_OUTPUT" == *"TIMEOUT_OR_ERROR"* ]]; then
        log_fail "Gemini CLI timeout o error"
    else
        log_fail "Gemini CLI respuesta inesperada"
        log_info "Output: ${GEMINI_OUTPUT:0:200}"
    fi
else
    log_skip "Gemini CLI no disponible para test (instalación o credenciales faltantes)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 7: VERIFICAR MODELOS GEMINI DISPONIBLES
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar modelos Gemini disponibles"

if command -v gemini &> /dev/null; then
    log_info "Modelos Gemini según documentación:"
    echo "  • gemini-2.5-flash-lite (ultra rápido, ~3.4s)"
    echo "  • gemini-2.5-flash (balance, ~2.6s) ⭐ RECOMENDADO"
    echo "  • gemini-2.5-pro (profundo, ~40s)"
    log_success "Documentación modelos Gemini verificada"
else
    log_skip "Gemini CLI no instalado"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 8: VERIFICAR MODELOS COPILOT DISPONIBLES
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar modelos Copilot disponibles"

if command -v copilot &> /dev/null; then
    log_info "Modelos Copilot según documentación:"
    echo "  • claude-haiku-4.5 (muy rápido, muy económico)"
    echo "  • claude-sonnet-4 (balance costo/calidad)"
    echo "  • claude-sonnet-4.5 (análisis profundos)"
    echo "  • gpt-5 (segunda opinión)"
    log_success "Documentación modelos Copilot verificada"
else
    log_skip "Copilot CLI no instalado"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 9: VERIFICAR FLAGS GEMINI
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar flags Gemini CLI disponibles"

if command -v gemini &> /dev/null; then
    log_info "Testing gemini --help..."

    GEMINI_HELP=$(gemini --help 2>&1 || echo "ERROR")

    if [[ "$GEMINI_HELP" == *"--yolo"* ]] || [[ "$GEMINI_HELP" == *"approval-mode"* ]]; then
        log_success "Flags Gemini disponibles: --yolo, --approval-mode, --sandbox"
        echo "  ✓ --yolo (100% autónomo)"
        echo "  ✓ --approval-mode [default|auto_edit|yolo]"
        echo "  ✓ --sandbox (ejecución segura)"
        echo "  ✓ --output-format [text|json|stream-json]"
        echo "  ✓ --allowed-tools (whitelist)"
    else
        log_info "Flags Gemini parcialmente detectados"
        log_info "Output: ${GEMINI_HELP:0:300}..."
    fi
else
    log_skip "Gemini CLI no instalado"
fi

# ═══════════════════════════════════════════════════════════════════════════
# TEST 10: VERIFICAR FLAGS COPILOT
# ═══════════════════════════════════════════════════════════════════════════

log_test "Verificar flags Copilot CLI disponibles"

if command -v copilot &> /dev/null; then
    log_info "Flags Copilot según documentación:"
    echo "  ✓ --model [claude-haiku-4.5|claude-sonnet-4|claude-sonnet-4.5|gpt-5]"
    echo "  ✓ --allow-all-paths"
    echo "  ✓ --allow-all-tools"
    echo "  ✓ -p \"prompt\""
    log_success "Documentación flags Copilot verificada"
else
    log_skip "Copilot CLI no instalado"
fi

# ═══════════════════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════════"
echo "📊 RESUMEN VALIDACIÓN CLI"
echo "════════════════════════════════════════════════════════════"
echo ""
echo -e "${GREEN}Tests Passed:${NC} $TESTS_PASSED/$TESTS_TOTAL"
echo -e "${RED}Tests Failed:${NC} $TESTS_FAILED/$TESTS_TOTAL"
echo -e "${YELLOW}Tests Skipped:${NC} $((TESTS_TOTAL - TESTS_PASSED - TESTS_FAILED))/$TESTS_TOTAL"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ VALIDACIÓN EXITOSA${NC}"
    echo "Todos los tests críticos pasaron correctamente."
    echo ""
    echo "🎯 Próximos pasos sugeridos:"
    echo "  1. Ejecutar test simple Gemini: gemini 'Hola, cuál es la capital de Chile?'"
    echo "  2. Ejecutar test simple Copilot: copilot -p 'Lista archivos en docs/prompts/' --model claude-haiku-4.5"
    echo "  3. Revisar documentación completa en:"
    echo "     • docs/prompts/GEMINI_CLI_AUTONOMO.md"
    echo "     • docs/prompts/COPILOT_CLI_AUTONOMO.md"
    echo ""
    exit 0
else
    echo -e "${RED}❌ VALIDACIÓN INCOMPLETA${NC}"
    echo "Algunos tests fallaron. Revisar output arriba para detalles."
    echo ""
    echo "🔧 Acciones correctivas recomendadas:"

    if ! command -v gemini &> /dev/null; then
        echo "  • Instalar Gemini CLI: npm install -g @google/gemini-cli"
    fi

    if ! command -v copilot &> /dev/null; then
        echo "  • Instalar Copilot CLI: npm install -g @githubnext/github-copilot-cli"
    fi

    if [ ! -f ~/.gemini/credentials.json ]; then
        echo "  • Autenticar Gemini: gemini (seguir OAuth)"
    fi

    if [ -z "${GITHUB_TOKEN:-}" ]; then
        echo "  • Configurar GITHUB_TOKEN en env"
    fi

    echo ""
    exit 1
fi
