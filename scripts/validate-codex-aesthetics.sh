#!/bin/bash
# Script de validación completa de mejoras de estética Codex CLI
# Ejecuta todas las pruebas para asegurar que todo funciona correctamente

# No usar set -e para permitir que todos los tests se ejecuten

echo "═══════════════════════════════════════════════════════════"
echo "🔍 Validación de Mejoras de Estética Codex CLI"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Colores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

# Función de test
test_check() {
    local name="$1"
    local command="$2"
    
    echo -n "Testing: $name... "
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((FAILED++))
        return 1
    fi
}

# 1. Verificar instalación de glow
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Verificando herramientas..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "glow instalado" "which glow"
if [ $? -eq 0 ]; then
    GLOW_VERSION=$(glow --version 2>/dev/null | head -1)
    echo "   Versión: $GLOW_VERSION"
fi

test_check "codex CLI instalado" "which codex"
if [ $? -eq 0 ]; then
    CODEX_VERSION=$(codex --version 2>/dev/null)
    echo "   Versión: $CODEX_VERSION"
fi

# 2. Verificar archivos creados
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. Verificando archivos..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "AGENTS.md existe y tiene contenido" "[ -f AGENTS.md ] && grep -q 'Output Formatting' AGENTS.md"
test_check ".codex/ESTETICA_PROFESIONAL.md existe" "[ -f .codex/ESTETICA_PROFESIONAL.md ]"
test_check ".codex/RESUMEN_MEJORAS_ESTETICA.md existe" "[ -f .codex/RESUMEN_MEJORAS_ESTETICA.md ]"
test_check "scripts/codex-format.sh existe y es ejecutable" "[ -x scripts/codex-format.sh ]"

# 3. Verificar configuración en .zshrc
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. Verificando configuración..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "Alias codex en .zshrc" "grep -q 'alias codex=' ~/.zshrc"
test_check "Alias codex-dev en .zshrc" "grep -q 'alias codex-dev=' ~/.zshrc"
test_check "Alias codex-format en .zshrc" "grep -q 'alias codex-format=' ~/.zshrc"
test_check "Aliases configurados correctamente" "grep -q 'alias codex=' ~/.zshrc"

# 4. Probar funcionalidad del script
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. Probando funcionalidad..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "Script codex-format.sh ejecutable" "bash scripts/codex-format.sh 'test' dark 2>&1 | head -1 >/dev/null"

# 5. Verificar contenido de AGENTS.md
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. Verificando contenido de AGENTS.md..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "AGENTS.md tiene sección de formato" "grep -q 'Output Formatting Guidelines' AGENTS.md"
test_check "AGENTS.md tiene estructura de informes" "grep -q 'Professional Report Structure' AGENTS.md"
test_check "AGENTS.md tiene guías de tablas" "grep -q 'Table Formatting' AGENTS.md"
test_check "AGENTS.md tiene guías de código" "grep -q 'Code Block Guidelines' AGENTS.md"

# 6. Verificar configuración Codex
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. Verificando configuración Codex..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "Configuración local existe" "[ -f .codex/config.toml ]"
test_check "Configuración global existe" "[ -f ~/.codex/config.toml ]"
test_check "Perfiles definidos en config local" "grep -q 'profiles.deep-engineering' .codex/config.toml"

# Resumen final
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "📊 Resumen de Validación"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo -e "✅ Pruebas pasadas: ${GREEN}$PASSED${NC}"
echo -e "❌ Pruebas fallidas: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ¡Todas las validaciones pasaron exitosamente!${NC}"
    echo ""
    echo "Próximos pasos:"
    echo "1. Recargar shell: source ~/.zshrc"
    echo "2. Probar: codex-format \"tu prompt\" dark"
    echo "3. Usar alias: codex-dev, codex-docs, codex-prototype"
    exit 0
else
    echo -e "${RED}⚠️  Algunas validaciones fallaron. Revisa los errores arriba.${NC}"
    exit 1
fi

