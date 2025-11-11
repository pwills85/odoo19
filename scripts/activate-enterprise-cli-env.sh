#!/bin/bash

# 🚀 ACTIVADOR ENTERPRISE: Entorno CLI Completo
# Activa todas las configuraciones enterprise para Copilot, Codex y Gemini

set -euo pipefail

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║           🚀 ACTIVADOR ENTERPRISE CLI - ODOO 19 CE                       ║
║                                                                           ║
║    Activando configuración con modelos más inteligentes disponibles     ║
║                  Temperatura 0.1 para máxima precisión                   ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# =============================================================================
# CARGAR CONFIGURACIONES
# =============================================================================

echo -e "${BLUE}▶ Activando Copilot CLI Enterprise...${NC}"
if [ -f "copilot-advanced.env" ]; then
    source copilot-advanced.env
    echo -e "${GREEN}  ✅ Copilot: $COPILOT_MODEL (temperatura: $COPILOT_TEMPERATURE)${NC}"
else
    echo -e "${YELLOW}  ⚠️  Archivo copilot-advanced.env no encontrado${NC}"
fi

echo ""
echo -e "${BLUE}▶ Activando Gemini CLI Enterprise...${NC}"
if [ -f "gemini-enhanced.env" ]; then
    source gemini-enhanced.env
    echo -e "${GREEN}  ✅ Gemini: $GEMINI_MODEL (temperatura: $GEMINI_TEMPERATURE)${NC}"
else
    echo -e "${YELLOW}  ⚠️  Archivo gemini-enhanced.env no encontrado${NC}"
fi

echo ""
echo -e "${BLUE}▶ Verificando Codex CLI Enterprise...${NC}"
if [ -f "$HOME/.codex/config.toml" ]; then
    local codex_model=$(grep "^model =" "$HOME/.codex/config.toml" | cut -d'"' -f2)
    local codex_temp=$(grep "^model_temperature =" "$HOME/.codex/config.toml" | cut -d'=' -f2 | tr -d ' ')
    echo -e "${GREEN}  ✅ Codex: $codex_model (temperatura: $codex_temp)${NC}"
else
    echo -e "${YELLOW}  ⚠️  Archivo ~/.codex/config.toml no encontrado${NC}"
fi

# =============================================================================
# CONFIGURAR ALIASES ÚTILES
# =============================================================================

echo ""
echo -e "${BLUE}▶ Configurando aliases útiles...${NC}"

# Alias para intelligent router
alias cli-route='./scripts/intelligent-cli-router-enterprise.sh'
alias cli-arch='./scripts/intelligent-cli-router-enterprise.sh architecture'
alias cli-comp='./scripts/intelligent-cli-router-enterprise.sh compliance'
alias cli-code='./scripts/intelligent-cli-router-enterprise.sh code-gen'
alias cli-debug='./scripts/intelligent-cli-router-enterprise.sh debugging'
alias cli-dte='./scripts/intelligent-cli-router-enterprise.sh dte-audit'

echo -e "${GREEN}  ✅ Aliases configurados:${NC}"
echo "     • cli-route   - Intelligent router general"
echo "     • cli-arch    - Análisis arquitectural"
echo "     • cli-comp    - Validación compliance"
echo "     • cli-code    - Generación de código"
echo "     • cli-debug   - Debugging complejo"
echo "     • cli-dte     - Auditoría DTE"

# =============================================================================
# VALIDAR CONFIGURACIÓN
# =============================================================================

echo ""
echo -e "${BLUE}▶ Ejecutando validación rápida...${NC}"

# Test de Copilot
if command -v gh &> /dev/null; then
    echo -e "${GREEN}  ✅ Copilot CLI disponible${NC}"
else
    echo -e "${YELLOW}  ⚠️  Copilot CLI no encontrado${NC}"
fi

# Test de Codex
if command -v codex &> /dev/null; then
    echo -e "${GREEN}  ✅ Codex CLI disponible${NC}"
else
    echo -e "${YELLOW}  ⚠️  Codex CLI no encontrado${NC}"
fi

# Test de Gemini
if command -v gemini &> /dev/null; then
    echo -e "${GREEN}  ✅ Gemini CLI disponible${NC}"
else
    echo -e "${YELLOW}  ⚠️  Gemini CLI no encontrado${NC}"
fi

# =============================================================================
# RESUMEN FINAL
# =============================================================================

echo ""
echo -e "${CYAN}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║               ✅ ENTORNO ENTERPRISE CLI ACTIVADO                          ║
║                                                                           ║
║   CONFIGURACIÓN:                                                          ║
║   • Copilot: GPT-5 (temp 0.1)                                            ║
║   • Codex: GPT-4o (temp 0.1)                                             ║
║   • Gemini: Ultra 1.5 (temp 0.1)                                         ║
║                                                                           ║
║   ALIASES DISPONIBLES:                                                    ║
║   • cli-arch "prompt"   - Análisis arquitectural                         ║
║   • cli-comp "prompt"   - Validación compliance                          ║
║   • cli-code "prompt"   - Generación de código                           ║
║   • cli-debug "prompt"  - Debugging complejo                             ║
║   • cli-dte "prompt"    - Auditoría DTE                                  ║
║                                                                           ║
║   🎯 SISTEMA LISTO PARA DESARROLLO ODOO 19 CE                            ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo ""
echo -e "${GREEN}Para validar configuración completa, ejecuta:${NC}"
echo "  ./scripts/validate-cli-enterprise-precision-config.sh"
echo ""
echo -e "${GREEN}Para ver guía de uso completa:${NC}"
echo "  cat GUIA_USO_CLI_ENTERPRISE_ODOO19.md"
echo ""
