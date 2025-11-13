#!/bin/bash
# Copilot CLI - Validación de Rendimiento Máximo (2025)
# Verifica configuración completa para máximo rendimiento

set -e

echo "🚀 VALIDACIÓN COPILOT CLI - RENDIMIENTO MÁXIMO"
echo "=============================================="
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
PROJECT_ROOT="/Users/pedro/Documents/odoo19"
AGENTS_DIR="$PROJECT_ROOT/.github/agents"
CONFIG_DIR="$HOME/.copilot"
MCP_CONFIG="$HOME/.config/mcp-config.json"

echo -e "${BLUE}🔍 Verificando instalación base...${NC}"

# 1. Verificar instalación de Copilot CLI
if command -v copilot &> /dev/null; then
    COPILOT_VERSION=$(copilot --version 2>/dev/null | head -1)
    echo -e "${GREEN}✅ Copilot CLI instalado${NC}: $COPILOT_VERSION"
else
    echo -e "${RED}❌ Copilot CLI no encontrado${NC}"
    exit 1
fi

# 2. Verificar autenticación
echo
echo -e "${BLUE}🔐 Verificando autenticación...${NC}"

if copilot /auth status &> /dev/null; then
    echo -e "${GREEN}✅ Autenticado correctamente${NC}"
else
    echo -e "${YELLOW}⚠️  Autenticación pendiente${NC}: Ejecutar 'copilot' y usar '/login'"
fi

# 3. Verificar variables de entorno críticas
echo
echo -e "${BLUE}⚙️  Verificando variables de entorno...${NC}"

ENV_VARS=(
    "GITHUB_TOKEN:Token de GitHub"
    "GITHUB_MCP_TOKEN:Token MCP GitHub"
    "COPILOT_MAX_TOKENS:Contexto máximo (128k recomendado)"
    "COPILOT_MODEL:Modelo por defecto"
    "MCP_TIMEOUT:Timeout MCP (30s recomendado)"
    "MAX_MCP_OUTPUT_TOKENS:Tokens MCP output (100k recomendado)"
)

for var in "${ENV_VARS[@]}"; do
    KEY=$(echo $var | cut -d: -f1)
    DESC=$(echo $var | cut -d: -f2)
    if [ -n "${!KEY}" ]; then
        echo -e "${GREEN}✅ $KEY${NC}: ${!KEY} ($DESC)"
    else
        echo -e "${RED}❌ $KEY${NC}: No configurado ($DESC)"
    fi
done

# 4. Verificar configuración MCP
echo
echo -e "${BLUE}🔗 Verificando configuración MCP...${NC}"

if [ -f "$MCP_CONFIG" ]; then
    echo -e "${GREEN}✅ Archivo MCP config encontrado${NC}: $MCP_CONFIG"

    # Verificar servidores MCP
    MCP_SERVERS=$(jq -r '.mcpServers | keys[]' "$MCP_CONFIG" 2>/dev/null || echo "")
    if [ -n "$MCP_SERVERS" ]; then
        echo "Servidores MCP configurados:"
        for server in $MCP_SERVERS; do
            echo -e "  ${GREEN}✅ $server${NC}"
        done
    else
        echo -e "${YELLOW}⚠️  No se encontraron servidores MCP${NC}"
    fi
else
    echo -e "${RED}❌ Archivo MCP config no encontrado${NC}: $MCP_CONFIG"
fi

# 5. Verificar agentes especializados
echo
echo -e "${BLUE}🤖 Verificando agentes especializados...${NC}"

if [ -d "$AGENTS_DIR" ]; then
    AGENT_COUNT=$(find "$AGENTS_DIR" -name "*.agent.md" | wc -l)
    echo -e "${GREEN}✅ Directorio de agentes encontrado${NC}: $AGENT_COUNT agentes"

    # Listar agentes disponibles
    echo "Agentes disponibles:"
    for agent in "$AGENTS_DIR"/*.agent.md; do
        if [ -f "$agent" ]; then
            AGENT_NAME=$(basename "$agent" .agent.md)
            echo -e "  ${GREEN}✅ $AGENT_NAME${NC}"
        fi
    done
else
    echo -e "${RED}❌ Directorio de agentes no encontrado${NC}: $AGENTS_DIR"
fi

# 6. Verificar contexto del proyecto
echo
echo -e "${BLUE}📁 Verificando contexto del proyecto...${NC}"

PROJECT_FILES=(
    ".github/copilot-instructions.md:Instrucciones Copilot"
    ".github/agents/knowledge/sii_regulatory_context.md:Contexto regulatorio SII"
    ".github/agents/knowledge/odoo19_patterns.md:Patrones Odoo19"
    ".github/agents/knowledge/project_architecture.md:Arquitectura proyecto"
)

for file_info in "${PROJECT_FILES[@]}"; do
    FILE=$(echo $file_info | cut -d: -f1)
    DESC=$(echo $file_info | cut -d: -f2)
    if [ -f "$PROJECT_ROOT/$FILE" ]; then
        echo -e "${GREEN}✅ $DESC${NC}: $FILE"
    else
        echo -e "${RED}❌ $DESC faltante${NC}: $FILE"
    fi
done

# 7. Verificar aliases de shell
echo
echo -e "${BLUE}🔧 Verificando aliases de shell...${NC}"

SHELL_ALIASES=(
    "cop:copilot"
    "cop-dte:copilot DTE specialist"
    "cop-payroll:copilot Payroll compliance"
    "cop-security:copilot Security auditor"
    "cop-test:copilot Test automation"
    "cop-architect:copilot Odoo architect"
)

for alias_info in "${SHELL_ALIASES[@]}"; do
    ALIAS=$(echo $alias_info | cut -d: -f1)
    DESC=$(echo $alias_info | cut -d: -f2)
    if command -v $ALIAS &> /dev/null; then
        echo -e "${GREEN}✅ $ALIAS${NC}: $DESC"
    else
        echo -e "${RED}❌ Alias faltante${NC}: $ALIAS ($DESC)"
    fi
done

# 8. Prueba de rendimiento básica
echo
echo -e "${BLUE}⚡ Ejecutando prueba de rendimiento...${NC}"

# Medir tiempo de respuesta básico
START_TIME=$(date +%s.%3N)
timeout 30 copilot /help > /dev/null 2>&1
END_TIME=$(date +%s.%3N)
RESPONSE_TIME=$(echo "$END_TIME - $START_TIME" | bc)

if (( $(echo "$RESPONSE_TIME < 10" | bc -l) )); then
    echo -e "${GREEN}✅ Tiempo de respuesta aceptable${NC}: ${RESPONSE_TIME}s (< 10s)"
elif (( $(echo "$RESPONSE_TIME < 30" | bc -l) )); then
    echo -e "${YELLOW}⚠️  Tiempo de respuesta lento${NC}: ${RESPONSE_TIME}s (10-30s)"
else
    echo -e "${RED}❌ Tiempo de respuesta muy lento${NC}: ${RESPONSE_TIME}s (> 30s)"
fi

# 9. Verificar conectividad MCP
echo
echo -e "${BLUE}🌐 Verificando conectividad MCP...${NC}"

# Verificar conectividad GitHub MCP
if [ -n "$GITHUB_TOKEN" ]; then
    echo -e "${GREEN}✅ Token GitHub configurado${NC}"

    # Prueba básica de conectividad (sin ejecutar comando real)
    if curl -s -H "Authorization: token $GITHUB_TOKEN" \
             -H "Accept: application/vnd.github.v3+json" \
             "https://api.github.com/user" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Conectividad GitHub API${NC}"
    else
        echo -e "${YELLOW}⚠️  Problemas de conectividad GitHub${NC}"
    fi
else
    echo -e "${RED}❌ Token GitHub no configurado${NC}"
fi

# 10. Verificar configuración de memoria
echo
echo -e "${BLUE}🧠 Verificando configuración de memoria...${NC}"

MEMORY_VARS=(
    "COPILOT_MEMORY_DB_PATH:Ruta base de datos memoria"
    "COPILOT_CONTEXT_CACHE_SIZE:Tamaño cache contexto"
    "MCP_CACHE_TTL:TTL cache MCP"
)

for var in "${MEMORY_VARS[@]}"; do
    KEY=$(echo $var | cut -d: -f1)
    DESC=$(echo $var | cut -d: -f2)
    if [ -n "${!KEY}" ]; then
        echo -e "${GREEN}✅ $KEY${NC}: ${!KEY} ($DESC)"
    else
        echo -e "${YELLOW}⚠️  $KEY no configurado${NC} ($DESC)"
    fi
done

# 11. Recomendaciones finales
echo
echo -e "${BLUE}📋 RECOMENDACIONES PARA MÁXIMO RENDIMIENTO${NC}"
echo "=============================================="

RECOMMENDATIONS=(
    "🔄 Reiniciar terminal: source ~/.zshrc"
    "🔐 Autenticar si es necesario: copilot → /login"
    "⚙️  Verificar modelos: copilot /models"
    "🤖 Probar agentes: cop-agent dte-specialist"
    "📊 Monitorear uso: copilot /usage"
    "🔧 Actualizar tokens si es necesario"
)

for rec in "${RECOMMENDATIONS[@]}"; do
    echo -e "${YELLOW}•${NC} $rec"
done

echo
echo -e "${GREEN}✅ VALIDACIÓN COMPLETADA${NC}"
echo
echo "Para soporte adicional:"
echo "- Documentación: COPILOT_CLI_MIGRATION_GUIDE_2025.md"
echo "- Logs: ~/.copilot/logs/"
echo "- Config: ~/.copilot/config.json"
