#!/bin/bash
# Script de Actualización: GitHub Copilot CLI (Nueva Versión 2025)
# Fecha: 2025-11-10
# Propósito: Migrar de gh-copilot (deprecado) a @github/copilot

set -e

echo "🚀 ACTUALIZACIÓN GITHUB COPILOT CLI - VERSIÓN 2025"
echo "=================================================="
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Backup directory
BACKUP_DIR="$HOME/backups/copilot-migration-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo -e "${BLUE}📦 Creando backups de configuración actual...${NC}"

# Backup existing configs
if [ -f "$HOME/.config/mcp-config.json" ]; then
    cp "$HOME/.config/mcp-config.json" "$BACKUP_DIR/"
    echo "✅ Backup: mcp-config.json"
fi

if [ -d "$HOME/.copilot" ]; then
    cp -r "$HOME/.copilot" "$BACKUP_DIR/"
    echo "✅ Backup: directorio .copilot"
fi

if [ -f "$HOME/.zshrc" ]; then
    cp "$HOME/.zshrc" "$BACKUP_DIR/.zshrc.backup"
    echo "✅ Backup: .zshrc"
fi

echo
echo -e "${YELLOW}🔄 Desinstalando versión deprecada...${NC}"

# Remove old version if exists
if command -v gh &> /dev/null && gh extension list | grep -q "gh-copilot"; then
    echo "Removiendo extensión gh-copilot..."
    gh extension remove github/gh-copilot || true
fi

# Remove global npm package if exists
if npm list -g gh-copilot &> /dev/null; then
    echo "Removiendo paquete npm global gh-copilot..."
    npm uninstall -g gh-copilot || true
fi

echo
echo -e "${GREEN}📥 Instalando nueva versión de Copilot CLI...${NC}"

# Install new version
npm install -g @github/copilot

echo
echo -e "${BLUE}⚙️  Configurando MCP Servers...${NC}"

# Create new config directory
mkdir -p "$HOME/.copilot"

# Create MCP configuration for new CLI
cat > "$HOME/.copilot/config.json" << 'EOF'
{
  "version": "1.0",
  "mcpServers": {
    "filesystem-odoo19": {
      "provider": "@modelcontextprotocol/server-filesystem",
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-filesystem",
        "--root", "/Users/pedro/Documents/odoo19",
        "--no-hidden",
        "--gitignore"
      ],
      "env": {
        "NODE_ENV": "production",
        "WORKSPACE_ROOT": "/Users/pedro/Documents/odoo19"
      }
    },
    "github": {
      "provider": "@modelcontextprotocol/server-github", 
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-github",
        "--owner", "pwills85",
        "--repo", "odoo19"
      ],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_MCP_TOKEN}"
      }
    },
    "memory": {
      "provider": "@modelcontextprotocol/server-memory",
      "command": "mcp-memory",
      "args": [
        "--db-path", "/Users/pedro/.copilot/odoo19-knowledge.db"
      ]
    },
    "context7": {
      "provider": "@modelcontextprotocol/server-context7",
      "command": "mcp-context7",
      "args": [],
      "env": {
        "CONTEXT7_API_KEY": "${CONTEXT7_API_KEY}"
      }
    }
  },
  "defaultModel": "claude-3-5-sonnet-20241022",
  "availableModels": [
    "claude-3-5-sonnet-20241022",
    "claude-3-5-sonnet-v2",
    "gpt-4o"
  ]
}
EOF

echo "✅ Configuración MCP creada"

echo
echo -e "${YELLOW}🔧 Actualizando configuración de shell...${NC}"

# Update shell configuration
if ! grep -q "# GitHub Copilot CLI (New Version)" "$HOME/.zshrc"; then
    cat >> "$HOME/.zshrc" << 'EOF'

# GitHub Copilot CLI (New Version) - Added $(date +%Y-%m-%d)
eval "$(copilot alias -- zsh)"

# Custom aliases for Odoo19 project
alias cop="copilot"
alias cop-dte="copilot --context $HOME/Documents/odoo19/.github/agents/dte-specialist.agent.md"
alias cop-payroll="copilot --context $HOME/Documents/odoo19/.github/agents/payroll-compliance.agent.md"
alias cop-security="copilot --context $HOME/Documents/odoo19/.github/agents/security-auditor.agent.md"
alias cop-test="copilot --context $HOME/Documents/odoo19/.github/agents/test-automation.agent.md"
alias cop-architect="copilot --context $HOME/Documents/odoo19/.github/agents/odoo-architect.agent.md"

# Function to quickly switch agent context
cop-agent() {
    local agent=$1
    shift
    if [ -f "$HOME/Documents/odoo19/.github/agents/${agent}.agent.md" ]; then
        copilot --context "$HOME/Documents/odoo19/.github/agents/${agent}.agent.md" "$@"
    else
        echo "Agent not found: ${agent}"
        echo "Available agents:"
        ls -1 $HOME/Documents/odoo19/.github/agents/*.agent.md | xargs -n1 basename | sed 's/.agent.md//'
    fi
}

# Programmatic mode helper
cop-run() {
    local prompt=$1
    shift
    copilot -p "$prompt" --allow-tool 'filesystem-odoo19' --allow-tool 'write' "$@"
}

EOF
    echo "✅ Aliases y helpers añadidos a .zshrc"
else
    echo "⏭️  Configuración de shell ya existe"
fi

echo
echo -e "${BLUE}📁 Creando estructura de agentes locales...${NC}"

# Create local agents directory
AGENTS_DIR="$HOME/.copilot/agents"
mkdir -p "$AGENTS_DIR"

# Create specialized Copilot agents (diferentes a Claude Code)
cat > "$AGENTS_DIR/chilean-compliance.md" << 'EOF'
# Chilean Compliance Specialist

You are an expert in Chilean regulatory compliance for business software, specializing in:

- SII (Servicio de Impuestos Internos) regulations
- DTE (Documentos Tributarios Electrónicos) requirements
- Chilean labor law and payroll regulations
- Previred integration requirements
- Financial reporting standards (F29, F22)

Always reference current Chilean law and SII resolutions when providing guidance.
EOF

cat > "$AGENTS_DIR/mcp-integration.md" << 'EOF'
# MCP Integration Specialist

You are an expert in Model Context Protocol (MCP) integration, specializing in:

- Setting up MCP servers for different tools
- Configuring filesystem, GitHub, and memory providers
- Optimizing MCP performance and security
- Troubleshooting MCP connection issues
- Building custom MCP servers

Focus on practical implementation and best practices for production environments.
EOF

cat > "$AGENTS_DIR/odoo-migration.md" << 'EOF'
# Odoo Migration Specialist

You are an expert in Odoo migrations, specializing in:

- Enterprise to Community Edition migrations
- Version upgrades (11 → 16 → 19)
- Data migration strategies
- Module compatibility analysis
- Performance optimization during migration

Focus on Chilean localization modules and maintaining regulatory compliance during migrations.
EOF

echo "✅ Agentes especializados creados"

echo
echo -e "${GREEN}🔍 Verificando instalación...${NC}"

# Verify installation
if command -v copilot &> /dev/null; then
    COPILOT_VERSION=$(copilot --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✅ GitHub Copilot CLI instalado correctamente${NC}"
    echo "   Versión: $COPILOT_VERSION"
else
    echo -e "${RED}❌ Error: Copilot CLI no se instaló correctamente${NC}"
    exit 1
fi

echo
echo -e "${BLUE}📋 Actualizando script de validación...${NC}"

# Update validation script
if [ -f "/Users/pedro/Documents/odoo19/scripts/validate_cli_integration.sh" ]; then
    # Create backup
    cp "/Users/pedro/Documents/odoo19/scripts/validate_cli_integration.sh" "$BACKUP_DIR/"
    
    # Update paths and commands
    sed -i '' 's|~/.config/mcp-config.json|~/.copilot/config.json|g' \
        "/Users/pedro/Documents/odoo19/scripts/validate_cli_integration.sh"
    sed -i '' 's|gh-copilot|copilot|g' \
        "/Users/pedro/Documents/odoo19/scripts/validate_cli_integration.sh"
    
    echo "✅ Script de validación actualizado"
fi

echo
echo -e "${YELLOW}📝 Creando documentación de migración...${NC}"

# Create migration guide
cat > "/Users/pedro/Documents/odoo19/COPILOT_CLI_MIGRATION_GUIDE_2025.md" << 'EOF'
# GitHub Copilot CLI - Guía de Migración 2025

## 🔄 Cambios Principales

### Antes (Deprecado)
```bash
gh extension install github/gh-copilot
gh copilot suggest "comando"
gh copilot explain "comando"
```

### Ahora (Nueva CLI)
```bash
npm install -g @github/copilot
copilot  # Modo interactivo
copilot -p "prompt" --allow-tool 'filesystem'  # Modo programático
```

## 🚀 Nuevas Características

1. **Modo Agéntico**: Copilot puede realizar tareas complejas
2. **MCP Integration**: Acceso a filesystem, GitHub, memoria
3. **Modo Programático**: Para CI/CD y automatización
4. **Modelos Múltiples**: Claude Sonnet 4.5, GPT-5

## 📁 Ubicaciones de Configuración

- **Config principal**: `~/.copilot/config.json`
- **Agentes locales**: `~/.copilot/agents/`
- **Base de conocimiento**: `~/.copilot/odoo19-knowledge.db`
- **Logs**: `~/.copilot/logs/`

## 🔧 Comandos Útiles

```bash
# Aliases configurados
cop                  # Copilot interactivo
cop-dte             # Con contexto DTE specialist
cop-payroll         # Con contexto Payroll compliance
cop-security        # Con contexto Security auditor

# Funciones helper
cop-agent <name>    # Cambiar agente rápidamente
cop-run "prompt"    # Ejecutar en modo programático
```

## 🔐 Variables de Entorno

```bash
export GITHUB_TOKEN="ghp_..."          # Para autenticación
export GITHUB_MCP_TOKEN="ghp_..."      # Para MCP GitHub server
export CONTEXT7_API_KEY="..."          # Para documentación
```

## 📊 Verificación

Ejecutar: `bash /Users/pedro/Documents/odoo19/scripts/validate_cli_integration.sh`
EOF

echo "✅ Guía de migración creada"

echo
echo "=================================================="
echo -e "${GREEN}✅ ACTUALIZACIÓN COMPLETADA${NC}"
echo
echo "Próximos pasos:"
echo "1. Reiniciar terminal o ejecutar: source ~/.zshrc"
echo "2. Probar nueva CLI: copilot"
echo "3. Verificar MCP: copilot /mcp"
echo "4. Ejecutar validación: bash scripts/validate_cli_integration.sh"
echo
echo "Backups guardados en: $BACKUP_DIR"
echo
echo -e "${YELLOW}⚠️  IMPORTANTE:${NC}"
echo "- La extensión gh-copilot fue deprecada el 25 de octubre 2025"
echo "- Usar 'copilot' en lugar de 'gh copilot'"
echo "- Revisar COPILOT_CLI_MIGRATION_GUIDE_2025.md para más detalles"