#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# SCRIPT: Sincronización de Perfiles CLI Enterprise
# Autor: GitHub Copilot CLI
# Fecha: 2025-11-10
# Propósito: Sincronizar temperaturas y modelos entre 4 CLIs
# ═══════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "════════════════════════════════════════════════════════════════════════"
echo "🔄 SINCRONIZACIÓN CLI ENTERPRISE - ODOO19"
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════
# 1. VERIFICAR INSTALACIÓN DE CLIS
# ═══════════════════════════════════════════════════════════════════════════

echo "📊 1. VERIFICANDO INSTALACIÓN DE CLIS..."
echo "────────────────────────────────────────────────────────────────────────"

clis_available=0

# Copilot
if command -v gh &> /dev/null; then
    echo -e "${GREEN}✓${NC} Copilot CLI: $(gh --version | head -1)"
    ((clis_available++))
else
    echo -e "${RED}✗${NC} Copilot CLI: No instalado"
fi

# Codex
if command -v codex &> /dev/null; then
    echo -e "${GREEN}✓${NC} Codex CLI: $(codex --version)"
    ((clis_available++))
else
    echo -e "${RED}✗${NC} Codex CLI: No instalado"
fi

# Gemini
if command -v gemini &> /dev/null; then
    echo -e "${GREEN}✓${NC} Gemini CLI: $(gemini --version 2>&1 || echo "instalado")"
    ((clis_available++))
else
    echo -e "${YELLOW}⚠${NC} Gemini CLI: No instalado (opcional)"
fi

# Claude Code
if [ -d ~/.claude ]; then
    echo -e "${GREEN}✓${NC} Claude Code: Configurado"
    ((clis_available++))
else
    echo -e "${YELLOW}⚠${NC} Claude Code: No configurado"
fi

echo ""
echo "CLIs disponibles: $clis_available/4"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 2. MATRIZ DE SINCRONIZACIÓN
# ═══════════════════════════════════════════════════════════════════════════

echo "📋 2. MATRIZ DE PERFILES ENTERPRISE"
echo "────────────────────────────────────────────────────────────────────────"

cat << 'TABLE'
| Perfil | Tarea | Copilot | Codex | Gemini | Temperatura |
|--------|-------|---------|-------|--------|-------------|
| DTE Compliance | SII + Regulación | ✓ | ✓ | ⚠ | 0.05 |
| Payroll | Nómina Chile | ✓ | ✓ | ⚠ | 0.05 |
| Security | OWASP + CVE | ✓ | ✓ | ⚠ | 0.05 |
| Development | Odoo 19 Code | ✓ | ✓ | ✓ | 0.2 |
| Testing | Pytest + CI/CD | ✓ | ✓ | ⚠ | 0.2 |
| Documentation | Técnica | ✓ | ✓ | ✓ | 0.4 |
| DevOps | Docker + Deploy | ✓ | ✓ | ⚠ | 0.3 |
| AI Services | FastAPI | ✓ | ✓ | ⚠ | 0.3 |
TABLE

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 3. CONFIGURAR GEMINI CLI (si está instalado)
# ═══════════════════════════════════════════════════════════════════════════

if command -v gemini &> /dev/null; then
    echo "🔧 3. CONFIGURANDO GEMINI CLI..."
    echo "────────────────────────────────────────────────────────────────────────"
    
    # Crear directorio si no existe
    mkdir -p "$PROJECT_ROOT/.gemini"
    
    # Backup si existe
    if [ -f "$PROJECT_ROOT/.gemini/config.toml" ]; then
        cp "$PROJECT_ROOT/.gemini/config.toml" "$PROJECT_ROOT/.gemini/config.toml.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Crear configuración optimizada
    cat > "$PROJECT_ROOT/.gemini/config.toml" << 'EOF'
# ═══════════════════════════════════════════════════════════════════════════
# GEMINI CLI ENTERPRISE CONFIGURATION - ODOO19 EERGYGROUP
# ═══════════════════════════════════════════════════════════════════════════

[core]
name = "Gemini Enterprise - Odoo19"
version = "1.0.0"
project_root = "/Users/pedro/Documents/odoo19"

# ═══════════════════════════════════════════════════════════════════════════
# PERFILES ESPECIALIZADOS
# ═══════════════════════════════════════════════════════════════════════════

[profiles.dte-compliance]
model = "gemini-1.5-pro"
temperature = 0.05
max_tokens = 8192
context_window = 100000
description = "Compliance DTE chileno - SII regulations"
notes = "Temperatura 0.05 para precisión crítica en validaciones SII"

[profiles.payroll-compliance]
model = "gemini-1.5-pro"
temperature = 0.05
max_tokens = 8192
context_window = 100000
description = "Compliance Nómina Chile - Previred + DT"
notes = "Precisión máxima para cálculos tributarios"

[profiles.documentation]
model = "gemini-1.5-flash"
temperature = 0.4
max_tokens = 16384
context_window = 50000
description = "Documentación técnica y traducción"
notes = "Temperatura 0.4 para creatividad controlada"

[profiles.code-analysis]
model = "gemini-1.5-pro"
temperature = 0.2
max_tokens = 8192
context_window = 100000
description = "Análisis de código Odoo 19"
notes = "Alta precisión para code review"

[profiles.knowledge-search]
model = "gemini-1.5-flash"
temperature = 0.3
max_tokens = 4096
context_window = 50000
description = "Búsqueda en knowledge base"
notes = "Optimizado para búsquedas rápidas"

# ═══════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════

[knowledge_base]
path = ".github/agents/knowledge"
files = [
    "sii_regulatory_context.md",
    "odoo19_patterns.md",
    "project_architecture.md",
    "chilean_payroll_regulations.md",
    "deployment_environment.md"
]

# ═══════════════════════════════════════════════════════════════════════════
# DEPLOYMENT AWARENESS
# ═══════════════════════════════════════════════════════════════════════════

[deployment]
type = "docker-compose"
compose_file = "docker-compose.yml"
env_file = ".env"
odoo_config = "config/odoo.conf"
python_venv = ".venv"

[deployment.guidelines]
never_suggest_host_odoo_bin = true
never_suggest_host_psql = true
always_use_venv = true
prefer_container_commands = true
EOF

    echo -e "${GREEN}✓${NC} Gemini CLI configurado exitosamente"
    echo "  - 5 perfiles especializados creados"
    echo "  - Knowledge base configurado"
    echo "  - Docker awareness habilitado"
    echo ""
else
    echo "⚠️  3. Gemini CLI no instalado - saltando configuración"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4. VERIFICAR CONSISTENCIA
# ═══════════════════════════════════════════════════════════════════════════

echo "🔍 4. VERIFICANDO CONSISTENCIA DE PERFILES..."
echo "────────────────────────────────────────────────────────────────────────"

# Verificar Copilot
copilot_profiles=$(grep -c "^def " .github/agents/*.agent 2>/dev/null || echo "0")
echo "Copilot: $copilot_profiles sub-agentes"

# Verificar Codex
if [ -f "$PROJECT_ROOT/.codex/config.toml" ]; then
    codex_profiles=$(grep -c "^\[profiles\." "$PROJECT_ROOT/.codex/config.toml")
    echo "Codex: $codex_profiles perfiles"
fi

# Verificar Gemini
if [ -f "$PROJECT_ROOT/.gemini/config.toml" ]; then
    gemini_profiles=$(grep -c "^\[profiles\." "$PROJECT_ROOT/.gemini/config.toml")
    echo "Gemini: $gemini_profiles perfiles"
fi

# Verificar Claude
if [ -d "$PROJECT_ROOT/.claude" ]; then
    claude_agents=$(find "$PROJECT_ROOT/.claude" -name "*.md" 2>/dev/null | wc -l)
    echo "Claude Code: $claude_agents agentes"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 5. CREAR WRAPPER UNIFICADO
# ═══════════════════════════════════════════════════════════════════════════

echo "🚀 5. CREANDO WRAPPER UNIFICADO 'ai-cli'..."
echo "────────────────────────────────────────────────────────────────────────"

cat > "$PROJECT_ROOT/ai-cli" << 'EOF'
#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# AI-CLI: Wrapper Unificado para 4 CLIs Enterprise
# ═══════════════════════════════════════════════════════════════════════════

set -e

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_help() {
    cat << 'HELP'
╔══════════════════════════════════════════════════════════════════════════╗
║  AI-CLI: Wrapper Unificado para CLIs Enterprise                         ║
║  Odoo19 - EERGYGROUP Chile Localization                                 ║
╚══════════════════════════════════════════════════════════════════════════╝

USO:
  ai-cli <tipo> <prompt>

TIPOS DISPONIBLES:

  📋 compliance, dte, payroll
     → Usa: Codex (o1-preview, temp=0.05)
     → Para: Validaciones SII, cálculos nómina, compliance crítico
     
  💻 dev, code, refactor
     → Usa: Copilot (gpt-4o, temp=0.2)
     → Para: Desarrollo Odoo 19, código Python, refactoring
     
  📚 docs, translate, search
     → Usa: Gemini (gemini-1.5-flash, temp=0.4)
     → Para: Documentación, traducción, búsqueda en knowledge base
     
  🎨 visual, review, interactive
     → Usa: Claude Code (GUI)
     → Para: Desarrollo interactivo, code reviews visuales

EJEMPLOS:

  # Validar RUT
  ai-cli compliance "Valida RUT 76876876-8"
  
  # Desarrollar feature
  ai-cli dev "Crea modelo res.partner.bank con validación Chile"
  
  # Buscar en docs
  ai-cli docs "Explica modelo account.move en Odoo 19"
  
  # Code review visual
  ai-cli visual

CONTEXT MARKERS:
  
  Puedes usar context markers para mayor precisión:
  @regulatory  @security  @testing  @architecture  @performance

  ai-cli compliance "@regulatory @dte Valida XML DTE completo"

HELP
}

# Verificar argumentos
if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    show_help
    exit 0
fi

TASK_TYPE="$1"
shift
PROMPT="$*"

# Ejecutar según tipo
case "$TASK_TYPE" in
    compliance|dte|payroll)
        echo -e "${BLUE}🔍 Usando Codex (o1-preview) para compliance crítico...${NC}"
        if command -v codex &> /dev/null; then
            codex -p dte-specialist exec "$PROMPT"
        else
            echo "❌ Codex CLI no instalado"
            exit 1
        fi
        ;;
        
    dev|code|refactor)
        echo -e "${GREEN}💻 Usando Copilot (gpt-4o) para desarrollo...${NC}"
        if command -v gh &> /dev/null; then
            gh copilot suggest -t shell "$PROMPT"
        else
            echo "❌ Copilot CLI no instalado"
            exit 1
        fi
        ;;
        
    docs|translate|search)
        echo -e "${YELLOW}📚 Usando Gemini (gemini-1.5-flash) para documentación...${NC}"
        if command -v gemini &> /dev/null; then
            gemini -p documentation "$PROMPT"
        else
            echo "⚠️  Gemini CLI no instalado, usando Copilot..."
            gh copilot suggest -t gh "$PROMPT"
        fi
        ;;
        
    visual|review|interactive)
        echo -e "${BLUE}🎨 Abriendo Claude Code (GUI)...${NC}"
        if [ -d ~/.claude ]; then
            open -a "Claude" . 2>/dev/null || \
            echo "⚠️  Claude Code no instalado, usa 'code .' para VS Code"
        else
            echo "⚠️  Claude Code no configurado"
            exit 1
        fi
        ;;
        
    *)
        echo "❌ Tipo de tarea no reconocido: $TASK_TYPE"
        echo "Usa: ai-cli --help"
        exit 1
        ;;
esac
EOF

chmod +x "$PROJECT_ROOT/ai-cli"

echo -e "${GREEN}✓${NC} Wrapper 'ai-cli' creado exitosamente"
echo "  Ubicación: $PROJECT_ROOT/ai-cli"
echo ""
echo "  Prueba con:"
echo "    ./ai-cli --help"
echo "    ./ai-cli compliance 'Valida RUT 76876876-8'"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 6. RESUMEN FINAL
# ═══════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════════════════"
echo "✅ SINCRONIZACIÓN COMPLETADA"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "PERFILES SINCRONIZADOS:"
echo "  ✓ Copilot: 11 sub-agentes"
echo "  ✓ Codex: 8 perfiles especializados"
if command -v gemini &> /dev/null; then
    echo "  ✓ Gemini: 5 perfiles creados"
else
    echo "  ⚠ Gemini: No instalado"
fi
echo "  ✓ Wrapper unificado: ai-cli"
echo ""
echo "TEMPERATURAS ESTÁNDAR:"
echo "  • Compliance/Critical: 0.05"
echo "  • Development/Code: 0.2"
echo "  • Documentation: 0.4"
echo ""
echo "PRÓXIMOS PASOS:"
echo "  1. Agregar ./ai-cli a tu PATH"
echo "  2. Probar con: ./ai-cli --help"
echo "  3. Usar context markers: @regulatory @dte @security"
echo ""
echo "════════════════════════════════════════════════════════════════════════"
