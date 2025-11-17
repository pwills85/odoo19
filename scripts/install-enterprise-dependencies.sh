#!/bin/bash
# Instalación de Dependencias Enterprise
# Instala todas las dependencias necesarias para el sistema enterprise

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuración de colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() {
    local level=$1
    local message=$2
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message"
}

# Función de verificación de sistema
check_system() {
    log "INFO" "Verificando sistema operativo..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "  ${GREEN}✅ macOS detectado${NC}"
        PACKAGE_MANAGER="brew"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            echo -e "  ${GREEN}✅ Ubuntu/Debian detectado${NC}"
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            echo -e "  ${GREEN}✅ CentOS/RHEL detectado${NC}"
            PACKAGE_MANAGER="yum"
        else
            echo -e "  ${YELLOW}⚠️  Sistema Linux no estándar${NC}"
            PACKAGE_MANAGER="unknown"
        fi
    else
        echo -e "  ${RED}❌ Sistema operativo no soportado: $OSTYPE${NC}"
        exit 1
    fi
}

# Función de instalación de Python y pip
install_python_deps() {
    log "INFO" "Instalando dependencias de Python..."

    # Verificar Python 3.8+
    if ! python3 --version | grep -q "Python 3.[89]\|3.[1-9][0-9]"; then
        echo -e "  ${RED}❌ Se requiere Python 3.8 o superior${NC}"
        exit 1
    fi

    echo -e "  ${GREEN}✅ Python $(python3 --version)${NC}"

    # Instalar pip si no está disponible
    if ! command -v pip3 &> /dev/null; then
        echo -e "  ${YELLOW}Instalando pip3...${NC}"
        curl -sS https://bootstrap.pypa.io/get-pip.py | python3
    fi

    echo -e "  ${GREEN}✅ Pip3 disponible${NC}"

    # Instalar dependencias Python
    local python_packages=(
        "chromadb"
        "sentence-transformers"
        "numpy"
        "scipy"
        "scikit-learn"
        "pandas"
        "toml"
        "sqlite3"
        "requests"
    )

    for package in "${python_packages[@]}"; do
        echo -e "  ${BLUE}Instalando $package...${NC}"
        if pip3 install "$package" --quiet; then
            echo -e "    ${GREEN}✅ $package${NC}"
        else
            echo -e "    ${RED}❌ Error instalando $package${NC}"
        fi
    done
}

# Función de instalación de Node.js y herramientas
install_nodejs_deps() {
    log "INFO" "Instalando dependencias de Node.js..."

    # Verificar Node.js
    if ! command -v node &> /dev/null; then
        echo -e "  ${YELLOW}Instalando Node.js...${NC}"
        if [[ "$PACKAGE_MANAGER" == "brew" ]]; then
            brew install node
        elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
            curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
            sudo apt-get install -y nodejs
        else
            echo -e "  ${RED}❌ Instala Node.js manualmente${NC}"
            exit 1
        fi
    fi

    echo -e "  ${GREEN}✅ Node.js $(node --version)${NC}"
    echo -e "  ${GREEN}✅ NPM $(npm --version)${NC}"

    # Instalar paquetes npm globales
    local npm_packages=(
        "@modelcontextprotocol/server-filesystem"
        "@modelcontextprotocol/server-github"
        "@modelcontextprotocol/server-memory"
    )

    for package in "${npm_packages[@]}"; do
        echo -e "  ${BLUE}Instalando $package...${NC}"
        if npm install -g "$package" --silent; then
            echo -e "    ${GREEN}✅ $package${NC}"
        else
            echo -e "    ${RED}❌ Error instalando $package${NC}"
        fi
    done
}

# Función de instalación de herramientas de sistema
install_system_tools() {
    log "INFO" "Instalando herramientas de sistema..."

    local system_tools=()

    if [[ "$PACKAGE_MANAGER" == "brew" ]]; then
        system_tools=("jq" "curl" "wget" "git" "sqlite3")
        for tool in "${system_tools[@]}"; do
            if ! command -v "$tool" &> /dev/null; then
                echo -e "  ${BLUE}Instalando $tool...${NC}"
                brew install "$tool"
                echo -e "    ${GREEN}✅ $tool${NC}"
            else
                echo -e "    ${GREEN}✅ $tool (ya instalado)${NC}"
            fi
        done
    elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        system_tools=("jq" "curl" "wget" "git" "sqlite3")
        echo -e "  ${BLUE}Actualizando lista de paquetes...${NC}"
        sudo apt-get update --quiet
        for tool in "${system_tools[@]}"; do
            if ! command -v "$tool" &> /dev/null; then
                echo -e "  ${BLUE}Instalando $tool...${NC}"
                sudo apt-get install -y "$tool" --quiet
                echo -e "    ${GREEN}✅ $tool${NC}"
            else
                echo -e "    ${GREEN}✅ $tool (ya instalado)${NC}"
            fi
        done
    fi
}

# Función de verificación de instalación
verify_installation() {
    log "INFO" "Verificando instalación completa..."

    local verification_passed=0
    local verification_total=0

    # Verificar Python y paquetes
    ((verification_total++))
    if python3 -c "import chromadb, sentence_transformers, numpy, toml" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Paquetes Python principales${NC}"
        ((verification_passed++))
    else
        echo -e "  ${RED}❌ Paquetes Python principales faltantes${NC}"
    fi

    # Verificar Node.js y paquetes
    ((verification_total++))
    if command -v npx &> /dev/null; then
        echo -e "  ${GREEN}✅ Herramientas Node.js${NC}"
        ((verification_passed++))
    else
        echo -e "  ${RED}❌ Herramientas Node.js faltantes${NC}"
    fi

    # Verificar herramientas de sistema
    ((verification_total++))
    if command -v jq &> /dev/null && command -v sqlite3 &> /dev/null; then
        echo -e "  ${GREEN}✅ Herramientas de sistema${NC}"
        ((verification_passed++))
    else
        echo -e "  ${RED}❌ Herramientas de sistema faltantes${NC}"
    fi

    # Verificar espacio en disco
    ((verification_total++))
    local available_space=$(df "$HOME" | tail -1 | awk '{print $4}')
    local min_space=$((1024*1024*10))  # 10GB en KB

    if [ "$available_space" -gt "$min_space" ]; then
        echo -e "  ${GREEN}✅ Espacio en disco suficiente${NC} ($(df -h "$HOME" | tail -1 | awk '{print $4}') disponible)"
        ((verification_passed++))
    else
        echo -e "  ${YELLOW}⚠️  Poco espacio en disco${NC} ($(df -h "$HOME" | tail -1 | awk '{print $4}') disponible)"
    fi

    local percentage=$((verification_passed * 100 / verification_total))
    echo -e "\nVerificación: $verification_passed/$verification_total ($percentage%)"

    if [ $percentage -ge 80 ]; then
        return 0
    else
        return 1
    fi
}

# Función de creación de directorios
create_directories() {
    log "INFO" "Creando estructura de directorios..."

    local dirs=(
        "~/.codex/enterprise/intelligence"
        "~/.codex/enterprise/knowledge-index"
        "~/.codex/enterprise/vector-store"
        "~/.codex/enterprise/memory-bank"
        "~/.codex/enterprise/memory-bank/backups"
        "~/.codex/enterprise/context-models"
        "~/.codex/enterprise/context-cache"
        "~/.codex/enterprise/context-cache/versions"
        "~/.codex/enterprise/model-optimization"
        "~/.codex/enterprise/model-optimization/metrics"
        "~/.codex/enterprise/mcp-enterprise"
        "~/.codex/enterprise/mcp-enterprise/logs"
        "~/.codex/enterprise/mcp-enterprise/metrics"
    )

    for dir in "${dirs[@]}"; do
        expanded_dir="${dir/#\~/$HOME}"
        if mkdir -p "$expanded_dir" 2>/dev/null; then
            echo -e "  ${GREEN}✅ ${dir}${NC}"
        else
            echo -e "  ${YELLOW}⚠️  ${dir}${NC} (Error creando directorio)"
        fi
    done
}

# Función principal
main() {
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 📦 INSTALACIÓN DE DEPENDENCIAS ENTERPRISE                                 ║"
    echo "║                                                                            ║"
    echo "║ Componentes a instalar:                                                    ║"
    echo "║ • Python 3.8+ con paquetes científicos                                    ║"
    echo "║ • Node.js con MCP servers                                                 ║"
    echo "║ • Herramientas de sistema (jq, sqlite3, etc.)                             ║"
    echo "║ • Estructura de directorios enterprise                                    ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    log "ENTERPRISE" "Iniciando instalación de dependencias enterprise..."

    # Verificar sistema
    check_system

    echo

    # Instalar componentes
    install_system_tools
    echo

    install_python_deps
    echo

    install_nodejs_deps
    echo

    create_directories
    echo

    # Verificar instalación
    if verify_installation; then
        echo
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║ ✅ INSTALACIÓN COMPLETADA EXITOSAMENTE                                    ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo
        log "SUCCESS" "Instalación de dependencias enterprise completada"

        echo "🚀 Próximos pasos:"
        echo "1. bash scripts/enterprise-orchestration-system.sh"
        echo "2. bash scripts/index-knowledge-base.sh"
        echo "3. bash scripts/train-context-models.sh"
        echo "4. bash scripts/validate-enterprise-system.sh"
        echo
        echo "📚 Documentación:"
        echo "• Archivos de configuración: .codex/enterprise/"
        echo "• Logs de instalación: ~/.codex/enterprise/installation.log"
        echo
    else
        echo
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║ ⚠️  INSTALACIÓN COMPLETADA CON ADVERTENCIAS                               ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo
        log "WARNING" "Instalación completada con algunos problemas"
        echo -e "${YELLOW}Revisa los errores arriba y ejecuta la validación${NC}"
    fi
}

# Ejecutar función principal
main "$@"
