#!/bin/bash
# Script de Validación: Configuración Enterprise Copilot CLI
# Fecha: 2024-11-10
# Verifica que toda la configuración enterprise esté funcionando correctamente

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuración de colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Función de logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Función para verificar conectividad de red
check_network() {
    if curl -s --connect-timeout 5 https://github.com >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Array para almacenar resultados
declare -a validation_results=()
declare -a warnings=()
declare -a errors=()

echo
echo "🤖 VALIDACIÓN CONFIGURACIÓN ENTERPRISE COPILOT CLI"
echo "=================================================="
echo

# 1. Verificar instalación base
log "1. Verificando instalación base de Copilot CLI..."
if command_exists copilot; then
    COPILOT_VERSION=$(copilot --version 2>/dev/null || echo "unknown")
    success "Copilot CLI instalado: $COPILOT_VERSION"
    validation_results+=("copilot_cli_installed:true")
else
    error "Copilot CLI no encontrado en PATH"
    errors+=("copilot_cli_not_found")
fi

# 2. Verificar configuración MCP
log "2. Verificando configuración MCP..."
CONFIG_FILE="$HOME/.copilot/config.json"
if [ -f "$CONFIG_FILE" ]; then
    success "Archivo de configuración encontrado: $CONFIG_FILE"

    # Verificar que sea JSON válido
    if jq empty "$CONFIG_FILE" 2>/dev/null; then
        success "Configuración JSON válida"

        # Verificar servidores MCP configurados
        MCP_SERVERS=$(jq -r '.mcpServers | keys[]' "$CONFIG_FILE" 2>/dev/null || echo "")
        SERVER_COUNT=$(echo "$MCP_SERVERS" | wc -l)

        if [ "$SERVER_COUNT" -gt 5 ]; then
            success "MCP Servers configurados: $SERVER_COUNT servidores"
            validation_results+=("mcp_servers_configured:true")

            # Verificar servidores específicos
            for server in filesystem-odoo19 github memory metrics-collector security-scanner multi-project-context; do
                if echo "$MCP_SERVERS" | grep -q "^$server$"; then
                    success "Servidor MCP '$server' configurado"
                else
                    warning "Servidor MCP '$server' no encontrado en configuración"
                    warnings+=("missing_mcp_server_$server")
                fi
            done
        else
            warning "Pocos servidores MCP configurados: $SERVER_COUNT"
            warnings+=("insufficient_mcp_servers")
        fi
    else
        error "Configuración JSON inválida"
        errors+=("invalid_json_config")
    fi
else
    error "Archivo de configuración no encontrado: $CONFIG_FILE"
    errors+=("config_file_missing")
fi

# 3. Verificar agentes especializados
log "3. Verificando agentes especializados..."
AGENTS_DIR="$PROJECT_ROOT/.github/agents"
if [ -d "$AGENTS_DIR" ]; then
    AGENT_FILES=$(find "$AGENTS_DIR" -name "*.agent.md" | wc -l)
    if [ "$AGENT_FILES" -ge 8 ]; then
        success "Agentes especializados encontrados: $AGENT_FILES agentes"

        # Verificar agentes específicos
        for agent in dte-specialist payroll-compliance security-auditor odoo-architect test-automation chilean-compliance-coordinator release-deployment-manager incident-response-specialist; do
            if [ -f "$AGENTS_DIR/${agent}.agent.md" ]; then
                success "Agente '$agent' encontrado"
            else
                warning "Agente '$agent' no encontrado"
                warnings+=("missing_agent_$agent")
            fi
        done

        validation_results+=("specialized_agents_configured:true")
    else
        warning "Pocos agentes especializados: $AGENT_FILES (esperado: 8+)"
        warnings+=("insufficient_agents")
    fi
else
    error "Directorio de agentes no encontrado: $AGENTS_DIR"
    errors+=("agents_directory_missing")
fi

# 4. Verificar base de conocimiento
log "4. Verificando base de conocimiento..."
KB_DIR="$AGENTS_DIR/knowledge"
if [ -d "$KB_DIR" ]; then
    KB_FILES=$(find "$KB_DIR" -name "*.md" | wc -l)
    if [ "$KB_FILES" -ge 3 ]; then
        success "Archivos de conocimiento encontrados: $KB_FILES archivos"

        # Verificar archivos específicos
        for kb_file in sii_regulatory_context odoo19_patterns project_architecture; do
            if [ -f "$KB_DIR/${kb_file}.md" ]; then
                success "Archivo de conocimiento '$kb_file' encontrado"
            else
                warning "Archivo de conocimiento '$kb_file' no encontrado"
                warnings+=("missing_kb_file_$kb_file")
            fi
        done

        validation_results+=("knowledge_base_configured:true")
    else
        warning "Pocos archivos de conocimiento: $KB_FILES"
        warnings+=("insufficient_kb_files")
    fi
else
    error "Directorio de conocimiento no encontrado: $KB_DIR"
    errors+=("knowledge_base_missing")
fi

# 5. Verificar memoria persistente
log "5. Verificando memoria persistente..."
MEMORY_DB="$HOME/.copilot/odoo19-knowledge.db"
if [ -f "$MEMORY_DB" ]; then
    DB_SIZE=$(stat -f%z "$MEMORY_DB" 2>/dev/null || stat -c%s "$MEMORY_DB" 2>/dev/null || echo "0")
    DB_SIZE_MB=$((DB_SIZE / 1024 / 1024))

    if [ "$DB_SIZE_MB" -gt 0 ]; then
        success "Base de datos de memoria encontrada: ${DB_SIZE_MB}MB"
        validation_results+=("persistent_memory_configured:true")
    else
        warning "Base de datos de memoria muy pequeña: ${DB_SIZE_MB}MB"
        warnings+=("small_memory_db")
    fi
else
    warning "Base de datos de memoria no encontrada (se creará en primer uso)"
    warnings+=("memory_db_not_initialized")
fi

# 6. Verificar configuración de seguridad
log "6. Verificando configuración de seguridad..."
SECURITY_DB="$HOME/.copilot/security.db"
if [ -f "$SECURITY_DB" ]; then
    success "Base de datos de seguridad encontrada"
    validation_results+=("security_configured:true")
else
    warning "Base de datos de seguridad no encontrada (se creará en primer uso)"
    warnings+=("security_db_not_initialized")
fi

# Verificar políticas de seguridad
SECURITY_POLICIES="$PROJECT_ROOT/config/security-policies.json"
if [ -f "$SECURITY_POLICIES" ]; then
    success "Archivo de políticas de seguridad encontrado"
    validation_results+=("security_policies_configured:true")
else
    error "Archivo de políticas de seguridad no encontrado: $SECURITY_POLICIES"
    errors+=("security_policies_missing")
fi

# 7. Verificar integración CI/CD
log "7. Verificando integración CI/CD..."
WORKFLOWS_DIR="$PROJECT_ROOT/.github/workflows"
if [ -d "$WORKFLOWS_DIR" ]; then
    WORKFLOW_FILES=$(find "$WORKFLOWS_DIR" -name "*.yml" | wc -l)
    if [ "$WORKFLOW_FILES" -ge 3 ]; then
        success "Workflows de CI/CD encontrados: $WORKFLOW_FILES workflows"

        # Verificar workflows específicos
        for workflow in copilot-code-review copilot-testing-automation copilot-documentation-automation; do
            if [ -f "$WORKFLOWS_DIR/${workflow}.yml" ]; then
                success "Workflow '$workflow' encontrado"
            else
                warning "Workflow '$workflow' no encontrado"
                warnings+=("missing_workflow_$workflow")
            fi
        done

        validation_results+=("cicd_integration_configured:true")
    else
        warning "Pocos workflows CI/CD: $WORKFLOW_FILES"
        warnings+=("insufficient_workflows")
    fi
else
    error "Directorio de workflows no encontrado: $WORKFLOWS_DIR"
    errors+=("workflows_directory_missing")
fi

# 8. Verificar conectividad de red
log "8. Verificando conectividad de red..."
if check_network; then
    success "Conectividad de red disponible"
    validation_results+=("network_connectivity:true")
else
    warning "Sin conectividad de red (modo offline disponible)"
    warnings+=("no_network_connectivity")
fi

# 9. Verificar dependencias del sistema
log "9. Verificando dependencias del sistema..."
DEPENDENCIES_OK=true

# Verificar Python
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    success "Python disponible: $PYTHON_VERSION"
else
    error "Python 3 no encontrado"
    DEPENDENCIES_OK=false
fi

# Verificar Node.js
if command_exists node; then
    NODE_VERSION=$(node --version)
    success "Node.js disponible: $NODE_VERSION"
else
    error "Node.js no encontrado"
    DEPENDENCIES_OK=false
fi

# Verificar npm
if command_exists npm; then
    NPM_VERSION=$(npm --version)
    success "npm disponible: $NPM_VERSION"
else
    error "npm no encontrado"
    DEPENDENCIES_OK=false
fi

# Verificar Docker (opcional)
if command_exists docker; then
    DOCKER_VERSION=$(docker --version | cut -d',' -f1)
    success "Docker disponible: $DOCKER_VERSION"
else
    warning "Docker no encontrado (funcionalidad limitada)"
    warnings+=("docker_not_available")
fi

if [ "$DEPENDENCIES_OK" = true ]; then
    validation_results+=("system_dependencies_ok:true")
else
    errors+=("system_dependencies_missing")
fi

# 10. Verificar permisos de archivos
log "10. Verificando permisos de archivos..."
PERMISSIONS_OK=true

# Verificar permisos de configuración
if [ -f "$CONFIG_FILE" ]; then
    if [ -r "$CONFIG_FILE" ] && [ -w "$CONFIG_FILE" ]; then
        success "Permisos de configuración correctos"
    else
        error "Permisos insuficientes en archivo de configuración"
        PERMISSIONS_OK=false
    fi
fi

# Verificar permisos de scripts
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
if [ -d "$SCRIPTS_DIR" ]; then
    EXECUTABLE_SCRIPTS=$(find "$SCRIPTS_DIR" -name "*.sh" -executable | wc -l)
    if [ "$EXECUTABLE_SCRIPTS" -gt 0 ]; then
        success "Scripts ejecutables encontrados: $EXECUTABLE_SCRIPTS"
    else
        warning "Pocos scripts ejecutables encontrados"
        warnings+=("few_executable_scripts")
    fi
fi

if [ "$PERMISSIONS_OK" = true ]; then
    validation_results+=("file_permissions_ok:true")
else
    errors+=("file_permissions_issues")
fi

echo
echo "📊 RESUMEN DE VALIDACIÓN"
echo "========================"

# Mostrar resultados
VALIDATION_COUNT=${#validation_results[@]}
WARNING_COUNT=${#warnings[@]}
ERROR_COUNT=${#errors[@]}

echo "✅ Componentes validados correctamente: $VALIDATION_COUNT"
echo "⚠️  Advertencias: $WARNING_COUNT"
echo "❌ Errores: $ERROR_COUNT"
echo

# Mostrar componentes validados
if [ $VALIDATION_COUNT -gt 0 ]; then
    echo "✅ COMPONENTES VALIDADOS:"
    for result in "${validation_results[@]}"; do
        component=$(echo "$result" | cut -d: -f1)
        echo "   • $(echo "$component" | tr '_' ' ')"
    done
    echo
fi

# Mostrar advertencias
if [ $WARNING_COUNT -gt 0 ]; then
    echo "⚠️  ADVERTENCIAS:"
    for warning in "${warnings[@]}"; do
        echo "   • $(echo "$warning" | tr '_' ' ')"
    done
    echo
fi

# Mostrar errores
if [ $ERROR_COUNT -gt 0 ]; then
    echo "❌ ERRORES CRÍTICOS:"
    for error in "${errors[@]}"; do
        echo "   • $(echo "$error" | tr '_' ' ')"
    done
    echo
fi

# Calcular puntuación general
TOTAL_CHECKS=$((VALIDATION_COUNT + WARNING_COUNT + ERROR_COUNT))
SUCCESS_RATE=0
if [ $TOTAL_CHECKS -gt 0 ]; then
    SUCCESS_RATE=$((VALIDATION_COUNT * 100 / TOTAL_CHECKS))
fi

echo "🎯 PUNTUACIÓN GENERAL: ${SUCCESS_RATE}%"
echo

# Recomendaciones finales
if [ $ERROR_COUNT -eq 0 ] && [ $VALIDATION_COUNT -ge 8 ]; then
    success "CONFIGURACIÓN ENTERPRISE COMPLETA - Copilot CLI listo para uso avanzado"
    echo
    echo "🚀 Próximos pasos recomendados:"
    echo "   1. Probar una sesión interactiva: copilot"
    echo "   2. Usar agentes especializados: copilot /agent dte-specialist"
    echo "   3. Iniciar dashboard de métricas: ./scripts/start-metrics-dashboard.sh --background"
    echo "   4. Ejecutar validación de integración: ./scripts/validate_cli_integration.sh"
elif [ $ERROR_COUNT -gt 0 ]; then
    error "CONFIGURACIÓN INCOMPLETA - Corregir errores antes de continuar"
    echo
    echo "🔧 Para solucionar errores:"
    echo "   • Revisar instalación de Copilot CLI"
    echo "   • Verificar archivos de configuración"
    echo "   • Comprobar permisos de archivos"
    echo "   • Ejecutar: ./scripts/update_copilot_cli_2025.sh"
else
    warning "CONFIGURACIÓN BÁSICA COMPLETA - Mejoras recomendadas disponibles"
    echo
    echo "📈 Mejoras recomendadas:"
    echo "   • Configurar más agentes especializados"
    echo "   • Implementar integración CI/CD completa"
    echo "   • Configurar monitoreo avanzado"
fi

echo
echo "📝 Log completo guardado en: /tmp/copilot-validation-$(date +%Y%m%d-%H%M%S).log"

# Guardar log completo
LOG_FILE="/tmp/copilot-validation-$(date +%Y%m%d-%H%M%S).log"
{
    echo "=== COPILOT CLI ENTERPRISE VALIDATION LOG ==="
    echo "Date: $(date)"
    echo "Validations: $VALIDATION_COUNT"
    echo "Warnings: $WARNING_COUNT"
    echo "Errors: $ERROR_COUNT"
    echo "Success Rate: ${SUCCESS_RATE}%"
    echo
    echo "=== VALIDATION RESULTS ==="
    printf '%s\n' "${validation_results[@]}"
    echo
    echo "=== WARNINGS ==="
    printf '%s\n' "${warnings[@]}"
    echo
    echo "=== ERRORS ==="
    printf '%s\n' "${errors[@]}"
} > "$LOG_FILE"

echo "Log saved to: $LOG_FILE"
