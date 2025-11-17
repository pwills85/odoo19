#!/bin/bash
# Sistema de Routing Inteligente Multi-CLI
# Selecciona automáticamente la CLI óptima para cada tarea chilena

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuración de colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    local level=$1
    local message=$2
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message"
}

# Función de análisis de tarea
analyze_task() {
    local task_description="$1"

    # Análisis de palabras clave críticas chilenas
    local dte_keywords="DTE|XML|SII|CAF|FOLIO|factura|boleta|guia"
    local payroll_keywords="AFP|ISAPRE|nomina|gratificacion|imponible|sueldo|impuesto|utm|uf"
    local math_keywords="calculo|matematico|tributario|porcentaje|tramo|tope|rebaja"
    local dev_keywords="modelo|campo|vista|controlador|metodo|clase|odoo"

    # Análisis de criticidad
    local is_dte_critical=false
    local is_payroll_critical=false
    local is_math_complex=false
    local is_dev_standard=false

    # Convertir a lowercase para análisis
    local task_lower=$(echo "$task_description" | tr '[:upper:]' '[:lower:]')

    # Detectar tipo de tarea
    if echo "$task_lower" | grep -qi "$dte_keywords"; then
        is_dte_critical=true
    fi

    if echo "$task_lower" | grep -qi "$payroll_keywords"; then
        is_payroll_critical=true
    fi

    if echo "$task_lower" | grep -qi "$math_keywords"; then
        is_math_complex=true
    fi

    if echo "$task_lower" | grep -qi "$dev_keywords"; then
        is_dev_standard=true
    fi

    # Determinar prioridad
    if [ "$is_dte_critical" = true ] || [ "$is_payroll_critical" = true ]; then
        echo "CRITICAL"
    elif [ "$is_math_complex" = true ]; then
        echo "HIGH"
    elif [ "$is_dev_standard" = true ]; then
        echo "MEDIUM"
    else
        echo "STANDARD"
    fi
}

# Función de selección de CLI
select_optimal_cli() {
    local priority="$1"
    local task_description="$2"

    case $priority in
        "CRITICAL")
            # Tareas críticas van a Codex CLI
            echo "codex-cli"
            echo "Razon: Tarea regulatoria crítica chilena requiere máxima precisión (95%+)"
            ;;
        "HIGH")
            # Cálculos matemáticos complejos van a Gemini CLI
            echo "gemini-cli"
            echo "Razon: Precisión matemática superior (98%+) para cálculos tributarios"
            ;;
        "MEDIUM")
            # Desarrollo estándar va a Copilot CLI
            echo "copilot-cli"
            echo "Razon: Velocidad óptima (100%) para desarrollo diario"
            ;;
        "STANDARD")
            # Por defecto Copilot CLI
            echo "copilot-cli"
            echo "Razon: Balance general de velocidad y precisión"
            ;;
        *)
            echo "copilot-cli"
            echo "Razon: Fallback seguro"
            ;;
    esac
}

# Función de ejecución de tarea
execute_task() {
    local cli="$1"
    local task_description="$2"

    echo -e "${BLUE}🎯 EJECUTANDO TAREA CON $cli${NC}"
    echo -e "${CYAN}Tarea: $task_description${NC}"
    echo

    case $cli in
        "codex-cli")
            echo -e "${PURPLE}📚 Usando Codex CLI (Enterprise Regulatorio)${NC}"
            echo "Perfil recomendado: codex-regulatorio-2025"
            echo "Configuración: model=o3, context=200K, reasoning=high"
            echo
            echo "Comando sugerido:"
            echo "codex --profile codex-regulatorio-2025 \"$task_description\""
            ;;

        "gemini-cli")
            echo -e "${PURPLE}🔢 Usando Gemini CLI (Matemático Avanzado)${NC}"
            echo "Perfil recomendado: calculos-tributarios-chile"
            echo "Configuración: model=gemini-1.5-pro, context=1M, precision=high"
            echo
            echo "Comando sugerido:"
            echo "gemini --profile calculos-tributarios-chile \"$task_description\""
            ;;

        "copilot-cli")
            echo -e "${PURPLE}⚡ Usando Copilot CLI (Desarrollo Diario)${NC}"
            echo "Perfil recomendado: odoo-dev"
            echo "Configuración: model=claude-3.5-sonnet, context=128K, speed=high"
            echo
            echo "Comando sugerido:"
            echo "copilot --profile odoo-dev \"$task_description\""
            ;;
    esac
}

# Función de validación de CLI disponible
validate_cli_availability() {
    local cli="$1"

    case $cli in
        "codex-cli")
            if [ -f "$HOME/.codex/config.toml" ] && grep -q "model.*o3" "$HOME/.codex/config.toml" 2>/dev/null; then
                echo "AVAILABLE"
            else
                echo "NOT_CONFIGURED"
            fi
            ;;
        "copilot-cli")
            if [ -f "$HOME/.codex/config.toml" ] && grep -q "claude-3-5-sonnet" "$HOME/.codex/config.toml" 2>/dev/null; then
                echo "AVAILABLE"
            else
                echo "NOT_CONFIGURED"
            fi
            ;;
        "gemini-cli")
            if [ -f "$HOME/.config/gemini-cli/config.yaml" ] && grep -q "gemini-1.5-pro" "$HOME/.config/gemini-cli/config.yaml" 2>/dev/null; then
                echo "AVAILABLE"
            else
                echo "NOT_CONFIGURED"
            fi
            ;;
        *)
            echo "UNKNOWN"
            ;;
    esac
}

# Función de métricas de performance
show_performance_metrics() {
    echo -e "${BLUE}📊 MÉTRICAS DE PERFORMANCE ESPERADAS${NC}"
    echo
    echo -e "${CYAN}Codex CLI (Regulatorio):${NC}"
    echo "  • Precisión: 95%+ (DTE/CAF)"
    echo "  • Velocidad: 2-3s (razonamiento profundo)"
    echo "  • Costo: $$$ (tokens reasoning)"
    echo
    echo -e "${CYAN}Copilot CLI (Desarrollo):${NC}"
    echo "  • Precisión: 98%+ (código estándar)"
    echo "  • Velocidad: 800ms (más rápido)"
    echo "  • Costo: $$ (balanceado)"
    echo
    echo -e "${CYAN}Gemini CLI (Matemático):${NC}"
    echo "  • Precisión: 98%+ (cálculos tributarios)"
    echo "  • Velocidad: ~600ms (ultra rápido)"
    echo "  • Costo: $ (más económico)"
    echo
}

# Función principal
main() {
    echo "🎯 SISTEMA DE ROUTING INTELIGENTE MULTI-CLI"
    echo "============================================"
    echo
    echo "Análisis automático de tareas chilenas para selección óptima de CLI"
    echo

    if [ $# -eq 0 ]; then
        echo "Uso: $0 \"descripción de la tarea\""
        echo
        echo "Ejemplos:"
        echo "  $0 \"Generar XML DTE compliant con SII\""
        echo "  $0 \"Calcular impuesto único 7 tramos\""
        echo "  $0 \"Crear modelo Odoo con campos chilenos\""
        echo
        show_performance_metrics
        exit 1
    fi

    local task_description="$1"

    echo -e "${YELLOW}🔍 ANALIZANDO TAREA...${NC}"
    echo "Tarea: $task_description"
    echo

    # Analizar tarea
    local priority=$(analyze_task "$task_description")

    echo -e "${BLUE}📋 ANÁLISIS COMPLETADO:${NC}"
    echo "Prioridad detectada: $priority"
    echo

    # Seleccionar CLI óptima
    local cli_selection=$(select_optimal_cli "$priority" "$task_description")
    local cli_name=$(echo "$cli_selection" | head -1)
    local reason=$(echo "$cli_selection" | tail -1)

    echo -e "${GREEN}🎯 CLI ÓPTIMA SELECCIONADA:${NC}"
    echo "CLI: $cli_name"
    echo "Razonamiento: $reason"
    echo

    # Validar disponibilidad
    local availability=$(validate_cli_availability "$cli_name")

    if [ "$availability" = "AVAILABLE" ]; then
        echo -e "${GREEN}✅ CLI configurado y disponible${NC}"
        echo
        execute_task "$cli_name" "$task_description"
    else
        echo -e "${RED}⚠️  CLI no configurado completamente${NC}"
        echo "Estado: $availability"
        echo
        echo -e "${YELLOW}💡 RECOMENDACIONES:${NC}"
        case $cli_name in
            "codex-cli")
                echo "• Ejecutar: bash scripts/enterprise-setup-all.sh"
                echo "• Configurar perfil: codex-regulatorio-2025"
                ;;
            "copilot-cli")
                echo "• Verificar configuración en ~/.codex/config.toml"
                echo "• Activar perfiles: odoo-dev, dte-specialist, payroll-compliance"
                ;;
            "gemini-cli")
                echo "• Instalar Gemini CLI"
                echo "• Configurar perfil: calculos-tributarios-chile"
                ;;
        esac
    fi

    echo
    echo -e "${PURPLE}🚀 RECUERDA: Esta selección es automática basada en análisis de precisión chilena${NC}"
    echo -e "${PURPLE}💡 Para tareas híbridas, considera ejecutar múltiples CLIs${NC}"

    log "ROUTING" "Tarea '$task_description' -> $cli_name (prioridad: $priority)"
}

# Manejo de argumentos especiales
case "${1:-}" in
    "--help"|"-h")
        echo "Sistema de Routing Inteligente Multi-CLI"
        echo
        echo "Análisis automático de tareas chilenas para selección óptima de CLI"
        echo
        echo "Uso:"
        echo "  $0 \"descripción de tarea\""
        echo "  $0 --metrics    # Ver métricas de performance"
        echo "  $0 --status     # Ver estado de CLIs"
        echo "  $0 --help       # Esta ayuda"
        echo
        echo "Ejemplos:"
        echo "  $0 \"Generar XML DTE SII compliant\""
        echo "  $0 \"Calcular nómina AFP con topes\""
        echo "  $0 \"Crear modelo Odoo chileno\""
        ;;
    "--metrics")
        show_performance_metrics
        ;;
    "--status")
        echo "Estado de CLIs disponibles:"
        echo
        echo "Codex CLI:"
        local codex_status=$(validate_cli_availability "codex-cli")
        if [ "$codex_status" = "AVAILABLE" ]; then
            echo -e "  ${GREEN}✅ Configurado${NC}"
        else
            echo -e "  ${RED}❌ No configurado${NC}"
        fi
        echo
        echo "Copilot CLI:"
        local copilot_status=$(validate_cli_availability "copilot-cli")
        if [ "$copilot_status" = "AVAILABLE" ]; then
            echo -e "  ${GREEN}✅ Configurado${NC}"
        else
            echo -e "  ${RED}❌ No configurado${NC}"
        fi
        echo
        echo "Gemini CLI:"
        local gemini_status=$(validate_cli_availability "gemini-cli")
        if [ "$gemini_status" = "AVAILABLE" ]; then
            echo -e "  ${GREEN}✅ Configurado${NC}"
        else
            echo -e "  ${RED}❌ No configurado${NC}"
        fi
        ;;
    *)
        main "$@"
        ;;
esac
