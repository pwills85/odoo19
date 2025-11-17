#!/bin/bash
# LANZADOR DE ANÁLISIS DE CLIs - MENÚ PRINCIPAL DE MONITOREO
# Punto de entrada unificado para todos los análisis de CLIs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuración de colores para menú
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Función de mostrar header
show_header() {
    clear
    echo -e "${BOLD}${WHITE}🎯 SISTEMA DE ANÁLISIS CRÍTICO DE CLIs${NC}"
    echo -e "${PURPLE}======================================${NC}"
    echo -e "${CYAN}Monitoreo ácido de agentes, modelos y CLIs${NC}"
    echo -e "${CYAN}Análisis completo: inteligencia, velocidad, precisión, contexto, memoria${NC}"
    echo ""
}

# Función de mostrar menú principal
show_main_menu() {
    echo -e "${BOLD}${BLUE}📋 MENÚ PRINCIPAL DE ANÁLISIS${NC}"
    echo -e "${BLUE}==============================${NC}"
    echo ""
    echo -e "${GREEN}1. ${WHITE}⚡ ANÁLISIS RÁPIDO${NC} (70s) - Evaluación expeditiva"
    echo -e "   ${CYAN}• Velocidad, precisión chilena, inteligencia básica${NC}"
    echo -e "   ${CYAN}• Veredicto inmediato con recomendaciones críticas${NC}"
    echo ""
    echo -e "${YELLOW}2. ${WHITE}🔬 MONITOREO AVANZADO${NC} (15min) - Análisis profundo"
    echo -e "   ${CYAN}• Evaluación completa de todas las métricas${NC}"
    echo -e "   ${CYAN}• Análisis comparativo detallado${NC}"
    echo ""
    echo -e "${BLUE}3. ${WHITE}🧠 ANÁLISIS DE INTELIGENCIA${NC} (10min) - Evaluación cognitiva"
    echo -e "   ${CYAN}• Razonamiento lógico, conocimiento especializado${NC}"
    echo -e "   ${CYAN}• Capacidad de resolución de problemas${NC}"
    echo ""
    echo -e "${PURPLE}4. ${WHITE}🏁 SUITE DE BENCHMARKING${NC} (12min) - Pruebas reales"
    echo -e "   ${CYAN}• Benchmarking con métricas cuantitativas${NC}"
    echo -e "   ${CYAN}• Comparativas por categorías específicas${NC}"
    echo ""
    echo -e "${RED}5. ${WHITE}📊 MONITOREO EN TIEMPO REAL${NC} (Interactivo) - Monitor continuo"
    echo -e "   ${CYAN}• Dashboard en tiempo real con alertas${NC}"
    echo -e "   ${CYAN}• Monitoreo continuo de rendimiento${NC}"
    echo ""
    echo -e "${BOLD}6. ${WHITE}🎼 ANÁLISIS MAESTRO COMPLETO${NC} (45min) - Orquestación total"
    echo -e "   ${CYAN}• Todos los análisis integrados${NC}"
    echo -e "   ${CYAN}• Reporte ejecutivo final completo${NC}"
    echo ""
    echo -e "${WHITE}0. ${RED}Salir${NC}"
    echo ""
}

# Función de mostrar información de análisis
show_analysis_info() {
    local choice=$1

    case $choice in
        1)
            echo -e "${BOLD}${GREEN}⚡ ANÁLISIS RÁPIDO${NC}"
            echo -e "${GREEN}=================${NC}"
            echo -e "⏱️  ${WHITE}Duración: 70 segundos${NC}"
            echo -e "🎯 ${WHITE}Objetivo: Evaluación expeditiva de variables críticas${NC}"
            echo -e "📊 ${WHITE}Métricas: Velocidad, precisión chilena, inteligencia básica${NC}"
            echo -e "💡 ${WHITE}Resultado: Veredicto inmediato con recomendaciones${NC}"
            ;;
        2)
            echo -e "${BOLD}${YELLOW}🔬 MONITOREO AVANZADO${NC}"
            echo -e "${YELLOW}=====================${NC}"
            echo -e "⏱️  ${WHITE}Duración: 15 minutos${NC}"
            echo -e "🎯 ${WHITE}Objetivo: Análisis profundo de todas las métricas${NC}"
            echo -e "📊 ${WHITE}Métricas: Rendimiento, inteligencia, recursos, alertas${NC}"
            echo -e "💡 ${WHITE}Resultado: Análisis comparativo detallado${NC}"
            ;;
        3)
            echo -e "${BOLD}${BLUE}🧠 ANÁLISIS DE INTELIGENCIA${NC}"
            echo -e "${BLUE}===========================${NC}"
            echo -e "⏱️  ${WHITE}Duración: 10 minutos${NC}"
            echo -e "🎯 ${WHITE}Objetivo: Evaluación cognitiva profunda${NC}"
            echo -e "📊 ${WHITE}Métricas: Razonamiento, conocimiento, resolución${NC}"
            echo -e "💡 ${WHITE}Resultado: Ranking de capacidades cognitivas${NC}"
            ;;
        4)
            echo -e "${BOLD}${PURPLE}🏁 SUITE DE BENCHMARKING${NC}"
            echo -e "${PURPLE}=========================${NC}"
            echo -e "⏱️  ${WHITE}Duración: 12 minutos${NC}"
            echo -e "🎯 ${WHITE}Objetivo: Pruebas reales cuantitativas${NC}"
            echo -e "📊 ${WHITE}Métricas: Benchmarks específicos por categoría${NC}"
            echo -e "💡 ${WHITE}Resultado: Métricas cuantitativas comparativas${NC}"
            ;;
        5)
            echo -e "${BOLD}${RED}📊 MONITOREO EN TIEMPO REAL${NC}"
            echo -e "${RED}===========================${NC}"
            echo -e "⏱️  ${WHITE}Duración: Interactiva (hasta interrupción)${NC}"
            echo -e "🎯 ${WHITE}Objetivo: Monitor continuo con alertas${NC}"
            echo -e "📊 ${WHITE}Métricas: Dashboard en tiempo real${NC}"
            echo -e "💡 ${WHITE}Resultado: Monitoreo continuo con alertas críticas${NC}"
            ;;
        6)
            echo -e "${BOLD}${BOLD}🎼 ANÁLISIS MAESTRO COMPLETO${NC}"
            echo -e "${BOLD}============================${NC}"
            echo -e "⏱️  ${WHITE}Duración: 45 minutos${NC}"
            echo -e "🎯 ${WHITE}Objetivo: Orquestación completa de todos los análisis${NC}"
            echo -e "📊 ${WHITE}Métricas: Todas las variables críticas integradas${NC}"
            echo -e "💡 ${WHITE}Resultado: Reporte ejecutivo final completo${NC}"
            ;;
    esac
    echo ""
}

# Función de ejecutar análisis seleccionado
execute_analysis() {
    local choice=$1

    case $choice in
        1)
            echo -e "${GREEN}🚀 Ejecutando análisis rápido...${NC}"
            sleep 1
            "$SCRIPT_DIR/quick-cli-analysis.sh"
            ;;
        2)
            echo -e "${YELLOW}🚀 Ejecutando monitoreo avanzado...${NC}"
            sleep 1
            "$SCRIPT_DIR/advanced-cli-monitoring.sh"
            ;;
        3)
            echo -e "${BLUE}🚀 Ejecutando análisis de inteligencia...${NC}"
            sleep 1
            "$SCRIPT_DIR/intelligence-analysis-engine.sh"
            ;;
        4)
            echo -e "${PURPLE}🚀 Ejecutando suite de benchmarking...${NC}"
            sleep 1
            "$SCRIPT_DIR/cli-benchmark-suite.sh"
            ;;
        5)
            echo -e "${RED}🚀 Iniciando monitoreo en tiempo real...${NC}"
            sleep 1
            "$SCRIPT_DIR/real-time-cli-monitor.sh"
            ;;
        6)
            echo -e "${BOLD}🚀 Ejecutando análisis maestro completo...${NC}"
            sleep 1
            "$SCRIPT_DIR/cli-master-analysis-orchestrator.sh"
            ;;
    esac
}

# Función principal del lanzador
main() {
    while true; do
        show_header
        show_main_menu

        read -p "Selecciona una opción (0-6): " choice

        case $choice in
            0)
                echo -e "\n${GREEN}¡Hasta luego! 👋${NC}"
                echo -e "${CYAN}Recuerda ejecutar análisis periódicos para mantener la calidad.${NC}"
                exit 0
                ;;
            1|2|3|4|5|6)
                show_header
                show_analysis_info "$choice"
                echo -e "${YELLOW}¿Deseas continuar con este análisis?${NC}"
                read -p "(s/n): " confirm

                if [[ $confirm =~ ^[Ss]$ ]]; then
                    execute_analysis "$choice"
                    echo -e "\n${GREEN}✅ Análisis completado.${NC}"
                    read -p "Presiona Enter para continuar..."
                else
                    echo -e "${YELLOW}Análisis cancelado.${NC}"
                    sleep 2
                fi
                ;;
            *)
                echo -e "${RED}❌ Opción inválida. Intenta de nuevo.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Ejecutar lanzador
main "$@"
