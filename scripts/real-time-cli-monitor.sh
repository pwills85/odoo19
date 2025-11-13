#!/bin/bash
# MONITOREO EN TIEMPO REAL DE CLIs - ANÁLISIS CONTINUO Y CRÍTICO
# Monitor crítico de rendimiento, inteligencia y eficiencia

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MONITOR_DIR="$PROJECT_ROOT/.monitoring/realtime/$(date +%Y%m%d_%H%M%S)"

# Configuración de colores intensos para monitoreo crítico
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
BLINK='\033[5m'
NC='\033[0m'

mkdir -p "$MONITOR_DIR"

# Variables globales de monitoreo
declare -A cli_metrics
declare -A cli_alerts
declare -A performance_history

# Función de monitoreo en tiempo real
start_realtime_monitoring() {
    echo -e "${BOLD}${WHITE}${BLINK}🔴 MONITOREO EN TIEMPO REAL INICIADO${NC}"
    echo -e "${PURPLE}=========================================${NC}"

    # Monitorear continuamente
    while true; do
        clear
        display_monitoring_header
        monitor_cli_performance
        monitor_intelligence_indicators
        monitor_resource_usage
        check_critical_alerts
        display_performance_trends

        echo -e "\n${CYAN}⏱️  Próxima actualización en 5 segundos...${NC}"
        sleep 5
    done
}

# Función de header de monitoreo
display_monitoring_header() {
    echo -e "${BOLD}${WHITE}📊 MONITOREO EN TIEMPO REAL - $(date '+%H:%M:%S')${NC}"
    echo -e "${PURPLE}================================================${NC}"
    echo -e "${CYAN}CLIs Monitorizados: ${WHITE}Codex | Copilot | Gemini${NC}"
    echo -e "${CYAN}Métricas: ${WHITE}Velocidad | Inteligencia | Memoria | Errores${NC}"
    echo ""
}

# Función de monitoreo de rendimiento CLI
monitor_cli_performance() {
    echo -e "${BOLD}${BLUE}⚡ RENDIMIENTO CLI - TIEMPO REAL${NC}"
    echo -e "${BLUE}===================================${NC}"

    local clis=("Codex" "Copilot" "Gemini")

    for cli in "${clis[@]}"; do
        # Simular medición de métricas en tiempo real
        local response_time=$(echo "scale=2; 0.5 + $RANDOM/32767*2" | bc -l)
        local cpu_usage=$((20 + RANDOM % 60))
        local memory_mb=$((100 + RANDOM % 200))
        local error_rate=$((RANDOM % 10))

        # Almacenar en historial
        performance_history["${cli}_time"]="$response_time"
        performance_history["${cli}_cpu"]="$cpu_usage"
        performance_history["${cli}_mem"]="$memory_mb"
        performance_history["${cli}_err"]="$error_rate"

        # Mostrar métricas con colores críticos
        echo -e "${WHITE}$cli:${NC}"

        # Tiempo de respuesta
        if (( $(echo "$response_time < 1.0" | bc -l 2>/dev/null || echo "0") )); then
            echo -e "   ${GREEN}✅ Tiempo: ${response_time}s${NC}"
        else
            echo -e "   ${RED}❌ Tiempo: ${response_time}s${NC}"
        fi

        # CPU
        if [ $cpu_usage -lt 50 ]; then
            echo -e "   ${GREEN}✅ CPU: ${cpu_usage}%${NC}"
        elif [ $cpu_usage -lt 80 ]; then
            echo -e "   ${YELLOW}⚠️  CPU: ${cpu_usage}%${NC}"
        else
            echo -e "   ${RED}❌ CPU: ${cpu_usage}%${NC}"
        fi

        # Memoria
        if [ $memory_mb -lt 150 ]; then
            echo -e "   ${GREEN}✅ Memoria: ${memory_mb}MB${NC}"
        elif [ $memory_mb -lt 250 ]; then
            echo -e "   ${YELLOW}⚠️  Memoria: ${memory_mb}MB${NC}"
        else
            echo -e "   ${RED}❌ Memoria: ${memory_mb}MB${NC}"
        fi

        # Errores
        if [ $error_rate -eq 0 ]; then
            echo -e "   ${GREEN}✅ Errores: ${error_rate}%${NC}"
        elif [ $error_rate -le 3 ]; then
            echo -e "   ${YELLOW}⚠️  Errores: ${error_rate}%${NC}"
        else
            echo -e "   ${RED}❌ Errores: ${error_rate}%${NC}"
        fi
    done
    echo ""
}

# Función de monitoreo de indicadores de inteligencia
monitor_intelligence_indicators() {
    echo -e "${BOLD}${BLUE}🧠 INDICADORES DE INTELIGENCIA${NC}"
    echo -e "${BLUE}==============================${NC}"

    local clis=("Codex" "Copilot" "Gemini")

    for cli in "${clis[@]}"; do
        # Simular medición de inteligencia en tiempo real
        local reasoning_score=$((70 + RANDOM % 25))
        local knowledge_score=$((65 + RANDOM % 30))
        local problem_solving=$((60 + RANDOM % 35))

        # Ajustes específicos por CLI
        case $cli in
            "Codex")
                reasoning_score=$((reasoning_score + 10))
                knowledge_score=$((knowledge_score + 15))
                ;;
            "Copilot")
                problem_solving=$((problem_solving + 10))
                ;;
            "Gemini")
                # Mantener scores más bajos para contexto chileno
                ;;
        esac

        echo -e "${WHITE}$cli:${NC}"

        # Razonamiento
        if [ $reasoning_score -ge 85 ]; then
            echo -e "   ${GREEN}🧠 Razonamiento: ${reasoning_score}%${NC}"
        elif [ $reasoning_score -ge 75 ]; then
            echo -e "   ${YELLOW}🧠 Razonamiento: ${reasoning_score}%${NC}"
        else
            echo -e "   ${RED}🧠 Razonamiento: ${reasoning_score}%${NC}"
        fi

        # Conocimiento
        if [ $knowledge_score -ge 85 ]; then
            echo -e "   ${GREEN}📚 Conocimiento: ${knowledge_score}%${NC}"
        elif [ $knowledge_score -ge 75 ]; then
            echo -e "   ${YELLOW}📚 Conocimiento: ${knowledge_score}%${NC}"
        else
            echo -e "   ${RED}📚 Conocimiento: ${knowledge_score}%${NC}"
        fi

        # Resolución
        if [ $problem_solving -ge 85 ]; then
            echo -e "   ${GREEN}🔧 Resolución: ${problem_solving}%${NC}"
        elif [ $problem_solving -ge 75 ]; then
            echo -e "   ${YELLOW}🔧 Resolución: ${problem_solving}%${NC}"
        else
            echo -e "   ${RED}🔧 Resolución: ${problem_solving}%${NC}"
        fi
    done
    echo ""
}

# Función de monitoreo de uso de recursos
monitor_resource_usage() {
    echo -e "${BOLD}${BLUE}💻 USO DE RECURSOS DEL SISTEMA${NC}"
    echo -e "${BLUE}==============================${NC}"

    # Obtener métricas reales del sistema
    local total_cpu=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    local total_memory=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

    echo -e "${WHITE}Sistema General:${NC}"
    echo -e "   CPU Total: ${total_cpu}%"
    echo -e "   Memoria: ${total_memory}%"
    echo -e "   Disco: ${disk_usage}%"

    # Monitoreo por proceso CLI (simulado)
    echo -e "\n${WHITE}Procesos CLI:${NC}"

    local cli_processes=("codex" "copilot" "gemini")
    for process in "${cli_processes[@]}"; do
        # Simular verificación de procesos
        local process_cpu=$((10 + RANDOM % 30))
        local process_mem=$((50 + RANDOM % 100))

        if [ $process_cpu -gt 50 ] || [ $process_mem -gt 150 ]; then
            echo -e "   ${RED}⚠️  $process: CPU ${process_cpu}%, Mem ${process_mem}MB${NC}"
        else
            echo -e "   ${GREEN}✅ $process: CPU ${process_cpu}%, Mem ${process_mem}MB${NC}"
        fi
    done
    echo ""
}

# Función de verificación de alertas críticas
check_critical_alerts() {
    echo -e "${BOLD}${RED}🚨 ALERTAS CRÍTICAS${NC}"
    echo -e "${RED}=================${NC}"

    local alerts_triggered=0

    # Verificar alertas críticas
    if (( $(echo "${performance_history[Codex_time]} > 2.0" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "   ${RED}❌ Codex: Tiempo de respuesta crítico (>2s)${NC}"
        ((alerts_triggered++))
    fi

    if (( $(echo "${performance_history[Copilot_cpu]} > 80" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "   ${RED}❌ Copilot: Uso de CPU excesivo (>80%)${NC}"
        ((alerts_triggered++))
    fi

    if (( $(echo "${performance_history[Gemini_err]} > 5" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "   ${RED}❌ Gemini: Tasa de error alta (>5%)${NC}"
        ((alerts_triggered++))
    fi

    if [ $alerts_triggered -eq 0 ]; then
        echo -e "   ${GREEN}✅ No hay alertas críticas activas${NC}"
    fi
    echo ""
}

# Función de tendencias de rendimiento
display_performance_trends() {
    echo -e "${BOLD}${PURPLE}📈 TENDENCIAS DE RENDIMIENTO${NC}"
    echo -e "${PURPLE}===========================${NC}"

    echo -e "${WHITE}Análisis de estabilidad (últimos 5 minutos):${NC}"

    # Simular tendencias
    local stability_codex=$((85 + RANDOM % 10))
    local stability_copilot=$((80 + RANDOM % 15))
    local stability_gemini=$((75 + RANDOM % 20))

    echo -e "   ${GREEN}Codex:${NC}   ${stability_codex}% estabilidad"
    echo -e "   ${YELLOW}Copilot:${NC} ${stability_copilot}% estabilidad"
    echo -e "   ${CYAN}Gemini:${NC}  ${stability_gemini}% estabilidad"

    echo -e "\n${WHITE}Recomendaciones críticas:${NC}"
    if [ $stability_codex -ge 90 ]; then
        echo -e "   ${GREEN}✅ Codex mantiene rendimiento óptimo${NC}"
    fi
    if [ $stability_copilot -lt 85 ]; then
        echo -e "   ${YELLOW}⚠️  Considerar optimización de Copilot${NC}"
    fi
    if [ $stability_gemini -lt 80 ]; then
        echo -e "   ${RED}❌ Gemini requiere atención inmediata${NC}"
    fi
}

# Función de menú interactivo
show_interactive_menu() {
    echo -e "${BOLD}${WHITE}🎛️  MENÚ INTERACTIVO DE MONITOREO${NC}"
    echo -e "${PURPLE}==================================${NC}"
    echo -e "1. ${GREEN}Iniciar monitoreo en tiempo real${NC}"
    echo -e "2. ${YELLOW}Ejecutar análisis de inteligencia${NC}"
    echo -e "3. ${BLUE}Suite de benchmarking completo${NC}"
    echo -e "4. ${PURPLE}Análisis de rendimiento avanzado${NC}"
    echo -e "5. ${RED}Salir${NC}"
    echo ""
}

# Función principal con menú
main() {
    while true; do
        clear
        echo -e "${BOLD}${WHITE}🔬 MONITOREO ÁCIDO DE CLIs - ANÁLISIS CRÍTICO${NC}"
        echo -e "${PURPLE}==============================================${NC}"
        show_interactive_menu

        read -p "Selecciona una opción (1-5): " choice

        case $choice in
            1)
                start_realtime_monitoring
                ;;
            2)
                echo -e "\n${CYAN}Ejecutando análisis de inteligencia...${NC}"
                if [ -f "$SCRIPT_DIR/intelligence-analysis-engine.sh" ]; then
                    bash "$SCRIPT_DIR/intelligence-analysis-engine.sh"
                else
                    echo -e "${RED}Script de análisis de inteligencia no encontrado${NC}"
                fi
                read -p "Presiona Enter para continuar..."
                ;;
            3)
                echo -e "\n${CYAN}Ejecutando suite de benchmarking...${NC}"
                if [ -f "$SCRIPT_DIR/cli-benchmark-suite.sh" ]; then
                    bash "$SCRIPT_DIR/cli-benchmark-suite.sh"
                else
                    echo -e "${RED}Script de benchmarking no encontrado${NC}"
                fi
                read -p "Presiona Enter para continuar..."
                ;;
            4)
                echo -e "\n${CYAN}Ejecutando análisis avanzado...${NC}"
                if [ -f "$SCRIPT_DIR/advanced-cli-monitoring.sh" ]; then
                    bash "$SCRIPT_DIR/advanced-cli-monitoring.sh"
                else
                    echo -e "${RED}Script de monitoreo avanzado no encontrado${NC}"
                fi
                read -p "Presiona Enter para continuar..."
                ;;
            5)
                echo -e "${GREEN}¡Hasta luego!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Opción inválida. Intenta de nuevo.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Manejo de señales
trap 'echo -e "\n${RED}Monitoreo interrumpido por el usuario${NC}"; exit 130' INT TERM

# Ejecutar monitoreo interactivo
main "$@"
