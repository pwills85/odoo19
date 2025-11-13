#!/bin/bash
# Configuración Completa Enterprise - Ejecución Automática
# Ejecuta todo el proceso de setup enterprise de una vez

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

show_progress() {
    local current=$1
    local total=$2
    local description=$3
    local percentage=$((current * 100 / total))

    echo -e "${BLUE}[$current/$total]${NC} $description"
    echo -e "${CYAN}Progreso: $percentage%${NC}"
    echo
}

# Función de verificación previa
pre_flight_check() {
    log "INFO" "Ejecutando verificación previa..."

    local checks_passed=0
    local checks_total=4

    # Verificar permisos de escritura en workspace
    if [ -w "$PROJECT_ROOT" ]; then
        echo -e "  ${GREEN}✅ Permisos de escritura en workspace${NC}"
        ((checks_passed++))
    else
        echo -e "  ${RED}❌ Sin permisos de escritura en workspace${NC}"
    fi

    # Verificar espacio en disco (2GB mínimo para enterprise)
    local available_space=$(df "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
    local min_space=$((1024*1024*2))  # 2GB en KB (reducido para entorno sandbox)

    if [ "$available_space" -gt "$min_space" ]; then
        echo -e "  ${GREEN}✅ Espacio en disco suficiente${NC} ($(df -h "$PROJECT_ROOT" | tail -1 | awk '{print $4}') disponible)"
        ((checks_passed++))
    else
        echo -e "  ${RED}❌ Espacio insuficiente (necesario: 2GB)${NC}"
    fi

    # Verificar conectividad de red
    if ping -c 1 8.8.8.8 &> /dev/null; then
        echo -e "  ${GREEN}✅ Conectividad de red${NC}"
        ((checks_passed++))
    else
        echo -e "  ${YELLOW}⚠️  Sin conectividad de red${NC}"
    fi

    # Verificar que estamos en el directorio correcto
    if [ -f "ENTERPRISE_UPGRADE_PLAN.md" ]; then
        echo -e "  ${GREEN}✅ Directorio del proyecto correcto${NC}"
        ((checks_passed++))
    else
        echo -e "  ${RED}❌ No estás en el directorio correcto${NC}"
        exit 1
    fi

    local percentage=$((checks_passed * 100 / checks_total))
    echo -e "\nVerificación previa: $checks_passed/$checks_total ($percentage%)"

    if [ $percentage -lt 75 ]; then
        echo -e "${RED}❌ Verificación previa fallida. Corrige los problemas antes de continuar.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Verificación previa exitosa${NC}"
    echo
}

# Función principal
main() {
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 🚀 SETUP COMPLETO SISTEMA ENTERPRISE - EJECUCIÓN AUTOMÁTICA             ║"
    echo "║                                                                            ║"
    echo "║ Este script ejecutará todo el proceso de configuración enterprise:        ║"
    echo "║ 1. Instalación de dependencias                                             ║"
    echo "║ 2. Inicialización del sistema                                              ║"
    echo "║ 3. Indexación de conocimiento                                              ║"
    echo "║ 4. Entrenamiento de modelos                                                ║"
    echo "║ 5. Validación final                                                        ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo
    echo -e "${YELLOW}⚠️  ADVERTENCIA:${NC}"
    echo "Este proceso tomará aproximadamente 30 minutos."
    echo "Asegúrate de tener conexión a internet estable."
    echo
    read -p "¿Deseas continuar? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Operación cancelada."
        exit 0
    fi

    local start_time=$(date +%s)

    # Verificación previa
    show_progress 0 5 "Verificación previa del sistema"
    pre_flight_check

    # Paso 1: Instalar dependencias
    show_progress 1 5 "Instalando dependencias enterprise"
    log "ENTERPRISE" "Paso 1: Instalando dependencias..."
    if bash "$SCRIPT_DIR/install-enterprise-dependencies.sh"; then
        log "SUCCESS" "Dependencias instaladas correctamente"
    else
        log "ERROR" "Fallo en instalación de dependencias"
        exit 1
    fi

    # Paso 2: Inicializar sistema
    show_progress 2 5 "Inicializando sistema enterprise"
    log "ENTERPRISE" "Paso 2: Inicializando sistema..."
    if bash "$SCRIPT_DIR/enterprise-orchestration-system.sh"; then
        log "SUCCESS" "Sistema inicializado correctamente"
    else
        log "ERROR" "Fallo en inicialización del sistema"
        exit 1
    fi

    # Paso 3: Indexar conocimiento
    show_progress 3 5 "Indexando base de conocimiento"
    log "ENTERPRISE" "Paso 3: Indexando conocimiento..."
    if bash "$SCRIPT_DIR/index-knowledge-base.sh"; then
        log "SUCCESS" "Base de conocimiento indexada correctamente"
    else
        log "ERROR" "Fallo en indexación de conocimiento"
        exit 1
    fi

    # Paso 4: Entrenar modelos
    show_progress 4 5 "Entrenando modelos de contexto"
    log "ENTERPRISE" "Paso 4: Entrenando modelos..."
    if bash "$SCRIPT_DIR/train-context-models.sh"; then
        log "SUCCESS" "Modelos entrenados correctamente"
    else
        log "ERROR" "Fallo en entrenamiento de modelos"
        exit 1
    fi

    # Paso 5: Validar sistema
    show_progress 5 5 "Validación final del sistema"
    log "ENTERPRISE" "Paso 5: Validando sistema completo..."
    if bash "$SCRIPT_DIR/validate-enterprise-system.sh"; then
        log "SUCCESS" "Sistema validado correctamente"
    else
        log "ERROR" "Fallo en validación del sistema"
        exit 1
    fi

    # Calcular tiempo total
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    # Resultado final
    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 🎉 SETUP ENTERPRISE COMPLETADO EXITOSAMENTE                               ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo
    echo -e "${GREEN}✅ Todos los componentes instalados y configurados${NC}"
    echo -e "${CYAN}⏱️  Tiempo total: ${minutes}m ${seconds}s${NC}"
    echo
    echo -e "${PURPLE}🚀 SISTEMA ENTERPRISE LISTO PARA USO${NC}"
    echo
    echo "Comandos disponibles:"
    echo "• codex --profile odoo-dev 'tarea'"
    echo "• codex --profile dte-compliance 'validación'"
    echo "• bash scripts/validate-enterprise-system.sh status"
    echo
    echo "Documentación:"
    echo "• ENTERPRISE_UPGRADE_PLAN.md"
    echo "• .codex/enterprise/ (configuraciones)"
    echo
    echo -e "${CYAN}¡Bienvenido al futuro del desarrollo enterprise! 🚀${NC}"

    log "ENTERPRISE" "Setup completo finalizado exitosamente en ${minutes}m ${seconds}s"
}

# Manejo de argumentos
case "${1:-}" in
    "--dry-run")
        echo "Ejecución en seco - mostrando pasos:"
        echo "1. Verificación previa"
        echo "2. Instalación de dependencias"
        echo "3. Inicialización del sistema"
        echo "4. Indexación de conocimiento"
        echo "5. Entrenamiento de modelos"
        echo "6. Validación final"
        echo
        echo "Para ejecutar realmente: bash scripts/enterprise-setup-all.sh"
        ;;
    "--help"|"-h")
        echo "Setup Completo Sistema Enterprise"
        echo
        echo "Uso:"
        echo "  bash scripts/enterprise-setup-all.sh        # Ejecutar setup completo"
        echo "  bash scripts/enterprise-setup-all.sh --dry-run  # Ver pasos sin ejecutar"
        echo "  bash scripts/enterprise-setup-all.sh --help     # Esta ayuda"
        ;;
    *)
        main "$@"
        ;;
esac
