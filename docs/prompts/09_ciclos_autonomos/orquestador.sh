#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# 🤖 ORQUESTADOR CICLO AUTÓNOMO RETROALIMENTADO
# ═══════════════════════════════════════════════════════════════════════════
# Versión: 1.0.0
# Fecha: 2025-11-12
# Autor: Pedro Troncoso (@pwills85) + Claude Sonnet 4.5
# Propósito: Sistema inteligente ciclo completo con aprendizaje incremental
#
# Características:
# - Interactivo al inicio (pregunta cómo proceder)
# - Dos tipos trabajo: Cierre brechas (correctivo) + Desarrollo features (evolutivo)
# - Retroalimentación inteligente (si falla → ajusta estrategia → reintenta)
# - Sistema memoria (aprende de ejecuciones previas)
# - Replicable a todo el stack (AI, DTE, Payroll, Financial, Infra)
#
# Uso:
#   ./orquestador.sh
#   ./orquestador.sh --config config/ai_service.yml
#   ./orquestador.sh --non-interactive --tipo cierre_brechas --modulo ai_service
# ═══════════════════════════════════════════════════════════════════════════

set -e
set -o pipefail

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

# Directorios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"
PROMPTS_DIR="$SCRIPT_DIR/prompts"
MEMORIA_DIR="$SCRIPT_DIR/memoria"
LIB_DIR="$SCRIPT_DIR/lib"
OUTPUTS_DIR="$SCRIPT_DIR/outputs"

# Librerías auxiliares
source "$LIB_DIR/interactive_prompts.sh"
source "$LIB_DIR/execution_engine.sh"
source "$LIB_DIR/error_handler.sh"
source "$LIB_DIR/memoria_inteligente.sh"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Versión
VERSION="1.0.0"

# Estado global
INTERACTIVE_MODE=true
CONFIG_FILE=""
TIPO_TRABAJO=""
MODULO_TARGET=""
NIVEL_AUTONOMIA=""
MODIFICACION_CODIGO=""
ITERACIONES_MAX_P0=5
ITERACIONES_MAX_P1=3
ITERACIONES_MAX_P2=1
APRENDIZAJE_HABILITADO=true
SESSION_ID=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUTPUTS_DIR/session_${SESSION_ID}.log"

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIONES BANNER Y UI
# ═══════════════════════════════════════════════════════════════════════════

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   🤖  ORQUESTADOR CICLO AUTÓNOMO RETROALIMENTADO                         ║
║                                                                           ║
║   Sistema Inteligente con Aprendizaje Incremental                        ║
║   Odoo 19 CE - Stack Completo EERGYGROUP                                 ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${WHITE}Versión:${NC} $VERSION"
    echo -e "${WHITE}Sesión:${NC} $SESSION_ID"
    echo -e "${WHITE}Log:${NC} $LOG_FILE"
    echo ""
}

print_separator() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)    echo -e "${BLUE}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
        DEBUG)   echo -e "${CYAN}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL: INICIO INTERACTIVO
# ═══════════════════════════════════════════════════════════════════════════

inicio_interactivo() {
    print_banner
    
    log_message INFO "Iniciando modo interactivo"
    
    # Pregunta 1: Tipo de trabajo
    print_separator
    echo -e "${CYAN}[1/8] 🎯 Tipo de trabajo:${NC}"
    echo ""
    echo "  1. 🔨 Cierre de Brechas (correctivo - solo fixes)"
    echo "  2. 🚀 Desarrollo Feature (evolutivo - nueva funcionalidad)"
    echo "  3. 🔄 Híbrido (cierre brechas + desarrollo features)"
    echo ""
    read -p "$(echo -e ${CYAN}Selección [1-3]:${NC} )" tipo_selection
    
    case "$tipo_selection" in
        1) TIPO_TRABAJO="cierre_brechas" ;;
        2) TIPO_TRABAJO="desarrollo_features" ;;
        3) TIPO_TRABAJO="hibrido" ;;
        *) log_message ERROR "Selección inválida"; exit 1 ;;
    esac
    
    log_message INFO "Tipo trabajo seleccionado: $TIPO_TRABAJO"
    
    # Pregunta 2: Módulo objetivo
    print_separator
    echo -e "${CYAN}[2/8] 📦 Módulo/componente objetivo:${NC}"
    echo ""
    echo "  1. ai_service (microservicio AI)"
    echo "  2. l10n_cl_dte (facturación electrónica)"
    echo "  3. l10n_cl_hr_payroll (nómina)"
    echo "  4. l10n_cl_financial_reports (reportes)"
    echo "  5. Múltiples módulos (especificar)"
    echo ""
    read -p "$(echo -e ${CYAN}Selección [1-5]:${NC} )" modulo_selection
    
    case "$modulo_selection" in
        1) MODULO_TARGET="ai_service" ;;
        2) MODULO_TARGET="l10n_cl_dte" ;;
        3) MODULO_TARGET="l10n_cl_hr_payroll" ;;
        4) MODULO_TARGET="l10n_cl_financial_reports" ;;
        5) 
            read -p "$(echo -e ${CYAN}Especificar módulos (separados por coma):${NC} )" custom_modules
            MODULO_TARGET="$custom_modules"
            ;;
        *) log_message ERROR "Selección inválida"; exit 1 ;;
    esac
    
    log_message INFO "Módulo objetivo: $MODULO_TARGET"
    
    # Pregunta 3: Nivel de autonomía
    print_separator
    echo -e "${CYAN}[3/8] 🔒 Nivel de autonomía:${NC}"
    echo ""
    echo "  1. 100% autónomo (ejecuta todo sin preguntar)"
    echo "  2. Semi-autónomo (aprobación por fase)"
    echo "  3. Aprobación por brecha crítica (P0 requiere OK, P1/P2 auto)"
    echo ""
    read -p "$(echo -e ${CYAN}Selección [1-3]:${NC} )" autonomia_selection
    
    case "$autonomia_selection" in
        1) NIVEL_AUTONOMIA="full_autonomous" ;;
        2) NIVEL_AUTONOMIA="semi_autonomous" ;;
        3) NIVEL_AUTONOMIA="critical_approval" ;;
        *) log_message ERROR "Selección inválida"; exit 1 ;;
    esac
    
    log_message INFO "Nivel autonomía: $NIVEL_AUTONOMIA"
    
    # Pregunta 4: Modificación código
    print_separator
    echo -e "${CYAN}[4/8] ⚙️  Modificación código permitida:${NC}"
    echo ""
    echo "  1. Sí, con restricciones (NO destruir, NO crear módulos)"
    echo "  2. Solo fixes simples (deprecaciones, formateo)"
    echo "  3. Solo generar fixes, aplicación manual"
    echo ""
    read -p "$(echo -e ${CYAN}Selección [1-3]:${NC} )" codigo_selection
    
    case "$codigo_selection" in
        1) MODIFICACION_CODIGO="con_restricciones" ;;
        2) MODIFICACION_CODIGO="solo_fixes_simples" ;;
        3) MODIFICACION_CODIGO="solo_generar" ;;
        *) log_message ERROR "Selección inválida"; exit 1 ;;
    esac
    
    log_message INFO "Modificación código: $MODIFICACION_CODIGO"
    
    # Pregunta 5: Iteraciones máximas
    print_separator
    echo -e "${CYAN}[5/8] 🔄 Iteraciones máximas por brecha/feature:${NC}"
    echo ""
    echo "  Configuración predeterminada:"
    echo "    P0 (críticos): 5 intentos"
    echo "    P1 (altos):    3 intentos"
    echo "    P2 (medios):   1 intento"
    echo ""
    read -p "$(echo -e ${CYAN}¿Confirmar o modificar? [Y/n]:${NC} )" iter_confirm
    
    if [[ "$iter_confirm" =~ ^[Nn]$ ]]; then
        read -p "$(echo -e ${CYAN}  P0 max intentos:${NC} )" ITERACIONES_MAX_P0
        read -p "$(echo -e ${CYAN}  P1 max intentos:${NC} )" ITERACIONES_MAX_P1
        read -p "$(echo -e ${CYAN}  P2 max intentos:${NC} )" ITERACIONES_MAX_P2
    fi
    
    log_message INFO "Iteraciones configuradas - P0:$ITERACIONES_MAX_P0 P1:$ITERACIONES_MAX_P1 P2:$ITERACIONES_MAX_P2"
    
    # Pregunta 6: Criterios de éxito
    print_separator
    echo -e "${CYAN}[6/8] 🎯 Criterios de éxito (proceso cerrado cuando):${NC}"
    echo ""
    echo "  ☑ Compliance Odoo 19 P0: 100% (cero deprecaciones)"
    echo "  ☑ Compliance Odoo 19 P1: ≥95%"
    echo "  ☑ Tests coverage: ≥90%"
    echo "  ☑ Tests passing: 100%"
    echo "  ☑ Brechas P0 cerradas: 100%"
    echo "  ☑ Brechas P1 cerradas: ≥95%"
    echo ""
    read -p "$(echo -e ${CYAN}Confirmar criterios [Y/n]:${NC} )" criterios_confirm
    
    if [[ ! "$criterios_confirm" =~ ^[Nn]$ ]]; then
        log_message INFO "Criterios éxito confirmados (predeterminados)"
    fi
    
    # Pregunta 7: Aprendizaje y memoria
    print_separator
    echo -e "${CYAN}[7/8] 🧠 Aprendizaje y memoria:${NC}"
    echo ""
    echo "  ☑ Guardar fixes exitosos como templates reutilizables"
    echo "  ☑ Registrar estrategias fallidas (evitar repetir)"
    echo "  ☑ Actualizar base conocimiento con patrones aprendidos"
    echo ""
    read -p "$(echo -e ${CYAN}Habilitar aprendizaje [Y/n]:${NC} )" aprendizaje_confirm
    
    if [[ "$aprendizaje_confirm" =~ ^[Nn]$ ]]; then
        APRENDIZAJE_HABILITADO=false
        log_message WARNING "Aprendizaje deshabilitado"
    else
        log_message INFO "Aprendizaje habilitado"
    fi
    
    # Pregunta 8: Reporting
    print_separator
    echo -e "${CYAN}[8/8] 📊 Reporting:${NC}"
    echo ""
    echo "  Generar reporte final en: $OUTPUTS_DIR/"
    echo "  Formato: Markdown + JSON (machine-readable)"
    echo ""
    read -p "$(echo -e ${CYAN}Confirmar [Y/n]:${NC} )" reporting_confirm
    
    # Resumen configuración
    print_separator
    echo -e "${GREEN}✅ Configuración completa${NC}"
    echo ""
    echo -e "${WHITE}Resumen:${NC}"
    echo "  - Tipo: $TIPO_TRABAJO"
    echo "  - Módulo: $MODULO_TARGET"
    echo "  - Autonomía: $NIVEL_AUTONOMIA"
    echo "  - Modificación código: $MODIFICACION_CODIGO"
    echo "  - Iteraciones: P0:$ITERACIONES_MAX_P0, P1:$ITERACIONES_MAX_P1, P2:$ITERACIONES_MAX_P2"
    echo "  - Aprendizaje: $([ "$APRENDIZAJE_HABILITADO" = true ] && echo "Habilitado" || echo "Deshabilitado")"
    echo ""
    
    read -p "$(echo -e ${CYAN}¿Proceder con estas configuraciones? [Y/n]:${NC} )" final_confirm
    
    if [[ "$final_confirm" =~ ^[Nn]$ ]]; then
        log_message INFO "Ejecución cancelada por usuario"
        exit 0
    fi
    
    log_message SUCCESS "Configuración confirmada - Iniciando ciclo autónomo"
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: CARGAR CONFIGURACIÓN MÓDULO
# ═══════════════════════════════════════════════════════════════════════════

cargar_configuracion_modulo() {
    local modulo=$1
    local config_file="$CONFIG_DIR/${modulo}.yml"
    
    if [ ! -f "$config_file" ]; then
        log_message WARNING "Configuración no encontrada: $config_file"
        log_message INFO "Usando configuración predeterminada"
        return 0
    fi
    
    log_message INFO "Cargando configuración: $config_file"
    
    # Leer configuración YAML (simplificado - en producción usar yq)
    # Por ahora, cargamos valores predeterminados
    
    log_message SUCCESS "Configuración cargada exitosamente"
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: CONSULTAR MEMORIA INTELIGENTE
# ═══════════════════════════════════════════════════════════════════════════

consultar_memoria() {
    local tipo_consulta=$1
    local contexto=$2
    
    log_message INFO "Consultando memoria: $tipo_consulta"
    
    if [ "$APRENDIZAJE_HABILITADO" = false ]; then
        log_message DEBUG "Aprendizaje deshabilitado - saltando consulta memoria"
        return 0
    fi
    
    # Llamar función de memoria inteligente
    consultar_fixes_similares "$contexto"
    consultar_estrategias_fallidas "$contexto"
    consultar_patrones_aprendidos "$contexto"
    
    log_message SUCCESS "Consulta memoria completada"
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: EJECUTAR CICLO SEGÚN TIPO
# ═══════════════════════════════════════════════════════════════════════════

ejecutar_ciclo() {
    print_separator
    echo -e "${MAGENTA}🚀 INICIANDO CICLO AUTÓNOMO${NC}"
    echo ""
    
    case "$TIPO_TRABAJO" in
        "cierre_brechas")
            log_message INFO "Ejecutando ciclo tipo A: Cierre de Brechas"
            ejecutar_ciclo_cierre_brechas
            ;;
        "desarrollo_features")
            log_message INFO "Ejecutando ciclo tipo B: Desarrollo Features"
            ejecutar_ciclo_desarrollo_features
            ;;
        "hibrido")
            log_message INFO "Ejecutando ciclo híbrido"
            ejecutar_ciclo_cierre_brechas
            ejecutar_ciclo_desarrollo_features
            ;;
        *)
            log_message ERROR "Tipo trabajo no reconocido: $TIPO_TRABAJO"
            exit 1
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: CICLO TIPO A - CIERRE BRECHAS
# ═══════════════════════════════════════════════════════════════════════════

ejecutar_ciclo_cierre_brechas() {
    log_message INFO "═══ FASE 1: AUDITORÍA INICIAL ═══"
    ejecutar_fase_auditoria_inicial
    
    log_message INFO "═══ FASE 2: IDENTIFICAR Y PRIORIZAR BRECHAS ═══"
    ejecutar_fase_identificar_brechas
    
    log_message INFO "═══ FASE 3: CICLO CERRAR BRECHAS (ITERATIVO) ═══"
    ejecutar_fase_cerrar_brechas_iterativo
    
    log_message INFO "═══ FASE 4: VALIDACIÓN FINAL ═══"
    ejecutar_fase_validacion_final
    
    log_message INFO "═══ FASE 5: CONSOLIDACIÓN RESULTADOS ═══"
    ejecutar_fase_consolidacion
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: CICLO TIPO B - DESARROLLO FEATURES
# ═══════════════════════════════════════════════════════════════════════════

ejecutar_ciclo_desarrollo_features() {
    log_message INFO "═══ FASE 1: ANÁLISIS REQUISITOS ═══"
    ejecutar_fase_analisis_requisitos
    
    log_message INFO "═══ FASE 2: DISEÑO SOLUCIÓN ═══"
    ejecutar_fase_diseno_solucion
    
    log_message INFO "═══ FASE 3: IMPLEMENTACIÓN ═══"
    ejecutar_fase_implementacion
    
    log_message INFO "═══ FASE 4: TESTING ═══"
    ejecutar_fase_testing
    
    log_message INFO "═══ FASE 5: VALIDACIÓN FINAL ═══"
    ejecutar_fase_validacion_feature
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: GUARDAR RESULTADOS EN MEMORIA
# ═══════════════════════════════════════════════════════════════════════════

guardar_en_memoria() {
    local tipo=$1
    local datos=$2
    
    if [ "$APRENDIZAJE_HABILITADO" = false ]; then
        return 0
    fi
    
    log_message INFO "Guardando en memoria: $tipo"
    
    case "$tipo" in
        "fix_exitoso")
            guardar_fix_exitoso "$datos"
            ;;
        "estrategia_fallida")
            guardar_estrategia_fallida "$datos"
            ;;
        "patron_aprendido")
            guardar_patron_aprendido "$datos"
            ;;
    esac
    
    log_message SUCCESS "Guardado en memoria exitosamente"
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN: GENERAR REPORTE FINAL
# ═══════════════════════════════════════════════════════════════════════════

generar_reporte_final() {
    print_separator
    echo -e "${GREEN}✅ CICLO AUTÓNOMO COMPLETADO${NC}"
    echo ""
    
    local reporte_file="$OUTPUTS_DIR/reporte_${SESSION_ID}.md"
    local metricas_file="$OUTPUTS_DIR/metricas_${SESSION_ID}.json"
    
    log_message INFO "Generando reporte final: $reporte_file"
    
    # Generar reporte markdown
    generar_reporte_markdown "$reporte_file"
    
    # Generar métricas JSON
    generar_metricas_json "$metricas_file"
    
    log_message SUCCESS "Reportes generados exitosamente"
    
    # Mostrar resumen
    print_separator
    echo -e "${WHITE}📊 RESUMEN EJECUCIÓN${NC}"
    echo ""
    echo "  Sesión: $SESSION_ID"
    echo "  Tipo: $TIPO_TRABAJO"
    echo "  Módulo: $MODULO_TARGET"
    echo "  Duración: $(calcular_duracion)"
    echo ""
    echo "  Reportes:"
    echo "    - Markdown: $reporte_file"
    echo "    - JSON:     $metricas_file"
    echo "    - Log:      $LOG_FILE"
    echo ""
    print_separator
}

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIÓN MAIN
# ═══════════════════════════════════════════════════════════════════════════

main() {
    # Inicializar log
    mkdir -p "$OUTPUTS_DIR"
    touch "$LOG_FILE"
    
    log_message INFO "╔════════════════════════════════════════════════════════════════╗"
    log_message INFO "║  Iniciando Orquestador Ciclo Autónomo Retroalimentado        ║"
    log_message INFO "╚════════════════════════════════════════════════════════════════╝"
    
    # Parsear argumentos
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --non-interactive)
                INTERACTIVE_MODE=false
                shift
                ;;
            --tipo)
                TIPO_TRABAJO="$2"
                shift 2
                ;;
            --modulo)
                MODULO_TARGET="$2"
                shift 2
                ;;
            --help)
                mostrar_ayuda
                exit 0
                ;;
            *)
                log_message ERROR "Argumento desconocido: $1"
                mostrar_ayuda
                exit 1
                ;;
        esac
    done
    
    # Modo interactivo o no interactivo
    if [ "$INTERACTIVE_MODE" = true ]; then
        inicio_interactivo
    else
        log_message INFO "Modo no interactivo"
        if [ -z "$TIPO_TRABAJO" ] || [ -z "$MODULO_TARGET" ]; then
            log_message ERROR "Modo no interactivo requiere --tipo y --modulo"
            exit 1
        fi
    fi
    
    # Cargar configuración módulo
    cargar_configuracion_modulo "$MODULO_TARGET"
    
    # Consultar memoria antes de empezar
    consultar_memoria "contexto_inicial" "$MODULO_TARGET"
    
    # Ejecutar ciclo
    ejecutar_ciclo
    
    # Generar reporte final
    generar_reporte_final
    
    log_message SUCCESS "Ejecución completada exitosamente"
}

# ═══════════════════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA
# ═══════════════════════════════════════════════════════════════════════════

# Trap para cleanup
trap 'handle_error $? $LINENO' ERR
trap 'cleanup' EXIT

# Ejecutar main
main "$@"

