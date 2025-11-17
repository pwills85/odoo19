#!/bin/bash

# 🚀 INTELLIGENT CLI ROUTER ENTERPRISE
# Router inteligente para seleccionar el CLI y modelo óptimo según tipo de tarea
# Configurado con modelos más inteligentes y temperatura 0.1 para máxima precisión

set -euo pipefail

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

TASK_TYPE="$1"
PROMPT="${@:2}"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

show_usage() {
    cat << EOF
🚀 INTELLIGENT CLI ROUTER ENTERPRISE

USAGE:
  ./intelligent-cli-router-enterprise.sh <task_type> <prompt>

TASK TYPES:
  architecture    - Análisis arquitectural Odoo 19 CE (GPT-5 / GPT-4o)
  compliance      - Análisis regulatorio chileno (Gemini Ultra)
  dte-audit       - Auditoría módulo DTE (GPT-5 + Gemini Ultra)
  code-gen        - Generación de código (Claude Sonnet 4.5)
  debugging       - Debugging complejo (O1-Preview)
  performance     - Optimización de performance (GPT-4o)
  security        - Auditoría de seguridad (GPT-4o)
  testing         - Generación de tests (GPT-5)
  general         - Tarea general (GPT-5)

EXAMPLES:
  # Análisis arquitectural
  ./intelligent-cli-router-enterprise.sh architecture "Analiza arquitectura del módulo l10n_cl_dte"

  # Compliance regulatorio
  ./intelligent-cli-router-enterprise.sh compliance "Valida compliance DTE contra Resolución SII 80/2014"

  # Generación de código
  ./intelligent-cli-router-enterprise.sh code-gen "Crea modelo Odoo para Guía de Despacho DTE 52"

CONFIGURATION:
  - Copilot CLI: GPT-5 (temperatura 0.1)
  - Codex CLI: GPT-4o (temperatura 0.1)
  - Gemini CLI: Ultra 1.5 (temperatura 0.1)
  - Perfiles especializados: Activados
EOF
    exit 1
}

# =============================================================================
# ROUTING INTELIGENTE
# =============================================================================

route_task() {
    local task_type="$1"
    local prompt="$2"

    case "$task_type" in
        architecture|arch)
            log_info "📐 TAREA: Análisis Arquitectural"
            log_info "CLI: Copilot → GPT-5 | Temperatura: 0.05"
            export COPILOT_MODEL="gpt-5"
            export COPILOT_TEMPERATURE="0.05"
            gh copilot ask "$prompt"
            ;;

        compliance|comp)
            log_info "📋 TAREA: Análisis Regulatorio Chileno"
            log_info "CLI: Gemini → Ultra 1.5 | Temperatura: 0.05"
            export GEMINI_TEMPERATURE="0.05"
            gemini ask "$prompt" --model ultra
            ;;

        dte-audit|dte)
            log_info "🔍 TAREA: Auditoría Profunda Módulo DTE"
            log_info "CLI: GPT-5 + Gemini Ultra | Coordinación inteligente"
            
            # Fase 1: Análisis arquitectural con GPT-5
            log_info "FASE 1: Análisis arquitectural..."
            export COPILOT_MODEL="gpt-5"
            export COPILOT_TEMPERATURE="0.05"
            gh copilot ask "Analiza arquitectura del módulo l10n_cl_dte: $prompt" > /tmp/dte_arch_analysis.txt
            
            # Fase 2: Validación compliance con Gemini Ultra
            log_info "FASE 2: Validación compliance..."
            export GEMINI_TEMPERATURE="0.05"
            gemini ask "Valida compliance regulatorio del módulo l10n_cl_dte: $prompt" --model ultra > /tmp/dte_compliance_analysis.txt
            
            # Mostrar resultados consolidados
            echo ""
            log_success "=== ANÁLISIS ARQUITECTURAL (GPT-5) ==="
            cat /tmp/dte_arch_analysis.txt
            echo ""
            log_success "=== VALIDACIÓN COMPLIANCE (Gemini Ultra) ==="
            cat /tmp/dte_compliance_analysis.txt
            ;;

        code-gen|code)
            log_info "💻 TAREA: Generación de Código"
            log_info "CLI: Copilot → Claude Sonnet 4.5 | Temperatura: 0.1"
            export COPILOT_MODEL="claude-sonnet-4.5"
            export COPILOT_TEMPERATURE="0.1"
            gh copilot ask "$prompt"
            ;;

        debugging|debug)
            log_info "🐛 TAREA: Debugging Complejo"
            log_info "CLI: Codex → O1-Preview | Razonamiento profundo"
            codex ask "$prompt" --profile reasoning-specialist
            ;;

        performance|perf)
            log_info "⚡ TAREA: Optimización de Performance"
            log_info "CLI: Codex → GPT-4o | Temperatura: 0.1"
            codex ask "$prompt" --profile performance-optimizer
            ;;

        security|sec)
            log_info "🔒 TAREA: Auditoría de Seguridad"
            log_info "CLI: Codex → GPT-4o | Temperatura: 0.05"
            codex ask "$prompt" --profile security-specialist
            ;;

        testing|test)
            log_info "🧪 TAREA: Generación de Tests"
            log_info "CLI: Copilot → GPT-5 | Temperatura: 0.1"
            export COPILOT_MODEL="gpt-5"
            export COPILOT_TEMPERATURE="0.1"
            gh copilot ask "$prompt"
            ;;

        payroll|nomina)
            log_info "💼 TAREA: Análisis Nómina Chilena"
            log_info "CLI: Codex → GPT-4o | Temperatura: 0.05"
            codex ask "$prompt" --profile payroll-compliance
            ;;

        general|*)
            log_info "🎯 TAREA: General"
            log_info "CLI: Copilot → GPT-5 | Temperatura: 0.1"
            export COPILOT_MODEL="gpt-5"
            export COPILOT_TEMPERATURE="0.1"
            gh copilot ask "$prompt"
            ;;
    esac
}

# =============================================================================
# EJECUCIÓN PRINCIPAL
# =============================================================================

main() {
    # Validar argumentos
    if [ $# -lt 2 ]; then
        log_error "Argumentos insuficientes"
        show_usage
    fi

    # Cargar variables de entorno optimizadas
    if [ -f "$(dirname "$0")/../copilot-advanced.env" ]; then
        source "$(dirname "$0")/../copilot-advanced.env"
    fi

    if [ -f "$(dirname "$0")/../gemini-enhanced.env" ]; then
        source "$(dirname "$0")/../gemini-enhanced.env"
    fi

    # Ejecutar routing
    log_success "🚀 INICIANDO INTELLIGENT CLI ROUTER ENTERPRISE"
    echo ""
    
    route_task "$TASK_TYPE" "$PROMPT"
    
    echo ""
    log_success "✅ TAREA COMPLETADA"
}

# Ejecutar si el script es llamado directamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
