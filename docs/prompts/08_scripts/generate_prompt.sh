#!/usr/bin/env bash

################################################################################
# GENERATE_PROMPT.SH - Generador de Prompts desde Templates
#
# Versión: 1.0.0
# Fecha: 2025-11-12
# Autor: Pedro Troncoso (@pwills85)
#
# Descripción:
#   Script interactivo para generar prompts desde templates con variables
#   parametrizadas. Genera metadata automática y guarda en ubicación correcta.
#
# Uso:
#   ./generate_prompt.sh
#   ./generate_prompt.sh --template TEMPLATE_AUDITORIA.md --module l10n_cl_dte
#   ./generate_prompt.sh --non-interactive --template TEMPLATE_P4_DEEP_ANALYSIS.md
#
# Dependencies:
#   - bash 4.0+
#   - envsubst (gettext package)
#   - jq (opcional, para JSON metadata)
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROMPTS_DIR="${PROJECT_ROOT}/docs/prompts"
TEMPLATES_DIR="${PROMPTS_DIR}/04_templates"
PRODUCTION_DIR="${PROMPTS_DIR}/05_prompts_produccion"
OUTPUTS_DIR="${PROMPTS_DIR}/06_outputs"

# Default values
INTERACTIVE=true
TEMPLATE=""
MODULE=""
PRIORITY="P1"
OUTPUT_FILE=""

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  🚀 GENERADOR DE PROMPTS - Odoo 19 EERGYGROUP${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

usage() {
    cat <<EOF
Uso: $0 [OPCIONES]

Genera un prompt desde template con variables parametrizadas.

OPCIONES:
    -h, --help              Mostrar esta ayuda
    -t, --template FILE     Template a usar (archivo en 04_templates/)
    -m, --module NAME       Nombre módulo Odoo
    -p, --priority P0|P1|P2 Prioridad (default: P1)
    -o, --output FILE       Archivo output (auto-generado si no se especifica)
    -n, --non-interactive   Modo no-interactivo (requiere todas las opciones)

TEMPLATES DISPONIBLES:
    - TEMPLATE_AUDITORIA.md
    - TEMPLATE_CIERRE_BRECHA.md
    - TEMPLATE_P4_DEEP_ANALYSIS.md
    - TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md
    - TEMPLATE_MULTI_AGENT_ORCHESTRATION.md

EJEMPLOS:
    # Modo interactivo (recomendado)
    $0

    # Generar auditoría módulo específico
    $0 --template TEMPLATE_AUDITORIA.md --module l10n_cl_dte

    # Generar análisis profundo
    $0 --template TEMPLATE_P4_DEEP_ANALYSIS.md --module l10n_cl_hr_payroll --priority P0

EOF
    exit 0
}

################################################################################
# Interactive Prompts
################################################################################

select_template() {
    echo -e "${BLUE}Selecciona el template:${NC}"
    echo ""

    local templates=()
    local i=1

    while IFS= read -r -d '' template; do
        local basename=$(basename "$template")
        templates+=("$basename")
        echo "  $i) $basename"
        ((i++))
    done < <(find "$TEMPLATES_DIR" -name "TEMPLATE_*.md" -print0 | sort -z)

    echo ""
    read -p "Opción [1-${#templates[@]}]: " selection

    if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#templates[@]}" ]; then
        TEMPLATE="${templates[$((selection-1))]}"
        print_success "Template seleccionado: $TEMPLATE"
    else
        print_error "Selección inválida"
        exit 1
    fi
}

prompt_module() {
    echo ""
    echo -e "${BLUE}Módulos disponibles:${NC}"
    echo "  - l10n_cl_dte (Facturación Electrónica)"
    echo "  - l10n_cl_hr_payroll (Nómina)"
    echo "  - l10n_cl_financial_reports (Reportes Financieros)"
    echo "  - ai_service (Microservicio AI)"
    echo "  - custom (Otro módulo)"
    echo ""

    read -p "Nombre del módulo: " MODULE

    if [ -z "$MODULE" ]; then
        print_error "Módulo requerido"
        exit 1
    fi

    print_success "Módulo: $MODULE"
}

prompt_priority() {
    echo ""
    echo -e "${BLUE}Prioridad:${NC}"
    echo "  P0 - Crítico bloqueante (deadline <1 semana)"
    echo "  P1 - Alta prioridad (deadline <1 mes)"
    echo "  P2 - Media prioridad (deadline <3 meses)"
    echo ""

    read -p "Prioridad [P0/P1/P2] (default: P1): " PRIORITY
    PRIORITY=${PRIORITY:-P1}

    if [[ ! "$PRIORITY" =~ ^P[0-2]$ ]]; then
        print_error "Prioridad inválida (debe ser P0, P1 o P2)"
        exit 1
    fi

    print_success "Prioridad: $PRIORITY"
}

################################################################################
# Template Processing
################################################################################

generate_metadata() {
    local date=$(date +%Y-%m-%d)
    local datetime=$(date +%Y-%m-%d_%H%M%S)

    cat <<EOF
---
prompt_metadata:
  generated_from: ${TEMPLATE}
  module: ${MODULE}
  priority: ${PRIORITY}
  created: ${date}
  author: $(git config user.name || echo "Unknown")
  version: 1.0.0
---

EOF
}

process_template() {
    local template_path="${TEMPLATES_DIR}/${TEMPLATE}"

    if [ ! -f "$template_path" ]; then
        print_error "Template no encontrado: $template_path"
        exit 1
    fi

    print_info "Procesando template: $TEMPLATE"

    # Export variables para envsubst
    export MODULE_NAME="$MODULE"
    export MODULE_PATH="addons/localization/${MODULE}"
    export PRIORITY="$PRIORITY"
    export DATE=$(date +%Y-%m-%d)
    export DATETIME=$(date +%Y%m%d_%H%M%S)
    export AUTHOR=$(git config user.name || echo "Unknown")

    # Generar prompt con variables reemplazadas
    local content=$(envsubst < "$template_path")

    # Agregar metadata al inicio
    local metadata=$(generate_metadata)

    echo "$metadata$content"
}

################################################################################
# Output Management
################################################################################

determine_output_path() {
    local date=$(date +%Y%m%d)
    local template_type=""

    # Detectar tipo de template
    if [[ "$TEMPLATE" =~ AUDIT ]]; then
        template_type="AUDIT"
    elif [[ "$TEMPLATE" =~ CIERRE ]]; then
        template_type="CIERRE"
    elif [[ "$TEMPLATE" =~ INFRA ]]; then
        template_type="INFRA"
    elif [[ "$TEMPLATE" =~ MULTI ]]; then
        template_type="MULTI_AGENT"
    else
        template_type="PROMPT"
    fi

    # Determinar directorio según tipo y módulo
    if [[ "$template_type" == "INFRA" ]]; then
        OUTPUT_FILE="${PRODUCTION_DIR}/consolidacion/${template_type}_${date}.md"
    elif [[ "$template_type" == "MULTI_AGENT" ]]; then
        OUTPUT_FILE="${PRODUCTION_DIR}/consolidacion/${template_type}_${date}.md"
    else
        # Crear directorio módulo si no existe
        local module_dir="${PRODUCTION_DIR}/modulos/${MODULE}"
        mkdir -p "$module_dir"
        OUTPUT_FILE="${module_dir}/${template_type}_${MODULE}_${date}.md"
    fi

    print_info "Output path: $OUTPUT_FILE"
}

save_prompt() {
    local content="$1"

    # Crear directorio si no existe
    mkdir -p "$(dirname "$OUTPUT_FILE")"

    # Guardar contenido
    echo "$content" > "$OUTPUT_FILE"

    print_success "Prompt generado exitosamente:"
    echo ""
    echo "  📄 Archivo: $OUTPUT_FILE"
    echo "  📊 Tamaño: $(wc -l < "$OUTPUT_FILE") líneas"
    echo ""
}

generate_json_metadata() {
    local date=$(date +%Y-%m-%d)

    cat > "${OUTPUT_FILE}.meta.json" <<EOF
{
  "prompt_metadata": {
    "generated_from": "${TEMPLATE}",
    "module": "${MODULE}",
    "priority": "${PRIORITY}",
    "created": "${date}",
    "author": "$(git config user.name || echo "Unknown")",
    "version": "1.0.0",
    "output_file": "${OUTPUT_FILE}",
    "status": "draft"
  },
  "execution": {
    "executed": false,
    "execution_date": null,
    "duration_hours": null,
    "agent": null
  },
  "metrics": {
    "findings_total": null,
    "findings_p0": null,
    "findings_p1": null,
    "findings_p2": null,
    "effort_hours": null
  }
}
EOF

    print_success "Metadata JSON generado: ${OUTPUT_FILE}.meta.json"
}

################################################################################
# Main Script
################################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                ;;
            -t|--template)
                TEMPLATE="$2"
                shift 2
                ;;
            -m|--module)
                MODULE="$2"
                shift 2
                ;;
            -p|--priority)
                PRIORITY="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -n|--non-interactive)
                INTERACTIVE=false
                shift
                ;;
            *)
                print_error "Opción desconocida: $1"
                usage
                ;;
        esac
    done
}

validate_args() {
    if [ "$INTERACTIVE" = false ]; then
        if [ -z "$TEMPLATE" ] || [ -z "$MODULE" ]; then
            print_error "Modo no-interactivo requiere --template y --module"
            usage
        fi
    fi
}

main() {
    parse_args "$@"
    validate_args

    print_header

    # Modo interactivo
    if [ "$INTERACTIVE" = true ]; then
        select_template
        prompt_module
        prompt_priority
    fi

    # Determinar output path si no se especificó
    if [ -z "$OUTPUT_FILE" ]; then
        determine_output_path
    fi

    # Generar prompt
    print_info "Generando prompt desde template..."
    local content=$(process_template)

    # Guardar archivo
    save_prompt "$content"

    # Generar metadata JSON
    if command -v jq &> /dev/null; then
        generate_json_metadata
    else
        print_warning "jq no instalado, metadata JSON omitido"
    fi

    echo ""
    print_success "✨ Prompt listo para usar!"
    echo ""
    print_info "Próximos pasos:"
    echo "  1. Revisar y ajustar prompt: ${OUTPUT_FILE}"
    echo "  2. Ejecutar con agente (Claude Code, Copilot CLI)"
    echo "  3. Guardar output en: ${OUTPUTS_DIR}/$(date +%Y-%m)/"
    echo "  4. Actualizar metadata JSON con métricas"
    echo ""
}

# Execute main
main "$@"
