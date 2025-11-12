#!/usr/bin/env bash

################################################################################
# VALIDATE_PROMPT.SH - Validador de Prompts contra Estándares
#
# Versión: 1.0.0
# Fecha: 2025-11-12
# Autor: Pedro Troncoso (@pwills85)
#
# Descripción:
#   Valida prompts generados contra checklists y estándares del proyecto.
#   Verifica compliance Odoo 19, estructura, completitud, y best practices.
#
# Uso:
#   ./validate_prompt.sh <prompt_file>
#   ./validate_prompt.sh --all  # Validar todos los prompts
#   ./validate_prompt.sh --json # Output JSON machine-readable
#
# Exit codes:
#   0 - Validación exitosa (score >= 80%)
#   1 - Validación fallida (score < 80%)
#   2 - Error de ejecución
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

# Validation state
SCORE=0
TOTAL_CHECKS=0
PASSED_CHECKS=0
ISSUES=()

# Output mode
JSON_OUTPUT=false
VERBOSE=true

################################################################################
# Helper Functions
################################################################################

print_header() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}  ✅ VALIDADOR DE PROMPTS - Odoo 19 EERGYGROUP${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi
}

print_success() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${GREEN}✅ $1${NC}"
    fi
}

print_error() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${RED}❌ $1${NC}"
    fi
}

print_warning() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}⚠️  $1${NC}"
    fi
}

print_info() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}ℹ️  $1${NC}"
    fi
}

add_issue() {
    local severity=$1
    local message=$2
    ISSUES+=("[$severity] $message")
}

check_pass() {
    ((TOTAL_CHECKS++))
    ((PASSED_CHECKS++))
}

check_fail() {
    local severity=$1
    local message=$2
    ((TOTAL_CHECKS++))
    add_issue "$severity" "$message"
}

################################################################################
# Validation Rules
################################################################################

validate_file_exists() {
    local file=$1

    if [ ! -f "$file" ]; then
        print_error "Archivo no encontrado: $file"
        exit 2
    fi

    check_pass
}

validate_metadata() {
    local file=$1
    print_info "Validando metadata..."

    # Check for metadata section
    if grep -q "^---$" "$file"; then
        check_pass
        print_success "Metadata presente"
    else
        check_fail "P2" "Falta sección metadata YAML"
        print_warning "Recomendación: Agregar metadata al inicio"
    fi

    # Check for required fields in metadata/content
    local required_fields=("prompt_id" "version" "module" "created")

    for field in "${required_fields[@]}"; do
        if grep -iq "$field" "$file"; then
            check_pass
        else
            check_fail "P2" "Falta campo: $field"
        fi
    done
}

validate_compliance_checklist() {
    local file=$1
    print_info "Validando checklist Odoo 19 CE..."

    # Verificar que menciona checklist compliance
    if grep -iq "CHECKLIST_ODOO19_VALIDACIONES\|compliance\|depreca" "$file"; then
        check_pass
        print_success "Referencia a compliance Odoo 19"
    else
        check_fail "P0" "Falta validación compliance Odoo 19 CE"
        print_error "CRÍTICO: Todo prompt auditoría debe incluir checklist deprecaciones"
    fi

    # Verificar patrones deprecación mencionados
    local patterns=("t-esc" "type='json'" "attrs=" "_sql_constraints" "self._cr" "fields_view_get")
    local patterns_found=0

    for pattern in "${patterns[@]}"; do
        if grep -q "$pattern" "$file"; then
            ((patterns_found++))
        fi
    done

    if [ $patterns_found -ge 4 ]; then
        check_pass
        print_success "Patrones deprecación mencionados: $patterns_found/6"
    else
        check_fail "P1" "Pocos patrones deprecación ($patterns_found/6)"
        print_warning "Incluir al menos 4 patrones deprecación principales"
    fi
}

validate_structure() {
    local file=$1
    print_info "Validando estructura prompt..."

    # Verificar secciones esenciales
    local sections=("Objetivo\|OBJETIVO\|🎯" "Contexto\|CONTEXTO\|📐" "Instrucciones\|INSTRUCCIONES\|📋" "Output\|DELIVERABLE\|📊")

    for section in "${sections[@]}"; do
        if grep -Eq "$section" "$file"; then
            check_pass
        else
            check_fail "P2" "Falta sección recomendada: ${section//|/ o }"
        fi
    done

    # Verificar comandos Docker si es auditoría técnica
    if grep -iq "audit\|análisis\|review" "$file"; then
        if grep -q "docker compose exec odoo" "$file"; then
            check_pass
            print_success "Comandos Docker presentes"
        else
            check_fail "P1" "Falta comandos Docker para validación"
            print_warning "Incluir comandos docker compose exec para auditoría"
        fi
    fi
}

validate_documentation_refs() {
    local file=$1
    print_info "Validando referencias documentación..."

    # Verificar referencias a docs proyecto
    local doc_refs=(
        "CHECKLIST_ODOO19_VALIDACIONES"
        "MAXIMAS_DESARROLLO\|MAXIMAS_AUDITORIA"
        "odoo19_patterns\|odoo19_deprecations"
        "docker_odoo_command_reference"
    )

    local refs_found=0

    for ref in "${doc_refs[@]}"; do
        if grep -Eq "$ref" "$file"; then
            ((refs_found++))
        fi
    done

    if [ $refs_found -ge 2 ]; then
        check_pass
        print_success "Referencias documentación: $refs_found/4"
    else
        check_fail "P2" "Pocas referencias documentación ($refs_found/4)"
    fi
}

validate_best_practices() {
    local file=$1
    print_info "Validando best practices..."

    # Máximas mencionadas
    if grep -iq "máxima\|regla" "$file"; then
        check_pass
        print_success "Menciona máximas/reglas"
    else
        check_fail "P2" "No menciona máximas del proyecto"
    fi

    # Métricas cuantitativas
    if grep -Eq "score\|métrica\|kpi\|coverage\|%\|hallazgos" "$file"; then
        check_pass
        print_success "Incluye métricas cuantitativas"
    else
        check_fail "P1" "Falta métricas cuantitativas esperadas"
    fi

    # Priorización (P0/P1/P2)
    if grep -Eq "P0\|P1\|P2\|prioridad" "$file"; then
        check_pass
        print_success "Incluye priorización hallazgos"
    else
        check_fail "P2" "Falta priorización hallazgos"
    fi
}

validate_security() {
    local file=$1
    print_info "Validando seguridad..."

    # No debe contener secrets
    local secret_patterns=("password\s*=\s*['\"][^'\"]+['\"]" "api_key\s*=\s*['\"][^'\"]+['\"]" "token\s*=\s*['\"][^'\"]+['\"]")

    for pattern in "${secret_patterns[@]}"; do
        if grep -Eq "$pattern" "$file"; then
            check_fail "P0" "CRÍTICO: Posible secret hardcoded detectado"
            print_error "Verificar manualmente y remover secrets"
            return
        fi
    done

    check_pass
    print_success "Sin secrets aparentes"
}

validate_completeness() {
    local file=$1
    print_info "Validando completitud..."

    # Verificar longitud mínima (prompt debe ser sustancial)
    local lines=$(wc -l < "$file")

    if [ "$lines" -ge 100 ]; then
        check_pass
        print_success "Longitud adecuada: $lines líneas"
    elif [ "$lines" -ge 50 ]; then
        check_fail "P2" "Prompt corto ($lines líneas), considerar expandir"
    else
        check_fail "P1" "Prompt muy corto ($lines líneas), probablemente incompleto"
    fi

    # Verificar que no es solo template (debe tener contenido específico)
    local template_markers=$(grep -c "{\|TODO\|FIXME\|XXX\|\[MÓDULO\]\|\[FECHA\]" "$file" || true)

    if [ "$template_markers" -eq 0 ]; then
        check_pass
        print_success "Sin placeholders pendientes"
    elif [ "$template_markers" -le 3 ]; then
        check_fail "P2" "Algunos placeholders sin reemplazar ($template_markers)"
    else
        check_fail "P1" "Múltiples placeholders sin reemplazar ($template_markers)"
        print_warning "Revisar y completar variables {MODULE}, {DATE}, etc."
    fi
}

################################################################################
# Scoring and Reporting
################################################################################

calculate_score() {
    if [ $TOTAL_CHECKS -eq 0 ]; then
        SCORE=0
    else
        SCORE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
    fi
}

generate_report() {
    local file=$1

    calculate_score

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  📊 REPORTE DE VALIDACIÓN${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Archivo: $(basename "$file")"
    echo "  Checks totales: $TOTAL_CHECKS"
    echo "  Checks pasados: $PASSED_CHECKS"
    echo -e "  Score: ${SCORE}% $(get_score_badge)"
    echo ""

    if [ ${#ISSUES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Issues encontrados:${NC}"
        echo ""
        for issue in "${ISSUES[@]}"; do
            echo "  • $issue"
        done
        echo ""
    fi

    if [ $SCORE -ge 90 ]; then
        echo -e "${GREEN}✅ EXCELENTE - Prompt cumple estándares clase mundial${NC}"
    elif [ $SCORE -ge 80 ]; then
        echo -e "${GREEN}✅ APROBADO - Prompt cumple estándares mínimos${NC}"
        echo -e "${YELLOW}   Revisar issues P1/P2 para mejorar calidad${NC}"
    elif [ $SCORE -ge 60 ]; then
        echo -e "${YELLOW}⚠️  ADVERTENCIA - Prompt requiere mejoras${NC}"
        echo -e "${YELLOW}   Corregir issues P0/P1 antes de usar en producción${NC}"
    else
        echo -e "${RED}❌ RECHAZADO - Prompt no cumple estándares mínimos${NC}"
        echo -e "${RED}   Revisar y corregir todos los issues${NC}"
    fi

    echo ""
}

get_score_badge() {
    if [ $SCORE -ge 90 ]; then
        echo -e "${GREEN}⭐⭐⭐⭐⭐${NC}"
    elif [ $SCORE -ge 80 ]; then
        echo -e "${GREEN}⭐⭐⭐⭐${NC}"
    elif [ $SCORE -ge 60 ]; then
        echo -e "${YELLOW}⭐⭐⭐${NC}"
    elif [ $SCORE -ge 40 ]; then
        echo -e "${YELLOW}⭐⭐${NC}"
    else
        echo -e "${RED}⭐${NC}"
    fi
}

generate_json_report() {
    local file=$1

    calculate_score

    cat <<EOF
{
  "validation": {
    "file": "$(basename "$file")",
    "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "score": $SCORE,
    "total_checks": $TOTAL_CHECKS,
    "passed_checks": $PASSED_CHECKS,
    "status": "$([ $SCORE -ge 80 ] && echo "passed" || echo "failed")",
    "issues": [
$(printf '      "%s"' "${ISSUES[@]}" | paste -sd ',' -)
    ]
  }
}
EOF
}

################################################################################
# Main Validation Flow
################################################################################

validate_prompt() {
    local file=$1

    print_header
    print_info "Validando: $(basename "$file")"
    echo ""

    validate_file_exists "$file"
    validate_metadata "$file"
    validate_compliance_checklist "$file"
    validate_structure "$file"
    validate_documentation_refs "$file"
    validate_best_practices "$file"
    validate_security "$file"
    validate_completeness "$file"

    if [ "$JSON_OUTPUT" = true ]; then
        generate_json_report "$file"
    else
        generate_report "$file"
    fi

    # Exit code basado en score
    if [ $SCORE -ge 80 ]; then
        exit 0
    else
        exit 1
    fi
}

validate_all_prompts() {
    print_header
    print_info "Validando todos los prompts en 05_prompts_produccion/"
    echo ""

    local total_prompts=0
    local passed_prompts=0

    while IFS= read -r -d '' prompt; do
        ((total_prompts++))
        print_info "Validando: $(basename "$prompt")"

        # Reset validation state
        SCORE=0
        TOTAL_CHECKS=0
        PASSED_CHECKS=0
        ISSUES=()
        VERBOSE=false

        validate_file_exists "$prompt"
        validate_metadata "$prompt"
        validate_compliance_checklist "$prompt"
        validate_structure "$prompt"
        validate_documentation_refs "$prompt"
        validate_best_practices "$prompt"
        validate_security "$prompt"
        validate_completeness "$prompt"

        calculate_score

        if [ $SCORE -ge 80 ]; then
            ((passed_prompts++))
            print_success "$(basename "$prompt"): ${SCORE}% ✅"
        else
            print_error "$(basename "$prompt"): ${SCORE}% ❌"
        fi

    done < <(find "${PROMPTS_DIR}/05_prompts_produccion" -name "*.md" -print0)

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "  Total prompts: $total_prompts"
    echo "  Aprobados: $passed_prompts"
    echo "  Rechazados: $((total_prompts - passed_prompts))"
    echo "  Tasa aprobación: $((passed_prompts * 100 / total_prompts))%"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

################################################################################
# CLI
################################################################################

usage() {
    cat <<EOF
Uso: $0 [OPCIONES] <prompt_file>

Valida prompts contra estándares del proyecto Odoo 19 EERGYGROUP.

OPCIONES:
    -h, --help       Mostrar esta ayuda
    --all            Validar todos los prompts en 05_prompts_produccion/
    --json           Output JSON machine-readable
    -q, --quiet      Modo silencioso (solo score final)

EXIT CODES:
    0 - Validación exitosa (score >= 80%)
    1 - Validación fallida (score < 80%)
    2 - Error de ejecución

EJEMPLOS:
    # Validar prompt específico
    $0 prompts/05_prompts_produccion/modulos/l10n_cl_dte/AUDIT_DTE_20251111.md

    # Validar todos
    $0 --all

    # Output JSON para CI/CD
    $0 --json prompt.md

EOF
    exit 0
}

main() {
    if [ $# -eq 0 ]; then
        usage
    fi

    case "$1" in
        -h|--help)
            usage
            ;;
        --all)
            validate_all_prompts
            ;;
        --json)
            JSON_OUTPUT=true
            VERBOSE=false
            shift
            validate_prompt "$1"
            ;;
        -q|--quiet)
            VERBOSE=false
            shift
            validate_prompt "$1"
            ;;
        *)
            validate_prompt "$1"
            ;;
    esac
}

main "$@"
