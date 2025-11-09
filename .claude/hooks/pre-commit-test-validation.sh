#!/bin/bash

################################################################################
# Pre-commit Hook: Test Validation
################################################################################

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
MIN_COVERAGE=85
TIMEOUT=30

# Funciones
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Obtener archivos modificados
get_changed_files() {
    git diff --cached --name-only --diff-filter=ACM
}

# Verificar si hay tests nuevos o modificados
check_tests_modified() {
    local changed_files=$(get_changed_files)
    local test_files=""

    for file in $changed_files; do
        if [[ $file == *"/tests/test_"* ]] && [[ $file == *.py ]]; then
            test_files="$test_files $file"
        fi
    done

    echo "$test_files"
}

# Ejecutar tests específicos
run_tests() {
    local test_file=$1

    log_info "Ejecutando test: $test_file"

    if ! $PYTHON_BIN -m pytest "$test_file" \
        --tb=short \
        --timeout=$TIMEOUT \
        -q 2>&1 | head -20; then
        return 1
    fi

    return 0
}

# Validar sintaxis Python
validate_python_syntax() {
    local file=$1

    log_info "Validando sintaxis Python: $file"

    if ! $PYTHON_BIN -m py_compile "$file" 2>&1; then
        log_error "Error de sintaxis en: $file"
        return 1
    fi

    return 0
}

# Validar imports
validate_imports() {
    local file=$1

    log_info "Validando imports: $file"

    # Verificar que no haya imports circulares
    if ! python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import $(basename "$file" .py)" 2>&1; then
        log_warning "Posible problema de imports en: $file"
        # No bloqueamos en imports (warning solamente)
    fi

    return 0
}

# Main logic
main() {
    log_info "Validando cambios para commit..."
    echo ""

    local changed_files=$(get_changed_files)
    local has_errors=0

    if [ -z "$changed_files" ]; then
        log_info "Sin cambios para validar"
        return 0
    fi

    # Validar archivos Python
    for file in $changed_files; do
        if [[ $file == *.py ]]; then
            # Sintaxis Python
            if ! validate_python_syntax "$PROJECT_ROOT/$file"; then
                has_errors=1
                continue
            fi

            # Imports
            if ! validate_imports "$PROJECT_ROOT/$file"; then
                # Warning only, no bloqueamos
                :
            fi

            # Si es test, ejecutar
            if [[ $file == *"/tests/test_"* ]]; then
                if ! run_tests "$PROJECT_ROOT/$file"; then
                    has_errors=1
                fi
            fi
        fi
    done

    echo ""

    if [ $has_errors -eq 0 ]; then
        log_success "Todas las validaciones pasaron"
        return 0
    else
        log_error "Hay errores que deben corregirse antes de commit"
        echo ""
        echo "Para hacer commit de todos modos, usa:"
        echo "  git commit --no-verify"
        echo ""
        return 1
    fi
}

# Ejecutar
main "$@"
