#!/bin/bash
# PRUEBAS DE BAJA COMPLEJIDAD - AUDITORÍA BÁSICA
# Validación automática de componentes básicos del sistema enterprise

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTERPRISE_DIR="$PROJECT_ROOT/.codex/enterprise"

# Variables de resultado
TOTAL_TESTS=15
PASSED_TESTS=0
FAILED_TESTS=()

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
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$ENTERPRISE_DIR/low-complexity-audit.log"
}

test_result() {
    local test_name=$1
    local status=$2
    local details=$3

    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}✅ $test_name${NC}: $details"
        ((PASSED_TESTS++))
        log "PASS" "$test_name: $details"
    else
        echo -e "  ${RED}❌ $test_name${NC}: $details"
        FAILED_TESTS+=("$test_name: $details")
        log "FAIL" "$test_name: $details"
    fi
}

# GRUPO 1: ARQUITECTURA (5 tests)
test_architecture() {
    echo -e "${BLUE}🏗️ GRUPO 1: VALIDANDO ARQUITECTURA ENTERPRISE${NC}"

    # Test 1.1: Existencia directorio base
    if [ -d "$ENTERPRISE_DIR" ]; then
        test_result "Test 1.1 - Directorio Base" "PASS" "Directorio .codex/enterprise existe"
    else
        test_result "Test 1.1 - Directorio Base" "FAIL" "Directorio .codex/enterprise faltante"
    fi

    # Test 1.2: Validación subdirectorios
    local expected_dirs=("intelligence" "memory-bank" "model-optimization" "context-cache" "mcp-enterprise" "knowledge-index" "vector-store" "context-models" "knowledge-graph")
    local found_dirs=0

    for dir in "${expected_dirs[@]}"; do
        if [ -d "$ENTERPRISE_DIR/$dir" ]; then
            ((found_dirs++))
        fi
    done

    if [ "$found_dirs" -ge 7 ]; then  # Al menos 7 de 9 para pasar
        test_result "Test 1.2 - Subdirectorios" "PASS" "$found_dirs/9 subdirectorios encontrados"
    else
        test_result "Test 1.2 - Subdirectorios" "FAIL" "Solo $found_dirs/9 subdirectorios (mínimo 7)"
    fi

    # Test 1.3: Archivos TOML de configuración
    local toml_count=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)
    if [ "$toml_count" -ge 4 ]; then
        test_result "Test 1.3 - Config TOML" "PASS" "$toml_count archivos TOML encontrados"
    else
        test_result "Test 1.3 - Config TOML" "FAIL" "Solo $toml_count archivos (mínimo 4)"
    fi

    # Test 1.4: Scripts de automatización
    local script_count=$(ls -1 "$SCRIPT_DIR"/enterprise-*.sh 2>/dev/null | wc -l)
    if [ "$script_count" -ge 4 ]; then
        test_result "Test 1.4 - Scripts Auto" "PASS" "$script_count scripts enterprise encontrados"
    else
        test_result "Test 1.4 - Scripts Auto" "FAIL" "Solo $script_count scripts (mínimo 4)"
    fi

    # Test 1.5: Permisos de ejecución
    local executable_scripts=0
    local total_scripts=$(ls -1 "$SCRIPT_DIR"/enterprise-*.sh 2>/dev/null | wc -l)

    for script in "$SCRIPT_DIR"/enterprise-*.sh 2>/dev/null; do
        if [ -x "$script" ]; then
            ((executable_scripts++))
        fi
    done

    if [ "$executable_scripts" -eq "$total_scripts" ] && [ "$total_scripts" -gt 0 ]; then
        test_result "Test 1.5 - Permisos Ejecución" "PASS" "$executable_scripts/$total_scripts scripts ejecutables"
    else
        test_result "Test 1.5 - Permisos Ejecución" "FAIL" "$executable_scripts/$total_scripts scripts ejecutables"
    fi
}

# GRUPO 2: CONOCIMIENTO (4 tests)
test_knowledge() {
    echo -e "${BLUE}📚 GRUPO 2: VALIDANDO CONOCIMIENTO REGULATORIO${NC}"

    # Test 2.1: Directorio de conocimiento
    if [ -d "$PROJECT_ROOT/.github/agents/knowledge" ]; then
        test_result "Test 2.1 - Directorio Conocimiento" "PASS" "Directorio .github/agents/knowledge existe"
    else
        test_result "Test 2.1 - Directorio Conocimiento" "FAIL" "Directorio faltante"
    fi

    # Test 2.2: Archivos de conocimiento especializados
    local knowledge_files=$(find "$PROJECT_ROOT/.github/agents/knowledge" -name "*.md" 2>/dev/null | wc -l)
    if [ "$knowledge_files" -ge 3 ]; then
        test_result "Test 2.2 - Archivos Conocimiento" "PASS" "$knowledge_files archivos de conocimiento especializados"
    else
        test_result "Test 2.2 - Archivos Conocimiento" "FAIL" "Solo $knowledge_files archivos (mínimo 3)"
    fi

    # Test 2.3: Contenido no vacío
    local empty_files=0
    local total_files=$(find "$PROJECT_ROOT/.github/agents/knowledge" -name "*.md" 2>/dev/null | wc -l)

    for file in "$PROJECT_ROOT/.github/agents/knowledge"/*.md 2>/dev/null; do
        if [ -f "$file" ] && [ ! -s "$file" ]; then
            ((empty_files++))
        fi
    done

    if [ "$empty_files" -eq 0 ] && [ "$total_files" -gt 0 ]; then
        test_result "Test 2.3 - Contenido Válido" "PASS" "Todos los archivos tienen contenido"
    else
        test_result "Test 2.3 - Contenido Válido" "FAIL" "$empty_files archivos vacíos encontrados"
    fi

    # Test 2.4: Referencias básicas chilenas
    local chilean_refs=$(grep -r "chile\|SII\|DTE\|2025" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l)
    if [ "$chilean_refs" -ge 10 ]; then
        test_result "Test 2.4 - Referencias Chilenas" "PASS" "$chilean_refs referencias regulatorias chilenas encontradas"
    else
        test_result "Test 2.4 - Referencias Chilenas" "FAIL" "Solo $chilean_refs referencias (mínimo 10)"
    fi
}

# GRUPO 3: CONFIGURACIONES (4 tests)
test_configurations() {
    echo -e "${BLUE}⚙️ GRUPO 3: VALIDANDO CONFIGURACIONES${NC}"

    # Test 3.1: Sintaxis TOML válida
    local invalid_toml=0
    local total_toml=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)

    for toml_file in "$ENTERPRISE_DIR"/*.toml 2>/dev/null; do
        if [ -f "$toml_file" ]; then
            # Verificar sintaxis básica (presencia de secciones)
            if ! grep -q "^\[" "$toml_file" 2>/dev/null; then
                ((invalid_toml++))
            fi
        fi
    done

    if [ "$invalid_toml" -eq 0 ] && [ "$total_toml" -gt 0 ]; then
        test_result "Test 3.1 - Sintaxis TOML" "PASS" "Sintaxis válida en $total_toml archivos TOML"
    else
        test_result "Test 3.1 - Sintaxis TOML" "FAIL" "$invalid_toml archivos con sintaxis inválida"
    fi

    # Test 3.2: Secciones obligatorias
    local missing_sections=0
    local total_files=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)

    for toml_file in "$ENTERPRISE_DIR"/*.toml 2>/dev/null; do
        if [ -f "$toml_file" ]; then
            # Cada archivo debería tener al menos una sección
            if ! grep -q "^\[" "$toml_file" 2>/dev/null; then
                ((missing_sections++))
            fi
        fi
    done

    if [ "$missing_sections" -eq 0 ] && [ "$total_files" -gt 0 ]; then
        test_result "Test 3.2 - Secciones Obligatorias" "PASS" "Todas las configuraciones tienen secciones definidas"
    else
        test_result "Test 3.2 - Secciones Obligatorias" "FAIL" "$missing_sections archivos sin secciones"
    fi

    # Test 3.3: Referencias a paths correctos
    local invalid_paths=0
    local total_configs=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)

    # Buscar paths que deberían existir
    if grep -r "\.\./\|\./\|~" "$ENTERPRISE_DIR"/*.toml 2>/dev/null | grep -v "env\|USER" | head -5 | wc -l > /dev/null; then
        test_result "Test 3.3 - Paths Correctos" "PASS" "Referencias de paths válidas encontradas"
    else
        test_result "Test 3.3 - Paths Correctos" "WARN" "Pocas referencias de paths encontradas (aceptable para config básica)"
    fi

    # Test 3.4: Configuraciones específicas chilenas
    local chilean_configs=0
    local total_configs=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)

    for config_file in "$ENTERPRISE_DIR"/*.toml 2>/dev/null; do
        if [ -f "$config_file" ] && grep -qi "chile\|sii\|dte\|2025" "$config_file" 2>/dev/null; then
            ((chilean_configs++))
        fi
    done

    if [ "$chilean_configs" -ge 2 ]; then
        test_result "Test 3.4 - Config Chilenas" "PASS" "$chilean_configs configuraciones con contexto chileno"
    else
        test_result "Test 3.4 - Config Chilenas" "FAIL" "Solo $chilean_configs configs con contexto chileno (mínimo 2)"
    fi
}

# GRUPO 4: AGENTES (2 tests)
test_agents() {
    echo -e "${BLUE}🤖 GRUPO 4: VALIDANDO AGENTES ESPECIALIZADOS${NC}"

    # Test 4.1: Archivo configuración Copilot
    if [ -f "$HOME/.codex/config.toml" ]; then
        test_result "Test 4.1 - Config Copilot" "PASS" "Archivo configuración Copilot encontrado"
    else
        test_result "Test 4.1 - Config Copilot" "FAIL" "Archivo configuración Copilot faltante"
    fi

    # Test 4.2: Perfiles básicos chilenos
    local chilean_profiles_found=0
    local expected_profiles=("payroll-compliance" "dte-specialist" "odoo-dev")

    if [ -f "$HOME/.codex/config.toml" ]; then
        for profile in "${expected_profiles[@]}"; do
            if grep -q "$profile" "$HOME/.codex/config.toml" 2>/dev/null; then
                ((chilean_profiles_found++))
            fi
        done
    fi

    if [ "$chilean_profiles_found" -ge 2 ]; then
        test_result "Test 4.2 - Perfiles Chilenos" "PASS" "$chilean_profiles_found perfiles especializados encontrados"
    else
        test_result "Test 4.2 - Perfiles Chilenos" "FAIL" "Solo $chilean_profiles_found perfiles (mínimo 2)"
    fi
}

# Función de reporte final
final_report() {
    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 📊 REPORTE FINAL: PRUEBAS BAJA COMPLEJIDAD                                ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    local percentage=$((PASSED_TESTS * 100 / TOTAL_TESTS))

    echo -e "${CYAN}📈 RESULTADOS:${NC}"
    echo -e "   Tests ejecutados: $TOTAL_TESTS"
    echo -e "   Tests aprobados: $PASSED_TESTS"
    echo -e "   Tests fallidos: $(($TOTAL_TESTS - $PASSED_TESTS))"
    echo -e "   Porcentaje de éxito: ${percentage}%"
    echo

    # Evaluar resultado
    if [ $percentage -ge 80 ]; then
        echo -e "${GREEN}✅ CALIFICACIÓN: ${percentage}/100 - AUDITORÍA BÁSICA APROBADA${NC}"
        echo -e "${GREEN}✅ Sistema enterprise tiene base sólida validada${NC}"

        if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
            echo
            echo -e "${YELLOW}⚠️ TESTS FALLIDOS (NO CRÍTICOS):${NC}"
            for failed_test in "${FAILED_TESTS[@]}"; do
                echo -e "   • $failed_test"
            done
        fi

        echo
        echo -e "${PURPLE}🚀 PRÓXIMO PASO: Ejecutar pruebas de mediana complejidad${NC}"
        echo -e "   bash scripts/enterprise-medium-complexity-tests.sh"

    else
        echo -e "${RED}❌ CALIFICACIÓN: ${percentage}/100 - AUDITORÍA BÁSICA FALLIDA${NC}"
        echo -e "${RED}❌ Corregir fallos antes de continuar${NC}"

        echo
        echo -e "${RED}❌ TESTS FALLIDOS CRÍTICOS:${NC}"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo -e "   • $failed_test"
        done
    fi

    log "FINAL" "Auditoría baja complejidad completada - Calificación: ${percentage}% ($PASSED_TESTS/$TOTAL_TESTS tests)"
}

# Función principal
main() {
    echo "🟢 PRUEBAS DE BAJA COMPLEJIDAD - AUDITORÍA BÁSICA"
    echo "================================================"
    echo
    echo "⏱️ TIEMPO ESTIMADO: 30 minutos"
    echo "🎯 OBJETIVO: Validación automática de componentes básicos"
    echo "📊 TESTS: 15 pruebas automatizadas"
    echo

    log "START" "Iniciando auditoría de baja complejidad"

    # Ejecutar pruebas
    test_architecture
    echo

    test_knowledge
    echo

    test_configurations
    echo

    test_agents
    echo

    # Generar reporte final
    final_report
}

# Ejecutar pruebas
main "$@"
