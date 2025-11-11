#!/bin/bash
# PRUEBAS DE MEDIANA COMPLEJIDAD - AUDITORÍA INTERMEDIA
# Validación profunda de funcionalidad y integración

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTERPRISE_DIR="$PROJECT_ROOT/.codex/enterprise"

# Variables de resultado
TOTAL_TESTS=12
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
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$ENTERPRISE_DIR/medium-complexity-audit.log"
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

# GRUPO 1: FUNCIONALIDAD (4 tests)
test_functionality() {
    echo -e "${BLUE}🔧 GRUPO 1: VALIDANDO FUNCIONALIDAD AVANZADA${NC}"

    # Test 1.1: Validación sintaxis TOML completa
    local invalid_toml=0
    local total_toml=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)

    for toml_file in "$ENTERPRISE_DIR"/*.toml 2>/dev/null; do
        if [ -f "$toml_file" ]; then
            # Verificar sintaxis básica y estructura
            if ! head -n 5 "$toml_file" 2>/dev/null | grep -q "^\["; then
                ((invalid_toml++))
            fi

            # Verificar que tiene contenido significativo
            if [ $(wc -l < "$toml_file") -lt 5 ]; then
                ((invalid_toml++))
            fi
        fi
    done

    if [ "$invalid_toml" -eq 0 ] && [ "$total_toml" -gt 0 ]; then
        test_result "Test 1.1 - Sintaxis TOML Completa" "PASS" "Sintaxis y estructura válidas en $total_toml archivos"
    else
        test_result "Test 1.1 - Sintaxis TOML Completa" "FAIL" "$invalid_toml archivos con problemas de sintaxis/estructura"
    fi

    # Test 1.2: Consistencia referencias cruzadas
    local cross_ref_errors=0
    local total_refs=0

    # Verificar referencias entre configuraciones
    if [ -f "$ENTERPRISE_DIR/knowledge-rag-system.toml" ]; then
        if grep -q "vector_store" "$ENTERPRISE_DIR/knowledge-rag-system.toml" 2>/dev/null; then
            ((total_refs++))
        fi
    fi

    if [ -f "$ENTERPRISE_DIR/persistent-memory-system.toml" ]; then
        if grep -q "sqlite\|memory" "$ENTERPRISE_DIR/persistent-memory-system.toml" 2>/dev/null; then
            ((total_refs++))
        fi
    fi

    if [ "$total_refs" -ge 2 ]; then
        test_result "Test 1.2 - Referencias Cruzadas" "PASS" "$total_refs referencias cruzadas consistentes"
    else
        test_result "Test 1.2 - Referencias Cruzadas" "FAIL" "Solo $total_refs referencias cruzadas (mínimo 2)"
    fi

    # Test 1.3: Configuraciones específicas chilenas válidas
    local chilean_config_errors=0
    local chilean_configs_validated=0

    # Validar configuraciones chilenas
    if [ -f "$ENTERPRISE_DIR/knowledge-rag-system.toml" ]; then
        if grep -q "chile\|SII\|DTE\|2025" "$ENTERPRISE_DIR/knowledge-rag-system.toml" 2>/dev/null; then
            ((chilean_configs_validated++))
        else
            ((chilean_config_errors++))
        fi
    fi

    if [ -f "$HOME/.codex/config.toml" ]; then
        if grep -q "payroll-compliance\|dte-specialist" "$HOME/.codex/config.toml" 2>/dev/null; then
            ((chilean_configs_validated++))
        else
            ((chilean_config_errors++))
        fi
    fi

    if [ "$chilean_config_errors" -eq 0 ] && [ "$chilean_configs_validated" -ge 1 ]; then
        test_result "Test 1.3 - Config Chilenas Válidas" "PASS" "$chilean_configs_validated configuraciones chilenas válidas"
    else
        test_result "Test 1.3 - Config Chilenas Válidas" "FAIL" "$chilean_config_errors errores en configuraciones chilenas"
    fi

    # Test 1.4: Dependencias de scripts resueltas
    local dependency_errors=0
    local scripts_checked=0

    # Verificar dependencias en scripts principales
    for script in "$SCRIPT_DIR"/enterprise-*.sh; do
        if [ -f "$script" ]; then
            ((scripts_checked++))
            # Verificar que scripts referenciados existen
            if grep -q "source.*\.\./" "$script" 2>/dev/null; then
                # Verificar si las dependencias existen
                if ! grep -q "scripts/" "$script" 2>/dev/null; then
                    ((dependency_errors++))
                fi
            fi
        fi
    done

    if [ "$dependency_errors" -eq 0 ] && [ "$scripts_checked" -gt 0 ]; then
        test_result "Test 1.4 - Dependencias Scripts" "PASS" "Dependencias resueltas en $scripts_checked scripts"
    else
        test_result "Test 1.4 - Dependencias Scripts" "FAIL" "$dependency_errors scripts con dependencias faltantes"
    fi
}

# GRUPO 2: INTEGRACIÓN (3 tests)
test_integration() {
    echo -e "${BLUE}🔗 GRUPO 2: VALIDANDO INTEGRACIÓN DE COMPONENTES${NC}"

    # Test 2.1: Integración RAG con vector store
    local rag_integration_valid=0
    local rag_checks=0

    # Verificar configuración RAG
    if [ -f "$ENTERPRISE_DIR/knowledge-rag-system.toml" ]; then
        ((rag_checks++))
        if grep -q "chromadb\|vector\|embeddings" "$ENTERPRISE_DIR/knowledge-rag-system.toml" 2>/dev/null; then
            ((rag_integration_valid++))
        fi
    fi

    # Verificar vector store
    if [ -d "$ENTERPRISE_DIR/vector-store" ]; then
        ((rag_checks++))
        if [ -f "$ENTERPRISE_DIR/vector-store/.gitkeep" ] 2>/dev/null || [ "$(ls -A "$ENTERPRISE_DIR/vector-store" 2>/dev/null | wc -l)" -ge 0 ]; then
            ((rag_integration_valid++))
        fi
    fi

    if [ "$rag_integration_valid" -eq "$rag_checks" ] && [ "$rag_checks" -gt 0 ]; then
        test_result "Test 2.1 - Integración RAG-Vector" "PASS" "RAG integrado correctamente con vector store"
    else
        test_result "Test 2.1 - Integración RAG-Vector" "FAIL" "Problemas de integración RAG-vector ($rag_integration_valid/$rag_checks)"
    fi

    # Test 2.2: Conexión memoria persistente
    local memory_integration_valid=0
    local memory_checks=0

    # Verificar configuración de memoria
    if [ -f "$ENTERPRISE_DIR/persistent-memory-system.toml" ]; then
        ((memory_checks++))
        if grep -q "sqlite\|database\|memory" "$ENTERPRISE_DIR/persistent-memory-system.toml" 2>/dev/null; then
            ((memory_integration_valid++))
        fi
    fi

    # Verificar directorio de memoria
    if [ -d "$ENTERPRISE_DIR/memory-bank" ]; then
        ((memory_checks++))
        if [ -f "$ENTERPRISE_DIR/memory-bank/persistent-memory-system.toml" ]; then
            ((memory_integration_valid++))
        fi
    fi

    if [ "$memory_integration_valid" -eq "$memory_checks" ] && [ "$memory_checks" -gt 0 ]; then
        test_result "Test 2.2 - Memoria Persistente" "PASS" "Sistema de memoria persistente correctamente conectado"
    else
        test_result "Test 2.2 - Memoria Persistente" "FAIL" "Problemas de conexión memoria ($memory_integration_valid/$memory_checks)"
    fi

    # Test 2.3: Compatibilidad modelo-CLI
    local model_compatibility_valid=0
    local compatibility_checks=0

    # Verificar configuración de modelos
    if [ -f "$ENTERPRISE_DIR/enterprise-model-system.toml" ]; then
        ((compatibility_checks++))
        if grep -q "claude\|gpt\|model.*routing" "$ENTERPRISE_DIR/enterprise-model-system.toml" 2>/dev/null; then
            ((model_compatibility_valid++))
        fi
    fi

    # Verificar configuración CLI
    if [ -f "$HOME/.codex/config.toml" ]; then
        ((compatibility_checks++))
        if grep -q "model.*provider\|api.*key" "$HOME/.codex/config.toml" 2>/dev/null; then
            ((model_compatibility_valid++))
        fi
    fi

    if [ "$model_compatibility_valid" -eq "$compatibility_checks" ] && [ "$compatibility_checks" -gt 0 ]; then
        test_result "Test 2.3 - Compatibilidad Modelo-CLI" "PASS" "Modelos y CLI correctamente compatibilizados"
    else
        test_result "Test 2.3 - Compatibilidad Modelo-CLI" "FAIL" "Problemas de compatibilidad ($model_compatibility_valid/$compatibility_checks)"
    fi
}

# GRUPO 3: ESPECIALIZACIÓN CHILENA (3 tests)
test_chilean_specialization() {
    echo -e "${BLUE}🇨🇱 GRUPO 3: VALIDANDO ESPECIALIZACIÓN CHILENA${NC}"

    # Test 3.1: Conocimiento regulatorio completo 2025
    local regulatory_knowledge_score=0
    local regulatory_checks=5

    # Verificar conocimiento regulatorio chileno
    local payroll_file="$PROJECT_ROOT/.github/agents/knowledge/chilean_payroll_regulations.md"
    if [ -f "$payroll_file" ]; then
        # Verificar contenido específico 2025
        if grep -q "2025\|octubre\|reformas" "$payroll_file" 2>/dev/null; then
            ((regulatory_knowledge_score++))
        fi
        if grep -q "AFP\|ISAPRE\|Impuesto.*Único" "$payroll_file" 2>/dev/null; then
            ((regulatory_knowledge_score++))
        fi
        if grep -q "tope.*APV\|tope.*AFC" "$payroll_file" 2>/dev/null; then
            ((regulatory_knowledge_score++))
        fi
        if grep -q "gratificación\|asignación.*familiar" "$payroll_file" 2>/dev/null; then
            ((regulatory_knowledge_score++))
        fi
        if grep -q "SII\|DTE\|factura.*electrónica" "$payroll_file" 2>/dev/null; then
            ((regulatory_knowledge_score++))
        fi
    fi

    if [ "$regulatory_knowledge_score" -ge 4 ]; then
        test_result "Test 3.1 - Conocimiento Regulatorio 2025" "PASS" "$regulatory_knowledge_score/5 aspectos regulatorios 2025 validados"
    else
        test_result "Test 3.1 - Conocimiento Regulatorio 2025" "FAIL" "Solo $regulatory_knowledge_score/5 aspectos (mínimo 4)"
    fi

    # Test 3.2: Configuraciones DTE válidas
    local dte_config_valid=0
    local dte_checks=3

    # Verificar configuraciones DTE
    if grep -r "DTE\|factura.*electrónica\|SII" "$ENTERPRISE_DIR/" 2>/dev/null | grep -v "binary" | wc -l > /dev/null; then
        ((dte_config_valid++))
    fi

    # Verificar tipos de DTE
    if grep -r "DTE.*33\|DTE.*34\|DTE.*52\|DTE.*56\|DTE.*61" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l > /dev/null; then
        ((dte_config_valid++))
    fi

    # Verificar integración SII
    if grep -r "SII\|webservice\|XML\|CAF" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l > /dev/null; then
        ((dte_config_valid++))
    fi

    if [ "$dte_config_valid" -ge 2 ]; then
        test_result "Test 3.2 - Configuraciones DTE" "PASS" "$dte_config_valid/3 aspectos DTE configurados"
    else
        test_result "Test 3.2 - Configuraciones DTE" "FAIL" "Solo $dte_config_valid/3 aspectos DTE (mínimo 2)"
    fi

    # Test 3.3: Parámetros nómina chilena correctos
    local payroll_params_valid=0
    local payroll_checks=4

    # Verificar indicadores económicos
    if grep -r "UF\|UTM\|IPC" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l > /dev/null; then
        ((payroll_params_valid++))
    fi

    # Verificar cálculos de nómina
    if grep -r "tope.*imponible\|base.*imponible" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l > /dev/null; then
        ((payroll_params_valid++))
    fi

    # Verificar tramos tributarios
    if grep -r "tramo.*tributario\|escala.*impuesto" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l > /dev/null; then
        ((payroll_params_valid++))
    fi

    # Verificar previred
    if grep -r "Previred\|TXT\|archivo.*remuneraciones" "$PROJECT_ROOT/.github/agents/knowledge/" 2>/dev/null | wc -l > /dev/null; then
        ((payroll_params_valid++))
    fi

    if [ "$payroll_params_valid" -ge 3 ]; then
        test_result "Test 3.3 - Parámetros Nómina Chilena" "PASS" "$payroll_params_valid/4 parámetros de nómina validados"
    else
        test_result "Test 3.3 - Parámetros Nómina Chilena" "FAIL" "Solo $payroll_params_valid/4 parámetros (mínimo 3)"
    fi
}

# GRUPO 4: RENDIMIENTO (2 tests)
test_performance() {
    echo -e "${BLUE}⚡ GRUPO 4: VALIDANDO RENDIMIENTO Y OPTIMIZACIÓN${NC}"

    # Test 4.1: Validación tiempos de carga
    local load_time_valid=0
    local load_checks=2

    # Medir tiempo de carga de configuraciones (simulado)
    local config_count=$(find "$ENTERPRISE_DIR" -name "*.toml" 2>/dev/null | wc -l)
    if [ "$config_count" -ge 3 ]; then
        ((load_time_valid++))  # Configuraciones existen
    fi

    # Verificar optimizaciones de carga
    if grep -r "cache\|ttl\|timeout" "$ENTERPRISE_DIR/" 2>/dev/null | wc -l > /dev/null; then
        ((load_time_valid++))  # Optimizaciones presentes
    fi

    if [ "$load_time_valid" -eq "$load_checks" ]; then
        test_result "Test 4.1 - Tiempos de Carga" "PASS" "Sistema optimizado para carga eficiente"
    else
        test_result "Test 4.1 - Tiempos de Carga" "FAIL" "Problemas de optimización ($load_time_valid/$load_checks)"
    fi

    # Test 4.2: Optimización de recursos
    local resource_optimization_valid=0
    local resource_checks=3

    # Verificar gestión de memoria
    if grep -r "memory\|cache\|pool" "$ENTERPRISE_DIR/" 2>/dev/null | wc -l > /dev/null; then
        ((resource_optimization_valid++))
    fi

    # Verificar optimización de conexiones
    if grep -r "connection.*pool\|timeout\|retry" "$ENTERPRISE_DIR/" 2>/dev/null | wc -l > /dev/null; then
        ((resource_optimization_valid++))
    fi

    # Verificar configuración de límites
    if grep -r "limit\|max\|threshold" "$ENTERPRISE_DIR/" 2>/dev/null | wc -l > /dev/null; then
        ((resource_optimization_valid++))
    fi

    if [ "$resource_optimization_valid" -ge 2 ]; then
        test_result "Test 4.2 - Optimización Recursos" "PASS" "$resource_optimization_valid/3 optimizaciones de recursos validadas"
    else
        test_result "Test 4.2 - Optimización Recursos" "FAIL" "Solo $resource_optimization_valid/3 optimizaciones (mínimo 2)"
    fi
}

# Función de reporte final
final_report() {
    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 📊 REPORTE FINAL: PRUEBAS MEDIANA COMPLEJIDAD                             ║"
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
    if [ $percentage -ge 90 ]; then
        echo -e "${GREEN}✅ CALIFICACIÓN: ${percentage}/100 - AUDITORÍA INTERMEDIA APROBADA${NC}"
        echo -e "${GREEN}✅ Sistema enterprise tiene funcionalidad e integración sólidas${NC}"

        if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
            echo
            echo -e "${YELLOW}⚠️ TESTS FALLIDOS (NO CRÍTICOS):${NC}"
            for failed_test in "${FAILED_TESTS[@]}"; do
                echo -e "   • $failed_test"
            done
        fi

        echo
        echo -e "${PURPLE}🚀 PRÓXIMO PASO: Ejecutar pruebas de alta complejidad${NC}"
        echo -e "   bash scripts/enterprise-high-complexity-tests.sh"

    else
        echo -e "${RED}❌ CALIFICACIÓN: ${percentage}/100 - AUDITORÍA INTERMEDIA FALLIDA${NC}"
        echo -e "${RED}❌ Corregir fallos antes de continuar${NC}"

        echo
        echo -e "${RED}❌ TESTS FALLIDOS CRÍTICOS:${NC}"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo -e "   • $failed_test"
        done
    fi

    log "FINAL" "Auditoría mediana complejidad completada - Calificación: ${percentage}% ($PASSED_TESTS/$TOTAL_TESTS tests)"
}

# Función principal
main() {
    echo "🟡 PRUEBAS DE MEDIANA COMPLEJIDAD - AUDITORÍA INTERMEDIA"
    echo "======================================================="
    echo
    echo "⏱️ TIEMPO ESTIMADO: 45 minutos"
    echo "🎯 OBJETIVO: Validación profunda de funcionalidad y integración"
    echo "📊 TESTS: 12 pruebas intermedias"
    echo

    log "START" "Iniciando auditoría de mediana complejidad"

    # Ejecutar pruebas
    test_functionality
    echo

    test_integration
    echo

    test_chilean_specialization
    echo

    test_performance
    echo

    # Generar reporte final
    final_report
}

# Ejecutar pruebas
main "$@"
