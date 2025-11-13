#!/bin/bash
# Pruebas Exhaustivas del Sistema Enterprise
# Valida cada mejora implementada con pruebas específicas

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTERPRISE_DIR="$PROJECT_ROOT/.codex/enterprise"

# Configuración de colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variables de resultado
TESTS_PASSED=0
TESTS_TOTAL=0
FAILED_TESTS=()

log() {
    local level=$1
    local message=$2
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$ENTERPRISE_DIR/testing.log"
}

test_result() {
    local test_name=$1
    local result=$2
    local details=$3

    ((TESTS_TOTAL++))

    if [ "$result" = "PASS" ]; then
        echo -e "  ${GREEN}✅ $test_name${NC}"
        ((TESTS_PASSED++))
        log "PASS" "$test_name: $details"
    else
        echo -e "  ${RED}❌ $test_name${NC}"
        FAILED_TESTS+=("$test_name: $details")
        log "FAIL" "$test_name: $details"
    fi

    if [ -n "$details" ] && [ "$result" = "FAIL" ]; then
        echo -e "    ${RED}Error: $details${NC}"
    fi
}

# Función de verificación de dependencias
test_dependencies() {
    echo -e "${BLUE}🔍 Probando dependencias enterprise...${NC}"

    # Python y paquetes
    if python3 -c "import chromadb, sentence_transformers, numpy, toml" 2>/dev/null; then
        test_result "Python Dependencies" "PASS" "ChromaDB, sentence-transformers, numpy, toml disponibles"
    else
        test_result "Python Dependencies" "FAIL" "Paquetes Python faltantes"
    fi

    # Node.js
    if command -v node &> /dev/null && command -v npm &> /dev/null; then
        test_result "Node.js Environment" "PASS" "Node.js $(node --version) y npm $(npm --version)"
    else
        test_result "Node.js Environment" "FAIL" "Node.js o npm no disponibles"
    fi

    # SQLite3
    if command -v sqlite3 &> /dev/null; then
        test_result "SQLite3 Database" "PASS" "SQLite3 disponible para memoria persistente"
    else
        test_result "SQLite3 Database" "FAIL" "SQLite3 no disponible"
    fi
}

# Función de prueba del sistema RAG
test_rag_system() {
    echo -e "${BLUE}📚 Probando sistema RAG...${NC}"

    # Verificar configuración RAG
    if [ -f "$ENTERPRISE_DIR/intelligence/knowledge-rag-system.toml" ]; then
        test_result "RAG Configuration" "PASS" "Configuración RAG encontrada"
    else
        test_result "RAG Configuration" "FAIL" "Configuración RAG faltante"
        return
    fi

    # Verificar base de datos vectorial
    if [ -d "$HOME/.codex/enterprise/vector-store" ]; then
        test_result "Vector Database Directory" "PASS" "Directorio de vector store creado"
    else
        test_result "Vector Database Directory" "FAIL" "Directorio de vector store faltante"
    fi

    # Intentar inicializar ChromaDB
    if python3 -c "
import chromadb
import os

try:
    vector_db_path = os.path.expanduser('~/.codex/enterprise/vector-store/odoo19-chile.db')
    client = chromadb.PersistentClient(path=vector_db_path)

    # Verificar colección
    collection = client.get_collection('odoo19_knowledge')
    vector_count = collection.count()

    if vector_count > 0:
        print(f'SUCCESS: {vector_count} vectores en base de datos')
    else:
        print('EMPTY: Base de datos vectorial vacía')
except Exception as e:
    print(f'ERROR: {e}')
    " 2>/dev/null | grep -q "SUCCESS"; then
        test_result "Vector Database Initialization" "PASS" "ChromaDB inicializado correctamente"
    else
        test_result "Vector Database Initialization" "FAIL" "Error en inicialización de ChromaDB"
    fi
}

# Función de prueba del sistema de memoria
test_memory_system() {
    echo -e "${BLUE}🧠 Probando sistema de memoria persistente...${NC}"

    # Verificar configuración de memoria
    if [ -f "$ENTERPRISE_DIR/memory-bank/persistent-memory-system.toml" ]; then
        test_result "Memory Configuration" "PASS" "Configuración de memoria encontrada"
    else
        test_result "Memory Configuration" "FAIL" "Configuración de memoria faltante"
    fi

    # Verificar directorios de memoria
    if [ -d "$HOME/.codex/enterprise/memory-bank" ]; then
        test_result "Memory Directories" "PASS" "Directorios de memoria creados"
    else
        test_result "Memory Directories" "FAIL" "Directorios de memoria faltantes"
    fi

    # Verificar base de datos de memoria
    if [ -f "$HOME/.codex/enterprise/memory-bank/odoo19-memory.db" ]; then
        # Verificar tablas
        table_count=$(python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$HOME/.codex/enterprise/memory-bank/odoo19-memory.db')
    cursor = conn.cursor()
    cursor.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")
    tables = cursor.fetchall()
    print(len(tables))
    conn.close()
except:
    print('0')
        " 2>/dev/null || echo "0")

        if [ "$table_count" -gt "0" ]; then
            test_result "Memory Database" "PASS" "$table_count tablas de memoria creadas"
        else
            test_result "Memory Database" "FAIL" "Base de datos de memoria sin tablas"
        fi
    else
        test_result "Memory Database" "FAIL" "Archivo de base de datos de memoria faltante"
    fi
}

# Función de prueba de optimización de modelos
test_model_optimization() {
    echo -e "${BLUE}🚀 Probando optimización de modelos...${NC}"

    # Verificar configuración de modelos
    if [ -f "$ENTERPRISE_DIR/model-optimization/enterprise-model-system.toml" ]; then
        test_result "Model Optimization Config" "PASS" "Configuración de modelos encontrada"
    else
        test_result "Model Optimization Config" "FAIL" "Configuración de modelos faltante"
    fi

    # Verificar directorio de métricas
    if [ -d "$HOME/.codex/enterprise/model-optimization/metrics" ]; then
        test_result "Model Metrics Directory" "PASS" "Directorio de métricas creado"
    else
        test_result "Model Metrics Directory" "FAIL" "Directorio de métricas faltante"
    fi

    # Verificar archivo de métricas
    if [ -f "$HOME/.codex/enterprise/model-optimization/metrics/model_performance.json" ]; then
        # Verificar contenido
        if python3 -c "
import json
try:
    with open('$HOME/.codex/enterprise/model-optimization/metrics/model_performance.json', 'r') as f:
        data = json.load(f)
    if isinstance(data, dict) and 'o3' in data:
        print('VALID')
    else:
        print('INVALID')
except:
    print('ERROR')
        " 2>/dev/null | grep -q "VALID"; then
            test_result "Model Metrics File" "PASS" "Archivo de métricas válido"
        else
            test_result "Model Metrics File" "FAIL" "Archivo de métricas inválido"
        fi
    else
        test_result "Model Metrics File" "FAIL" "Archivo de métricas faltante"
    fi
}

# Función de prueba del sistema de contexto
test_context_system() {
    echo -e "${BLUE}🎯 Probando sistema de contexto inteligente...${NC}"

    # Verificar configuración de contexto
    if [ -f "$ENTERPRISE_DIR/context-cache/intelligent-context-system.toml" ]; then
        test_result "Context Configuration" "PASS" "Configuración de contexto encontrada"
    else
        test_result "Context Configuration" "FAIL" "Configuración de contexto faltante"
    fi

    # Verificar modelos de contexto
    local models=("code_patterns.json" "domain_context.json" "relevance_model.json")
    local models_found=0

    for model in "${models[@]}"; do
        if [ -f "$HOME/.codex/enterprise/context-models/$model" ]; then
            ((models_found++))
        fi
    done

    if [ "$models_found" -eq "${#models[@]}" ]; then
        test_result "Context Models" "PASS" "$models_found modelos de contexto encontrados"
    else
        test_result "Context Models" "FAIL" "$models_found/${#models[@]} modelos encontrados"
    fi

    # Verificar cache de contexto
    if [ -f "$HOME/.codex/enterprise/context-cache/context_cache.json" ]; then
        test_result "Context Cache" "PASS" "Cache de contexto inicializado"
    else
        test_result "Context Cache" "FAIL" "Cache de contexto faltante"
    fi
}

# Función de prueba de MCP Enterprise
test_mcp_enterprise() {
    echo -e "${BLUE}🔗 Probando integración MCP Enterprise...${NC}"

    # Verificar configuración MCP
    if [ -f "$ENTERPRISE_DIR/mcp-enterprise/mcp-enterprise-integration.toml" ]; then
        test_result "MCP Configuration" "PASS" "Configuración MCP encontrada"
    else
        test_result "MCP Configuration" "FAIL" "Configuración MCP faltante"
    fi

    # Verificar directorios MCP
    local mcp_dirs=("logs" "metrics")
    local dirs_found=0

    for dir in "${mcp_dirs[@]}"; do
        if [ -d "$HOME/.codex/enterprise/mcp-enterprise/$dir" ]; then
            ((dirs_found++))
        fi
    done

    if [ "$dirs_found" -eq "${#mcp_dirs[@]}" ]; then
        test_result "MCP Directories" "PASS" "$dirs_found directorios MCP creados"
    else
        test_result "MCP Directories" "FAIL" "$dirs_found/${#mcp_dirs[@]} directorios encontrados"
    fi
}

# Función de prueba de base de conocimiento
test_knowledge_base() {
    echo -e "${BLUE}📖 Probando base de conocimiento...${NC}"

    # Verificar archivos indexados
    local kb_files=("documents.json" "codebase.json")
    local files_found=0

    for file in "${kb_files[@]}"; do
        if [ -f "$HOME/.codex/enterprise/knowledge-index/$file" ]; then
            ((files_found++))
        fi
    done

    if [ "$files_found" -eq "${#kb_files[@]}" ]; then
        test_result "Knowledge Index Files" "PASS" "$files_found archivos de índice encontrados"
    else
        test_result "Knowledge Index Files" "FAIL" "$files_found/${#kb_files[@]} archivos encontrados"
    fi

    # Contar entradas en archivos de índice
    local total_docs=0
    local total_code=0

    if [ -f "$HOME/.codex/enterprise/knowledge-index/documents.json" ]; then
        total_docs=$(wc -l < "$HOME/.codex/enterprise/knowledge-index/documents.json" 2>/dev/null || echo "0")
    fi

    if [ -f "$HOME/.codex/enterprise/knowledge-index/codebase.json" ]; then
        total_code=$(wc -l < "$HOME/.codex/enterprise/knowledge-index/codebase.json" 2>/dev/null || echo "0")
    fi

    if [ "$total_docs" -gt "0" ] && [ "$total_code" -gt "0" ]; then
        test_result "Knowledge Content" "PASS" "$total_docs documentos, $total_code archivos de código indexados"
    else
        test_result "Knowledge Content" "FAIL" "Contenido insuficiente indexado"
    fi
}

# Función de prueba de integración con Codex CLI
test_codex_integration() {
    echo -e "${BLUE}🤖 Probando integración con Codex CLI...${NC}"

    # Verificar que codex esté disponible
    if command -v codex &> /dev/null; then
        test_result "Codex CLI Available" "PASS" "Codex CLI encontrado en PATH"
    else
        test_result "Codex CLI Available" "FAIL" "Codex CLI no encontrado"
        return
    fi

    # Verificar perfiles disponibles
    local profiles=("odoo-dev" "dte-compliance" "test-automation" "docker-devops" "ai-fastapi-dev")
    local profiles_found=0

    for profile in "${profiles[@]}"; do
        if grep -q "$profile" "$HOME/.codex/config.toml" 2>/dev/null; then
            ((profiles_found++))
        fi
    done

    if [ "$profiles_found" -eq "${#profiles[@]}" ]; then
        test_result "Codex Profiles" "PASS" "$profiles_found perfiles especializados configurados"
    else
        test_result "Codex Profiles" "FAIL" "$profiles_found/${#profiles[@]} perfiles encontrados"
    fi
}

# Función de prueba de performance
test_performance_metrics() {
    echo -e "${BLUE}⚡ Probando métricas de performance...${NC}"

    # Verificar que el sistema responde en tiempo razonable
    local start_time=$(date +%s.%3N)

    # Prueba simple de Python
    python3 -c "print('test')" >/dev/null 2>&1

    local end_time=$(date +%s.%3N)
    local response_time=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")

    if (( $(echo "$response_time < 1.0" | bc -l 2>/dev/null || echo "1") )); then
        test_result "System Response Time" "PASS" "Tiempo de respuesta: ${response_time}s (< 1s)"
    else
        test_result "System Response Time" "FAIL" "Tiempo de respuesta lento: ${response_time}s"
    fi

    # Verificar espacio en disco
    local available_space=$(df "$HOME" | tail -1 | awk '{print $4}')
    local min_space=$((1024*1024))  # 1GB en KB

    if [ "$available_space" -gt "$min_space" ]; then
        test_result "Disk Space" "PASS" "Espacio disponible suficiente"
    else
        test_result "Disk Space" "FAIL" "Espacio en disco insuficiente"
    fi
}

# Función de reporte final
generate_final_report() {
    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 📊 REPORTE FINAL DE PRUEBAS ENTERPRISE                                    ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    local percentage=$((TESTS_PASSED * 100 / TESTS_TOTAL))

    echo -e "${CYAN}📈 Resultados Generales:${NC}"
    echo -e "   Tests ejecutados: $TESTS_TOTAL"
    echo -e "   Tests aprobados: $TESTS_PASSED"
    echo -e "   Tests fallidos: $((TESTS_TOTAL - TESTS_PASSED))"
    echo -e "   Porcentaje de éxito: ${percentage}%"
    echo

    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo -e "${RED}❌ Tests Fallidos:${NC}"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo -e "   • $failed_test"
        done
        echo
    fi

    # Calificación final
    if [ $percentage -ge 95 ]; then
        echo -e "${GREEN}🏆 CALIFICACIÓN: EXCELENTE (${percentage}%)${NC}"
        echo -e "${GREEN}✅ Sistema Enterprise completamente funcional${NC}"
    elif [ $percentage -ge 85 ]; then
        echo -e "${YELLOW}⚠️  CALIFICACIÓN: BUENO (${percentage}%)${NC}"
        echo -e "${YELLOW}Algunos componentes requieren atención menor${NC}"
    elif [ $percentage -ge 75 ]; then
        echo -e "${CYAN}📋 CALIFICACIÓN: ACEPTABLE (${percentage}%)${NC}"
        echo -e "${CYAN}Sistema funcional pero con áreas de mejora${NC}"
    else
        echo -e "${RED}❌ CALIFICACIÓN: REQUIERE ATENCIÓN (${percentage}%)${NC}"
        echo -e "${RED}Múltiples componentes necesitan corrección${NC}"
    fi

    echo
    echo -e "${BLUE}📋 Próximos pasos recomendados:${NC}"

    if [ $percentage -ge 95 ]; then
        echo -e "   ${GREEN}✅ Sistema listo para uso enterprise${NC}"
        echo -e "   🎯 Prueba los perfiles especializados: codex --profile odoo-dev 'tarea'"
        echo -e "   📊 Monitorea métricas: bash scripts/validate-enterprise-system.sh status"
    else
        echo -e "   🔧 Revisa los tests fallidos arriba"
        echo -e "   📖 Consulta ENTERPRISE_UPGRADE_PLAN.md para troubleshooting"
        echo -e "   🆘 Ejecuta: bash scripts/enterprise-setup-all.sh (para reinstalar)"
    fi

    echo
    echo -e "${PURPLE}📁 Logs de pruebas: $ENTERPRISE_DIR/testing.log${NC}"

    # Guardar resultados en archivo
    {
        echo "=== REPORTE DE PRUEBAS ENTERPRISE ==="
        echo "Fecha: $(date)"
        echo "Tests Totales: $TESTS_TOTAL"
        echo "Tests Aprobados: $TESTS_PASSED"
        echo "Porcentaje: ${percentage}%"
        echo
        if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
            echo "Tests Fallidos:"
            printf '%s\n' "${FAILED_TESTS[@]}"
        fi
    } >> "$ENTERPRISE_DIR/test_results_$(date +%Y%m%d_%H%M%S).txt"

    log "ENTERPRISE" "Testing completado - Puntuación: ${percentage}% ($TESTS_PASSED/$TESTS_TOTAL)"
}

# Función principal
main() {
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 🧪 PRUEBAS EXHAUSTIVAS SISTEMA ENTERPRISE                                 ║"
    echo "║                                                                            ║"
    echo "║ Probando cada mejora implementada:                                        ║"
    echo "║ • Dependencias y entorno base                                             ║"
    echo "║ • Sistema RAG (Retrieval Augmented Generation)                            ║"
    echo "║ • Memoria persistente multi-capa                                          ║"
    echo "║ • Optimización de modelos enterprise                                       ║"
    echo "║ • Sistema de contexto inteligente                                         ║"
    echo "║ • Integración MCP enterprise                                              ║"
    echo "║ • Base de conocimiento indexada                                           ║"
    echo "║ • Integración con Codex CLI                                               ║"
    echo "║ • Métricas de performance                                                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    log "ENTERPRISE" "Iniciando pruebas exhaustivas del sistema enterprise..."

    # Crear directorio de logs si no existe
    mkdir -p "$ENTERPRISE_DIR"

    # Ejecutar todas las pruebas
    test_dependencies
    echo

    test_rag_system
    echo

    test_memory_system
    echo

    test_model_optimization
    echo

    test_context_system
    echo

    test_mcp_enterprise
    echo

    test_knowledge_base
    echo

    test_codex_integration
    echo

    test_performance_metrics
    echo

    # Generar reporte final
    generate_final_report
}

# Manejo de argumentos
case "${1:-}" in
    "quick")
        # Pruebas rápidas solo de componentes críticos
        echo "Ejecutando pruebas rápidas..."
        test_dependencies
        echo
        test_codex_integration
        echo
        test_performance_metrics
        ;;
    "status")
        echo "Estado de componentes enterprise:"
        echo "- Dependencias: $(python3 -c "import chromadb" 2>/dev/null && echo "✅" || echo "❌") ChromaDB"
        echo "- Vector DB: $([ -d "$HOME/.codex/enterprise/vector-store" ] && echo "✅" || echo "❌") Directorio"
        echo "- Memoria: $([ -f "$HOME/.codex/enterprise/memory-bank/odoo19-memory.db" ] && echo "✅" || echo "❌") Base datos"
        echo "- Contexto: $([ -d "$HOME/.codex/enterprise/context-models" ] && echo "✅" || echo "❌") Modelos"
        echo "- MCP: $([ -d "$HOME/.codex/enterprise/mcp-enterprise" ] && echo "✅" || echo "❌") Configuración"
        ;;
    *)
        main "$@"
        ;;
esac
