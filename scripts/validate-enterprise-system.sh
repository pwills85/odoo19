#!/bin/bash
# Validación Completa del Sistema Enterprise
# Valida todos los componentes del sistema enterprise

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

# Función de logging
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [$level] $message" >> "$ENTERPRISE_DIR/validation.log"
}

# Función de validación de componentes básicos
validate_core_components() {
    echo -e "${BLUE}🔍 Validando componentes básicos...${NC}"

    local components=(
        "intelligence/knowledge-rag-system.toml:RAG System"
        "memory-bank/persistent-memory-system.toml:Memory System"
        "model-optimization/enterprise-model-system.toml:Model Optimization"
        "context-cache/intelligent-context-system.toml:Context System"
        "mcp-enterprise/mcp-enterprise-integration.toml:MCP Enterprise"
    )

    local passed=0
    local total=${#components[@]}

    for component in "${components[@]}"; do
        IFS=':' read -r file desc <<< "$component"
        if [ -f "$ENTERPRISE_DIR/$file" ]; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${RED}❌ $desc${NC} (Archivo faltante: $file)"
        fi
    done

    echo -e "\nComponentes básicos: $passed/$total"
    return $((total - passed))
}

# Función de validación de dependencias
validate_dependencies() {
    echo -e "${BLUE}📦 Validando dependencias...${NC}"

    local deps=(
        "python3:Python 3"
        "pip3:Pip3"
        "chromadb:ChromaDB"
        "sentence-transformers:Sentence Transformers"
    )

    local passed=0
    local total=${#deps[@]}

    for dep in "${deps[@]}"; do
        IFS=':' read -r cmd desc <<< "$dep"
        if command -v "$cmd" &> /dev/null; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${RED}❌ $desc${NC}"
        fi
    done

    # Verificar paquetes Python específicos
    if python3 -c "import chromadb" 2>/dev/null; then
        echo -e "  ${GREEN}✅ ChromaDB Python${NC}"
        ((passed++))
    else
        echo -e "  ${RED}❌ ChromaDB Python${NC}"
    fi

    if python3 -c "import sentence_transformers" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Sentence Transformers${NC}"
        ((passed++))
    else
        echo -e "  ${RED}❌ Sentence Transformers${NC}"
    fi

    echo -e "\nDependencias: $passed/$((total + 2))"
}

# Función de validación de base de conocimiento
validate_knowledge_base() {
    echo -e "${BLUE}📚 Validando base de conocimiento...${NC}"

    local kb_files=(
        "knowledge-index/documents.json:Documentos indexados"
        "knowledge-index/codebase.json:Base de código indexada"
    )

    local passed=0
    local total=${#kb_files[@]}

    for kb_file in "${kb_files[@]}"; do
        IFS=':' read -r file desc <<< "$kb_file"
        if [ -f "$HOME/.codex/enterprise/$file" ]; then
            local count=$(wc -l < "$HOME/.codex/enterprise/$file" 2>/dev/null || echo "0")
            echo -e "  ${GREEN}✅ $desc${NC} ($count entradas)"
            ((passed++))
        else
            echo -e "  ${RED}❌ $desc${NC} (Archivo faltante)"
        fi
    done

    # Validar base de datos vectorial
    if [ -d "$HOME/.codex/enterprise/vector-store" ]; then
        local vector_count=$(python3 -c "
import chromadb
try:
    client = chromadb.PersistentClient(path='$HOME/.codex/enterprise/vector-store/odoo19-chile.db')
    collection = client.get_collection('odoo19_knowledge')
    print(collection.count())
except:
    print('0')
        " 2>/dev/null || echo "0")

        if [ "$vector_count" -gt 0 ]; then
            echo -e "  ${GREEN}✅ Base de datos vectorial${NC} ($vector_count vectores)"
            ((passed++))
        else
            echo -e "  ${RED}❌ Base de datos vectorial${NC} (Sin vectores)"
        fi
    else
        echo -e "  ${RED}❌ Base de datos vectorial${NC} (Directorio faltante)"
    fi

    echo -e "\nBase de conocimiento: $passed/$((total + 1))"
}

# Función de validación de modelos de contexto
validate_context_models() {
    echo -e "${BLUE}🧠 Validando modelos de contexto...${NC}"

    local model_files=(
        "context-models/code_patterns.json:Patrones de código"
        "context-models/domain_context.json:Contexto de dominio"
        "context-models/relevance_model.json:Modelo de relevancia"
    )

    local passed=0
    local total=${#model_files[@]}

    for model_file in "${model_files[@]}"; do
        IFS=':' read -r file desc <<< "$model_file"
        if [ -f "$HOME/.codex/enterprise/$file" ]; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${RED}❌ $desc${NC} (Archivo faltante)"
        fi
    done

    echo -e "\nModelos de contexto: $passed/$total"
}

# Función de validación de memoria persistente
validate_memory_system() {
    echo -e "${BLUE}🧬 Validando sistema de memoria...${NC}"

    local memory_files=(
        "memory-bank/odoo19-memory.db:Base de datos de memoria"
        "memory-bank/backups/:Directorio de backups"
    )

    local passed=0
    local total=${#memory_files[@]}

    for mem_file in "${memory_files[@]}"; do
        IFS=':' read -r file desc <<< "$mem_file"
        if [ -e "$HOME/.codex/enterprise/$file" ]; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${RED}❌ $desc${NC} (Archivo/directorio faltante)"
        fi
    done

    # Validar tablas de memoria
    if [ -f "$HOME/.codex/enterprise/memory-bank/odoo19-memory.db" ]; then
        local table_count=$(python3 -c "
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

        if [ "$table_count" -gt 0 ]; then
            echo -e "  ${GREEN}✅ Tablas de memoria${NC} ($table_count tablas)"
            ((passed++))
        else
            echo -e "  ${RED}❌ Tablas de memoria${NC} (Sin tablas)"
        fi
    fi

    echo -e "\nSistema de memoria: $passed/$((total + 1))"
}

# Función de validación de optimización de modelos
validate_model_optimization() {
    echo -e "${BLUE}🚀 Validando optimización de modelos...${NC}"

    local opt_files=(
        "model-optimization/metrics/model_performance.json:Métricas de modelos"
    )

    local passed=0
    local total=${#opt_files[@]}

    for opt_file in "${opt_files[@]}"; do
        IFS=':' read -r file desc <<< "$opt_file"
        if [ -f "$HOME/.codex/enterprise/$file" ]; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${YELLOW}⚠️  $desc${NC} (Archivo faltante - se creará en uso)"
        fi
    done

    # Validar configuración de modelos
    if python3 -c "
import toml
try:
    with open('$ENTERPRISE_DIR/model-optimization/enterprise-model-system.toml', 'r') as f:
        config = toml.load(f)
    print('valid')
except:
    print('invalid')
    " 2>/dev/null | grep -q "valid"; then
        echo -e "  ${GREEN}✅ Configuración de modelos válida${NC}"
        ((passed++))
    else
        echo -e "  ${RED}❌ Configuración de modelos inválida${NC}"
    fi

    echo -e "\nOptimización de modelos: $passed/$((total + 1))"
}

# Función de validación de integración MCP
validate_mcp_integration() {
    echo -e "${BLUE}🔗 Validando integración MCP...${NC}"

    local mcp_dirs=(
        "mcp-enterprise/logs/:Logs MCP"
        "mcp-enterprise/metrics/:Métricas MCP"
    )

    local passed=0
    local total=${#mcp_dirs[@]}

    for mcp_dir in "${mcp_dirs[@]}"; do
        IFS=':' read -r dir desc <<< "$mcp_dir"
        if [ -d "$HOME/.codex/enterprise/$dir" ]; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${YELLOW}⚠️  $desc${NC} (Directorio faltante - se creará en uso)"
        fi
    done

    # Validar configuración MCP
    if python3 -c "
import toml
try:
    with open('$ENTERPRISE_DIR/mcp-enterprise/mcp-enterprise-integration.toml', 'r') as f:
        config = toml.load(f)
    servers = config.get('servers_enterprise', {})
    print(f'{len(servers)} servers configured')
except Exception as e:
    print(f'error: {e}')
    " 2>/dev/null | grep -v "error" > /dev/null; then
        local server_count=$(python3 -c "
import toml
with open('$ENTERPRISE_DIR/mcp-enterprise/mcp-enterprise-integration.toml', 'r') as f:
    config = toml.load(f)
servers = config.get('servers_enterprise', {})
print(len(servers))
        " 2>/dev/null || echo "0")

        echo -e "  ${GREEN}✅ Servidores MCP configurados${NC} ($server_count servidores)"
        ((passed++))
    else
        echo -e "  ${RED}❌ Configuración MCP inválida${NC}"
    fi

    echo -e "\nIntegración MCP: $passed/$((total + 1))"
}

# Función de validación de configuración de contexto
validate_context_system() {
    echo -e "${BLUE}🎯 Validando sistema de contexto inteligente...${NC}"

    local context_files=(
        "context-cache/context_cache.json:Cache de contexto"
        "context-cache/versions/:Versiones de contexto"
    )

    local passed=0
    local total=${#context_files[@]}

    for ctx_file in "${context_files[@]}"; do
        IFS=':' read -r file desc <<< "$ctx_file"
        if [ -e "$HOME/.codex/enterprise/$file" ]; then
            echo -e "  ${GREEN}✅ $desc${NC}"
            ((passed++))
        else
            echo -e "  ${YELLOW}⚠️  $desc${NC} (Archivo/directorio faltante - se creará en uso)"
        fi
    done

    echo -e "\nSistema de contexto: $passed/$total"
}

# Función de cálculo de puntuación general
calculate_overall_score() {
    local component_scores=("$@")
    local total_score=0
    local max_score=0

    for score in "${component_scores[@]}"; do
        IFS='/' read -r actual possible <<< "$score"
        total_score=$((total_score + actual))
        max_score=$((max_score + possible))
    done

    local percentage=$((total_score * 100 / max_score))

    echo "$total_score/$max_score ($percentage%)"
}

# Función principal
main() {
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 🔍 VALIDACIÓN COMPLETA SISTEMA ENTERPRISE                                ║"
    echo "║                                                                            ║"
    echo "║ Componentes validados:                                                     ║"
    echo "║ • Componentes básicos                                                      ║"
    echo "║ • Dependencias                                                             ║"
    echo "║ • Base de conocimiento                                                     ║"
    echo "║ • Modelos de contexto                                                      ║"
    echo "║ • Sistema de memoria                                                       ║"
    echo "║ • Optimización de modelos                                                  ║"
    echo "║ • Integración MCP                                                          ║"
    echo "║ • Sistema de contexto                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    log "ENTERPRISE" "Iniciando validación completa del sistema enterprise..."

    # Crear directorio de logs si no existe
    mkdir -p "$ENTERPRISE_DIR"

    # Ejecutar validaciones
    local scores=()

    validate_core_components
    scores+=("$?")

    echo
    validate_dependencies

    echo
    validate_knowledge_base
    scores+=("$?")

    echo
    validate_context_models
    scores+=("$?")

    echo
    validate_memory_system
    scores+=("$?")

    echo
    validate_model_optimization
    scores+=("$?")

    echo
    validate_mcp_integration
    scores+=("$?")

    echo
    validate_context_system
    scores+=("$?")

    # Calcular puntuación general
    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 📊 RESULTADO FINAL DE VALIDACIÓN                                          ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    local overall_score=$(calculate_overall_score "${scores[@]}")
    IFS=' ' read -r score percentage <<< "$overall_score"

    if [ "${percentage%(*}" -ge 90 ]; then
        echo -e "${GREEN}🏆 SISTEMA ENTERPRISE: EXCELENTE${NC}"
        echo -e "${GREEN}Puntuación: $score${NC}"
        echo -e "\n${CYAN}✅ El sistema está listo para uso enterprise${NC}"
    elif [ "${percentage%(*}" -ge 75 ]; then
        echo -e "${YELLOW}⚠️  SISTEMA ENTERPRISE: BUENO${NC}"
        echo -e "${YELLOW}Puntuación: $score${NC}"
        echo -e "\n${YELLOW}Algunos componentes requieren atención${NC}"
    else
        echo -e "${RED}❌ SISTEMA ENTERPRISE: REQUIERE ATENCIÓN${NC}"
        echo -e "${RED}Puntuación: $score${NC}"
        echo -e "\n${RED}Múltiples componentes necesitan configuración${NC}"
    fi

    echo
    echo "📋 Próximos pasos recomendados:"
    if [ "${percentage%(*}" -lt 90 ]; then
        echo "• Ejecutar: bash scripts/enterprise-orchestration-system.sh"
        echo "• Ejecutar: bash scripts/index-knowledge-base.sh"
        echo "• Ejecutar: bash scripts/train-context-models.sh"
    fi
    echo "• Monitorear logs: tail -f ~/.codex/enterprise/validation.log"
    echo "• Ver métricas: cat ~/.codex/enterprise/*/metrics/*.json"

    echo
    log "SUCCESS" "Validación completada - Puntuación: $score"
}

# Manejo de argumentos
case "${1:-}" in
    "status")
        echo "Estado rápido del sistema Enterprise:"
        [ -f "$ENTERPRISE_DIR/intelligence/knowledge-rag-system.toml" ] && echo "✅ RAG System" || echo "❌ RAG System"
        [ -d "$HOME/.codex/enterprise/vector-store" ] && echo "✅ Vector Store" || echo "❌ Vector Store"
        [ -d "$HOME/.codex/enterprise/memory-bank" ] && echo "✅ Memory System" || echo "❌ Memory System"
        [ -d "$HOME/.codex/enterprise/context-models" ] && echo "✅ Context Models" || echo "❌ Context Models"
        ;;
    "logs")
        if [ -f "$ENTERPRISE_DIR/validation.log" ]; then
            tail -20 "$ENTERPRISE_DIR/validation.log"
        else
            echo "No hay logs de validación disponibles"
        fi
        ;;
    *)
        main "$@"
        ;;
esac
