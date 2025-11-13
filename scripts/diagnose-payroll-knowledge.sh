#!/bin/bash
# Diagnóstico de Conocimiento Nóminas Chilenas en Codex CLI
# Verifica si el sistema tiene todo el conocimiento necesario

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

check_result() {
    local test_name=$1
    local status=$2
    local details=$3

    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}✅ $test_name${NC}: $details"
    elif [ "$status" = "WARN" ]; then
        echo -e "  ${YELLOW}⚠️  $test_name${NC}: $details"
    else
        echo -e "  ${RED}❌ $test_name${NC}: $details"
    fi
}

echo "🔍 DIAGNÓSTICO COMPLETO: CONOCIMIENTO NÓMINAS CHILENAS EN CODEX CLI"
echo "=================================================================="
echo

# 1. Verificar archivos de conocimiento existentes
echo -e "${BLUE}📚 ANALIZANDO ARCHIVOS DE CONOCIMIENTO...${NC}"

knowledge_files=(
    ".github/agents/knowledge/sii_regulatory_context.md:SII Regulatory Context"
    ".github/agents/knowledge/odoo19_patterns.md:Odoo19 Patterns"
    ".github/agents/knowledge/project_architecture.md:Project Architecture"
    ".github/agents/knowledge/chilean_payroll_regulations.md:Chilean Payroll Regulations"
)

total_files=0
existing_files=0

for file_info in "${knowledge_files[@]}"; do
    IFS=':' read -r file_path description <<< "$file_info"
    ((total_files++))

    if [ -f "$PROJECT_ROOT/$file_path" ]; then
        file_size=$(stat -f%z "$PROJECT_ROOT/$file_path" 2>/dev/null || stat -c%s "$PROJECT_ROOT/$file_path" 2>/dev/null || echo "0")
        check_result "$description" "PASS" "Presente (${file_size} bytes)"
        ((existing_files++))
    else
        check_result "$description" "FAIL" "Faltante"
    fi
done

echo -e "\nArchivos de conocimiento: $existing_files/$total_files"
echo

# 2. Verificar datos regulatorios actualizados
echo -e "${BLUE}📊 VERIFICANDO DATOS REGULATORIOS 2025...${NC}"

regulatory_checks=(
    "addons/localization/l10n_cl_hr_payroll/data/hr_tax_bracket_2025.xml:Tax Brackets 2025"
    "addons/localization/l10n_cl_hr_payroll/data/l10n_cl_legal_caps_2025.xml:Legal Caps 2025"
    "addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_ley21735.xml:Ley 21.735 Pension Reform"
)

regulatory_found=0
total_regulatory=${#regulatory_checks[@]}

for check_info in "${regulatory_checks[@]}"; do
    IFS=':' read -r file_path description <<< "$check_info"

    if [ -f "$PROJECT_ROOT/$file_path" ]; then
        # Verificar que contiene datos 2025
        if grep -q "2025" "$PROJECT_ROOT/$file_path" 2>/dev/null; then
            check_result "$description" "PASS" "Actualizado 2025"
            ((regulatory_found++))
        else
            check_result "$description" "WARN" "Presente pero sin datos 2025"
            ((regulatory_found++))
        fi
    else
        check_result "$description" "FAIL" "Archivo faltante"
    fi
done

echo -e "\nDatos regulatorios: $regulatory_found/$total_regulatory"
echo

# 3. Verificar sistema RAG y vectorización
echo -e "${BLUE}🧠 VERIFICANDO SISTEMA RAG Y VECTORIZACIÓN...${NC}"

# Verificar directorios RAG
rag_checks=(
    ".codex/enterprise/vector-store/:Vector Store Directory"
    ".codex/enterprise/knowledge-index/:Knowledge Index Directory"
    ".codex/enterprise/memory-bank/:Memory Bank Directory"
)

rag_components=0
total_rag=${#rag_checks[@]}

for check_info in "${rag_checks[@]}"; do
    IFS=':' read -r dir_path description <<< "$check_info"

    if [ -d "$HOME/$dir_path" ]; then
        check_result "$description" "PASS" "Presente"
        ((rag_components++))
    else
        check_result "$description" "FAIL" "Faltante - ejecutar setup enterprise"
    fi
done

# Verificar archivos indexados
if [ -f "$HOME/.codex/enterprise/knowledge-index/documents.json" ]; then
    doc_count=$(wc -l < "$HOME/.codex/enterprise/knowledge-index/documents.json" 2>/dev/null || echo "0")
    check_result "Documents Index" "PASS" "$doc_count documentos indexados"
else
    check_result "Documents Index" "FAIL" "Sin ejecutar indexación"
fi

if [ -f "$HOME/.codex/enterprise/knowledge-index/codebase.json" ]; then
    code_count=$(wc -l < "$HOME/.codex/enterprise/knowledge-index/codebase.json" 2>/dev/null || echo "0")
    check_result "Codebase Index" "PASS" "$code_count archivos de código indexados"
else
    check_result "Codebase Index" "FAIL" "Sin ejecutar indexación"
fi

# Verificar vectores
if [ -d "$HOME/.codex/enterprise/vector-store" ]; then
    # Intentar contar vectores con ChromaDB
    vector_count=$(python3 -c "
import os
import chromadb

try:
    client = chromadb.PersistentClient(path=os.path.expanduser('~/.codex/enterprise/vector-store/odoo19-chile.db'))
    collection = client.get_collection('odoo19_knowledge')
    print(collection.count())
except Exception as e:
    print('ERROR')
    " 2>/dev/null || echo "ERROR")

    if [ "$vector_count" != "ERROR" ] && [ "$vector_count" -gt 0 ] 2>/dev/null; then
        check_result "Vector Embeddings" "PASS" "$vector_count vectores generados"
    else
        check_result "Vector Embeddings" "FAIL" "Sin vectores - ejecutar indexación"
    fi
else
    check_result "Vector Embeddings" "FAIL" "Directorio vector store faltante"
fi

echo

# 4. Verificar conocimientos específicos de nóminas
echo -e "${BLUE}💰 VERIFICANDO CONOCIMIENTOS ESPECÍFICOS DE NÓMINAS...${NC}"

payroll_knowledge_checks=(
    "AFP.*10%:AFP 10% obligatorio"
    "tope.*83\.1.*UF:Tope AFP 83.1 UF"
    "ISAPRE.*7%:Salud 7% obligatorio"
    "gratificación.*4\.75.*UTM:Gratificación 4.75 UTM"
    "asignación.*familiar:AFC cálculo"
    "impuesto.*único.*7.*tramos:Impuesto único 7 tramos"
    "Ley.*21\.057:Reforma previsional 2025"
    "cesantía.*0\.6%:Seguro cesantía 0.6%"
)

knowledge_found=0
total_payroll_checks=${#payroll_knowledge_checks[@]}

for check_info in "${payroll_knowledge_checks[@]}"; do
    IFS=':' read -r pattern description <<< "$check_info"

    # Buscar en archivos de conocimiento
    found=false
    for knowledge_file in "${knowledge_files[@]}"; do
        IFS=':' read -r file_path _ <<< "$knowledge_file"
        if [ -f "$PROJECT_ROOT/$file_path" ] && grep -qi "$pattern" "$PROJECT_ROOT/$file_path" 2>/dev/null; then
            found=true
            break
        fi
    done

    # Buscar en archivos de payroll
    if [ "$found" = false ] && [ -f "$PROJECT_ROOT/.github/agents/knowledge/chilean_payroll_regulations.md" ]; then
        if grep -qi "$pattern" "$PROJECT_ROOT/.github/agents/knowledge/chilean_payroll_regulations.md" 2>/dev/null; then
            found=true
        fi
    fi

    if [ "$found" = true ]; then
        check_result "$description" "PASS" "Presente en base de conocimiento"
        ((knowledge_found++))
    else
        check_result "$description" "FAIL" "Faltante en base de conocimiento"
    fi
done

echo -e "\nConocimientos nóminas: $knowledge_found/$total_payroll_checks"
echo

# 5. Verificar perfiles de agentes especializados
echo -e "${BLUE}🤖 VERIFICANDO PERFILES DE AGENTES ESPECIALIZADOS...${NC}"

agent_profiles=(
    "payroll-compliance:Agente cumplimiento nóminas"
    "dte-compliance:Agente cumplimiento DTE"
    "odoo-dev:Agente desarrollo Odoo"
    "test-automation:Agente testing automatizado"
)

agents_configured=0
total_agents=${#agent_profiles[@]}

for profile_info in "${agent_profiles[@]}"; do
    IFS=':' read -r profile_name description <<< "$profile_info"

    if [ -f "$HOME/.codex/config.toml" ] && grep -q "\[$profile_name\]" "$HOME/.codex/config.toml" 2>/dev/null; then
        check_result "$description" "PASS" "Perfil configurado"
        ((agents_configured++))
    else
        check_result "$description" "FAIL" "Perfil faltante"
    fi
done

echo -e "\nPerfiles de agentes: $agents_configured/$total_agents"
echo

# 6. Análisis de brechas y recomendaciones
echo -e "${BLUE}🔍 ANÁLISIS DE BRECHAS Y RECOMENDACIONES${NC}"
echo "=============================================="

# Calcular puntuación general
total_checks=$((total_files + total_regulatory + 4 + total_payroll_checks + total_agents))  # RAG components = 4
passed_checks=$((existing_files + regulatory_found + rag_components + knowledge_found + agents_configured))

if [ $passed_checks -gt 0 ] 2>/dev/null; then
    percentage=$((passed_checks * 100 / total_checks))
else
    percentage=0
fi

echo -e "${CYAN}📊 Puntuación General: $passed_checks/$total_checks ($percentage%)${NC}"
echo

# Determinar estado
if [ $percentage -ge 90 ]; then
    echo -e "${GREEN}🏆 ESTADO: EXCELENTE${NC}"
    echo -e "${GREEN}✅ Codex CLI tiene conocimiento completo de nóminas chilenas 2025${NC}"
elif [ $percentage -ge 75 ]; then
    echo -e "${YELLOW}⚠️  ESTADO: BUENO${NC}"
    echo -e "${YELLOW}Algunos componentes requieren actualización menor${NC}"
elif [ $percentage -ge 50 ]; then
    echo -e "${CYAN}📋 ESTADO: ACEPTABLE${NC}"
    echo -e "${CYAN}Sistema funcional pero con brechas regulatorias${NC}"
else
    echo -e "${RED}❌ ESTADO: CRÍTICO${NC}"
    echo -e "${RED}Faltan conocimientos regulatorios esenciales${NC}"
fi

echo
echo -e "${PURPLE}📋 RECOMENDACIONES PARA COMPLETAR CONOCIMIENTO:${NC}"

if [ $existing_files -lt $total_files ]; then
    echo -e "• ${YELLOW}Crear archivos de conocimiento faltantes${NC}"
fi

if [ $regulatory_found -lt $total_regulatory ]; then
    echo -e "• ${YELLOW}Actualizar datos regulatorios a 2025${NC}"
fi

if [ $rag_components -lt 4 ]; then
    echo -e "• ${YELLOW}Ejecutar configuración RAG enterprise${NC}"
fi

if [ $knowledge_found -lt $total_payroll_checks ]; then
    echo -e "• ${YELLOW}Indexar conocimientos específicos de nóminas${NC}"
fi

if [ $agents_configured -lt $total_agents ]; then
    echo -e "• ${YELLOW}Configurar perfiles de agentes especializados${NC}"
fi

echo
echo -e "${BLUE}🚀 PARA COMPLETAR LA CONFIGURACIÓN:${NC}"
echo "1. bash scripts/enterprise-setup-all.sh"
echo "2. bash scripts/index-knowledge-base.sh"
echo "3. bash scripts/train-context-models.sh"
echo "4. bash scripts/validate-enterprise-system.sh"
echo

log "DIAGNOSTIC" "Diagnóstico completado - Puntuación: $percentage% ($passed_checks/$total_checks)"

echo -e "${CYAN}💡 El sistema tendrá conocimiento experto de:${NC}"
echo "   • Cálculos AFP con topes 83.1 UF"
echo "   • Sistema salud ISAPRE/FONASA 7%"
echo "   • Impuesto único 7 tramos 2025"
echo "   • Gratificación 4.75 UTM tope"
echo "   • Asignación familiar montos 2025"
echo "   • Reforma previsional 2025 (Ley 21.057)"
echo "   • Seguro cesantía 0.6% empleador"
echo "   • APV y AFC con topes actualizados"
