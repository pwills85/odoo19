#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CLI Benchmark Suite - Inteligencia, Rapidez, Locuacidad
# ══════════════════════════════════════════════════════════════════════════════
#
# Evalúa diferentes CLI tools y modelos en:
# - Rapidez (latencia, tiempo total)
# - Inteligencia (calidad output, especificidad, referencias)
# - Locuacidad (cantidad output útil, verbosidad)
# - Costo estimado (tokens, USD)
#
# Versión: 1.0.0
# Fecha: 2025-11-13
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directorios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPTS_DIR="$SCRIPT_DIR/../"
OUTPUTS_DIR="$PROMPTS_DIR/06_outputs/2025-11/benchmarks"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUTS_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN DE PRUEBAS
# ══════════════════════════════════════════════════════════════════════════════

# Tests a ejecutar
declare -a TESTS=(
    "test_rapidez_simple"
    "test_inteligencia_compliance"
    "test_locuacidad_analisis"
    "test_profundidad_arquitectura"
)

# CLI Tools a evaluar
declare -a CLI_TOOLS=(
    "gemini-flash-lite"
    "gemini-flash"
    "gemini-pro"
    "copilot"
    "codex"
)

# ══════════════════════════════════════════════════════════════════════════════
# FUNCIONES UTILITARIAS
# ══════════════════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si CLI está instalado
check_cli_installed() {
    local cli=$1
    case "$cli" in
        "gemini-flash-lite"|"gemini-flash"|"gemini-pro")
            command -v gemini >/dev/null 2>&1 || return 1
            ;;
        "copilot")
            command -v copilot >/dev/null 2>&1 || return 1
            ;;
        "codex")
            command -v codex >/dev/null 2>&1 || return 1
            ;;
        *)
            return 1
            ;;
    esac
}

# Obtener modelo Gemini según CLI tool
get_gemini_model() {
    case "$1" in
        "gemini-flash-lite") echo "gemini-2.5-flash-lite" ;;
        "gemini-flash") echo "gemini-2.5-flash" ;;
        "gemini-pro") echo "gemini-2.5-pro" ;;
        *) echo "" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: RAPIDEZ (Latencia Simple)
# ══════════════════════════════════════════════════════════════════════════════

test_rapidez_simple() {
    local cli_tool=$1
    local output_file="$OUTPUTS_DIR/${TIMESTAMP}_rapidez_${cli_tool}.json"
    
    log_info "Test Rapidez: $cli_tool"
    
    local prompt="¿Cuál es la diferencia entre t-esc y t-out en Odoo 19 QWeb templates? Responde en máximo 50 palabras."
    
    local start_time=$(date +%s.%N)
    
    case "$cli_tool" in
        "gemini-flash-lite"|"gemini-flash"|"gemini-pro")
            local model=$(get_gemini_model "$cli_tool")
            gemini -m "$model" --output-format json --yolo "$prompt" > "$output_file" 2>&1
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" --output-format json > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    # Extraer métricas
    local word_count=$(cat "$output_file" | wc -w 2>/dev/null || echo "0")
    local char_count=$(cat "$output_file" | wc -c 2>/dev/null || echo "0")
    
    echo "{\"cli\": \"$cli_tool\", \"duration\": $duration, \"word_count\": $word_count, \"char_count\": $char_count}" > "$OUTPUTS_DIR/${TIMESTAMP}_rapidez_${cli_tool}_metrics.json"
    
    log_success "Rapidez $cli_tool: ${duration}s"
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: INTELIGENCIA (Compliance Odoo 19)
# ══════════════════════════════════════════════════════════════════════════════

test_inteligencia_compliance() {
    local cli_tool=$1
    local output_file="$OUTPUTS_DIR/${TIMESTAMP}_inteligencia_${cli_tool}.md"
    
    log_info "Test Inteligencia Compliance: $cli_tool"
    
    local prompt="Analiza el archivo addons/localization/l10n_cl_dte/models/account_move.py y detecta deprecaciones Odoo 19 CE.

Busca específicamente:
- t-esc (debe ser t-out)
- type='json' (debe ser type='jsonrpc')
- self._cr (debe ser self.env.cr)
- attrs={} (debe ser Python expressions)

Genera reporte markdown con:
1. Lista de deprecaciones encontradas (archivo:línea)
2. Compliance rate (%)
3. Comandos grep para verificar

Sé específico y proporciona referencias exactas (archivo:línea)."

    local start_time=$(date +%s.%N)
    
    case "$cli_tool" in
        "gemini-flash-lite"|"gemini-flash"|"gemini-pro")
            local model=$(get_gemini_model "$cli_tool")
            gemini -m "$model" --yolo --sandbox --output-format json \
                --allowed-tools read_file,grep,list_dir \
                "$prompt" > "$output_file" 2>&1 || true
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" --sandbox-access read-only > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    # Analizar calidad output
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.py:[0-9]+" "$output_file" 2>/dev/null | wc -l || echo "0")
    local compliance_rate=$(grep -i "compliance\|%" "$output_file" 2>/dev/null | head -1 || echo "N/A")
    local grep_commands=$(grep -c "grep\|command" "$output_file" 2>/dev/null || echo "0")
    
    echo "{\"cli\": \"$cli_tool\", \"duration\": $duration, \"file_refs\": $file_refs, \"compliance_rate\": \"$compliance_rate\", \"grep_commands\": $grep_commands}" > "$OUTPUTS_DIR/${TIMESTAMP}_inteligencia_${cli_tool}_metrics.json"
    
    log_success "Inteligencia $cli_tool: ${duration}s, $file_refs referencias"
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: LOCUACIDAD (Análisis Detallado)
# ══════════════════════════════════════════════════════════════════════════════

test_locuacidad_analisis() {
    local cli_tool=$1
    local output_file="$OUTPUTS_DIR/${TIMESTAMP}_locuacidad_${cli_tool}.md"
    
    log_info "Test Locuacidad: $cli_tool"
    
    local prompt="Analiza la estructura del módulo addons/localization/l10n_cl_dte/ y genera un análisis detallado que incluya:

1. Arquitectura del módulo (modelos principales, herencias)
2. Integraciones externas (SII, APIs)
3. Patrones de diseño utilizados
4. Áreas de mejora identificadas
5. Recomendaciones priorizadas

Sé exhaustivo y proporciona ejemplos de código específicos con referencias (archivo:línea)."

    local start_time=$(date +%s.%N)
    
    case "$cli_tool" in
        "gemini-flash-lite"|"gemini-flash"|"gemini-pro")
            local model=$(get_gemini_model "$cli_tool")
            gemini -m "$model" --yolo --sandbox --output-format json \
                --allowed-tools read_file,grep,list_dir,codebase_search \
                "$prompt" > "$output_file" 2>&1 || true
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" --sandbox-access read-only > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    # Analizar locuacidad
    local word_count=$(cat "$output_file" 2>/dev/null | wc -w || echo "0")
    local char_count=$(cat "$output_file" 2>/dev/null | wc -c || echo "0")
    local sections=$(grep -cE "^#|^##" "$output_file" 2>/dev/null || echo "0")
    local code_blocks=$(grep -c "```" "$output_file" 2>/dev/null || echo "0")
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.(py|xml):[0-9]+" "$output_file" 2>/dev/null | wc -l || echo "0")
    
    # Calcular densidad información útil
    local useful_density=$(echo "scale=2; $file_refs * 100 / ($word_count + 1)" | bc)
    
    echo "{\"cli\": \"$cli_tool\", \"duration\": $duration, \"word_count\": $word_count, \"char_count\": $char_count, \"sections\": $sections, \"code_blocks\": $code_blocks, \"file_refs\": $file_refs, \"useful_density\": $useful_density}" > "$OUTPUTS_DIR/${TIMESTAMP}_locuacidad_${cli_tool}_metrics.json"
    
    log_success "Locuacidad $cli_tool: ${duration}s, $word_count palabras, densidad útil: ${useful_density}%"
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4: PROFUNDIDAD (Análisis Arquitectónico)
# ══════════════════════════════════════════════════════════════════════════════

test_profundidad_arquitectura() {
    local cli_tool=$1
    local output_file="$OUTPUTS_DIR/${TIMESTAMP}_profundidad_${cli_tool}.md"
    
    log_info "Test Profundidad Arquitectura: $cli_tool"
    
    local prompt="Ejecuta una auditoría P4-Deep del módulo addons/localization/l10n_cl_dte/ siguiendo la estrategia en docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md.

Analiza las siguientes dimensiones:
A) Arquitectura y modularidad
B) Patrones diseño Odoo 19
C) Integraciones externas (SII)
D) Seguridad y protección datos
E) Observabilidad
F) Testing
G) Performance
H) Dependencias externas
I) Configuración y deployment
J) Recomendaciones priorizadas

Para cada dimensión:
- Identifica hallazgos específicos (archivo:línea)
- Proporciona verificaciones reproducibles (comandos)
- Prioriza por criticidad (P0/P1/P2)
- Estima esfuerzo de corrección

Genera reporte completo con métricas cuantitativas."

    local start_time=$(date +%s.%N)
    
    case "$cli_tool" in
        "gemini-flash-lite"|"gemini-flash"|"gemini-pro")
            local model=$(get_gemini_model "$cli_tool")
            gemini -m "$model" --yolo --sandbox --output-format json \
                --allowed-tools read_file,grep,list_dir,codebase_search \
                "$prompt" > "$output_file" 2>&1 || true
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" --sandbox-access read-only > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    # Analizar profundidad
    local dimensions=$(grep -cE "^[A-J]\)" "$output_file" 2>/dev/null || echo "0")
    local findings=$(grep -ciE "hallazgo|finding|issue|problema" "$output_file" 2>/dev/null || echo "0")
    local p0_count=$(grep -ciE "P0|crítico|critical" "$output_file" 2>/dev/null || echo "0")
    local p1_count=$(grep -ciE "P1|alto|high" "$output_file" 2>/dev/null || echo "0")
    local verifications=$(grep -cE "```bash|grep|pytest" "$output_file" 2>/dev/null || echo "0")
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.(py|xml|yml):[0-9]+" "$output_file" 2>/dev/null | wc -l || echo "0")
    
    # Calcular especificidad (referencias / palabras)
    local word_count=$(cat "$output_file" 2>/dev/null | wc -w || echo "1")
    local specificity=$(echo "scale=3; $file_refs / ($word_count / 100)" | bc)
    
    echo "{\"cli\": \"$cli_tool\", \"duration\": $duration, \"dimensions\": $dimensions, \"findings\": $findings, \"p0_count\": $p0_count, \"p1_count\": $p1_count, \"verifications\": $verifications, \"file_refs\": $file_refs, \"specificity\": $specificity}" > "$OUTPUTS_DIR/${TIMESTAMP}_profundidad_${cli_tool}_metrics.json"
    
    log_success "Profundidad $cli_tool: ${duration}s, especificidad: ${specificity}, $findings hallazgos"
}

# ══════════════════════════════════════════════════════════════════════════════
# EJECUCIÓN DE PRUEBAS
# ══════════════════════════════════════════════════════════════════════════════

main() {
    log_info "═══════════════════════════════════════════════════════════════════"
    log_info "CLI Benchmark Suite - Iniciando"
    log_info "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    # Verificar CLIs disponibles
    log_info "Verificando CLIs instalados..."
    declare -a available_clis=()
    
    for cli in "${CLI_TOOLS[@]}"; do
        if check_cli_installed "$cli"; then
            available_clis+=("$cli")
            log_success "$cli: Disponible"
        else
            log_warning "$cli: No instalado (se omitirá)"
        fi
    done
    
    if [ ${#available_clis[@]} -eq 0 ]; then
        log_error "No hay CLIs disponibles. Instala al menos uno."
        exit 1
    fi
    
    echo ""
    log_info "CLIs disponibles: ${#available_clis[@]}"
    echo ""
    
    # Ejecutar pruebas para cada CLI disponible
    for cli in "${available_clis[@]}"; do
        log_info "═══════════════════════════════════════════════════════════════"
        log_info "Evaluando: $cli"
        log_info "═══════════════════════════════════════════════════════════════"
        echo ""
        
        # Test 1: Rapidez
        if [[ " ${TESTS[@]} " =~ " test_rapidez_simple " ]]; then
            test_rapidez_simple "$cli" || log_warning "Test rapidez falló para $cli"
            sleep 2  # Pausa entre tests
        fi
        
        # Test 2: Inteligencia
        if [[ " ${TESTS[@]} " =~ " test_inteligencia_compliance " ]]; then
            test_inteligencia_compliance "$cli" || log_warning "Test inteligencia falló para $cli"
            sleep 2
        fi
        
        # Test 3: Locuacidad
        if [[ " ${TESTS[@]} " =~ " test_locuacidad_analisis " ]]; then
            test_locuacidad_analisis "$cli" || log_warning "Test locuacidad falló para $cli"
            sleep 2
        fi
        
        # Test 4: Profundidad
        if [[ " ${TESTS[@]} " =~ " test_profundidad_arquitectura " ]]; then
            test_profundidad_arquitectura "$cli" || log_warning "Test profundidad falló para $cli"
            sleep 2
        fi
        
        echo ""
    done
    
    # Generar reporte consolidado
    log_info "Generando reporte consolidado..."
    generate_consolidated_report
    
    log_success "═══════════════════════════════════════════════════════════════"
    log_success "Benchmark completado"
    log_success "Reportes en: $OUTPUTS_DIR"
    log_success "═══════════════════════════════════════════════════════════════"
}

# ══════════════════════════════════════════════════════════════════════════════
# GENERAR REPORTE CONSOLIDADO
# ══════════════════════════════════════════════════════════════════════════════

generate_consolidated_report() {
    local report_file="$OUTPUTS_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"
    
    cat > "$report_file" << 'EOF'
# 🧪 CLI Benchmark Report - Inteligencia, Rapidez, Locuacidad

**Fecha:** $(date +%Y-%m-%d\ %H:%M:%S)
**Sesión:** $TIMESTAMP

---

## 📊 Resumen Ejecutivo

EOF

    # Agregar métricas consolidadas
    echo "### Métricas por CLI" >> "$report_file"
    echo "" >> "$report_file"
    echo "| CLI | Rapidez (s) | Inteligencia | Locuacidad | Profundidad | Especificidad |" >> "$report_file"
    echo "|-----|-------------|--------------|------------|-------------|---------------|" >> "$report_file"
    
    # Procesar métricas JSON
    for metrics_file in "$OUTPUTS_DIR"/*_metrics.json; do
        if [ -f "$metrics_file" ]; then
            local cli=$(jq -r '.cli' "$metrics_file" 2>/dev/null || echo "unknown")
            local duration=$(jq -r '.duration // "N/A"' "$metrics_file" 2>/dev/null || echo "N/A")
            local file_refs=$(jq -r '.file_refs // 0' "$metrics_file" 2>/dev/null || echo "0")
            local specificity=$(jq -r '.specificity // "N/A"' "$metrics_file" 2>/dev/null || echo "N/A")
            
            echo "| $cli | $duration | $file_refs refs | - | - | $specificity |" >> "$report_file"
        fi
    done
    
    echo "" >> "$report_file"
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## 📁 Archivos Generados" >> "$report_file"
    echo "" >> "$report_file"
    echo "Todos los outputs están en: \`$OUTPUTS_DIR\`" >> "$report_file"
    
    log_success "Reporte generado: $report_file"
}

# Ejecutar main
main "$@"

