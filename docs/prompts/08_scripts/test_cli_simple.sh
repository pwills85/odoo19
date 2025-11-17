#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CLI Simple Benchmark - Pruebas Rápidas de Inteligencia, Rapidez, Locuacidad
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

OUTPUT_DIR="docs/prompts/06_outputs/2025-11/benchmarks"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: RAPIDEZ - Pregunta Simple
# ══════════════════════════════════════════════════════════════════════════════

test_rapidez() {
    local cli=$1
    local model=$2
    local output_file="$OUTPUT_DIR/${TIMESTAMP}_rapidez_${cli}_${model}.txt"
    
    log "Test Rapidez: $cli ($model)"
    
    local prompt="¿Cuál es la diferencia entre t-esc y t-out en Odoo 19? Responde en máximo 3 oraciones."
    
    local start=$(date +%s.%N)
    
    case "$cli" in
        "gemini")
            gemini -m "$model" --yolo "$prompt" > "$output_file" 2>&1
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    local words=$(wc -w < "$output_file" 2>/dev/null || echo "0")
    
    echo "$cli|$model|$duration|$words" >> "$OUTPUT_DIR/${TIMESTAMP}_rapidez_results.csv"
    
    echo -e "${GREEN}✓${NC} $cli ($model): ${duration}s, $words palabras"
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: INTELIGENCIA - Compliance Check
# ══════════════════════════════════════════════════════════════════════════════

test_inteligencia() {
    local cli=$1
    local model=$2
    local output_file="$OUTPUT_DIR/${TIMESTAMP}_inteligencia_${cli}_${model}.md"
    
    log "Test Inteligencia: $cli ($model)"
    
    local prompt="Analiza addons/localization/l10n_cl_dte/models/account_move.py y detecta deprecaciones Odoo 19:
- Busca t-esc (debe ser t-out)
- Busca type='json' (debe ser type='jsonrpc')
- Busca self._cr (debe ser self.env.cr)
Lista hallazgos con archivo:línea específicos."

    local start=$(date +%s.%N)
    
    case "$cli" in
        "gemini")
            gemini -m "$model" --yolo --sandbox --allowed-tools read_file,grep \
                "$prompt" > "$output_file" 2>&1 || true
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" --sandbox-access read-only > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.py:[0-9]+" "$output_file" 2>/dev/null | wc -l || echo "0")
    local deprecations=$(grep -ciE "t-esc|type='json'|self\._cr" "$output_file" 2>/dev/null || echo "0")
    
    echo "$cli|$model|$duration|$file_refs|$deprecations" >> "$OUTPUT_DIR/${TIMESTAMP}_inteligencia_results.csv"
    
    echo -e "${GREEN}✓${NC} $cli ($model): ${duration}s, $file_refs refs, $deprecations deprecaciones"
}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: LOCUACIDAD - Análisis Detallado
# ══════════════════════════════════════════════════════════════════════════════

test_locuacidad() {
    local cli=$1
    local model=$2
    local output_file="$OUTPUT_DIR/${TIMESTAMP}_locuacidad_${cli}_${model}.md"
    
    log "Test Locuacidad: $cli ($model)"
    
    local prompt="Analiza la estructura de addons/localization/l10n_cl_dte/ y genera análisis detallado:
1. Arquitectura (modelos principales)
2. Integraciones (SII, APIs)
3. Patrones diseño
4. Áreas mejora
5. Recomendaciones
Incluye ejemplos código con referencias archivo:línea."

    local start=$(date +%s.%N)
    
    case "$cli" in
        "gemini")
            gemini -m "$model" --yolo --sandbox --allowed-tools read_file,grep,list_dir \
                "$prompt" > "$output_file" 2>&1 || true
            ;;
        "copilot")
            copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output_file" 2>&1 || true
            ;;
        "codex")
            codex exec "$prompt" --sandbox-access read-only > "$output_file" 2>&1 || true
            ;;
    esac
    
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    local words=$(wc -w < "$output_file" 2>/dev/null || echo "0")
    local sections=$(grep -cE "^#|^##" "$output_file" 2>/dev/null || echo "0")
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.(py|xml):[0-9]+" "$output_file" 2>/dev/null | wc -l || echo "0")
    local code_blocks=$(grep -c '\`\`\`' "$output_file" 2>/dev/null || echo "0")
    
    # Densidad útil = referencias / palabras * 100
    local density=$(echo "scale=2; $file_refs * 100 / ($words + 1)" | bc)
    
    echo "$cli|$model|$duration|$words|$sections|$file_refs|$code_blocks|$density" >> "$OUTPUT_DIR/${TIMESTAMP}_locuacidad_results.csv"
    
    echo -e "${GREEN}✓${NC} $cli ($model): ${duration}s, $words palabras, densidad útil: ${density}%"
}

# ══════════════════════════════════════════════════════════════════════════════
# EJECUCIÓN
# ══════════════════════════════════════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════════════════"
echo "🧪 CLI Benchmark Suite - Pruebas de Inteligencia, Rapidez, Locuacidad"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Inicializar CSVs
echo "cli|model|duration|words" > "$OUTPUT_DIR/${TIMESTAMP}_rapidez_results.csv"
echo "cli|model|duration|file_refs|deprecations" > "$OUTPUT_DIR/${TIMESTAMP}_inteligencia_results.csv"
echo "cli|model|duration|words|sections|file_refs|code_blocks|density" > "$OUTPUT_DIR/${TIMESTAMP}_locuacidad_results.csv"

# Gemini Flash Lite
log "═══════════════════════════════════════════════════════════════"
log "Evaluando Gemini Flash Lite"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "gemini" "gemini-2.5-flash-lite"
sleep 1
test_inteligencia "gemini" "gemini-2.5-flash-lite"
sleep 1
test_locuacidad "gemini" "gemini-2.5-flash-lite"
sleep 2

# Gemini Flash
log ""
log "═══════════════════════════════════════════════════════════════"
log "Evaluando Gemini Flash"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "gemini" "gemini-2.5-flash"
sleep 1
test_inteligencia "gemini" "gemini-2.5-flash"
sleep 1
test_locuacidad "gemini" "gemini-2.5-flash"
sleep 2

# Gemini Pro
log ""
log "═══════════════════════════════════════════════════════════════"
log "Evaluando Gemini Pro"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "gemini" "gemini-2.5-pro"
sleep 1
test_inteligencia "gemini" "gemini-2.5-pro"
sleep 1
test_locuacidad "gemini" "gemini-2.5-pro"
sleep 2

# Copilot CLI
log ""
log "═══════════════════════════════════════════════════════════════"
log "Evaluando Copilot CLI"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "copilot" "gpt-4"
sleep 1
test_inteligencia "copilot" "gpt-4"
sleep 1
test_locuacidad "copilot" "gpt-4"
sleep 2

# Codex CLI
log ""
log "═══════════════════════════════════════════════════════════════"
log "Evaluando Codex CLI"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "codex" "gpt-4-turbo"
sleep 1
test_inteligencia "codex" "gpt-4-turbo"
sleep 1
test_locuacidad "codex" "gpt-4-turbo"

# Generar reporte
log ""
log "═══════════════════════════════════════════════════════════════"
log "Generando reporte consolidado"
log "═══════════════════════════════════════════════════════════════"

# Generar reporte markdown
{
    echo "# 🧪 CLI Benchmark Report - Inteligencia, Rapidez, Locuacidad"
    echo ""
    echo "**Fecha:** $(date +%Y-%m-%d\ %H:%M:%S)"
    echo "**Sesión:** $TIMESTAMP"
    echo ""
    echo "---"
    echo ""
    echo "## 📊 Resumen Ejecutivo"
    echo ""
    echo "Este reporte compara el rendimiento de diferentes CLI tools y modelos."
    echo ""
    echo "---"
    echo ""
    echo "## ⚡ Test 1: Rapidez (Latencia Simple)"
    echo ""
    echo "| CLI | Modelo | Duración (s) | Palabras |"
    echo "|-----|--------|--------------|----------|"
    if [ -f "$OUTPUT_DIR/${TIMESTAMP}_rapidez_results.csv" ]; then
        tail -n +2 "$OUTPUT_DIR/${TIMESTAMP}_rapidez_results.csv" | awk -F'|' '{printf "| %s | %s | %.2f | %s |\n", $1, $2, $3, $4}'
    fi
    echo ""
    echo "---"
    echo ""
    echo "## 🧠 Test 2: Inteligencia (Compliance Check)"
    echo ""
    echo "| CLI | Modelo | Duración (s) | Referencias | Deprecaciones |"
    echo "|-----|--------|--------------|-------------|---------------|"
    if [ -f "$OUTPUT_DIR/${TIMESTAMP}_inteligencia_results.csv" ]; then
        tail -n +2 "$OUTPUT_DIR/${TIMESTAMP}_inteligencia_results.csv" | awk -F'|' '{printf "| %s | %s | %.2f | %s | %s |\n", $1, $2, $3, $4, $5}'
    fi
    echo ""
    echo "---"
    echo ""
    echo "## 💬 Test 3: Locuacidad (Análisis Detallado)"
    echo ""
    echo "| CLI | Modelo | Duración (s) | Palabras | Secciones | Referencias | Bloques Código | Densidad Útil (%) |"
    echo "|-----|--------|--------------|----------|-----------|-------------|----------------|-------------------|"
    if [ -f "$OUTPUT_DIR/${TIMESTAMP}_locuacidad_results.csv" ]; then
        tail -n +2 "$OUTPUT_DIR/${TIMESTAMP}_locuacidad_results.csv" | awk -F'|' '{printf "| %s | %s | %.2f | %s | %s | %s | %s | %.2f |\n", $1, $2, $3, $4, $5, $6, $7, $8}'
    fi
    echo ""
    echo "---"
    echo ""
    echo "## 📁 Archivos Generados"
    echo ""
    echo "Todos los outputs están en: $OUTPUT_DIR"
    echo ""
    echo "**Generado:** $(date)"
} > "$OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"

echo -e "${GREEN}✓${NC} Reporte generado: $OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✅ Benchmark completado"
echo "═══════════════════════════════════════════════════════════════"

