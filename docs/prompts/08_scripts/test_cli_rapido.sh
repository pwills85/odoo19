#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CLI Quick Benchmark - Pruebas Rápidas (30 segundos por CLI)
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

OUTPUT_DIR="docs/prompts/06_outputs/2025-11/benchmarks"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[TEST]${NC} $1"; }

# Test rápido de rapidez
test_rapidez() {
    local cli=$1
    local model=$2
    local output="$OUTPUT_DIR/${TIMESTAMP}_rapidez_${cli}_${model}.txt"
    
    log "Rapidez: $cli ($model)"
    local prompt="Diferencia entre t-esc y t-out en Odoo 19. Máximo 2 oraciones."
    
    local start=$(date +%s.%N)
    case "$cli" in
        "gemini")
            gemini -m "$model" --yolo "$prompt" > "$output" 2>&1 || true
            ;;
        "copilot")
            timeout 10 copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output" 2>&1 || true
            ;;
        "codex")
            timeout 10 codex exec "$prompt" > "$output" 2>&1 || true
            ;;
    esac
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
    local words=$(wc -w < "$output" 2>/dev/null || echo "0")
    
    echo "$cli|$model|$duration|$words" >> "$OUTPUT_DIR/${TIMESTAMP}_rapidez.csv"
    echo -e "${GREEN}✓${NC} ${duration}s, $words palabras"
}

# Test rápido de inteligencia (solo lectura archivo)
test_inteligencia() {
    local cli=$1
    local model=$2
    local output="$OUTPUT_DIR/${TIMESTAMP}_inteligencia_${cli}_${model}.md"
    
    log "Inteligencia: $cli ($model)"
    local prompt="Lee addons/localization/l10n_cl_dte/models/account_move.py línea 50-100 y resume qué hace esa función en 3 líneas."
    
    local start=$(date +%s.%N)
    case "$cli" in
        "gemini")
            gemini -m "$model" --yolo --sandbox --allowed-tools read_file \
                "$prompt" > "$output" 2>&1 || true
            ;;
        "copilot")
            timeout 15 copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output" 2>&1 || true
            ;;
        "codex")
            timeout 15 codex exec "$prompt" --sandbox-access read-only > "$output" 2>&1 || true
            ;;
    esac
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.py:[0-9]+" "$output" 2>/dev/null | wc -l || echo "0")
    
    echo "$cli|$model|$duration|$file_refs" >> "$OUTPUT_DIR/${TIMESTAMP}_inteligencia.csv"
    echo -e "${GREEN}✓${NC} ${duration}s, $file_refs referencias"
}

# Test rápido de locuacidad
test_locuacidad() {
    local cli=$1
    local model=$2
    local output="$OUTPUT_DIR/${TIMESTAMP}_locuacidad_${cli}_${model}.md"
    
    log "Locuacidad: $cli ($model)"
    local prompt="Lista los 5 modelos principales en addons/localization/l10n_cl_dte/models/ y explica brevemente qué hace cada uno."
    
    local start=$(date +%s.%N)
    case "$cli" in
        "gemini")
            gemini -m "$model" --yolo --sandbox --allowed-tools read_file,list_dir \
                "$prompt" > "$output" 2>&1 || true
            ;;
        "copilot")
            timeout 20 copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output" 2>&1 || true
            ;;
        "codex")
            timeout 20 codex exec "$prompt" --sandbox-access read-only > "$output" 2>&1 || true
            ;;
    esac
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
    local words=$(wc -w < "$output" 2>/dev/null || echo "0")
    local file_refs=$(grep -oE "[a-zA-Z0-9_/]+\.py" "$output" 2>/dev/null | wc -l || echo "0")
    local density=$(echo "scale=2; $file_refs * 100 / ($words + 1)" | bc 2>/dev/null || echo "0")
    
    echo "$cli|$model|$duration|$words|$file_refs|$density" >> "$OUTPUT_DIR/${TIMESTAMP}_locuacidad.csv"
    echo -e "${GREEN}✓${NC} ${duration}s, $words palabras, densidad: ${density}%"
}

# Inicializar CSVs
echo "cli|model|duration|words" > "$OUTPUT_DIR/${TIMESTAMP}_rapidez.csv"
echo "cli|model|duration|file_refs" > "$OUTPUT_DIR/${TIMESTAMP}_inteligencia.csv"
echo "cli|model|duration|words|file_refs|density" > "$OUTPUT_DIR/${TIMESTAMP}_locuacidad.csv"

echo "═══════════════════════════════════════════════════════════════"
echo "🧪 CLI Quick Benchmark - Pruebas Rápidas"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Gemini Flash Lite
log "═══════════════════════════════════════════════════════════════"
log "Gemini Flash Lite"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "gemini" "gemini-2.5-flash-lite"
sleep 1
test_inteligencia "gemini" "gemini-2.5-flash-lite"
sleep 1
test_locuacidad "gemini" "gemini-2.5-flash-lite"
sleep 1

# Gemini Flash
log ""
log "═══════════════════════════════════════════════════════════════"
log "Gemini Flash"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "gemini" "gemini-2.5-flash"
sleep 1
test_inteligencia "gemini" "gemini-2.5-flash"
sleep 1
test_locuacidad "gemini" "gemini-2.5-flash"
sleep 1

# Gemini Pro
log ""
log "═══════════════════════════════════════════════════════════════"
log "Gemini Pro"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "gemini" "gemini-2.5-pro"
sleep 1
test_inteligencia "gemini" "gemini-2.5-pro"
sleep 1
test_locuacidad "gemini" "gemini-2.5-pro"
sleep 1

# Copilot CLI
log ""
log "═══════════════════════════════════════════════════════════════"
log "Copilot CLI"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "copilot" "gpt-4"
sleep 1
test_inteligencia "copilot" "gpt-4"
sleep 1
test_locuacidad "copilot" "gpt-4"
sleep 1

# Codex CLI
log ""
log "═══════════════════════════════════════════════════════════════"
log "Codex CLI"
log "═══════════════════════════════════════════════════════════════"
test_rapidez "codex" "gpt-4-turbo"
sleep 1
test_inteligencia "codex" "gpt-4-turbo"
sleep 1
test_locuacidad "codex" "gpt-4-turbo"

# Generar reporte
log ""
log "Generando reporte..."

cat > "$OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md" << 'REPORT_EOF'
# 🧪 CLI Benchmark Report - Inteligencia, Rapidez, Locuacidad

**Fecha:** TIMESTAMP_PLACEHOLDER

---

## ⚡ Test 1: Rapidez

| CLI | Modelo | Duración (s) | Palabras |
|-----|--------|--------------|----------|
TABLE_RAPIDEZ_PLACEHOLDER

---

## 🧠 Test 2: Inteligencia

| CLI | Modelo | Duración (s) | Referencias |
|-----|--------|--------------|-------------|
TABLE_INTELIGENCIA_PLACEHOLDER

---

## 💬 Test 3: Locuacidad

| CLI | Modelo | Duración (s) | Palabras | Referencias | Densidad (%) |
|-----|--------|--------------|----------|-------------|--------------|
TABLE_LOCUACIDAD_PLACEHOLDER

---

**Generado:** TIMESTAMP_PLACEHOLDER
REPORT_EOF

# Reemplazar placeholders
if [ -f "$OUTPUT_DIR/${TIMESTAMP}_rapidez.csv" ]; then
    RAPIDEZ_TABLE=$(tail -n +2 "$OUTPUT_DIR/${TIMESTAMP}_rapidez.csv" | awk -F'|' '{printf "| %s | %s | %.2f | %s |\n", $1, $2, $3, $4}')
    sed -i '' "s|TABLE_RAPIDEZ_PLACEHOLDER|$RAPIDEZ_TABLE|g" "$OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"
fi

if [ -f "$OUTPUT_DIR/${TIMESTAMP}_inteligencia.csv" ]; then
    INTELIGENCIA_TABLE=$(tail -n +2 "$OUTPUT_DIR/${TIMESTAMP}_inteligencia.csv" | awk -F'|' '{printf "| %s | %s | %.2f | %s |\n", $1, $2, $3, $4}')
    sed -i '' "s|TABLE_INTELIGENCIA_PLACEHOLDER|$INTELIGENCIA_TABLE|g" "$OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"
fi

if [ -f "$OUTPUT_DIR/${TIMESTAMP}_locuacidad.csv" ]; then
    LOCUACIDAD_TABLE=$(tail -n +2 "$OUTPUT_DIR/${TIMESTAMP}_locuacidad.csv" | awk -F'|' '{printf "| %s | %s | %.2f | %s | %s | %.2f |\n", $1, $2, $3, $4, $5, $6}')
    sed -i '' "s|TABLE_LOCUACIDAD_PLACEHOLDER|$LOCUACIDAD_TABLE|g" "$OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"
fi

sed -i '' "s|TIMESTAMP_PLACEHOLDER|$(date +%Y-%m-%d\ %H:%M:%S)|g" "$OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"

echo -e "${GREEN}✅${NC} Benchmark completado: $OUTPUT_DIR/${TIMESTAMP}_BENCHMARK_REPORT.md"

