#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Test Todos los Modelos Disponibles: Copilot CLI y Codex CLI
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

OUTPUT_DIR="docs/prompts/06_outputs/2025-11/benchmarks"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}[TEST]${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

# Modelos Copilot CLI
declare -a COPILOT_MODELS=(
    "claude-sonnet-4.5"
    "claude-sonnet-4"
    "claude-haiku-4.5"
    "gpt-5"
)

# Modelos Codex CLI (verificar cuáles están disponibles)
declare -a CODEX_MODELS=(
    "gpt-5-codex"
    "gpt-4-turbo"
    "o3"
    "o1"
)

# Test modelo Copilot
test_copilot_model() {
    local model=$1
    local output="$OUTPUT_DIR/${TIMESTAMP}_copilot_${model//-/_}.txt"
    
    log "Copilot CLI - Modelo: $model"
    
    local prompt="Responde en máximo 2 oraciones: ¿Cuál es la diferencia entre t-esc y t-out en Odoo 19?"
    
    local start=$(date +%s.%N)
    
    if copilot -p "$prompt" --model "$model" --allow-all-tools --allow-all-paths > "$output" 2>&1; then
        local end=$(date +%s.%N)
        local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
        local words=$(wc -w < "$output" 2>/dev/null | tr -d ' ' || echo "0")
        local api_time=$(grep "Total duration (API):" "$output" 2>/dev/null | awk '{print $4}' || echo "N/A")
        local tokens=$(grep -A 1 "Usage by model:" "$output" 2>/dev/null | tail -1 | awk '{print $2, $3}' || echo "N/A")
        
        if [ "$words" -lt 5 ]; then
            error "Output muy corto ($words palabras)"
            cat "$output" | tail -5
        else
            success "${duration}s (API: ${api_time}s), $words palabras, tokens: $tokens"
        fi
        
        echo "copilot|$model|$duration|$words|$api_time|$tokens" >> "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv"
    else
        error "Falló"
        cat "$output" | tail -10
        echo "copilot|$model|ERROR|0|N/A|N/A" >> "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv"
    fi
}

# Test modelo Codex
test_codex_model() {
    local model=$1
    local output="$OUTPUT_DIR/${TIMESTAMP}_codex_${model//-/_}.txt"
    
    log "Codex CLI - Modelo: $model"
    
    local prompt="Responde en máximo 2 oraciones: ¿Cuál es la diferencia entre t-esc y t-out en Odoo 19?"
    
    local start=$(date +%s.%N)
    
    if codex exec -m "$model" "$prompt" > "$output" 2>&1; then
        local end=$(date +%s.%N)
        local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
        local words=$(wc -w < "$output" 2>/dev/null | tr -d ' ' || echo "0")
        local tokens=$(grep "tokens used" "$output" 2>/dev/null | awk '{print $3}' || echo "N/A")
        
        if [ "$words" -lt 5 ]; then
            error "Output muy corto ($words palabras)"
            cat "$output" | tail -5
        else
            success "${duration}s, $words palabras, tokens: $tokens"
        fi
        
        echo "codex|$model|$duration|$words|N/A|$tokens" >> "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv"
    else
        error "Falló o modelo no disponible"
        cat "$output" | tail -10
        echo "codex|$model|ERROR|0|N/A|N/A" >> "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv"
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "🧪 Test Todos los Modelos: Copilot CLI y Codex CLI"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Inicializar CSV
echo "cli|model|duration|words|api_time|tokens" > "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv"

# Test Copilot CLI - Todos los modelos
echo "═══════════════════════════════════════════════════════════════"
echo "COPILOT CLI - Modelos Disponibles"
echo "═══════════════════════════════════════════════════════════════"
echo ""

for model in "${COPILOT_MODELS[@]}"; do
    test_copilot_model "$model"
    sleep 2
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "CODEX CLI - Modelos Disponibles"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Test Codex CLI - Todos los modelos
for model in "${CODEX_MODELS[@]}"; do
    test_codex_model "$model"
    sleep 2
done

# Generar reporte
echo ""
log "Generando reporte..."

cat > "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md" << 'REPORT_EOF'
# 🧪 Test Todos los Modelos: Copilot CLI y Codex CLI

**Fecha:** TIMESTAMP_PLACEHOLDER

---

## 📊 Copilot CLI - Modelos Probados

| Modelo | Duración (s) | API Time (s) | Palabras | Tokens |
|--------|--------------|--------------|----------|--------|
TABLE_COPILOT_PLACEHOLDER

---

## 📊 Codex CLI - Modelos Probados

| Modelo | Duración (s) | Palabras | Tokens |
|--------|--------------|----------|--------|
TABLE_CODEX_PLACEHOLDER

---

## 📈 Análisis Comparativo

### Rapidez por Modelo

**Copilot CLI:**
- Más rápido: FASTEST_COPILOT_PLACEHOLDER
- Más lento: SLOWEST_COPILOT_PLACEHOLDER

**Codex CLI:**
- Más rápido: FASTEST_CODEX_PLACEHOLDER
- Más lento: SLOWEST_CODEX_PLACEHOLDER

---

## 🎯 Recomendaciones

### Para Consultas Rápidas
**Recomendado:** RECOMMENDED_FAST_PLACEHOLDER

### Para Análisis Profundos
**Recomendado:** RECOMMENDED_DEEP_PLACEHOLDER

---

**Generado:** TIMESTAMP_PLACEHOLDER
REPORT_EOF

# Procesar datos y generar tablas
if [ -f "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" ]; then
    # Tabla Copilot
    COPILOT_TABLE=$(grep "^copilot" "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" | awk -F'|' '{printf "| %s | %.2f | %s | %s | %s |\n", $2, $3, $5, $4, $6}')
    sed -i '' "s|TABLE_COPILOT_PLACEHOLDER|$COPILOT_TABLE|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
    
    # Tabla Codex
    CODEX_TABLE=$(grep "^codex" "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" | awk -F'|' '{printf "| %s | %.2f | %s | %s |\n", $2, $3, $4, $6}')
    sed -i '' "s|TABLE_CODEX_PLACEHOLDER|$CODEX_TABLE|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
    
    # Más rápido/más lento
    FASTEST_COPILOT=$(grep "^copilot" "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" | awk -F'|' '{print $3, $2}' | sort -n | head -1 | awk '{print $2 " (" $1 "s)"}')
    SLOWEST_COPILOT=$(grep "^copilot" "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" | awk -F'|' '{print $3, $2}' | sort -rn | head -1 | awk '{print $2 " (" $1 "s)"}')
    
    FASTEST_CODEX=$(grep "^codex" "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" | awk -F'|' '{print $3, $2}' | sort -n | head -1 | awk '{print $2 " (" $1 "s)"}')
    SLOWEST_CODEX=$(grep "^codex" "$OUTPUT_DIR/${TIMESTAMP}_all_models.csv" | awk -F'|' '{print $3, $2}' | sort -rn | head -1 | awk '{print $2 " (" $1 "s)"}')
    
    sed -i '' "s|FASTEST_COPILOT_PLACEHOLDER|$FASTEST_COPILOT|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
    sed -i '' "s|SLOWEST_COPILOT_PLACEHOLDER|$SLOWEST_COPILOT|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
    sed -i '' "s|FASTEST_CODEX_PLACEHOLDER|$FASTEST_CODEX|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
    sed -i '' "s|SLOWEST_CODEX_PLACEHOLDER|$SLOWEST_CODEX|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
fi

sed -i '' "s|TIMESTAMP_PLACEHOLDER|$(date +%Y-%m-%d\ %H:%M:%S)|g" "$OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"

success "Reporte generado: $OUTPUT_DIR/${TIMESTAMP}_ALL_MODELS_REPORT.md"
echo ""
echo "═══════════════════════════════════════════════════════════════"
success "Test completado"

