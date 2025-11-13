#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Test Específico: Copilot CLI y Codex CLI
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
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

# Test Copilot CLI
test_copilot() {
    local test_name=$1
    local prompt=$2
    local output="$OUTPUT_DIR/${TIMESTAMP}_copilot_${test_name}.txt"
    
    log "Copilot CLI - $test_name"
    
    local start=$(date +%s.%N)
    
    # Intentar con timeout de 30 segundos
    if timeout 30 copilot -p "$prompt" --allow-all-tools --allow-all-paths > "$output" 2>&1; then
        local end=$(date +%s.%N)
        local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
        local words=$(wc -w < "$output" 2>/dev/null || echo "0")
        local lines=$(wc -l < "$output" 2>/dev/null || echo "0")
        
        # Verificar si hay contenido real
        if [ "$words" -lt 5 ]; then
            warn "Output muy corto ($words palabras) - posible error"
            cat "$output" | head -10
        else
            success "${duration}s, $words palabras, $lines líneas"
        fi
        
        echo "copilot|$test_name|$duration|$words|$lines" >> "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv"
    else
        local exit_code=$?
        error "Falló (exit code: $exit_code)"
        cat "$output" | tail -20
        echo "copilot|$test_name|ERROR|0|0" >> "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv"
    fi
}

# Test Codex CLI
test_codex() {
    local test_name=$1
    local prompt=$2
    local output="$OUTPUT_DIR/${TIMESTAMP}_codex_${test_name}.txt"
    
    log "Codex CLI - $test_name"
    
    local start=$(date +%s.%N)
    
    # Intentar con timeout de 30 segundos
    if timeout 30 codex exec "$prompt" > "$output" 2>&1; then
        local end=$(date +%s.%N)
        local duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
        local words=$(wc -w < "$output" 2>/dev/null || echo "0")
        local lines=$(wc -l < "$output" 2>/dev/null || echo "0")
        
        # Verificar si hay contenido real
        if [ "$words" -lt 5 ]; then
            warn "Output muy corto ($words palabras) - posible error"
            cat "$output" | head -10
        else
            success "${duration}s, $words palabras, $lines líneas"
        fi
        
        echo "codex|$test_name|$duration|$words|$lines" >> "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv"
    else
        local exit_code=$?
        error "Falló (exit code: $exit_code)"
        cat "$output" | tail -20
        echo "codex|$test_name|ERROR|0|0" >> "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv"
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "🧪 Test Específico: Copilot CLI y Codex CLI"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Inicializar CSV
echo "cli|test|duration|words|lines" > "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv"

# Verificar instalación
echo "Verificando instalación..."
if command -v copilot >/dev/null 2>&1; then
    success "Copilot CLI instalado: $(copilot --version 2>&1 | head -1)"
else
    error "Copilot CLI no encontrado"
    exit 1
fi

if command -v codex >/dev/null 2>&1; then
    success "Codex CLI instalado: $(codex --version 2>&1 | head -1)"
else
    error "Codex CLI no encontrado"
    exit 1
fi

echo ""

# Test 1: Rapidez - Pregunta Simple
echo "═══════════════════════════════════════════════════════════════"
echo "Test 1: Rapidez (Pregunta Simple)"
echo "═══════════════════════════════════════════════════════════════"

test_copilot "rapidez" "¿Cuál es la diferencia entre t-esc y t-out en Odoo 19? Responde en máximo 3 oraciones."
sleep 2

test_codex "rapidez" "¿Cuál es la diferencia entre t-esc y t-out en Odoo 19? Responde en máximo 3 oraciones."
sleep 2

# Test 2: Inteligencia - Lectura Archivo
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Test 2: Inteligencia (Lectura Archivo)"
echo "═══════════════════════════════════════════════════════════════"

test_copilot "inteligencia" "Lee el archivo addons/localization/l10n_cl_dte/models/account_move.py y resume las primeras 50 líneas en 3 puntos clave."
sleep 2

test_codex "inteligencia" "Lee el archivo addons/localization/l10n_cl_dte/models/account_move.py y resume las primeras 50 líneas en 3 puntos clave."
sleep 2

# Test 3: Locuacidad - Análisis Estructura
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Test 3: Locuacidad (Análisis Estructura)"
echo "═══════════════════════════════════════════════════════════════"

test_copilot "locuacidad" "Lista los archivos principales en addons/localization/l10n_cl_dte/models/ y explica brevemente qué hace cada modelo (máximo 5 modelos)."
sleep 2

test_codex "locuacidad" "Lista los archivos principales en addons/localization/l10n_cl_dte/models/ y explica brevemente qué hace cada modelo (máximo 5 modelos)."
sleep 2

# Generar reporte
echo ""
echo "═══════════════════════════════════════════════════════════════"
log "Generando reporte..."

cat > "$OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md" << 'REPORT_EOF'
# 🧪 Copilot CLI y Codex CLI - Test Comparativo

**Fecha:** TIMESTAMP_PLACEHOLDER

---

## 📊 Resultados

### Test 1: Rapidez (Pregunta Simple)

| CLI | Duración (s) | Palabras | Líneas |
|-----|--------------|----------|--------|
TABLE_RAPIDEZ_PLACEHOLDER

### Test 2: Inteligencia (Lectura Archivo)

| CLI | Duración (s) | Palabras | Líneas |
|-----|--------------|----------|--------|
TABLE_INTELIGENCIA_PLACEHOLDER

### Test 3: Locuacidad (Análisis Estructura)

| CLI | Duración (s) | Palabras | Líneas |
|-----|--------------|----------|--------|
TABLE_LOCUACIDAD_PLACEHOLDER

---

## 📁 Archivos Generados

Todos los outputs están en: `OUTPUT_DIR_PLACEHOLDER`

**Generado:** TIMESTAMP_PLACEHOLDER
REPORT_EOF

# Reemplazar placeholders
if [ -f "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv" ]; then
    RAPIDEZ=$(grep "rapidez" "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv" | awk -F'|' '{printf "| %s | %.2f | %s | %s |\n", $1, $3, $4, $5}')
    INTELIGENCIA=$(grep "inteligencia" "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv" | awk -F'|' '{printf "| %s | %.2f | %s | %s |\n", $1, $3, $4, $5}')
    LOCUACIDAD=$(grep "locuacidad" "$OUTPUT_DIR/${TIMESTAMP}_copilot_codex.csv" | awk -F'|' '{printf "| %s | %.2f | %s | %s |\n", $1, $3, $4, $5}')
    
    sed -i '' "s|TABLE_RAPIDEZ_PLACEHOLDER|$RAPIDEZ|g" "$OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md"
    sed -i '' "s|TABLE_INTELIGENCIA_PLACEHOLDER|$INTELIGENCIA|g" "$OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md"
    sed -i '' "s|TABLE_LOCUACIDAD_PLACEHOLDER|$LOCUACIDAD|g" "$OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md"
fi

sed -i '' "s|TIMESTAMP_PLACEHOLDER|$(date +%Y-%m-%d\ %H:%M:%S)|g" "$OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md"
sed -i '' "s|OUTPUT_DIR_PLACEHOLDER|$OUTPUT_DIR|g" "$OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md"

success "Reporte generado: $OUTPUT_DIR/${TIMESTAMP}_COPILOT_CODEX_REPORT.md"
echo ""
echo "═══════════════════════════════════════════════════════════════"
success "Test completado"

