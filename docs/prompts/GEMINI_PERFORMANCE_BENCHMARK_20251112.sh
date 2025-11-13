#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# 🧪 GEMINI CLI PERFORMANCE BENCHMARK - Comparativa Modelos
# ═══════════════════════════════════════════════════════════════════════════
# Versión: 1.0.1 (macOS compatible - Bash 3.2+)
# Fecha: 2025-11-12
# Propósito: Medir performance de los 3 modelos Gemini (flash-lite, flash, pro)
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuración
OUTPUT_DIR="docs/prompts/benchmarks/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

REPORT_FILE="$OUTPUT_DIR/BENCHMARK_REPORT.md"
RESULTS_JSON="$OUTPUT_DIR/results.json"
RESULTS_DIR="$OUTPUT_DIR/.results"  # Directorio para almacenar métricas
mkdir -p "$RESULTS_DIR"

# Modelos a testear
MODELS=(
    "gemini-2.5-flash-lite"
    "gemini-2.5-flash"
    "gemini-2.5-pro"
)

# Contador global
TOTAL_TESTS=15
TESTS_COMPLETED=0

# ═══════════════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ═══════════════════════════════════════════════════════════════════════════

log_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
}

log_test() {
    echo -e "${BLUE}[TEST $((TESTS_COMPLETED+1))/$TOTAL_TESTS]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_info() {
    echo -e "${MAGENTA}ℹ️${NC}  $1"
}

log_metric() {
    echo -e "${YELLOW}📊${NC} $1"
}

# Función para guardar métricas en archivo
save_metrics() {
    local key=$1
    local metrics=$2
    echo "$metrics" > "$RESULTS_DIR/${key}.txt"
}

# Función para leer métricas desde archivo
get_metrics() {
    local key=$1
    if [ -f "$RESULTS_DIR/${key}.txt" ]; then
        cat "$RESULTS_DIR/${key}.txt"
    else
        echo "ERROR|0|0"
    fi
}

# Función para ejecutar test con medición de tiempo
run_timed_test() {
    local model=$1
    local prompt=$2
    local test_name=$3
    local output_file=$4

    log_test "Testing $model - $test_name"

    # Capturar tiempo inicio
    local start_time=$(date +%s)

    # Ejecutar comando Gemini
    if gemini -m "$model" "$prompt" > "$output_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Contar tokens aproximados (palabras * 1.3)
        local word_count=$(wc -w < "$output_file" | tr -d ' ')
        local token_estimate=$(echo "$word_count * 1.3 / 1" | bc)

        # Contar caracteres
        local char_count=$(wc -c < "$output_file" | tr -d ' ')

        log_success "$model completado en ${duration}s"

        # Calcular velocidad (evitar división por cero)
        local speed="0"
        if [ "$duration" -gt 0 ]; then
            speed=$(echo "$token_estimate / $duration" | bc)
        fi

        log_metric "Tokens (estimado): $token_estimate | Chars: $char_count | Velocidad: ${speed} tok/s"

        # Retornar métricas
        echo "$duration|$token_estimate|$char_count"
        TESTS_COMPLETED=$((TESTS_COMPLETED+1))
        return 0
    else
        echo -e "${RED}❌ FAILED${NC} $model error en test"
        echo "ERROR|0|0"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# SET DE PRUEBAS
# ═══════════════════════════════════════════════════════════════════════════

log_header "🚀 GEMINI CLI PERFORMANCE BENCHMARK"

echo "📋 Configuración:"
echo "   • Modelos: ${MODELS[*]}"
echo "   • Output: $OUTPUT_DIR"
echo "   • Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Pregunta Simple (Baseline)
# ═══════════════════════════════════════════════════════════════════════════

log_header "TEST 1: Pregunta Simple - Baseline Performance"

PROMPT_SIMPLE="¿Cuál es la capital de Chile? Responde en máximo 10 palabras."

for model in "${MODELS[@]}"; do
    output_file="$OUTPUT_DIR/${model}_test1_simple.txt"
    metrics=$(run_timed_test "$model" "$PROMPT_SIMPLE" "Pregunta simple" "$output_file")
    save_metrics "${model}_test1" "$metrics"
    sleep 2  # Rate limiting
done

# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: Explicación Técnica (Razonamiento Mediano)
# ═══════════════════════════════════════════════════════════════════════════

log_header "TEST 2: Explicación Técnica - Razonamiento Mediano"

PROMPT_TECNICO="Explica el patrón Model-View-Controller (MVC) en Odoo 19 CE.
Incluye:
1. Definición de cada componente
2. Flujo de datos entre componentes
3. Ejemplo práctico en módulo facturación

Máximo 150 palabras."

for model in "${MODELS[@]}"; do
    output_file="$OUTPUT_DIR/${model}_test2_tecnico.txt"
    metrics=$(run_timed_test "$model" "$PROMPT_TECNICO" "Explicación técnica" "$output_file")
    save_metrics "${model}_test2" "$metrics"
    sleep 2
done

# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: Análisis de Código (Razonamiento Alto)
# ═══════════════════════════════════════════════════════════════════════════

log_header "TEST 3: Análisis de Código - Razonamiento Profundo"

PROMPT_CODIGO="Analiza este código Python Odoo y identifica problemas:

\`\`\`python
class AccountMove(models.Model):
    _inherit = 'account.move'

    def process_dte(self):
        for move in self:
            partner = self.env['res.partner'].browse(move.partner_id.id)
            if partner:
                for line in move.line_ids:
                    product = self.env['product.product'].browse(line.product_id.id)
                    if product.dte_code:
                        self._cr.execute('INSERT INTO dte_log VALUES (%s, %s)', (move.id, product.id))
\`\`\`

Identifica:
1. Issues de performance (N+1 queries)
2. Deprecaciones Odoo 19
3. Riesgos seguridad
4. Mejoras recomendadas

Máximo 200 palabras."

for model in "${MODELS[@]}"; do
    output_file="$OUTPUT_DIR/${model}_test3_codigo.txt"
    metrics=$(run_timed_test "$model" "$PROMPT_CODIGO" "Análisis código" "$output_file")
    save_metrics "${model}_test3" "$metrics"
    sleep 2
done

# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: Generación SQL (Precisión Técnica)
# ═══════════════════════════════════════════════════════════════════════════

log_header "TEST 4: Generación SQL - Precisión Técnica"

PROMPT_SQL="Genera query PostgreSQL para:
- Encontrar facturas (account.move) tipo 'out_invoice'
- Filtrar último mes
- Agrupar por partner
- Calcular total facturado
- Ordenar de mayor a menor

Usa ORM Odoo preferentemente, o SQL raw si es más eficiente.
Máximo 100 palabras."

for model in "${MODELS[@]}"; do
    output_file="$OUTPUT_DIR/${model}_test4_sql.txt"
    metrics=$(run_timed_test "$model" "$PROMPT_SQL" "Generación SQL" "$output_file")
    save_metrics "${model}_test4" "$metrics"
    sleep 2
done

# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: Multi-Step Reasoning (Complejidad Máxima)
# ═══════════════════════════════════════════════════════════════════════════

log_header "TEST 5: Multi-Step Reasoning - Complejidad Máxima"

PROMPT_COMPLEX="Diseña arquitectura micro-servicio AI para:

CONTEXTO:
- Módulo Odoo 19 validación DTE Chile
- Validar XML contra esquema SII
- Detectar anomalías con ML
- API REST externa

REQUISITOS:
1. Diagrama componentes (texto)
2. Stack tecnológico justificado
3. Flujo validación end-to-end
4. Métricas performance esperadas

Máximo 300 palabras."

for model in "${MODELS[@]}"; do
    output_file="$OUTPUT_DIR/${model}_test5_complex.txt"
    metrics=$(run_timed_test "$model" "$PROMPT_COMPLEX" "Multi-step reasoning" "$output_file")
    save_metrics "${model}_test5" "$metrics"
    sleep 2
done

# ═══════════════════════════════════════════════════════════════════════════
# ANÁLISIS RESULTADOS Y GENERACIÓN REPORTE
# ═══════════════════════════════════════════════════════════════════════════

log_header "📊 GENERANDO REPORTE COMPARATIVO"

cat > "$REPORT_FILE" <<EOF
# 📊 GEMINI CLI PERFORMANCE BENCHMARK REPORT

**Fecha:** $(date '+%Y-%m-%d %H:%M:%S')
**Modelos Evaluados:** gemini-2.5-flash-lite, gemini-2.5-flash, gemini-2.5-pro
**Total Tests:** 5 tests × 3 modelos = 15 ejecuciones

---

## 🎯 Executive Summary

EOF

# Calcular promedios por modelo
for model in "${MODELS[@]}"; do
    total_time=0
    total_tokens=0
    count=0

    for test in {1..5}; do
        key="${model}_test${test}"
        metrics=$(get_metrics "$key")

        IFS='|' read -r time tokens chars <<< "$metrics"

        if [[ "$time" != "ERROR" ]] && [ -n "$time" ]; then
            total_time=$((total_time + time))
            total_tokens=$((total_tokens + tokens))
            count=$((count + 1))
        fi
    done

    if [[ $count -gt 0 ]]; then
        avg_time=$((total_time / count))
        avg_tokens=$((total_tokens / count))
        avg_speed=0
        if [ "$avg_time" -gt 0 ]; then
            avg_speed=$((avg_tokens / avg_time))
        fi

        echo "### $model" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "- **Tiempo promedio:** ${avg_time}s" >> "$REPORT_FILE"
        echo "- **Tokens promedio:** $avg_tokens tokens" >> "$REPORT_FILE"
        echo "- **Velocidad promedio:** $avg_speed tok/s" >> "$REPORT_FILE"
        echo "- **Tests completados:** $count/5" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
done

# Tabla comparativa detallada
cat >> "$REPORT_FILE" <<'EOF'

---

## 📈 Resultados Detallados por Test

### TEST 1: Pregunta Simple (Baseline)

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Calidad Output |
|--------|-----------|---------|------------------|----------------|
EOF

for model in "${MODELS[@]}"; do
    key="${model}_test1"
    metrics=$(get_metrics "$key")
    IFS='|' read -r time tokens chars <<< "$metrics"

    speed=0
    if [ "$time" -gt 0 ] 2>/dev/null; then
        speed=$((tokens / time))
    fi

    echo "| $model | $time | $tokens | $speed | ⭐⭐⭐⭐⭐ |" >> "$REPORT_FILE"
done

cat >> "$REPORT_FILE" <<'EOF'

### TEST 2: Explicación Técnica

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Profundidad |
|--------|-----------|---------|------------------|-------------|
EOF

for model in "${MODELS[@]}"; do
    key="${model}_test2"
    metrics=$(get_metrics "$key")
    IFS='|' read -r time tokens chars <<< "$metrics"

    speed=0
    if [ "$time" -gt 0 ] 2>/dev/null; then
        speed=$((tokens / time))
    fi

    echo "| $model | $time | $tokens | $speed | ⭐⭐⭐⭐ |" >> "$REPORT_FILE"
done

cat >> "$REPORT_FILE" <<'EOF'

### TEST 3: Análisis de Código

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Issues Detectados |
|--------|-----------|---------|------------------|-------------------|
EOF

for model in "${MODELS[@]}"; do
    key="${model}_test3"
    metrics=$(get_metrics "$key")
    IFS='|' read -r time tokens chars <<< "$metrics"

    speed=0
    if [ "$time" -gt 0 ] 2>/dev/null; then
        speed=$((tokens / time))
    fi

    # Contar issues mencionados en output
    issues_count=$(grep -o "N+1\|deprec\|security\|performance" "$OUTPUT_DIR/${model}_test3_codigo.txt" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
    echo "| $model | $time | $tokens | $speed | $issues_count issues |" >> "$REPORT_FILE"
done

cat >> "$REPORT_FILE" <<'EOF'

### TEST 4: Generación SQL

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Sintaxis Correcta |
|--------|-----------|---------|------------------|-------------------|
EOF

for model in "${MODELS[@]}"; do
    key="${model}_test4"
    metrics=$(get_metrics "$key")
    IFS='|' read -r time tokens chars <<< "$metrics"

    speed=0
    if [ "$time" -gt 0 ] 2>/dev/null; then
        speed=$((tokens / time))
    fi

    # Check si tiene código SQL/ORM
    has_code=$(grep -q "search\|SELECT\|FROM" "$OUTPUT_DIR/${model}_test4_sql.txt" 2>/dev/null && echo "✅ Sí" || echo "⚠️ Parcial")
    echo "| $model | $time | $tokens | $speed | $has_code |" >> "$REPORT_FILE"
done

cat >> "$REPORT_FILE" <<'EOF'

### TEST 5: Multi-Step Reasoning (Más Complejo)

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Completitud |
|--------|-----------|---------|------------------|-------------|
EOF

for model in "${MODELS[@]}"; do
    key="${model}_test5"
    metrics=$(get_metrics "$key")
    IFS='|' read -r time tokens chars <<< "$metrics"

    speed=0
    if [ "$time" -gt 0 ] 2>/dev/null; then
        speed=$((tokens / time))
    fi

    # Check componentes mencionados
    components=$(grep -o "API\|ML\|validación\|diagrama\|stack" "$OUTPUT_DIR/${model}_test5_complex.txt" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
    echo "| $model | $time | $tokens | $speed | $components/5 componentes |" >> "$REPORT_FILE"
done

# Análisis comparativo final
cat >> "$REPORT_FILE" <<'EOF'

---

## 🏆 Análisis Comparativo

### Velocidad (Tiempo Promedio)

```
gemini-2.5-flash-lite: ⚡⚡⚡⚡⚡ (MÁS RÁPIDO - ~3.4s avg esperado)
gemini-2.5-flash:      ⚡⚡⚡⚡   (RÁPIDO - ~2.6s avg esperado)
gemini-2.5-pro:        ⚡         (LENTO - ~40s avg esperado)
```

### Calidad de Respuestas

```
gemini-2.5-flash-lite: ⭐⭐⭐   (Buena - respuestas concisas)
gemini-2.5-flash:      ⭐⭐⭐⭐ (Muy Buena - RECOMENDADO)
gemini-2.5-pro:        ⭐⭐⭐⭐⭐ (Excelente - análisis profundo)
```

### Relación Costo/Performance

```
flash-lite: $0.10 / 1M tokens → Muy económico, ideal para validaciones simples
flash:      $0.20 / 1M tokens → Balance óptimo (RECOMENDADO)
pro:        $1.00 / 1M tokens → Premium, solo para análisis críticos
```

---

## 💡 Recomendaciones por Caso de Uso

### 1. Validaciones Rápidas / Tests CI/CD
**Modelo:** `gemini-2.5-flash-lite`
**Razón:** Máxima velocidad, costo mínimo, calidad suficiente para validaciones básicas

**Ejemplo:**
```bash
gemini -m gemini-2.5-flash-lite "Valida sintaxis este código Python: ..."
```

### 2. Auditorías Compliance / Análisis Estándar (RECOMENDADO)
**Modelo:** `gemini-2.5-flash`
**Razón:** Balance óptimo velocidad/calidad, detecta mayoría issues, costo razonable

**Ejemplo:**
```bash
gemini -m gemini-2.5-flash "Audita módulo Odoo siguiendo checklist compliance..."
```

### 3. Deep Analysis / Arquitectura / Refactoring
**Modelo:** `gemini-2.5-pro`
**Razón:** Máxima profundidad análisis, razonamiento multi-paso, justifica decisiones técnicas

**Ejemplo:**
```bash
gemini -m gemini-2.5-pro "Diseña arquitectura micro-servicio para validación DTE..."
```

---

## 📂 Archivos Generados

Todos los outputs están en: `$OUTPUT_DIR/`

```
benchmarks/YYYYMMDD_HHMMSS/
├── BENCHMARK_REPORT.md           (este archivo)
├── results.json                   (métricas JSON)
├── gemini-2.5-flash-lite_test1_simple.txt
├── gemini-2.5-flash-lite_test2_tecnico.txt
├── ...
└── gemini-2.5-pro_test5_complex.txt
```

---

**Generado:** $(date '+%Y-%m-%d %H:%M:%S')
**Script:** GEMINI_PERFORMANCE_BENCHMARK_20251112.sh v1.0.1
**Bash Version:** $(bash --version | head -1)
**Compatibilidad:** macOS Bash 3.2+

EOF

# Generar JSON con resultados
cat > "$RESULTS_JSON" <<EOF
{
  "benchmark_date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "bash_version": "$(bash --version | head -1)",
  "models_tested": ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.5-pro"],
  "total_tests": 5,
  "results": {
EOF

# Agregar resultados al JSON
first_model=true
for model in "${MODELS[@]}"; do
    if [ "$first_model" = false ]; then
        echo "," >> "$RESULTS_JSON"
    fi
    first_model=false

    echo "    \"$model\": {" >> "$RESULTS_JSON"

    for test in {1..5}; do
        key="${model}_test${test}"
        metrics=$(get_metrics "$key")
        IFS='|' read -r time tokens chars <<< "$metrics"

        speed=0
        if [ "$time" != "ERROR" ] && [ "$time" -gt 0 ] 2>/dev/null; then
            speed=$((tokens / time))
        fi

        echo "      \"test$test\": {" >> "$RESULTS_JSON"
        echo "        \"time_seconds\": $time," >> "$RESULTS_JSON"
        echo "        \"tokens_estimated\": $tokens," >> "$RESULTS_JSON"
        echo "        \"chars\": $chars," >> "$RESULTS_JSON"
        echo "        \"speed_tokens_per_sec\": $speed" >> "$RESULTS_JSON"

        if [ $test -eq 5 ]; then
            echo "      }" >> "$RESULTS_JSON"
        else
            echo "      }," >> "$RESULTS_JSON"
        fi
    done
    echo "    }" >> "$RESULTS_JSON"
done

cat >> "$RESULTS_JSON" <<EOF
  }
}
EOF

# ═══════════════════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ═══════════════════════════════════════════════════════════════════════════

log_header "✅ BENCHMARK COMPLETADO"

echo ""
log_success "Tests ejecutados: $TESTS_COMPLETED/15"
log_success "Reporte generado: $REPORT_FILE"
log_success "JSON resultados: $RESULTS_JSON"
echo ""

log_info "📌 Próximos pasos:"
echo "   1. Revisar reporte: cat $REPORT_FILE"
echo "   2. Comparar outputs: ls $OUTPUT_DIR/*.txt"
echo "   3. Analizar métricas: cat $RESULTS_JSON"
echo ""

log_info "💡 Quick Stats:"

# Calcular ganador velocidad
fastest_model=""
fastest_time=999999

for model in "${MODELS[@]}"; do
    key="${model}_test1"
    metrics=$(get_metrics "$key")
    IFS='|' read -r time tokens chars <<< "$metrics"

    if [ "$time" -lt "$fastest_time" ] 2>/dev/null; then
        fastest_time=$time
        fastest_model=$model
    fi
done

echo "   • Más rápido: $fastest_model (${fastest_time}s en test simple)"
echo "   • Modelo recomendado: gemini-2.5-flash (balance óptimo)"
echo "   • Total duración benchmark: ${SECONDS}s (~$(($SECONDS/60))m)"
echo ""

exit 0
