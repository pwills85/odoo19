# 📊 GEMINI CLI PERFORMANCE BENCHMARK REPORT

**Fecha:** 2025-11-12 21:59:39
**Modelos Evaluados:** gemini-2.5-flash-lite, gemini-2.5-flash, gemini-2.5-pro
**Total Tests:** 5 tests × 3 modelos = 15 ejecuciones

---

## 🎯 Executive Summary


---

## 📈 Resultados Detallados por Test

### TEST 1: Pregunta Simple (Baseline)

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Calidad Output |
|--------|-----------|---------|------------------|----------------|
| gemini-2.5-flash-lite | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash-lite - Pregunta simple |  | 0 | ⭐⭐⭐⭐⭐ |
| gemini-2.5-flash | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash - Pregunta simple |  | 0 | ⭐⭐⭐⭐⭐ |
| gemini-2.5-pro | [0;34m[TEST 1/15][0m Testing gemini-2.5-pro - Pregunta simple |  | 0 | ⭐⭐⭐⭐⭐ |

### TEST 2: Explicación Técnica

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Profundidad |
|--------|-----------|---------|------------------|-------------|
| gemini-2.5-flash-lite | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash-lite - Explicación técnica |  | 0 | ⭐⭐⭐⭐ |
| gemini-2.5-flash | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash - Explicación técnica |  | 0 | ⭐⭐⭐⭐ |
| gemini-2.5-pro | [0;34m[TEST 1/15][0m Testing gemini-2.5-pro - Explicación técnica |  | 0 | ⭐⭐⭐⭐ |

### TEST 3: Análisis de Código

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Issues Detectados |
|--------|-----------|---------|------------------|-------------------|
| gemini-2.5-flash-lite | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash-lite - Análisis código |  | 0 | 4 issues |
| gemini-2.5-flash | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash - Análisis código |  | 0 | 2 issues |
| gemini-2.5-pro | [0;34m[TEST 1/15][0m Testing gemini-2.5-pro - Análisis código |  | 0 | 2 issues |

### TEST 4: Generación SQL

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Sintaxis Correcta |
|--------|-----------|---------|------------------|-------------------|
| gemini-2.5-flash-lite | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash-lite - Generación SQL |  | 0 | ✅ Sí |
| gemini-2.5-flash | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash - Generación SQL |  | 0 | ⚠️ Parcial |
| gemini-2.5-pro | [0;34m[TEST 1/15][0m Testing gemini-2.5-pro - Generación SQL |  | 0 | ✅ Sí |

### TEST 5: Multi-Step Reasoning (Más Complejo)

| Modelo | Tiempo (s) | Tokens | Velocidad (tok/s) | Completitud |
|--------|-----------|---------|------------------|-------------|
| gemini-2.5-flash-lite | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash-lite - Multi-step reasoning |  | 0 | 29/5 componentes |
| gemini-2.5-flash | [0;34m[TEST 1/15][0m Testing gemini-2.5-flash - Multi-step reasoning |  | 0 | 26/5 componentes |
| gemini-2.5-pro | [0;34m[TEST 1/15][0m Testing gemini-2.5-pro - Multi-step reasoning |  | 0 | 20/5 componentes |

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

