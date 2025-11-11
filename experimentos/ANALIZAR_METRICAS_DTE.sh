#!/bin/bash
# Script para analizar métricas de output P4-Deep DTE
# Fecha: 2025-11-11
# Fase 4: Validación Empírica

set -e

PROJECT_DIR="/Users/pedro/Documents/odoo19"
OUTPUT_FILE="$1"

if [ -z "$OUTPUT_FILE" ]; then
    echo "❌ ERROR: Debe proporcionar el archivo de output como argumento"
    echo "Uso: $0 experimentos/auditoria_dte_YYYYMMDD.md"
    exit 1
fi

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "❌ ERROR: Archivo no encontrado: $OUTPUT_FILE"
    exit 1
fi

cd "$PROJECT_DIR"

echo "📊 Analizando métricas de P4-Deep DTE..."
echo "📄 Archivo: $OUTPUT_FILE"
echo ""

# Métrica 1: Conteo de palabras
echo "=== MÉTRICA 1: PALABRAS ==="
PALABRAS=$(wc -w < "$OUTPUT_FILE")
echo "Palabras: $PALABRAS"
if [ $PALABRAS -ge 1020 ] && [ $PALABRAS -le 1725 ]; then
    echo "✅ PASS: Dentro del rango 1,020-1,725 (target 1,200-1,500 ±15%)"
else
    echo "❌ FAIL: Fuera del rango aceptable"
fi
echo ""

# Métrica 2: File references (formato ruta.py:línea)
echo "=== MÉTRICA 2: FILE REFERENCES ==="
FILE_REFS=$(grep -oE '[a-z_/]+\.py:[0-9]+(-[0-9]+)?' "$OUTPUT_FILE" | wc -l | tr -d ' ')
echo "File refs: $FILE_REFS"
if [ $FILE_REFS -ge 30 ]; then
    echo "✅ PASS: ≥30 referencias (target: ≥30)"
else
    echo "❌ FAIL: Menos de 30 referencias"
fi
echo ""

# Métrica 3: Verificaciones (formato V1, V2, etc.)
echo "=== MÉTRICA 3: VERIFICACIONES ==="
VERIFICACIONES=$(grep -cE '^### Verificación V[0-9]' "$OUTPUT_FILE" || echo "0")
echo "Verificaciones: $VERIFICACIONES"
if [ $VERIFICACIONES -ge 6 ]; then
    echo "✅ PASS: ≥6 verificaciones (target: ≥6)"
else
    echo "❌ FAIL: Menos de 6 verificaciones"
fi
echo ""

# Métrica 4: Dimensiones analizadas (A-J)
echo "=== MÉTRICA 4: DIMENSIONES ==="
DIMENSIONES=$(grep -cE '^### [A-J]\)' "$OUTPUT_FILE" || echo "0")
echo "Dimensiones: $DIMENSIONES"
if [ $DIMENSIONES -eq 10 ]; then
    echo "✅ PASS: 10/10 dimensiones (A-J)"
elif [ $DIMENSIONES -ge 6 ]; then
    echo "⚠️  PARCIAL: $DIMENSIONES/10 dimensiones (mínimo aceptable: 6)"
else
    echo "❌ FAIL: Menos de 6 dimensiones"
fi
echo ""

# Métrica 5: Clasificación de prioridad (P0/P1/P2)
echo "=== MÉTRICA 5: PRIORIDADES ==="
P0_COUNT=$(grep -cE '\(P0\)' "$OUTPUT_FILE" || echo "0")
P1_COUNT=$(grep -cE '\(P1\)' "$OUTPUT_FILE" || echo "0")
P2_COUNT=$(grep -cE '\(P2\)' "$OUTPUT_FILE" || echo "0")
echo "P0 (Crítico): $P0_COUNT"
echo "P1 (Alto): $P1_COUNT"
echo "P2 (Medio): $P2_COUNT"
if [ $P0_COUNT -ge 1 ] && [ $P1_COUNT -ge 1 ] && [ $P2_COUNT -ge 1 ]; then
    echo "✅ PASS: Al menos 1 de cada prioridad (P0/P1/P2)"
else
    echo "❌ FAIL: Falta alguna clasificación de prioridad"
fi
echo ""

# Métrica 6: Términos técnicos únicos (aproximación)
echo "=== MÉTRICA 6: TÉRMINOS TÉCNICOS ==="
TERMINOS_TECNICOS=$(grep -oE '\b(lxml|xmlsec|zeep|SOAP|DTE|SII|CAF|TED|RFC|CVE|async|cron|ORM|PostgreSQL|Redis|FastAPI|Claude|API|webhook|polling|retry|exponential|backoff|schema|XSD|validation|signature|certificate|PEM|base64|SHA256|RSA|AES|TLS|SSL|HTTPS|JSON|XML|UTF-8|ISO-8859-1|Docker|Kubernetes|CI/CD|pytest|unittest|coverage|mypy|pylint|black|flake8|pre-commit|git|GitHub|GitLab|Odoo|Python|JavaScript|TypeScript|React|Vue|Angular|Node\.js|npm|yarn|pip|venv|virtualenv|conda|apt|yum|brew|curl|wget|grep|sed|awk|jq|psql|redis-cli)\b' "$OUTPUT_FILE" | sort -u | wc -l | tr -d ' ')
echo "Términos técnicos únicos: $TERMINOS_TECNICOS"
if [ $TERMINOS_TECNICOS -ge 80 ]; then
    echo "✅ PASS: ≥80 términos técnicos (target: ≥80)"
elif [ $TERMINOS_TECNICOS -ge 60 ]; then
    echo "⚠️  PARCIAL: $TERMINOS_TECNICOS términos (aceptable: ≥60)"
else
    echo "❌ FAIL: Menos de 60 términos técnicos"
fi
echo ""

# Métrica 7: Tablas comparativas
echo "=== MÉTRICA 7: TABLAS COMPARATIVAS ==="
TABLAS=$(grep -cE '^\|.*\|.*\|' "$OUTPUT_FILE" || echo "0")
echo "Tablas: $TABLAS líneas de tabla"
if [ $TABLAS -ge 15 ]; then
    echo "✅ PASS: Múltiples tablas (≥5 tablas estimadas)"
else
    echo "⚠️  REVISAR: Verificar manualmente cantidad de tablas"
fi
echo ""

# Métrica 8: Código/snippets
echo "=== MÉTRICA 8: CÓDIGO/SNIPPETS ==="
CODE_BLOCKS=$(grep -cE '^```' "$OUTPUT_FILE" || echo "0")
CODE_BLOCKS=$((CODE_BLOCKS / 2))  # Dividir por 2 (inicio y fin de bloque)
echo "Bloques de código: $CODE_BLOCKS"
if [ $CODE_BLOCKS -ge 15 ]; then
    echo "✅ PASS: ≥15 snippets de código (target: ≥15)"
elif [ $CODE_BLOCKS -ge 10 ]; then
    echo "⚠️  PARCIAL: $CODE_BLOCKS snippets (aceptable: ≥10)"
else
    echo "❌ FAIL: Menos de 10 snippets de código"
fi
echo ""

# RESUMEN FINAL
echo "═══════════════════════════════════════════"
echo "           RESUMEN DE VALIDACIÓN           "
echo "═══════════════════════════════════════════"
echo ""

SCORE=0
MAX_SCORE=8

[ $PALABRAS -ge 1020 ] && [ $PALABRAS -le 1725 ] && SCORE=$((SCORE + 1))
[ $FILE_REFS -ge 30 ] && SCORE=$((SCORE + 1))
[ $VERIFICACIONES -ge 6 ] && SCORE=$((SCORE + 1))
[ $DIMENSIONES -eq 10 ] && SCORE=$((SCORE + 1))
[ $P0_COUNT -ge 1 ] && [ $P1_COUNT -ge 1 ] && [ $P2_COUNT -ge 1 ] && SCORE=$((SCORE + 1))
[ $TERMINOS_TECNICOS -ge 80 ] && SCORE=$((SCORE + 1))
[ $TABLAS -ge 15 ] && SCORE=$((SCORE + 1))
[ $CODE_BLOCKS -ge 15 ] && SCORE=$((SCORE + 1))

echo "SCORE: $SCORE/$MAX_SCORE"
echo ""

if [ $SCORE -ge 7 ]; then
    echo "🎉 ÉXITO: Cumple con estándares P4-Deep"
    echo "   → Proceder con auditorías restantes (Payroll, AI Service, Financial)"
elif [ $SCORE -ge 5 ]; then
    echo "⚠️  PARCIAL: Requiere ajustes menores"
    echo "   → Revisar métricas fallidas y ajustar template"
else
    echo "❌ REQUIERE MEJORA: Múltiples criterios no cumplidos"
    echo "   → Ajustar template P4-Deep y re-ejecutar"
fi
echo ""

echo "📋 Próximos pasos:"
echo "1. Revisar output manualmente: code $OUTPUT_FILE"
echo "2. Validar contra checklist: code docs/prompts_desarrollo/templates/checklist_calidad_p4.md"
echo "3. Si score ≥7: Ejecutar auditorías restantes"
echo "4. Si score <7: Ajustar template y re-ejecutar"
echo ""

# Calcular especificidad (requiere script Python)
if [ -f "experimentos/analysis/analyze_response.py" ]; then
    echo "=== MÉTRICA 9: ESPECIFICIDAD (Python) ==="
    .venv/bin/python3 experimentos/analysis/analyze_response.py \
        "$OUTPUT_FILE" \
        audit_dte \
        P4-Deep || echo "⚠️  Script de análisis no disponible aún"
    echo ""
fi
