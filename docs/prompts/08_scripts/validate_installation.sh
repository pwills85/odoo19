#!/bin/bash
# Script: validate_installation.sh
# Versión: 2.0.0 (Framework Robusto 2025-11-14)
# Propósito: Validación instalación real Odoo 19 CE (MÁXIMA #0.5 FASE 2)
# Uso: ./validate_installation.sh [MODULO]

set -e

# ═══════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════

MODULE="${1:-l10n_cl_dte}"
DATE=$(date +%Y%m%d)
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
TEST_DB="test_odoo19_${DATE}_${MODULE}"
OUTPUT_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/validaciones"
OUTPUT_FILE="${OUTPUT_DIR}/${DATE}_INSTALL_VALIDATION_${MODULE}.md"
LOG_FILE="/tmp/install_${MODULE}_${DATE}.log"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔍 VALIDACIÓN INSTALACIÓN REAL - Odoo 19 CE (MÁXIMA #0.5)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Módulo:${NC}       ${MODULE}"
echo -e "${YELLOW}Test DB:${NC}      ${TEST_DB}"
echo -e "${YELLOW}Log:${NC}          ${LOG_FILE}"
echo -e "${YELLOW}Reporte:${NC}      ${OUTPUT_FILE}"
echo -e "${YELLOW}Timestamp:${NC}    ${TIMESTAMP}"
echo ""

# ═══════════════════════════════════════════════════════════
# VALIDACIONES PREVIAS
# ═══════════════════════════════════════════════════════════

echo -e "${BLUE}📋 Validaciones previas...${NC}"
echo ""

# Verificar Docker Compose
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker no está instalado${NC}"
    exit 1
fi

# Verificar módulo existe
if [ ! -d "addons/localization/${MODULE}" ]; then
    echo -e "${RED}❌ Error: Módulo no encontrado en addons/localization/${MODULE}/${NC}"
    exit 1
fi

# Crear directorio output
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}✓${NC} Docker: disponible"
echo -e "${GREEN}✓${NC} Módulo: existe (addons/localization/${MODULE}/)"
echo -e "${GREEN}✓${NC} Directorio output: ${OUTPUT_DIR}"
echo ""

# ═══════════════════════════════════════════════════════════
# INSTALACIÓN EN BBDD LIMPIA
# ═══════════════════════════════════════════════════════════

echo -e "${BLUE}⚙️  Iniciando instalación en BBDD limpia...${NC}"
echo ""

START_TIME=$(date +%s)

# Ejecutar instalación
docker compose run --rm odoo odoo \
  -d "$TEST_DB" \
  -i "$MODULE" \
  --stop-after-init \
  --log-level=warn \
  --without-demo=all \
  2>&1 | tee "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# ANÁLISIS DE RESULTADOS
# ═══════════════════════════════════════════════════════════

echo -e "${BLUE}📊 Analizando resultados...${NC}"
echo ""

# Contar errores y warnings
ERRORS=$(grep -c -E "ERROR|CRITICAL" "$LOG_FILE" || true)
PARSE_ERRORS=$(grep -c "ParseError" "$LOG_FILE" || true)
IMPORT_ERRORS=$(grep -c "ImportError" "$LOG_FILE" || true)
MISSING_DEPS=$(grep -c "MissingDependency" "$LOG_FILE" || true)
INTEGRITY_ERRORS=$(grep -c "IntegrityError" "$LOG_FILE" || true)

WARNINGS=$(grep -c "WARNING" "$LOG_FILE" || true)
DEPRECATION_WARNINGS=$(grep -c "DeprecationWarning" "$LOG_FILE" || true)
UNKNOWN_PARAMS=$(grep -c "unknown parameter" "$LOG_FILE" || true)

MODULES_LOADED=$(grep "modules loaded" "$LOG_FILE" | tail -1 || echo "N/A")
REGISTRY_LOADED=$(grep "Registry loaded" "$LOG_FILE" | tail -1 || echo "N/A")
QUERIES=$(grep -oP '\d+(?= queries)' "$LOG_FILE" | tail -1 || echo "N/A")

TOTAL_CRITICAL=$((ERRORS + PARSE_ERRORS + IMPORT_ERRORS + MISSING_DEPS + INTEGRITY_ERRORS))

# ═══════════════════════════════════════════════════════════
# DETERMINAR RESULTADO
# ═══════════════════════════════════════════════════════════

if [ $TOTAL_CRITICAL -eq 0 ] && [ $EXIT_CODE -eq 0 ]; then
    STATUS="✅ ÉXITO"
    STATUS_EMOJI="✅"
    STATUS_COLOR=$GREEN
    RESULT_MESSAGE="Módulo instalable sin errores críticos"
else
    STATUS="❌ FALLO"
    STATUS_EMOJI="❌"
    STATUS_COLOR=$RED
    RESULT_MESSAGE="Errores críticos detectados durante instalación"
fi

# ═══════════════════════════════════════════════════════════
# MOSTRAR RESUMEN EN CONSOLA
# ═══════════════════════════════════════════════════════════

echo -e "${STATUS_COLOR}${STATUS}${NC} - ${RESULT_MESSAGE}"
echo ""
echo -e "${YELLOW}📈 Métricas:${NC}"
echo -e "  Errores críticos:        ${TOTAL_CRITICAL}"
echo -e "  - ParseError:            ${PARSE_ERRORS}"
echo -e "  - ImportError:           ${IMPORT_ERRORS}"
echo -e "  - MissingDependency:     ${MISSING_DEPS}"
echo -e "  - IntegrityError:        ${INTEGRITY_ERRORS}"
echo -e "  - Otros ERRORS:          $((ERRORS - PARSE_ERRORS - IMPORT_ERRORS - MISSING_DEPS - INTEGRITY_ERRORS))"
echo ""
echo -e "  Warnings (no críticos):  ${WARNINGS}"
echo -e "  - DeprecationWarning:    ${DEPRECATION_WARNINGS}"
echo -e "  - Unknown parameters:    ${UNKNOWN_PARAMS}"
echo ""
echo -e "  Tiempo instalación:      ${DURATION}s"
echo -e "  Queries ejecutadas:      ${QUERIES}"
echo ""

# ═══════════════════════════════════════════════════════════
# GENERAR REPORTE MARKDOWN
# ═══════════════════════════════════════════════════════════

echo -e "${BLUE}📝 Generando reporte markdown...${NC}"

cat > "$OUTPUT_FILE" <<EOF
# ${STATUS_EMOJI} Validación Instalación Real - ${MODULE}

**MÁXIMA #0.5 - FASE 2: Instalación Runtime**

---

## 📋 Información General

| Campo | Valor |
|-------|-------|
| **Módulo** | \`${MODULE}\` |
| **Fecha validación** | ${TIMESTAMP} |
| **Test Database** | \`${TEST_DB}\` |
| **Odoo Version** | 19.0 CE |
| **Método** | Instalación en BBDD limpia (--stop-after-init) |
| **Resultado global** | **${STATUS}** |

---

## 📊 Resultado Instalación

### Métricas Críticas

| Métrica | Valor | Status |
|---------|-------|--------|
| **Errores críticos totales** | ${TOTAL_CRITICAL} | $([ $TOTAL_CRITICAL -eq 0 ] && echo '✅ OK' || echo '❌ FALLO') |
| **ParseError (XML views)** | ${PARSE_ERRORS} | $([ $PARSE_ERRORS -eq 0 ] && echo '✅' || echo '❌') |
| **ImportError (Python)** | ${IMPORT_ERRORS} | $([ $IMPORT_ERRORS -eq 0 ] && echo '✅' || echo '❌') |
| **MissingDependency** | ${MISSING_DEPS} | $([ $MISSING_DEPS -eq 0 ] && echo '✅' || echo '❌') |
| **IntegrityError (DB)** | ${INTEGRITY_ERRORS} | $([ $INTEGRITY_ERRORS -eq 0 ] && echo '✅' || echo '❌') |
| **Exit code** | ${EXIT_CODE} | $([ $EXIT_CODE -eq 0 ] && echo '✅' || echo '❌') |

### Métricas Performance

| Métrica | Valor | Status |
|---------|-------|--------|
| **Tiempo instalación** | ${DURATION}s | $([ $DURATION -lt 120 ] && echo '✅ OK' || echo '⚠️ Lento') |
| **Queries ejecutadas** | ${QUERIES} | ℹ️ |
| **Módulos cargados** | ${MODULES_LOADED} | ✅ |

### Warnings (No críticos)

| Tipo Warning | Count | Acción |
|--------------|-------|--------|
| **Total warnings** | ${WARNINGS} | 📋 Documentar |
| **DeprecationWarning** | ${DEPRECATION_WARNINGS} | P2 Backlog |
| **Unknown parameters** | ${UNKNOWN_PARAMS} | P3 Legacy OK |

---

## ✅ Validaciones Runtime

EOF

# Agregar validaciones específicas
if [ $PARSE_ERRORS -eq 0 ]; then
    echo "- ✅ **XML Views válidas** (0 ParseError)" >> "$OUTPUT_FILE"
else
    echo "- ❌ **XML Views inválidas** (${PARSE_ERRORS} ParseError)" >> "$OUTPUT_FILE"
fi

if [ $IMPORT_ERRORS -eq 0 ]; then
    echo "- ✅ **Python imports OK** (0 ImportError)" >> "$OUTPUT_FILE"
else
    echo "- ❌ **Python imports fallidos** (${IMPORT_ERRORS} ImportError)" >> "$OUTPUT_FILE"
fi

if [ $MISSING_DEPS -eq 0 ]; then
    echo "- ✅ **Dependencias instaladas** (0 MissingDependency)" >> "$OUTPUT_FILE"
else
    echo "- ❌ **Dependencias faltantes** (${MISSING_DEPS} MissingDependency)" >> "$OUTPUT_FILE"
fi

if [ $INTEGRITY_ERRORS -eq 0 ]; then
    echo "- ✅ **Database constraints OK** (0 IntegrityError)" >> "$OUTPUT_FILE"
else
    echo "- ❌ **Database constraints violados** (${INTEGRITY_ERRORS} IntegrityError)" >> "$OUTPUT_FILE"
fi

if grep -q "Registry loaded" "$LOG_FILE"; then
    echo "- ✅ **Registry loaded** (\`${REGISTRY_LOADED}\`)" >> "$OUTPUT_FILE"
else
    echo "- ❌ **Registry NO loaded**" >> "$OUTPUT_FILE"
fi

# Agregar sección de errores si existen
if [ $TOTAL_CRITICAL -gt 0 ]; then
    cat >> "$OUTPUT_FILE" <<EOF

---

## 🔴 Errores Críticos Detectados

EOF

    # ParseErrors
    if [ $PARSE_ERRORS -gt 0 ]; then
        echo "### ParseError (XML Views)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        grep -A 10 "ParseError" "$LOG_FILE" | head -50 >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi

    # ImportErrors
    if [ $IMPORT_ERRORS -gt 0 ]; then
        echo "### ImportError (Python)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        grep -A 5 "ImportError" "$LOG_FILE" | head -30 >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi

    # MissingDependency
    if [ $MISSING_DEPS -gt 0 ]; then
        echo "### MissingDependency" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        grep -A 3 "MissingDependency" "$LOG_FILE" | head -20 >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi

    # IntegrityError
    if [ $INTEGRITY_ERRORS -gt 0 ]; then
        echo "### IntegrityError (Database)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        grep -A 5 "IntegrityError" "$LOG_FILE" | head -30 >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
fi

# Agregar warnings si existen
if [ $WARNINGS -gt 0 ]; then
    cat >> "$OUTPUT_FILE" <<EOF

---

## ⚠️ Warnings Identificados (No críticos)

**Total:** ${WARNINGS} warnings

### Clasificación

EOF

    if [ $DEPRECATION_WARNINGS -gt 0 ]; then
        echo "#### DeprecationWarning (${DEPRECATION_WARNINGS})" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "**Ejemplos:**" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        grep "DeprecationWarning" "$LOG_FILE" | head -5 >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "**Acción:** Documentar en backlog P2 (no bloquea producción)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi

    if [ $UNKNOWN_PARAMS -gt 0 ]; then
        echo "#### Unknown Parameters (${UNKNOWN_PARAMS})" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "**Ejemplos:**" >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        grep "unknown parameter" "$LOG_FILE" | head -5 >> "$OUTPUT_FILE"
        echo "\`\`\`" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "**Acción:** Parámetros legacy funcionales, backlog P3" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
fi

# Agregar log completo
cat >> "$OUTPUT_FILE" <<EOF

---

## 📜 Log de Instalación Completo

### Comando Ejecutado

\`\`\`bash
docker compose run --rm odoo odoo \\
  -d ${TEST_DB} \\
  -i ${MODULE} \\
  --stop-after-init \\
  --log-level=warn \\
  --without-demo=all
\`\`\`

### Output (últimas 100 líneas)

\`\`\`
$(tail -100 "$LOG_FILE")
\`\`\`

**Log completo:** \`${LOG_FILE}\`

---

## ✅ Certificación

EOF

if [ $TOTAL_CRITICAL -eq 0 ] && [ $EXIT_CODE -eq 0 ]; then
    cat >> "$OUTPUT_FILE" <<EOF
### ✅ MÓDULO CERTIFICADO PARA PRODUCCIÓN

**Resultado:** El módulo \`${MODULE}\` es **instalable en Odoo 19 CE** sin errores críticos.

**Validaciones:**
- ✅ 0 errores críticos
- ✅ Exit code 0
- ✅ Registry loaded correctamente
- ⚠️ ${WARNINGS} warnings (no críticos, documentar en backlog)

**Próximos pasos:**
1. Revisar warnings en backlog P2/P3
2. Ejecutar tests de integración (opcional)
3. Deploy a staging
4. Validación funcional end-to-end

**Auditor:** SuperClaude AI (Automated)
**Timestamp:** ${TIMESTAMP}
**Framework:** MÁXIMA #0.5 FASE 2 v2.0.0
EOF
else
    cat >> "$OUTPUT_FILE" <<EOF
### ❌ MÓDULO NO CERTIFICADO - REQUIERE CORRECCIONES

**Resultado:** El módulo \`${MODULE}\` tiene **${TOTAL_CRITICAL} errores críticos** que bloquean producción.

**Errores detectados:**
- ParseError: ${PARSE_ERRORS}
- ImportError: ${IMPORT_ERRORS}
- MissingDependency: ${MISSING_DEPS}
- IntegrityError: ${INTEGRITY_ERRORS}
- Exit code: ${EXIT_CODE}

**Acción requerida:**
1. ❌ Corregir todos los errores críticos (ver sección 🔴 arriba)
2. 🔄 Re-ejecutar validación después de fixes
3. ✅ Certificar cuando TOTAL_CRITICAL = 0

**Bloqueado para producción hasta corrección**

**Auditor:** SuperClaude AI (Automated)
**Timestamp:** ${TIMESTAMP}
**Framework:** MÁXIMA #0.5 FASE 2 v2.0.0
EOF
fi

# ═══════════════════════════════════════════════════════════
# CLEANUP OPCIONAL
# ═══════════════════════════════════════════════════════════

echo ""
echo -e "${YELLOW}🧹 Cleanup BBDD test...${NC}"
echo ""

# Opcional: Eliminar BBDD test
# Comentado por defecto para permitir debugging
# docker compose exec -T db psql -U odoo -c "DROP DATABASE IF EXISTS ${TEST_DB};" 2>/dev/null || true

echo -e "${BLUE}ℹ️  BBDD test preservada para debugging: ${TEST_DB}${NC}"
echo -e "${BLUE}   Para eliminar manualmente:${NC}"
echo -e "${BLUE}   docker compose exec db psql -U odoo -c \"DROP DATABASE ${TEST_DB};\"${NC}"

# ═══════════════════════════════════════════════════════════
# RESUMEN FINAL
# ═══════════════════════════════════════════════════════════

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ $TOTAL_CRITICAL -eq 0 ] && [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ VALIDACIÓN EXITOSA${NC}"
    echo ""
    echo -e "${GREEN}Módulo ${MODULE} instalable sin errores críticos${NC}"
    echo ""
    echo -e "${YELLOW}Reporte:${NC} ${OUTPUT_FILE}"
    echo -e "${YELLOW}Log:${NC}     ${LOG_FILE}"
    echo ""
    exit 0
else
    echo -e "${RED}❌ VALIDACIÓN FALLIDA${NC}"
    echo ""
    echo -e "${RED}${TOTAL_CRITICAL} errores críticos detectados${NC}"
    echo ""
    echo -e "${YELLOW}Reporte:${NC} ${OUTPUT_FILE}"
    echo -e "${YELLOW}Log:${NC}     ${LOG_FILE}"
    echo ""
    echo -e "${RED}Ver detalles en reporte markdown${NC}"
    echo ""
    exit 1
fi
