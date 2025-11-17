#!/bin/bash
# Script: close_gaps_copilot.sh
# Versión: 1.0.0
# Fecha: 2025-11-13
# Propósito: Cierre automático de brechas P0 con Copilot CLI optimizado
# Uso: ./close_gaps_copilot.sh [AUDIT_REPORT_PATH]

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

AUDIT_REPORT="${1:-}"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔧 Cierre Automático Brechas P0 - Copilot CLI${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Validar argumentos
if [ -z "$AUDIT_REPORT" ] || [ ! -f "$AUDIT_REPORT" ]; then
  echo -e "${RED}❌ Error: Ruta reporte auditoría requerida${NC}"
  echo ""
  echo -e "${YELLOW}Uso:${NC}"
  echo "  $0 /path/to/audit_report.md"
  echo ""
  echo -e "${YELLOW}Ejemplo:${NC}"
  echo "  $0 docs/prompts/06_outputs/2025-11/auditorias/20251113_AUDIT_l10n_cl_dte_COMPLIANCE_COPILOT.md"
  exit 1
fi

# Detectar módulo del nombre del reporte
MODULE=$(basename "$AUDIT_REPORT" | sed -E 's/.*AUDIT_(.+)_COMPLIANCE.*/\1/')
echo -e "${YELLOW}Reporte:${NC} $AUDIT_REPORT"
echo -e "${YELLOW}Módulo:${NC} ${MODULE}"
echo ""

# Verificar Copilot CLI
if ! command -v copilot &> /dev/null; then
    echo -e "${RED}❌ Error: Copilot CLI no instalado${NC}"
    echo "Instalar con: npm install -g @github/copilot"
    exit 1
fi

echo -e "${GREEN}✓${NC} Copilot CLI disponible"

# Verificar que el módulo existe
if [ ! -d "addons/localization/${MODULE}" ]; then
    echo -e "${RED}❌ Error: Módulo no encontrado: addons/localization/${MODULE}/${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Módulo existe: addons/localization/${MODULE}/"

# Extraer hallazgos P0 del reporte
P0_COUNT=$(grep -c "^### P0-" "$AUDIT_REPORT" 2>/dev/null || echo "0")
echo -e "${GREEN}✓${NC} Hallazgos P0 detectados: ${P0_COUNT}"
echo ""

if [ "$P0_COUNT" -eq 0 ]; then
  echo -e "${GREEN}✅ No hay deprecaciones P0 para corregir${NC}"
  echo "El módulo ya está en compliance Odoo 19 CE."
  exit 0
fi

# Preparar directorio logs
LOG_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/logs/close_gaps_${MODULE}"
mkdir -p "$LOG_DIR"

# Preparar directorio output
OUTPUT_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/auditorias"
OUTPUT_FILE="${OUTPUT_DIR}/$(date +%Y%m%d)_CLOSE_GAPS_${MODULE}_COPILOT.md"
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}✓${NC} Logs debug: $LOG_DIR"
echo -e "${GREEN}✓${NC} Output reporte: $OUTPUT_FILE"
echo ""
echo -e "${BLUE}🚀 Iniciando cierre automático de ${P0_COUNT} brechas P0...${NC}"
echo -e "${YELLOW}⏳ Esto puede tomar 8-15 minutos dependiendo del número de archivos...${NC}"
echo ""

# Extraer hallazgos del reporte para contexto
HALLAZGOS=$(grep -A 10 "^### P0-" "$AUDIT_REPORT" 2>/dev/null || echo "No se pudieron extraer hallazgos")

# Prompt cierre automático (usa TEMPLATE_CIERRE_BRECHA.md)
PROMPT="Cierra automáticamente las ${P0_COUNT} deprecaciones P0 listadas en el reporte de auditoría.

**Contexto:**
- Reporte auditoría: ${AUDIT_REPORT}
- Módulo: addons/localization/${MODULE}/
- Hallazgos P0: ${P0_COUNT}
- Template base: docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md
- Compliance: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md

**Hallazgos extraídos del reporte:**
${HALLAZGOS}

**Proceso de cierre automático:**

1. **Leer reporte auditoría:**
   - Extraer todos los hallazgos P0
   - Identificar archivos:líneas afectados
   - Clasificar por tipo de deprecación

2. **Por cada hallazgo P0, aplicar corrección:**

   **P0-01: t-esc → t-out (QWeb templates)**
   - Buscar: <t t-esc=\"variable\">
   - Reemplazar: <t t-out=\"variable\">
   - Validar: XML sintácticamente correcto

   **P0-02: type='json' → type='jsonrpc' (HTTP routes)**
   - Buscar: @http.route(..., type='json', ...)
   - Reemplazar: @http.route(..., type='jsonrpc', csrf=False, ...)
   - Validar: Sintaxis Python correcta

   **P0-03: attrs={} → Python expressions (XML views)**
   - Buscar: <field name=\"X\" attrs=\"{...}\"/>
   - Reemplazar: <field name=\"X\" invisible=\"python_expr\"/>
   - Validar: Expresión Python válida

   **P0-04: _sql_constraints → models.Constraint (ORM)**
   - Buscar: _sql_constraints = [('name', 'sql', 'message')]
   - Reemplazar: _sql_constraints = [models.Constraint('sql', name='name', message='message')]
   - Validar: Import correcto, sintaxis ORM

   **P0-05: <dashboard> → <kanban class=\"o_kanban_dashboard\"> (Views)**
   - Buscar: <dashboard>...</dashboard>
   - Reemplazar: <kanban class=\"o_kanban_dashboard\">...</kanban>
   - Validar: XML bien formado

3. **Validación post-corrección:**

   **CRÍTICO - Entorno correcto por operación:**
   
   **Análisis estático (HOST con .venv):**
   - xmllint --noout addons/localization/${MODULE}/views/*.xml
   - .venv/bin/python -m py_compile addons/localization/${MODULE}/models/*.py
   
   **Tests Odoo (DOCKER contenedor odoo):**
   - docker compose exec odoo pytest /mnt/extra-addons/localization/${MODULE}/tests/ -v
   
   **Validación módulo (DOCKER contenedor odoo):**
   - docker compose exec odoo odoo-bin --check-module-deps -d odoo19_db --stop-after-init
   
   - Verificar: 0 errores sintaxis, tests pasan

4. **Generar reporte de cambios:**

## 🔧 Reporte Cierre Automático Brechas P0

**Módulo:** ${MODULE}  
**Fecha:** $(date +%Y-%m-%d)  
**Herramienta:** Copilot CLI (autónomo)  
**Brechas cerradas:** ${P0_COUNT}

---

## 📊 Resumen de Cambios

| Tipo Deprecación | Archivos Modificados | Líneas Modificadas | Status |
|------------------|---------------------|-------------------|--------|
| P0-01: t-esc | X | X | ✅ |
| P0-02: type='json' | X | X | ✅ |
| P0-03: attrs={} | X | X | ✅ |
| P0-04: _sql_constraints | X | X | ✅ |
| P0-05: <dashboard> | X | X | ✅ |
| **Total** | **X** | **X** | **✅** |

---

## 🔧 Cambios Aplicados por Archivo

### Archivo: path/to/file.py

**Línea X:** [Descripción cambio]
\`\`\`python
# ANTES
código_anterior

# DESPUÉS
código_nuevo
\`\`\`

[... más archivos ...]

---

## ✅ Validaciones Post-Corrección

### Validación Sintaxis XML (HOST con xmllint)
\`\`\`bash
xmllint --noout addons/localization/${MODULE}/views/*.xml
# Output: [OK o errores]
\`\`\`

### Validación Sintaxis Python (HOST con .venv)
\`\`\`bash
.venv/bin/python -m py_compile addons/localization/${MODULE}/models/*.py
# Output: [OK o errores]
\`\`\`

### Tests Unitarios (DOCKER contenedor odoo)
\`\`\`bash
docker compose exec odoo pytest /mnt/extra-addons/localization/${MODULE}/tests/ -v --tb=short
# Output: X tests passed, 0 failed
\`\`\`

---

## 📈 Compliance Post-Corrección

| Patrón | Antes | Después | Status |
|--------|-------|---------|--------|
| P0-01: t-esc | X ocurrencias | 0 | ✅ |
| P0-02: type='json' | X ocurrencias | 0 | ✅ |
| P0-03: attrs={} | X ocurrencias | 0 | ✅ |
| P0-04: _sql_constraints | X ocurrencias | 0 | ✅ |
| P0-05: <dashboard> | X ocurrencias | 0 | ✅ |

**Compliance Rate P0:** 100% (5/5 patrones OK) ✅

---

## 🎯 Próximos Pasos

1. **Revisar cambios aplicados:**
   \`\`\`bash
   git diff addons/localization/${MODULE}/
   \`\`\`

2. **Ejecutar tests completos (DOCKER):**
   \`\`\`bash
   docker compose exec odoo pytest /mnt/extra-addons/localization/${MODULE}/tests/ -v
   \`\`\`

3. **Validar en instancia Odoo (DOCKER):**
   \`\`\`bash
   docker compose exec odoo odoo-bin -u ${MODULE} -d odoo19_db --stop-after-init
   \`\`\`

4. **Commit cambios:**
   \`\`\`bash
   git add addons/localization/${MODULE}/
   git commit -m \"fix(${MODULE}): cierre automático ${P0_COUNT} deprecaciones P0 Odoo 19 CE\"
   \`\`\`

---

**Criterios éxito (tarea completa cuando):**
✅ Todas las deprecaciones P0 corregidas
✅ Tests unitarios pasan (pytest exit 0)
✅ Validación sintaxis OK (xmllint + py_compile)
✅ Compliance Odoo 19 CE alcanzado (P0: 100%)
✅ Reporte cambios generado con diffs
✅ Próximos pasos documentados

**Guarda reporte en:** ${OUTPUT_FILE}"

# Ejecutar cierre automático con flags optimizadas
copilot -p "$PROMPT" \
  --model claude-sonnet-4 \
  --stream on \
  --log-level debug \
  --log-dir "$LOG_DIR" \
  --add-dir "addons/localization/${MODULE}" \
  --allow-tool 'read' \
  --allow-tool "write(addons/localization/${MODULE}/*)" \
  --allow-tool 'shell(grep:*)' \
  --allow-tool 'shell(find:*)' \
  --allow-tool 'shell(xmllint:*)' \
  --allow-tool 'shell(.venv/bin/python:*)' \
  --allow-tool 'shell(docker:*)' \
  --deny-tool 'shell(git push)' \
  --deny-tool 'shell(rm:*)' \
  --deny-tool 'shell(python)' \
  --deny-tool 'shell(pytest)' \
  --deny-tool 'shell(odoo-bin)'

EXIT_CODE=$?

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $EXIT_CODE -eq 0 ]; then
  echo -e "${GREEN}✅ Cierre automático completado exitosamente${NC}"
  echo ""
  echo -e "${YELLOW}Reporte generado:${NC}"
  echo "  ${OUTPUT_FILE}"
  echo ""
  echo -e "${YELLOW}Logs debug:${NC}"
  echo "  ${LOG_DIR}"
  echo ""
  echo -e "${BLUE}⚠️  IMPORTANTE: Revisar cambios antes de commit:${NC}"
  echo "  git diff addons/localization/${MODULE}/"
  echo ""
  echo -e "${BLUE}Próximos pasos:${NC}"
  echo "  1. Revisar diff: git diff addons/localization/${MODULE}/"
  echo "  2. Ejecutar tests: pytest addons/localization/${MODULE}/tests/ -v"
  echo "  3. Validar en Odoo: docker compose exec odoo odoo-bin -u ${MODULE} -d odoo19_db --stop-after-init"
  echo "  4. Commit: git add addons/localization/${MODULE}/ && git commit -m \"fix(${MODULE}): cierre ${P0_COUNT} P0\""
else
  echo -e "${RED}❌ Error en cierre automático (exit code: ${EXIT_CODE})${NC}"
  echo ""
  echo -e "${YELLOW}Troubleshooting:${NC}"
  echo "  1. Revisar logs: cat ${LOG_DIR}/copilot-*.log"
  echo "  2. Verificar permisos: ls -la addons/localization/${MODULE}/"
  echo "  3. Validar reporte: cat ${AUDIT_REPORT}"
  echo ""
  echo -e "${BLUE}Logs de debug disponibles en:${NC}"
  echo "  ${LOG_DIR}"
  exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit $EXIT_CODE
