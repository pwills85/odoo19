#!/bin/bash
# Script: audit_compliance_copilot.sh
# Versión: 1.0.0
# Fecha: 2025-11-12
# Propósito: Auditoría autónoma compliance Odoo 19 CE con Copilot CLI
# Uso: ./audit_compliance_copilot.sh [MODULO]

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
MODULE="${1:-l10n_cl_dte}"
OUTPUT_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/auditorias"
OUTPUT_FILE="${OUTPUT_DIR}/$(date +%Y%m%d)_AUDIT_${MODULE}_COMPLIANCE_COPILOT.md"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🤖 Auditoría Compliance Odoo 19 CE - Copilot CLI${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Módulo:${NC} ${MODULE}"
echo -e "${YELLOW}Output:${NC} ${OUTPUT_FILE}"
echo ""

# Verificar Copilot CLI instalado
if ! command -v copilot &> /dev/null; then
    echo -e "${RED}❌ Error: Copilot CLI no instalado${NC}"
    echo "Instalar con: npm install -g @github/copilot"
    exit 1
fi

# Verificar autenticación
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}❌ Error: GITHUB_TOKEN no configurado${NC}"
    echo "Ejecutar: copilot"
    echo "Luego: /login"
    exit 1
fi

# Crear directorio output
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}✓${NC} Copilot CLI: $(copilot --version)"
echo -e "${GREEN}✓${NC} Autenticación: OK"
echo -e "${GREEN}✓${NC} Directorio output: $OUTPUT_DIR"
echo ""
echo -e "${BLUE}⚙️  Ejecutando auditoría autónoma...${NC}"
echo ""

# Ejecutar auditoría autónoma
copilot -p "Audita compliance Odoo 19 CE en módulo addons/localization/${MODULE}/ siguiendo checklist docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md.

**Objetivo:** Validar 8 patrones deprecación P0/P1/P2

**Patrones a validar:**
- P0-01: t-esc → t-out (QWeb templates)
- P0-02: type='json' → type='jsonrpc' (HTTP routes)
- P0-03: attrs={} → Python expressions (XML views)
- P0-04: _sql_constraints → models.Constraint (ORM)
- P0-05: <dashboard> → <kanban class=\"o_kanban_dashboard\">
- P1-06: self._cr → self.env.cr (Database)
- P1-07: fields_view_get() → get_view() (Views)
- P2-08: _() → _lt() (lazy translations - audit only)

**Por cada patrón:**
1. Ejecuta comando grep correspondiente
2. Cuenta ocurrencias
3. Lista archivos:líneas afectados (si aplica)

**Genera reporte markdown con:**

## 📊 Resumen Ejecutivo
- Módulo auditado: ${MODULE}
- Fecha: $(date +%Y-%m-%d)
- Herramienta: Copilot CLI (autónomo)

## ✅ Compliance Odoo 19 CE

| Patrón | Occurrences | Status | Criticidad |
|--------|-------------|--------|-----------|
| P0-01: t-esc | X | ✅/❌ | Breaking |
| P0-02: type='json' | X | ✅/❌ | Breaking |
| P0-03: attrs={} | X | ✅/❌ | Breaking |
| P0-04: _sql_constraints | X | ✅/❌ | Breaking |
| P0-05: <dashboard> | X | ✅/❌ | Breaking |
| P1-06: self._cr | X | ✅/❌ | High |
| P1-07: fields_view_get() | X | ✅/❌ | High |
| P2-08: _() sin _lt() | X | 📋 | Audit only |

## 📈 Métricas Compliance

- **Compliance Rate P0:** XX% (X/5 patrones OK)
- **Compliance Rate P1:** XX% (X/2 patrones OK)
- **Compliance Rate Global:** XX% (X/7 validaciones OK)
- **Deadline P0:** 2025-03-01 (X días restantes)
- **Deprecaciones críticas:** X (P0+P1)

## 🔴 Hallazgos Críticos (si aplica)

### [Patrón]: [Descripción]
**Archivos afectados:**
- path/to/file.py:línea
- path/to/file.xml:línea

**Impacto:** [Descripción impacto]
**Solución:** [Recomendación fix]

## ✅ Verificaciones Reproducibles

\`\`\`bash
# Comando validación
grep -rn \"patrón\" addons/localization/${MODULE}/
# Output: [resultado actual]
\`\`\`

## 📋 Archivos Críticos Pendientes (si aplica)

Si hay deprecaciones P0/P1, listar archivos que requieren corrección manual.

**Guarda reporte en:** ${OUTPUT_FILE}

**Criterios éxito (tarea completa cuando):**
✅ 8 patrones validados (tabla completa)
✅ Compliance rates calculados (P0, P1, Global)
✅ Hallazgos críticos listados con archivo:línea
✅ ≥8 verificaciones reproducibles ejecutadas
✅ Reporte guardado en ubicación especificada
✅ Métricas cuantitativas incluidas" --allow-all-tools --allow-all-paths

EXIT_CODE=$?

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Auditoría completada exitosamente${NC}"
    echo ""
    echo -e "${YELLOW}Reporte generado:${NC}"
    echo "  ${OUTPUT_FILE}"
    echo ""
    
    if [ -f "$OUTPUT_FILE" ]; then
        LINES=$(wc -l < "$OUTPUT_FILE")
        SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
        echo -e "${GREEN}✓${NC} Líneas: $LINES"
        echo -e "${GREEN}✓${NC} Tamaño: $SIZE"
        echo ""
        echo -e "${BLUE}Ver reporte:${NC}"
        echo "  cat $OUTPUT_FILE"
        echo "  open $OUTPUT_FILE  # macOS"
    else
        echo -e "${YELLOW}⚠️  Reporte no encontrado en ubicación esperada${NC}"
        echo "Buscar en: $OUTPUT_DIR"
    fi
else
    echo -e "${RED}❌ Error en auditoría (exit code: $EXIT_CODE)${NC}"
    echo ""
    echo -e "${YELLOW}Posibles causas:${NC}"
    echo "  - Copilot CLI no autenticado correctamente"
    echo "  - Módulo no existe: addons/localization/${MODULE}/"
    echo "  - Permisos insuficientes (requiere --allow-all-tools)"
    echo ""
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo "  1. Verificar autenticación: env | grep GITHUB_TOKEN"
    echo "  2. Verificar módulo existe: ls addons/localization/${MODULE}/"
    echo "  3. Ejecutar modo interactivo: copilot"
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit $EXIT_CODE

