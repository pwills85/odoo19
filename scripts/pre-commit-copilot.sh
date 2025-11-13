#!/bin/bash
# Script: pre-commit-copilot.sh
# Versión: 1.0.0
# Fecha: 2025-11-12
# Propósito: Hook pre-commit con validación autónoma Copilot CLI
# Instalación: cp scripts/pre-commit-copilot.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔍 Pre-Commit: Validación Compliance Odoo 19 CE${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Obtener archivos staged Python/XML
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|xml)$' || true)

if [ -z "$STAGED_FILES" ]; then
  echo -e "${GREEN}✓${NC} No hay archivos Python/XML staged"
  echo -e "${GREEN}✅ Commit permitido${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  exit 0
fi

echo -e "${YELLOW}Archivos staged a validar:${NC}"
echo "$STAGED_FILES" | while read -r file; do
  echo "  - $file"
done
echo ""

# Verificar Copilot CLI disponible
if ! command -v copilot &> /dev/null; then
    echo -e "${YELLOW}⚠️  Copilot CLI no instalado${NC}"
    echo -e "${YELLOW}Validación manual recomendada:${NC}"
    echo "  grep -rn \"t-esc\\|type='json'\\|attrs=\\|self\\._cr\" \\"
    echo "    $(echo "$STAGED_FILES" | tr '\n' ' ')"
    echo ""
    echo -e "${GREEN}✅ Commit permitido (sin validación automática)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 0
fi

# Verificar autenticación
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${YELLOW}⚠️  GITHUB_TOKEN no configurado${NC}"
    echo -e "${YELLOW}Validación manual recomendada (ver arriba)${NC}"
    echo ""
    echo -e "${GREEN}✅ Commit permitido (sin validación automática)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 0
fi

echo -e "${GREEN}✓${NC} Copilot CLI disponible y autenticado"
echo ""
echo -e "${BLUE}⚙️  Ejecutando validación compliance autónoma...${NC}"
echo ""

# Crear archivo temporal para reporte
TEMP_REPORT=$(mktemp)

# Ejecutar validación con Copilot CLI
copilot -p "Valida deprecaciones P0+P1 Odoo 19 CE en archivos staged para commit:

$STAGED_FILES

**Checklist:** docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md

**Patrones P0 (Breaking Changes):**
- t-esc → t-out (QWeb templates)
- type='json' → type='jsonrpc' (HTTP routes)
- attrs={} → Python expressions (XML views)
- _sql_constraints → models.Constraint (ORM)
- <dashboard> → <kanban class=\"o_kanban_dashboard\">

**Patrones P1 (High Priority):**
- self._cr → self.env.cr (Database access)
- fields_view_get() → get_view() (View methods)

**Comandos validación:**
\`\`\`bash
# Por cada archivo staged
for file in $STAGED_FILES; do
  grep -n \"t-esc\\|type='json'\\|attrs=\\|_sql_constraints\\|<dashboard>\\|self\\._cr\\|fields_view_get\" \"\$file\" || true
done
\`\`\`

**Si encuentras ≥1 deprecación P0/P1:**
- Lista archivos:líneas afectados
- Genera reporte markdown conciso
- Exit code 1 (BLOQUEAR COMMIT)

**Si NO encuentras deprecaciones:**
- Mensaje: \"✅ Compliance Odoo 19 OK - 0 deprecaciones\"
- Exit code 0 (PERMITIR COMMIT)

**Output temporal:** ${TEMP_REPORT}" --allow-all-tools --allow-all-paths > "$TEMP_REPORT" 2>&1

EXIT_CODE=$?

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $EXIT_CODE -ne 0 ] || grep -qE "deprecación|deprecation|t-esc|type='json'|attrs=|self\._cr" "$TEMP_REPORT"; then
    echo -e "${RED}❌ COMMIT BLOQUEADO${NC}"
    echo ""
    echo -e "${YELLOW}Deprecaciones P0/P1 detectadas:${NC}"
    echo ""
    cat "$TEMP_REPORT"
    echo ""
    echo -e "${YELLOW}Acciones requeridas:${NC}"
    echo "  1. Corrige deprecaciones en archivos listados"
    echo "  2. Consulta: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md"
    echo "  3. Valida manualmente: grep -rn \"patrón\" archivo.py"
    echo "  4. Re-stage archivos: git add archivo.py"
    echo "  5. Intenta commit nuevamente"
    echo ""
    echo -e "${RED}Commit no permitido hasta corregir deprecaciones${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    rm "$TEMP_REPORT"
    exit 1
fi

echo -e "${GREEN}✅ Compliance Odoo 19 CE: OK${NC}"
echo ""
echo -e "${GREEN}✓${NC} 0 deprecaciones P0/P1 detectadas"
echo -e "${GREEN}✓${NC} Archivos validados: $(echo "$STAGED_FILES" | wc -l | tr -d ' ')"
echo ""
echo -e "${GREEN}✅ Commit permitido${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

rm "$TEMP_REPORT"
exit 0

