#!/bin/bash
# orquestar_mejora_permanente.sh - Script de Orquestación Completa
# Versión: 1.0.0
# Fecha: 2025-11-13
# Propósito: Ejecutar ciclo completo de mejora permanente en un módulo

set -euo pipefail

# ════════════════════════════════════════════════════════════════
# COLORES
# ════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ════════════════════════════════════════════════════════════════
# FUNCIONES
# ════════════════════════════════════════════════════════════════

banner() {
    local message="$1"
    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  $message${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() {
    local step_num="$1"
    local step_name="$2"
    echo -e "${BOLD}${MAGENTA}┌─ PASO $step_num: $step_name${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# ════════════════════════════════════════════════════════════════
# PARÁMETROS
# ════════════════════════════════════════════════════════════════

MODULE="${1:-}"
MODE="${2:-full}"  # full, audit-only, close-only

if [ -z "$MODULE" ]; then
    error "Módulo requerido"
    echo ""
    echo -e "${YELLOW}Uso:${NC}"
    echo "  $0 <module_name> [mode]"
    echo ""
    echo -e "${YELLOW}Ejemplos:${NC}"
    echo "  $0 l10n_cl_dte                    # Ciclo completo"
    echo "  $0 l10n_cl_hr_payroll audit-only # Solo auditoría"
    echo "  $0 l10n_cl_financial_reports      # Ciclo completo"
    echo ""
    echo -e "${YELLOW}Módulos disponibles:${NC}"
    ls -1 addons/localization/ 2>/dev/null | grep "^l10n_cl" | sed 's/^/  - /'
    exit 1
fi

# ════════════════════════════════════════════════════════════════
# VALIDACIONES
# ════════════════════════════════════════════════════════════════

banner "🚀 ORQUESTACIÓN DE MEJORA PERMANENTE"

info "Módulo: ${MODULE}"
info "Modo: ${MODE}"
echo ""

# Validar que módulo existe
if [ ! -d "addons/localization/${MODULE}" ]; then
    error "Módulo no encontrado: addons/localization/${MODULE}/"
    exit 1
fi

success "Módulo encontrado: addons/localization/${MODULE}/"

# Validar Copilot CLI
if ! command -v copilot &> /dev/null; then
    error "Copilot CLI no instalado"
    echo "Instalar con: npm install -g @github/copilot"
    exit 1
fi

success "Copilot CLI disponible"
echo ""

# ════════════════════════════════════════════════════════════════
# PASO 1: AUDITORÍA INICIAL
# ════════════════════════════════════════════════════════════════

step 1 "AUDITORÍA INICIAL (Compliance Odoo 19)"
echo ""

info "Ejecutando audit_compliance_copilot.sh..."
echo ""

./docs/prompts/08_scripts/audit_compliance_copilot.sh "${MODULE}"

echo ""

# Buscar reporte más reciente
AUDIT_REPORT=$(ls -t docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/*AUDIT_${MODULE}_COMPLIANCE*.md 2>/dev/null | head -1)

if [ -z "$AUDIT_REPORT" ] || [ ! -f "$AUDIT_REPORT" ]; then
    error "Reporte auditoría no encontrado"
    exit 1
fi

success "Reporte auditoría: ${AUDIT_REPORT}"
echo ""

# Extraer métricas
COMPLIANCE_GLOBAL=$(grep "Compliance Global:" "$AUDIT_REPORT" | head -1 | sed 's/.*: //')
P0_COUNT=$(grep -c "^### P0-" "$AUDIT_REPORT" 2>/dev/null || echo "0")
P1_COUNT=$(grep -c "^### P1-" "$AUDIT_REPORT" 2>/dev/null || echo "0")

info "Compliance Global: ${COMPLIANCE_GLOBAL}"
info "Hallazgos P0: ${P0_COUNT}"
info "Hallazgos P1: ${P1_COUNT}"
echo ""

# Si modo audit-only, terminar aquí
if [ "$MODE" = "audit-only" ]; then
    banner "✅ AUDITORÍA COMPLETADA"
    info "Para continuar con cierre de brechas, ejecutar:"
    echo "  $0 ${MODULE} full"
    exit 0
fi

# ════════════════════════════════════════════════════════════════
# PASO 2: CIERRE DE BRECHAS P0 (Si existen)
# ════════════════════════════════════════════════════════════════

if [ "$P0_COUNT" -gt 0 ]; then
    step 2 "CIERRE AUTOMÁTICO BRECHAS P0 (${P0_COUNT} detectadas)"
    echo ""

    info "Ejecutando close_gaps_copilot.sh..."
    echo ""

    ./docs/prompts/08_scripts/close_gaps_copilot.sh "$AUDIT_REPORT"

    echo ""

    # Buscar reporte cierre
    CLOSE_REPORT=$(ls -t docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/*CLOSE_GAPS_${MODULE}*.md 2>/dev/null | head -1)

    if [ -f "$CLOSE_REPORT" ]; then
        success "Reporte cierre: ${CLOSE_REPORT}"
    else
        warning "Reporte cierre no encontrado (puede ser normal si no había brechas)"
    fi

    echo ""
else
    success "No hay brechas P0 para cerrar"
    echo ""
fi

# ════════════════════════════════════════════════════════════════
# PASO 3: TESTING (Docker)
# ════════════════════════════════════════════════════════════════

step 3 "TESTING (pytest en Docker)"
echo ""

info "Ejecutando tests del módulo..."
echo ""

# Verificar que Docker está corriendo
if ! docker compose ps odoo | grep -q "Up"; then
    warning "Odoo no está corriendo. Iniciando..."
    docker compose up -d odoo
    sleep 5
fi

# Ejecutar tests
if docker compose exec odoo pytest "/mnt/extra-addons/localization/${MODULE}/tests/" -v 2>&1; then
    success "Tests pasaron correctamente"
else
    warning "Algunos tests fallaron (revisar output arriba)"
fi

echo ""

# ════════════════════════════════════════════════════════════════
# PASO 4: RE-AUDITORÍA (Confirmación)
# ════════════════════════════════════════════════════════════════

if [ "$P0_COUNT" -gt 0 ]; then
    step 4 "RE-AUDITORÍA (Confirmación cierre P0)"
    echo ""

    info "Ejecutando audit_compliance_copilot.sh nuevamente..."
    echo ""

    ./docs/prompts/08_scripts/audit_compliance_copilot.sh "${MODULE}"

    echo ""

    # Buscar nuevo reporte
    NEW_AUDIT_REPORT=$(ls -t docs/prompts/06_outputs/$(date +%Y-%m)/auditorias/*AUDIT_${MODULE}_COMPLIANCE*.md 2>/dev/null | head -1)

    if [ -f "$NEW_AUDIT_REPORT" ]; then
        NEW_COMPLIANCE_GLOBAL=$(grep "Compliance Global:" "$NEW_AUDIT_REPORT" | head -1 | sed 's/.*: //')
        NEW_P0_COUNT=$(grep -c "^### P0-" "$NEW_AUDIT_REPORT" 2>/dev/null || echo "0")

        info "Nuevo Compliance Global: ${NEW_COMPLIANCE_GLOBAL}"
        info "Nuevos Hallazgos P0: ${NEW_P0_COUNT}"

        if [ "$NEW_P0_COUNT" -eq 0 ]; then
            success "¡Todas las brechas P0 fueron cerradas! 🎉"
        else
            warning "Aún quedan ${NEW_P0_COUNT} brechas P0"
        fi
    fi

    echo ""
fi

# ════════════════════════════════════════════════════════════════
# PASO 5: REPORTE CONSOLIDADO
# ════════════════════════════════════════════════════════════════

step 5 "REPORTE CONSOLIDADO"
echo ""

CONSOLIDADO="docs/prompts/06_outputs/$(date +%Y-%m)/CICLO_COMPLETO_${MODULE}_$(date +%Y%m%d_%H%M%S).md"

cat > "$CONSOLIDADO" <<EOF
# Ciclo Completo Mejora Permanente - ${MODULE}

**Fecha:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Modo:** ${MODE}
**Script:** orquestar_mejora_permanente.sh v1.0.0

---

## 📊 Resumen Ejecutivo

### Auditoría Inicial

- **Compliance Global:** ${COMPLIANCE_GLOBAL}
- **Hallazgos P0:** ${P0_COUNT}
- **Hallazgos P1:** ${P1_COUNT}
- **Reporte:** \`${AUDIT_REPORT}\`

EOF

if [ "$P0_COUNT" -gt 0 ]; then
    cat >> "$CONSOLIDADO" <<EOF
### Cierre de Brechas P0

- **Brechas cerradas:** ${P0_COUNT}
- **Tiempo estimado:** 2-12 minutos
- **Reporte:** \`${CLOSE_REPORT:-N/A}\`

### Re-auditoría

- **Nuevo Compliance Global:** ${NEW_COMPLIANCE_GLOBAL:-N/A}
- **Nuevos Hallazgos P0:** ${NEW_P0_COUNT:-N/A}
- **Reporte:** \`${NEW_AUDIT_REPORT:-N/A}\`

EOF
fi

cat >> "$CONSOLIDADO" <<EOF
### Testing

\`\`\`bash
docker compose exec odoo pytest /mnt/extra-addons/localization/${MODULE}/tests/ -v
\`\`\`

Ver output completo arriba.

---

## 📋 Archivos Modificados

\`\`\`bash
git status
\`\`\`

$(git status --short addons/localization/${MODULE}/ 2>/dev/null || echo "No hay cambios en Git")

---

## 🎯 Próximos Pasos

EOF

if [ "${NEW_P0_COUNT:-$P0_COUNT}" -gt 0 ]; then
    cat >> "$CONSOLIDADO" <<EOF
1. ⚠️ **Revisar brechas P0 restantes:** ${NEW_P0_COUNT:-$P0_COUNT}
2. Corregir manualmente si close_gaps no pudo automatizar
3. Re-ejecutar testing
4. Re-auditar hasta 100% compliance

EOF
else
    cat >> "$CONSOLIDADO" <<EOF
1. ✅ **Revisar cambios en Git**
2. ✅ **Commitear mejoras:**
   \`\`\`bash
   git add addons/localization/${MODULE}/
   git commit -m "fix: compliance Odoo 19 CE 100% - ${MODULE}"
   \`\`\`
3. ✅ **Push a repo**

EOF
fi

cat >> "$CONSOLIDADO" <<EOF
---

## 📚 Referencias

- **Auditoría inicial:** \`${AUDIT_REPORT}\`
EOF

if [ -n "${CLOSE_REPORT:-}" ]; then
    echo "- **Cierre brechas:** \`${CLOSE_REPORT}\`" >> "$CONSOLIDADO"
fi

if [ -n "${NEW_AUDIT_REPORT:-}" ]; then
    echo "- **Re-auditoría:** \`${NEW_AUDIT_REPORT}\`" >> "$CONSOLIDADO"
fi

cat >> "$CONSOLIDADO" <<EOF

---

**Generado por:** orquestar_mejora_permanente.sh v1.0.0
**Mantenedor:** Pedro Troncoso (@pwills85)
EOF

success "Reporte consolidado: ${CONSOLIDADO}"
echo ""

# ════════════════════════════════════════════════════════════════
# FINALIZACIÓN
# ════════════════════════════════════════════════════════════════

banner "✅ ORQUESTACIÓN COMPLETADA"

info "Resumen:"
echo "  - Módulo: ${MODULE}"
echo "  - Modo: ${MODE}"
echo "  - Compliance inicial: ${COMPLIANCE_GLOBAL}"

if [ "$P0_COUNT" -gt 0 ]; then
    echo "  - Brechas P0 cerradas: ${P0_COUNT}"
    echo "  - Compliance final: ${NEW_COMPLIANCE_GLOBAL:-N/A}"
fi

echo ""
info "Revisar reporte consolidado en:"
echo "  ${CONSOLIDADO}"
echo ""

if [ "${NEW_P0_COUNT:-0}" -eq 0 ] && [ "$P0_COUNT" -gt 0 ]; then
    success "🎉 ¡Módulo ${MODULE} alcanzó 100% compliance Odoo 19 CE!"
fi
