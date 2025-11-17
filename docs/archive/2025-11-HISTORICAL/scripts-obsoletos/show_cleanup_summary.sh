#!/bin/bash

###############################################################################
# RESUMEN INTERACTIVO DE ANÁLISIS DE LIMPIEZA
# Este script muestra un resumen visual del análisis realizado
###############################################################################

PROJECT_ROOT="/Users/pedro/Documents/odoo19"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

clear

cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                  ANÁLISIS DE LIMPIEZA - PROYECTO ODOO19                      ║
║                         📊 RESUMEN EJECUTIVO                                 ║
║                        24 de octubre de 2025                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

EOF

echo -e "${CYAN}📋 DOCUMENTOS GENERADOS:${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} CLEANUP_SUMMARY.md               - Resumen ejecutivo (1 página)"
echo -e "  ${GREEN}✓${NC} CLEANUP_RECOMMENDATIONS.md       - Análisis detallado completo"
echo -e "  ${GREEN}✓${NC} CLEANUP_VISUAL_GUIDE.md          - Guía visual detallada"
echo -e "  ${GREEN}✓${NC} CLEANUP_DECISION_MATRIX.md       - Matriz de decisiones"
echo -e "  ${GREEN}✓${NC} cleanup.sh                       - Script automático"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}🎯 HALLAZGOS PRINCIPALES:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${RED}❌ CATEGORÍA 1: ARCHIVOS ACCIDENTALES (ELIMINAR)${NC}"
echo ""
echo -e "  ${RED}[19 archivos]${NC} ~1 KB | Riesgo: ✅ NULO"
echo ""
echo "  Bandera de Docker:"
echo "    • --rm, --stop-after-init, -d, -name, -u, -o"
echo ""
echo "  Redirecciones/Comandos accidentales:"
echo "    • 0, Total, archivos, docker-compose, echo, find, run, test:"
echo ""
echo "  Referencias duplicadas:"
echo "    • l10n_cl_dte, odoo, odoo19, *test.py, test*.py"
echo ""

echo -e "${YELLOW}🗑️  CATEGORÍA 2: CACHÉS PYTHON (ELIMINAR - Auto-regenerables)${NC}"
echo ""
echo -e "  ${YELLOW}[12+ carpetas]${NC} ~380 KB | Riesgo: ✅ NULO"
echo ""
echo "  Ubicaciones:"
echo "    • ai-service/__pycache__ (56 KB)"
echo "    • ai-service/chat/__pycache__ (64 KB)"
echo "    • ai-service/utils/__pycache__ (60 KB)"
echo "    • ai-service/plugins/__pycache__ (48 KB)"
echo "    • [8 más...] (152 KB)"
echo ""

echo -e "${BLUE}📚 CATEGORÍA 3: DOCUMENTACIÓN HISTÓRICA (MOVER → docs/ARCHIVE/)${NC}"
echo ""
echo -e "  ${BLUE}[23 archivos]${NC} ~340 KB | Riesgo: ⚠️ BAJO"
echo ""
echo "  Tipos de documentos:"
echo "    • 2 Auditorías completadas"
echo "    • 2 Planes finalizados"
echo "    • 2 Reportes de migración"
echo "    • 2 Reportes de servicios"
echo "    • 5 Análisis completados"
echo "    • 2 Sprints completados"
echo "    • 4 Reorganizaciones completadas"
echo "    • 4 Documentación general"
echo ""
echo "  EXCEPCIONES (mantener en raíz):"
echo "    • README.md (56 KB) - Entrada principal"
echo "    • START_HERE.md (2 KB) - Guía inicial"
echo ""

echo -e "${GREEN}📋 CATEGORÍA 4: LOGS ANTIGUOS (ARCHIVAR → backups/logs_archive_DATE/)${NC}"
echo ""
echo -e "  ${GREEN}[6 archivos]${NC} ~90 KB | Riesgo: ✅ NULO"
echo ""
echo "  Archivos de log (22 de octubre):"
echo "    • baseline_validation.log (2.8 KB)"
echo "    • update_production_etapa2.log (23.6 KB)"
echo "    • update_production_final.log (16.6 KB)"
echo "    • update_wizard_attempt2.log (18.2 KB)"
echo "    • update_wizard_minimal_staging.log (12.4 KB)"
echo "    • update_wizard_staging.log (12.4 KB)"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}📊 IMPACTO CUANTIFICABLE:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

cat << EOF

┌─────────────────────────────────────────────────────────────────────────────┐
│ MÉTRICA                          │ ANTES  │ DESPUÉS │ CAMBIO    │ % MEJORA  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Archivos en raíz                 │  54    │   ~35   │ -19      │ ↓ 35%    │
│ Tamaño raíz                      │ 465 KB │ 116 KB  │ -349 KB  │ ↓ 75%    │
│ Cachés Python                    │ 380 KB │   0 KB  │ -380 KB  │ ↓ 100%   │
│ Documentación en raíz            │  23    │   2     │ -21      │ ↓ 91%    │
│ Logs sin archivar                │   6    │   0     │ -6       │ ↓ 100%   │
│ ─────────────────────────────────────────────────────────────────────────────│
│ TOTAL ESPACIO LIBERADO           │        │         │ ~811 KB  │ Ganancia │
│ ORGANIZACIÓN                     │   ★★☆  │  ★★★★★  │ 5/5      │ Mejora   │
└─────────────────────────────────────────────────────────────────────────────┘

EOF

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}🚀 CÓMO EJECUTAR LA LIMPIEZA:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BOLD}Opción 1: AUTOMÁTICA (Recomendado - 2-3 minutos)${NC}"
echo ""
echo "  $ cd /Users/pedro/Documents/odoo19"
echo "  $ ./cleanup.sh"
echo ""
echo "  Esto ejecutará automáticamente:"
echo "    ✓ Fase 1: Elimina 19 archivos accidentales"
echo "    ✓ Fase 2: Limpia ~380 KB de cachés Python"
echo "    ✓ Fase 3: Crea estructura de backup"
echo "    ✓ Fase 4: Archiva 6 logs antiguos"
echo "    ✓ Fase 5: Actualiza .gitignore"
echo ""

echo -e "${BOLD}Opción 2: MANUAL SELECTIVA (Por pasos)${NC}"
echo ""
echo "  Solo eliminar accidentales:"
echo "  $ rm -f /Users/pedro/Documents/odoo19/--{rm,stop-after-init,d,name,u,o}"
echo ""
echo "  Solo limpiar cachés:"
echo "  $ find /Users/pedro/Documents/odoo19/ai-service -name __pycache__ -exec rm -rf {} +"
echo ""
echo "  Solo archivar logs:"
echo "  $ mkdir -p /Users/pedro/Documents/odoo19/backups/logs_archive_$(date +%Y-%m-%d)"
echo "  $ mv /Users/pedro/Documents/odoo19/logs/*.log /Users/pedro/Documents/odoo19/backups/..."
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}⚠️  CONSIDERACIONES IMPORTANTES:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "  ${YELLOW}1. BACKUP${NC}"
echo "     Se recomienda hacer backup antes de ejecutar:"
echo "     $ tar -czf ~/odoo19_backup_\$(date +%Y%m%d).tar.gz /Users/pedro/Documents/odoo19"
echo ""

echo -e "  ${YELLOW}2. RIESGO${NC}"
echo "     • Fase 1 (archivos accidentales): ✅ RIESGO NULO"
echo "     • Fase 2 (cachés Python): ✅ RIESGO NULO (se regeneran)"
echo "     • Fase 3 (documentación): ⚠️ RIESGO BAJO (todo es reversible con Git)"
echo "     • Impacto funcional: ✅ CERO (no afecta operación)"
echo ""

echo -e "  ${YELLOW}3. REVERSIBILIDAD${NC}"
echo "     Todo es reversible con Git:"
echo "     $ git restore ."
echo ""

echo -e "  ${YELLOW}4. DOCUMENTACIÓN${NC}"
echo "     Los archivos archivados seguirán siendo accesibles en docs/ARCHIVE/"
echo ""

echo -e "  ${YELLOW}5. GIT${NC}"
echo "     Después de ejecutar, hacer:"
echo "     $ git add -A"
echo "     $ git commit -m 'chore: cleanup project structure'"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}📁 ESTRUCTURA POST-LIMPIEZA:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

cat << "EOF"

/odoo19/
├── 📄 README.md                  ← Mantener en raíz
├── 📄 START_HERE.md              ← Mantener en raíz
├── 📄 docker-compose.yml         ← Config actual
├── 📄 .env                       ← Secrets
├── 🔧 cleanup.sh                 ← Script de limpieza
│
├── 📁 addons/                    (57 MB) ✓ No tocar
├── 📁 ai-service/                (1.2 MB) ✓ Sin __pycache__
├── 📁 config/                    (24 KB) ✓ Mantener
├── 📁 scripts/                   (156 KB) ✓ Mantener
├── 📁 tests/                     (28 KB) ✓ Mantener
│
├── 📁 docs/
│   ├── 📁 ARCHIVE/               ← 23 docs históricos
│   ├── 📄 AI_*.md
│   └── 📄 ANALISIS_*.md
│
├── 📁 backups/
│   ├── 📁 l10n_cl_dte.backup/
│   ├── 📁 logs_archive_2025-10-22/  ← 6 logs antiguos
│   └── 📁 [otros backups]
│
└── 📁 logs/                      (Limpio, solo actuales)

EOF

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}✅ CHECKLIST RECOMENDADO:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo "  PRE-EJECUCIÓN:"
echo "    [ ] Hacer backup: tar -czf ~/odoo19_backup_*.tar.gz ..."
echo "    [ ] Verificar rama: git branch (debe ser feature/gap-closure...)"
echo "    [ ] Sin cambios sin commit: git status"
echo "    [ ] Leer CLEANUP_SUMMARY.md (5 min)"
echo ""

echo "  EJECUCIÓN:"
echo "    [ ] chmod +x cleanup.sh"
echo "    [ ] ./cleanup.sh"
echo ""

echo "  POST-EJECUCIÓN:"
echo "    [ ] Sin archivos accidentales: ls | grep -E '^--|-[dou]$|^0$|^Total$'"
echo "    [ ] Sin cachés: find ai-service -name __pycache__ | wc -l (debe ser 0)"
echo "    [ ] Docs archivados: ls docs/ARCHIVE | wc -l (debe ser ~23)"
echo "    [ ] Logs archivados: ls backups/logs_archive* | wc -l (debe existir)"
echo "    [ ] Git limpio: git status"
echo ""

echo "  COMMIT:"
echo "    [ ] git add -A"
echo "    [ ] git commit -m 'chore: cleanup project structure'"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}📚 DOCUMENTACIÓN GENERADA:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo "  • CLEANUP_SUMMARY.md          (Resumen 1 página)"
echo "  • CLEANUP_RECOMMENDATIONS.md  (Análisis completo detallado)"
echo "  • CLEANUP_VISUAL_GUIDE.md     (Guía visual con instrucciones)"
echo "  • CLEANUP_DECISION_MATRIX.md  (Matriz y flujos de decisión)"
echo "  • show_cleanup_summary.sh     (Este script)"
echo "  • cleanup.sh                  (Script automático)"
echo ""

echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}✅ ANÁLISIS COMPLETADO - LISTO PARA EJECUTAR${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

echo "Próximos pasos:"
echo "  1. Revisar documentación generada"
echo "  2. Ejecutar: ./cleanup.sh"
echo "  3. Confirmar cambios: git status"
echo "  4. Hacer commit: git commit -m 'chore: cleanup'"
echo ""

echo "Tiempo estimado total: 5-10 minutos"
echo "Riesgo: ✅ BAJO (0% impacto en funcionalidad)"
echo "Ganancia: ~811 KB + mejor organización"
echo ""
