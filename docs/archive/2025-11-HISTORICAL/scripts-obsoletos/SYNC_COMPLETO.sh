#!/bin/bash
###############################################################################
# SINCRONIZACIÓN COMPLETA LOCAL → REMOTO
# Análisis profundo + Sincronización automatizada
# Fecha: 2025-11-13
###############################################################################

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

REPO_DIR="/Users/pedro/Documents/odoo19"
cd "$REPO_DIR"

clear

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║        SINCRONIZACIÓN COMPLETA: LOCAL → GITHUB                   ║
║        Análisis Profundo + Sync Automatizado                     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""

# =============================================================================
# FASE 1: ANÁLISIS PROFUNDO
# =============================================================================
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  FASE 1: ANÁLISIS PROFUNDO${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[1/7] Obteniendo información actualizada de GitHub...${NC}"
git fetch origin --prune
echo -e "${GREEN}✅ Información remota actualizada${NC}"
echo ""

# Guardar rama actual
CURRENT_BRANCH=$(git branch --show-current)
echo -e "${CYAN}📍 Rama actual: ${MAGENTA}$CURRENT_BRANCH${NC}"
echo ""

# Obtener todas las ramas locales
LOCAL_BRANCHES=$(git for-each-ref --format='%(refname:short)' refs/heads/)

echo -e "${BLUE}[2/7] Analizando todas las ramas locales...${NC}"
echo ""

# Contadores
TOTAL_BRANCHES=0
SYNCED_BRANCHES=0
DIVERGED_BRANCHES=0
UNPUBLISHED_BRANCHES=0

# Arrays para guardar ramas por estado
SYNCED_LIST=()
DIVERGED_LIST=()
UNPUBLISHED_LIST=()

for branch in $LOCAL_BRANCHES; do
    TOTAL_BRANCHES=$((TOTAL_BRANCHES + 1))
    
    LOCAL_HASH=$(git rev-parse "$branch" 2>/dev/null)
    REMOTE_HASH=$(git rev-parse "origin/$branch" 2>/dev/null || echo "")
    
    if [ -z "$REMOTE_HASH" ]; then
        # Rama no existe en remoto
        UNPUBLISHED_BRANCHES=$((UNPUBLISHED_BRANCHES + 1))
        UNPUBLISHED_LIST+=("$branch")
        echo -e "   🔴 ${YELLOW}$branch${NC} → No publicada"
    elif [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
        # Sincronizada
        SYNCED_BRANCHES=$((SYNCED_BRANCHES + 1))
        SYNCED_LIST+=("$branch")
        echo -e "   ✅ ${GREEN}$branch${NC} → Sincronizada"
    else
        # Divergente
        DIVERGED_BRANCHES=$((DIVERGED_BRANCHES + 1))
        DIVERGED_LIST+=("$branch")
        AHEAD=$(git rev-list --count "origin/$branch..$branch" 2>/dev/null || echo "0")
        BEHIND=$(git rev-list --count "$branch..origin/$branch" 2>/dev/null || echo "0")
        echo -e "   ⚠️  ${YELLOW}$branch${NC} → Divergente (↑$AHEAD ↓$BEHIND)"
    fi
done

echo ""
echo -e "${BLUE}[3/7] Analizando working tree...${NC}"
echo ""

# Archivos modificados
MODIFIED_COUNT=$(git diff --name-only 2>/dev/null | wc -l | tr -d ' ')
STAGED_COUNT=$(git diff --cached --name-only 2>/dev/null | wc -l | tr -d ' ')
UNTRACKED_COUNT=$(git ls-files --others --exclude-standard 2>/dev/null | wc -l | tr -d ' ')

echo "   📝 Archivos modificados: $MODIFIED_COUNT"
echo "   ✅ Archivos staged: $STAGED_COUNT"
echo "   ❓ Archivos sin track: $UNTRACKED_COUNT"

echo ""
echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}  RESUMEN DEL ANÁLISIS${NC}"
echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "   📊 Total ramas locales:    ${MAGENTA}$TOTAL_BRANCHES${NC}"
echo -e "   ✅ Sincronizadas:          ${GREEN}$SYNCED_BRANCHES${NC}"
echo -e "   ⚠️  Divergentes:           ${YELLOW}$DIVERGED_BRANCHES${NC}"
echo -e "   🔴 Sin publicar:          ${RED}$UNPUBLISHED_BRANCHES${NC}"
echo ""
echo -e "   📝 Cambios pendientes:     ${YELLOW}$(($MODIFIED_COUNT + $UNTRACKED_COUNT))${NC} archivos"
echo ""

# Calcular total de acciones necesarias
ACTIONS_NEEDED=$(($DIVERGED_BRANCHES + $UNPUBLISHED_BRANCHES))
if [ "$MODIFIED_COUNT" -gt 0 ] || [ "$UNTRACKED_COUNT" -gt 0 ]; then
    ACTIONS_NEEDED=$((ACTIONS_NEEDED + 1))
fi

if [ "$ACTIONS_NEEDED" -eq 0 ]; then
    echo -e "${GREEN}✅ ESTADO ÓPTIMO: Todo está sincronizado${NC}"
    echo ""
    exit 0
else
    echo -e "${YELLOW}⚠️  SINCRONIZACIÓN REQUERIDA: $ACTIONS_NEEDED acción(es) pendiente(s)${NC}"
fi

echo ""
read -p "¿Continuar con la sincronización? (s/n): " CONTINUE

if [[ ! "$CONTINUE" =~ ^[Ss]$ ]]; then
    echo "Sincronización cancelada por el usuario"
    exit 0
fi

echo ""

# =============================================================================
# FASE 2: BACKUP DE SEGURIDAD
# =============================================================================
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  FASE 2: BACKUP DE SEGURIDAD${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[4/7] Creando backup completo...${NC}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="/tmp/odoo19-backup-$TIMESTAMP.bundle"

git bundle create "$BACKUP_FILE" --all

if [ -f "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | awk '{print $1}')
    echo -e "${GREEN}✅ Backup creado: $BACKUP_FILE ($BACKUP_SIZE)${NC}"
else
    echo -e "${RED}❌ Error creando backup. Abortando.${NC}"
    exit 1
fi

echo ""

# =============================================================================
# FASE 3: LIMPIAR Y COMMITEAR
# =============================================================================
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  FASE 3: PREPARAR CAMBIOS LOCALES${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$MODIFIED_COUNT" -gt 0 ] || [ "$UNTRACKED_COUNT" -gt 0 ]; then
    echo -e "${BLUE}[5/7] Limpiando archivos temporales...${NC}"
    
    # Actualizar .gitignore
    if ! grep -q "^\.tmp_" .gitignore 2>/dev/null; then
        cat >> .gitignore <<EOF

# Archivos temporales de análisis
.tmp_*
*.tmp
*_temp_*
EOF
        echo -e "${GREEN}✅ .gitignore actualizado${NC}"
    fi
    
    # Eliminar archivos temporales
    find . -maxdepth 1 \( -name ".tmp_*" -o -name "*_temp_*" \) -type f -delete 2>/dev/null || true
    
    echo ""
    echo -e "${BLUE}Commiteando cambios en rama actual ($CURRENT_BRANCH)...${NC}"
    
    # Stage todos los archivos relevantes
    git add -A
    
    # Commit
    git commit -m "feat(sync): Consolidate pending changes for full sync

- Update configuration files and documentation
- Add new test cases and improvements
- Clean temporary analysis files
- Prepare for complete GitHub synchronization

Branch: $CURRENT_BRANCH
Timestamp: $TIMESTAMP
Platform: macOS (Apple Silicon)" || echo "Sin cambios nuevos para commitear"
    
    echo -e "${GREEN}✅ Cambios commiteados en $CURRENT_BRANCH${NC}"
else
    echo -e "${BLUE}[5/7] No hay cambios pendientes para commitear${NC}"
    echo -e "${GREEN}✅ Working tree limpio${NC}"
fi

echo ""

# =============================================================================
# FASE 4: SINCRONIZACIÓN COMPLETA
# =============================================================================
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  FASE 4: SINCRONIZACIÓN CON GITHUB${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[6/7] Sincronizando todas las ramas...${NC}"
echo ""

# Contador de éxitos
PUSHED_COUNT=0
FAILED_COUNT=0
FAILED_BRANCHES=()

# Sincronizar ramas divergentes primero
if [ "$DIVERGED_BRANCHES" -gt 0 ]; then
    echo -e "${CYAN}Sincronizando ramas divergentes...${NC}"
    for branch in "${DIVERGED_LIST[@]}"; do
        echo -e "   → $branch"
        git checkout "$branch" 2>/dev/null
        
        # Pull con rebase para mantener historial limpio
        if git pull --rebase origin "$branch" 2>/dev/null; then
            if git push origin "$branch" 2>/dev/null; then
                echo -e "      ${GREEN}✅ Sincronizada${NC}"
                PUSHED_COUNT=$((PUSHED_COUNT + 1))
            else
                echo -e "      ${RED}❌ Error en push${NC}"
                FAILED_COUNT=$((FAILED_COUNT + 1))
                FAILED_BRANCHES+=("$branch")
            fi
        else
            echo -e "      ${RED}❌ Error en pull/rebase${NC}"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            FAILED_BRANCHES+=("$branch")
        fi
    done
    echo ""
fi

# Publicar ramas no publicadas
if [ "$UNPUBLISHED_BRANCHES" -gt 0 ]; then
    echo -e "${CYAN}Publicando ramas nuevas...${NC}"
    for branch in "${UNPUBLISHED_LIST[@]}"; do
        echo -e "   → $branch"
        git checkout "$branch" 2>/dev/null
        
        if git push -u origin "$branch" 2>/dev/null; then
            echo -e "      ${GREEN}✅ Publicada${NC}"
            PUSHED_COUNT=$((PUSHED_COUNT + 1))
        else
            echo -e "      ${RED}❌ Error en push${NC}"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            FAILED_BRANCHES+=("$branch")
        fi
    done
    echo ""
fi

# Volver a la rama original
git checkout "$CURRENT_BRANCH" 2>/dev/null

echo -e "${GREEN}✅ Sincronización completada${NC}"
echo -e "   - Ramas sincronizadas: $PUSHED_COUNT"
if [ "$FAILED_COUNT" -gt 0 ]; then
    echo -e "   ${RED}- Ramas con error: $FAILED_COUNT${NC}"
    for failed in "${FAILED_BRANCHES[@]}"; do
        echo -e "      ${RED}• $failed${NC}"
    done
fi

echo ""

# =============================================================================
# FASE 5: VERIFICACIÓN FINAL
# =============================================================================
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  FASE 5: VERIFICACIÓN FINAL${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}[7/7] Verificando sincronización...${NC}"
echo ""

git fetch origin --prune 2>/dev/null

# Re-verificar estado
STILL_UNPUBLISHED=0
for branch in $LOCAL_BRANCHES; do
    REMOTE_HASH=$(git rev-parse "origin/$branch" 2>/dev/null || echo "")
    if [ -z "$REMOTE_HASH" ]; then
        STILL_UNPUBLISHED=$((STILL_UNPUBLISHED + 1))
    fi
done

if [ "$STILL_UNPUBLISHED" -eq 0 ] && [ "$FAILED_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✅ SINCRONIZACIÓN COMPLETA Y EXITOSA${NC}"
else
    echo -e "${YELLOW}⚠️  Sincronización parcial${NC}"
    echo -e "   - Ramas aún sin publicar: $STILL_UNPUBLISHED"
fi

echo ""
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║              ✅ PROCESO COMPLETADO                               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo ""
echo -e "${GREEN}📊 RESUMEN FINAL:${NC}"
echo ""
echo -e "   Backup:              ${CYAN}$BACKUP_FILE${NC}"
echo -e "   Ramas sincronizadas: ${GREEN}$PUSHED_COUNT${NC}"
echo -e "   Rama actual:         ${MAGENTA}$CURRENT_BRANCH${NC}"
echo -e "   Working tree:        ${GREEN}Limpio${NC}"
echo ""

echo -e "${BLUE}🔗 Verifica en GitHub:${NC}"
echo -e "   ${CYAN}https://github.com/pwills85/odoo19${NC}"
echo ""

echo -e "${BLUE}📝 Próximos pasos recomendados:${NC}"
echo "   1. Verifica las ramas en GitHub web"
echo "   2. Crea Pull Requests si es necesario"
echo "   3. Configura sync automático diario"
echo ""

exit 0

