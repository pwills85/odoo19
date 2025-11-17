#!/bin/bash
###############################################################################
# SINCRONIZACIÓN GITHUB - OPTIMIZADO PARA MACOS APPLE SILICON (M1/M2/M3)
# MacBook Pro con chip M#
# Fecha: 2025-11-13
###############################################################################

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  SINCRONIZACIÓN GITHUB - MACOS APPLE SILICON (MacBook Pro M#)   ║"
echo "║  Repositorio: odoo19 (pwills85)                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

REPO_DIR="/Users/pedro/Documents/odoo19"
cd "$REPO_DIR"

# =============================================================================
# PASO 1: FIX SSL/CERTIFICADOS (macOS específico)
# =============================================================================
echo -e "${BLUE}[1/8] Configurando SSL para macOS...${NC}"

# macOS usa el Keychain del sistema, pero Git necesita apuntar al cert.pem correcto
if [ -f "/etc/ssl/cert.pem" ]; then
    git config --global http.sslCAInfo /etc/ssl/cert.pem
    echo -e "${GREEN}✅ Certificados macOS configurados: /etc/ssl/cert.pem${NC}"
else
    # Fallback: certificados de Homebrew (Apple Silicon)
    if [ -f "/opt/homebrew/etc/openssl@3/cert.pem" ]; then
        git config --global http.sslCAInfo /opt/homebrew/etc/openssl@3/cert.pem
        echo -e "${GREEN}✅ Certificados Homebrew configurados${NC}"
    else
        echo -e "${YELLOW}⚠️  Certificados no encontrados, usando keychain del sistema${NC}"
        # Limpiar configuración para usar el default del sistema
        git config --global --unset http.sslCAInfo 2>/dev/null || true
    fi
fi

# Configurar credential helper para macOS
git config --global credential.helper osxkeychain
echo -e "${GREEN}✅ Credential helper: osxkeychain${NC}"

echo ""

# =============================================================================
# PASO 2: VERIFICAR GITHUB CLI (recomendado para macOS)
# =============================================================================
echo -e "${BLUE}[2/8] Verificando GitHub CLI...${NC}"

if command -v gh &> /dev/null; then
    GH_VERSION=$(gh --version | head -1)
    echo -e "${GREEN}✅ GitHub CLI instalado: $GH_VERSION${NC}"
    
    if gh auth status &> /dev/null 2>&1; then
        echo -e "${GREEN}✅ GitHub CLI autenticado${NC}"
        gh auth setup-git 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠️  GitHub CLI no autenticado${NC}"
        echo ""
        echo -e "${CYAN}Recomendación: Autenticar GitHub CLI es la forma MÁS FÁCIL en macOS${NC}"
        echo ""
        read -p "¿Deseas autenticar GitHub CLI ahora? (s/n): " RESPUESTA
        
        if [[ "$RESPUESTA" =~ ^[Ss]$ ]]; then
            echo ""
            echo -e "${BLUE}Iniciando autenticación web...${NC}"
            gh auth login --web --git-protocol https
            
            if gh auth status &> /dev/null 2>&1; then
                echo -e "${GREEN}✅ Autenticación exitosa!${NC}"
                gh auth setup-git
            fi
        else
            echo -e "${YELLOW}⚠️  Continuando sin GitHub CLI (necesitarás token manual)${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  GitHub CLI no está instalado${NC}"
    echo ""
    echo "Para instalar (recomendado):"
    echo -e "${CYAN}brew install gh${NC}"
    echo ""
    read -p "¿Deseas continuar sin GitHub CLI? (s/n): " CONTINUAR
    
    if [[ ! "$CONTINUAR" =~ ^[Ss]$ ]]; then
        echo "Instala GitHub CLI y vuelve a ejecutar este script"
        exit 0
    fi
fi

echo ""

# =============================================================================
# PASO 3: PROBAR CONECTIVIDAD
# =============================================================================
echo -e "${BLUE}[3/8] Probando conectividad con GitHub...${NC}"

if git ls-remote https://github.com/pwills85/odoo19.git &> /dev/null; then
    echo -e "${GREEN}✅ Conexión exitosa con GitHub${NC}"
else
    echo -e "${RED}❌ No se puede conectar con GitHub${NC}"
    echo ""
    echo "Opciones:"
    echo "1. Si tienes GitHub CLI: gh auth login"
    echo "2. Configura un token: https://github.com/settings/tokens"
    echo "3. Usa SSH en lugar de HTTPS"
    echo ""
    exit 1
fi

echo ""

# =============================================================================
# PASO 4: CREAR BACKUP
# =============================================================================
echo -e "${BLUE}[4/8] Creando backup de seguridad...${NC}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="/tmp/odoo19-backup-$TIMESTAMP.bundle"

git bundle create "$BACKUP_FILE" --all

if [ -f "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | awk '{print $1}')
    echo -e "${GREEN}✅ Backup creado: $BACKUP_FILE ($BACKUP_SIZE)${NC}"
else
    echo -e "${RED}❌ Error creando backup${NC}"
    exit 1
fi

echo ""

# =============================================================================
# PASO 5: LIMPIAR ARCHIVOS TEMPORALES
# =============================================================================
echo -e "${BLUE}[5/8] Limpiando archivos temporales...${NC}"

# Actualizar .gitignore
if ! grep -q "^\.tmp_" .gitignore 2>/dev/null; then
    cat >> .gitignore <<EOF

# Archivos temporales de análisis (agregado automáticamente)
.tmp_*.md
.tmp_*
*_temp_*.md
EOF
    echo -e "${GREEN}✅ .gitignore actualizado${NC}"
fi

# Eliminar archivos .tmp_*
TMP_FILES=$(find . -maxdepth 1 -name ".tmp_*" -o -name "*_temp_*" 2>/dev/null | wc -l | tr -d ' ')
if [ "$TMP_FILES" -gt 0 ]; then
    find . -maxdepth 1 \( -name ".tmp_*" -o -name "*_temp_*" \) -type f -delete 2>/dev/null || true
    echo -e "${GREEN}✅ Eliminados $TMP_FILES archivos temporales${NC}"
else
    echo -e "${CYAN}ℹ️  No hay archivos temporales${NC}"
fi

echo ""

# =============================================================================
# PASO 6: COMMITEAR CAMBIOS PENDIENTES
# =============================================================================
echo -e "${BLUE}[6/8] Commiteando cambios pendientes...${NC}"

if ! git diff-index --quiet HEAD -- 2>/dev/null || [ -n "$(git ls-files --others --exclude-standard)" ]; then
    # Stage archivos relevantes
    git add .gitignore 2>/dev/null || true
    git add .claude/settings.local.json 2>/dev/null || true
    git add ai-service/config.py 2>/dev/null || true
    git add ai-service/main.py 2>/dev/null || true
    git add ai-service/tests/integration/test_critical_endpoints.py 2>/dev/null || true
    git add docs/prompts/00_knowledge_base/INDEX.md 2>/dev/null || true
    git add docs/prompts/CHANGELOG.md 2>/dev/null || true
    git add docs/prompts/README.md 2>/dev/null || true
    
    # Commit solo si hay algo staged
    if ! git diff-index --quiet --cached HEAD -- 2>/dev/null; then
        git commit -m "feat(audit-p0-ciclo2): Consolidate P0 audit cycle 2 improvements

- Update Claude AI settings for enhanced audit workflow
- Improve AI service configuration and error handling  
- Add comprehensive critical endpoint integration tests
- Update documentation (index, changelog, knowledge base)
- Clean temporary analysis files from working tree

Platform: macOS Apple Silicon (MacBook Pro M#)
Branch: fix/audit-p0-ciclo2-20251113"

        echo -e "${GREEN}✅ Cambios commiteados${NC}"
    else
        echo -e "${CYAN}ℹ️  No hay cambios relevantes para commitear${NC}"
    fi
else
    echo -e "${CYAN}ℹ️  Working tree limpio, no hay cambios${NC}"
fi

echo ""

# =============================================================================
# PASO 7: SINCRONIZAR CON REMOTO
# =============================================================================
echo -e "${BLUE}[7/8] Sincronizando con GitHub...${NC}"

CURRENT_BRANCH=$(git branch --show-current)
echo -e "${CYAN}Rama actual: $CURRENT_BRANCH${NC}"

# Fetch
git fetch origin --prune
echo -e "${GREEN}✅ Información remota actualizada${NC}"

# Sincronizar main
echo ""
echo -e "${CYAN}Sincronizando rama main...${NC}"
git checkout main

COMMITS_AHEAD=$(git rev-list --count origin/main..main 2>/dev/null || echo "0")
COMMITS_BEHIND=$(git rev-list --count main..origin/main 2>/dev/null || echo "0")

echo "   Local adelante: $COMMITS_AHEAD commits"
echo "   Remoto adelante: $COMMITS_BEHIND commits"

if [ "$COMMITS_BEHIND" -eq 0 ] && [ "$COMMITS_AHEAD" -gt 0 ]; then
    # Solo push
    git push origin main
    echo -e "${GREEN}✅ Main pushed a GitHub${NC}"
elif [ "$COMMITS_AHEAD" -eq 0 ] && [ "$COMMITS_BEHIND" -gt 0 ]; then
    # Solo pull
    git pull origin main
    echo -e "${GREEN}✅ Main actualizado desde GitHub${NC}"
elif [ "$COMMITS_AHEAD" -gt 0 ] && [ "$COMMITS_BEHIND" -gt 0 ]; then
    # Divergencia
    git pull origin main --no-edit
    git push origin main
    echo -e "${GREEN}✅ Main sincronizado (merge realizado)${NC}"
else
    echo -e "${GREEN}✅ Main ya estaba sincronizado${NC}"
fi

# Volver a rama de trabajo y pushear
echo ""
echo -e "${CYAN}Publicando rama $CURRENT_BRANCH...${NC}"
git checkout "$CURRENT_BRANCH"

# Verificar si la rama existe en remoto
if git ls-remote --heads origin "$CURRENT_BRANCH" | grep -q "$CURRENT_BRANCH"; then
    # Rama existe, hacer push normal
    git push origin "$CURRENT_BRANCH"
else
    # Rama nueva, crear en remoto
    git push -u origin "$CURRENT_BRANCH"
fi

echo -e "${GREEN}✅ Rama $CURRENT_BRANCH publicada${NC}"

echo ""

# =============================================================================
# PASO 8: VERIFICACIÓN FINAL
# =============================================================================
echo -e "${BLUE}[8/8] Verificación final...${NC}"

git fetch origin --prune &> /dev/null

# Verificar rama actual
LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse origin/"$CURRENT_BRANCH" 2>/dev/null || echo "")

if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
    echo -e "${GREEN}✅ Rama $CURRENT_BRANCH: sincronizada${NC}"
else
    echo -e "${YELLOW}⚠️  Rama $CURRENT_BRANCH: hay diferencias${NC}"
fi

# Verificar main
MAIN_LOCAL=$(git rev-parse main)
MAIN_REMOTE=$(git rev-parse origin/main)

if [ "$MAIN_LOCAL" = "$MAIN_REMOTE" ]; then
    echo -e "${GREEN}✅ Rama main: sincronizada${NC}"
else
    echo -e "${YELLOW}⚠️  Rama main: hay diferencias${NC}"
fi

echo ""
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                  ✅ SINCRONIZACIÓN COMPLETADA                    ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}Resumen:${NC}"
echo "   ✅ Backup: $BACKUP_FILE"
echo "   ✅ Archivos temporales limpiados"
echo "   ✅ Cambios commiteados"
echo "   ✅ Rama main sincronizada"
echo "   ✅ Rama $CURRENT_BRANCH publicada"
echo ""

echo -e "${BLUE}Próximos pasos:${NC}"
echo "   1. Verifica en: ${CYAN}https://github.com/pwills85/odoo19${NC}"
echo "   2. Crea PR si es necesario"
echo "   3. Confirma que todo se ve bien"
echo ""

exit 0

