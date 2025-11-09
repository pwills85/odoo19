#!/bin/bash
# Git Health Check - Monitoreo de Calidad de Git
# Analiza métricas clave de la estrategia de commits y branches
# Basado en: docs/COMMIT_STRATEGY.md

# Colores
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Targets (de COMMIT_STRATEGY.md)
TARGET_CONVENTIONAL=95
TARGET_BRANCHES=10
TARGET_AHEAD=0
TARGET_SIZE=500

echo ""
echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║         GIT HEALTH CHECK - ODOO19 EERGYGROUP          ║${NC}"
echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# 1. CONVENCIONALIDAD DE COMMITS
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}📊 1. CONVENTIONAL COMMITS COMPLIANCE${NC}"
echo "─────────────────────────────────────────────────────────"

total_commits=$(git log --oneline -100 --all | wc -l | tr -d ' ')
conventional_commits=$(git log --oneline -100 --all --format="%s" | \
    grep -E "^(feat|fix|docs|test|i18n|refactor|perf|style|chore|build|ci|revert)\(" | \
    wc -l | tr -d ' ')

if [ "$total_commits" -gt 0 ]; then
    pct_conventional=$((conventional_commits * 100 / total_commits))
else
    pct_conventional=0
fi

echo "   Últimos 100 commits:"
echo "   Total: $total_commits"
echo "   Convencionales: $conventional_commits"
echo -n "   Porcentaje: "

if [ "$pct_conventional" -ge "$TARGET_CONVENTIONAL" ]; then
    echo -e "${GREEN}${pct_conventional}% ✅ (Target: ${TARGET_CONVENTIONAL}%)${NC}"
else
    echo -e "${YELLOW}${pct_conventional}% ⚠️  (Target: ${TARGET_CONVENTIONAL}%)${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════
# 2. DISTRIBUCIÓN DE TIPOS
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}📈 2. DISTRIBUCIÓN DE TIPOS (últimos 50 commits)${NC}"
echo "─────────────────────────────────────────────────────────"

git log --oneline -50 --all --format="%s" | \
    awk -F'[(:)]' '{print $1}' | \
    sort | uniq -c | sort -rn | head -10 | \
    while read count type; do
        printf "   %-12s %3d commits\n" "$type:" "$count"
    done

echo ""

# ═══════════════════════════════════════════════════════════
# 3. GESTIÓN DE RAMAS
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}🌿 3. BRANCH MANAGEMENT${NC}"
echo "─────────────────────────────────────────────────────────"

total_branches=$(git branch | wc -l | tr -d ' ')
echo -n "   Ramas locales: $total_branches "

if [ "$total_branches" -le "$TARGET_BRANCHES" ]; then
    echo -e "${GREEN}✅ (Target: ≤${TARGET_BRANCHES})${NC}"
else
    echo -e "${YELLOW}⚠️  (Target: ≤${TARGET_BRANCHES})${NC}"
fi

# Ramas desincronizadas
ahead_count=$(git for-each-ref --format='%(refname:short) %(upstream:track)' refs/heads/ 2>/dev/null | \
    grep -E "\[ahead" | wc -l | tr -d ' ')
echo -n "   Ramas ahead: $ahead_count "

if [ "$ahead_count" -eq "$TARGET_AHEAD" ]; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${YELLOW}⚠️  (riesgo de pérdida)${NC}"
fi

# Ramas huérfanas
git fetch --prune > /dev/null 2>&1
gone_count=$(git branch -vv 2>/dev/null | grep '\[gone\]' | wc -l | tr -d ' ')
echo -n "   Ramas huérfanas: $gone_count "

if [ "$gone_count" -eq 0 ]; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌ (eliminar)${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════
# 4. TAMAÑO DE COMMITS
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}📏 4. COMMIT SIZE ANALYSIS (últimos 20 commits)${NC}"
echo "─────────────────────────────────────────────────────────"

avg_insertions=$(git log --oneline --shortstat -20 | \
    grep "file.*changed" | \
    awk '{sum+=$4} END {print int(sum/NR)}' || echo "0")

avg_deletions=$(git log --oneline --shortstat -20 | \
    grep "file.*changed" | \
    awk '{sum+=$6} END {print int(sum/NR)}' || echo "0")

avg_total=$((avg_insertions + avg_deletions))

echo "   Promedio inserciones: +$avg_insertions"
echo "   Promedio eliminaciones: -$avg_deletions"
echo -n "   Total promedio: $avg_total LOC "

if [ "$avg_total" -le "$TARGET_SIZE" ]; then
    echo -e "${GREEN}✅ (Target: ≤${TARGET_SIZE} LOC)${NC}"
elif [ "$avg_total" -le 1000 ]; then
    echo -e "${YELLOW}⚠️  (Target: ≤${TARGET_SIZE} LOC)${NC}"
else
    echo -e "${RED}❌ (Target: ≤${TARGET_SIZE} LOC)${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════
# 5. CONFIGURACIÓN DE GIT
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}⚙️  5. GIT CONFIGURATION${NC}"
echo "─────────────────────────────────────────────────────────"

# Template
template=$(git config --get commit.template 2>/dev/null || echo "")
echo -n "   Commit template: "
if [ -n "$template" ]; then
    echo -e "${GREEN}✅ configurado${NC}"
else
    echo -e "${YELLOW}⚠️  no configurado${NC}"
fi

# Hooks
echo -n "   Hook commit-msg: "
if [ -x ".git/hooks/commit-msg" ]; then
    echo -e "${GREEN}✅ activo${NC}"
else
    echo -e "${YELLOW}⚠️  inactivo${NC}"
fi

echo -n "   Hook pre-commit: "
if [ -x ".git/hooks/pre-commit" ]; then
    echo -e "${GREEN}✅ activo${NC}"
else
    echo -e "${YELLOW}⚠️  inactivo${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════
# 6. ACTIVIDAD RECIENTE
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}📅 6. RECENT ACTIVITY${NC}"
echo "─────────────────────────────────────────────────────────"

commits_7d=$(git log --since="7 days ago" --oneline --all | wc -l | tr -d ' ')
commits_30d=$(git log --since="30 days ago" --oneline --all | wc -l | tr -d ' ')

echo "   Commits últimos 7 días: $commits_7d"
echo "   Commits últimos 30 días: $commits_30d"

# Contributors
echo "   Top 3 contributors (últimos 50 commits):"
git log --all --pretty=format:"%an" -50 | \
    sort | uniq -c | sort -rn | head -3 | \
    while read count author; do
        printf "   - %-30s %2d commits\n" "$author" "$count"
    done

echo ""

# ═══════════════════════════════════════════════════════════
# 7. RECOMENDACIONES
# ═══════════════════════════════════════════════════════════

echo -e "${BOLD}${BLUE}💡 RECOMENDACIONES${NC}"
echo "─────────────────────────────────────────────────────────"

recommendations=0

if [ "$pct_conventional" -lt "$TARGET_CONVENTIONAL" ]; then
    echo -e "   ${YELLOW}⚠${NC}  Mejorar adopción de Conventional Commits"
    echo "      Actual: ${pct_conventional}% | Target: ${TARGET_CONVENTIONAL}%"
    recommendations=$((recommendations + 1))
fi

if [ "$total_branches" -gt "$TARGET_BRANCHES" ]; then
    echo -e "   ${YELLOW}⚠${NC}  Limpiar ramas obsoletas"
    echo "      Actual: ${total_branches} ramas | Target: ≤${TARGET_BRANCHES} ramas"
    echo "      Comando: git branch --merged main | grep -v main | xargs git branch -d"
    recommendations=$((recommendations + 1))
fi

if [ "$ahead_count" -gt "$TARGET_AHEAD" ]; then
    echo -e "   ${RED}❌${NC} Sincronizar ramas con remoto (riesgo de pérdida)"
    echo "      Ramas ahead: ${ahead_count}"
    echo "      Comando: git push origin <branch-name>"
    recommendations=$((recommendations + 1))
fi

if [ "$gone_count" -gt 0 ]; then
    echo -e "   ${RED}❌${NC} Eliminar ramas huérfanas"
    echo "      Ramas huérfanas: ${gone_count}"
    echo "      Comando: git branch -D <branch-name>"
    recommendations=$((recommendations + 1))
fi

if [ "$avg_total" -gt "$TARGET_SIZE" ]; then
    echo -e "   ${YELLOW}⚠${NC}  Reducir tamaño de commits"
    echo "      Promedio: ${avg_total} LOC | Target: ≤${TARGET_SIZE} LOC"
    echo "      Tips: Commits más atómicos, git add -p"
    recommendations=$((recommendations + 1))
fi

if [ -z "$template" ]; then
    echo -e "   ${YELLOW}⚠${NC}  Configurar template de commit"
    echo "      Comando: git config commit.template .gitmessage"
    recommendations=$((recommendations + 1))
fi

if [ ! -x ".git/hooks/commit-msg" ] || [ ! -x ".git/hooks/pre-commit" ]; then
    echo -e "   ${YELLOW}⚠${NC}  Activar hooks de validación"
    echo "      Ver: scripts/install-hooks.sh"
    recommendations=$((recommendations + 1))
fi

if [ "$recommendations" -eq 0 ]; then
    echo -e "   ${GREEN}✅ ¡Excelente! No hay recomendaciones pendientes${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════
# 8. SCORE GLOBAL
# ═══════════════════════════════════════════════════════════

score=0

# Conventional commits (30 puntos)
if [ "$pct_conventional" -ge 98 ]; then
    score=$((score + 30))
elif [ "$pct_conventional" -ge 95 ]; then
    score=$((score + 25))
elif [ "$pct_conventional" -ge 85 ]; then
    score=$((score + 20))
else
    score=$((score + 10))
fi

# Branch management (25 puntos)
if [ "$total_branches" -le 5 ] && [ "$ahead_count" -eq 0 ] && [ "$gone_count" -eq 0 ]; then
    score=$((score + 25))
elif [ "$total_branches" -le 10 ] && [ "$ahead_count" -le 1 ]; then
    score=$((score + 20))
else
    score=$((score + 10))
fi

# Commit size (25 puntos)
if [ "$avg_total" -le 300 ]; then
    score=$((score + 25))
elif [ "$avg_total" -le 500 ]; then
    score=$((score + 20))
elif [ "$avg_total" -le 1000 ]; then
    score=$((score + 15))
else
    score=$((score + 5))
fi

# Configuration (20 puntos)
config_score=0
[ -n "$template" ] && config_score=$((config_score + 7))
[ -x ".git/hooks/commit-msg" ] && config_score=$((config_score + 7))
[ -x ".git/hooks/pre-commit" ] && config_score=$((config_score + 6))
score=$((score + config_score))

echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -n -e "${BOLD}${BLUE}║${NC}  "

if [ "$score" -ge 90 ]; then
    echo -n -e "${GREEN}SCORE: ${score}/100 - EXCELENTE ✅${NC}"
elif [ "$score" -ge 75 ]; then
    echo -n -e "${YELLOW}SCORE: ${score}/100 - BUENO ⚠️${NC}"
elif [ "$score" -ge 60 ]; then
    echo -n -e "${YELLOW}SCORE: ${score}/100 - MEJORABLE ⚠️${NC}"
else
    echo -n -e "${RED}SCORE: ${score}/100 - REQUIERE ATENCIÓN ❌${NC}"
fi

# Padding para alinear
padding=$((49 - ${#score}))
printf "%${padding}s" ""
echo -e "${BOLD}${BLUE}║${NC}"

echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}📖 Documentación completa: docs/COMMIT_STRATEGY.md${NC}"
echo ""

exit 0
