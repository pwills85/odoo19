#!/bin/bash
# Análisis profundo de todas las ramas locales vs remotas

cd /Users/pedro/Documents/odoo19

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          ANÁLISIS PROFUNDO: LOCAL vs REMOTO                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Obtener información actualizada del remoto
echo "[INFO] Obteniendo información actualizada de GitHub..."
git fetch origin --prune 2>&1

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ANÁLISIS DE RAMAS"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Listar todas las ramas locales
LOCAL_BRANCHES=$(git for-each-ref --format='%(refname:short)' refs/heads/)

echo "[1] RAMAS LOCALES ENCONTRADAS:"
echo ""
for branch in $LOCAL_BRANCHES; do
    echo "   - $branch"
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  COMPARACIÓN DETALLADA"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Analizar cada rama
for branch in $LOCAL_BRANCHES; do
    echo "─────────────────────────────────────────────────────────────"
    echo "📍 RAMA: $branch"
    echo "─────────────────────────────────────────────────────────────"
    
    # Obtener hash local
    LOCAL_HASH=$(git rev-parse "$branch" 2>/dev/null)
    echo "   Local commit:  $LOCAL_HASH"
    
    # Verificar si existe en remoto
    REMOTE_HASH=$(git rev-parse "origin/$branch" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "   Remote commit: $REMOTE_HASH"
        
        if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
            echo "   Estado: ✅ SINCRONIZADA"
        else
            # Contar commits
            AHEAD=$(git rev-list --count origin/$branch..$branch 2>/dev/null || echo "0")
            BEHIND=$(git rev-list --count $branch..origin/$branch 2>/dev/null || echo "0")
            
            echo "   Estado: ⚠️  DIVERGENTE"
            echo "   - Commits adelante (local): $AHEAD"
            echo "   - Commits atrás (remoto): $BEHIND"
        fi
    else
        echo "   Remote commit: ❌ NO EXISTE EN REMOTO"
        
        # Contar commits desde el merge-base
        BASE=$(git merge-base origin/main "$branch" 2>/dev/null)
        if [ $? -eq 0 ]; then
            COMMITS=$(git rev-list --count "$BASE".."$branch" 2>/dev/null || echo "?")
            echo "   - Commits únicos sin publicar: $COMMITS"
        fi
        
        echo "   Estado: 🔴 NO PUBLICADA"
    fi
    
    # Mostrar último commit
    LAST_COMMIT=$(git log -1 --format="%h - %s" "$branch" 2>/dev/null)
    echo "   Último commit: $LAST_COMMIT"
    
    echo ""
done

echo "════════════════════════════════════════════════════════════════"
echo "  ESTADO DEL WORKING TREE"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Rama actual
CURRENT=$(git branch --show-current)
echo "📍 RAMA ACTUAL: $CURRENT"
echo ""

# Archivos modificados
MODIFIED=$(git diff --name-only | wc -l | tr -d ' ')
echo "📝 Archivos modificados (no staged): $MODIFIED"
if [ "$MODIFIED" -gt 0 ]; then
    git diff --name-only | head -10 | sed 's/^/   - /'
    if [ "$MODIFIED" -gt 10 ]; then
        echo "   ... y $(($MODIFIED - 10)) más"
    fi
fi

echo ""

# Archivos staged
STAGED=$(git diff --cached --name-only | wc -l | tr -d ' ')
echo "✅ Archivos staged (listos para commit): $STAGED"
if [ "$STAGED" -gt 0 ]; then
    git diff --cached --name-only | head -10 | sed 's/^/   - /'
    if [ "$STAGED" -gt 10 ]; then
        echo "   ... y $(($STAGED - 10)) más"
    fi
fi

echo ""

# Archivos sin track
UNTRACKED=$(git ls-files --others --exclude-standard | wc -l | tr -d ' ')
echo "❓ Archivos sin track (nuevos): $UNTRACKED"
if [ "$UNTRACKED" -gt 0 ]; then
    git ls-files --others --exclude-standard | head -10 | sed 's/^/   - /'
    if [ "$UNTRACKED" -gt 10 ]; then
        echo "   ... y $(($UNTRACKED - 10)) más"
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  RESUMEN EJECUTIVO"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Contar estados
TOTAL_BRANCHES=$(echo "$LOCAL_BRANCHES" | wc -l | tr -d ' ')
SYNCED=0
DIVERGED=0
UNPUBLISHED=0

for branch in $LOCAL_BRANCHES; do
    REMOTE_HASH=$(git rev-parse "origin/$branch" 2>/dev/null)
    if [ $? -eq 0 ]; then
        LOCAL_HASH=$(git rev-parse "$branch" 2>/dev/null)
        if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
            SYNCED=$((SYNCED + 1))
        else
            DIVERGED=$((DIVERGED + 1))
        fi
    else
        UNPUBLISHED=$((UNPUBLISHED + 1))
    fi
done

echo "📊 Total de ramas locales: $TOTAL_BRANCHES"
echo ""
echo "   ✅ Sincronizadas:     $SYNCED"
echo "   ⚠️  Divergentes:      $DIVERGED"
echo "   🔴 Sin publicar:     $UNPUBLISHED"
echo ""
echo "   📝 Archivos modificados:  $MODIFIED"
echo "   ✅ Archivos staged:       $STAGED"
echo "   ❓ Archivos sin track:    $UNTRACKED"
echo ""

TOTAL_PENDING=$(($MODIFIED + $UNTRACKED))
if [ "$UNPUBLISHED" -gt 0 ] || [ "$DIVERGED" -gt 0 ] || [ "$TOTAL_PENDING" -gt 0 ]; then
    echo "⚠️  ACCIÓN REQUERIDA: Hay cambios sin sincronizar con GitHub"
else
    echo "✅ ESTADO ÓPTIMO: Todo sincronizado con GitHub"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"

