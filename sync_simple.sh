#!/bin/bash
# Sincronización Simple - Ya tienes gh funcionando

cd /Users/pedro/Documents/odoo19

echo "=== Sincronización Simple ==="
echo ""

# 1. Backup rápido
echo "1. Creando backup..."
git bundle create /tmp/odoo19-backup-$(date +%Y%m%d-%H%M%S).bundle --all
echo "✅ Backup creado"
echo ""

# 2. Limpiar temporales
echo "2. Limpiando temporales..."
rm -f .tmp_*.md 2>/dev/null
echo ".tmp_*" >> .gitignore
echo "✅ Limpiado"
echo ""

# 3. Commitear cambios
echo "3. Commiteando cambios..."
git add -A
git commit -m "feat(audit-p0-ciclo2): Sync changes from cycle 2" || echo "Sin cambios nuevos"
echo ""

# 4. Fetch y push
echo "4. Sincronizando con GitHub..."
git fetch origin
git push origin main
git push origin $(git branch --show-current)
echo ""

echo "✅ Listo"
git status

