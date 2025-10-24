#!/bin/bash
# Script de Restore Odoo 19
# Uso: ./scripts/restore_odoo.sh <backup_file.sql.gz> [db_name]

set -e

if [ -z "$1" ]; then
    echo "❌ ERROR: Debe especificar archivo de backup"
    echo "Uso: $0 <backup_file.sql.gz> [db_name]"
    echo ""
    echo "Backups disponibles:"
    ls -lh backups/*.sql.gz | tail -5
    exit 1
fi

BACKUP_FILE="$1"
DB_NAME="${2:-odoo_restored}"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ ERROR: Archivo no encontrado: $BACKUP_FILE"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  RESTORE ODOO 19 - $(date)"
echo "  Backup: $BACKUP_FILE"
echo "  Base de datos destino: $DB_NAME"
echo "═══════════════════════════════════════════════════════"

# Confirmación
read -p "⚠️  ¿Confirma restore a '$DB_NAME'? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "❌ Restore cancelado por usuario"
    exit 1
fi

# 1. Eliminar DB si existe
echo "[1/3] Eliminando base de datos existente (si existe)..."
docker-compose exec -T db dropdb -U odoo "$DB_NAME" --if-exists
echo "✅ DB eliminada (si existía)"

# 2. Crear nueva DB
echo "[2/3] Creando nueva base de datos..."
docker-compose exec -T db createdb -U odoo "$DB_NAME"
echo "✅ DB creada: $DB_NAME"

# 3. Restaurar dump
echo "[3/3] Restaurando backup..."
gunzip -c "$BACKUP_FILE" | docker-compose exec -T db psql -U odoo "$DB_NAME" > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ Restore completado exitosamente"
else
    echo "❌ ERROR durante restore"
    exit 1
fi

# Verificar
echo ""
echo "Verificando módulos instalados..."
docker-compose exec -T db psql -U odoo -d "$DB_NAME" -c \
  "SELECT COUNT(*) as total_modulos FROM ir_module_module WHERE state='installed';"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ RESTORE COMPLETADO"
echo "  Base de datos: $DB_NAME"
echo "  Para conectar Odoo, actualice odoo.conf: db_name = $DB_NAME"
echo "═══════════════════════════════════════════════════════"
