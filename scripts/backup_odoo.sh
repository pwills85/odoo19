#!/bin/bash
# Script de Backup Automatizado Odoo 19
# Uso: ./scripts/backup_odoo.sh [db_name]

set -e  # Exit on error

BACKUP_DIR="/Users/pedro/Documents/odoo19/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="${1:-odoo}"

# Crear directorio si no existe
mkdir -p "$BACKUP_DIR"

echo "═══════════════════════════════════════════════════════"
echo "  BACKUP ODOO 19 - $(date)"
echo "  Base de datos: $DB_NAME"
echo "═══════════════════════════════════════════════════════"

# 1. Backup PostgreSQL
echo "[1/4] Respaldando base de datos PostgreSQL..."
docker-compose exec -T db pg_dump -U odoo "$DB_NAME" | \
  gzip > "$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz"

if [ $? -eq 0 ]; then
    echo "✅ Backup DB completado: ${DB_NAME}_${TIMESTAMP}.sql.gz"
else
    echo "❌ ERROR en backup DB"
    exit 1
fi

# 2. Backup filestore (archivos adjuntos)
echo "[2/4] Respaldando filestore (archivos adjuntos)..."
docker-compose exec -T odoo tar czf - /var/lib/odoo/.local/share/Odoo/filestore/"$DB_NAME" 2>/dev/null > \
  "$BACKUP_DIR/filestore_${DB_NAME}_${TIMESTAMP}.tar.gz"

if [ $? -eq 0 ]; then
    echo "✅ Backup filestore completado: filestore_${DB_NAME}_${TIMESTAMP}.tar.gz"
else
    echo "⚠️  Warning: No se pudo respaldar filestore (puede no existir aún)"
fi

# 3. Backup configuración
echo "[3/4] Respaldando configuración..."
cp config/odoo.conf "$BACKUP_DIR/odoo_${TIMESTAMP}.conf"
echo "✅ Backup configuración completado: odoo_${TIMESTAMP}.conf"

# 4. Verificar integridad
echo "[4/4] Verificando integridad de backups..."
gzip -t "$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz"

if [ $? -eq 0 ]; then
    echo "✅ Verificación de integridad exitosa"
else
    echo "❌ ERROR: Archivo backup corrupto"
    exit 1
fi

# Obtener tamaños
DB_SIZE=$(du -h "$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz" | cut -f1)
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ BACKUP COMPLETADO EXITOSAMENTE"
echo "  Ubicación: $BACKUP_DIR"
echo "  Archivo DB: ${DB_NAME}_${TIMESTAMP}.sql.gz ($DB_SIZE)"
echo "  Timestamp: $TIMESTAMP"
echo "═══════════════════════════════════════════════════════"

# Limpiar backups antiguos (mantener últimos 7)
echo ""
echo "Limpiando backups antiguos (manteniendo últimos 7)..."
ls -t "$BACKUP_DIR"/${DB_NAME}_*.sql.gz | tail -n +8 | xargs -r rm -f
ls -t "$BACKUP_DIR"/filestore_${DB_NAME}_*.tar.gz | tail -n +8 | xargs -r rm -f
ls -t "$BACKUP_DIR"/odoo_*.conf | tail -n +8 | xargs -r rm -f

echo "✅ Limpieza completada"
echo ""
echo "Backups disponibles:"
ls -lh "$BACKUP_DIR"/${DB_NAME}_*.sql.gz | tail -5
