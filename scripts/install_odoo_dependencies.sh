#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Instalar dependencias Python en contenedor Odoo
# ═══════════════════════════════════════════════════════════

set -e

echo "🔧 Instalando dependencias Python en Odoo..."

# Instalar pika para RabbitMQ
docker-compose exec -T odoo pip install --no-cache-dir \
    pika==1.3.2

echo "✅ Dependencias instaladas exitosamente"
echo ""
echo "Dependencias instaladas:"
docker-compose exec -T odoo pip list | grep -E "(pika)"
