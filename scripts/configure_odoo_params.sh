#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Configurar parámetros de sistema en Odoo
# ═══════════════════════════════════════════════════════════

set -e

echo "🔧 Configurando parámetros de sistema en Odoo..."

# Obtener variables de .env
source .env

# Ejecutar SQL para configurar parámetros
docker-compose exec -T postgres psql -U odoo -d odoo << EOF
-- Configuración RabbitMQ
INSERT INTO ir_config_parameter (key, value, create_date, write_date, create_uid, write_uid)
VALUES
    ('rabbitmq.host', '${RABBITMQ_HOST:-rabbitmq}', NOW(), NOW(), 1, 1),
    ('rabbitmq.port', '${RABBITMQ_PORT:-5672}', NOW(), NOW(), 1, 1),
    ('rabbitmq.vhost', '${RABBITMQ_VHOST:-/odoo}', NOW(), NOW(), 1, 1),
    ('rabbitmq.user', '${RABBITMQ_USER:-admin}', NOW(), NOW(), 1, 1),
    ('rabbitmq.password', '${RABBITMQ_PASS:-changeme}', NOW(), NOW(), 1, 1),
    ('dte.webhook_key', '${ODOO_WEBHOOK_KEY:-secret_key}', NOW(), NOW(), 1, 1)
ON CONFLICT (key) DO UPDATE SET 
    value = EXCLUDED.value,
    write_date = NOW();

-- Verificar configuración
SELECT key, value FROM ir_config_parameter 
WHERE key LIKE 'rabbitmq.%' OR key LIKE 'dte.%'
ORDER BY key;
EOF

echo "✅ Parámetros configurados exitosamente"
