-- ═══════════════════════════════════════════════════════════
-- CONFIGURACIÓN RABBITMQ INTEGRATION - ODOO 19
-- ═══════════════════════════════════════════════════════════
-- Ejecutar en base de datos Odoo después de instalar módulo l10n_cl_dte

-- 1. Configuración RabbitMQ
INSERT INTO ir_config_parameter (key, value, create_date, write_date, create_uid, write_uid)
VALUES
    ('rabbitmq.host', 'rabbitmq', NOW(), NOW(), 1, 1),
    ('rabbitmq.port', '5672', NOW(), NOW(), 1, 1),
    ('rabbitmq.vhost', '/odoo', NOW(), NOW(), 1, 1),
    ('rabbitmq.user', 'admin', NOW(), NOW(), 1, 1),
    ('rabbitmq.password', 'changeme', NOW(), NOW(), 1, 1)
ON CONFLICT (key) DO UPDATE SET 
    value = EXCLUDED.value,
    write_date = NOW();

-- 2. Configuración Webhook
INSERT INTO ir_config_parameter (key, value, create_date, write_date, create_uid, write_uid)
VALUES
    ('dte.webhook_key', 'secret_webhook_key_change_in_production', NOW(), NOW(), 1, 1)
ON CONFLICT (key) DO UPDATE SET 
    value = EXCLUDED.value,
    write_date = NOW();

-- 3. Verificar configuración
SELECT key, value 
FROM ir_config_parameter 
WHERE key LIKE 'rabbitmq.%' OR key LIKE 'dte.%'
ORDER BY key;
