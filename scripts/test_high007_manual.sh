#!/bin/bash
# Script validación manual HIGH-007
# Auto-actualización AFP rates

set -e

echo "🔄 HIGH-007: Validación Manual Auto-actualización AFP"
echo "======================================================"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}📊 Test 1: Verificar modelo hr.afp cargado${NC}"
docker compose exec -T odoo python3 << 'EOF'
import odoo
from odoo import api, SUPERUSER_ID
import odoo.tools.config as config

config.parse_config(['-d', 'odoo19_db', '--no-http'])
with odoo.registry('odoo19_db').cursor() as cr:
    env = api.Environment(cr, SUPERUSER_ID, {})
    try:
        afp_model = env['hr.afp']
        print(f"✅ Modelo hr.afp cargado: {afp_model._name}")
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)
EOF

echo ""
echo -e "${YELLOW}📊 Test 2: Verificar método _cron_update_afp_rates${NC}"
docker compose exec -T odoo python3 << 'EOF'
import odoo
from odoo import api, SUPERUSER_ID
import odoo.tools.config as config

config.parse_config(['-d', 'odoo19_db', '--no-http'])
with odoo.registry('odoo19_db').cursor() as cr:
    env = api.Environment(cr, SUPERUSER_ID, {})
    afp_model = env['hr.afp']
    
    if hasattr(afp_model, '_cron_update_afp_rates'):
        print("✅ Método _cron_update_afp_rates existe")
    else:
        print("❌ Método NO existe")
        exit(1)
EOF

echo ""
echo -e "${YELLOW}📊 Test 3: Verificar campo last_update_date${NC}"
docker compose exec -T odoo python3 << 'EOF'
import odoo
from odoo import api, SUPERUSER_ID
import odoo.tools.config as config

config.parse_config(['-d', 'odoo19_db', '--no-http'])
with odoo.registry('odoo19_db').cursor() as cr:
    env = api.Environment(cr, SUPERUSER_ID, {})
    afp_model = env['hr.afp']
    
    if 'last_update_date' in afp_model._fields:
        print("✅ Campo last_update_date existe")
        field = afp_model._fields['last_update_date']
        print(f"   Tipo: {field.type}")
        print(f"   Readonly: {field.readonly}")
    else:
        print("❌ Campo NO existe")
        exit(1)
EOF

echo ""
echo -e "${YELLOW}📊 Test 4: Listar AFPs actuales${NC}"
docker compose exec -T odoo python3 << 'EOF'
import odoo
from odoo import api, SUPERUSER_ID
import odoo.tools.config as config

config.parse_config(['-d', 'odoo19_db', '--no-http'])
with odoo.registry('odoo19_db').cursor() as cr:
    env = api.Environment(cr, SUPERUSER_ID, {})
    afps = env['hr.afp'].search([])
    
    print(f"📊 AFPs encontradas: {len(afps)}")
    for afp in afps:
        update_status = afp.last_update_date.strftime('%Y-%m-%d') if afp.last_update_date else 'Nunca'
        print(f"  - {afp.name} ({afp.code}): {afp.rate:.4f}% | Actualizada: {update_status}")
EOF

echo ""
echo -e "${YELLOW}📊 Test 5: Verificar cron job configurado${NC}"
docker compose exec -T odoo python3 << 'EOF'
import odoo
from odoo import api, SUPERUSER_ID
import odoo.tools.config as config

config.parse_config(['-d', 'odoo19_db', '--no-http'])
with odoo.registry('odoo19_db').cursor() as cr:
    env = api.Environment(cr, SUPERUSER_ID, {})
    
    cron = env['ir.cron'].search([
        ('model_id.model', '=', 'hr.afp'),
        ('code', 'ilike', '_cron_update_afp_rates')
    ], limit=1)
    
    if cron:
        print("✅ Cron job configurado")
        print(f"   Nombre: {cron.name}")
        print(f"   Intervalo: {cron.interval_number} {cron.interval_type}")
        print(f"   Activo: {cron.active}")
    else:
        print("❌ Cron job NO encontrado")
        exit(1)
EOF

echo ""
echo -e "${GREEN}✅ Validación HIGH-007 completada exitosamente${NC}"
echo ""
echo "📝 Próximos pasos:"
echo "   1. Ejecutar tests pytest cuando entorno esté listo"
echo "   2. Validar actualización manual desde UI"
echo "   3. Continuar con HIGH-010 (Previred 105 campos)"
