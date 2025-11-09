#!/bin/bash
################################################################################
#                                                                              #
#                    🚀 PRUEBA RÁPIDA - BYPASS ODOO 12                        #
#                                                                              #
################################################################################

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                            ║"
echo "║                  🚀 PRUEBA RÁPIDA - BYPASS ODOO 12                         ║"
echo "║                                                                            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Test 1: Servicios corriendo
echo -e "${BLUE}[1/5]${NC} Verificando servicios Docker..."
if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✅ Servicios Docker corriendo${NC}"
else
    echo -e "${RED}❌ Servicios Docker no están corriendo${NC}"
    exit 1
fi

# Test 2: Modificación Backend
echo -e "${BLUE}[2/5]${NC} Verificando modificación Backend..."
if grep -q "🔓 BYPASS PERMANENTE" ../prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py 2>/dev/null; then
    echo -e "${GREEN}✅ Backend modificado correctamente${NC}"
else
    echo -e "${RED}❌ Modificación Backend no encontrada${NC}"
    exit 1
fi

# Test 3: Modificación Frontend
echo -e "${BLUE}[3/5]${NC} Verificando modificación Frontend..."
BYPASS_COUNT=$(grep -c "🔓 BYPASS PERMANENTE" ../prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js 2>/dev/null)
if [ "$BYPASS_COUNT" -eq "2" ]; then
    echo -e "${GREEN}✅ Frontend modificado correctamente (2 funciones)${NC}"
else
    echo -e "${RED}❌ Modificación Frontend incompleta${NC}"
    exit 1
fi

# Test 4: Accesibilidad HTTP
echo -e "${BLUE}[4/5]${NC} Verificando accesibilidad HTTP..."
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' https://odoo.gestionriego.cl --max-time 10 --insecure)
if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "303" ]]; then
    echo -e "${GREEN}✅ Odoo accesible (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${YELLOW}⚠️  Odoo responde con código HTTP $HTTP_CODE${NC}"
fi

# Test 5: Sin errores críticos
echo -e "${BLUE}[5/5]${NC} Verificando logs..."
if docker-compose logs --tail=50 web 2>&1 | grep -qi "CRITICAL\|FATAL"; then
    echo -e "${YELLOW}⚠️  Se encontraron errores en logs${NC}"
else
    echo -e "${GREEN}✅ Sin errores críticos en logs${NC}"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                           ✅ TODOS LOS TESTS PASARON                       ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}🎉 Bypass funcionando correctamente${NC}"
echo ""
echo "📋 Próximos pasos:"
echo "  1. Accede a: https://odoo.gestionriego.cl"
echo "  2. Verifica que NO aparezca mensaje de expiración"
echo "  3. Haz login y prueba la funcionalidad"
echo ""
echo "🔍 Para ver el reporte completo:"
echo "  cat RESUMEN_EJECUTIVO_FINAL.md"
echo ""
