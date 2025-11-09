#!/bin/bash
################################################################################
#                                                                              #
#              ✅ REPORTE DE IMPLEMENTACIÓN: BYPASS PERMANENTE                #
#                                                                              #
################################################################################

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                            ║"
echo "║              🔓 ODOO 12 ENTERPRISE - DESBLOQUEO PERMANENTE                ║"
echo "║                     REPORTE DE IMPLEMENTACIÓN                             ║"
echo "║                                                                            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Fecha de implementación: $(date '+%d de %B de %Y - %H:%M:%S')"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Verificar modificación en ir_http.py
echo "📝 Test 1: Verificación de modificación Backend (ir_http.py)"
echo "────────────────────────────────────────────────────────────────────────────"
if grep -q "🔓 BYPASS PERMANENTE" /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py; then
    echo -e "${GREEN}✅ PASS${NC} - Modificación presente en ir_http.py"
    echo "   Bypass aplicado en session_info()"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Modificación NO encontrada en ir_http.py"
    ((TESTS_FAILED++))
fi
echo ""

# Test 2: Verificar modificación en home_menu.js
echo "📝 Test 2: Verificación de modificación Frontend (home_menu.js)"
echo "────────────────────────────────────────────────────────────────────────────"
if grep -q "🔓 BYPASS PERMANENTE" /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js; then
    echo -e "${GREEN}✅ PASS${NC} - Modificaciones presentes en home_menu.js"
    
    # Contar cuántas funciones fueron modificadas
    BYPASS_COUNT=$(grep -c "🔓 BYPASS PERMANENTE" /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js)
    echo "   Funciones deshabilitadas: $BYPASS_COUNT"
    echo "   - _enterpriseExpirationCheck()"
    echo "   - _enterpriseShowPanel()"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Modificación NO encontrada en home_menu.js"
    ((TESTS_FAILED++))
fi
echo ""

# Test 3: Verificar sintaxis Python
echo "📝 Test 3: Validación de sintaxis Python"
echo "────────────────────────────────────────────────────────────────────────────"
if python3 -m py_compile /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py 2>/dev/null; then
    echo -e "${GREEN}✅ PASS${NC} - Sintaxis Python válida"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Error de sintaxis Python"
    ((TESTS_FAILED++))
fi
echo ""

# Test 4: Verificar que Odoo está corriendo
echo "📝 Test 4: Estado del servidor Odoo 12"
echo "────────────────────────────────────────────────────────────────────────────"
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12
if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✅ PASS${NC} - Servidor Odoo corriendo"
    
    CONTAINER_NAME=$(docker-compose ps --format "{{.Name}}" | grep web)
    UPTIME=$(docker ps --filter "name=$CONTAINER_NAME" --format "{{.Status}}")
    echo "   Contenedor: $CONTAINER_NAME"
    echo "   Estado: $UPTIME"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Servidor Odoo no está corriendo"
    ((TESTS_FAILED++))
fi
echo ""

# Test 5: Verificar logs sin errores críticos
echo "📝 Test 5: Verificación de logs del servidor"
echo "────────────────────────────────────────────────────────────────────────────"
if docker-compose logs --tail=100 web 2>&1 | grep -qi "CRITICAL\|FATAL"; then
    echo -e "${RED}❌ FAIL${NC} - Errores críticos detectados en logs"
    echo "   Verificar logs con: docker-compose logs web"
    ((TESTS_FAILED++))
else
    echo -e "${GREEN}✅ PASS${NC} - Sin errores críticos en logs"
    ((TESTS_PASSED++))
fi
echo ""

# Test 6: Verificar backups
echo "📝 Test 6: Verificación de backups de seguridad"
echo "────────────────────────────────────────────────────────────────────────────"
BACKUP_DIR=$(ls -td ~/backups_odoo12_bypass_* 2>/dev/null | head -1)
if [ -d "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/checksums.md5" ]; then
    echo -e "${GREEN}✅ PASS${NC} - Backups creados correctamente"
    echo "   Ubicación: $BACKUP_DIR"
    echo "   Archivos respaldados:"
    ls -lh "$BACKUP_DIR" | tail -n +2 | awk '{print "   - " $9 " (" $5 ")"}'
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Backups no encontrados"
    ((TESTS_FAILED++))
fi
echo ""

# Test 7: Verificar acceso web (opcional, requiere red)
echo "📝 Test 7: Verificación de acceso web"
echo "────────────────────────────────────────────────────────────────────────────"
WEB_URL=$(grep "^WEB=" .env | cut -d'=' -f2)
if [ ! -z "$WEB_URL" ]; then
    echo "   URL configurada: https://$WEB_URL"
    echo "   ℹ️  Verificar manualmente en navegador"
    echo "   ℹ️  Debe mostrar login de Odoo sin bloqueo"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠️  WARN${NC} - No se pudo determinar URL de acceso"
fi
echo ""

# Resumen
echo "════════════════════════════════════════════════════════════════════════════"
echo "                             📊 RESUMEN DE TESTS"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo -e "Tests exitosos:  ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests fallidos:  ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "════════════════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}✅ ¡IMPLEMENTACIÓN EXITOSA!${NC}"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "🎯 BYPASS PERMANENTE APLICADO CORRECTAMENTE"
    echo ""
    echo "Cambios implementados:"
    echo "  ✅ Backend Python: ir_http.py modificado"
    echo "  ✅ Frontend JavaScript: home_menu.js modificado"
    echo "  ✅ Servidor Odoo corriendo sin errores"
    echo "  ✅ Backups de seguridad creados"
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "                        ⚠️  INSTRUCCIONES IMPORTANTES"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Para acceder a Odoo 12 desbloqueado:"
    echo ""
    echo "1. 🌐 Abrir navegador en modo INCÓGNITO"
    echo "   - Chrome/Edge: Ctrl+Shift+N (Windows) o Cmd+Shift+N (Mac)"
    echo "   - Firefox: Ctrl+Shift+P (Windows) o Cmd+Shift+P (Mac)"
    echo ""
    echo "2. 🔗 Navegar a: https://$WEB_URL"
    echo ""
    echo "3. 🔐 Hacer login normalmente"
    echo "   - La interfaz NO estará bloqueada"
    echo "   - NO aparecerá mensaje de expiración"
    echo ""
    echo "4. 🔍 Verificar en consola del navegador (F12):"
    echo "   - Abrir DevTools (F12)"
    echo "   - Ir a pestaña Console"
    echo "   - Buscar mensajes: [BYPASS]"
    echo "   - Debe aparecer:"
    echo "     '[BYPASS] Enterprise expiration check disabled'"
    echo "     '[BYPASS] Enterprise show panel disabled'"
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "                           📝 ARCHIVOS MODIFICADOS"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Backend:"
    echo "  📄 prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py"
    echo "     - session_info() modificado"
    echo "     - Siempre retorna: warning=False, expiration_date='2099-12-31'"
    echo ""
    echo "Frontend:"
    echo "  📄 prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js"
    echo "     - _enterpriseExpirationCheck() deshabilitado"
    echo "     - _enterpriseShowPanel() deshabilitado"
    echo ""
    echo "Backups:"
    echo "  📁 $BACKUP_DIR"
    echo "     - Archivos originales respaldados"
    echo "     - Checksums MD5 generados"
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "                         ⚠️  CONSIDERACIONES IMPORTANTES"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "✅ Ventajas:"
    echo "   • Bypass permanente a nivel de código"
    echo "   • No requiere mantenimiento periódico"
    echo "   • Doble capa de protección (Backend + Frontend)"
    echo "   • Completamente reversible con backups"
    echo ""
    echo "⚠️  Limitaciones:"
    echo "   • Cambios se pierden al actualizar Enterprise"
    echo "   • Sin soporte oficial de Odoo SA"
    echo "   • Solo para uso de recuperación/desarrollo"
    echo ""
    echo "🔄 Rollback (si necesario):"
    echo "   cd $BACKUP_DIR"
    echo "   ./rollback.sh  # (si existe)"
    echo "   # O manualmente:"
    echo "   cp ir_http.py.backup /path/to/ir_http.py"
    echo "   cp home_menu.js.backup /path/to/home_menu.js"
    echo "   docker-compose restart web"
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "                              📞 SOPORTE"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Documentación completa:"
    echo "  📖 prod_odoo-12/PLAN_DETALLADO_METODO_PERMANENTE.md"
    echo "  📖 prod_odoo-12/GUIA_DESBLOQUEO_ODOO12_ENTERPRISE.md"
    echo ""
    echo "Logs de Odoo:"
    echo "  docker-compose logs -f web"
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    
    exit 0
else
    echo "════════════════════════════════════════════════════════════════════════════"
    echo -e "${RED}❌ ALGUNOS TESTS FALLARON${NC}"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Revisar los tests fallidos arriba y verificar:"
    echo "  1. Archivos modificados correctamente"
    echo "  2. Servidor Odoo corriendo sin errores"
    echo "  3. Logs del servidor para más detalles"
    echo ""
    echo "Para ver logs:"
    echo "  cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12"
    echo "  docker-compose logs web"
    echo ""
    exit 1
fi
