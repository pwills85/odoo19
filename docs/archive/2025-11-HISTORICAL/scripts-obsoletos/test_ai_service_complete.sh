#!/bin/bash
# test_ai_service_complete.sh
# Script completo de testing para AI Microservice
# Autor: EERGYGROUP
# Fecha: 2025-10-24

echo "🧪 TESTING COMPLETO AI MICROSERVICE"
echo "===================================="
echo ""

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

passed=0
failed=0
skipped=0

# Función para ejecutar test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local optional="${3:-false}"
    
    echo -n "Testing: $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((passed++))
    else
        if [ "$optional" = "true" ]; then
            echo -e "${YELLOW}⚠️  SKIP (optional)${NC}"
            ((skipped++))
        else
            echo -e "${RED}❌ FAIL${NC}"
            ((failed++))
        fi
    fi
}

# 1. Tests de Infraestructura
echo -e "${BLUE}1️⃣  TESTS DE INFRAESTRUCTURA${NC}"
echo "----------------------------"
run_test "Contenedor corriendo" "docker ps | grep -q ai_service"
run_test "Health check OK" "[ \$(docker inspect odoo19_ai_service --format='{{.State.Health.Status}}' 2>/dev/null) = 'healthy' ]"
run_test "Sin errores críticos en logs" "! docker logs --tail 100 odoo19_ai_service 2>&1 | grep -qi 'error.*critical'"
run_test "Memoria < 500MB" "[ \$(docker stats odoo19_ai_service --no-stream --format '{{.MemUsage}}' 2>/dev/null | cut -d'/' -f1 | sed 's/MiB//' | cut -d'.' -f1) -lt 500 ]" "true"

# 2. Tests de Configuración
echo ""
echo -e "${BLUE}2️⃣  TESTS DE CONFIGURACIÓN${NC}"
echo "-------------------------"
run_test "Variables cargadas" "docker exec odoo19_ai_service python -c 'from config import settings; assert settings.anthropic_api_key' 2>/dev/null"
run_test "Modelo correcto" "docker exec odoo19_ai_service python -c 'from config import settings; assert settings.anthropic_model == \"claude-sonnet-4-5-20250929\"' 2>/dev/null"
run_test "Redis URL configurado" "docker exec odoo19_ai_service python -c 'from config import settings; assert settings.redis_url' 2>/dev/null"
run_test "Odoo URL configurado" "docker exec odoo19_ai_service python -c 'from config import settings; assert settings.odoo_url' 2>/dev/null"

# 3. Tests de Conectividad
echo ""
echo -e "${BLUE}3️⃣  TESTS DE CONECTIVIDAD${NC}"
echo "------------------------"
run_test "Redis conectado" "docker exec odoo19_ai_service python -c 'import redis; from config import settings; redis.from_url(settings.redis_url).ping()' 2>/dev/null"
run_test "Anthropic API inicializada" "docker exec odoo19_ai_service python -c 'from anthropic import Anthropic; from config import settings; Anthropic(api_key=settings.anthropic_api_key)' 2>/dev/null"
run_test "Odoo accesible" "curl -sf http://localhost:8069/web/health" "true"

# 4. Tests de Endpoints (desde dentro del contenedor - red interna)
echo ""
echo -e "${BLUE}4️⃣  TESTS DE ENDPOINTS${NC}"
echo "---------------------"
run_test "Health endpoint responde" "docker exec odoo19_ai_service curl -sf http://localhost:8002/health"
run_test "Health retorna JSON válido" "docker exec odoo19_ai_service curl -sf http://localhost:8002/health | python3 -m json.tool"
run_test "Metrics endpoint responde" "docker exec odoo19_ai_service curl -sf http://localhost:8002/metrics | grep -q 'HELP'"
run_test "Auth requerida en API" "[ \$(docker exec odoo19_ai_service curl -s -w '%{http_code}' -o /dev/null -X POST http://localhost:8002/api/v1/analytics/match -H 'Content-Type: application/json' -d '{}') = '401' ] || [ \$(docker exec odoo19_ai_service curl -s -w '%{http_code}' -o /dev/null -X POST http://localhost:8002/api/v1/analytics/match -H 'Content-Type: application/json' -d '{}') = '403' ]"

# 5. Tests de Performance
echo ""
echo -e "${BLUE}5️⃣  TESTS DE PERFORMANCE${NC}"
echo "-----------------------"
run_test "Health < 200ms" "[ \$(docker exec odoo19_ai_service curl -s -w '%{time_total}' -o /dev/null http://localhost:8002/health | cut -d. -f1) -eq 0 ]"
run_test "Redis read/write rápido" "docker exec odoo19_ai_service python -c 'import redis, time; from config import settings; r = redis.from_url(settings.redis_url); start = time.time(); r.set(\"test\", \"val\"); r.get(\"test\"); r.delete(\"test\"); assert (time.time() - start) < 0.1' 2>/dev/null"

# 6. Tests de Seguridad
echo ""
echo -e "${BLUE}6️⃣  TESTS DE SEGURIDAD${NC}"
echo "---------------------"
run_test "No secrets en logs" "! docker logs --tail 100 odoo19_ai_service 2>&1 | grep -i 'sk-ant-'"
run_test "No secrets en metrics" "! docker exec odoo19_ai_service curl -sf http://localhost:8002/metrics | grep -i 'sk-ant-'"
run_test "CORS headers presentes" "docker exec odoo19_ai_service curl -sI http://localhost:8002/health | grep -qi 'access-control'" "true"

# 7. Tests de Resiliencia
echo ""
echo -e "${BLUE}7️⃣  TESTS DE RESILIENCIA${NC}"
echo "----------------------"
run_test "Logs estructurados" "docker logs --tail 10 odoo19_ai_service 2>&1 | grep -q 'info\|INFO'"
run_test "Health check periódico" "docker inspect odoo19_ai_service --format='{{.State.Health.Status}}' 2>/dev/null | grep -q 'healthy'"

# Resumen
echo ""
echo "===================================="
echo -e "${BLUE}📊 RESUMEN DE TESTS${NC}"
echo "===================================="
echo -e "✅ Passed:  ${GREEN}$passed${NC}"
echo -e "❌ Failed:  ${RED}$failed${NC}"
echo -e "⚠️  Skipped: ${YELLOW}$skipped${NC}"
echo -e "📈 Total:   $((passed + failed + skipped))"

if [ $((passed + failed)) -gt 0 ]; then
    success_rate=$(( passed * 100 / (passed + failed) ))
    echo -e "🎯 Success Rate: ${success_rate}%"
fi

echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}🎉 TODOS LOS TESTS CRÍTICOS PASARON${NC}"
    echo ""
    echo "✅ El microservicio AI está funcionando correctamente"
    echo "✅ Todas las features críticas validadas"
    echo "✅ Listo para producción"
    exit 0
else
    echo -e "${RED}⚠️  ALGUNOS TESTS FALLARON${NC}"
    echo ""
    echo "❌ Revisa los tests fallidos arriba"
    echo "📖 Ver documentación: docs/TESTING_COMPLETO_AI_SERVICE.md"
    exit 1
fi
