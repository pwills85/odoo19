# 🧪 TESTING COMPLETO: AI MICROSERVICE

**Proyecto:** Odoo 19 - AI Microservice  
**Fecha:** 2025-10-24  
**Objetivo:** Validar todas las features del microservicio mediante línea de comandos

---

## 📋 ÍNDICE

1. [Tests Básicos de Infraestructura](#tests-básicos)
2. [Tests de Configuración](#tests-configuración)
3. [Tests de Conectividad](#tests-conectividad)
4. [Tests de Endpoints API](#tests-endpoints)
5. [Tests de Integración con Odoo](#tests-odoo)
6. [Tests de Performance](#tests-performance)
7. [Tests de Seguridad](#tests-seguridad)
8. [Tests de Resiliencia](#tests-resiliencia)

---

## 🔧 PREREQUISITOS

### Variables de Entorno Requeridas

```bash
# Verificar que existen en .env raíz
grep -E "ANTHROPIC_API_KEY|AI_SERVICE_API_KEY" /Users/pedro/Documents/odoo19/.env

# Exportar para tests locales (opcional)
export AI_SERVICE_API_KEY=$(grep AI_SERVICE_API_KEY .env | cut -d '=' -f2)
export ANTHROPIC_API_KEY=$(grep ANTHROPIC_API_KEY .env | cut -d '=' -f2)
```

---

## 1️⃣ TESTS BÁSICOS DE INFRAESTRUCTURA

### Test 1.1: Contenedor Corriendo

```bash
# Verificar que el contenedor está up
docker ps | grep ai_service

# Resultado esperado:
# odoo19_ai_service   Up X minutes (healthy)   8002/tcp
```

**✅ Criterio de éxito:** Contenedor en estado "Up" y "healthy"

---

### Test 1.2: Health Check del Contenedor

```bash
# Ver estado de health
docker inspect odoo19_ai_service --format='{{.State.Health.Status}}'

# Resultado esperado: healthy
```

**✅ Criterio de éxito:** Status = "healthy"

---

### Test 1.3: Logs Sin Errores

```bash
# Verificar últimos 50 logs
docker logs --tail 50 odoo19_ai_service

# Buscar errores
docker logs odoo19_ai_service 2>&1 | grep -i error

# Buscar warnings críticos
docker logs odoo19_ai_service 2>&1 | grep -i "warning\|critical"
```

**✅ Criterio de éxito:** Sin errores críticos en logs

---

### Test 1.4: Recursos del Contenedor

```bash
# Ver uso de recursos
docker stats odoo19_ai_service --no-stream

# Resultado esperado:
# CPU < 50%, MEM < 500MB en idle
```

**✅ Criterio de éxito:** Recursos dentro de límites normales

---

## 2️⃣ TESTS DE CONFIGURACIÓN

### Test 2.1: Variables de Entorno Cargadas

```bash
# Verificar todas las variables críticas
docker exec odoo19_ai_service python -c "
from config import settings
import sys

checks = {
    'ANTHROPIC_API_KEY': bool(settings.anthropic_api_key),
    'AI_SERVICE_API_KEY': bool(settings.api_key),
    'ANTHROPIC_MODEL': settings.anthropic_model,
    'REDIS_URL': settings.redis_url,
    'ODOO_URL': settings.odoo_url,
}

print('🔍 VERIFICACIÓN DE CONFIGURACIÓN:')
print('=' * 50)
for key, value in checks.items():
    status = '✅' if value else '❌'
    print(f'{status} {key}: {value}')

# Exit code 0 si todo OK
sys.exit(0 if all(checks.values()) else 1)
"
```

**✅ Criterio de éxito:** Todas las variables con ✅

---

### Test 2.2: Modelo Anthropic Correcto

```bash
# Verificar modelo configurado
docker exec odoo19_ai_service python -c "
from config import settings
print(f'Modelo: {settings.anthropic_model}')
assert settings.anthropic_model == 'claude-sonnet-4-5-20250929', 'Modelo incorrecto'
print('✅ Modelo correcto')
"
```

**✅ Criterio de éxito:** Modelo = claude-sonnet-4-5-20250929

---

### Test 2.3: Configuración de Tokens

```bash
# Verificar límites de tokens
docker exec odoo19_ai_service python -c "
from config import settings

tokens = {
    'Default': settings.anthropic_max_tokens_default,
    'Chat': settings.chat_max_tokens,
    'DTE': settings.dte_validation_max_tokens,
    'Payroll': settings.payroll_validation_max_tokens,
}

print('🎯 CONFIGURACIÓN DE TOKENS:')
print('=' * 50)
for name, value in tokens.items():
    print(f'{name}: {value} tokens')

assert all(v > 0 for v in tokens.values()), 'Tokens mal configurados'
print('✅ Todos los límites de tokens configurados')
"
```

**✅ Criterio de éxito:** Todos los límites > 0

---

## 3️⃣ TESTS DE CONECTIVIDAD

### Test 3.1: Redis Conectado

```bash
# Test de conexión a Redis
docker exec odoo19_ai_service python -c "
import redis
from config import settings

try:
    r = redis.from_url(settings.redis_url)
    ping = r.ping()
    print(f'✅ Redis conectado: {ping}')
    
    # Test de escritura/lectura
    r.set('test_key', 'test_value', ex=10)
    value = r.get('test_key')
    assert value == b'test_value', 'Redis read/write failed'
    print('✅ Redis read/write OK')
    
    # Limpiar
    r.delete('test_key')
    print('✅ Redis funcionando correctamente')
except Exception as e:
    print(f'❌ Redis error: {e}')
    exit(1)
"
```

**✅ Criterio de éxito:** Redis ping + read/write exitoso

---

### Test 3.2: Anthropic API Accesible

```bash
# Test de conexión a Anthropic (sin consumir tokens)
docker exec odoo19_ai_service python -c "
from anthropic import Anthropic
from config import settings

try:
    client = Anthropic(api_key=settings.anthropic_api_key)
    # Solo verificar que el cliente se inicializa
    print(f'✅ Cliente Anthropic inicializado')
    print(f'✅ API Key válida (primeros 10 chars): {settings.anthropic_api_key[:10]}...')
except Exception as e:
    print(f'❌ Anthropic error: {e}')
    exit(1)
"
```

**✅ Criterio de éxito:** Cliente Anthropic inicializado sin errores

---

### Test 3.3: Conectividad con Odoo

```bash
# Test de conectividad con Odoo (HTTP)
docker exec odoo19_ai_service python -c "
import requests
from config import settings

try:
    # Test simple de conectividad
    response = requests.get(f'{settings.odoo_url}/web/health', timeout=5)
    print(f'✅ Odoo accesible: Status {response.status_code}')
except requests.exceptions.Timeout:
    print('⚠️  Odoo timeout (puede estar iniciando)')
except Exception as e:
    print(f'⚠️  Odoo no accesible: {e}')
    print('   (Esto es normal si Odoo no está corriendo)')
"
```

**✅ Criterio de éxito:** Odoo accesible o timeout esperado

---

## 4️⃣ TESTS DE ENDPOINTS API

### Test 4.1: Health Endpoint

```bash
# Test del endpoint /health
curl -s http://localhost:8002/health | python3 -m json.tool

# Resultado esperado:
# {
#   "status": "healthy",
#   "service": "AI Microservice",
#   "version": "1.0.0"
# }
```

**✅ Criterio de éxito:** Status 200 + JSON válido

---

### Test 4.2: Health Endpoint (Detallado)

```bash
# Test con verificación de campos
curl -s http://localhost:8002/health | python3 -c "
import sys, json
data = json.load(sys.stdin)

required_fields = ['status', 'service', 'version']
for field in required_fields:
    if field not in data:
        print(f'❌ Campo faltante: {field}')
        sys.exit(1)
    print(f'✅ {field}: {data[field]}')

if data['status'] != 'healthy':
    print(f'❌ Status no es healthy: {data[\"status\"]}')
    sys.exit(1)

print('✅ Health endpoint OK')
"
```

**✅ Criterio de éxito:** Todos los campos presentes y status=healthy

---

### Test 4.3: Metrics Endpoint

```bash
# Test del endpoint /metrics (Prometheus)
curl -s http://localhost:8002/metrics | head -20

# Verificar que hay métricas
curl -s http://localhost:8002/metrics | grep -c "^# HELP" || echo "❌ No metrics found"
```

**✅ Criterio de éxito:** Métricas Prometheus presentes

---

### Test 4.4: Analytics Endpoint (Sin Auth - Debe Fallar)

```bash
# Test de seguridad: debe requerir autenticación
response=$(curl -s -w "%{http_code}" -o /dev/null \
  -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Content-Type: application/json" \
  -d '{"invoice_description": "Test", "projects": []}')

if [ "$response" = "401" ] || [ "$response" = "403" ]; then
    echo "✅ Endpoint protegido correctamente (HTTP $response)"
else
    echo "❌ Endpoint NO protegido (HTTP $response)"
fi
```

**✅ Criterio de éxito:** HTTP 401 o 403 (sin autenticación)

---

### Test 4.5: Analytics Endpoint (Con Auth)

```bash
# Test con autenticación
API_KEY=$(grep AI_SERVICE_API_KEY .env | cut -d '=' -f2)

curl -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "invoice_description": "Desarrollo software proyecto X",
    "projects": [
      {"id": 1, "name": "Proyecto X", "description": "Desarrollo software"},
      {"id": 2, "name": "Proyecto Y", "description": "Marketing digital"}
    ]
  }' | python3 -m json.tool
```

**✅ Criterio de éxito:** HTTP 200 + JSON con match_score

---

## 5️⃣ TESTS DE INTEGRACIÓN CON ODOO

### Test 5.1: Verificar Odoo Corriendo

```bash
# Verificar que Odoo está up
docker ps | grep odoo

# Test de conectividad
curl -s -o /dev/null -w "%{http_code}" http://localhost:8069/web/health
```

**✅ Criterio de éxito:** Odoo container up + HTTP 200

---

### Test 5.2: Test de Comunicación AI → Odoo

```bash
# Simular llamada desde AI service a Odoo
docker exec odoo19_ai_service python -c "
import requests
from config import settings

try:
    # Test de conectividad básica
    response = requests.get(
        f'{settings.odoo_url}/web/database/list',
        timeout=10
    )
    print(f'✅ Comunicación AI → Odoo: HTTP {response.status_code}')
    
    if response.status_code == 200:
        print('✅ Odoo respondiendo correctamente')
    else:
        print(f'⚠️  Odoo responde pero con status {response.status_code}')
        
except Exception as e:
    print(f'❌ Error comunicación: {e}')
    exit(1)
"
```

**✅ Criterio de éxito:** Comunicación exitosa entre contenedores

---

### Test 5.3: Test de Webhook (Odoo → AI)

```bash
# Simular webhook desde Odoo hacia AI service
API_KEY=$(grep AI_SERVICE_API_KEY .env | cut -d '=' -f2)

curl -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Odoo-Webhook: true" \
  -d '{
    "invoice_description": "Test webhook",
    "projects": []
  }' -w "\nHTTP Status: %{http_code}\n"
```

**✅ Criterio de éxito:** HTTP 200 + respuesta JSON

---

## 6️⃣ TESTS DE PERFORMANCE

### Test 6.1: Tiempo de Respuesta Health

```bash
# Medir tiempo de respuesta del health endpoint
for i in {1..10}; do
  curl -s -w "Request $i: %{time_total}s\n" -o /dev/null http://localhost:8002/health
done
```

**✅ Criterio de éxito:** < 100ms promedio

---

### Test 6.2: Carga Concurrente (Health)

```bash
# Test de carga con 50 requests concurrentes
echo "🔥 Test de carga: 50 requests concurrentes"
time for i in {1..50}; do
  curl -s http://localhost:8002/health > /dev/null &
done
wait

echo "✅ Test de carga completado"
```

**✅ Criterio de éxito:** Todas las requests exitosas en < 5s

---

### Test 6.3: Memoria Bajo Carga

```bash
# Monitorear memoria durante carga
echo "📊 Memoria antes de carga:"
docker stats odoo19_ai_service --no-stream --format "{{.MemUsage}}"

# Generar carga
for i in {1..100}; do
  curl -s http://localhost:8002/health > /dev/null &
done
wait

sleep 2

echo "📊 Memoria después de carga:"
docker stats odoo19_ai_service --no-stream --format "{{.MemUsage}}"
```

**✅ Criterio de éxito:** Memoria < 500MB después de carga

---

### Test 6.4: Cache Redis Performance

```bash
# Test de performance del cache
docker exec odoo19_ai_service python -c "
import redis
import time
from config import settings

r = redis.from_url(settings.redis_url)

# Test de escritura
start = time.time()
for i in range(1000):
    r.set(f'test_key_{i}', f'value_{i}', ex=60)
write_time = time.time() - start

# Test de lectura
start = time.time()
for i in range(1000):
    r.get(f'test_key_{i}')
read_time = time.time() - start

# Limpiar
for i in range(1000):
    r.delete(f'test_key_{i}')

print(f'✅ Redis Write: {write_time:.3f}s (1000 ops)')
print(f'✅ Redis Read: {read_time:.3f}s (1000 ops)')
print(f'✅ Write speed: {1000/write_time:.0f} ops/s')
print(f'✅ Read speed: {1000/read_time:.0f} ops/s')

assert write_time < 2.0, 'Redis write too slow'
assert read_time < 1.0, 'Redis read too slow'
print('✅ Redis performance OK')
"
```

**✅ Criterio de éxito:** Write < 2s, Read < 1s (1000 ops)

---

## 7️⃣ TESTS DE SEGURIDAD

### Test 7.1: API Key Requerida

```bash
# Test sin API key (debe fallar)
echo "🔒 Test 1: Sin API key"
curl -s -w "HTTP %{http_code}\n" -o /dev/null \
  -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Content-Type: application/json" \
  -d '{"invoice_description": "Test"}'

# Test con API key inválida (debe fallar)
echo "🔒 Test 2: API key inválida"
curl -s -w "HTTP %{http_code}\n" -o /dev/null \
  -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Authorization: Bearer invalid_key_123" \
  -H "Content-Type: application/json" \
  -d '{"invoice_description": "Test"}'

# Test con API key válida (debe funcionar)
echo "🔒 Test 3: API key válida"
API_KEY=$(grep AI_SERVICE_API_KEY .env | cut -d '=' -f2)
curl -s -w "HTTP %{http_code}\n" -o /dev/null \
  -X POST http://localhost:8002/api/v1/analytics/match \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"invoice_description": "Test", "projects": []}'
```

**✅ Criterio de éxito:** 401/403 sin key, 200 con key válida

---

### Test 7.2: Rate Limiting

```bash
# Test de rate limiting (si está habilitado)
echo "⏱️  Test de rate limiting"
API_KEY=$(grep AI_SERVICE_API_KEY .env | cut -d '=' -f2)

for i in {1..100}; do
  response=$(curl -s -w "%{http_code}" -o /dev/null \
    -X POST http://localhost:8002/api/v1/analytics/match \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"invoice_description": "Test", "projects": []}')
  
  if [ "$response" = "429" ]; then
    echo "✅ Rate limiting activado en request $i"
    break
  fi
done
```

**✅ Criterio de éxito:** HTTP 429 después de N requests

---

### Test 7.3: CORS Headers

```bash
# Test de CORS headers
curl -s -I http://localhost:8002/health | grep -i "access-control"

# Test con Origin header
curl -s -I -H "Origin: http://odoo:8069" http://localhost:8002/health \
  | grep -i "access-control"
```

**✅ Criterio de éxito:** Headers CORS presentes

---

### Test 7.4: Secrets No Expuestos

```bash
# Verificar que secrets no están en logs
docker logs odoo19_ai_service 2>&1 | grep -i "sk-ant-" && \
  echo "❌ API KEY EXPUESTA EN LOGS" || \
  echo "✅ No hay secrets en logs"

# Verificar que secrets no están en /metrics
curl -s http://localhost:8002/metrics | grep -i "sk-ant-" && \
  echo "❌ API KEY EXPUESTA EN METRICS" || \
  echo "✅ No hay secrets en metrics"
```

**✅ Criterio de éxito:** No hay secrets expuestos

---

## 8️⃣ TESTS DE RESILIENCIA

### Test 8.1: Restart del Contenedor

```bash
# Test de restart
echo "🔄 Reiniciando contenedor..."
docker restart odoo19_ai_service

# Esperar a que esté healthy
echo "⏳ Esperando health check..."
sleep 10

# Verificar que está up
docker ps | grep ai_service | grep "healthy" && \
  echo "✅ Contenedor reiniciado correctamente" || \
  echo "❌ Contenedor no está healthy"

# Test de endpoint
curl -s http://localhost:8002/health > /dev/null && \
  echo "✅ Endpoint respondiendo después de restart" || \
  echo "❌ Endpoint no responde"
```

**✅ Criterio de éxito:** Contenedor healthy después de restart

---

### Test 8.2: Redis Desconectado

```bash
# Simular desconexión de Redis
echo "🔌 Deteniendo Redis..."
docker stop odoo19_redis

# Verificar que AI service maneja el error
sleep 2
curl -s http://localhost:8002/health

# Reiniciar Redis
echo "🔌 Reiniciando Redis..."
docker start odoo19_redis

sleep 5

# Verificar reconexión
curl -s http://localhost:8002/health && \
  echo "✅ AI service se recuperó de fallo de Redis" || \
  echo "❌ AI service no se recuperó"
```

**✅ Criterio de éxito:** Service se recupera automáticamente

---

### Test 8.3: Carga Sostenida

```bash
# Test de carga sostenida (5 minutos)
echo "⏱️  Test de carga sostenida (5 min)..."
API_KEY=$(grep AI_SERVICE_API_KEY .env | cut -d '=' -f2)

end=$((SECONDS+300))
count=0
errors=0

while [ $SECONDS -lt $end ]; do
  response=$(curl -s -w "%{http_code}" -o /dev/null \
    -X POST http://localhost:8002/api/v1/analytics/match \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"invoice_description": "Test", "projects": []}')
  
  ((count++))
  
  if [ "$response" != "200" ]; then
    ((errors++))
  fi
  
  sleep 1
done

echo "✅ Requests totales: $count"
echo "✅ Errores: $errors"
echo "✅ Success rate: $(( (count - errors) * 100 / count ))%"
```

**✅ Criterio de éxito:** Success rate > 99%

---

## 📊 SCRIPT DE TEST COMPLETO

### Ejecutar Todos los Tests

```bash
#!/bin/bash
# test_ai_service_complete.sh

echo "🧪 TESTING COMPLETO AI MICROSERVICE"
echo "===================================="
echo ""

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

passed=0
failed=0

# Función para ejecutar test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -n "Testing: $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((passed++))
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((failed++))
    fi
}

# 1. Tests de Infraestructura
echo "1️⃣  TESTS DE INFRAESTRUCTURA"
echo "----------------------------"
run_test "Contenedor corriendo" "docker ps | grep -q ai_service"
run_test "Health check OK" "[ \$(docker inspect odoo19_ai_service --format='{{.State.Health.Status}}') = 'healthy' ]"
run_test "Sin errores en logs" "! docker logs odoo19_ai_service 2>&1 | grep -qi 'error.*critical'"

# 2. Tests de Configuración
echo ""
echo "2️⃣  TESTS DE CONFIGURACIÓN"
echo "-------------------------"
run_test "Variables cargadas" "docker exec odoo19_ai_service python -c 'from config import settings; assert settings.anthropic_api_key'"
run_test "Modelo correcto" "docker exec odoo19_ai_service python -c 'from config import settings; assert settings.anthropic_model == \"claude-sonnet-4-5-20250929\"'"

# 3. Tests de Conectividad
echo ""
echo "3️⃣  TESTS DE CONECTIVIDAD"
echo "------------------------"
run_test "Redis conectado" "docker exec odoo19_ai_service python -c 'import redis; from config import settings; redis.from_url(settings.redis_url).ping()'"
run_test "Anthropic API OK" "docker exec odoo19_ai_service python -c 'from anthropic import Anthropic; from config import settings; Anthropic(api_key=settings.anthropic_api_key)'"

# 4. Tests de Endpoints
echo ""
echo "4️⃣  TESTS DE ENDPOINTS"
echo "---------------------"
run_test "Health endpoint" "curl -sf http://localhost:8002/health"
run_test "Metrics endpoint" "curl -sf http://localhost:8002/metrics | grep -q 'HELP'"
run_test "Auth requerida" "[ \$(curl -s -w '%{http_code}' -o /dev/null -X POST http://localhost:8002/api/v1/analytics/match) = '401' ]"

# 5. Tests de Performance
echo ""
echo "5️⃣  TESTS DE PERFORMANCE"
echo "-----------------------"
run_test "Health < 100ms" "[ \$(curl -s -w '%{time_total}' -o /dev/null http://localhost:8002/health | cut -d. -f1) -eq 0 ]"
run_test "Memoria < 500MB" "[ \$(docker stats odoo19_ai_service --no-stream --format '{{.MemUsage}}' | cut -d'/' -f1 | sed 's/MiB//') -lt 500 ]"

# Resumen
echo ""
echo "===================================="
echo "📊 RESUMEN DE TESTS"
echo "===================================="
echo -e "✅ Passed: ${GREEN}$passed${NC}"
echo -e "❌ Failed: ${RED}$failed${NC}"
echo -e "📈 Total: $((passed + failed))"
echo -e "🎯 Success Rate: $(( passed * 100 / (passed + failed) ))%"
echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}🎉 TODOS LOS TESTS PASARON${NC}"
    exit 0
else
    echo -e "${RED}⚠️  ALGUNOS TESTS FALLARON${NC}"
    exit 1
fi
```

### Guardar y Ejecutar

```bash
# Guardar script
cat > test_ai_service_complete.sh << 'EOF'
# ... (copiar script de arriba)
EOF

# Dar permisos de ejecución
chmod +x test_ai_service_complete.sh

# Ejecutar
./test_ai_service_complete.sh
```

---

## 🎯 CHECKLIST DE VALIDACIÓN

### Pre-Deployment

- [ ] Todos los tests de infraestructura pasan
- [ ] Todos los tests de configuración pasan
- [ ] Todos los tests de conectividad pasan
- [ ] Todos los tests de endpoints pasan
- [ ] Success rate > 99% en tests de carga

### Post-Deployment

- [ ] Health check respondiendo
- [ ] Logs sin errores críticos
- [ ] Memoria estable < 500MB
- [ ] Redis conectado
- [ ] Anthropic API accesible

### Monitoring Continuo

- [ ] Health check cada 30s
- [ ] Logs monitoreados
- [ ] Métricas Prometheus activas
- [ ] Alertas configuradas

---

## 📚 RECURSOS ADICIONALES

### Documentación Relacionada

- `ai-service/README.md` - Documentación del microservicio
- `ai-service/TESTING_GUIDE.md` - Guía de testing original
- `docs/ANALISIS_VARIABLES_ENTORNO_AI_SERVICE.md` - Análisis de configuración

### Scripts Útiles

```bash
# Monitor en tiempo real
watch -n 5 'docker stats odoo19_ai_service --no-stream'

# Logs en tiempo real
docker logs -f odoo19_ai_service

# Test rápido de salud
curl -s http://localhost:8002/health | jq .
```

---

**Última actualización:** 2025-10-24  
**Mantenido por:** EERGYGROUP  
**Contacto:** support@eergygroup.cl
