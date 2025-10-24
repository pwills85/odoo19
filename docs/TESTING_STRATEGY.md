# 🧪 TESTING STRATEGY - ODOO 19 + DTE + AI Stack

**Fecha:** 2025-10-22
**Stack:** Odoo 19 CE | DTE Service | AI Service | PostgreSQL | Redis | RabbitMQ
**Objetivo:** Asegurar funcionalidad completa, conectividad y rendimiento del stack

---

## 📋 Índice

1. [Visión General](#visión-general)
2. [Arquitectura de Testing](#arquitectura-de-testing)
3. [Suite de Pruebas Integradas](#suite-de-pruebas-integradas)
4. [Ejecución de Tests](#ejecución-de-tests)
5. [Criterios de Éxito](#criterios-de-éxito)
6. [Troubleshooting](#troubleshooting)

---

## 🎯 Visión General

### Stack Completo

```
┌─────────────────────────────────────────────────────────────┐
│                    USUARIO FINAL                             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
         ┌─────────────────────────┐
         │   ODOO 19 Web UI        │
         │   Port: 8169            │
         └────────┬────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ↓             ↓             ↓
┌───────┐   ┌──────────┐   ┌──────────┐
│  DB   │   │   DTE    │   │   AI     │
│ PG 15 │   │ Service  │   │ Service  │
└───────┘   └──────────┘   └──────────┘
                │               │
                └───────┬───────┘
                        │
              ┌─────────┴─────────┐
              │                   │
              ↓                   ↓
         ┌────────┐          ┌─────────┐
         │ Redis  │          │RabbitMQ │
         │ Cache  │          │  Queue  │
         └────────┘          └─────────┘
```

### Componentes Críticos

| Componente | Puerto | Función | Criticidad |
|------------|--------|---------|------------|
| **PostgreSQL** | 5432 | Base de datos Odoo | 🔴 Crítico |
| **Redis** | 6379 | Cache & Sessions (DB 0: DTE, DB 1: AI) | 🟡 Alta |
| **RabbitMQ** | 5672, 15672 | Message Queue asíncrono | 🟡 Alta |
| **Odoo 19** | 8069/8169 | Aplicación web principal | 🔴 Crítico |
| **DTE Service** | 8001 | Microservicio DTEs | 🔴 Crítico |
| **AI Service** | 8002 | Microservicio IA (Claude) | 🟢 Media |

---

## 🏗️ Arquitectura de Testing

### Niveles de Testing

```
┌────────────────────────────────────────────────────┐
│  LEVEL 0: Prerequisites                            │
│  ✓ Docker, docker-compose, curl, jq               │
└────────────────────────────────────────────────────┘
                     ↓
┌────────────────────────────────────────────────────┐
│  LEVEL 1: Infrastructure                           │
│  ✓ Containers running                              │
│  ✓ Healthchecks passing                            │
│  ✓ Networks & Volumes                              │
└────────────────────────────────────────────────────┘
                     ↓
┌────────────────────────────────────────────────────┐
│  LEVEL 2-6: Individual Services                    │
│  ✓ Database connectivity                           │
│  ✓ Redis operations                                │
│  ✓ RabbitMQ messaging                              │
│  ✓ DTE Service endpoints                           │
│  ✓ AI Service endpoints                            │
│  ✓ Odoo application                                │
└────────────────────────────────────────────────────┘
                     ↓
┌────────────────────────────────────────────────────┐
│  LEVEL 8: Inter-Service Communication              │
│  ✓ Odoo → DTE Service                              │
│  ✓ Odoo → AI Service                               │
│  ✓ Services → Redis                                │
│  ✓ Services → RabbitMQ                             │
└────────────────────────────────────────────────────┘
                     ↓
┌────────────────────────────────────────────────────┐
│  LEVEL 9: Functional Tests                         │
│  ✓ AI Chat session creation                        │
│  ✓ Message processing                              │
│  ✓ RUT validation                                  │
└────────────────────────────────────────────────────┘
                     ↓
┌────────────────────────────────────────────────────┐
│  LEVEL 10: Performance Tests                       │
│  ✓ Resource usage                                  │
│  ✓ Response times                                  │
│  ✓ Throughput                                      │
└────────────────────────────────────────────────────┘
```

---

## 🧪 Suite de Pruebas Integradas

### PHASE 0: Prerequisites (4 tests)

**Objetivo:** Verificar herramientas necesarias

- ✅ `docker` command available
- ✅ `docker-compose` command available
- ✅ `curl` command available
- ✅ `jq` JSON processor available
- ✅ `.env` file exists

**Criterio de Éxito:** Todas las herramientas disponibles

---

### PHASE 1: Docker Infrastructure (15+ tests)

**Objetivo:** Validar que toda la infraestructura Docker está operativa

#### 1.1 Containers Running
```bash
docker ps --format '{{.Names}}' | grep odoo19_
```
- ✅ odoo19_db
- ✅ odoo19_redis
- ✅ odoo19_rabbitmq
- ✅ odoo19_dte_service
- ✅ odoo19_ai_service

#### 1.2 Health Checks
```bash
docker inspect --format='{{.State.Health.Status}}' <container>
```
- ✅ All services report "healthy"
- ⚠️ Services without healthcheck noted

#### 1.3 Networks
```bash
docker network inspect odoo19_stack_network
```
- ✅ Network exists
- ✅ All containers attached

#### 1.4 Volumes
```bash
docker volume inspect <volume>
```
- ✅ odoo19_postgres_data
- ✅ odoo19_odoo_filestore
- ✅ odoo19_rabbitmq_data

**Criterio de Éxito:** Todos los contenedores running y healthy

---

### PHASE 2: Database Connectivity (6+ tests)

**Objetivo:** Verificar PostgreSQL está operativo y Odoo DB inicializado

#### 2.1 PostgreSQL Connection
```bash
docker exec odoo19_db psql -U odoo -d odoo -c "SELECT 1;"
```
- ✅ Connection successful

#### 2.2 Database Exists
```bash
docker exec odoo19_db psql -U odoo -lqt | grep odoo
```
- ✅ Database 'odoo' exists

#### 2.3 Critical Tables
```sql
\dt ir_module_module
\dt res_users
\dt res_company
\dt account_move
```
- ✅ All core Odoo tables exist

**Criterio de Éxito:** DB accesible y con estructura Odoo correcta

---

### PHASE 3: Redis Connectivity (5 tests)

**Objetivo:** Validar Redis como cache/session store

#### 3.1 PING Test
```bash
docker exec odoo19_redis redis-cli ping
# Expected: PONG
```

#### 3.2 SET/GET Test
```bash
redis-cli SET test_key "test_value"
redis-cli GET test_key
# Expected: test_value
```

#### 3.3 Database Access
```bash
redis-cli -n 0 DBSIZE  # DTE Service
redis-cli -n 1 DBSIZE  # AI Service
```
- ✅ DB 0 accessible (DTE Service)
- ✅ DB 1 accessible (AI Service sessions)

**Criterio de Éxito:** Redis operativo en ambos DBs

---

### PHASE 4: RabbitMQ Connectivity (6 tests)

**Objetivo:** Verificar message queue para procesamiento asíncrono

#### 4.1 Health Check
```bash
docker exec odoo19_rabbitmq rabbitmq-diagnostics ping
```

#### 4.2 VHost Check
```bash
rabbitmqctl list_vhosts
# Expected: /odoo vhost exists
```

#### 4.3 Queues
```bash
rabbitmqctl list_queues -p /odoo name
```
Expected queues:
- ✅ `dte.generate`
- ✅ `dte.validate`
- ✅ `dte.send`

#### 4.4 Exchange
```bash
rabbitmqctl list_exchanges -p /odoo name type
# Expected: dte.direct (direct)
```

**Criterio de Éxito:** RabbitMQ con vhost /odoo y queues operativos

---

### PHASE 5: DTE Service Connectivity (6 tests)

**Objetivo:** Validar microservicio DTE está respondiendo

#### 5.1 Health Endpoint
```bash
curl http://dte-service:8001/health
# Expected: 200 OK
```

#### 5.2 API Documentation
```bash
curl http://dte-service:8001/docs
# Expected: 200 OK (FastAPI auto-docs)
```

#### 5.3 Metrics Endpoint
```bash
curl http://dte-service:8001/metrics
# Expected: Prometheus metrics
```

#### 5.4 RabbitMQ Connection
```bash
docker logs odoo19_dte_service | grep rabbitmq_connected
# Expected: Connection success log
```

#### 5.5 Redis Connection
```bash
docker logs odoo19_dte_service | grep redis
# Expected: No errors
```

**Criterio de Éxito:** DTE Service completamente operativo

---

### PHASE 6: AI Service Connectivity (5 tests)

**Objetivo:** Validar microservicio AI y conexión con Claude

#### 6.1 Health Endpoint
```bash
curl http://ai-service:8002/health
```
Response JSON:
```json
{
  "status": "healthy",
  "anthropic_configured": true,
  "redis_connected": true,
  "model": "claude-3-5-sonnet-20241022"
}
```

#### 6.2 Anthropic API Configured
- ✅ `anthropic_configured: true`
- ✅ ANTHROPIC_API_KEY presente

#### 6.3 Redis Connection
- ✅ `redis_connected: true`
- ✅ Sessions en Redis DB 1

#### 6.4 API Documentation
```bash
curl http://ai-service:8002/docs
# Expected: 200 OK
```

**Criterio de Éxito:** AI Service con Claude API configurado

---

### PHASE 7: Odoo Application (5 tests)

**Objetivo:** Validar Odoo web app y módulo l10n_cl_dte

#### 7.1 Web Interface
```bash
curl http://localhost:8169/web
# Expected: 303 redirect or 200 OK
```

#### 7.2 Log Analysis
```bash
docker logs odoo19_app | grep ERROR
# Expected: 0 errors
```

#### 7.3 Module Installation
```sql
SELECT state FROM ir_module_module WHERE name='l10n_cl_dte';
```
Expected states:
- ✅ `installed` - Module ready
- ⚠️ `to upgrade` - Needs update
- ⚠️ `to install` - Pending install

#### 7.4 Views Loaded
```sql
SELECT COUNT(*) FROM ir_ui_view WHERE name LIKE '%dte%';
```
- ✅ DTE views loaded (>20 views)

**Criterio de Éxito:** Odoo accesible y módulo instalado

---

### PHASE 8: Inter-Service Communication (6 tests)

**Objetivo:** Verificar comunicación entre servicios

#### 8.1 Odoo → DTE Service
```bash
docker exec odoo19_app curl http://dte-service:8001/health
# Expected: 200 OK from Odoo container
```

#### 8.2 Odoo → AI Service
```bash
docker exec odoo19_app curl http://ai-service:8002/health
# Expected: 200 OK from Odoo container
```

#### 8.3 DTE Service → Redis
```bash
docker logs odoo19_dte_service | grep redis
# Expected: Connection logs, no errors
```

#### 8.4 AI Service → Redis
```bash
curl http://localhost:8002/health | jq .redis_connected
# Expected: true
```

#### 8.5 DTE Service → RabbitMQ
```bash
docker logs odoo19_dte_service | grep rabbitmq_connected
# Expected: Connection success
```

**Criterio de Éxito:** Todos los servicios se comunican correctamente

---

### PHASE 9: Functional Tests (5 tests)

**Objetivo:** Probar funcionalidad end-to-end

#### 9.1 AI Chat Session Creation
```bash
curl -X POST http://localhost:8002/api/v1/chat/session \
  -H "Content-Type: application/json" \
  -d '{"user_id": "test_user"}'
```
Expected response:
```json
{
  "session_id": "uuid-xxxxx",
  "created_at": "2025-10-22T...",
  "user_id": "test_user"
}
```

#### 9.2 AI Chat Message Processing
```bash
curl -X POST http://localhost:8002/api/v1/chat/message \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "uuid-xxxxx",
    "message": "¿Qué es un DTE?"
  }'
```
Expected:
- ✅ Response with `reply` field
- ✅ Reply length > 10 characters
- ✅ Reply in Spanish

#### 9.3 RUT Validation (DTE Service)
```bash
curl http://localhost:8001/api/v1/validate/rut/76666666-6
```
Expected:
- ✅ Validation response
- ✅ Boolean `valid` field

#### 9.4 Module Wizard Access
- ✅ Menu "🤖 Asistente IA" accessible
- ✅ Wizard opens without errors
- ✅ All fields visible

**Criterio de Éxito:** Funcionalidad principal operativa

---

### PHASE 10: Performance Tests (4 tests)

**Objetivo:** Validar rendimiento del stack

#### 10.1 Resource Usage
```bash
docker stats --no-stream
```
Thresholds:
- ✅ CPU < 50% per container
- ✅ Memory < 80% allocated

#### 10.2 Response Times
```bash
curl -w "%{time_total}" http://localhost:8001/health
curl -w "%{time_total}" http://localhost:8002/health
```
Targets:
- ✅ DTE Service < 1.0s
- ✅ AI Service < 1.0s

#### 10.3 Database Query Performance
```sql
EXPLAIN ANALYZE SELECT * FROM account_move LIMIT 100;
```
- ✅ Query execution < 100ms

**Criterio de Éxito:** Performance dentro de umbrales aceptables

---

## 🚀 Ejecución de Tests

### Quick Start

```bash
# 1. Navegar al directorio del proyecto
cd /Users/pedro/Documents/odoo19

# 2. Hacer ejecutable el script
chmod +x tests/integration_test_suite.sh

# 3. Ejecutar suite completa
./tests/integration_test_suite.sh
```

### Salida Esperada

```
╔═══════════════════════════════════════════════════════════╗
║     ODOO 19 + DTE + AI - INTEGRATION TEST SUITE          ║
║     Comprehensive Stack Validation                       ║
╚═══════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════
PHASE 0: PREREQUISITES CHECK
═══════════════════════════════════════════════════════════
✅ Command 'docker' is available
✅ Command 'docker-compose' is available
✅ Command 'curl' is available
✅ Command 'jq' is available
✅ .env file exists

═══════════════════════════════════════════════════════════
PHASE 1: DOCKER INFRASTRUCTURE
═══════════════════════════════════════════════════════════
ℹ️  Checking if services are running...
✅ Service odoo19_db is running
✅ Service odoo19_redis is running
...
```

### Interpretación de Resultados

| Símbolo | Significado | Acción |
|---------|-------------|--------|
| ✅ | Test PASSED | OK - Continuar |
| ❌ | Test FAILED | CRÍTICO - Revisar logs |
| ⚠️ | Warning | Revisar - Puede ser OK |
| ℹ️ | Info | Solo informativo |

---

## ✅ Criterios de Éxito

### Criterio Mínimo (Stack Funcional)

Para considerar el stack **funcional**:

- ✅ **100% de tests PHASE 0-7** pasados (infraestructura + servicios individuales)
- ✅ **80% de tests PHASE 8** pasados (comunicación inter-servicios)
- ✅ **0 ERRORES** en logs de Odoo
- ✅ **Módulo l10n_cl_dte** en estado `installed`

### Criterio Óptimo (Stack Production-Ready)

Para considerar el stack **production-ready**:

- ✅ **100% de todos los tests** pasados
- ✅ **0 WARNINGS** críticos
- ✅ Response times < thresholds
- ✅ Resource usage < 70%
- ✅ All healthchecks `healthy`

### Métricas de Calidad

```
Test Success Rate = (Tests Passed / Total Tests) × 100%

┌────────────────────┬──────────────┬────────────┐
│ Success Rate       │ Estado       │ Acción     │
├────────────────────┼──────────────┼────────────┤
│ 100%               │ ✅ Excelente │ Deploy OK  │
│ 90-99%             │ 🟢 Bueno     │ Revisar    │
│ 80-89%             │ 🟡 Aceptable │ Fix antes  │
│ <80%               │ 🔴 Crítico   │ NO DEPLOY  │
└────────────────────┴──────────────┴────────────┘
```

---

## 🔧 Troubleshooting

### Problema 1: DTE Service Unhealthy

**Síntomas:**
```bash
odoo19_dte_service   Up 3 hours (unhealthy)
```

**Diagnóstico:**
```bash
# Ver logs
docker logs odoo19_dte_service | tail -50

# Posibles causas:
# 1. XSD schemas not downloaded
# 2. RabbitMQ connection failed
# 3. Redis connection failed
```

**Solución:**
```bash
# Download XSD schemas
docker exec odoo19_dte_service bash /app/scripts/download_xsd.sh

# Restart service
docker-compose restart dte-service
```

---

### Problema 2: AI Service No Responde

**Síntomas:**
```bash
curl http://localhost:8002/health
# Connection refused
```

**Diagnóstico:**
```bash
# Check if running
docker ps | grep ai_service

# Check logs
docker logs odoo19_ai_service
```

**Posibles Causas:**
- ANTHROPIC_API_KEY no configurado
- Redis DB 1 no accesible
- Puerto 8002 en uso

**Solución:**
```bash
# Verify API key
docker exec odoo19_ai_service env | grep ANTHROPIC

# Restart
docker-compose restart ai-service
```

---

### Problema 3: RabbitMQ Queues No Existen

**Síntomas:**
```bash
rabbitmqctl list_queues -p /odoo
# Empty result
```

**Solución:**
```bash
# Queues are created on first use - this is OK
# Send a test message to create them:

docker exec odoo19_dte_service python -c "
import pika
connection = pika.BlockingConnection(
    pika.URLParameters('amqp://admin:changeme@rabbitmq:5672//odoo')
)
channel = connection.channel()
channel.queue_declare(queue='dte.generate', durable=True)
channel.queue_declare(queue='dte.validate', durable=True)
channel.queue_declare(queue='dte.send', durable=True)
connection.close()
"
```

---

### Problema 4: Módulo l10n_cl_dte No Instalado

**Síntomas:**
```sql
SELECT state FROM ir_module_module WHERE name='l10n_cl_dte';
-- Result: to install
```

**Solución:**
```bash
# Install module
docker-compose run --rm odoo odoo -c /etc/odoo/odoo.conf \
  -d odoo -i l10n_cl_dte --stop-after-init

# Verify
docker-compose run --rm odoo odoo -c /etc/odoo/odoo.conf \
  -d odoo --stop-after-init
```

---

### Problema 5: Performance Slow

**Síntomas:**
- Response times > 2s
- High CPU/Memory usage

**Diagnóstico:**
```bash
# Check resources
docker stats --no-stream

# Check slow queries
docker exec odoo19_db psql -U odoo -d odoo -c "
SELECT query, mean_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
"
```

**Solución:**
```bash
# Increase resources in docker-compose.yml
# Add indexes to database
# Clear Redis cache
docker exec odoo19_redis redis-cli FLUSHDB
```

---

## 📊 Test Execution Log Template

Crear un registro de cada ejecución:

```markdown
# Test Execution Log

**Fecha:** 2025-10-22
**Ejecutado por:** [Nombre]
**Commit:** [Git commit hash]

## Resumen

- **Total Tests:** 75
- **Passed:** 72
- **Failed:** 3
- **Success Rate:** 96%
- **Duration:** 45s

## Tests Fallidos

1. **PHASE 5: DTE Service XSD Validation**
   - Status: ⚠️ Warning
   - Causa: XSD schemas not downloaded
   - Acción: Execute download_xsd.sh
   - Prioridad: Baja

2. **PHASE 9: AI Chat Response Time**
   - Status: ⚠️ Warning
   - Causa: First request (cold start)
   - Acción: None - expected behavior
   - Prioridad: Baja

## Métricas de Performance

- DTE Service health: 0.234s
- AI Service health: 0.456s
- PostgreSQL query: 23ms
- CPU Usage: 35% avg
- Memory Usage: 2.1GB / 8GB

## Conclusión

✅ Stack FUNCIONAL - Ready for development
```

---

## 🎯 Próximos Pasos

### Testing Automatizado (CI/CD)

1. **GitHub Actions Integration**
   ```yaml
   name: Integration Tests
   on: [push, pull_request]
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v2
         - name: Run tests
           run: ./tests/integration_test_suite.sh
   ```

2. **Scheduled Testing**
   - Nightly builds
   - Weekly full stack validation
   - Pre-deployment verification

3. **Performance Benchmarking**
   - Track response times over time
   - Resource usage trends
   - Alert on degradation

---

## 📚 Referencias

- **Odoo 19 Testing:** [Official Docs](https://www.odoo.com/documentation/19.0/developer/reference/backend/testing.html)
- **Docker Health Checks:** [Docker Docs](https://docs.docker.com/engine/reference/builder/#healthcheck)
- **FastAPI Testing:** [FastAPI Docs](https://fastapi.tiangolo.com/tutorial/testing/)
- **PostgreSQL Performance:** [PG Wiki](https://wiki.postgresql.org/wiki/Performance_Optimization)

---

**Documento creado:** 2025-10-22
**Última actualización:** 2025-10-22
**Mantenido por:** Eergygroup Development Team
