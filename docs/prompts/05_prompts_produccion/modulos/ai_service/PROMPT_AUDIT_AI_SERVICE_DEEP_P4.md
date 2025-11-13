# 🤖 Prompt Auditoría Profunda Microservicio IA - Nivel P4

**Fecha:** 2025-11-12  
**Nivel:** P4 (Máxima Precisión + Compliance)  
**Módulo:** AI Service (FastAPI + Claude API)  
**Status:** ✅ VALIDADO PARA COPILOT CLI

---

## 🎯 PROMPT EJECUTABLE PARA COPILOT CLI

```bash
# Ejecutar desde: /Users/pedro/Documents/odoo19
# Copilot CLI detectará automáticamente este prompt

@workspace Actúa como Auditor Experto en Microservicios Python (FastAPI) y Seguridad Cloud.

**OBJETIVO:** Auditoría técnica P4-Deep del microservicio IA que integra con Odoo 19 CE.

**MÓDULO EN ALCANCE:**
- ai-service/ (FastAPI + Claude API + Redis)
- Integración: docker-compose.yml (configuración ai-service)
- Dependencias: requirements.txt, Dockerfile

**CONTEXTO CRÍTICO:**

1. **Stack Técnico:**
   - FastAPI 0.115.0
   - Python 3.11-slim (container)
   - Claude API (Anthropic SDK)
   - Redis 7-alpine (cache + sessions)
   - Docker Compose (10 servicios)

2. **Arquitectura:**
   - Microservicio NON-CRITICAL (NO se usa para firma DTE)
   - Propósito: AI Chat, Project Matching, Analytics
   - Comunicación: HTTP REST API (puerto 8001)
   - Base de datos: Odoo PostgreSQL (readonly queries)

3. **Compliance Odoo 19 Docker:**
   - ✅ Comandos SOLO con: `docker compose exec ai-service [comando]`
   - ❌ NUNCA: comandos host directo (`python`, `pip`, `uvicorn`)
   - ✅ Testing: `docker compose exec ai-service pytest tests/ -v`

**DIMENSIONES DE AUDITORÍA (10 CRÍTICAS):**

**1. ✅ COMPLIANCE DOCKER + ODOO 19 (P0 - VALIDAR PRIMERO):**

Ejecutar validaciones automatizadas:

```bash
# 1.1 Verificar que ai-service está corriendo
docker compose ps ai-service

# 1.2 Validar healthcheck endpoint
docker compose exec ai-service curl -f http://localhost:8001/health || echo "FAIL"

# 1.3 Verificar logs recientes por errores críticos
docker compose logs ai-service --since 24h | grep -i "error\|critical\|exception" | tail -20

# 1.4 Validar conectividad Redis
docker compose exec ai-service python -c "import redis; r=redis.Redis(host='redis-master', port=6379, password='${REDIS_PASSWORD}'); print(r.ping())"

# 1.5 Validar conectividad Odoo DB (readonly)
docker compose exec ai-service python -c "import psycopg2; conn=psycopg2.connect('dbname=odoo19_db user=odoo host=db'); print('OK')"

# 1.6 Verificar API keys NO hardcodeadas
grep -rn "api_key.*=.*['\"]sk-" ai-service/ --exclude-dir=__pycache__

# Esperado: 0 matches (API keys deben venir de .env)
```

**2. 🔐 SEGURIDAD (P0 - CRÍTICO):**

```bash
# 2.1 Detectar secrets hardcodeados
grep -rn "api_key\|API_KEY\|secret\|SECRET\|password\|PASSWORD" ai-service/ \
  | grep -v ".pyc\|__pycache__\|.env.example" \
  | grep "=.*['\"]" \
  | head -20

# 2.2 Validar uso de environment variables
grep -rn "os.getenv\|os.environ" ai-service/config.py ai-service/main.py

# 2.3 Verificar HTTPS enforcement en producción
grep -rn "ssl_context\|HTTPS\|SSL" ai-service/ docker-compose.yml | head -10

# 2.4 Buscar vulnerabilidades SQL injection
grep -rn "execute.*%\|execute.*format\|execute.*f\"" ai-service/ \
  | grep -v ".pyc\|test_"

# 2.5 Validar CORS configuration
grep -rn "CORSMiddleware\|allow_origins" ai-service/main.py
```

**3. 🏗️ ARQUITECTURA Y PATRONES (P1):**

```bash
# 3.1 Contar endpoints REST API
grep -rn "@app\.\(get\|post\|put\|delete\)" ai-service/routes/ | wc -l

# 3.2 Validar uso de async/await
grep -rn "async def\|await " ai-service/ --include="*.py" | wc -l

# 3.3 Identificar patrones de diseño
grep -rn "class.*Factory\|class.*Singleton\|class.*Strategy" ai-service/

# 3.4 Verificar dependency injection
grep -rn "Depends\(" ai-service/routes/ ai-service/main.py | head -10

# 3.5 Validar error handling
grep -rn "try:\|except \|raise HTTPException" ai-service/ \
  --include="*.py" | wc -l
```

**4. ⚡ PERFORMANCE Y ESCALABILIDAD (P1):**

```bash
# 4.1 Validar timeouts configurados
grep -rn "timeout=\|TIMEOUT" ai-service/clients/ ai-service/config.py

# 4.2 Verificar circuit breaker implementation
ls -lah ai-service/utils/circuit_breaker.py
grep -rn "CircuitBreaker\|circuit_breaker" ai-service/

# 4.3 Validar caching strategy
grep -rn "@lru_cache\|redis.*set\|redis.*get" ai-service/utils/cache.py

# 4.4 Identificar N+1 queries potenciales
grep -rn "for.*in.*:\s*.*query\|for.*in.*:\s*.*select" ai-service/ \
  --include="*.py" | head -10

# 4.5 Verificar connection pooling
grep -rn "pool_size\|max_overflow\|pool_recycle" ai-service/
```

**5. 🧪 TESTING Y COBERTURA (P1):**

```bash
# 5.1 Contar archivos de tests
find ai-service/tests -name "test_*.py" -type f | wc -l

# 5.2 Ejecutar tests unitarios
docker compose exec ai-service pytest ai-service/tests/unit/ -v --tb=short

# 5.3 Verificar cobertura de código
docker compose exec ai-service pytest ai-service/tests/ \
  --cov=ai-service --cov-report=term-missing | tail -30

# 5.4 Validar mocks de servicios externos
grep -rn "@pytest.fixture\|@mock\|MagicMock" ai-service/tests/ | wc -l

# 5.5 Identificar tests de integración
find ai-service/tests/integration -name "*.py" -type f 2>/dev/null | wc -l
```

**6. 📊 OBSERVABILIDAD Y LOGGING (P2):**

```bash
# 6.1 Verificar logging estructurado
grep -rn "logger\.\(info\|error\|warning\|debug\)" ai-service/ \
  --include="*.py" | wc -l

# 6.2 Validar métricas exportadas
grep -rn "prometheus\|metric\|counter\|histogram" ai-service/middleware/

# 6.3 Verificar tracing distribuido
grep -rn "opentelemetry\|trace\|span" ai-service/

# 6.4 Validar health checks
curl -f http://localhost:8001/health -H "Content-Type: application/json"
curl -f http://localhost:8001/ready -H "Content-Type: application/json"

# 6.5 Revisar logs estructurados JSON
docker compose logs ai-service --tail=10 | grep -o "{.*}" | head -3
```

**7. 🔗 INTEGRACIÓN ODOO 19 (P1 - ESPECÍFICO):**

```bash
# 7.1 Validar endpoints expuestos a Odoo
grep -rn "@app.post.*odoo\|@app.get.*odoo" ai-service/routes/

# 7.2 Verificar autenticación Odoo
grep -rn "X-Odoo-Session\|Authorization" ai-service/middleware/

# 7.3 Validar queries readonly a Odoo DB
grep -rn "SELECT\|INSERT\|UPDATE\|DELETE" ai-service/ \
  --include="*.py" | grep -v "test_"

# 7.4 Verificar rate limiting Odoo → AI
grep -rn "rate_limit\|throttle\|RateLimiter" ai-service/middleware/

# 7.5 Validar response serialization
grep -rn "pydantic\|BaseModel\|schema" ai-service/models/
```

**8. 🐛 GESTIÓN DE ERRORES Y RESILENCIA (P1):**

```bash
# 8.1 Validar retry logic
grep -rn "retry\|backoff\|exponential" ai-service/clients/

# 8.2 Verificar fallback strategies
grep -rn "fallback\|default_response" ai-service/

# 8.3 Validar manejo de timeouts
grep -rn "TimeoutError\|asyncio.timeout\|timeout" ai-service/

# 8.4 Verificar graceful shutdown
grep -rn "signal\|SIGTERM\|shutdown" ai-service/main.py

# 8.5 Validar dead letter queue
grep -rn "dlq\|dead_letter" ai-service/
```

**9. 📦 DEPENDENCIAS Y CVEs (P0 - SEGURIDAD):**

```bash
# 9.1 Listar dependencias directas
cat ai-service/requirements.txt | grep -v "^#" | grep -v "^$"

# 9.2 Verificar versiones con CVEs conocidas
docker compose exec ai-service pip list --format=json | \
  grep -i "lxml\|pillow\|cryptography\|requests"

# 9.3 Validar actualizaciones de seguridad
grep -i "CVE\|security\|vulnerability" ai-service/requirements.txt

# 9.4 Verificar pinning de versiones
grep -rn "==" ai-service/requirements.txt | wc -l

# 9.5 Validar compatibilidad Python 3.11
docker compose exec ai-service python --version
```

**10. 🚀 DEPLOYMENT Y DEVOPS (P2):**

```bash
# 10.1 Validar configuración Docker Compose
grep -A20 "ai-service:" docker-compose.yml

# 10.2 Verificar restart policy
grep -A5 "ai-service:" docker-compose.yml | grep restart

# 10.3 Validar resource limits
grep -A20 "ai-service:" docker-compose.yml | grep -i "limit\|reserve"

# 10.4 Verificar networks y volumes
grep -A20 "ai-service:" docker-compose.yml | grep -i "network\|volume"

# 10.5 Validar environment variables
grep -A30 "ai-service:" docker-compose.yml | grep -A10 "environment:"
```

---

## 📋 ENTREGABLE ESPERADO

Generar archivo: `AUDITORIA_AI_SERVICE_P4_DEEP_[FECHA].md`

**Estructura:**

### 1. RESUMEN EJECUTIVO

- **Score Salud General:** X/100
- **Hallazgos P0 (Critical):** N
- **Hallazgos P1 (High):** N
- **Hallazgos P2 (Medium):** N
- **Hallazgos P3 (Low):** N
- **Estado Compliance Docker:** ✅/⚠️/❌

### 2. ✅ COMPLIANCE DOCKER + ODOO 19 (OBLIGATORIO)

**Validaciones Automatizadas (10):**

| ID | Validación | Resultado | Evidencia |
|----|------------|-----------|-----------|
| C1 | ai-service running | ✅/❌ | `docker compose ps ai-service` |
| C2 | Health endpoint | ✅/❌ | HTTP 200 /health |
| C3 | Logs sin errores críticos | ✅/⚠️/❌ | Últimas 24h |
| C4 | Conectividad Redis | ✅/❌ | redis.ping() |
| C5 | Conectividad Odoo DB | ✅/❌ | psycopg2.connect() |
| C6 | API keys no hardcodeadas | ✅/❌ | 0 matches |
| C7 | Environment vars | ✅/⚠️ | os.getenv usage |
| C8 | HTTPS enforcement | ✅/⚠️/❌ | Production config |
| C9 | CORS configurado | ✅/⚠️ | CORSMiddleware |
| C10 | Tests ejecutados | ✅/❌ | pytest exit code |

**Compliance Rate:** [X/10] = [%]

### 3. MATRIZ DE HALLAZGOS

| ID | Dimensión | Archivo:Línea | Descripción | Criticidad | Recomendación | Compliance Odoo19 |
|----|-----------|---------------|-------------|------------|---------------|-------------------|
| H1 | Seguridad | ai-service/config.py:25 | API key hardcodeada | P0 | Usar os.getenv() | NO |
| H2 | Performance | ai-service/clients/anthropic_client.py:45 | Sin timeout configurado | P1 | Agregar timeout=30 | N/A |
| ... | ... | ... | ... | ... | ... | ... |

### 4. ANÁLISIS POR DIMENSIÓN

**Para cada dimensión (1-10):**

- **Estado:** ✅ Excelente / ⚠️ Necesita mejoras / ❌ Crítico
- **Hallazgos:** Listado de problemas encontrados
- **Evidencias:** Comandos ejecutados + outputs
- **Recomendaciones:** Acciones específicas

### 5. COMANDOS DE VERIFICACIÓN REPRODUCIBLES

Lista de todos los comandos ejecutados para que puedan ser replicados:

```bash
# Ejemplo
docker compose ps ai-service
docker compose logs ai-service --tail=50 | grep ERROR
# ... etc
```

### 6. PLAN DE REMEDIACIÓN PRIORIZADO

**P0 (Inmediato - 24-48h):**
1. [H1] Eliminar API keys hardcodeadas
2. [H3] Configurar timeouts HTTP

**P1 (Corto Plazo - 1 semana):**
1. [H5] Implementar circuit breaker
2. [H8] Mejorar cobertura tests a 80%+

**P2 (Mediano Plazo - 2-4 semanas):**
1. [H10] Implementar métricas Prometheus
2. [H15] Documentar API endpoints

### 7. MÉTRICAS CUANTITATIVAS

```yaml
Código:
  Total Líneas Python: XXXX
  Total Archivos: XX
  Comentarios: XX%
  Funciones Async: XX

Tests:
  Archivos Test: XX
  Cobertura: XX%
  Tests Passed: XX/XX

Seguridad:
  Secrets Hardcodeados: X
  Vulnerabilidades CVE: X
  Dependencias Outdated: X

Performance:
  Endpoints: XX
  Timeout Configurados: XX/XX
  Circuit Breakers: XX
```

---

## 🚨 RESTRICCIONES Y MÁXIMAS

**MÁXIMA #0:** Validar compliance Docker + Odoo 19 PRIMERO. Ninguna auditoría procede sin verificar que el stack está corriendo.

**MÁXIMA #1:** Todos los comandos DEBEN ejecutarse dentro de containers (`docker compose exec`).

**MÁXIMA #2:** NO modificar ningún archivo. Auditoría en modo solo lectura.

**MÁXIMA #3:** Evidencias reproducibles. Cada hallazgo debe tener comando verificable.

**MÁXIMA #4:** Priorización clara. P0 = Bloqueante producción, P1 = Alta prioridad, P2 = Mejora, P3 = Nice-to-have.

**MÁXIMA #5:** Foco en seguridad. API keys, secrets, CVEs son P0 siempre.

---

## 📖 REFERENCIAS

**Documentación Proyecto:**
- `.github/copilot-instructions.md` (comandos Docker + Odoo CLI)
- `.github/agents/knowledge/docker_odoo_command_reference.md` (referencia completa)
- `.github/agents/knowledge/deployment_environment.md` (stack completo)
- `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md` (compliance Odoo)
- `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md` (12 máximas auditoría)

**Código Fuente:**
- `ai-service/` (código microservicio)
- `docker-compose.yml` (configuración servicios)
- `.env` (secrets - NO commitear)

**API Externa:**
- Anthropic Claude API: https://docs.anthropic.com/

---

## ✅ CHECKLIST PRE-EJECUCIÓN

Antes de ejecutar este prompt, verificar:

- [ ] Stack Docker corriendo: `docker compose ps`
- [ ] Archivo .env existe y tiene ANTHROPIC_API_KEY
- [ ] Redis accesible: `docker compose exec redis-master redis-cli ping`
- [ ] Odoo DB accesible: `docker compose exec db psql -U odoo -l`
- [ ] ai-service health OK: `curl http://localhost:8001/health`

---

**Fecha Creación:** 2025-11-12  
**Última Actualización:** 2025-11-12  
**Mantenedor:** Pedro Troncoso (@pwills85)  
**Nivel Prompt:** P4 (Máxima Precisión + Compliance)  
**Status:** ✅ VALIDADO PARA COPILOT CLI
```

---

## 🎯 CÓMO EJECUTAR CON COPILOT CLI

**Opción 1: Modo Interactivo**

```bash
# Desde /Users/pedro/Documents/odoo19
copilot

# Luego en el chat:
# "Lee y ejecuta el prompt: docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md"
```

**Opción 2: Modo Directo (Recomendado)**

```bash
cd /Users/pedro/Documents/odoo19

# Copilot CLI ejecutará el prompt completo
copilot -p "Ejecuta auditoría P4-Deep del microservicio IA siguiendo el prompt en docs/prompts/05_prompts_produccion/modulos/ai_service/PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md. Genera el output completo con todos los comandos Docker y la matriz de hallazgos."
```

**Opción 3: Modo Autónomo (Loop Continuo)**

```bash
# Loop autónomo hasta lograr éxito total
copilot /autonomous \
  "Auditoría P4-Deep microservicio IA según prompt PROMPT_AUDIT_AI_SERVICE_DEEP_P4.md" \
  /agent security-auditor \
  /max-iterations 10 \
  /success-threshold 0.95 \
  /auto-commit false
```

---

## 📊 OUTPUTS ESPERADOS

**Archivo generado:**
`docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_AI_SERVICE_P4_DEEP.md`

**Contenido:**
- Resumen ejecutivo con score salud
- Compliance Docker validado (10 checks)
- Matriz hallazgos completa (P0/P1/P2/P3)
- Análisis detallado 10 dimensiones
- Comandos verificación reproducibles
- Plan remediación priorizado
- Métricas cuantitativas

**Tiempo estimado ejecución:** 5-8 minutos (dependiendo de tests)

---

**🚀 Prompt listo para ejecución inmediata con Copilot CLI**
