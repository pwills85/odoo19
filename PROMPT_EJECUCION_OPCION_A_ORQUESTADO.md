# 🎯 PROMPT: Ejecución Cierre de Brechas AI Service - Orquestado con Sub-Agentes

**Documento:** PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md  
**Versión:** 1.0  
**Fecha:** 2025-11-09  
**Autor:** Agente Coordinador Principal  
**Base:** AI_SERVICE_GAP_ANALYSIS_2025-11-09.md  
**Destinatarios:** Sub-agentes especializados de `.claude/agents/`

---

## 📋 CONTEXTO EJECUTIVO

### Situación Actual

El AI Microservice ha completado exitosamente **todas las implementaciones PHASE 1** (Prompt Caching, Streaming SSE, Token Pre-counting). Sin embargo, el análisis exhaustivo del agente remoto identificó **10 brechas críticas** que impiden despliegue a producción.

**Score Actual:** 82/100  
**Score Target:** 95/100  
**Gap:** 13 puntos (16% mejora requerida)

### Brechas Identificadas

| Prioridad | Cantidad | Impacto | Esfuerzo |
|-----------|----------|---------|----------|
| 🔴 **P1 (Critical)** | 5 | Alto - Bloquean producción | 2 semanas |
| 🟡 **P2 (Important)** | 3 | Medio - Afectan operación | 1 semana |
| 🟢 **P3 (Nice to Have)** | 2 | Bajo - Mejoras calidad | 2 días |
| **TOTAL** | **10** | **2,000 LOC afectadas (20.7%)** | **3-4 semanas** |

---

## 🎯 OBJETIVO DE ESTA EJECUCIÓN

**Cerrar las 10 brechas identificadas** mediante trabajo orquestado de 4 sub-agentes especializados, siguiendo metodología enterprise-grade con:

- ✅ **TDD (Test-Driven Development)** donde aplique
- ✅ **Commits atómicos** por brecha cerrada
- ✅ **Validación continua** con checkpoints
- ✅ **Documentación actualizada** en cada cambio
- ✅ **Rollback strategy** con Git tags

---

## 👥 SUB-AGENTES ASIGNADOS

### 1. **Test Automation Specialist** (`.claude/agents/test-automation.md`)

**Responsabilidad:** Brechas P1-1, P1-4, P1-5 (Testing)

**Alcance:**
- P1-1: Escribir tests para `anthropic_client.py` y `chat/engine.py` (≥80% coverage)
- P1-4: Configurar `pyproject.toml` con pytest + coverage
- P1-5: Tests de integración para features PHASE 1

**Herramientas:** pytest, pytest-cov, pytest-mock, pytest-asyncio

**Entregables:**
- `tests/unit/test_anthropic_client.py` (300+ LOC, ≥90% coverage)
- `tests/unit/test_chat_engine.py` (250+ LOC, ≥85% coverage)
- `tests/integration/test_prompt_caching.py` (80 LOC)
- `tests/integration/test_streaming_sse.py` (100 LOC)
- `tests/integration/test_token_precounting.py` (60 LOC)
- `pyproject.toml` actualizado con `[tool.pytest.ini_options]`

**Duración:** 10 días (2 semanas)

---

### 2. **AI & FastAPI Developer** (`.claude/agents/ai-fastapi-dev.md`)

**Responsabilidad:** Brechas P1-2, P2-1, P2-2 (Features core)

**Alcance:**
- P1-2: Resolver TODOs críticos (confidence calculado, métricas Redis, knowledge base loading)
- P2-1: Implementar loading de knowledge base desde markdown
- P2-2: Enhanced health checks (Anthropic API, Plugin Registry, Knowledge Base)

**Herramientas:** FastAPI, Pydantic, aiofiles, PyYAML, Redis client

**Entregables:**
- `chat/engine.py` actualizado con `_calculate_confidence()` (NO hardcoded 95.0)
- `main.py` actualizado con métricas SII Monitor desde Redis
- `chat/knowledge_base.py` con `_load_documents()` funcional
- `main.py` con enhanced `/health` endpoint (4 dependencies validadas)
- Tests unitarios para cada implementación

**Duración:** 5 días (1 semana)

---

### 3. **Docker & DevOps Expert** (`.claude/agents/docker-devops.md`)

**Responsabilidad:** Brechas P1-3, P2-3 (Infraestructura resiliente)

**Alcance:**
- P1-3: Configurar Redis HA con Sentinel (master + 2 replicas + 3 sentinels)
- P2-3: Implementar Prometheus alerting (Redis down, error rate, daily cost)

**Herramientas:** Docker Compose, Redis Sentinel, Prometheus, bash scripting

**Entregables:**
- `docker-compose.yml` actualizado con Redis HA (6 servicios)
- `config/sentinel.conf` (configuración Sentinel)
- `monitoring/prometheus/alerts.yml` (4 reglas de alertas)
- `scripts/test_redis_failover.sh` (script de validación)
- `docs/REDIS_HA_SETUP.md` (documentación completa)

**Duración:** 3 días

---

### 4. **DTE Compliance Expert** (`.claude/agents/dte-compliance.md`)

**Responsabilidad:** Validación final y compliance

**Alcance:**
- Validación read-only de cambios (NO modifica código)
- Verificar que no se afecta compliance SII
- Validar que tests cubren escenarios regulatorios

**Herramientas:** Read, Grep, WebFetch (solo lectura)

**Entregables:**
- Reporte de validación de compliance
- Checklist de escenarios regulatorios cubiertos

**Duración:** 1 día (validación post-implementación)

---

## 📅 PLAN DE EJECUCIÓN POR SPRINTS

### **SPRINT 0: Preparación y Backup** (30 minutos)

**Responsable:** Docker & DevOps Expert

**Tareas:**
1. Backup completo de base de datos
2. Crear Git tag de baseline: `sprint0_backup_ai_service_$(date +%Y%m%d)`
3. Validar estado inicial de tests
4. Documentar baseline metrics

**Comandos:**

```bash
# Backup DB
docker exec odoo19_postgres pg_dump -U odoo odoo_db > backups/ai_service_baseline_$(date +%Y%m%d).sql

# Git tag
git tag -a sprint0_backup_ai_service_$(date +%Y%m%d) -m "Baseline antes de cierre de brechas AI Service"

# Baseline tests
cd ai-service
pytest --collect-only -q | tee baseline_tests_count.txt
```

**Checkpoint:** ✅ Backup > 10MB, tag creado, tests baseline documentado

---

### **SPRINT 1: P1-1 Testing Foundation** (Días 1-5)

**Responsable:** Test Automation Specialist

#### **Fase 1.1: Configuración pytest (Día 1)**

**Comando para agente:**
```bash
# Invocar sub-agente
codex-test-automation "Ejecuta SPRINT 1 - FASE 1.1 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md:

Configura pyproject.toml con:
- [tool.pytest.ini_options]: minversion='7.0', testpaths=['tests'], markers (unit, integration, slow)
- addopts para coverage: --cov=. --cov-report=html --cov-fail-under=80
- [tool.coverage.run]: source=['.'], omit=['tests/*', 'venv/*']
- [tool.coverage.report]: fail_under=80, show_missing=true

Valida con:
pytest --version
pytest --markers
pytest --collect-only

Commit: 'test(config): add pytest configuration with coverage targets (80%)'
"
```

**Entregables:**
- `pyproject.toml` actualizado (50 líneas nuevas)
- Validación: `pytest --markers` muestra unit, integration, slow

**Checkpoint 1.1:** ✅ pytest configurado, markers validados

---

#### **Fase 1.2: Tests anthropic_client.py (Días 2-4)**

**Comando para agente:**
```bash
codex-test-automation "Ejecuta SPRINT 1 - FASE 1.2:

Crea tests/unit/test_anthropic_client.py con 10+ tests:

1. test_prompt_caching_enabled():
   - Mock client.messages.create
   - Validar cache_control={'type': 'ephemeral'} presente
   - Validar cache_read_tokens > 0 en segunda llamada

2. test_estimate_tokens():
   - Mock client.messages.count_tokens
   - Validar cálculo estimated_cost correcto
   - Validar pricing lookup desde CLAUDE_PRICING

3. test_token_precounting_blocks_expensive_requests():
   - Request con 200k tokens estimados
   - Validar ValueError raised
   - Validar NO llamó client.messages.create

4. test_validate_dte_with_caching():
   - Mock validate_dte completo
   - Validar system prompt cacheable
   - Validar cache_hit_rate calculado

5. test_circuit_breaker_triggers():
   - Simular 5 errores consecutivos
   - Validar CircuitBreakerError
   - Validar fallback response

Target: ≥90% coverage de anthropic_client.py

Valida con:
pytest tests/unit/test_anthropic_client.py -v --cov=clients/anthropic_client.py --cov-report=term-missing

Commit: 'test(anthropic_client): add comprehensive unit tests (90% coverage)'
"
```

**Entregables:**
- `tests/unit/test_anthropic_client.py` (300+ LOC)
- Coverage ≥90% de `anthropic_client.py`

**Checkpoint 1.2:** ✅ Coverage ≥90% validado

---

#### **Fase 1.3: Tests chat/engine.py (Días 4-5)**

**Comando para agente:**
```bash
codex-test-automation "Ejecuta SPRINT 1 - FASE 1.3:

Crea tests/unit/test_chat_engine.py con 8+ tests:

1. test_send_message():
   - Mock anthropic_client, context_manager, knowledge_base
   - Validar ChatResponse structure
   - Validar confidence calculado (NO hardcoded 95.0)

2. test_calculate_confidence():
   - Casos: muchas fuentes (95%), pocas (75%), sin fuentes (50%)
   - Casos: respuesta larga (boost), corta (penalty)
   - Validar range 0-100

3. test_send_message_with_plugin():
   - Mock plugin_registry.get_plugin_for_query
   - Validar plugin_used en response

4. test_send_message_stream():
   - Mock async generator
   - Validar chunks yielded correctamente

Target: ≥85% coverage de chat/engine.py

Valida con:
pytest tests/unit/test_chat_engine.py -v --cov=chat/engine.py

Commit: 'test(chat_engine): add comprehensive unit tests (85% coverage)'
"
```

**Entregables:**
- `tests/unit/test_chat_engine.py` (250+ LOC)
- Coverage ≥85% de `chat/engine.py`

**Checkpoint 1.3:** ✅ Total coverage ≥80% alcanzado

**Score después de Sprint 1:** 82/100 → 89/100 (+7 puntos por testing)

---

### **SPRINT 2: P1-5 Tests de Integración PHASE 1** (Días 6-7)

**Responsable:** Test Automation Specialist

#### **Fase 2.1: Test Prompt Caching End-to-End**

**Comando para agente:**
```bash
codex-test-automation "Ejecuta SPRINT 2 - FASE 2.1:

Crea tests/integration/test_prompt_caching.py:

@pytest.mark.integration
async def test_prompt_caching_reduces_cost():
    client = AnthropicClient(api_key=settings.anthropic_api_key, model='claude-sonnet-4-5-20250929')
    
    dte_data = {...}
    history = []
    
    # Primera llamada (crea cache)
    result1 = await client.validate_dte(dte_data, history)
    usage1 = ...
    
    # Segunda llamada (usa cache)
    result2 = await client.validate_dte(dte_data, history)
    usage2 = ...
    
    # Validaciones
    assert usage2['cache_read_tokens'] > 0
    assert usage2['cache_hit_rate'] > 0.8
    assert usage2['cost_usd'] < usage1['cost_usd'] * 0.15

IMPORTANTE: Usar @pytest.mark.integration para no correr en CI por default.

Commit: 'test(integration): add prompt caching end-to-end validation'
"
```

---

#### **Fase 2.2: Test Streaming SSE**

**Comando para agente:**
```bash
codex-test-automation "Ejecuta SPRINT 2 - FASE 2.2:

Crea tests/integration/test_streaming_sse.py:

@pytest.mark.integration
async def test_streaming_returns_chunks():
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    
    with client.stream('POST', '/api/chat/message/stream', 
                       json={'session_id': 'test', 'message': '¿Qué es DTE 33?'}) as response:
        
        chunks = []
        for line in response.iter_lines():
            if line.startswith('data: '):
                chunk = json.loads(line[6:])
                chunks.append(chunk)
        
        assert len(chunks) > 1
        assert chunks[0]['type'] == 'text'
        assert chunks[-1]['type'] == 'done'
        assert 'metadata' in chunks[-1]

Commit: 'test(integration): add streaming SSE validation'
"
```

---

#### **Fase 2.3: Test Token Pre-counting**

**Comando para agente:**
```bash
codex-test-automation "Ejecuta SPRINT 2 - FASE 2.3:

Crea tests/integration/test_token_precounting.py:

@pytest.mark.integration
async def test_token_precounting_blocks_expensive_request():
    settings.enable_token_precounting = True
    settings.max_estimated_cost_per_request = 0.01  # $0.01 limit
    
    client = AnthropicClient(...)
    
    # Payload enorme (>100k tokens)
    huge_dte_data = {
        'tipo_dte': '33',
        'items': [{'description': 'x' * 10000} for _ in range(100)]
    }
    
    result = await client.validate_dte(huge_dte_data, [])
    
    assert result['confidence'] == 0.0
    assert any('too expensive' in str(w).lower() for w in result['warnings'])

Commit: 'test(integration): add token pre-counting budget enforcement validation'
"
```

**Checkpoint Sprint 2:** ✅ Tests integración PHASE 1 completos (10+ tests)

**Score después de Sprint 2:** 89/100 → 92/100 (+3 puntos por integration tests)

---

### **SPRINT 3: P1-2 TODOs Críticos** (Días 8-10)

**Responsable:** AI & FastAPI Developer

#### **Fase 3.1: Fix Hardcoded confidence=95.0**

**Comando para agente:**
```bash
codex-ai-fastapi-dev "Ejecuta SPRINT 3 - FASE 3.1:

En chat/engine.py, implementa _calculate_confidence():

def _calculate_confidence(
    self,
    response_text: str,
    sources_count: int,
    llm_used: str,
    plugin_used: Optional[str] = None
) -> float:
    '''
    Calcula confidence basado en:
    - Fuentes encontradas (más fuentes = mayor confidence)
    - Largo de respuesta (muy corto = penalty)
    - LLM usado (Anthropic > otros)
    - Plugin usado (plugin específico = boost)
    
    Returns:
        float: Confidence 0-100
    '''
    base_confidence = 85.0 if llm_used == 'anthropic' else 75.0
    source_boost = min(sources_count * 1.5, 15)
    length_penalty = -15 if len(response_text) < 50 else (-5 if len(response_text) < 100 else 0)
    plugin_boost = 5 if plugin_used else 0
    
    confidence = base_confidence + source_boost + length_penalty + plugin_boost
    return max(0, min(100, confidence))

Reemplaza en send_message() línea 237:
    confidence=self._calculate_confidence(
        response_text=response_text,
        sources_count=len(relevant_docs),
        llm_used=llm_used,
        plugin_used=plugin_module
    ),

Escribe tests unitarios para validar esta función.

Valida:
grep -n 'confidence=95.0' chat/engine.py  # Debe retornar vacío

Commit: 'feat(chat): implement dynamic confidence calculation (fix hardcoded 95.0)'
"
```

---

#### **Fase 3.2: Métricas SII Monitor desde Redis**

**Comando para agente:**
```bash
codex-ai-fastapi-dev "Ejecuta SPRINT 3 - FASE 3.2:

En main.py, actualiza endpoint /api/sii/monitor/stats:

@app.get('/api/sii/monitor/stats')
async def get_sii_monitor_stats():
    from utils.redis_helper import get_redis_client
    
    redis = get_redis_client()
    
    last_execution = redis.get('sii_monitor:last_execution')
    news_count = redis.get('sii_monitor:news_count_24h') or 0
    
    return {
        'status': 'active',
        'last_execution': last_execution,
        'news_count_last_24h': int(news_count)
    }

Valida:
grep -n 'TODO.*Agregar métricas' main.py  # Debe retornar vacío

Commit: 'feat(sii_monitor): implement real metrics from Redis (remove TODO)'
"
```

---

#### **Fase 3.3: Knowledge Base Loading**

**Comando para agente:**
```bash
codex-ai-fastapi-dev "Ejecuta SPRINT 3 - FASE 3.3:

En chat/knowledge_base.py, implementa _load_documents():

def _load_documents(self) -> List[Dict[str, Any]]:
    import yaml
    from pathlib import Path
    
    docs = []
    knowledge_path = Path(settings.knowledge_base_path)
    
    if not knowledge_path.exists():
        logger.warning('knowledge_base_path_not_found', path=str(knowledge_path))
        return []
    
    for md_file in knowledge_path.glob('**/*.md'):
        try:
            content = md_file.read_text(encoding='utf-8')
            
            # Parse frontmatter
            if content.startswith('---'):
                _, frontmatter, body = content.split('---', 2)
                metadata = yaml.safe_load(frontmatter)
            else:
                metadata = {}
                body = content
            
            doc = {
                'title': metadata.get('title', md_file.stem),
                'module': metadata.get('module', 'general'),
                'tags': metadata.get('tags', []),
                'content': body.strip(),
                'file_path': str(md_file)
            }
            
            docs.append(doc)
            
        except Exception as e:
            logger.error('knowledge_base_load_error', file=str(md_file), error=str(e))
    
    logger.info('knowledge_base_loaded', doc_count=len(docs))
    return docs

Actualiza __init__ para llamar a _load_documents().

Escribe tests unitarios.

Valida:
grep -n 'TODO.*Load from' chat/knowledge_base.py  # Debe retornar vacío

Commit: 'feat(knowledge_base): implement markdown file loading (remove TODO)'
"
```

**Checkpoint Sprint 3:** ✅ 3 TODOs críticos resueltos

**Score después de Sprint 3:** 92/100 → 95/100 (+3 puntos por TODOs resueltos)

---

### **SPRINT 4: P2-2 Enhanced Health Checks** (Día 11)

**Responsable:** AI & FastAPI Developer

**Comando para agente:**
```bash
codex-ai-fastapi-dev "Ejecuta SPRINT 4:

En main.py, actualiza /health endpoint:

@app.get('/health')
async def health_check():
    health = {
        'status': 'healthy',
        'service': settings.app_name,
        'version': settings.app_version,
        'timestamp': datetime.utcnow().isoformat(),
        'dependencies': {}
    }
    
    # 1. Redis (existente - mantener)
    try:
        redis_client = get_redis_client()
        redis_client.ping()
        health['dependencies']['redis'] = {'status': 'up'}
    except Exception as e:
        health['dependencies']['redis'] = {'status': 'down', 'error': str(e)[:200]}
        health['status'] = 'degraded'
    
    # 2. Anthropic API (NUEVO)
    try:
        client = AnthropicClient(api_key=settings.anthropic_api_key, model=settings.anthropic_model)
        test_tokens = await client.estimate_tokens(
            messages=[{'role': 'user', 'content': 'test'}],
            system='test'
        )
        health['dependencies']['anthropic'] = {
            'status': 'up',
            'model': settings.anthropic_model,
            'test_tokens': test_tokens['input_tokens']
        }
    except Exception as e:
        health['dependencies']['anthropic'] = {'status': 'down', 'error': str(e)[:200]}
        health['status'] = 'degraded'
    
    # 3. Plugin Registry (NUEVO)
    try:
        registry = PluginRegistry()
        modules = registry.list_modules()
        health['dependencies']['plugin_registry'] = {
            'status': 'up',
            'modules_count': len(modules),
            'modules': modules[:5]
        }
    except Exception as e:
        health['dependencies']['plugin_registry'] = {'status': 'down', 'error': str(e)[:200]}
        health['status'] = 'degraded'
    
    # 4. Knowledge Base (NUEVO)
    try:
        kb = KnowledgeBase()
        doc_count = len(kb.documents)
        health['dependencies']['knowledge_base'] = {
            'status': 'up' if doc_count > 0 else 'empty',
            'documents_count': doc_count
        }
        if doc_count == 0:
            health['status'] = 'degraded'
    except Exception as e:
        health['dependencies']['knowledge_base'] = {'status': 'down', 'error': str(e)[:200]}
        health['status'] = 'degraded'
    
    status_code = 200 if health['status'] == 'healthy' else 503
    return JSONResponse(content=health, status_code=status_code)

Escribe tests de integración.

Valida:
curl http://localhost:8002/health | jq .dependencies

Commit: 'feat(health): add enhanced health checks (4 dependencies)'
"
```

**Checkpoint Sprint 4:** ✅ Health checks validados

**Score después de Sprint 4:** 95/100 → 96/100 (+1 punto por observabilidad)

---

### **SPRINT 5: P1-3 Redis HA con Sentinel** (Días 12-14)

**Responsable:** Docker & DevOps Expert

#### **Fase 5.1: Configurar Redis HA**

**Comando para agente:**
```bash
codex-docker-devops "Ejecuta SPRINT 5 - FASE 5.1:

Actualiza docker-compose.yml con Redis HA:

services:
  # Redis Master
  redis-master:
    image: redis:7-alpine
    container_name: odoo19_redis_master
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_master_data:/data
    networks:
      - stack_network
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis Replica 1
  redis-replica-1:
    image: redis:7-alpine
    container_name: odoo19_redis_replica_1
    command: redis-server --replicaof redis-master 6379 --appendonly yes
    depends_on:
      - redis-master
    volumes:
      - redis_replica_1_data:/data
    networks:
      - stack_network

  # Redis Replica 2
  redis-replica-2:
    image: redis:7-alpine
    container_name: odoo19_redis_replica_2
    command: redis-server --replicaof redis-master 6379 --appendonly yes
    depends_on:
      - redis-master
    volumes:
      - redis_replica_2_data:/data
    networks:
      - stack_network

  # Sentinel 1
  redis-sentinel-1:
    image: redis:7-alpine
    container_name: odoo19_sentinel_1
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./config/sentinel.conf:/etc/redis/sentinel.conf
    depends_on:
      - redis-master
    networks:
      - stack_network

  # Sentinel 2
  redis-sentinel-2:
    image: redis:7-alpine
    container_name: odoo19_sentinel_2
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./config/sentinel.conf:/etc/redis/sentinel.conf
    depends_on:
      - redis-master
    networks:
      - stack_network

  # Sentinel 3
  redis-sentinel-3:
    image: redis:7-alpine
    container_name: odoo19_sentinel_3
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./config/sentinel.conf:/etc/redis/sentinel.conf
    depends_on:
      - redis-master
    networks:
      - stack_network

volumes:
  redis_master_data:
  redis_replica_1_data:
  redis_replica_2_data:

Crea config/sentinel.conf:
sentinel monitor mymaster redis-master 6379 2
sentinel down-after-milliseconds mymaster 5000
sentinel parallel-syncs mymaster 1
sentinel failover-timeout mymaster 10000

Actualiza ai-service environment:
  - REDIS_SENTINEL_HOSTS=redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379
  - REDIS_MASTER_NAME=mymaster

Actualiza utils/redis_helper.py para usar Sentinel.

Commit: 'feat(redis): implement Redis HA with Sentinel (master + 2 replicas)'
"
```

---

#### **Fase 5.2: Test de Failover**

**Comando para agente:**
```bash
codex-docker-devops "Ejecuta SPRINT 5 - FASE 5.2:

Crea script scripts/test_redis_failover.sh:

#!/bin/bash
set -e

echo '1. Estado inicial:'
docker exec odoo19_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster

echo '2. Matando master...'
docker stop odoo19_redis_master

echo '3. Esperando failover (10s)...'
sleep 10

echo '4. Nuevo master:'
docker exec odoo19_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster

echo '5. Validar que AI service sigue funcionando:'
curl http://localhost:8002/health

echo '6. Reviviendo master original:'
docker start odoo19_redis_master

Ejecuta test:
bash scripts/test_redis_failover.sh

Documenta en docs/REDIS_HA_SETUP.md:
- Arquitectura (diagrama ASCII)
- Configuración
- Proceso de failover
- Troubleshooting
- Backup/restore

Commit: 'docs(redis): add Redis HA setup and failover testing guide'
"
```

**Checkpoint Sprint 5:** ✅ Redis HA validado, failover funcional

**Score después de Sprint 5:** 96/100 → 98/100 (+2 puntos por infraestructura resiliente)

---

### **SPRINT 6: P2-3 Prometheus Alerting** (Día 15)

**Responsable:** Docker & DevOps Expert

**Comando para agente:**
```bash
codex-docker-devops "Ejecuta SPRINT 6:

Crea monitoring/prometheus/alerts.yml:

groups:
  - name: ai_service_alerts
    interval: 30s
    rules:
      # Redis Down
      - alert: RedisDown
        expr: up{job='redis'} == 0
        for: 1m
        labels:
          severity: critical
          service: ai-service
        annotations:
          summary: 'Redis instance is down'
          description: 'Redis {{ \$labels.instance }} has been down for more than 1 minute'
      
      # High Error Rate
      - alert: HighErrorRate
        expr: rate(http_request_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
          service: ai-service
        annotations:
          summary: 'High error rate detected'
          description: 'Error rate is {{ \$value | humanizePercentage }} (threshold: 10%)'
      
      # Daily Cost Exceeded
      - alert: DailyCostExceeded
        expr: sum(increase(claude_api_cost_usd_total[24h])) > 50
        for: 1h
        labels:
          severity: warning
          service: ai-service
        annotations:
          summary: 'Daily cost exceeded \$50'
          description: 'Claude API cost in last 24h: \${{ \$value }}'
      
      # Cache Hit Rate Low
      - alert: LowCacheHitRate
        expr: rate(claude_cache_read_tokens_total[10m]) / rate(claude_input_tokens_total[10m]) < 0.5
        for: 15m
        labels:
          severity: info
          service: ai-service
        annotations:
          summary: 'Cache hit rate below 50%'
          description: 'Current cache hit rate: {{ \$value | humanizePercentage }}'

Documenta en docs/PROMETHEUS_ALERTING.md.

Valida:
promtool check rules monitoring/prometheus/alerts.yml

Commit: 'feat(monitoring): add Prometheus alerting rules (4 alerts)'
"
```

**Checkpoint Sprint 6:** ✅ Prometheus alerting configurado

**Score después de Sprint 6:** 98/100 → 99/100 (+1 punto por alerting)

---

### **SPRINT 7: P3 Mejoras Nice-to-Have** (Día 16)

**Responsables:** AI & FastAPI Developer + Docker & DevOps Expert

**Comando para agentes:**
```bash
# P3-2: Rate Limiting Mejorado
codex-ai-fastapi-dev "Ejecuta SPRINT 7 - P3-2:

En main.py, actualiza rate limiting:

def get_user_identifier(request: Request):
    api_key = request.headers.get('Authorization', 'unknown')
    ip = get_remote_address(request)
    return f'{api_key}:{ip}'

limiter = Limiter(key_func=get_user_identifier)

Commit: 'feat(security): improve rate limiting with API key + IP (P3-2)'
"

# P3-1: Documentar API Keys
codex-docker-devops "Ejecuta SPRINT 7 - P3-1:

En config.py línea 25, actualiza comentario:

api_key: str = 'default_ai_api_key'  # ⚠️ DEVELOPMENT ONLY - MUST override with env var ANTHROPIC_API_KEY in production

Commit: 'docs(config): clarify default API key is for development only (P3-1)'
"
```

**Checkpoint Sprint 7:** ✅ P3 mejoras completadas

**Score después de Sprint 7:** 99/100 → 100/100 (+1 punto por mejoras de seguridad)

---

### **SPRINT 8: Validación Final y Documentación** (Día 17)

**Responsable:** DTE Compliance Expert (Read-only validation)

**Comando para agente:**
```bash
codex-dte-compliance "VALIDACIÓN READ-ONLY - NO MODIFICAR CÓDIGO:

Valida que los cambios implementados NO afectan compliance SII:

1. Validar que libs/ sigue sin dependencias Odoo
2. Validar que DTE validation sigue usando safe_xml_parser
3. Validar que tests cubren escenarios regulatorios (RUT modulo 11, CAF validation)
4. Validar que AI Service NO está en critical path (solo chat/analytics)

Genera reporte: AI_SERVICE_COMPLIANCE_VALIDATION_REPORT.md

Checklist esperado:
- [ ] libs/ sin dependencias ORM (grep 'from odoo import' libs/)
- [ ] safe_xml_parser usado en validaciones DTE
- [ ] Tests cubren RUT modulo 11 (3 formatos)
- [ ] Tests cubren CAF signature validation
- [ ] AI Service NO en critical path (confirmado en arquitectura)
"
```

**Entregable:**
- `AI_SERVICE_COMPLIANCE_VALIDATION_REPORT.md` (reporte read-only)

**Checkpoint Final:** ✅ Compliance validado, NO regresiones

---

## 📊 MÉTRICAS DE ÉXITO

### Coverage Targets

| Archivo | Coverage Inicial | Coverage Target | Coverage Final |
|---------|------------------|-----------------|----------------|
| **anthropic_client.py** | 0% | ≥90% | ___% |
| **chat/engine.py** | 0% | ≥85% | ___% |
| **Total AI Service** | ~65% | ≥80% | ___% |

### TODOs Resolution

| TODO | Status Inicial | Status Final |
|------|----------------|--------------|
| confidence=95.0 | ❌ Hardcoded | ✅ Calculado |
| Métricas SII Monitor | ❌ Dummy | ✅ Redis real |
| Knowledge Base loading | ❌ Vacío | ✅ Markdown loaded |

### Infrastructure

| Componente | Status Inicial | Status Final |
|------------|----------------|--------------|
| Redis | ❌ SPOF | ✅ HA (3 sentinels) |
| Health Checks | ⚠️ 2/5 | ✅ 5/5 |
| Alerting | ❌ 0/4 | ✅ 4/4 |

### Score Progression

```
Sprint 0:  82/100  (baseline)
Sprint 1:  89/100  (+7 - testing foundation)
Sprint 2:  92/100  (+3 - integration tests)
Sprint 3:  95/100  (+3 - TODOs críticos)
Sprint 4:  96/100  (+1 - health checks)
Sprint 5:  98/100  (+2 - Redis HA)
Sprint 6:  99/100  (+1 - Prometheus)
Sprint 7: 100/100  (+1 - P3 mejoras)
```

---

## ✅ CHECKLIST FINAL

Antes de marcar como completo, validar:

### Testing (35 puntos)
- [ ] pytest configurado con coverage en pyproject.toml
- [ ] tests/unit/test_anthropic_client.py (300+ LOC, ≥90% coverage)
- [ ] tests/unit/test_chat_engine.py (250+ LOC, ≥85% coverage)
- [ ] tests/integration/test_prompt_caching.py (validación end-to-end)
- [ ] tests/integration/test_streaming_sse.py (validación chunks)
- [ ] tests/integration/test_token_precounting.py (budget enforcement)
- [ ] Total coverage ≥80% medido con pytest-cov

### Features Core (20 puntos)
- [ ] `_calculate_confidence()` implementado (NO hardcoded 95.0)
- [ ] Métricas SII Monitor desde Redis (NO dummy data)
- [ ] Knowledge Base loading desde markdown funcional
- [ ] Enhanced /health endpoint (4 dependencies validadas)
- [ ] TODOs críticos: 0/3 (eliminados o resueltos)

### Infraestructura (30 puntos)
- [ ] Redis HA con Sentinel (master + 2 replicas + 3 sentinels)
- [ ] Failover automático validado (test script ejecutado)
- [ ] Persistence configurada (RDB + AOF)
- [ ] Prometheus alerting (4 reglas configuradas)
- [ ] Documentación completa (REDIS_HA_SETUP.md, PROMETHEUS_ALERTING.md)

### Compliance (10 puntos)
- [ ] Validación read-only completada por DTE Compliance Expert
- [ ] Sin regresiones en compliance SII
- [ ] Tests cubren escenarios regulatorios
- [ ] Reporte de validación generado

### Documentación (5 puntos)
- [ ] Coverage report HTML generado
- [ ] README actualizado con nuevas features
- [ ] CHANGELOG con todos los cambios
- [ ] Commits atómicos con mensajes convencionales

---

## 🚀 COMANDOS DE INICIO RÁPIDO

### Iniciar Ejecución Completa

```bash
# 1. Crear branch de trabajo
git checkout -b feat/ai_service_gap_closure

# 2. Ejecutar SPRINT 0 (backup)
codex-docker-devops "Ejecuta SPRINT 0 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"

# 3. Ejecutar sprints secuencialmente
codex-test-automation "Ejecuta SPRINT 1 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-test-automation "Ejecuta SPRINT 2 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-ai-fastapi-dev "Ejecuta SPRINT 3 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-ai-fastapi-dev "Ejecuta SPRINT 4 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-docker-devops "Ejecuta SPRINT 5 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-docker-devops "Ejecuta SPRINT 6 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-ai-fastapi-dev "Ejecuta SPRINT 7 - P3-2 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-docker-devops "Ejecuta SPRINT 7 - P3-1 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-dte-compliance "VALIDACIÓN READ-ONLY - SPRINT 8 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"

# 4. Validación final
pytest --cov=. --cov-report=html --cov-fail-under=80
bash scripts/test_redis_failover.sh
curl http://localhost:8002/health | jq
```

### Validación Pre-Push

```bash
# Checklist final antes de PR
pytest --cov=. --cov-fail-under=80 -v
docker-compose config --quiet
grep -r "TODO" ai-service/ --include="*.py" | wc -l  # Debe ser ≤3
promtool check rules monitoring/prometheus/alerts.yml
bash scripts/test_redis_failover.sh
```

---

## 🔴 PROHIBICIONES ABSOLUTAS

Durante la ejecución de este PROMPT:

❌ **NO improvisar** soluciones no documentadas aquí
❌ **NO saltarse checkpoints** de validación
❌ **NO hacer commits sin ejecutar tests**
❌ **NO modificar código sin tests primero** (TDD preferido)
❌ **NO ignorar warnings de coverage**
❌ **NO skip tests sin justificación** documentada
❌ **NO deployar sin validar health checks**
❌ **NO modificar docker-compose.yml sin backup**

✅ **SÍ seguir** PEP8 y Google Style docstrings
✅ **SÍ usar** type hints estrictos
✅ **SÍ documentar** cada cambio en commit message
✅ **SÍ validar** cada sprint antes de continuar
✅ **SÍ hacer** commits atómicos por brecha cerrada

---

## 📎 REFERENCIAS

- **Análisis Base:** `docs/gap-closure/AI_SERVICE_GAP_ANALYSIS_2025-11-09.md`
- **Sub-agentes:** `.claude/agents/` (test-automation, ai-fastapi-dev, docker-devops, dte-compliance)
- **Knowledge Base:** `.claude/agents/knowledge/` (project_architecture, sii_regulatory_context, odoo19_patterns)
- **Branch de Trabajo:** `feat/ai_service_gap_closure`
- **Tag Baseline:** `sprint0_backup_ai_service_$(date +%Y%m%d)`

---

## 🎯 OBJETIVO FINAL

**Al completar este PROMPT:**

- ✅ **Score:** 100/100 (de 82/100)
- ✅ **Coverage:** ≥80% (de ~65%)
- ✅ **TODOs Críticos:** 0 (de 3)
- ✅ **Infraestructura:** Redis HA + Prometheus alerting
- ✅ **Tests:** 50+ tests nuevos (unit + integration)
- ✅ **Compliance:** Validado sin regresiones

**Resultado:** AI Service production-ready con calidad enterprise-grade

---

**Última Actualización:** 2025-11-09  
**Versión del PROMPT:** 1.0  
**Autor:** Agente Coordinador Principal  
**Estado:** ✅ LISTO PARA EJECUCIÓN
