# 🎯 PROMPT: Cierre Total de Brechas AI Service - PHASE 1 Quality Assurance

**Documento:** GAP_CLOSURE_PHASE1_QA_PROMPT.md
**Versión:** 1.0
**Fecha:** 2025-11-09
**Autor:** Claude Analysis Agent
**Destinatario:** Equipo de Agentes Especializados (.claude/agents/)

---

## 📋 CONTEXTO EJECUTIVO

### Situación Actual

El AI Microservice (`ai-service/`) ha completado exitosamente la implementación de **todas las features PHASE 1**:

✅ **Implementado (100%):**
- Prompt Caching (90% cost reduction)
- Streaming SSE (3x mejor UX)
- Token Pre-counting (budget control)
- Cost Tracking completo
- Circuit Breaker resiliente

❌ **Pendiente (Brechas de Calidad):**
- Test Coverage formal: **desconocido** (estimado 60-70%, target 80%)
- Tests unitarios features PHASE 1: **0%**
- Redis SPOF: **sin HA/failover**
- TODOs críticos: **3 sin resolver**
- Enhanced health checks: **incompletos**

### Objetivo de Esta Misión

**Elevar el score del microservicio de 82/100 a 95/100** mediante:
1. Testing comprehensivo (≥80% coverage)
2. Infraestructura resiliente (Redis HA)
3. Cierre de TODOs críticos
4. Enhanced observability

---

## 🎯 MISIÓN: Cierre Profesional de Brechas AI Service PHASE 1

**Contexto:**
Eres un Senior Software Engineer responsable del cierre completo de las 10 brechas identificadas en el AI Microservice (ai-service). Las implementaciones core de PHASE 1 (Prompt Caching, Streaming SSE, Token Pre-counting) están funcionales, pero requieren testing robusto, configuración profesional e infraestructura resiliente.

**Objetivo:**
Elevar el score del microservicio de **82/100** a **95/100** mediante cierre sistemático de brechas, testing comprehensivo y configuración enterprise-grade.

**Restricciones:**
- ❌ NO improvisar soluciones
- ❌ NO crear parches temporales
- ❌ NO saltarse tests
- ✅ SÍ seguir best practices de Python 3.11+
- ✅ SÍ usar type hints estrictos
- ✅ SÍ documentar con docstrings Google Style
- ✅ SÍ validar cada cambio con tests

---

## 📋 INVENTARIO DE BRECHAS (10 Total)

### 🔴 P1 - CRÍTICAS (5 brechas)

#### **P1-1: Test Coverage No Medida Formalmente**
- **Ubicación:** `tests/`, `clients/anthropic_client.py` (483 LOC), `chat/engine.py` (658 LOC)
- **Problema:**
  - Sin tests para anthropic_client.py
  - Sin tests para chat/engine.py
  - Sin pytest.ini ni .coveragerc
  - Coverage real: desconocido (estimado 60-70%)
- **Target:** ≥80% coverage medido formalmente
- **Entregables:**
  - `tests/unit/test_anthropic_client.py` (nuevo)
  - `tests/unit/test_chat_engine.py` (nuevo)
  - `pyproject.toml` actualizado con [tool.pytest.ini_options]
  - Reporte HTML de coverage

#### **P1-2: TODOs en Código Productivo**
- **Ubicación:** 14 TODOs en 9 archivos
- **TODOs Críticos:**
  1. `chat/engine.py:237` - Hardcoded `confidence=95.0`
  2. `main.py:797` - Métricas no implementadas
  3. `chat/knowledge_base.py:52` - Knowledge base no carga desde markdown
- **Target:** 0 TODOs críticos, ≤3 TODOs no-críticos documentados
- **Entregables:**
  - Implementación de `_calculate_confidence()` en `chat/engine.py`
  - Métricas SII Monitor desde Redis
  - Knowledge base loading desde `/app/knowledge/*.md`

#### **P1-3: Redis SPOF (Single Point of Failure)**
- **Ubicación:** `docker-compose.yml:29-41`
- **Problema:**
  - Sin replication
  - Sin Sentinel
  - Sin persistence (RDB/AOF)
  - Sin backup strategy
- **Target:** Redis HA con automatic failover
- **Entregables:**
  - `docker-compose.yml` actualizado con Redis Sentinel (1 master + 2 replicas)
  - Configuración de persistence (RDB + AOF)
  - Health checks actualizados
  - Documentación de failover

#### **P1-4: Configuración Formal de Testing Faltante**
- **Ubicación:** `pyproject.toml`
- **Problema:** Sin [tool.pytest.ini_options] ni [tool.coverage.*]
- **Target:** Configuración enterprise-grade de testing
- **Entregables:**
  - `pyproject.toml` con pytest config completa
  - Markers (unit, integration, slow)
  - Coverage thresholds (80%)
  - Pre-commit hooks configurados

#### **P1-5: Tests de Integración No Cubren Features PHASE 1**
- **Ubicación:** `tests/integration/`
- **Problema:** Sin tests para prompt caching, streaming, token pre-counting
- **Target:** Integration tests comprehensivos para PHASE 1
- **Entregables:**
  - `tests/integration/test_prompt_caching.py` (nuevo)
  - `tests/integration/test_streaming_sse.py` (nuevo)
  - `tests/integration/test_token_precounting.py` (nuevo)

---

### 🟡 P2 - IMPORTANTES (3 brechas)

#### **P2-1: Knowledge Base In-Memory (No Escalable)**
- **Ubicación:** `chat/knowledge_base.py:52`
- **Target:** Implementar loading desde markdown files
- **Entregables:**
  - Método `_load_documents()` implementado
  - Lectura de `/app/knowledge/*.md`
  - Parsing de metadata (module, title, tags)

#### **P2-2: Health Check Incompleto**
- **Ubicación:** `main.py:231-268`
- **Problema:** No verifica Anthropic API, Plugin Registry, Knowledge Base
- **Target:** Enhanced health checks
- **Entregables:**
  - Validación de Anthropic API connectivity
  - Validación de Plugin Registry
  - Validación de Knowledge Base loaded

#### **P2-3: Prometheus Alerting Faltante**
- **Ubicación:** `monitoring/` (NO EXISTE)
- **Target:** Configuración de alertas Prometheus
- **Entregables:**
  - `monitoring/prometheus/alerts.yml` (nuevo)
  - Alertas para Redis down, error rate >10%, daily cost >$50

---

### 🟢 P3 - MEJORAS (2 brechas)

#### **P3-1: Hardcoded Default API Keys**
- **Ubicación:** `config.py:25`
- **Target:** Mejorar documentación
- **Entregables:** Comentario claro indicando uso solo en desarrollo

#### **P3-2: Rate Limiting IP-based (Bypasseable)**
- **Ubicación:** `main.py:67`
- **Target:** Rate limiting por API key + IP
- **Entregables:** `get_user_identifier()` implementado

---

## 🤖 ORQUESTACIÓN DE SUB-AGENTES

**IMPORTANTE:** Debes orquestar sub-agentes especializados de `.claude/agents/` para garantizar calidad enterprise-grade. NO trabajes directamente en el código sin validación de expertos.

### Sub-agentes Disponibles:

1. **`Test Automation Specialist`** (.claude/agents)
   - **Responsabilidad:** P1-1, P1-4, P1-5 (testing)
   - **Scope:** Escribir tests unitarios e integración con ≥80% coverage
   - **Entregables:**
     - tests/unit/test_anthropic_client.py
     - tests/unit/test_chat_engine.py
     - tests/integration/test_prompt_caching.py
     - tests/integration/test_streaming_sse.py
     - tests/integration/test_token_precounting.py
     - pyproject.toml con pytest config

2. **`Docker & DevOps Expert`** (.claude/agents)
   - **Responsabilidad:** P1-3 (Redis HA), P2-3 (Prometheus Alerting)
   - **Scope:** Infraestructura resiliente y observabilidad
   - **Entregables:**
     - docker-compose.yml con Redis Sentinel
     - monitoring/prometheus/alerts.yml
     - Documentación de failover

3. **`AI & FastAPI Developer`** (.claude/agents)
   - **Responsabilidad:** P1-2 (TODOs), P2-1 (Knowledge Base), P2-2 (Health Checks)
   - **Scope:** Features core del microservicio
   - **Entregables:**
     - _calculate_confidence() implementado
     - Knowledge base loading desde markdown
     - Enhanced health checks

4. **`DTE Compliance Expert`** (.claude/agents)
   - **Responsabilidad:** Validación de calidad y compliance
   - **Scope:** Review final de cambios
   - **Entregables:** Reporte de validación de compliance

---

## 📐 WORKFLOW PASO A PASO

### **FASE 1: Configuración de Testing (Días 1-2)**

**Sub-agente:** Test Automation Specialist

```bash
# Paso 1.1: Crear configuración pytest
Task: "Crea pyproject.toml [tool.pytest.ini_options] con:
  - minversion = '7.0'
  - testpaths = ['tests']
  - addopts para coverage (--cov=. --cov-report=html --cov-fail-under=80)
  - markers: unit, integration, slow
  - [tool.coverage.run] con source=['.'] y omit=['tests/*']
  - [tool.coverage.report] con fail_under=80 y show_missing=true
"

# Validación:
pytest --version
pytest --markers  # Verificar markers configurados
```

**Checkpoint 1.1:** ✅ pyproject.toml validado con pytest --collect-only

---

### **FASE 2: Tests Unitarios (Días 2-5)**

**Sub-agente:** Test Automation Specialist

```bash
# Paso 2.1: Tests para anthropic_client.py
Task: "Crea tests/unit/test_anthropic_client.py que cubra:

1. test_prompt_caching_enabled():
   - Mock client.messages.create
   - Validar que cache_control={'type': 'ephemeral'} está presente
   - Validar cache_read_tokens > 0 en uso

2. test_estimate_tokens():
   - Mock client.messages.count_tokens
   - Validar cálculo de estimated_cost correcto
   - Validar pricing lookup desde CLAUDE_PRICING

3. test_token_precounting_blocks_expensive_requests():
   - Request con 200k tokens estimados
   - Validar ValueError raised
   - Validar NO llamó client.messages.create

4. test_validate_dte_with_caching():
   - Mock completo de validate_dte
   - Validar system prompt cacheable
   - Validar tracking de cache_hit_rate

5. test_circuit_breaker_triggers():
   - Simular 5 errores consecutivos
   - Validar CircuitBreakerError raised
   - Validar fallback response

Target: ≥90% coverage de anthropic_client.py
"

# Validación:
pytest tests/unit/test_anthropic_client.py -v --cov=clients/anthropic_client.py --cov-report=term-missing
```

**Checkpoint 2.1:** ✅ Coverage de anthropic_client.py ≥90%

```bash
# Paso 2.2: Tests para chat/engine.py
Task: "Crea tests/unit/test_chat_engine.py que cubra:

1. test_send_message():
   - Mock anthropic_client
   - Mock context_manager
   - Mock knowledge_base
   - Validar ChatResponse structure
   - Validar confidence calculado (NO hardcoded 95.0)

2. test_send_message_with_plugin():
   - Mock plugin_registry.get_plugin_for_query
   - Validar plugin_used en response
   - Validar system prompt incluye plugin context

3. test_calculate_confidence():
   - Casos: muchas fuentes (95%), pocas fuentes (75%), sin fuentes (50%)
   - Casos: respuesta larga (boost), respuesta corta (penalty)
   - Validar range 0-100

4. test_send_message_stream():
   - Mock async generator
   - Validar chunks yielded correctamente
   - Validar metadata final con tokens_used

5. test_build_plugin_system_prompt():
   - Validar plugin_prompt incluido
   - Validar knowledge_base docs incluidos
   - Validar user_context incluido

Target: ≥85% coverage de chat/engine.py
"

# Validación:
pytest tests/unit/test_chat_engine.py -v --cov=chat/engine.py --cov-report=term-missing
```

**Checkpoint 2.2:** ✅ Coverage de chat/engine.py ≥85%

---

### **FASE 3: Tests de Integración PHASE 1 (Días 5-7)**

**Sub-agente:** Test Automation Specialist

```bash
# Paso 3.1: Test Prompt Caching End-to-End
Task: "Crea tests/integration/test_prompt_caching.py:

@pytest.mark.integration
async def test_prompt_caching_reduces_cost():
    '''Validar que segunda llamada usa cache y reduce cost.'''

    client = AnthropicClient(api_key=settings.anthropic_api_key, model='claude-sonnet-4-5-20250929')

    dte_data = {...}  # Mismo payload
    history = []

    # Primera llamada (crea cache)
    result1 = await client.validate_dte(dte_data, history)
    usage1 = ...  # Obtener usage del tracker

    # Segunda llamada (usa cache)
    result2 = await client.validate_dte(dte_data, history)
    usage2 = ...

    # Validaciones
    assert usage2['cache_read_tokens'] > 0, 'Cache no fue usado'
    assert usage2['cache_hit_rate'] > 0.8, 'Cache hit rate bajo'
    assert usage2['cost_usd'] < usage1['cost_usd'] * 0.15, 'Cost no redujo 85%'

IMPORTANTE: Usar @pytest.mark.integration para tests que llaman Anthropic API real.
Solo correr con --integration flag para evitar costos.
"

# Validación:
pytest tests/integration/test_prompt_caching.py -v -m integration --integration
```

**Checkpoint 3.1:** ✅ Prompt caching validado con API real

```bash
# Paso 3.2: Test Streaming SSE End-to-End
Task: "Crea tests/integration/test_streaming_sse.py:

@pytest.mark.integration
async def test_streaming_returns_chunks():
    '''Validar que streaming retorna chunks en tiempo real.'''

    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)

    # Stream request
    with client.stream('POST', '/api/chat/message/stream',
                       json={'session_id': 'test', 'message': '¿Qué es DTE 33?'},
                       headers={'Authorization': f'Bearer {settings.api_key}'}) as response:

        chunks = []
        for line in response.iter_lines():
            if line.startswith('data: '):
                chunk = json.loads(line[6:])
                chunks.append(chunk)

        # Validaciones
        assert len(chunks) > 1, 'No streaming (solo 1 chunk)'
        assert chunks[0]['type'] == 'text', 'Primer chunk no es texto'
        assert chunks[-1]['type'] == 'done', 'Último chunk no es done'
        assert 'metadata' in chunks[-1], 'Metadata faltante'
        assert 'tokens_used' in chunks[-1]['metadata'], 'tokens_used faltante'
        assert 'cache_read_tokens' in chunks[-1]['metadata']['tokens_used'], 'cache metrics faltantes'
"

# Validación:
pytest tests/integration/test_streaming_sse.py -v -m integration
```

**Checkpoint 3.2:** ✅ Streaming SSE validado

```bash
# Paso 3.3: Test Token Pre-counting Budget Enforcement
Task: "Crea tests/integration/test_token_precounting.py:

@pytest.mark.integration
async def test_token_precounting_blocks_expensive_request():
    '''Validar que requests caros son bloqueados ANTES de llamar API.'''

    from config import settings
    settings.enable_token_precounting = True
    settings.max_estimated_cost_per_request = 0.01  # $0.01 limit

    client = AnthropicClient(api_key=settings.anthropic_api_key, model='claude-sonnet-4-5-20250929')

    # Crear payload enorme (>100k tokens)
    huge_dte_data = {
        'tipo_dte': '33',
        'items': [{'description': 'x' * 10000} for _ in range(100)]  # ~1M chars
    }

    # Validar que bloquea sin llamar API
    result = await client.validate_dte(huge_dte_data, [])

    assert result['confidence'] == 0.0, 'Debió bloquear request'
    assert any('too expensive' in str(w).lower() for w in result['warnings']), 'Warning incorrecto'

    # Validar que NO incrementó contador de API calls
    # (verificar en Anthropic dashboard: 0 requests)
"

# Validación:
pytest tests/integration/test_token_precounting.py -v -m integration
```

**Checkpoint 3.3:** ✅ Token pre-counting validado

---

### **FASE 4: Implementación de TODOs Críticos (Días 7-9)**

**Sub-agente:** AI & FastAPI Developer

```bash
# Paso 4.1: Fix TODO Crítico - Hardcoded confidence=95.0
Task: "En chat/engine.py, implementa _calculate_confidence():

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

    Examples:
        >>> _calculate_confidence('response', sources_count=5, llm_used='anthropic')
        92.0  # Base 85 + 5*1.5 (sources) - 0 (good length) + 0 (no plugin)

        >>> _calculate_confidence('short', sources_count=0, llm_used='anthropic')
        70.0  # Base 85 + 0 (no sources) - 15 (too short) + 0
    '''
    base_confidence = 85.0 if llm_used == 'anthropic' else 75.0

    # Boost por fuentes (max +15 pts)
    source_boost = min(sources_count * 1.5, 15)

    # Penalty por respuesta muy corta (max -15 pts)
    length_penalty = 0
    if len(response_text) < 50:
        length_penalty = -15
    elif len(response_text) < 100:
        length_penalty = -5

    # Boost por plugin específico (+5 pts)
    plugin_boost = 5 if plugin_used else 0

    confidence = base_confidence + source_boost + length_penalty + plugin_boost

    # Clamp 0-100
    return max(0, min(100, confidence))

Luego reemplaza en send_message() línea 237:
    confidence=self._calculate_confidence(
        response_text=response_text,
        sources_count=len(relevant_docs),
        llm_used=llm_used,
        plugin_used=plugin_module
    ),

Escribe tests en test_chat_engine.py para validar esta función.
"

# Validación:
pytest tests/unit/test_chat_engine.py::test_calculate_confidence -v
grep -n "confidence=95.0" chat/engine.py  # Debe retornar vacío
```

**Checkpoint 4.1:** ✅ TODO crítico resuelto con tests

```bash
# Paso 4.2: Implementar Knowledge Base Loading desde Markdown
Task: "En chat/knowledge_base.py, implementa _load_documents():

def _load_documents(self) -> List[Dict[str, Any]]:
    '''
    Carga documentos desde /app/knowledge/*.md

    Formato esperado markdown:
    ---
    title: \"Validación DTE 33\"
    module: l10n_cl_dte
    tags: [dte, factura, sii]
    ---
    # Contenido
    Documentación aquí...

    Returns:
        List[Dict]: [{title, module, tags, content, embedding}]
    '''
    import os
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

Elimina TODO en línea 52.
Escribe tests unitarios para esta función.
"

# Validación:
pytest tests/unit/test_knowledge_base.py::test_load_documents_from_markdown -v
grep -n "TODO.*Load from" chat/knowledge_base.py  # Debe retornar vacío
```

**Checkpoint 4.2:** ✅ Knowledge base loading implementado

---

### **FASE 5: Infraestructura Redis HA (Días 9-11)**

**Sub-agente:** Docker & DevOps Expert

```bash
# Paso 5.1: Configurar Redis Sentinel
Task: "Actualiza docker-compose.yml para Redis HA:

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

Actualiza ai-service environment en docker-compose.yml:
  - REDIS_SENTINEL_HOSTS=redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379
  - REDIS_MASTER_NAME=mymaster

Actualiza utils/redis_helper.py para usar Sentinel.
"

# Validación:
docker-compose up -d redis-master redis-replica-1 redis-replica-2 redis-sentinel-1 redis-sentinel-2 redis-sentinel-3
docker exec odoo19_sentinel_1 redis-cli -p 26379 SENTINEL masters
```

**Checkpoint 5.1:** ✅ Redis HA configurado y validado

```bash
# Paso 5.2: Test de Failover
Task: "Documenta y ejecuta test de failover:

# Test Script: scripts/test_redis_failover.sh
#!/bin/bash

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

Documenta en docs/REDIS_HA_SETUP.md:
- Arquitectura (diagrama)
- Configuración
- Proceso de failover
- Troubleshooting
- Backup/restore
"

# Validación:
bash scripts/test_redis_failover.sh
```

**Checkpoint 5.2:** ✅ Failover validado y documentado

---

### **FASE 6: Enhanced Health Checks (Día 12)**

**Sub-agente:** AI & FastAPI Developer

```bash
# Paso 6.1: Mejorar /health endpoint
Task: "En main.py:231-268, mejora health_check():

@app.get('/health')
async def health_check():
    '''Enhanced health check con validación de dependencias.'''

    health = {
        'status': 'healthy',
        'service': settings.app_name,
        'version': settings.app_version,
        'timestamp': datetime.utcnow().isoformat(),
        'dependencies': {}
    }

    # 1. Redis connectivity (existente - mantener)
    try:
        redis_client = get_redis_client()
        redis_client.ping()
        health['dependencies']['redis'] = {'status': 'up'}
    except Exception as e:
        health['dependencies']['redis'] = {'status': 'down', 'error': str(e)[:200]}
        health['status'] = 'degraded'

    # 2. Anthropic API connectivity (NUEVO)
    try:
        from clients.anthropic_client import AnthropicClient
        client = AnthropicClient(api_key=settings.anthropic_api_key, model=settings.anthropic_model)

        # Test ligero: count_tokens (no consume output tokens)
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
        from plugins.registry import PluginRegistry
        registry = PluginRegistry()
        modules = registry.list_modules()

        health['dependencies']['plugin_registry'] = {
            'status': 'up',
            'modules_count': len(modules),
            'modules': modules[:5]  # Primeros 5
        }
    except Exception as e:
        health['dependencies']['plugin_registry'] = {'status': 'down', 'error': str(e)[:200]}
        health['status'] = 'degraded'

    # 4. Knowledge Base (NUEVO)
    try:
        from chat.knowledge_base import KnowledgeBase
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

    # Response con status code apropiado
    status_code = 200 if health['status'] == 'healthy' else 503
    return JSONResponse(content=health, status_code=status_code)

Escribe tests de integración para este endpoint.
"

# Validación:
curl http://localhost:8002/health | jq
pytest tests/integration/test_health_check.py -v
```

**Checkpoint 6.1:** ✅ Enhanced health checks implementados

---

### **FASE 7: Prometheus Alerting (Día 13)**

**Sub-agente:** Docker & DevOps Expert

```bash
# Paso 7.1: Configurar Prometheus Alerts
Task: "Crea monitoring/prometheus/alerts.yml:

groups:
  - name: ai_service_alerts
    interval: 30s
    rules:
      # Redis Down
      - alert: RedisDown
        expr: up{job=\"redis\"} == 0
        for: 1m
        labels:
          severity: critical
          service: ai-service
        annotations:
          summary: \"Redis instance is down\"
          description: \"Redis {{ $labels.instance }} has been down for more than 1 minute\"

      # High Error Rate
      - alert: HighErrorRate
        expr: rate(http_request_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
          service: ai-service
        annotations:
          summary: \"High error rate detected\"
          description: \"Error rate is {{ $value | humanizePercentage }} (threshold: 10%)\"

      # Daily Cost Exceeded
      - alert: DailyCostExceeded
        expr: sum(increase(claude_api_cost_usd_total[24h])) > 50
        for: 1h
        labels:
          severity: warning
          service: ai-service
        annotations:
          summary: \"Daily cost exceeded $50\"
          description: \"Claude API cost in last 24h: ${{ $value }}\"

      # Cache Hit Rate Low
      - alert: LowCacheHitRate
        expr: rate(claude_cache_read_tokens_total[10m]) / rate(claude_input_tokens_total[10m]) < 0.5
        for: 15m
        labels:
          severity: info
          service: ai-service
        annotations:
          summary: \"Cache hit rate below 50%\"
          description: \"Current cache hit rate: {{ $value | humanizePercentage }}\"

Documenta en docs/PROMETHEUS_ALERTING.md:
- Configuración
- Reglas de alertas
- Interpretación
- Acciones recomendadas por alerta
"

# Validación:
promtool check rules monitoring/prometheus/alerts.yml
```

**Checkpoint 7.1:** ✅ Prometheus alerting configurado

---

### **FASE 8: Validación Final y Coverage (Día 14)**

**Sub-agente:** Test Automation Specialist

```bash
# Paso 8.1: Ejecutar coverage completo
Task: "Ejecuta y valida coverage ≥80%:

# Full test suite con coverage
pytest --cov=. --cov-report=html --cov-report=term-missing --cov-fail-under=80 -v

# Generar badges
coverage-badge -o coverage.svg -f

# Validar archivos críticos
pytest --cov=clients/anthropic_client.py --cov-report=term-missing --cov-fail-under=90
pytest --cov=chat/engine.py --cov-report=term-missing --cov-fail-under=85
pytest --cov=middleware/observability.py --cov-report=term-missing --cov-fail-under=75

# Reporte final
cat > coverage_report.md << EOF
# Test Coverage Report - PHASE 1 QA

**Date:** $(date +%Y-%m-%d)
**Total Coverage:** $(coverage report | tail -1 | awk '{print $NF}')

## Per-File Coverage

$(coverage report --skip-empty)

## Critical Files

- anthropic_client.py: $(coverage report | grep anthropic_client | awk '{print $NF}')
- chat/engine.py: $(coverage report | grep 'chat/engine' | awk '{print $NF}')
- middleware/observability.py: $(coverage report | grep observability | awk '{print $NF}')

## Tests Summary

- Unit Tests: $(pytest --collect-only -m unit -q | tail -1)
- Integration Tests: $(pytest --collect-only -m integration -q | tail -1)
- Total Tests: $(pytest --collect-only -q | tail -1)

EOF
"

# Validación:
test -f htmlcov/index.html
coverage report | grep TOTAL | awk '{if ($NF < 80) exit 1}'
```

**Checkpoint 8.1:** ✅ Coverage ≥80% alcanzado

---

## ✅ CRITERIOS DE ÉXITO

### Métricas Obligatorias:

1. **Test Coverage:**
   - Total: ≥80% ✅
   - anthropic_client.py: ≥90% ✅
   - chat/engine.py: ≥85% ✅
   - middleware/observability.py: ≥75% ✅

2. **TODOs:**
   - TODOs críticos: 0/3 ✅
   - TODOs totales: ≤3/14 ✅

3. **Infraestructura:**
   - Redis HA: Master + 2 replicas + 3 Sentinels ✅
   - Failover automático funcionando ✅
   - Persistence configurada (RDB + AOF) ✅

4. **Testing:**
   - pyproject.toml con pytest config ✅
   - Tests unitarios: ≥50 tests ✅
   - Tests integración PHASE 1: ≥10 tests ✅

5. **Observabilidad:**
   - Enhanced health checks (4 dependencies) ✅
   - Prometheus alerts (4 reglas) ✅

### Entregables Finales:

```
ai-service/
├── pyproject.toml (actualizado con pytest config)
├── tests/
│   ├── unit/
│   │   ├── test_anthropic_client.py (NUEVO - 300+ LOC)
│   │   ├── test_chat_engine.py (NUEVO - 250+ LOC)
│   │   └── test_knowledge_base.py (NUEVO - 100+ LOC)
│   └── integration/
│       ├── test_prompt_caching.py (NUEVO - 80+ LOC)
│       ├── test_streaming_sse.py (NUEVO - 100+ LOC)
│       ├── test_token_precounting.py (NUEVO - 60+ LOC)
│       └── test_health_check.py (NUEVO - 50+ LOC)
├── chat/
│   ├── engine.py (actualizado - sin TODO confidence)
│   └── knowledge_base.py (actualizado - loading implementado)
├── main.py (actualizado - enhanced health checks)
├── docker-compose.yml (actualizado - Redis HA)
├── config/
│   └── sentinel.conf (NUEVO)
├── monitoring/
│   └── prometheus/
│       └── alerts.yml (NUEVO)
├── scripts/
│   └── test_redis_failover.sh (NUEVO)
├── docs/
│   ├── REDIS_HA_SETUP.md (NUEVO)
│   └── PROMETHEUS_ALERTING.md (NUEVO)
├── coverage_report.md (NUEVO)
└── htmlcov/ (coverage HTML report)
```

---

## 🚫 PROHIBICIONES ABSOLUTAS

1. ❌ **NO escribir código sin tests primero** (TDD approach preferido)
2. ❌ **NO hacer commits sin ejecutar pytest**
3. ❌ **NO usar mocks innecesarios** (preferir tests reales cuando sea seguro)
4. ❌ **NO hardcodear valores** (usar config/settings)
5. ❌ **NO ignorar warnings de coverage**
6. ❌ **NO skip tests sin justificación** (documentar @pytest.mark.skip con razón)
7. ❌ **NO modificar docker-compose.yml sin backup**
8. ❌ **NO deployar sin validar health checks**

---

## 📊 REPORTE FINAL ESPERADO

Al terminar, genera reporte markdown:

```markdown
# 🎯 Reporte de Cierre de Brechas - AI Service PHASE 1 QA

**Ejecutor:** [Tu nombre de agente]
**Fecha:** [Fecha]
**Duración:** [Días]
**Branch:** claude/gap-closure-phase1-qa

## ✅ Resumen Ejecutivo

- **Brechas Cerradas:** 10/10 (100%)
- **Coverage Alcanzado:** [X]% (target: 80%)
- **Tests Escritos:** [N] tests ([N] unit + [N] integration)
- **TODOs Resueltos:** [X]/14
- **Archivos Modificados:** [N]
- **Archivos Nuevos:** [N]
- **LOC Agregado:** [N] (+[N] tests)

## 📊 Métricas Detalladas

### Coverage por Módulo
[Tabla con coverage por archivo]

### Tests por Categoría
- Unit tests: [N]
- Integration tests: [N]
- E2E tests: [N]

### Performance
- Redis Failover Time: [X]s
- Health Check Response: [X]ms
- Test Suite Duration: [X]s

## 🎯 Brechas Cerradas

[Tabla detallada de cada brecha con status]

## 📝 Cambios Implementados

[Lista de commits con descripción]

## ⚠️ Issues Encontrados

[Cualquier problema encontrado durante implementación]

## 🚀 Próximos Pasos

[Recomendaciones para PHASE 2]

## 📎 Enlaces

- Coverage Report: file://htmlcov/index.html
- Docker Compose: docker-compose.yml
- Prometheus Alerts: monitoring/prometheus/alerts.yml
```

---

## 🤝 INSTRUCCIONES DE EJECUCIÓN

### Inicio:

```bash
# 1. Crear branch
git checkout -b claude/gap-closure-phase1-qa

# 2. Iniciar con FASE 1
[Invocar Test Automation Specialist para Paso 1.1]

# 3. Proceder fase por fase validando checkpoints
[Seguir workflow secuencial]

# 4. Al finalizar, generar reporte y push
git add .
git commit -m "feat(ai-service): complete gap closure PHASE 1 QA

- ✅ Test coverage 80%+ (anthropic_client, chat/engine)
- ✅ Integration tests for PHASE 1 features
- ✅ Redis HA with Sentinel (master + 2 replicas)
- ✅ Enhanced health checks (4 dependencies)
- ✅ Prometheus alerting (4 rules)
- ✅ Critical TODOs resolved (confidence, knowledge_base)

Closes: 10 brechas (5 P1, 3 P2, 2 P3)
"
git push -u origin claude/gap-closure-phase1-qa
```

### Validación Pre-Push:

```bash
# Checklist final
□ pytest --cov=. --cov-fail-under=80 ✅
□ docker-compose config --quiet ✅
□ bash scripts/test_redis_failover.sh ✅
□ curl http://localhost:8002/health | jq .status # "healthy" ✅
□ promtool check rules monitoring/prometheus/alerts.yml ✅
□ grep -r "TODO" --include="*.py" | wc -l # ≤3 ✅
□ Reporte final generado ✅
```

---

## 🎓 REFERENCIAS

- pytest docs: https://docs.pytest.org/
- coverage.py: https://coverage.readthedocs.io/
- Redis Sentinel: https://redis.io/docs/management/sentinel/
- Prometheus Alerting: https://prometheus.io/docs/alerting/latest/
- FastAPI Testing: https://fastapi.tiangolo.com/tutorial/testing/
- Anthropic API: https://docs.anthropic.com/

---

**IMPORTANTE:** Este es un proyecto de calidad enterprise. Cada línea de código debe tener:
1. ✅ Type hints
2. ✅ Docstring Google Style
3. ✅ Test que lo valide
4. ✅ Logging estructurado
5. ✅ Error handling apropiado

**Sin excepciones. Sin atajos. Sin parches.**

---

## 📋 DOCUMENTOS RELACIONADOS

- **Análisis de Brechas:** `docs/gap-closure/AI_SERVICE_GAP_ANALYSIS.md`
- **Informe de Auditoría:** `ai-service/docs/AI_SERVICE_AUDIT_REPORT_2025-10-24.md`
- **Roadmap PHASE 1:** Ver informe de auditoría sección "Roadmap"

---

**Fin del Prompt - v1.0**
**Última actualización:** 2025-11-09 03:30 UTC
