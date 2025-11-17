# Prompt P4-Deep: Auditoría Arquitectónica ai-service

**Módulo:** Microservicio AI (FastAPI + Claude)  
**Versión:** 2.0.0  
**Nivel:** P4-Deep (1,200-1,500 palabras | ≥30 refs | ≥6 verificaciones)  
**Objetivo:** Auditoría arquitectónica microservicio AI con multi-agent system + prompt caching

---

## 🔄 REGLAS DE PROGRESO (7 PASOS OBLIGATORIOS)

[Ver estructura progreso en template P4-Deep base]

---

## 📊 CONTEXTO CUANTIFICADO DENSO - MICROSERVICIO AI-SERVICE

### Métricas del Servicio

| Métrica | Valor | Contexto |
|---------|-------|----------|
| **Archivos Python** | 78 archivos | `/ai-service/` (sin tests) |
| **LOC Total** | ~8,500 líneas | Sin comentarios ni blanks |
| **Módulo Principal** | `main.py` | 650 LOC (FastAPI app) |
| **Segundo Crítico** | `chat/engine.py` | 1,200 LOC (chat multi-agent) |
| **Tercero Crítico** | `knowledge/knowledge_base.py` | 580 LOC (RAG + embeddings) |
| **Tests** | 120+ tests | `tests/`, coverage ~72% |
| **Dependencias Python** | 15 críticas | anthropic, fastapi, uvicorn, httpx, lxml, pydantic, redis |
| **Framework** | FastAPI 0.115+ | Async/await nativo |
| **AI Model** | Claude Sonnet 4.5 | Anthropic API (prompt caching beta) |
| **Redis** | 7.4-alpine | Caching sesiones + respuestas AI |
| **Endpoints API** | 25+ rutas | `/chat`, `/payroll`, `/dte`, `/reconciliation`, `/analytics` |
| **Plugins** | 8 especializados | DTE validation, payroll calc, project matcher, etc. |
| **Agents** | 6 tipos | generalist, dte-specialist, payroll-compliance, etc. |
| **Documentación** | 45+ archivos MD | `/docs`, `/knowledge`, READMEs |

### Optimizaciones Arquitectónicas Clave

1. **Prompt Caching Beta**: -90% tokens/latency en llamadas repetidas (Anthropic 2024-08-14)
2. **Multi-Agent System**: 6 agentes especializados con routing automático
3. **Redis Session Store**: Persistencia conversaciones + cache respuestas AI
4. **Async/Await Nativo**: FastAPI + httpx (no blocking I/O)
5. **Plugin Architecture**: 8 plugins desacoplados (DTE, Payroll, Analytics)
6. **Knowledge Base RAG**: Embeddings + semantic search para documentación
7. **Circuit Breaker**: Timeout 60s, retry 3x exponential backoff
8. **Error Handling Multicapa**: FastAPI exceptions + custom middleware

### Arquitectura Multi-Capa

```
Layer 1: API Gateway (FastAPI)
  ├── main.py (650 LOC - app initialization)
  ├── routes/*.py (25+ endpoints)
  └── middleware/error_handler.py (custom exceptions)

Layer 2: Business Logic (Agents + Plugins)
  ├── chat/engine.py (1,200 LOC - multi-agent orchestration)
  ├── chat/agent_selector.py (routing logic)
  ├── plugins/dte_validator.py (DTE-specific)
  ├── plugins/payroll_calculator.py (Payroll-specific)
  └── plugins/project_matcher.py (async migration complete)

Layer 3: AI Integration (Anthropic Claude)
  ├── clients/anthropic_client.py (Claude API wrapper)
  ├── clients/prompt_caching.py (beta feature)
  └── knowledge/knowledge_base.py (RAG + embeddings)

Layer 4: Persistence (Redis + File Cache)
  ├── cache/redis_client.py (session store)
  ├── cache/file_cache.py (fallback)
  └── uploads/ (file storage temporary)

Layer 5: Monitoring & Observability
  ├── monitoring/metrics.py (Prometheus)
  ├── monitoring/logger.py (structured logging)
  └── middleware/request_id.py (tracing)
```

### Deuda Técnica Conocida

1. **chat/engine.py monolítico**: 1,200 LOC → Debería ser <600 LOC (refactorización multi-agent)
2. **Tests async incompletos**: Coverage 72% → Target 85%+ (faltan tests plugins)
3. **Redis single-instance**: Debería ser Redis Cluster (HA) o Redis Sentinel
4. **Knowledge Base sin embeddings**: RAG implementado pero sin vector store (Pinecone/Qdrant pendiente)
5. **Monitoring básico**: Prometheus metrics parciales → Falta OpenTelemetry completo
6. **Documentación plugins desactualizada**: 3 plugins tienen docs obsoletas vs código real

---

## 🔍 RUTAS CLAVE A ANALIZAR (≥30 FILES TARGET)

### Core FastAPI (P0 - Críticos)

```
1.  ai-service/main.py:1
2.  ai-service/config.py:1
3.  ai-service/routes/chat.py:1
4.  ai-service/routes/payroll.py:1
5.  ai-service/routes/dte.py:1
6.  ai-service/routes/reconciliation.py:1
7.  ai-service/routes/analytics.py:1
8.  ai-service/middleware/error_handler.py:1
9.  ai-service/middleware/request_id.py:1
10. ai-service/middleware/cors.py:1
```

### Multi-Agent System (P0)

```
11. ai-service/chat/engine.py:1
12. ai-service/chat/agent_selector.py:1
13. ai-service/chat/context_manager.py:1
14. ai-service/chat/prompt_builder.py:1
15. ai-service/chat/response_parser.py:1
```

### Plugins (P1)

```
16. ai-service/plugins/dte_validator.py:1
17. ai-service/plugins/payroll_calculator.py:1
18. ai-service/plugins/project_matcher.py:1
19. ai-service/plugins/reconciliation_helper.py:1
20. ai-service/plugins/analytics_insights.py:1
21. ai-service/plugins/previred_validator.py:1
22. ai-service/plugins/sii_monitor.py:1
23. ai-service/plugins/training_manager.py:1
```

### AI Integration (P0)

```
24. ai-service/clients/anthropic_client.py:1
25. ai-service/clients/prompt_caching.py:1
26. ai-service/knowledge/knowledge_base.py:1
27. ai-service/knowledge/embeddings.py:1
```

### Caching & Persistence (P1)

```
28. ai-service/cache/redis_client.py:1
29. ai-service/cache/file_cache.py:1
30. ai-service/cache/session_store.py:1
```

### Monitoring (P2)

```
31. ai-service/monitoring/metrics.py:1
32. ai-service/monitoring/logger.py:1
```

### Testing (P2)

```
33. ai-service/tests/test_chat_engine.py:1
34. ai-service/tests/test_plugins.py:1
35. ai-service/tests/integration/test_end_to_end.py:1
```

---

## 📋 ÁREAS DE EVALUACIÓN (10 DIMENSIONES OBLIGATORIAS)

### A) ARQUITECTURA Y MODULARIDAD (≥5 sub-dimensiones)

**Analizar:**

- A.1) **Plugin desacoplamiento**: ¿Plugins son independientes? ¿Interface común?
- A.2) **Multi-agent routing**: ¿Lógica routing en `agent_selector.py` vs hardcoded en `engine.py`?
- A.3) **Monolito engine.py**: ¿1,200 LOC mezclando orchestration + business logic?
- A.4) **Dependencies injection**: ¿FastAPI Depends() usado correctamente? ¿Testable?
- A.5) **Async patterns**: ¿Todos I/O usan `async/await`? ¿No blocking calls?

**Referencias clave:** `chat/engine.py:1`, `chat/agent_selector.py:1`, `plugins/*.py`

---

### B) PATRONES DE DISEÑO FASTAPI (≥5 sub-dimensiones)

**Analizar:**

- B.1) **Pydantic models**: ¿Validación request/response con BaseModel? ¿Tipos correctos?
- B.2) **Dependency Injection**: ¿Redis client, Anthropic client inyectados con Depends()?
- B.3) **Error handling**: ¿HTTPException vs custom exceptions? ¿Status codes correctos?
- B.4) **Async endpoints**: ¿Todos endpoints `async def`? ¿No sync I/O blocking?
- B.5) **API versioning**: ¿Rutas con `/v1/` vs sin versión?

**Referencias clave:** `routes/*.py`, `main.py:100-200` (app setup)

---

### C) INTEGRACIONES EXTERNAS (≥6 sub-dimensiones)

**Analizar:**

- C.1) **Anthropic Claude API**: ¿Timeout configurado? ¿Retry logic exponential backoff?
- C.2) **Prompt Caching Beta**: ¿Habilitado correctamente? ¿Métricas token savings?
- C.3) **Redis**: ¿Circuit breaker si Redis down? ¿Fallback file cache?
- C.4) **Odoo integration**: ¿Endpoints `/dte`, `/payroll` llaman a Odoo o son standalone?
- C.5) **Knowledge Base RAG**: ¿Embeddings actualizados automáticamente? ¿Vector store?
- C.6) **Error handling externo**: ¿API key inválida, rate limit, timeout manejados?

**Referencias clave:** `clients/anthropic_client.py:50-150`, `cache/redis_client.py:1`, `knowledge/knowledge_base.py:200-300`

---

### D) SEGURIDAD MULTICAPA (≥5 sub-dimensiones)

**Analizar:**

- D.1) **API Keys management**: ¿`ANTHROPIC_API_KEY` en `.env`? ¿NO hardcoded?
- D.2) **CORS configurado**: ¿Whitelist origins vs `allow_origins=["*"]` (inseguro)?
- D.3) **Request validation**: ¿Pydantic valida inputs maliciosos? ¿XSS/SQL injection?
- D.4) **Rate limiting**: ¿Middleware anti-abuse? ¿Token bucket?
- D.5) **File upload seguro**: ¿Validación extensión/MIME? ¿Size limit? ¿Path traversal?

**Referencias clave:** `main.py:50-100` (CORS), `middleware/rate_limit.py` (si existe), `uploads/` (file handling)

---

### E) OBSERVABILIDAD (≥4 sub-dimensiones)

**Analizar:**

- E.1) **Structured logging**: ¿`logger.info()` con contexto (request_id, agent_type, plugin)?
- E.2) **Prometheus metrics**: ¿Métricas request latency, error rate, AI tokens used?
- E.3) **Request tracing**: ¿X-Request-ID header propagado? ¿OpenTelemetry?
- E.4) **Error tracking**: ¿Sentry/Rollbar integrado? ¿Stack traces completos?

**Referencias clave:** `monitoring/metrics.py:1`, `monitoring/logger.py:1`, `middleware/request_id.py:1`

---

### F) TESTING Y COBERTURA (≥5 sub-dimensiones)

**Analizar:**

- F.1) **Coverage actual**: ¿72% suficiente? ¿Qué archivos críticos <80%?
- F.2) **Tests async**: ¿Pytest-asyncio usado correctamente? ¿No sync tests para async code?
- F.3) **Mocks externos**: ¿Anthropic API, Redis, Odoo mockeados? ¿O tests reales (frágiles)?
- F.4) **Integration tests**: ¿Test end-to-end chat → agent selection → plugin → response?
- F.5) **Performance tests**: ¿Load testing 100 req/s? ¿Latency p95 < 400ms?

**Referencias clave:** `tests/test_chat_engine.py:1`, `tests/integration/test_end_to_end.py:1`

---

### G) PERFORMANCE Y ESCALABILIDAD (≥4 sub-dimensiones)

**Analizar:**

- G.1) **Async I/O**: ¿Todos llamados externos (Anthropic, Redis, Odoo) son async?
- G.2) **Connection pooling**: ¿httpx AsyncClient reutilizado? ¿Pool size configurado?
- G.3) **Redis caching effectiveness**: ¿Hit rate > 80%? ¿TTL configurado por tipo dato?
- G.4) **AI token optimization**: ¿Prompt caching reduce tokens 90%+? ¿Medido?

**Referencias clave:** `clients/anthropic_client.py:100-200`, `cache/redis_client.py:50-100`

---

### H) DEPENDENCIAS Y DEUDA TÉCNICA (≥4 sub-dimensiones)

**Analizar:**

- H.1) **Dependencias Python**: ¿Vulnerabilidades CVE en anthropic, fastapi, httpx?
- H.2) **Monolito engine.py**: ¿1,200 LOC refactorizable en <600 LOC?
- H.3) **Redis single-instance**: ¿Debería ser Cluster/Sentinel para HA?
- H.4) **TODOs en código**: ¿Hay `# TODO:` sin ticket asignado?

**Referencias clave:** `requirements.txt:1`, `chat/engine.py:1-1200`

---

### I) CONFIGURACIÓN Y DEPLOYMENT (≥3 sub-dimensiones)

**Analizar:**

- I.1) **Environment vars**: ¿Todas configs en `.env`? ¿Secrets no commiteados?
- I.2) **Docker**: ¿Dockerfile optimizado? ¿Multi-stage build? ¿Image size <500MB?
- I.3) **Health check**: ¿Endpoint `/health` retorna Redis, Anthropic API status?

**Referencias clave:** `Dockerfile:1`, `config.py:1`, `routes/health.py:1` (si existe)

---

### J) ERRORES Y MEJORAS CRÍTICAS (≥5 sub-dimensiones)

**Analizar:**

- J.1) **AI hallucinations**: ¿Validación outputs Claude con business rules?
- J.2) **Rate limit Anthropic**: ¿Manejo 429 Too Many Requests con retry?
- J.3) **Redis down**: ¿Fallback file cache funcional? ¿Degraded mode?
- J.4) **Knowledge Base obsoleta**: ¿Docs actualizados automáticamente vs manual?
- J.5) **Plugin errors no catcheados**: ¿Excepciones en plugins crashean todo vs isolated?

**Referencias clave:** `chat/engine.py:500-700` (error handling), `plugins/*.py` (exception handling)

---

## ✅ REQUISITOS DE SALIDA (OBLIGATORIO)

[Ver requisitos completos en template P4-Deep base]

### Verificaciones Obligatorias (≥6)

#### V1 (P0): API Key Anthropic hardcodeada

**Comando:**

```bash
grep -r "sk-ant-" ai-service/*.py || echo "NOT FOUND"
```

**Hallazgo Esperado:**

```
NOT FOUND (API key debe estar en .env)
```

**Si se encuentra API key hardcodeada:**

- **Problema:** Vulnerabilidad crítica (secret exposure)
- **Corrección:** Mover a `.env` y usar `os.getenv("ANTHROPIC_API_KEY")`

**Clasificación:** P0 (crítico - seguridad)

---

#### V2 (P1): Redis single-instance sin HA

**Comando:**

```bash
grep -r "redis.cluster" ai-service/cache/ || echo "NOT FOUND"
```

**Hallazgo Esperado:**

```
NOT FOUND (Redis Cluster no configurado)
```

**Si NOT FOUND:**

- **Problema:** Single point of failure (Redis down = service down)
- **Corrección:** Configurar Redis Sentinel o Cluster en `docker-compose.yml`

**Clasificación:** P1 (alta - disponibilidad)

---

[Agregar V3-V6 siguiendo mismo formato]

---

## 📖 ANEXOS Y REFERENCIAS

### Anthropic Claude

- **API Documentation**: https://docs.anthropic.com/claude/reference
- **Prompt Caching Beta**: https://docs.anthropic.com/claude/docs/prompt-caching (2024-08-14)
- **Rate Limits**: 50k requests/day (Tier 1)

### FastAPI

- **Documentation**: https://fastapi.tiangolo.com/
- **Async patterns**: https://fastapi.tiangolo.com/async/
- **Dependency Injection**: https://fastapi.tiangolo.com/tutorial/dependencies/

### Redis

- **Cluster**: https://redis.io/docs/management/scaling/
- **Sentinel**: https://redis.io/docs/management/sentinel/

---

**Última Actualización:** 2025-11-11  
**Versión Prompt:** 1.0.0  
**Autor:** EERGYGROUP  
**Basado en:** Template P4-Deep
