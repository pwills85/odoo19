# Instrucción: Auditoría Cambios Microservicio AI

## 🎯 Objetivo
Auditar implementación PHASE 1 del microservicio AI contra roadmap documentado y validar calidad production-ready.

---

## 📋 Contexto del Proyecto

### Documentación Base
- **Roadmap**: `docs/ai-service/ANALISIS_MEJORAS_MICROSERVICIO_AI_SENIOR_2025-11-09.md` (1,150 líneas)
- **Score actual**: ⭐⭐⭐⭐ (4/5)
- **ROI esperado**: 303% ($6.6K inversión → $20K ahorro/año)

### Commits Implementación (Range: 5726b26d..8d565ca5)
```bash
5726b26d: feat(ai-service): Implement PHASE 1 optimizations - 90% cost reduction achieved
6e1bb935: feat(ai-service): Implement streaming for chat (Sprint 1D complete)
8d565ca5: docs(ai-service): Update README with Phase 1 + Streaming completion
fa3262e2: docs(ai-service): integrate senior production-readiness analysis
```

### Archivos Críticos a Revisar
```
ai-service/
├── clients/anthropic_client.py           # Prompt caching (5min/24h TTL)
├── chat/engine.py                        # Streaming SSE implementation
├── middleware/observability.py           # Token pre-counting (Claude tokenizer)
├── config.py                             # Configuration (cache TTL, streaming)
├── plugins/*/plugin.py                   # Plugin architecture (DTE, payroll, account, stock)
├── tests/                                # Test coverage (target ≥80%)
└── README.md                             # Documentation updates
```

---

## 🔍 Alcance de Auditoría

### 1. Validación Funcional (P0)

#### A. Prompt Caching Implementation
**Especificación (roadmap)**:
- 90% cost reduction
- 5min TTL (system prompts)
- 24h TTL (extended cache)
- Cache-aware request construction

**Validar**:
- [ ] `anthropic_client.py` implementa `cache_control` parameter
- [ ] System prompts usan `ephemeral` type (5min)
- [ ] Conversational context usa `extended` type (24h)
- [ ] Token pre-counting incluye cache writes/reads
- [ ] Métricas observability rastrean cache hit rate

#### B. Streaming SSE
**Especificación**:
- Server-Sent Events (SSE) protocol
- Partial message streaming
- `text-stream-start`, `content-block-delta`, `text-stream-end` events
- Graceful error handling

**Validar**:
- [ ] `chat/engine.py` implementa streaming generator
- [ ] FastAPI endpoint retorna `StreamingResponse`
- [ ] Content-Type: `text/event-stream`
- [ ] Error handling en stream interruptions
- [ ] Tests validan streaming behavior

#### C. Token Pre-Counting
**Especificación**:
- Claude 3.5 Sonnet tokenizer
- Pre-request token counting
- Budget validation before API call
- Observability metrics

**Validar**:
- [ ] `middleware/observability.py` usa tokenizer correcto
- [ ] Pre-counting antes de cada request
- [ ] Logging de token usage (input/output/cache)
- [ ] Budget enforcement logic

---

### 2. Calidad de Código (P1)

#### A. Python Best Practices
- [ ] PEP8 compliance (línea ≤120 chars, naming conventions)
- [ ] Type hints (Python 3.10+ syntax: `list[str]`, `dict[str, Any]`)
- [ ] Docstrings (Google style: Args, Returns, Raises)
- [ ] Error handling (try/except específicos, no bare except)

#### B. Architecture Patterns
- [ ] Single Responsibility Principle (funciones pequeñas, cohesivas)
- [ ] Dependency Injection (config as parameter, no globals)
- [ ] Separation of Concerns (clients/ vs chat/ vs middleware/)
- [ ] Plugin architecture consistency (registry, loader, interface)

#### C. Testing Coverage
- [ ] Unit tests críticos (`clients/`, `chat/`, `middleware/`)
- [ ] Integration tests (end-to-end streaming, caching)
- [ ] Coverage ≥80% (usar `pytest-cov`)
- [ ] Mocking correcto (Anthropic API, Redis, DB)

---

### 3. Security & Performance (P0)

#### A. Security
- [ ] No API keys hardcoded (usar env vars)
- [ ] Input validation (sanitize user prompts)
- [ ] Rate limiting logic (prevenir abuse)
- [ ] Error messages no exponen internals

#### B. Performance
- [ ] Async/await consistency (FastAPI endpoints)
- [ ] Connection pooling (Redis, DB)
- [ ] Graceful degradation (cache miss → fallback)
- [ ] Resource cleanup (context managers, finally blocks)

---

## 📊 Entregables Esperados

### 1. Reporte Auditoría (Markdown)

```markdown
# Auditoría AI Service - PHASE 1 Implementation

## Executive Summary
- **Score**: X/100
- **Status**: ✅ Production Ready | ⚠️ Minor Fixes | ❌ Blocker Issues
- **Coverage**: X% (target ≥80%)

## Hallazgos por Categoría

### P0 (Blocker)
- [H1] Descripción issue crítico
  - Archivo: `path/to/file.py:line`
  - Impacto: Security/Performance/Correctness
  - Solución: Paso a paso

### P1 (High Priority)
- [H2] Descripción issue importante
  - Archivo: `path/to/file.py:line`
  - Impacto: Code quality/Maintainability
  - Solución: Sugerencia

### P2 (Nice to Have)
- [H3] Mejora opcional

## Validación vs Roadmap

| Feature | Spec | Implementado | Status |
|---------|------|--------------|--------|
| Prompt Caching | 90% cost reduction | ✅/⚠️/❌ | Detalles |
| Streaming SSE | FastAPI SSE | ✅/⚠️/❌ | Detalles |
| Token Pre-counting | Claude tokenizer | ✅/⚠️/❌ | Detalles |
| Tests Coverage | ≥80% | X% | Gap |

## Recomendaciones Próximos Pasos

1. **Inmediato (1-2 días)**:
   - Fix P0 issues
   - Completar tests críticos

2. **Corto Plazo (1 semana)**:
   - Resolver P1 issues
   - Alcanzar 80% coverage

3. **Mediano Plazo (2-4 semanas)**:
   - Implementar P1 roadmap (Redis HA, Health checks)
   - Monitoring/Alerting

## Code Examples

### Issue Detectado
```python
# ❌ PROBLEMA:
def process_chat(prompt: str):  # No type hints return
    result = api.call(prompt)    # No error handling
    return result
```

### Solución Propuesta
```python
# ✅ SOLUCIÓN:
def process_chat(prompt: str) -> dict[str, Any]:
    """Process chat request with streaming support.
    
    Args:
        prompt: User input prompt
        
    Returns:
        Dictionary with response and metadata
        
    Raises:
        ValueError: If prompt is empty
        APIError: If Anthropic API fails
    """
    if not prompt.strip():
        raise ValueError("Prompt cannot be empty")
    
    try:
        result = api.call(prompt)
        return {"response": result, "status": "success"}
    except AnthropicAPIError as e:
        logger.error(f"API call failed: {e}")
        raise APIError(f"Chat processing failed: {e}")
```
```

---

### 2. Coverage Report
```bash
# Ejecutar localmente y adjuntar output:
cd ai-service/
pytest --cov=. --cov-report=term-missing tests/
```

### 3. Diff Summary (Opcional)
Si necesitas más contexto, ejecuta:
```bash
git diff 5726b26d..8d565ca5 -- ai-service/ > .claude/AI_SERVICE_PHASE1_DIFF.txt
```

---

## 🚀 Metodología de Ejecución

### Step 1: Context Gathering (15min)
1. Leer `docs/ai-service/ANALISIS_MEJORAS_MICROSERVICIO_AI_SENIOR_2025-11-09.md` completo
2. Revisar commits: `git show 5726b26d`, `git show 6e1bb935`, `git show 8d565ca5`
3. Mapear archivos modificados vs especificaciones

### Step 2: Code Review (45min)
1. **Prompt Caching**: Analizar `clients/anthropic_client.py`
   - Buscar `cache_control`, `ephemeral`, `extended`
   - Validar TTL configuration (5min/24h)
   
2. **Streaming**: Analizar `chat/engine.py`
   - Buscar `StreamingResponse`, `yield`, SSE format
   - Validar error handling en streaming
   
3. **Token Counting**: Analizar `middleware/observability.py`
   - Buscar tokenizer import, pre-counting logic
   - Validar métricas logging

### Step 3: Quality Assessment (30min)
1. Run linters:
   ```bash
   cd ai-service/
   flake8 . --max-line-length=120
   mypy . --ignore-missing-imports
   ```

2. Run tests:
   ```bash
   pytest --cov=. --cov-report=html tests/
   ```

3. Review test files:
   - `tests/test_anthropic_client.py`
   - `tests/test_chat_engine.py`
   - `tests/test_observability.py`

### Step 4: Report Generation (30min)
1. Consolidar hallazgos por prioridad (P0/P1/P2)
2. Generar tabla comparativa (spec vs implementación)
3. Proponer fixes con code examples
4. Calcular score final (0-100)

---

## ✅ Criterios de Éxito

### Minimum Viable (Score ≥70)
- ✅ Prompt caching implementado correctamente
- ✅ Streaming funcional (end-to-end test passing)
- ✅ Token pre-counting activo
- ✅ No security vulnerabilities (P0)
- ✅ Coverage ≥60%

### Production Ready (Score ≥85)
- ✅ Todos los criterios Minimum Viable
- ✅ PEP8 + type hints completos
- ✅ Error handling robusto
- ✅ Coverage ≥80%
- ✅ Documentation actualizada (README, docstrings)

### Excellence (Score ≥95)
- ✅ Todos los criterios Production Ready
- ✅ Integration tests completos
- ✅ Performance benchmarks documentados
- ✅ Monitoring/observability dashboards
- ✅ Zero P0/P1 issues

---

## 📌 Notas Importantes

1. **Sandbox Mode**: Esta auditoría es **read-only**. No modifiques código, solo analiza.
2. **Evidence-Based**: Usa referencias exactas (`file:line`) en todos los hallazgos.
3. **Actionable**: Cada issue debe tener solución propuesta con código ejemplo.
4. **Prioritization**: Clasifica correctamente (P0 bloquea producción, P1 alta prioridad, P2 nice-to-have).

---

## 🔗 Referencias

- Roadmap completo: `docs/ai-service/ANALISIS_MEJORAS_MICROSERVICIO_AI_SENIOR_2025-11-09.md`
- Anthropic Docs: https://docs.anthropic.com/claude/docs/prompt-caching
- FastAPI Streaming: https://fastapi.tiangolo.com/advanced/custom-response/#streamingresponse
- Pytest Coverage: https://pytest-cov.readthedocs.io/

---

**Fecha**: 2025-11-09  
**Auditor**: Claude Agent (Remote)  
**Alcance**: PHASE 1 Implementation (Prompt Caching + Streaming + Token Pre-counting)  
**Deadline**: 2 horas (análisis completo)
