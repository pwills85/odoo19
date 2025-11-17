# Auditoría P4-Deep: Integración Odoo-AI (Cursor IDE)

**IDE Target:** Cursor AI-powered IDE  
**Nivel:** P4-Deep (Auditoría Integración)  
**Target:** 1,200-1,500 palabras  
**Objetivo:** Auditar integración Odoo ↔ AI Service con enfoque Cursor

---

## 🎯 CONTEXTO INTEGRACIÓN

**Project Structure:**
```
odoo19/
├── ai-service/
│   ├── app/
│   │   ├── main.py          # FastAPI routes
│   │   ├── engine.py        # Claude integration
│   │   └── schemas.py       # Pydantic models
│   └── tests/
├── addons/localization/
│   └── l10n_cl_dte/
│       └── models/
│           └── ai_chat_integration.py  # Odoo client
└── docker-compose.yml        # Services orchestration
```

**Integration Flow:**
```
┌─────────┐  HTTP POST   ┌────────────┐  Anthropic API  ┌─────────┐
│  Odoo   │ ───────────> │ AI Service │ ──────────────> │ Claude  │
│ Backend │  JSON        │  FastAPI   │     JSON        │ Sonnet  │
└─────────┘              └────────────┘                 └─────────┘
```

**Technologies:**
- **Backend:** Python 3.11 (Odoo ORM + FastAPI async)
- **AI:** Claude Sonnet 4.5 (anthropic SDK)
- **Database:** PostgreSQL 16 + Redis 7.4
- **Deployment:** Docker Compose + uvicorn

---

## 📋 ESTRUCTURA ANÁLISIS

### PASO 1: RESUMEN EJECUTIVO (100-150 palabras)

**Cursor Composer Mode:**
```
@workspace Analiza la integración entre Odoo y AI Service.
Resume en 2-3 párrafos:
- Propósito de la integración
- Arquitectura HTTP/REST
- Score salud general X/10
- Top 3 hallazgos críticos
```

### PASO 2: ANÁLISIS MULTI-ARCHIVO (800-1,000 palabras)

#### A) Arquitectura HTTP/REST

**Cursor Chat:**
```
@ai-service/app/main.py ¿Qué endpoints FastAPI están definidos?
@ai-service/app/engine.py ¿Cómo se integra con Claude API?
@addons/l10n_cl_dte/models/ai_chat_integration.py ¿Cómo llama Odoo al AI Service?
```

**Analiza:**
- Endpoints RESTful correctamente diseñados
- Async/await patterns en FastAPI
- Request/Response schemas (Pydantic)
- Error handling HTTP status codes

#### B) Seguridad

**Cursor Terminal:**
```bash
# Buscar hardcoded secrets
rg "api_key|password|secret" --type py

# Verificar environment variables
cat .env | grep -i "api\|key\|secret"

# Check SSL/TLS config
grep -r "ssl\|https" docker-compose.yml config/
```

**Analiza:**
- API keys en environment variables
- SSL/TLS entre servicios (o falta)
- Input validation Pydantic schemas
- CORS policies configuradas

#### C) Resiliencia

**Cursor Codebase Search:**
```
Search: "retry" in ai-service/
Search: "CircuitBreaker" in ai-service/
Search: "timeout" in addons/l10n_cl_dte/
```

**Analiza:**
- Retry logic con exponential backoff
- Circuit breaker implementation
- Timeout configuration consistente
- Fallback strategies cuando AI falla

#### D) Performance

**Cursor AI Commands:**
```
Cmd+K: "Identifica blocking operations en ai-service/app/main.py"
Cmd+K: "Encuentra queries N+1 en ai_chat_integration.py"
Cmd+K: "Sugiere optimizaciones caching en engine.py"
```

**Analiza:**
- Async operations correctamente usadas
- Connection pooling (httpx AsyncClient)
- Redis caching strategy
- Database query optimization

#### E) Testing

**Cursor Test Generation:**
```
@ai-service/tests ¿Qué coverage tienen los tests?
@ai-service/app/main.py Genera tests para /api/chat endpoint
@ai-service/app/engine.py Genera tests mockeando Claude API
```

**Analiza:**
- Unit tests pytest coverage %
- Integration tests HTTP endpoints
- Mocking external services (anthropic)
- Test fixtures y factories

#### F) Código Limpio

**Cursor Linting:**
```
# Inline lint errors visible
pylint ai-service/app/*.py
black --check ai-service/
mypy ai-service/app/
```

**Analiza:**
- Type hints comprehensivos
- Docstrings Google style
- Naming conventions PEP8
- Complexity metrics (radon)

#### G) Deployment Docker

**Cursor File Preview:**
```
@docker-compose.yml Analiza configuración ai-service
@config/odoo.conf Busca settings relacionados AI
@.env.example Verifica variables requeridas
```

**Analiza:**
- Services health checks
- Environment variables strategy
- Volume mounts correctos
- Network configuration

#### H) Observabilidad

**Cursor Code Search:**
```
Find: logger.info in ai-service/
Find: correlation_id in ai-service/
Find: metrics in ai-service/
```

**Analiza:**
- Structured logging (JSON)
- Correlation IDs cross-service
- Prometheus metrics exposed
- Distributed tracing setup

#### I) Dependencies

**Cursor Terminal:**
```bash
# Check outdated packages
pip list --outdated

# Security vulnerabilities
safety check -r ai-service/requirements.txt

# License compliance
pip-licenses --from=mixed
```

**Analiza:**
- Pinned versions en requirements.txt
- CVEs conocidos (anthropic, fastapi, etc)
- Deprecated packages
- License compatibility

#### J) Technical Debt

**Cursor Codebase Indexing:**
```
Search: "TODO" in ai-service/ addons/
Search: "FIXME" in ai-service/ addons/
Search: "HACK" in ai-service/ addons/
Search: "deprecated" in ai-service/ addons/
```

**Analiza:**
- TODOs pendientes y prioridad
- FIXMEs que necesitan atención
- HACK workarounds temporales
- Deprecation warnings

### PASO 3: FIXES CON CURSOR (≥3 ejemplos)

#### Fix P0-01: SSL/TLS Missing

**Cursor Composer:**
```
@docker-compose.yml @ai-service/app/main.py
Agrega soporte SSL/TLS para comunicación segura entre Odoo y AI Service.
Incluye:
- Configuración docker-compose con certificados
- Modificar uvicorn para usar SSL
- Actualizar cliente Odoo para HTTPS
```

**Diff Preview esperado:**
```yaml
# docker-compose.yml
services:
  ai-service:
    ports:
      - "8001:8443"  # HTTPS port
    volumes:
      - ./certs:/etc/ssl/certs:ro
    environment:
      - SSL_CERT_FILE=/etc/ssl/certs/ai-service.crt
      - SSL_KEY_FILE=/etc/ssl/certs/ai-service.key
```

```python
# ai-service/app/main.py
if __name__ == "__main__":
    import ssl
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        os.getenv('SSL_CERT_FILE'),
        os.getenv('SSL_KEY_FILE')
    )
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl_context=ssl_context)
```

**Esfuerzo:** 6-8h

#### Fix P1-01: Timeout Inconsistente

**Cursor Inline Edit:**
```
Select timeout lines in ai_chat_integration.py and engine.py
Cmd+K: "Estandarizar todos los timeouts a 60 segundos y usar constante"
```

**Diff esperado:**
```python
# ai-service/app/config.py (NEW)
TIMEOUT_AI_SERVICE = 60  # seconds

# ai-service/app/engine.py
from .config import TIMEOUT_AI_SERVICE

client = anthropic.Anthropic(timeout=TIMEOUT_AI_SERVICE)

# addons/l10n_cl_dte/models/ai_chat_integration.py
TIMEOUT_AI_SERVICE = 60  # Sync with AI service

response = requests.post(url, json=data, timeout=TIMEOUT_AI_SERVICE)
```

**Esfuerzo:** 2-3h

#### Fix P1-02: Missing Observability

**Cursor Multi-file Edit:**
```
@ai-service/app/main.py @ai-service/app/engine.py
Agrega correlation IDs para tracing distribuido:
- Middleware FastAPI que genera correlation_id
- Propaga header X-Correlation-ID en requests
- Incluye correlation_id en todos los logs
```

**Diff esperado:**
```python
# ai-service/app/middleware.py (NEW)
from fastapi import Request
import uuid

@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response

# ai-service/app/engine.py
logger.info(
    "Claude API call",
    extra={"correlation_id": request.state.correlation_id}
)
```

**Esfuerzo:** 4-6h

### PASO 4: RECOMENDACIONES (300-400 palabras)

**Formato Cursor-optimizado:**
- Comandos Composer listos ejecutar
- Inline edits sugeridos (Cmd+K)
- Tests generados automáticamente
- Multi-file refactors planificados

---

## 🎨 ENFOQUE CURSOR IDE

**Ventajas Cursor:**

1. **Composer Mode:** Edita múltiples archivos simultáneamente
   ```
   @workspace Refactor timeout configuration across all files
   ```

2. **Inline AI Edit (Cmd+K):** Ediciones precisas línea por línea
   ```
   Select code block → Cmd+K → "Add error handling with retry logic"
   ```

3. **Codebase Indexing:** Búsqueda semántica inteligente
   ```
   "Where is the AI service client configured?"
   → Cursor finds ai_chat_integration.py:78
   ```

4. **Test Generation:** Genera tests automáticamente
   ```
   @ai-service/app/main.py Generate pytest tests for all endpoints
   ```

5. **Terminal Integration:** Ejecuta comandos y parsea output
   ```
   Terminal: pytest --cov
   Cursor: Analiza coverage report y sugiere mejoras
   ```

**Workflow Cursor:**
```
1. Cmd+L → "Analiza integración Odoo-AI"
2. Composer → Multi-file changes
3. Cmd+K → Inline fixes
4. Terminal → Run tests
5. Repeat hasta score ≥7/10
```

---

## 📊 MÉTRICAS ESPERADAS

- Palabras: 1,200-1,500
- File refs: ≥30 con @mentions
- Código fixes: ≥3 con diffs Cursor
- Comandos Cursor: ≥15 (Composer, Cmd+K, searches)
- Score: X/10 con justificación

---

**COMIENZA ANÁLISIS. USA @MENTIONS Y COMPOSER COMMANDS CUANDO SEA RELEVANTE.**
