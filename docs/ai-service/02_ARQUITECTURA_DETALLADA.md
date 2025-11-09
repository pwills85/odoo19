# 🏗️ AI Microservice - Arquitectura Detallada

**Documento:** 02 de 06  
**Fecha:** 2025-10-25  
**Audiencia:** Arquitectos, Tech Leads, DevOps

---

## 📐 Principios de Diseño

### 1. **Stateless Architecture**
- Todo el estado en Redis (sessions, cache, metrics)
- Permite escalado horizontal sin sticky sessions
- Múltiples instancias del AI service sin conflictos

### 2. **Graceful Degradation**
- Si Claude API falla → respuesta neutral (no bloquea flujo)
- Si Redis falla → funciona sin cache (degradado)
- Circuit breaker previene cascading failures

### 3. **API-First Design**
- FastAPI con OpenAPI/Swagger automático
- Contratos claros (Pydantic models)
- Versionado de endpoints preparado

### 4. **Observability by Default**
- Structured logging (structlog)
- Prometheus metrics en `/metrics`
- Cost tracking en tiempo real
- Health checks comprehensivos

---

## 🎯 Patrones Arquitectónicos

### Singleton Pattern
```python
# Global instances para evitar re-inicialización
_client: Optional[AnthropicClient] = None

def get_anthropic_client(api_key: str, model: str) -> AnthropicClient:
    global _client
    if _client is None:
        _client = AnthropicClient(api_key, model)
    return _client
```

**Usado en:**
- `AnthropicClient` (clients/anthropic_client.py)
- `CostTracker` (utils/cost_tracker.py)
- `PluginRegistry` (plugins/registry.py)
- `ChatEngine` (chat/engine.py)

### Circuit Breaker Pattern
```python
from utils.circuit_breaker import anthropic_circuit_breaker

with anthropic_circuit_breaker:
    response = await client.messages.create(...)
```

**Configuración:**
- **Failure threshold:** 5 fallos consecutivos
- **Recovery timeout:** 60 segundos
- **Half-open test:** 1 request de prueba

### Repository Pattern
```python
class NewsStorage:
    """Abstracción sobre Redis para noticias SII"""
    
    def save_news(self, news: Dict, news_id: str):
        # Implementación Redis oculta
        pass
```

**Beneficio:** Fácil migración a PostgreSQL/MongoDB si es necesario

### Strategy Pattern (Plugin System)
```python
class AIPlugin(ABC):
    @abstractmethod
    def get_system_prompt(self) -> str:
        pass
    
    @abstractmethod
    def process_query(self, query: str, context: Dict) -> str:
        pass
```

**Plugins disponibles:**
- `DTEPlugin` (l10n_cl_dte)
- `PayrollPlugin` (l10n_cl_hr_payroll)
- `StockPlugin` (stock)
- `AccountPlugin` (account)

---

## 🔄 Flujos de Datos Principales

### Flujo 1: Validación DTE Pre-Envío

```
┌─────────────┐
│ Odoo Module │ account.move.action_post()
│ l10n_cl_dte │
└──────┬──────┘
       │ HTTP POST /api/ai/validate
       │ {dte_data, company_id, history}
       ▼
┌─────────────────────────────────────────┐
│         AI Service (main.py)            │
│  1. Validate request (Pydantic)         │
│  2. Rate limit check (20/min)           │
│  3. API key verification                │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   AnthropicClient (optimized)           │
│  1. Build prompts (system + user)       │
│  2. Pre-count tokens (cost estimate)    │
│  3. Apply prompt caching (90% ahorro)   │
│  4. Call Claude API (async)             │
│  5. Track cost (Redis)                  │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   Response Processing                   │
│  1. Extract JSON from LLM response      │
│  2. Validate schema                     │
│  3. Expand compact format               │
│  4. Log metrics                         │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────┐
│ Odoo Module │ Recibe: {confidence, warnings, errors, recommendation}
│ l10n_cl_dte │ Decide: enviar al SII o revisar
└─────────────┘
```

**Latencia típica:** 500ms (con caching)  
**Costo típico:** $0.002 por validación

---

### Flujo 2: Chat Conversacional Multi-Agente

```
┌─────────────┐
│ Odoo Widget │ Usuario escribe: "¿Cómo anulo una factura?"
│ Chat Button │
└──────┬──────┘
       │ HTTP POST /api/chat/message/stream
       │ {session_id, message, user_context}
       ▼
┌─────────────────────────────────────────┐
│      ChatEngine (chat/engine.py)        │
│  1. Retrieve conversation history       │
│     (Redis: last 10 messages)           │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   PluginRegistry (intelligent select)   │
│  1. Analyze query keywords              │
│     "anulo" + "factura" → DTE Plugin    │
│  2. Return specialized plugin           │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   KnowledgeBase (module-specific)       │
│  1. Search relevant docs                │
│     filters: {module: 'l10n_cl_dte'}    │
│  2. Return top 3 docs                   │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   Build System Prompt (plugin-based)    │
│  1. Plugin's specialized prompt         │
│  2. + User context (company, role)      │
│  3. + Knowledge base docs (cached)      │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   Claude API (Streaming)                │
│  1. Stream response chunks              │
│  2. Yield to client in real-time        │
│  3. Track cache hits                    │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────┐
│ Odoo Widget │ Muestra respuesta en tiempo real (SSE)
│ Chat Button │ UX: 3x más rápido percibido
└─────────────┘
```

**Latencia TTFT:** 0.3s (time to first token)  
**Costo típico:** $0.003 por mensaje

---

### Flujo 3: Monitoreo SII Automático (Cron)

```
┌─────────────┐
│ Odoo Cron   │ Ejecuta cada 6 horas
│ ir.cron     │
└──────┬──────┘
       │ HTTP POST /api/ai/sii/monitor
       │ {force: false}
       ▼
┌─────────────────────────────────────────┐
│   MonitoringOrchestrator                │
│  (sii_monitor/orchestrator.py)          │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   SIIScraper (scraper.py)               │
│  1. Scrape 5 URLs SII                   │
│     - Noticias                          │
│     - Normativas                        │
│     - Resoluciones                      │
│  2. Calculate content hash              │
│  3. Detect changes vs Redis cache       │
└──────┬──────────────────────────────────┘
       │ Si hay cambios
       ▼
┌─────────────────────────────────────────┐
│   DocumentExtractor (extractor.py)      │
│  1. Extract text from HTML              │
│  2. Clean text (remove noise)           │
│  3. Extract metadata (date, type, #)    │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   SIIDocumentAnalyzer (analyzer.py)     │
│  1. Call Claude API                     │
│  2. Analyze: tipo, impacto, plazos      │
│  3. Extract structured data             │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   ImpactClassifier (classifier.py)      │
│  1. Calculate priority (1-5)            │
│  2. Determine required actions          │
│  3. Assign responsible team             │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   NewsNotifier (notifier.py)            │
│  1. Format Slack message                │
│  2. Send to #sii-compliance channel     │
│  3. Tag @tech-lead if priority >= 4     │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│   NewsStorage (storage.py)              │
│  1. Save to Redis                       │
│  2. Update URL hash                     │
│  3. Store for 90 days                   │
└─────────────────────────────────────────┘
```

**Frecuencia:** Cada 6 horas  
**Costo típico:** $0.05 por ejecución (5 URLs × $0.01)

---

## 🗄️ Modelo de Datos (Redis)

### Keys Structure

```
# Chat Sessions
chat:session:{session_id}:history     → List[Dict] (last 10 messages)
chat:session:{session_id}:context     → Dict (user context)
chat:session:{session_id}:stats       → Dict (message count, tokens)

# Cost Tracking
cost_tracker:daily:{YYYY-MM-DD}       → List[TokenUsage]
cost_tracker:monthly:{YYYY-MM}        → List[TokenUsage]
cost_tracker:counters                 → Hash (total_tokens, total_cost)

# SII Monitoring
sii:url_hash:{url_key}                → String (MD5 hash)
sii:news:{news_id}                    → Dict (analyzed news)
sii:last_execution                    → String (ISO timestamp)

# Cache (generic)
cache:{operation}:{key_hash}          → String (JSON serialized)
```

### TTL (Time To Live)

| Key Pattern | TTL | Rationale |
|-------------|-----|-----------|
| `chat:session:*` | 1 hora | Sesiones temporales |
| `cost_tracker:daily:*` | 90 días | Análisis histórico |
| `sii:news:*` | 90 días | Compliance audit trail |
| `cache:*` | 1 hora | Reduce llamadas Claude |

---

## 🔌 Endpoints API

### Health & Monitoring

```
GET  /health                    → Health check con dependencies
GET  /metrics                   → Prometheus metrics (público)
GET  /metrics/costs?period=today → Cost breakdown (autenticado)
```

### DTE Operations

```
POST /api/ai/validate           → Pre-validación DTE
POST /api/ai/reconcile          → Reconciliación con PO (deprecated)
POST /api/ai/reception/match_po → Match DTE recibido con PO
```

### Chat Operations

```
POST /api/chat/message          → Chat tradicional (no streaming)
POST /api/chat/message/stream   → Chat streaming (recomendado)
POST /api/chat/session/new      → Crear nueva sesión
GET  /api/chat/session/{id}     → Obtener sesión existente
```

### Payroll Operations

```
POST /api/payroll/validate      → Validar liquidación
GET  /api/payroll/indicators/{period} → Indicadores Previred
```

### SII Monitoring

```
POST /api/ai/sii/monitor        → Trigger monitoreo manual
GET  /api/ai/sii/status         → Estado del sistema
```

### Analytics

```
POST /api/v1/analytics/match    → Project matching (analytics router)
```

---

## 🔐 Seguridad en Profundidad

### Capa 1: Network (Docker)

```yaml
# docker-compose.yml
ai-service:
  expose:
    - "8002"  # ⭐ Solo red interna (NO ports:)
  networks:
    - stack_network
```

**Resultado:** AI service NO accesible desde internet

### Capa 2: Authentication

```python
# main.py
security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials):
    # Timing-attack resistant comparison
    if not secrets.compare_digest(
        credentials.credentials.encode('utf-8'),
        settings.api_key.encode('utf-8')
    ):
        raise HTTPException(403, "Invalid API key")
```

**Método:** Bearer token en header `Authorization`

### Capa 3: Rate Limiting

```python
# main.py
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/ai/validate")
@limiter.limit("20/minute")  # Max 20 validaciones por minuto
async def validate_dte(...):
    pass
```

**Protección:** DDoS, abuse, cost control

### Capa 4: Input Validation

```python
# main.py
class DTEValidationRequest(BaseModel):
    dte_data: Dict[str, Any] = Field(..., description="Datos del DTE")
    company_id: int = Field(..., gt=0)
    history: Optional[List[Dict]] = Field(default=[], max_items=100)
    
    @validator('dte_data')
    def validate_dte_data(cls, v):
        if not isinstance(v, dict) or not v:
            raise ValueError("dte_data debe ser un diccionario no vacío")
        # ... más validaciones
```

**Protección:** Injection attacks, malformed data

### Capa 5: Cost Control

```python
# clients/anthropic_client.py
if settings.enable_token_precounting:
    estimate = await self.estimate_tokens(messages, system)
    
    if estimate["estimated_cost_usd"] > settings.max_estimated_cost_per_request:
        raise ValueError(f"Request too expensive: ${estimate['estimated_cost_usd']}")
```

**Protección:** Runaway costs, budget overruns

---

## 📊 Observability Stack

### Structured Logging (Structlog)

```python
logger.info(
    "dte_validation_completed",
    company_id=data.company_id,
    confidence=result["confidence"],
    recommendation=result["recommendation"],
    tokens_used=usage.total_tokens,
    cost_usd=round(cost, 6)
)
```

**Output:**
```json
{
  "event": "dte_validation_completed",
  "company_id": 1,
  "confidence": 95.0,
  "recommendation": "send",
  "tokens_used": 850,
  "cost_usd": 0.002,
  "timestamp": "2025-10-25T04:30:15.123Z"
}
```

### Prometheus Metrics

```python
# utils/metrics.py
from prometheus_client import Counter, Histogram

claude_requests_total = Counter(
    'claude_api_requests_total',
    'Total Claude API requests',
    ['operation', 'status']
)

claude_request_duration = Histogram(
    'claude_api_request_duration_seconds',
    'Claude API request duration',
    ['operation']
)
```

**Dashboards:** Grafana (futuro)

### Cost Tracking

```python
# utils/cost_tracker.py
tracker = get_cost_tracker()
tracker.record_usage(
    input_tokens=150,
    output_tokens=450,
    model="claude-sonnet-4-5-20250929",
    endpoint="/api/dte/validate",
    operation="dte_validation"
)
```

**Query:** `GET /metrics/costs?period=today`

---

## 🚀 Deployment Architecture

### Development (Local)

```bash
cd ai-service
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn main:app --reload --port 8002
```

**Hot reload:** Cambios en código se reflejan automáticamente

### Production (Docker)

```bash
cd /Users/pedro/Documents/odoo19
docker-compose up -d ai-service
```

**Características:**
- Auto-restart (unless-stopped)
- Health checks cada 30s
- Logs centralizados
- Volume mounts para cache

### Scaling (Futuro)

```yaml
# docker-compose.yml
ai-service:
  deploy:
    replicas: 3
    resources:
      limits:
        cpus: '1.0'
        memory: 1G
```

**Load balancer:** Nginx/Traefik (pendiente)

---

## 📈 Performance Benchmarks

### Latencia por Endpoint

| Endpoint | P50 | P95 | P99 |
|----------|-----|-----|-----|
| `/api/ai/validate` | 450ms | 800ms | 1.2s |
| `/api/chat/message/stream` | 300ms (TTFT) | 500ms | 800ms |
| `/api/payroll/validate` | 400ms | 700ms | 1.0s |
| `/api/ai/sii/monitor` | 15s | 25s | 35s |

### Throughput

- **Max concurrent requests:** 50 (FastAPI async)
- **Rate limit:** 20-30 req/min por endpoint
- **Bottleneck:** Claude API rate limits (no el servicio)

### Resource Usage

```bash
docker stats odoo19_ai_service

CONTAINER           CPU %   MEM USAGE / LIMIT
odoo19_ai_service   5.2%    245MB / 1GB
```

**Footprint:** Muy ligero (FastAPI + async)

---

## 🔗 Próximo Documento

**03_COMPONENTES_PRINCIPALES.md** - Análisis detallado de cada módulo

---

**Última Actualización:** 2025-10-25  
**Mantenido por:** EERGYGROUP Development Team
