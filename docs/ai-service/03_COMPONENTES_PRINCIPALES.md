# 🧩 AI Microservice - Componentes Principales

**Documento:** 03 de 06  
**Fecha:** 2025-10-25  
**Audiencia:** Desarrolladores, Tech Leads

---

## 📦 Estructura de Directorios

```
ai-service/
├── main.py                      # FastAPI app + endpoints
├── config.py                    # Pydantic Settings
├── requirements.txt             # Dependencies
├── Dockerfile                   # Container image
│
├── clients/                     # API clients
│   └── anthropic_client.py      # Claude API (optimized)
│
├── chat/                        # Chat engine
│   ├── engine.py                # ChatEngine (multi-agent)
│   ├── context_manager.py       # Session management (Redis)
│   └── knowledge_base.py        # Document search
│
├── payroll/                     # Payroll validation
│   ├── payroll_validator.py     # Liquidación validator
│   └── previred_scraper.py      # Indicadores extractor
│
├── sii_monitor/                 # SII monitoring
│   ├── orchestrator.py          # Main orchestrator
│   ├── scraper.py               # Web scraping
│   ├── extractor.py             # Text extraction
│   ├── analyzer.py              # Claude analysis
│   ├── classifier.py            # Impact classification
│   ├── notifier.py              # Slack notifications
│   └── storage.py               # Redis persistence
│
├── analytics/                   # Analytics matching
│   └── project_matcher_claude.py # Project assignment
│
├── plugins/                     # Plugin system (multi-agent)
│   ├── base.py                  # AIPlugin abstract class
│   ├── loader.py                # Auto-discovery
│   ├── registry.py              # Plugin registry
│   ├── dte/                     # DTE plugin
│   ├── payroll/                 # Payroll plugin
│   ├── stock/                   # Stock plugin
│   └── account/                 # Account plugin
│
├── utils/                       # Utilities
│   ├── cost_tracker.py          # Token/cost tracking
│   ├── metrics.py               # Prometheus metrics
│   ├── redis_helper.py          # Redis client
│   ├── circuit_breaker.py       # Resilience pattern
│   ├── cache.py                 # Caching decorators
│   ├── llm_helpers.py           # LLM utilities
│   └── validators.py            # Input validation
│
├── middleware/                  # FastAPI middleware
│   └── observability.py         # Logging, tracing
│
├── routes/                      # API routers
│   └── analytics.py             # Analytics endpoints
│
└── tests/                       # Test suite
    ├── test_dte_regression.py
    └── conftest.py
```

---

## 🎯 Componente 1: Anthropic Client (Optimizado)

**Archivo:** `clients/anthropic_client.py`  
**Líneas:** 484  
**Responsabilidad:** Cliente optimizado para Claude API

### Características Principales

#### 1. Prompt Caching (90% ahorro)

```python
# System prompt marcado como cacheable
message = await self.client.messages.create(
    model=self.model,
    max_tokens=512,
    system=[
        {
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"}  # ✅ CACHE
        }
    ],
    messages=messages
)
```

**Beneficio:**
- Input tokens: 10,000 → 100 fresh + 9,900 cached
- Costo: $0.030 → $0.003 (-90%)
- Latencia: 5s → 0.75s (-85%)

#### 2. Token Pre-counting

```python
async def estimate_tokens(self, messages, system) -> Dict:
    """Estima tokens y costo ANTES de hacer request"""
    count = await self.client.messages.count_tokens(
        model=self.model,
        system=system,
        messages=messages
    )
    
    estimated_cost = (
        count.input_tokens * pricing["input"] +
        estimated_output * pricing["output"]
    )
    
    # Validar límites de seguridad
    if estimated_cost > settings.max_estimated_cost_per_request:
        raise ValueError(f"Request too expensive: ${estimated_cost}")
```

**Beneficio:** Previene requests inesperadamente caros

#### 3. Token-Efficient Output

```python
# Prompt solicita JSON compacto
system_prompt = """
OUTPUT FORMAT (JSON COMPACTO):
{
  "c": 85.0,        // confidence 0-100
  "w": ["msg1"],    // warnings (abreviado)
  "e": [],          // errors
  "r": "send"       // recommendation
}
"""
```

**Beneficio:** 70% menos output tokens

#### 4. Circuit Breaker Integration

```python
from utils.circuit_breaker import anthropic_circuit_breaker

with anthropic_circuit_breaker:
    message = await self.client.messages.create(...)
```

**Configuración:**
- 5 fallos consecutivos → OPEN
- 60s recovery → HALF_OPEN
- 1 success → CLOSED

#### 5. Cost Tracking Automático

```python
# Después de cada request
from utils.cost_tracker import get_cost_tracker

tracker = get_cost_tracker()
tracker.record_usage(
    input_tokens=usage.input_tokens,
    output_tokens=usage.output_tokens,
    model=self.model,
    endpoint="/api/dte/validate",
    operation="dte_validation",
    metadata={
        "cache_read_tokens": cache_read_tokens,
        "cache_hit_rate": cache_hit_rate
    }
)
```

### Métodos Públicos

| Método | Descripción | Uso |
|--------|-------------|-----|
| `estimate_tokens()` | Pre-count tokens | Control costos |
| `validate_dte()` | Validar DTE | DTE validation |
| `call_with_caching()` | Generic call | Chat, Payroll |

---

## 💬 Componente 2: Chat Engine (Multi-Agente)

**Archivo:** `chat/engine.py`  
**Líneas:** 659  
**Responsabilidad:** Motor conversacional con plugin system

### Arquitectura Multi-Agente

```
User Query: "¿Cómo anulo una factura?"
     ↓
PluginRegistry.get_plugin_for_query()
     ↓
Keyword matching: "anulo" + "factura" → DTEPlugin
     ↓
DTEPlugin.get_system_prompt()
     ↓
KnowledgeBase.search(filters={module: 'l10n_cl_dte'})
     ↓
Build specialized prompt + context + KB docs
     ↓
Claude API (streaming)
     ↓
Response: "Para anular una factura electrónica..."
```

### Características Principales

#### 1. Plugin Selection Inteligente

```python
# Estrategia 1: Context hint explícito
if context and 'module' in context:
    plugin = self.get_plugin(context['module'])

# Estrategia 2: Keyword matching
keywords_map = {
    'l10n_cl_dte': ['dte', 'factura', 'boleta', 'sii', 'folio'],
    'l10n_cl_hr_payroll': ['liquidación', 'sueldo', 'afp', 'previred'],
    'stock': ['inventario', 'stock', 'almacén', 'picking'],
    # ...
}

# Estrategia 3: Fallback a default (l10n_cl_dte)
```

#### 2. Context Management (Redis)

```python
class ContextManager:
    def get_conversation_history(self, session_id: str) -> List[Dict]:
        """Retrieve last N messages from Redis"""
        key = f"chat:session:{session_id}:history"
        messages = self.redis.lrange(key, 0, self.max_messages - 1)
        return [json.loads(m) for m in messages]
    
    def save_conversation_history(self, session_id: str, history: List[Dict]):
        """Save conversation with TTL"""
        key = f"chat:session:{session_id}:history"
        self.redis.delete(key)
        for msg in history:
            self.redis.rpush(key, json.dumps(msg))
        self.redis.expire(key, self.session_ttl)
```

**TTL:** 1 hora (configurable)

#### 3. Knowledge Base Search

```python
class KnowledgeBase:
    def search(
        self,
        query: str,
        top_k: int = 3,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search relevant documentation.
        
        Filters:
            - module: 'l10n_cl_dte', 'hr_payroll', etc.
            - doc_type: 'guide', 'api', 'troubleshooting'
        """
        # Semantic search (futuro: embeddings)
        # Por ahora: keyword matching
```

#### 4. Streaming Support

```python
async def send_message_stream(
    self,
    session_id: str,
    user_message: str,
    user_context: Optional[Dict] = None
):
    """Stream response in real-time (SSE)"""
    
    async with self.anthropic_client.client.messages.stream(...) as stream:
        async for text in stream.text_stream:
            yield {"type": "text", "content": text}
    
    yield {"type": "done", "metadata": {...}}
```

**Beneficio:** TTFT 0.3s (vs 5s sin streaming)

### Métodos Públicos

| Método | Descripción | Streaming |
|--------|-------------|-----------|
| `send_message()` | Chat tradicional | No |
| `send_message_stream()` | Chat streaming | Sí ⭐ |
| `get_conversation_stats()` | Estadísticas sesión | - |

---

## 💰 Componente 3: Payroll Validator

**Archivo:** `payroll/payroll_validator.py`  
**Líneas:** 253  
**Responsabilidad:** Validación inteligente de liquidaciones

### Validaciones Implementadas

#### 1. Validaciones Rápidas (Sin IA)

```python
# Coherencia básica
if wage <= 0:
    errors.append("Sueldo base debe ser mayor a 0")

if liquido < 0:
    errors.append(f"Líquido negativo: ${liquido:,.0f}")

if total_descuentos > total_haberes * 0.5:
    warnings.append("Descuentos muy altos: {:.1f}%".format(...))
```

#### 2. Validación Profunda (Claude API)

```python
async def _validate_with_claude(self, payslip_data: Dict) -> Dict:
    """
    Analiza liquidación comparando con:
    - Indicadores Previred del período
    - Legislación laboral chilena
    - Coherencia matemática
    """
    
    prompt = f"""
    Analiza esta liquidación:
    
    CRITERIOS (Legislación Chile 2025):
    1. AFP: Tasa ≈ 10.75-11.44% según AFP
    2. SALUD: Mínimo 7% (Fonasa)
    3. AFC: Trabajador 0.6%, Empleador 2.4%
    4. IMPUESTO ÚNICO: Según tramos SII
    
    RESPONDE JSON:
    {{
        "errors": ["errores graves"],
        "warnings": ["advertencias"],
        "confidence": 85.5,
        "reasoning": "explicación"
    }}
    """
```

### Criterios de Validación

| Concepto | Validación | Fuente |
|----------|------------|--------|
| **AFP** | 10.75-11.44% según AFP | Previred |
| **Salud** | Mínimo 7% (Fonasa) | Ley 18.469 |
| **AFC** | 0.6% trabajador | Ley 19.728 |
| **Impuesto Único** | Según tramos | SII 2025 |
| **Líquido** | Debe ser > 0 | Lógica |

### Integración con Previred

```python
# payroll/previred_scraper.py
class PreviredScraper:
    async def extract_indicators(self, period: str) -> Dict:
        """
        Extrae 60 campos desde PDF oficial Previred:
        - UF, UTM, UTA, sueldo mínimo
        - Tasas AFP por fondo (5 AFPs × 5 fondos)
        - Topes imponibles
        - Asignación familiar por tramo
        """
```

**Cache:** Redis, 1 mes (indicadores no cambian)

---

## 📡 Componente 4: SII Monitor

**Archivos:** `sii_monitor/*.py` (7 archivos)  
**Responsabilidad:** Monitoreo automático de noticias/normativas SII

### Subcomponentes

#### 1. Orchestrator (orchestrator.py)

```python
class MonitoringOrchestrator:
    def execute_monitoring(self, force: bool = False) -> Dict:
        """
        Ciclo completo:
        1. Scrape URLs SII
        2. Detect changes (hash comparison)
        3. Extract text
        4. Analyze with Claude
        5. Classify impact
        6. Notify Slack
        7. Store in Redis
        """
```

#### 2. Scraper (scraper.py)

```python
SII_URLS = {
    'noticias': 'https://www.sii.cl/noticias/',
    'normativa': 'https://www.sii.cl/normativa_legislacion/',
    'resoluciones': 'https://www.sii.cl/normativa_legislacion/resoluciones/',
    'circulares': 'https://www.sii.cl/normativa_legislacion/circulares/',
    'oficios': 'https://www.sii.cl/normativa_legislacion/oficios/'
}

class SIIScraper:
    def scrape_all(self, urls: Dict[str, str]) -> Dict:
        """Scrape all URLs and return documents"""
        
    def detect_changes(self, new_hash: str, old_hash: str) -> bool:
        """Compare content hashes"""
```

#### 3. Analyzer (analyzer.py)

```python
class SIIDocumentAnalyzer:
    async def analyze_document(
        self,
        text: str,
        metadata: Dict
    ) -> DocumentAnalysis:
        """
        Analiza con Claude:
        - Tipo: Resolución, Circular, Oficio, Noticia
        - Número: Identificador oficial
        - Fecha: Publicación
        - Resumen: 2-3 líneas
        - Impacto: Alto/Medio/Bajo
        - Módulos afectados: ['l10n_cl_dte', 'account']
        - Plazos: Fechas límite
        - Acciones requeridas: Lista
        """
```

#### 4. Classifier (classifier.py)

```python
class ImpactClassifier:
    def calculate_priority(self, analysis: Dict) -> int:
        """
        Calcula prioridad 1-5:
        
        5 (CRÍTICO): Cambio normativo obligatorio con plazo < 30 días
        4 (ALTO): Afecta compliance, plazo < 90 días
        3 (MEDIO): Mejora recomendada
        2 (BAJO): Informativo
        1 (INFO): FYI
        """
    
    def determine_actions(self, analysis: Dict) -> List[str]:
        """
        Acciones requeridas:
        - "Actualizar módulo l10n_cl_dte"
        - "Revisar validaciones CAF"
        - "Comunicar a clientes"
        """
```

#### 5. Notifier (notifier.py)

```python
class NewsNotifier:
    def notify_new_news(self, news: Dict) -> bool:
        """
        Envía a Slack #sii-compliance:
        
        🔴 PRIORIDAD 5: Resolución Exenta N° 123
        📅 Fecha: 2025-10-20
        ⏰ Plazo: 2025-11-30 (40 días)
        
        📋 Resumen:
        Nuevos requisitos para DTEs...
        
        🎯 Módulos Afectados:
        - l10n_cl_dte
        - account
        
        ✅ Acciones Requeridas:
        1. Actualizar validación XML
        2. Agregar campo nuevo
        
        @tech-lead @compliance-team
        """
```

### Frecuencia de Ejecución

```python
# Odoo ir.cron
<record id="cron_sii_monitoring" model="ir.cron">
    <field name="name">SII Monitoring</field>
    <field name="interval_number">6</field>
    <field name="interval_type">hours</field>
    <field name="numbercall">-1</field>
    <field name="model_id" ref="model_ir_http"/>
    <field name="code">
        # Call AI service
        requests.post('http://ai-service:8002/api/ai/sii/monitor')
    </field>
</record>
```

**Costo:** ~$0.05 por ejecución (5 URLs × $0.01)

---

## 📊 Componente 5: Analytics Matcher

**Archivo:** `analytics/project_matcher_claude.py`  
**Responsabilidad:** Asignación inteligente de gastos a proyectos

### Funcionamiento

```python
class ProjectMatcherClaude:
    async def match_invoice_to_project(
        self,
        invoice_description: str,
        projects: List[Dict]
    ) -> Dict:
        """
        Analiza descripción de factura y sugiere proyecto.
        
        Input:
            invoice_description: "Compra materiales construcción edificio A"
            projects: [
                {"id": 1, "name": "Edificio A", "description": "..."},
                {"id": 2, "name": "Edificio B", "description": "..."}
            ]
        
        Output:
            {
                "matched_project_id": 1,
                "confidence": 95.0,
                "reasoning": "Mención explícita 'edificio A'"
            }
        """
```

### Prompt Engineering

```python
prompt = f"""
Eres un experto en gestión de proyectos y contabilidad analítica.

FACTURA:
{invoice_description}

PROYECTOS ACTIVOS:
{json.dumps(projects, indent=2)}

TAREA:
Determina a qué proyecto corresponde esta factura.

RESPONDE JSON:
{{
    "matched_project_id": 1,
    "confidence": 95.0,
    "reasoning": "explicación breve"
}}
"""
```

**Beneficio:** 80% reducción en asignación manual

---

## 🔌 Componente 6: Plugin System

**Archivos:** `plugins/*.py`  
**Responsabilidad:** Arquitectura multi-agente extensible

### Plugin Base (Abstract)

```python
# plugins/base.py
class AIPlugin(ABC):
    @abstractmethod
    def get_module_name(self) -> str:
        """Odoo module name (e.g., 'l10n_cl_dte')"""
        pass
    
    @abstractmethod
    def get_display_name(self) -> str:
        """Human-readable name"""
        pass
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Specialized system prompt for this domain"""
        pass
    
    @abstractmethod
    def get_supported_operations(self) -> List[str]:
        """Operations this plugin handles"""
        pass
    
    @abstractmethod
    def get_keywords(self) -> List[str]:
        """Keywords for auto-selection"""
        pass
```

### Plugin Concreto: DTE

```python
# plugins/dte/plugin.py
class DTEPlugin(AIPlugin):
    def get_module_name(self) -> str:
        return "l10n_cl_dte"
    
    def get_display_name(self) -> str:
        return "Facturación Electrónica Chile"
    
    def get_system_prompt(self) -> str:
        return """
        Eres un experto en facturación electrónica chilena.
        
        EXPERTISE:
        - DTEs 33, 34, 52, 56, 61
        - Normativa SII 2025
        - CAF, Folios, Timbres
        - Validación RUT (Módulo 11)
        
        RESPONDE EN ESPAÑOL CHILENO.
        """
    
    def get_supported_operations(self) -> List[str]:
        return [
            "validate_dte",
            "explain_dte_types",
            "troubleshoot_rejection",
            "caf_management"
        ]
    
    def get_keywords(self) -> List[str]:
        return [
            'dte', 'factura', 'boleta', 'guía', 'nota de crédito',
            'sii', 'folio', 'caf', 'timbre', 'envío'
        ]
```

### Plugin Registry (Auto-Discovery)

```python
# plugins/registry.py
class PluginRegistry:
    def __init__(self, auto_discover: bool = True):
        self.plugins: Dict[str, AIPlugin] = {}
        
        if auto_discover:
            self._auto_register()
    
    def _auto_register(self):
        """Discover and register all plugins"""
        loader = PluginLoader()
        discovered = loader.load_all_plugins()
        
        for plugin in discovered:
            self.register(plugin)
    
    def get_plugin_for_query(
        self,
        query: str,
        context: Optional[Dict] = None
    ) -> Optional[AIPlugin]:
        """
        Intelligent plugin selection:
        1. Explicit context hint
        2. Keyword matching
        3. Fallback to default
        """
```

### Plugins Disponibles

| Plugin | Módulo | Keywords | Operaciones |
|--------|--------|----------|-------------|
| **DTEPlugin** | l10n_cl_dte | factura, dte, sii | validate, explain, troubleshoot |
| **PayrollPlugin** | l10n_cl_hr_payroll | liquidación, afp, previred | validate, calculate, explain |
| **StockPlugin** | stock | inventario, picking, almacén | track, transfer, adjust |
| **AccountPlugin** | account | contabilidad, asiento, balance | reconcile, report, analyze |

---

## 🛠️ Componente 7: Utilities

### Cost Tracker

```python
# utils/cost_tracker.py
class CostTracker:
    def record_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str,
        endpoint: str,
        operation: str
    ) -> TokenUsage:
        """
        Track usage and persist to Redis:
        - cost_tracker:daily:{YYYY-MM-DD}
        - cost_tracker:monthly:{YYYY-MM}
        - cost_tracker:counters
        """
```

**Pricing (Claude Sonnet 4.5):**
- Input: $3.00 / 1M tokens
- Output: $15.00 / 1M tokens
- Cache read: $0.30 / 1M tokens (90% ahorro)

### Circuit Breaker

```python
# utils/circuit_breaker.py
from circuitbreaker import circuit

anthropic_circuit_breaker = circuit(
    failure_threshold=5,
    recovery_timeout=60,
    expected_exception=anthropic.APIError
)
```

### Redis Helper

```python
# utils/redis_helper.py
def get_redis_client() -> redis.Redis:
    """Get Redis client (singleton)"""
    return redis.from_url(
        settings.redis_url,
        decode_responses=True
    )
```

### LLM Helpers

```python
# utils/llm_helpers.py
def extract_json_from_llm_response(text: str) -> Dict:
    """
    Extract JSON from LLM response (handles markdown, etc.)
    """
    
def validate_llm_json_schema(
    data: Dict,
    required_fields: List[str],
    field_types: Dict
) -> Dict:
    """
    Validate LLM JSON output against schema
    """
```

---

## 📈 Métricas por Componente

| Componente | Requests/día | Costo/día | Latencia P95 |
|------------|--------------|-----------|--------------|
| Chat Engine | 500 | $1.50 | 500ms |
| DTE Validator | 200 | $0.40 | 800ms |
| Payroll Validator | 50 | $0.05 | 700ms |
| SII Monitor | 4 | $0.20 | 25s |
| Analytics Matcher | 100 | $0.05 | 300ms |
| **TOTAL** | **854** | **$2.20** | - |

**Costo mensual:** ~$66 (muy por debajo del presupuesto)

---

## 🔗 Próximo Documento

**04_OPTIMIZACIONES_TECNICAS.md** - Implementación detallada de optimizaciones

---

**Última Actualización:** 2025-10-25  
**Mantenido por:** EERGYGROUP Development Team
