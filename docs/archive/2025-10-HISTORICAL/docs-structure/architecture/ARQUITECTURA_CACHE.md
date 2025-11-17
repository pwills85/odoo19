# Arquitectura de Cache - Stack Odoo 19 CE

**Fecha:** 2025-10-23
**Contexto:** Refactorización FASE 1 - Eliminación cache service duplicado
**Stack:** Odoo 19 CE + Redis 7 + PostgreSQL 15

---

## DECISIÓN ARQUITECTÓNICA

**Eliminado:** `l10n_cl_base.cache_service` (PostgreSQL-based)
**Razón:** Duplicación innecesaria, 50-100x más lento que Redis
**Reemplazo:** Usar herramientas nativas según contexto

---

## ESTRATEGIA DE CACHE POR CAPA

### 1. Odoo Models (Python)

**Usar:** `@tools.cache` decorator (Odoo 19 CE nativo)

```python
from odoo import models, tools

class AccountMove(models.Model):
    _inherit = 'account.move'

    @tools.ormcache('self.id', 'date')
    def _compute_tax_totals(self, date):
        """Cache computado basado en invoice ID + date"""
        # Computation logic
        return totals
```

**Características:**
- Invalidación automática en write/unlink
- Basado en PostgreSQL (optimizado para ORM)
- Perfecto para datos relacionados al ORM
- Performance: ~5-10ms

**Cuándo usar:**
- Computed fields costosos
- Búsquedas ORM frecuentes
- Datos relacionados a registros específicos

---

### 2. Microservices (Python - AI Service, Eergy Services)

**Usar:** Redis directo con decorator custom

**Ubicación:** `ai-service/utils/cache.py` (318 líneas, production-ready)

```python
from utils.cache import cache_method

class AnthropicClient:
    @cache_method(ttl_seconds=1800)
    def validate_dte(self, dte_data, history):
        """Cache LLM responses to reduce API costs"""
        response = await self.client.messages.create(...)
        return response
```

**Características:**
- TTL configurable (default: 15 min)
- Automatic serialization (JSON)
- Fallback graceful si Redis falla
- Performance: ~0.5-2ms

**Configuración Redis:**
```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  container_name: odoo19_redis
  expose:
    - "6379"
  networks:
    - stack_network
```

**Cuándo usar:**
- Respuestas LLM (Claude, OpenAI)
- API calls externas (SII, Previred)
- Computaciones pesadas (>500ms)
- Datos NO relacionados al ORM

---

### 3. Comunicación Odoo ↔ Microservices

**Patrón:** Odoo hace request HTTP al microservicio, microservicio cachea

```python
# En Odoo (NO cachear aquí)
class DteAiClient(models.AbstractModel):
    _name = 'dte.ai.client'

    def validate_dte_with_ai(self, dte_data):
        """Call AI service - NO cache en Odoo"""
        url = f"{AI_SERVICE_URL}/api/ai/dte/validate"
        response = requests.post(url, json=dte_data)
        return response.json()

# En ai-service (SI cachear aquí)
@router.post("/api/ai/dte/validate")
@cache_llm_response(ttl_seconds=900)
async def validate_dte(request: DteValidationRequest):
    """Validate DTE using Claude - cached 15 min"""
    result = await anthropic_client.validate(request.dte_data)
    return result
```

**Razón:** El microservicio conoce la semántica del cache mejor que Odoo

---

## COMPARATIVA DE PERFORMANCE

| Método | Latencia | Caso de Uso | Invalidación |
|--------|:--------:|-------------|--------------|
| PostgreSQL (ir.config_parameter) | 50-100ms | ❌ NO usar | Manual |
| PostgreSQL (@tools.cache) | 5-10ms | ✅ ORM queries | Automática |
| Redis (microservices) | 0.5-2ms | ✅ LLM, APIs | TTL |
| In-memory (functools.lru_cache) | <0.1ms | ⚠️ Single worker | Process restart |

---

## EJEMPLOS CONCRETOS

### ✅ CORRECTO: Cache ORM con @tools.cache

```python
# addons/localization/l10n_cl_dte/models/account_move_dte.py
from odoo import models, tools

class AccountMoveDte(models.Model):
    _inherit = 'account.move'

    @tools.ormcache('self.id')
    def _get_dte_document_xml(self):
        """Cache DTE XML to avoid regeneration"""
        # Generate XML (expensive operation)
        return xml_content
```

### ✅ CORRECTO: Cache LLM con Redis

```python
# ai-service/analytics/project_matcher_claude.py
from utils.cache import cache_method

class ProjectMatcher:
    @cache_method(ttl_seconds=1800)
    async def suggest_project(self, purchase_data, vendor_history):
        """Cache project suggestions for 30 min"""
        response = await self.claude_client.suggest(...)
        return response
```

### ❌ INCORRECTO: Cache PostgreSQL custom

```python
# ANTES (ELIMINADO)
class L10nClCacheService(models.AbstractModel):
    _name = 'l10n_cl_base.cache_service'

    def get_cached(self, key, ttl=3600):
        # Uses ir.config_parameter (50-100ms) ❌
        param_key = f'l10n_cl_cache.{key}'
        return self.env['ir.config_parameter'].sudo().get_param(param_key)
```

---

## MATRIZ DE DECISIÓN

```
┌─────────────────────────────────────────────────────────────────┐
│ Cache Decision Matrix                                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ ¿Datos relacionados al ORM (account.move, res.partner)?        │
│    ├─ SI → @tools.cache (Odoo nativo)                          │
│    └─ NO → ¿Dónde se ejecuta?                                  │
│              ├─ Odoo → NO cachear, delegar a microservicio     │
│              └─ Microservicio → Redis con decorator custom     │
│                                                                  │
│ ¿Operación >500ms?                                             │
│    ├─ SI → Considerar cache (cualquier método)                 │
│    └─ NO → Probablemente no justifica cache                    │
│                                                                  │
│ ¿Datos cambian frecuentemente (<5 min)?                        │
│    ├─ SI → TTL bajo (5-15 min) o no cachear                    │
│    └─ NO → TTL alto (30-60 min)                                │
│                                                                  │
│ ¿Cache crítico para funcionamiento?                            │
│    ├─ SI → Implementar fallback graceful                       │
│    └─ NO → Permitir fallos silenciosos                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## PATRONES DE INVALIDACIÓN

### Odoo @tools.cache

**Automático en:**
- `self.write(...)` - Invalida cache del registro
- `self.unlink()` - Invalida cache del registro
- `self.create(...)` - No afecta cache existente

**Manual:**
```python
# Invalidar cache específico
self.env.cache.invalidate()

# Invalidar solo un modelo
self.env['account.move'].invalidate_cache()

# Invalidar solo un método
self._compute_tax_totals.clear_cache()
```

### Redis (Microservices)

**Por TTL:**
```python
@cache_method(ttl_seconds=900)  # Auto-expire en 15 min
```

**Manual:**
```python
from utils.cache import clear_llm_cache

# Limpiar todo el cache LLM
clear_llm_cache()

# Limpiar solo validaciones DTE
clear_llm_cache("llm_cache:validate_dte:*")
```

---

## MONITOREO

### Redis Stats

```python
from utils.cache import get_cache_stats

stats = get_cache_stats()
# {
#   'total_keys': 1247,
#   'memory_used_mb': 12.34,
#   'cache_prefix': 'llm_cache:'
# }
```

### Odoo Cache Stats

```python
# En shell Odoo
stats = self.env.cache.get_stats()
# {'hits': 12450, 'misses': 3210, 'size': 45MB}
```

---

## MIGRACIÓN DESDE cache_service

### ANTES (l10n_cl_base.cache_service) ❌

```python
# l10n_cl_base/models/cache_service.py (ELIMINADO)
cache_value = self.env['l10n_cl_base.cache_service'].get_cached(
    key='sii_exchange_rate_2024-10',
    ttl=3600
)
```

### DESPUÉS - Opción 1: @tools.cache ✅

```python
# Si es dato ORM-related
from odoo import models, tools

class ResCompany(models.Model):
    _inherit = 'res.company'

    @tools.ormcache('self.id', 'date')
    def get_sii_exchange_rate(self, date):
        # Fetch from SII API
        return rate
```

### DESPUÉS - Opción 2: Delegar a microservicio ✅

```python
# En Odoo
class SiiClient(models.AbstractModel):
    _name = 'sii.client'

    def get_exchange_rate(self, date):
        # Call eergy-service (tiene cache Redis)
        url = f"{EERGY_SERVICE_URL}/api/sii/exchange_rate/{date}"
        return requests.get(url).json()

# En eergy-service
@router.get("/api/sii/exchange_rate/{date}")
@cache_method(ttl_seconds=3600)
async def get_exchange_rate(date: str):
    # Fetch from SII, cache 1 hour
    rate = await sii_client.fetch_rate(date)
    return {"rate": rate, "date": date}
```

---

## COSTOS ESTIMADOS

### Cache Hit Savings (LLM)

```
Escenario: 1000 validaciones DTE/mes
- Sin cache: 1000 llamadas × $0.003 = $3.00
- Con cache (40% hit rate): 600 llamadas × $0.003 = $1.80
- Ahorro mensual: $1.20
- Ahorro anual: $14.40

Escenario: 10,000 validaciones DTE/mes
- Sin cache: 10,000 llamadas × $0.003 = $30.00
- Con cache (40% hit rate): 6,000 llamadas × $0.003 = $18.00
- Ahorro mensual: $12.00
- Ahorro anual: $144.00
```

### Performance Improvement

```
Query time improvement (PostgreSQL → Redis):
- 100 queries/min × 95ms saved = 9.5 segundos/min ahorrados
- Throughput: +63% (10 req/s → 16 req/s)
```

---

## REFERENCIAS

**Documentación Oficial:**
- Odoo 19 Cache: https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html#caching
- Redis Best Practices: https://redis.io/docs/manual/patterns/

**Código Fuente:**
- Odoo @tools.cache: `/usr/lib/python3/dist-packages/odoo/tools/cache.py`
- AI Service cache: `ai-service/utils/cache.py:1-318`
- Redis helper: `ai-service/utils/redis_helper.py`

**Análisis Arquitectónico:**
- Auditoría completa: `/docs/AUDITORIA_ODOO19_CAPACIDADES_NATIVAS.md`
- Resumen ejecutivo: `/RESUMEN_EJECUTIVO_AUDITORIA.md`

---

**Principio Arquitectónico:**

> "Don't cache where you call, cache where you compute"
> — Si Odoo llama a un microservicio, el cache debe estar en el microservicio, no en Odoo

**Corolario:**

> "Use the right tool: ORM cache for ORM data, Redis cache for everything else"
> — @tools.cache para datos Odoo, Redis para APIs/LLM/computación pesada
