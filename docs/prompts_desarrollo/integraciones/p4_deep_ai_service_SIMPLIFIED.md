# Auditoría Arquitectónica P4-Deep: AI Microservice

**OBJETIVO:** Analizar arquitectura del microservicio AI (FastAPI + Claude API).

**OUTPUT REQUERIDO:**
- 1,200-1,500 palabras (máximo 1,500)
- ≥30 referencias código (`archivo.py:línea`)
- ≥6 verificaciones reproducibles
- 10 dimensiones (A-J)
- Prioridades P0/P1/P2

---

## ESTRUCTURA OBLIGATORIA

### PASO 1: RESUMEN EJECUTIVO (100-150 palabras)

Propósito, arquitectura, 3 hallazgos, score salud

### PASO 2: ANÁLISIS POR DIMENSIONES (800-1,000 palabras)

#### A) Arquitectura y Patrones
FastAPI routers, dependency injection

#### B) Integraciones y Dependencias
- Claude API (Anthropic SDK)
- Odoo (HTTP calls)
- Redis cache

#### C) Seguridad y Compliance
API keys, rate limiting, XSS/injection

#### D) Testing y Calidad
Unit tests, integration tests, coverage

#### E) Performance y Escalabilidad
Async operations, connection pooling, caching

#### F) Observabilidad y Debugging
Logging, tracing, health endpoints

#### G) Deployment y DevOps
Docker, docker-compose, CI/CD

#### H) Documentación y Mantenibilidad
OpenAPI, docstrings, README

#### I) CVEs y Dependencias Vulnerables
fastapi, anthropic, httpx versions

#### J) Roadmap y Deuda Técnica
Mejoras pendientes, quick wins

### PASO 3: VERIFICACIONES REPRODUCIBLES (≥6 comandos)

Formato:
```markdown
### Verificación V1: [Título] (P0/P1/P2)

**Comando:**
```bash
[comando]
```

**Hallazgo esperado:** [...]
**Problema si falla:** [...]
**Cómo corregir:** [...]
```

### PASO 4: RECOMENDACIONES PRIORIZADAS (300-400 palabras)

Tabla + detalles código ANTES/DESPUÉS

---

## CONTEXTO MICROSERVICIO

**Ubicación:** `ai-service/`

**Stack:**
- FastAPI 0.115.5
- Anthropic SDK 0.39.0
- Python 3.11.10
- Docker (linux/arm64)

**Estructura:**
```
ai-service/
├── app/
│   ├── main.py (200 LOC)
│   ├── engine.py (450 LOC - core logic)
│   ├── knowledge_base.py (300 LOC)
│   └── models.py (150 LOC - Pydantic schemas)
├── tests/ (unit + integration)
├── Dockerfile
└── requirements.txt
```

**Endpoints clave:**
- POST `/api/chat` - Chat interactivo
- POST `/api/analyze` - Análisis documentos
- GET `/health` - Healthcheck
- POST `/api/payroll/validate` - Validación nóminas
- POST `/api/dte/validate` - Validación DTE

**Integraciones:**
- Claude API: `claude-sonnet-4.5` (context 200K tokens)
- Odoo: HTTP calls para data sync
- Redis: Session cache (no implementado aún)

---

## REGLAS CRÍTICAS

1. File refs: `archivo.py:línea`
2. Comandos shell verificables
3. Prioridades P0/P1/P2 justificadas
4. Cuantifica: ms, tokens, %, LOC
5. Si no verificas: `[NO VERIFICADO]`

---

## EJEMPLO HALLAZGO

❌ **MAL:** "Hay problemas de seguridad"

✅ **BIEN:**
"**Timeouts no configurados** (`engine.py:125`)

```python
# engine.py:125
response = httpx.get(url)  # ❌ Sin timeout
```

**Verificación:**
```bash
grep -n "httpx.get\|httpx.post" ai-service/app/engine.py
```

**Impacto:** P1 - Requests pueden colgar indefinidamente
**Solución:**
```python
response = httpx.get(url, timeout=30.0)  # ✅ Timeout 30s
```"

---

**COMIENZA ANÁLISIS. MAX 1,500 PALABRAS.**
