# Prompt P4-Deep: Auditoría Arquitectónica Profunda de Módulo Odoo 19 CE

**Versión:** 1.0.0  
**Nivel:** P4-Deep (Auditoría Arquitectónica / Tech Debt Assessment)  
**Target Output:** 1,200-1,500 palabras (±15% si justificas)  
**Tiempo estimado:** 5-10 minutos generación

---

## 📋 Objetivo

Realizar análisis arquitectónico profundo del módulo **[MODULE_NAME]** de EERGYGROUP (Odoo 19 CE) con evidencia verificable, recomendaciones priorizadas P0/P1/P2 y roadmap técnico listo para ejecución.

---

## 🔄 Reglas de Progreso (Preamble Obligatorio)

### ⭐ PASO 0: SELF-REFLECTION (Pre-análisis obligatorio)

**Antes de analizar, reflexiona sobre:**

1. **Información faltante:**
   - ¿Tengo acceso a todos los archivos críticos del módulo?
   - ¿Conozco las dependencias externas completas?
   - ¿Hay documentación (CHANGELOG, migration guides) que deba leer primero?

2. **Suposiciones peligrosas:**
   - ¿Estoy asumiendo que el código sigue patrones estándar Odoo/FastAPI?
   - ¿Estoy asumiendo que tests existen y cubren casos críticos?
   - ¿Estoy asumiendo versiones de dependencias vs confirmar?

3. **Riesgos potenciales:**
   - ¿Qué pasa si hay código legacy no documentado?
   - ¿Qué pasa si las métricas LOC son incorrectas?
   - ¿Qué pasa si hay código crítico en paths no estándar?

4. **Verificaciones previas necesarias:**
   - ¿Debo verificar estructura de directorios primero?
   - ¿Debo confirmar versiones de frameworks antes de analizar?
   - ¿Debo leer tests existentes para entender cobertura real?

**Output esperado:** Lista verificaciones previas + plan mitigación de riesgos

---

### Progreso Estándar

1. **Reformula el objetivo** en 1-2 líneas (confirma comprensión)
2. **Plan de 5-7 pasos** con estructura "Paso i/N: [descripción]"
3. **Anuncia cada paso** al comenzar: "Ejecutando Paso i/N..."
4. **Cierra cada paso** con resumen: "Completado Paso i/N: [logros clave con métricas]"
5. **Cierre final** con:
   - Cobertura de dimensiones (A-J) vs requisitos
   - Métricas cumplidas (refs ≥30, verificaciones ≥6, palabras 1,200-1,500)
   - Roadmap priorizado (P0→P1→P2 con estimaciones)
   - Próximos pasos y dependencias críticas

---

## 📊 Contexto del Módulo (Tabla + Rutas)

### Tabla de Métricas

| Métrica | Valor |
|---------|-------|
| **Módulo** | [MODULE_NAME] (ej: l10n_cl_dte, l10n_cl_hr_payroll, ai-service) |
| **Stack** | Odoo 19 CE + Python 3.11 + PostgreSQL 16 + Redis 7 |
| **Archivos Python** | [NUM_FILES] archivos |
| **LOC total** | [TOTAL_LOC] líneas |
| **Archivo principal** | [MAIN_FILE] ([MAIN_LOC] LOC) |
| **Tests unitarios** | [NUM_TESTS] tests |
| **Coverage** | [COVERAGE]% (estimado o medido) |
| **Dependencias** | [NUM_DEPS] packages (requirements.txt o __manifest__.py) |
| **Endpoints/Models** | [NUM_ENDPOINTS] endpoints FastAPI o [NUM_MODELS] modelos Odoo |
| **Integraciones externas** | [INTEGRATIONS] (SII, Previred, Claude API, etc.) |
| **Deployment** | Docker Compose ([NUM_SERVICES] servicios) |

### Contexto Cuantificado Denso

**Optimizaciones conocidas:**
- [OPTIMIZATION_1]: [METRIC] (ej: "Prompt caching: 90% cost reduction")
- [OPTIMIZATION_2]: [METRIC] (ej: "Redis Sentinel HA: 3 sentinels + 2 replicas")
- [OPTIMIZATION_3]: [METRIC] (ej: "Circuit breaker: 5 failure threshold, 60s timeout")

**Arquitectura:**
- [ARCHITECTURE_PATTERN_1] (ej: "Multi-agente con plugin selection")
- [ARCHITECTURE_PATTERN_2] (ej: "Herencia Odoo con mixins")
- [ARCHITECTURE_PATTERN_3] (ej: "Streaming SSE para responses")

**Deuda técnica visible:**
- [TECH_DEBT_1] (ej: "main.py monolítico: 2,016 LOC")
- [TECH_DEBT_2] (ej: "Gaps testing: payroll/, sii_monitor/ sin tests")
- [TECH_DEBT_3] (ej: "Dependencias: httpx<0.28 por starlette 0.27")

### Rutas Clave a Analizar (Concretas)

```
addons/localization/[MODULE_NAME]/  # O ai-service/ si es microservicio
├── models/                          # O clients/ para microservicio
│   ├── [main_model].py ([NUM_LINES] LOC)
│   ├── [secondary_model_1].py
│   └── [secondary_model_2].py
├── views/                           # O routes/ para FastAPI
│   └── [views].xml
├── security/                        # O middleware/ para FastAPI
│   ├── ir.model.access.csv
│   └── ir_rule.xml (record rules)
├── data/                            # O config/ para microservicio
│   └── [master_data].xml
├── wizards/                         # O utils/ para microservicio
│   └── [wizard].py
├── reports/                         # O reports/ para ambos
│   └── [report].py
├── tests/
│   ├── test_[module].py ([NUM_TESTS] tests)
│   └── conftest.py (fixtures)
├── libs/                            # Si usa pure Python validators
│   └── [validator].py
└── __manifest__.py                  # O requirements.txt + Dockerfile
```

**Archivos foco obligatorios (≥15 referencias esperadas):**
- `[MAIN_MODEL_PATH]` (modelo/cliente principal)
- `[INTEGRATION_PATH_1]` (integración externa 1)
- `[INTEGRATION_PATH_2]` (integración externa 2)
- `[SECURITY_PATH]` (ir.model.access.csv o middleware/auth.py)
- `[TEST_PATH_1]` (test unitario principal)
- `[TEST_PATH_2]` (test integración)
- `[CONFIG_PATH]` (__manifest__.py o config/settings.py)
- `[UTILS_PATH]` (utils/ o libs/)

---

## 🎯 Dimensiones de Evaluación (A-J) con Granularidad

Analiza TODAS estas dimensiones con sub-bullets detallados:

### A) Arquitectura y Modularidad

**Sub-dimensiones:**
- **Separación de responsabilidades:** routes/models/services (FastAPI) vs models/views/controllers (Odoo)
- **Patrones de diseño:** Herencia (`_inherit`, mixins), Singleton, Factory, Dependency Injection
- **Acoplamiento:** Dependencias entre módulos, imports circulares
- **Cohesión:** Archivos con >1,000 LOC (monolitos identificados con `ruta.py:línea`)
- **Extensibilidad:** Puntos de extensión (hooks, decorators, abstract methods)

**Evidencia esperada:**
- Referencias: ≥5 archivos con análisis LOC
- Snippets: ≥2 ejemplos de patrones (buenos o malos)

---

### B) Patrones de Diseño Odoo/FastAPI

**Sub-dimensiones:**
- **Decorators Odoo:** `@api.depends`, `@api.constrains`, `@api.onchange` (uso correcto)
- **Computed fields:** Store=True justificado, dependencias explícitas
- **ORM vs Raw SQL:** Uso de ORM, prefetch para evitar N+1
- **FastAPI patterns:** Dependency injection, lifespan events, background tasks
- **Async/await:** Uso correcto de async functions, event loop

**Evidencia esperada:**
- Referencias: ≥4 archivos con decorators/patterns
- Trade-offs: ≥1 evaluado (store=True vs computed on-the-fly)

---

### C) Integraciones Externas

**Sub-dimensiones:**
- **APIs externas:** SII SOAP, Previred scraping, Claude API, Odoo XML-RPC
- **Autenticación:** API keys (NO hardcoded), tokens, OAuth
- **Manejo de errores:** Reintentos (exponential backoff), circuit breaker, fallbacks
- **Timeouts:** Configurados en todas las llamadas externas
- **Validación responses:** Schema validation (Pydantic, xmlschema)
- **Logging de integraciones:** Trazabilidad de requests/responses (sin PII)

**Evidencia esperada:**
- Referencias: ≥4 archivos de integración
- Verificaciones: ≥2 (timeout configurado, circuit breaker activo)

---

### D) Seguridad Multicapa

**Sub-dimensiones:**
- **Gestión de secretos:** Environment variables, ir.config_parameter, NO hardcoded
- **Input validation:** Pydantic validators, Odoo fields constraints
- **SQL injection:** Uso de ORM, parámetros seguros en raw SQL
- **XSS:** Sanitización en views (`t-out` en Odoo 19, no `t-esc`)
- **CORS:** Configurado restrictivamente (orígenes permitidos)
- **Rate limiting:** Por API key, por IP, por endpoint
- **Permisos Odoo:** ir.model.access.csv, record rules, groups
- **Dockerfile:** Non-root user, minimal base image, CVE scanning

**Evidencia esperada:**
- Referencias: ≥5 archivos (security/, middleware/, config/)
- Verificaciones: ≥2 P0 (secrets, SQL injection)

---

### E) Observabilidad

**Sub-dimensiones:**
- **Logging:** Structured (structlog JSON), niveles de severidad correctos
- **Métricas:** Prometheus /metrics, custom metrics relevantes
- **Health checks:** /health, /ready, /live (FastAPI) o controllers Odoo
- **Tracing distribuido:** OpenTelemetry, APM (Datadog, New Relic) - ¿presente?
- **Error tracking:** Sentry, custom error middleware
- **Performance monitoring:** Query timing, slow queries alertas

**Evidencia esperada:**
- Referencias: ≥3 archivos (middleware/observability.py, logs/, metrics/)
- Gaps: ≥1 identificado (ej: "MISSING: distributed tracing")

---

### F) Testing y Cobertura

**Sub-dimensiones:**
- **Coverage actual:** % líneas cubiertas (medido con pytest --cov)
- **Gaps identificados:** Módulos sin tests (listar rutas específicas)
- **Test types:** Unit, integration, e2e (markers pytest)
- **Fixtures:** Reutilización, setup/teardown correcto
- **Mocks:** AsyncMock para async, mock integraciones externas
- **Edge cases:** Tests de errores, límites, casos negativos
- **Performance tests:** Load testing, stress testing (si crítico)

**Evidencia esperada:**
- Referencias: ≥4 archivos (test_*.py, conftest.py)
- Verificaciones: ≥1 (ejecutar pytest y reportar coverage)

---

### G) Performance y Escalabilidad

**Sub-dimensiones:**
- **N+1 queries:** Identificar con QueryCounter, proponer prefetch
- **Caching:** Redis usage, cache invalidation strategy
- **Database indexes:** Campos frecuentemente buscados indexados
- **Batch processing:** Operaciones masivas optimizadas
- **SPOF (Single Points of Failure):** Redis master, LLM API, database
- **Degradación graceful:** Fallbacks cuando servicios caen
- **Autoscaling:** Configurado en Docker Compose o K8s (si aplica)
- **Latencia:** Mediciones, presupuestos de latencia

**Evidencia esperada:**
- Referencias: ≥3 archivos (models/, utils/cache.py, docker-compose.yml)
- Métricas: ≥2 cuantificadas (latencia Redis, threshold circuit breaker)

---

### H) Dependencias y Deuda Técnica

**Sub-dimensiones:**
- **Dependencias críticas:** versions pinned, CVE scanning
- **Versiones desactualizadas:** Identificar packages obsoletos
- **Conflictos de versión:** Constraints transitorias (ej: httpx<0.28)
- **Security advisories:** CVEs conocidos en dependencies
- **Deuda técnica cuantificada:** TODOs en código, FIXMEs, HACKs
- **Code complexity:** Cyclomatic complexity, archivos >1,000 LOC
- **Duplicación de código:** DRY violations

**Evidencia esperada:**
- Referencias: ≥3 archivos (requirements.txt, __manifest__.py, main.py)
- Verificaciones: ≥1 (scan CVEs con safety o pip-audit)

---

### I) Configuración y Deployment

**Sub-dimensiones:**
- **Settings management:** Pydantic Settings, environment variables, secrets
- **Config validation:** Startup validation, fail-fast si config inválida
- **Docker Compose:** Multi-service, networks, volumes, health checks
- **Environment separation:** dev/staging/prod configs
- **Secrets management:** .env files (gitignored), Docker secrets, Vault
- **Load balancing:** Nginx, HAProxy (si aplica)
- **Disaster recovery:** Backups automatizados, restore procedure
- **CI/CD:** GitHub Actions, tests en pipeline

**Evidencia esperada:**
- Referencias: ≥4 archivos (config/, docker-compose.yml, Dockerfile, .env.example)
- Gaps: ≥1 (ej: "MISSING: autoscaling config, DR plan")

---

### J) Errores y Mejoras Críticas

**Sub-dimensiones:**
- **Bugs conocidos:** TODO comments, GitHub issues, error logs
- **Mejoras P0:** Seguridad crítica, data loss risk
- **Mejoras P1:** Performance blockers, availability issues
- **Mejoras P2:** Code quality, developer experience
- **Refactoring necesario:** Archivos monolíticos, god classes
- **Breaking changes:** Odoo 19 deprecations (t-esc→t-out, type='json'→'jsonrpc')

**Evidencia esperada:**
- Referencias: ≥3 archivos con TODOs/FIXMEs
- Recomendaciones: ≥3 priorizadas (1 P0 + 2 P1)

---

## 📏 Requisitos de Salida (OBLIGATORIO)

### Formato

- **Longitud:** 1,200-1,500 palabras (±15% solo si justificas)
- **Referencias válidas:** ≥30 con formato `ruta.py:línea[-línea]`
  - Cobertura ≥30% de archivos clave (~15 de 50 archivos típicos)
  - Ejemplo: `ai-service/clients/anthropic_client.py:145-150`
- **Estructura:** Markdown con headers H2 (##) por dimensión (A-J)
- **Sub-secciones:** H3 (###) para sub-dimensiones dentro de cada área

### Verificaciones Reproducibles (≥6)

**OBLIGATORIO:** ≥1 verificación por área A-F (mínimo 6 total), clasificadas:
- **≥1 verificación P0** (crítica: seguridad, data loss, compliance crítico)
- **≥2 verificación P1** (alta: performance, availability, compliance medio)
- **≥3 verificación P2** (media: code quality, mantenibilidad)

**Formato de verificación:**

```markdown
### Verificación V{N}: [Título] (P0/P1/P2)

**Área:** [A-J]

**Comando:**
```bash
[comando reproducible con parámetros exactos]
```

**Hallazgo esperado:**
[Output esperado si todo está correcto - específico]

**Problema si falla:**
[Impacto técnico y de negocio - justifica P0/P1/P2]

**Cómo corregir:**
[Pasos específicos para resolver - comandos/código]

**Esfuerzo estimado:**
[Horas de desarrollo + testing]
```

### Datos NO VERIFICADOS (Gestión de Incertidumbre)

Si encuentras datos inciertos:

1. **Marca como [NO VERIFICADO]** o **[NO VERIFICADO, CONFIANZA: BAJA/MEDIA/ALTA]**
2. **Explica cómo verificar** (comando/métrica/log específico)
3. **Proporciona rango probable** con justificación técnica

**Ejemplo:**

```markdown
"86% test coverage" **[NO VERIFICADO, CONFIANZA: MEDIA]**

**Estimación basada en:**
- 51 tests identificados en test_anthropic_client.py (25) + test_chat_engine.py (26)
- Módulos clave: anthropic_client.py (483 LOC) + chat_engine.py (718 LOC) ≈ 60% codebase crítico

**Probable range:** 75-90%
- Optimista (90%): Si tests cubren todos los happy paths + edge cases
- Pesimista (75%): Si faltan tests de error handling y edge cases

**Verificar con:**
```bash
pytest ai-service/tests/ --cov=ai-service --cov-report=term-missing
```

**Output esperado:**
```
TOTAL    1500    150    90%
```
```

### Recomendaciones Estructuradas (Template Obligatorio)

Cada recomendación DEBE seguir este template:

```markdown
### Recomendación R{N}: [Título breve y accionable] (P0/P1/P2)

**Prioridad:** P0/P1/P2  
**Área:** [A-J]  
**Esfuerzo estimado:** [X horas desarrollo + Y horas testing]

**Problema:**
[1-2 líneas del anti-pattern identificado con referencia específica `ruta.py:línea`]

**Solución propuesta:**
```python
# ANTES (anti-pattern en ruta/archivo.py:línea-línea)
[código actual problemático - snippet real del proyecto]

# DESPUÉS (propuesta mejorada)
[código refactorizado con best practices]

# Justificación técnica
[Por qué este approach es mejor - pattern aplicado]
```

**Impacto esperado:**
- **Métrica cuantificable:** [Testability +300%, Latency -50ms, etc.]
- **Riesgo mitigado:** [Thread-safety, SQL injection, etc.]
- **Esfuerzo:** [Horas desarrollo + testing]
- **Trade-off:** [Ninguno | Complejidad +X | Performance -Y]

**Validación:**
```bash
[Comando para verificar que la mejora funcionó]
```

**Dependencies:**
[Si requiere otras mejoras antes - R{M}, R{K}]
```

---

## 🚫 Restricciones

- **Solo lectura:** No modificar archivos del proyecto
- **Sin secretos:** No exponer API keys, passwords, tokens reales
- **Sin llamadas externas reales:** Mockear SII, Previred, Claude API
- **Evidencia verificable:** Toda afirmación crítica requiere verificación reproducible
- **Foco en arquitectura:** No auditar lógica de negocio específica (ej: cálculo AFP)

---

## ✅ Checklist de Aceptación (Auto-Validación)

Antes de entregar, verifica:

**Formato (obligatorio):**
- [ ] Progreso visible (plan 5-7 pasos + "Paso i/N" + cierres con métricas)
- [ ] Cobertura A-J completa con evidencias
- [ ] ≥30 referencias válidas (`ruta.py:línea`)
- [ ] ≥6 verificaciones reproducibles (≥1 por A-F, clasificadas P0/P1/P2)
- [ ] Riesgos P0/P1/P2 justificados técnicamente
- [ ] Recomendaciones con template completo (Problema, Solución, Impacto, Validación)
- [ ] Resumen ejecutivo ≤200 palabras
- [ ] Roadmap priorizado (P0→P1→P2 con estimaciones)

**Profundidad (calidad técnica):**
- [ ] Términos técnicos: ≥80 (arquitectura, patrones, CVEs, compliance)
- [ ] Snippets de código: ≥15 (código real del proyecto)
- [ ] Trade-offs evaluados: ≥3 (pros/contras explícitos)
- [ ] Tablas comparativas: ≥5 (antes/después, opción A vs B, métricas)
- [ ] Anti-patterns identificados: ≥3 (con evidencia file:line + solución)
- [ ] Best practices reconocidas: ≥5 (aplicadas correctamente con justificación)
- [ ] Especificidad: ≥0.85 (calculado con analyze_response.py)
- [ ] Diagramas/Esquemas: ≥1 (ASCII art o descripción estructural detallada)
- [ ] Métricas cuantitativas: ≥10 números específicos (LOC, coverage, latency, etc.)

---

## 🎓 Ejemplo de Output Esperado (Estructura)

```markdown
# Auditoría Arquitectónica Profunda: [MODULE_NAME]

## Objetivo Reformulado
[1-2 líneas confirmando entendimiento con scope específico]

## Plan de Ejecución (5-7 pasos)
Paso 1/7: Análisis de arquitectura y patrones de diseño
Paso 2/7: Evaluación de integraciones externas y resiliencia
Paso 3/7: Auditoría de seguridad multicapa
...

---

## Ejecutando Paso 1/7: Arquitectura y Patrones

### A) Arquitectura y Modularidad

**Separación de responsabilidades:**
- `ai-service/main.py:1-2016` (2,016 LOC) - MONOLITO CRÍTICO
- Mezc routes + business logic + orchestration
- RECOMENDACIÓN: Separar en main.py (50 LOC) + routes/ (300) + services/ (1,666)

[... análisis detallado con 5+ referencias específicas ...]

### B) Patrones de Diseño

**Singleton anti-pattern detectado:**
```python
# ai-service/main.py:145-150
_orchestrator = None  # Global mutable state ❌
def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator
```

**Trade-off evaluado:**
| Opción | Pros | Contras | Recomendación |
|--------|------|---------|---------------|
| Singleton global | Simple (5 LOC) | Not testable, thread-unsafe | ❌ Evitar |
| Dependency Injection | Testable, thread-safe | Más verboso (20 LOC) | ✅ Implementar |

[... análisis detallado ...]

**Completado Paso 1/7:** Identificadas 5 mejoras arquitectura (1 P0, 2 P1, 2 P2). 8 referencias específicas analizadas.

---

## Ejecutando Paso 2/7: Integraciones Externas

### C) Integraciones Externas

**Claude API Client:**
- `ai-service/clients/anthropic_client.py:80-120` - Circuit breaker ✅
- `ai-service/clients/anthropic_client.py:145-160` - Caching 90% ✅
- `ai-service/clients/anthropic_client.py:200-220` - Token pre-counting ✅

**GAPS identificados:**
- ❌ Timeout NO configurado en `ai-service/clients/anthropic_client.py:85`
- ❌ Retry sin exponential backoff en `ai-service/clients/anthropic_client.py:105`

### Verificación V1: Timeout en Cliente Claude (P1)

**Área:** C (Integraciones)

**Comando:**
```bash
grep -n "timeout=" ai-service/clients/anthropic_client.py
```

**Hallazgo esperado:** 
```
85:    timeout=30.0,  # 30 seconds default
```

**Problema si falla:**
Requests sin timeout pueden colgar indefinidamente, bloqueando workers.
Impacto: Availability degradada, workers agotados.

**Cómo corregir:**
```python
# ai-service/clients/anthropic_client.py:85
async def call_api(self, ...):
    async with httpx.AsyncClient(timeout=30.0) as client:  # ✅ Añadir
        ...
```

**Esfuerzo estimado:** 1 hora desarrollo + 1 hora testing

[... análisis detallado ...]

**Completado Paso 2/7:** Identificadas 3 mejoras integraciones (0 P0, 2 P1, 1 P2). 6 referencias analizadas.

---

## Recomendaciones Priorizadas (Roadmap)

### P0: Critical (Merge Blockers)

### Recomendación R1: Eliminar Hardcoded API Keys (P0)

**Prioridad:** P0  
**Área:** D (Seguridad)  
**Esfuerzo estimado:** 2 horas desarrollo + 1 hora testing

**Problema:**
API key hardcoded en `ai-service/config/settings.py:15` expuesta en repo público.

**Solución propuesta:**
```python
# ANTES (ai-service/config/settings.py:15)
ANTHROPIC_API_KEY = "sk-ant-api03-xxx"  # ❌ HARDCODED

# DESPUÉS (propuesta con environment variable)
import os
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    anthropic_api_key: str = Field(..., env="ANTHROPIC_API_KEY")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# .env (gitignored)
ANTHROPIC_API_KEY=sk-ant-api03-xxx
```

**Impacto esperado:**
- **Métrica:** Security risk eliminado (OWASP A02:2021 - Cryptographic Failures)
- **Riesgo mitigado:** Exposición de credenciales en GitHub
- **Esfuerzo:** 2h desarrollo + 1h testing = 3h total
- **Trade-off:** Ninguno (best practice obligatoria)

**Validación:**
```bash
# Verificar que no hay secrets hardcoded
grep -rn "sk-ant-api" ai-service/ --exclude-dir=tests
# Output esperado: vacío (0 matches)
```

**Dependencies:** Ninguna

---

### P1: High Priority (Sprint Actual)

### Recomendación R2: Refactorizar main.py Monolítico (P1)
[... detalles con template completo ...]

### Recomendación R3: Añadir Timeouts en Integraciones (P1)
[... detalles ...]

---

### P2: Medium Priority (Próximo Sprint)

### Recomendación R4: Implementar Distributed Tracing (P2)
[... detalles ...]

---

## Resumen Ejecutivo (≤200 palabras)

**Hallazgos clave:**
- 1 riesgo P0 crítico (API keys hardcoded - 3h fix)
- 4 mejoras P1 bloqueantes (monolito 2K LOC, timeouts, testing gaps - 18h total)
- 6 mejoras P2 técnicas (tracing, autoscaling, refactoring - 32h total)

**Métricas de calidad actual:**
- Coverage: 86% estimado (51 tests, gaps en payroll/)
- LOC crítico: main.py 2,016 (riesgo mantenibilidad)
- Dependencias: 26 packages (httpx<0.28 constraint activo)
- Integraciones: 5 externas (Claude, SII, Previred, Odoo, Slack)

**Fortalezas identificadas:**
- Circuit breaker bien implementado (5 failure threshold)
- Caching optimizado (90% cost reduction validado)
- Redis Sentinel HA configurado (3 sentinels + 2 replicas)

**Roadmap recomendado:**
1. **Semana 1:** Fix P0 (3h) + P1 críticos R2-R3 (12h) = 15h
2. **Semana 2-3:** P1 restantes R4-R5 (18h)
3. **Semana 4+:** P2 mejoras técnicas (32h)

---

## Cobertura vs Requisitos

**Dimensiones analizadas:** A-J (100% ✅)
- A) Arquitectura: 8 referencias, 2 anti-patterns, 1 trade-off
- B) Patrones diseño: 5 referencias, 1 refactoring propuesto
- C) Integraciones: 6 referencias, 2 gaps P1
- D) Seguridad: 7 referencias, 1 P0 crítico
- E) Observabilidad: 4 referencias, 1 gap (tracing)
- F) Testing: 5 referencias, coverage 86%
- G) Performance: 4 referencias, latency Redis <100ms
- H) Dependencias: 3 referencias, 1 constraint activo
- I) Config: 5 referencias, gaps autoscaling/DR
- J) Mejoras: 10 recomendaciones (1 P0 + 4 P1 + 5 P2)

**Métricas cumplidas:**
- Referencias: 47 válidas (target: ≥30) ✅
- Verificaciones: 8 (2 P0 + 3 P1 + 3 P2, target: ≥6) ✅
- Términos técnicos: 92 (target: ≥80) ✅
- Snippets código: 18 (target: ≥15) ✅
- Tablas: 7 (target: ≥5) ✅
- Palabras: 1,420 (target: 1,200-1,500) ✅
- Especificidad: 0.89 (target: ≥0.85) ✅

**Próximos pasos y dependencias:**
1. **Inmediato:** Ejecutar verificaciones V1-V8 para validar hallazgos
2. **Semana 1:** Fix R1 (P0) - bloqueante para merge
3. **Semana 2-3:** Implementar R2-R5 (P1) - mejoras críticas
4. **Sprint siguiente:** Evaluar R6-R10 (P2) - roadmap técnico

**Dependencies críticas:**
- R2 (refactor main.py) debe completarse antes de R4 (tracing) y R7 (autoscaling)
- R3 (timeouts) es prerequisito para R8 (circuit breaker improvements)
```

---

## 🚀 Cómo Usar este Prompt

### Personalizar Contexto

1. **Reemplazar placeholders en tabla:**
   ```bash
   [MODULE_NAME] → l10n_cl_dte
   [NUM_FILES] → 28 archivos
   [TOTAL_LOC] → 4,500 líneas
   [MAIN_FILE] → models/account_move.py
   [MAIN_LOC] → 1,200
   [NUM_TESTS] → 35 tests
   [COVERAGE] → 78% medido
   [NUM_DEPS] → 8 packages
   [NUM_MODELS] → 6 modelos
   [INTEGRATIONS] → SII SOAP webservices, xmlsec signatures
   [NUM_SERVICES] → 10 (Docker Compose)
   ```

2. **Actualizar contexto cuantificado:**
   - Optimizaciones conocidas (métricas reales)
   - Patrones arquitectónicos (descripción técnica)
   - Deuda técnica visible (LOC, gaps)

3. **Ajustar rutas clave:**
   - Listar archivos específicos a profundidad
   - Incluir integraciones externas críticas
   - Especificar archivos de testing

### Ejecutar con Copilot CLI

```bash
# Preparar prompt personalizado
cat templates/prompt_p4_deep_template.md | \
  sed 's/\[MODULE_NAME\]/l10n_cl_dte/g' | \
  sed 's/\[NUM_FILES\]/28/g' | \
  sed 's/\[TOTAL_LOC\]/4500/g' \
  > /tmp/prompt_dte_deep.md

# Ejecutar análisis profundo
copilot -p "$(cat /tmp/prompt_dte_deep.md)" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_dte_deep_$(date +%Y%m%d_%H%M%S).md
```

### Validar Output

```bash
# Medir métricas automáticamente
.venv/bin/python3 experimentos/analysis/analyze_response.py \
  experimentos/outputs/audit_dte_deep_*.md \
  audit_dte_deep \
  P4-Deep

# Verificar checklist manualmente
cat templates/checklist_calidad_p4.md
```

---

## 📖 Referencias

- **Estrategia completa:** `docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`
- **Checklist validación:** `docs/prompts_desarrollo/templates/checklist_calidad_p4.md`
- **Template P4-Lite:** `docs/prompts_desarrollo/templates/prompt_p4_lite_template.md`
- **Feedback metodológico:** `experimentos/FEEDBACK_AGENTE_MEJORADOR_PROMPTS.txt`
- **Experimento P1→P4:** `experimentos/RESUMEN_EJECUTIVO_P4_2.md`

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-11  
**Mantenedor:** Pedro Troncoso (@pwills85)
