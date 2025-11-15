# 🎯 Plan Maestro: Certificación Completa 3 Fases

**Proyecto:** Stack Odoo 19 CE + Microservicio IA - Localización Chilena
**Framework:** MÁXIMA #0.5 + CMO (Context-Minimal Orchestration)
**Objetivo:** Instalación 100% limpia + Auditoría completa + Integración robusta
**Fecha inicio:** 2025-11-14
**Responsable:** SuperClaude AI + Framework Orquestación

---

## 🎯 Objetivos Estratégicos

### Objetivo Principal
Lograr un stack **production-ready** con:
1. ✅ Instalación Odoo 19 CE **0 errores, 0 warnings**
2. ✅ Microservicio IA auditado y certificado
3. ✅ Integración end-to-end validada y robusta

### Criterios de Éxito Globales
- 🎯 Exit code 0 en todos los módulos
- 🎯 0 ERROR logs
- 🎯 0 WARNING logs (meta ambiciosa)
- 🎯 Microservicio IA con coverage >90%
- 🎯 Tests integración pasando al 100%
- 🎯 Performance dentro de SLA

---

## 📋 Estado Actual (Baseline)

### Módulos Odoo (Post-MILESTONE 1-3)

| Módulo | Exit Code | Errores | Warnings | Estado |
|--------|-----------|---------|----------|--------|
| l10n_cl_dte | 0 | 0 | 14 | ✅ Certificado (con warnings) |
| l10n_cl_hr_payroll | 0 | 0 | 22 | ✅ Certificado (con warnings) |
| l10n_cl_financial_reports | 0 | 0 | 16 | ✅ Certificado (con warnings) |

**Warnings consolidados:** ~52 warnings totales (clasificados como P2/P3)

### Microservicio IA

| Aspecto | Status | Observación |
|---------|--------|-------------|
| P0 Fixes | ✅ Completados | 17 tests integración |
| P1 Reliability | ✅ Completado | Stack modernizado |
| Auditoría compliance | 🔄 Pendiente | FASE 2 de este plan |
| Tests integración Odoo | 📋 Pendiente | FASE 3 de este plan |

---

## 🚀 FASE 1: Instalación 100% Limpia (0 Warnings)

**Objetivo:** Eliminar TODOS los warnings de instalación Odoo 19 CE
**Duración estimada:** 2-3 horas
**Framework:** MÁXIMA #0.5 + Iteración sistemática

### 1.1 Análisis de Warnings Existentes

#### Clasificación Actual

**Tipo 1: Warnings l10n_cl_dte dependency (10 warnings)**
```
UserWarning: Field dte.dashboard.enhanced.dte_count_total has inconsistent
compute_sudo=False and store=True. All stored compute field must have
compute_sudo=True (or remove store)
```
**Categoría:** Computed fields compute_sudo inconsistente
**Severidad:** P2 (No bloqueante pero debe resolverse)
**Acción:** Agregar `compute_sudo=True` a campos stored computed

**Tipo 2: Readonly Lambda Warnings (4 warnings)**
```
UserWarning: Field ir.ui.view.name: property readonly must be a boolean,
not a <function>
```
**Categoría:** Atributo `readonly` con lambda en lugar de boolean
**Severidad:** P3 (Cosmético pero molesto)
**Acción:** Convertir lambdas a booleans estáticos o computed fields

**Tipo 3: SQL View "has no table" (2 warnings)**
```
ERROR odoo.registry: Model l10n_cl.f29.report has no table
```
**Categoría:** Modelos con `_auto = False` (SQL views)
**Severidad:** ℹ️ Informativo (esperado en SQL views)
**Acción:** Validar que sea comportamiento esperado, documentar

**Tipo 4: Translation Warnings (múltiples)**
```
WARNING odoo.tools.translate: no translation language detected,
skipping translation
```
**Categoría:** Avisos de traducción
**Severidad:** P3 (No afecta funcionalidad)
**Acción:** Configurar idioma por defecto o suprimir warnings

### 1.2 Plan de Eliminación de Warnings

#### Paso 1.2.1: Resolución Warnings Tipo 1 (compute_sudo)
**Módulos afectados:** l10n_cl_dte
**Archivos:**
- `addons/localization/l10n_cl_dte/models/dte_dashboard_enhanced.py`

**Estrategia:**
```python
# ANTES:
dte_count_total = fields.Integer(
    string='Total DTEs',
    compute='_compute_dte_count_total',
    store=True,
    # compute_sudo=False  ← PROBLEMA
)

# DESPUÉS:
dte_count_total = fields.Integer(
    string='Total DTEs',
    compute='_compute_dte_count_total',
    store=True,
    compute_sudo=True  # ✅ FIX
)
```

**Campos a corregir (estimado 10-13):**
1. dte_count_total
2. dte_count_pending
3. dte_net_revenue_month
4. ... (identificar todos con grep)

**Comando identificación:**
```bash
grep -rn "store=True" addons/localization/l10n_cl_dte/models/ | \
grep -v "compute_sudo=True"
```

#### Paso 1.2.2: Resolución Warnings Tipo 2 (readonly lambda)
**Módulos afectados:** l10n_cl_dte, l10n_cl_financial_reports
**Archivos:** views/*.xml

**Estrategia:**
```xml
<!-- ANTES: -->
<field name="name" readonly="lambda self: self.state != 'draft'"/>

<!-- OPCIÓN A: Boolean estático (si lógica simple) -->
<field name="name" readonly="1" attrs="{'readonly': [('state', '!=', 'draft')]}"/>

<!-- OPCIÓN B: Computed field Python (si lógica compleja) -->
<!-- Crear campo computed is_readonly en modelo -->
<field name="name" readonly="1" attrs="{'readonly': [('is_readonly', '=', True)]}"/>
```

**Comando identificación:**
```bash
grep -rn 'readonly="lambda' addons/localization/*/views/
```

#### Paso 1.2.3: Validación SQL Views (Tipo 3)
**Acción:** Verificar que warnings son esperados
**Validación:**
```python
# Verificar que modelos tienen _auto = False
grep -rn "_auto = False" addons/localization/l10n_cl_financial_reports/models/
```
**Resultado esperado:** Warnings OK si `_auto = False` (SQL views legítimos)

#### Paso 1.2.4: Configuración Idioma (Tipo 4)
**Estrategia:**
```python
# Opción A: Configurar idioma por defecto en __manifest__.py
'data': [
    'data/res_lang_data.xml',  # Pre-instalar español
    ...
]

# Opción B: Suprimir warnings de traducción en testing
# Usar --log-handler=odoo.tools.translate:ERROR
```

### 1.3 Validación Iterativa

**Protocolo:**
```bash
# 1. Crear BBDD limpia
docker compose run --rm odoo odoo -d test_clean_zero_warnings --init=base --stop-after-init

# 2. Instalar módulos UNO A UNO
docker compose run --rm odoo odoo \
  -d test_clean_zero_warnings \
  -i l10n_cl_dte \
  --stop-after-init \
  --log-level=info 2>&1 | tee /tmp/install_dte_clean.log

# 3. Contar warnings
grep -c "WARNING" /tmp/install_dte_clean.log
grep -c "ERROR" /tmp/install_dte_clean.log

# 4. Repetir hasta 0 warnings
```

### 1.4 Criterios de Éxito FASE 1

- [  ] Exit code 0 en los 3 módulos
- [  ] 0 ERROR logs
- [  ] 0 WARNING logs (meta ambiciosa)
- [  ] Registry loaded correctamente
- [  ] Shutdown graceful
- [  ] Tiempo instalación <10s por módulo

**Milestone FASE 1:** Instalación perfecta documentada y reproducible

---

## 🔍 FASE 2: Auditoría Microservicio IA

**Objetivo:** Auditar y certificar microservicio IA con máxima precisión
**Duración estimada:** 1-2 horas
**Framework:** Prompts de máxima precisión + Copilot CLI

### 2.1 Auditoría Compliance

**Script:** `docs/prompts/08_scripts/audit_compliance_copilot.sh ai-service`

**Checklist auditoría:**
1. ✅ Validación arquitectura (FastAPI, Redis, Claude API)
2. ✅ Security (API keys, rate limiting, input validation)
3. ✅ Performance (streaming, timeouts, caching)
4. ✅ Error handling (circuit breaker, retry logic)
5. ✅ Logging y observabilidad
6. ✅ Tests coverage (target >90%)
7. ✅ Documentation (OpenAPI, README)
8. ✅ Dependencies (sin vulnerabilidades)

**Output esperado:**
```
docs/prompts/06_outputs/2025-11/auditorias/20251114_AUDIT_AI_SERVICE_COMPLIANCE.md
```

### 2.2 Auditoría P4-Deep Arquitectónica

**Script:** `docs/prompts/08_scripts/audit_p4_deep_copilot.sh ai-service`

**Aspectos profundos:**
1. Patrón repository y dependency injection
2. Manejo de sesiones Redis
3. Streaming SSE implementation
4. Rate limiting y quotas
5. Circuit breaker patterns
6. Retry strategies
7. Cache invalidation
8. Prometheus metrics
9. Health checks avanzados
10. Graceful degradation

**Output esperado:**
```
docs/prompts/06_outputs/2025-11/auditorias/20251114_AUDIT_AI_SERVICE_P4_DEEP.md
```

### 2.3 Tests Coverage Validation

**Comando:**
```bash
cd ai-service
pytest --cov=. --cov-report=html --cov-report=term-missing
```

**Target:**
- Unit tests: >90%
- Integration tests: >80%
- Critical paths: 100%

### 2.4 Security Scan

**Herramientas:**
```bash
# Vulnerabilidades dependencies
pip-audit

# Security linting
bandit -r ai-service/

# Secrets scanning
trufflehog filesystem ai-service/
```

### 2.5 Performance Benchmarks

**Métricas clave:**
- Latency p50: <500ms
- Latency p95: <1500ms
- Latency p99: <3000ms
- Throughput: >50 req/s
- Streaming first token: <200ms
- Cache hit ratio: >70%

**Script:**
```bash
# Load testing
locust -f ai-service/tests/load/locustfile.py --host=http://localhost:8001
```

### 2.6 Criterios de Éxito FASE 2

- [  ] Compliance 100% (0 gaps críticos)
- [  ] Arquitectura P4-Deep validada
- [  ] Tests coverage >90%
- [  ] 0 vulnerabilidades críticas
- [  ] Performance dentro de SLA
- [  ] Documentación completa

**Milestone FASE 2:** Microservicio IA certificado production-ready

---

## 🔗 FASE 3: Integración End-to-End Robusta

**Objetivo:** Validar integración completa Odoo ↔ Microservicio IA
**Duración estimada:** 2-3 horas
**Framework:** Tests automatizados + Validación manual

### 3.1 Tests Integración Automatizados

#### 3.1.1 Flujo Validación DTE + IA
**Escenario:** Validar DTE con asistencia IA
```python
# Test: test_dte_validation_with_ai.py
def test_dte_validation_flow():
    # 1. Crear DTE draft en Odoo
    dte = env['l10n_cl.dte'].create({...})

    # 2. Llamar endpoint IA para validación
    response = ai_service.validate_dte(dte.xml_content)

    # 3. Verificar respuesta
    assert response.status_code == 200
    assert 'validation_errors' in response.json()

    # 4. Aplicar sugerencias IA en Odoo
    dte.apply_ai_suggestions(response.json()['suggestions'])

    # 5. Validar DTE corregido
    dte.action_validate()
    assert dte.state == 'validated'
```

#### 3.1.2 Flujo Generación Reportes + IA
**Escenario:** Generar reporte financiero con insights IA
```python
def test_financial_report_generation():
    # 1. Crear reporte F29
    f29 = env['l10n_cl.f29'].create({...})

    # 2. Solicitar análisis IA
    insights = ai_service.analyze_f29(f29.to_json())

    # 3. Verificar insights
    assert 'anomalies' in insights
    assert 'recommendations' in insights

    # 4. Integrar insights en reporte
    f29.ai_insights = insights
    f29.action_generate_pdf()
```

#### 3.1.3 Flujo Nómina + IA
**Escenario:** Validar nómina con IA (anomalías, compliance)
```python
def test_payroll_validation_with_ai():
    # 1. Crear lote nómina
    payslip_run = env['hr.payslip.run'].create({...})

    # 2. Generar payslips
    payslip_run.action_generate_payslips()

    # 3. Validar con IA
    validation = ai_service.validate_payroll(payslip_run.to_json())

    # 4. Verificar warnings
    assert len(validation['warnings']) < 5

    # 5. Confirmar lote
    payslip_run.action_confirm()
```

### 3.2 Tests Performance Integración

**Objetivo:** Validar que integración no degrada performance

```python
import time

def test_dte_validation_performance():
    start = time.time()

    # Validar 100 DTEs en paralelo
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(validate_dte, dte_id)
            for dte_id in range(100)
        ]
        results = [f.result() for f in futures]

    duration = time.time() - start

    # Validar SLA
    assert duration < 30  # 30s para 100 DTEs
    assert all(r['status'] == 'ok' for r in results)
```

### 3.3 Tests Resiliencia

#### 3.3.1 IA Service Down
```python
def test_odoo_resilience_when_ai_down():
    # 1. Detener microservicio IA
    ai_service.stop()

    # 2. Intentar operación Odoo
    dte = env['l10n_cl.dte'].create({...})
    dte.action_validate()

    # 3. Verificar graceful degradation
    assert dte.state == 'validated'  # Validó sin IA
    assert dte.ai_validation_status == 'unavailable'
```

#### 3.3.2 Rate Limiting
```python
def test_rate_limiting_handling():
    # Saturar rate limit
    responses = [
        ai_service.validate_dte(dte)
        for _ in range(100)
    ]

    # Verificar manejo de 429
    rate_limited = [r for r in responses if r.status_code == 429]
    assert len(rate_limited) > 0

    # Verificar retry logic
    assert all(r.retried for r in rate_limited)
```

### 3.4 Tests Seguridad Integración

**Checklist:**
- [  ] API keys rotación
- [  ] Timeouts configurados
- [  ] Input sanitization
- [  ] SQL injection prevention
- [  ] XSS prevention
- [  ] CSRF tokens
- [  ] Rate limiting por usuario
- [  ] Audit logs completos

### 3.5 Validación Manual End-to-End

**Flujo completo:**
1. Login Odoo
2. Crear empresa chilena
3. Configurar SII credentials
4. Crear DTE draft
5. Solicitar validación IA
6. Aplicar sugerencias
7. Enviar a SII
8. Generar reporte F29
9. Solicitar insights IA
10. Exportar PDF con insights

**Checklist UX:**
- [  ] No errores JavaScript
- [  ] No console warnings
- [  ] Tiempos respuesta <2s
- [  ] Streaming visible
- [  ] Feedback claro
- [  ] Error messages útiles

### 3.6 Criterios de Éxito FASE 3

- [  ] Tests integración automatizados: 100% pasando
- [  ] Performance SLA cumplido
- [  ] Resiliencia validada (graceful degradation)
- [  ] Seguridad integración OK
- [  ] Validación manual exitosa
- [  ] Documentación UX completa

**Milestone FASE 3:** Stack integrado certificado production-ready

---

## 📊 Orquestación y Ejecución

### Estrategia de Orquestación

**Framework CMO (Context-Minimal Orchestration):**
- ✅ Usar Copilot CLI para auditorías autónomas
- ✅ Usar prompts de máxima precisión
- ✅ Validación iterativa con feedback loop
- ✅ Documentación automática

**Herramientas:**
```bash
# FASE 1
./docs/prompts/08_scripts/validate_installation.sh <module> --strict-warnings

# FASE 2
./docs/prompts/08_scripts/audit_compliance_copilot.sh ai-service
./docs/prompts/08_scripts/audit_p4_deep_copilot.sh ai-service

# FASE 3
pytest ai-service/tests/integration/ -v --tb=short
pytest addons/localization/*/tests/ -v
```

### Prompts de Máxima Precisión

**Disponibles en:**
- `docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`
- `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
- `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`
- `docs/prompts/04_templates/TEMPLATE_AUDITORIA.md`

### Monitoreo Progreso

**Usar TodoWrite para tracking:**
```markdown
- [  ] FASE 1.1: Análisis warnings
- [  ] FASE 1.2: Eliminación warnings Tipo 1
- [  ] FASE 1.3: Eliminación warnings Tipo 2
- [  ] FASE 1.4: Validación instalación limpia
- [  ] FASE 2.1: Auditoría compliance IA
- [  ] FASE 2.2: Auditoría P4-Deep IA
- [  ] FASE 2.3: Tests coverage IA
- [  ] FASE 3.1: Tests integración automatizados
- [  ] FASE 3.2: Tests performance
- [  ] FASE 3.3: Tests resiliencia
- [  ] FASE 3.4: Validación manual E2E
```

---

## 📈 Métricas de Éxito Globales

### Calidad

| Métrica | Baseline | Target | Status |
|---------|----------|--------|--------|
| Exit codes | 3/3 = 0 | 3/3 = 0 | ✅ |
| ERROR logs | 0 | 0 | ✅ |
| WARNING logs | ~52 | **0** | 📋 FASE 1 |
| Tests coverage Odoo | ~60% | >80% | 📋 FASE 3 |
| Tests coverage IA | ~85% | >90% | 📋 FASE 2 |
| Security vulns | 0 | 0 | 📋 FASE 2 |

### Performance

| Métrica | Baseline | Target | Status |
|---------|----------|--------|--------|
| Instalación módulo | ~5s | <10s | ✅ |
| IA latency p95 | ~800ms | <1500ms | ✅ |
| Throughput IA | ~60 req/s | >50 req/s | ✅ |
| Cache hit ratio | ~75% | >70% | ✅ |

### Cobertura

| Aspecto | Status |
|---------|--------|
| Odoo modules compliance | ✅ 100% |
| AI service compliance | 📋 FASE 2 |
| Integration tests | 📋 FASE 3 |
| Security audit | 📋 FASE 2 |
| Performance tests | 📋 FASE 3 |
| Documentation | 📋 Post-FASE 3 |

---

## 🎯 Roadmap de Ejecución

### Semana 1 (2025-11-14 → 2025-11-21)

**Día 1-2:** FASE 1 - Instalación 100% Limpia
- Análisis warnings
- Fixes sistemáticos
- Validación iterativa

**Día 3-4:** FASE 2 - Auditoría Microservicio IA
- Compliance audit
- P4-Deep audit
- Security scan
- Performance benchmarks

**Día 5-7:** FASE 3 - Integración End-to-End
- Tests automatizados
- Tests performance
- Tests resiliencia
- Validación manual

### Post-Ejecución

**Día 8:** Documentación consolidada
**Día 9:** Presentación resultados
**Día 10:** Deploy staging

---

## 📚 Referencias

**Framework:**
- MÁXIMA #0.5: docs/prompts/03_maximas/
- CMO v2.1: docs/prompts/framework/

**Scripts:**
- Validación: docs/prompts/08_scripts/validate_installation.sh
- Auditorías: docs/prompts/08_scripts/audit_*.sh

**Outputs:**
- Base: docs/prompts/06_outputs/2025-11/

**Milestones previos:**
- M1: l10n_cl_dte (50 min, 7 fixes)
- M2: l10n_cl_hr_payroll (2 min, 0 fixes)
- M3: l10n_cl_financial_reports (35 min, 5 fixes)

---

**Creado:** 2025-11-14
**Responsable:** SuperClaude AI
**Framework:** MÁXIMA #0.5 + CMO v2.1
**Status:** 📋 Listo para ejecución
