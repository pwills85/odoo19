# 🔬 ANÁLISIS COBERTURA AUDITORÍA - Ingeniero Senior vs Templates Actuales

**Fecha:** 2025-11-12
**Objetivo:** Comparar cobertura de templates P3-P4 contra dominios que auditaría un ingeniero senior
**Status:** 🔍 ANÁLISIS CRÍTICO + GAPS IDENTIFICADOS

---

## 📋 TEMPLATES ANALIZADOS

### 1. TEMPLATE_P4_DEEP_ANALYSIS.md (P4 - 1500 palabras)

**Dominios Cubiertos:**
1. ✅ **Compliance Odoo 19 CE** (8 patrones deprecación P0/P1/P2)
2. ✅ **Arquitectura y Patrones** (estructura, diseño, dependencias, acoplamiento)
3. ✅ **Seguridad OWASP Top 10** (SQL injection, XSS, access control, input validation)
4. ✅ **Performance** (N+1 queries, indexación, caching)
5. ✅ **Testing** (cobertura, calidad tests, edge cases)

**Métricas Cuantitativas:**
- Cyclomatic Complexity
- Test Coverage %
- Security Score
- Performance Score
- Compliance Score

---

### 2. TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md (P4 - 1200 palabras)

**Dominios Cubiertos:**
1. ✅ **Docker Compose Audit** (configuración servicios, networking, secrets)
2. ✅ **PostgreSQL Audit** (performance, tuning, backups, recovery)
3. ✅ **Redis Audit** (configuración, persistencia, backup)
4. ✅ **Seguridad Infraestructura** (secrets scanning, CVE scanning, permisos)
5. ✅ **Monitoring y Observabilidad** (logs, métricas, alertas)

**Deliverables:**
- Infrastructure Score Card
- Runbook Operacional (startup, shutdown, backup, recovery, troubleshooting)

---

### 3. TEMPLATE_AUDITORIA.md (P3 - 500 palabras)

**Dominios Cubiertos:**
1. ✅ **Compliance Odoo 19 CE** (P0/P1 validaciones)
2. ✅ **Código y Arquitectura** (re-implementaciones, herencias, convenciones)
3. ✅ **Funcionalidad y Conformidad Legal** (cálculos, normativa, vistas)
4. ✅ **Rendimiento y Seguridad** (queries, permisos, vulnerabilidades)
5. ✅ **Testing** (cobertura, robustez)

---

## 🎯 DOMINIOS INGENIERO SENIOR DE DESARROLLO

### Clasificación por Categorías

#### CATEGORÍA A: Código y Arquitectura

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 1 | **Compliance Framework** | P4 Deep + P3 Audit | ✅ 100% | Excelente (8 patrones Odoo 19) |
| 2 | **Arquitectura y Diseño** | P4 Deep | ✅ 90% | Falta: Event-Driven, Message Queues |
| 3 | **Patrones de Diseño** | P4 Deep | ✅ 85% | Falta: CQRS, Saga patterns |
| 4 | **Code Quality** | P4 Deep | ✅ 95% | Excelente (complexity, maintainability) |
| 5 | **Refactoring Opportunities** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 6 | **Technical Debt** | - | ⚠️ 20% | Parcial (mencionado, no medido) |

**Subtotal Categoría A:** 65% cobertura

---

#### CATEGORÍA B: Seguridad

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 7 | **OWASP Top 10** | P4 Deep | ✅ 95% | Excelente (SQL, XSS, Access Control) |
| 8 | **Authentication & Authorization** | P4 Deep | ✅ 80% | Falta: OAuth, JWT, 2FA |
| 9 | **Data Encryption** | P4 Infra | ⚠️ 40% | Falta: at-rest, in-transit, key mgmt |
| 10 | **Secrets Management** | P4 Infra | ✅ 90% | Bien (secrets scanning, env vars) |
| 11 | **API Security** | - | ⚠️ 30% | Parcial (HTTP controllers, no REST API) |
| 12 | **CVE & Vulnerability Scanning** | P4 Infra | ✅ 85% | Bien (CVE scanning Docker images) |
| 13 | **Compliance Legal (GDPR, SOC2)** | - | ❌ 0% | **CRÍTICO: NO cubierto** |

**Subtotal Categoría B:** 60% cobertura

---

#### CATEGORÍA C: Performance y Escalabilidad

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 14 | **Database Performance** | P4 Deep + P4 Infra | ✅ 95% | Excelente (N+1, indexes, tuning) |
| 15 | **Caching Strategy** | P4 Deep + P4 Infra | ✅ 90% | Bien (Redis, application cache) |
| 16 | **Load Testing** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 17 | **Scalability Limits** | - | ⚠️ 20% | Falta: horizontal scaling, sharding |
| 18 | **Resource Optimization** | P4 Infra | ✅ 85% | Bien (memory, CPU, I/O) |
| 19 | **CDN & Asset Optimization** | - | ❌ 0% | Falta: static assets, compression |

**Subtotal Categoría C:** 48% cobertura

---

#### CATEGORÍA D: Testing y QA

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 20 | **Unit Testing** | P4 Deep | ✅ 90% | Bien (cobertura, calidad) |
| 21 | **Integration Testing** | P4 Deep | ⚠️ 50% | Parcial (mencionado, no exhaustivo) |
| 22 | **E2E Testing** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 23 | **Performance Testing** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 24 | **Security Testing** | P4 Deep | ✅ 80% | Bien (OWASP, validaciones) |
| 25 | **Regression Testing** | - | ⚠️ 30% | Falta: estrategia automated |
| 26 | **Test Data Management** | - | ❌ 0% | Falta: fixtures, mocks, factories |

**Subtotal Categoría D:** 36% cobertura

---

#### CATEGORÍA E: Infraestructura y DevOps

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 27 | **Docker & Containers** | P4 Infra | ✅ 95% | Excelente (config, networking, secrets) |
| 28 | **Database Management** | P4 Infra | ✅ 95% | Excelente (PostgreSQL tuning, backups) |
| 29 | **CI/CD Pipeline** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 30 | **Deployment Strategy** | P4 Infra | ⚠️ 40% | Parcial (startup/shutdown, no blue-green) |
| 31 | **Disaster Recovery** | P4 Infra | ✅ 85% | Bien (backups, recovery procedures) |
| 32 | **Infrastructure as Code** | - | ❌ 0% | Falta: Terraform, Ansible, versioning |

**Subtotal Categoría E:** 53% cobertura

---

#### CATEGORÍA F: Observabilidad y Monitoring

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 33 | **Logging Strategy** | P4 Infra | ✅ 85% | Bien (logs analysis, levels) |
| 34 | **Metrics & Dashboards** | P4 Infra | ✅ 80% | Bien (métricas, Prometheus) |
| 35 | **Alerting** | P4 Infra | ✅ 75% | Bien (alerting strategy) |
| 36 | **Tracing Distribuido** | - | ❌ 0% | Falta: OpenTelemetry, Jaeger |
| 37 | **Error Tracking** | - | ⚠️ 30% | Parcial (logs, no Sentry/Rollbar) |
| 38 | **APM (Application Performance Monitoring)** | - | ❌ 0% | Falta: New Relic, DataDog |

**Subtotal Categoría F:** 45% cobertura

---

#### CATEGORÍA G: API y Integraciones

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 39 | **API Design (REST/GraphQL)** | - | ⚠️ 25% | Parcial (HTTP controllers, no REST) |
| 40 | **API Versioning** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 41 | **API Documentation** | - | ❌ 0% | Falta: OpenAPI/Swagger |
| 42 | **Rate Limiting & Throttling** | - | ❌ 0% | Falta: protección abuse |
| 43 | **Webhooks** | - | ❌ 0% | Falta: estrategia webhooks |
| 44 | **External Integrations** | P3 Audit | ⚠️ 40% | Parcial (SII, Previred mencionado) |

**Subtotal Categoría G:** 11% cobertura

---

#### CATEGORÍA H: UX/UI y Accesibilidad

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 45 | **UX/UI Review** | P3 Audit | ⚠️ 30% | Parcial (vistas mencionadas) |
| 46 | **Accessibility (a11y)** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 47 | **Responsive Design** | - | ❌ 0% | Falta: mobile, tablet |
| 48 | **Performance UX (TTFB, FCP, LCP)** | - | ❌ 0% | Falta: Core Web Vitals |
| 49 | **Error Messages & User Feedback** | - | ⚠️ 20% | Falta: UX error handling |

**Subtotal Categoría H:** 10% cobertura

---

#### CATEGORÍA I: Documentación y Mantenibilidad

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 50 | **Code Documentation** | - | ⚠️ 30% | Falta: docstrings, comments |
| 51 | **API Documentation** | - | ❌ 0% | Falta: OpenAPI, Postman |
| 52 | **Architecture Documentation** | - | ⚠️ 25% | Parcial (análisis, no docs) |
| 53 | **Runbooks & SOPs** | P4 Infra | ✅ 90% | Excelente (runbook operacional) |
| 54 | **README & Onboarding** | - | ❌ 0% | Falta: developer onboarding |
| 55 | **Changelog & Release Notes** | - | ❌ 0% | Falta: versioning docs |

**Subtotal Categoría I:** 24% cobertura

---

#### CATEGORÍA J: Data y Migraciones

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 56 | **Data Modeling** | P4 Deep | ✅ 80% | Bien (modelos ORM) |
| 57 | **Database Migrations** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 58 | **Data Validation** | P4 Deep | ✅ 85% | Bien (input validation, constraints) |
| 59 | **Data Backup & Recovery** | P4 Infra | ✅ 90% | Excelente (PostgreSQL backups) |
| 60 | **Data Privacy (PII)** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 61 | **Data Retention Policies** | - | ❌ 0% | Falta: GDPR, cleanup |

**Subtotal Categoría J:** 43% cobertura

---

#### CATEGORÍA K: Resiliencia y Error Handling

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 62 | **Error Handling Strategy** | - | ⚠️ 30% | Parcial (validaciones, no estrategia) |
| 63 | **Retry Logic & Circuit Breakers** | - | ❌ 0% | Falta: resilience patterns |
| 64 | **Graceful Degradation** | - | ❌ 0% | Falta: fallback strategies |
| 65 | **Idempotency** | - | ❌ 0% | Falta: HTTP endpoints, jobs |
| 66 | **Timeout Management** | - | ❌ 0% | Falta: timeouts config |

**Subtotal Categoría K:** 6% cobertura

---

#### CATEGORÍA L: Internacionalización y Localización

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 67 | **i18n (Internationalization)** | - | ⚠️ 30% | Parcial (Chile específico) |
| 68 | **l10n (Localization)** | P3 Audit | ✅ 85% | Bien (normativa chilena) |
| 69 | **Multi-currency** | - | ❌ 0% | Falta: si aplica |
| 70 | **Timezone Handling** | - | ❌ 0% | Falta: UTC, conversions |

**Subtotal Categoría L:** 29% cobertura

---

#### CATEGORÍA M: Licenciamiento y Legal

| # | Dominio | Template Actual | Cobertura | Gap |
|---|---------|----------------|-----------|-----|
| 71 | **License Compliance** | - | ❌ 0% | **CRÍTICO: NO cubierto** |
| 72 | **Open Source Licenses** | - | ❌ 0% | Falta: dependency licenses |
| 73 | **Legal Requirements (Chile)** | P3 Audit | ✅ 90% | Excelente (SII, Previred, DT) |
| 74 | **Terms of Service** | - | ❌ 0% | Falta: si aplica |

**Subtotal Categoría M:** 23% cobertura

---

## 📊 RESUMEN POR CATEGORÍA

| Categoría | Dominios | Cobertura | Rating | Gap Crítico |
|-----------|----------|-----------|--------|-------------|
| **A. Código y Arquitectura** | 6 | 65% | ⭐⭐⭐ | Refactoring, Tech Debt |
| **B. Seguridad** | 7 | 60% | ⭐⭐⭐ | Compliance Legal (GDPR) |
| **C. Performance** | 6 | 48% | ⭐⭐ | Load Testing, Scalability |
| **D. Testing y QA** | 7 | 36% | ⭐⭐ | E2E, Performance, Test Data |
| **E. Infraestructura** | 6 | 53% | ⭐⭐⭐ | CI/CD, IaC |
| **F. Observabilidad** | 6 | 45% | ⭐⭐ | Tracing, APM |
| **G. API e Integraciones** | 6 | 11% | ⭐ | **MUY BAJO** |
| **H. UX/UI** | 5 | 10% | ⭐ | **MUY BAJO** |
| **I. Documentación** | 6 | 24% | ⭐ | **BAJO** |
| **J. Data y Migraciones** | 6 | 43% | ⭐⭐ | Migrations, Privacy |
| **K. Resiliencia** | 5 | 6% | ⭐ | **MUY BAJO** |
| **L. i18n/l10n** | 4 | 29% | ⭐⭐ | i18n, Timezones |
| **M. Legal** | 4 | 23% | ⭐⭐ | Licenses |

---

## 🎯 COBERTURA GLOBAL

**Total dominios evaluados:** 74 dominios
**Dominios cubiertos (≥80%):** 18 dominios (24%)
**Dominios parciales (30-79%):** 19 dominios (26%)
**Dominios NO cubiertos (<30%):** 37 dominios (50%)

### Score Global: **37% cobertura**

---

## 🚨 GAPS CRÍTICOS IDENTIFICADOS (TOP 15)

### P0 - Crítico (Impacto Alto, No Cubierto)

| # | Dominio Faltante | Impacto | Categoría | Template Propuesto |
|---|------------------|---------|-----------|-------------------|
| 1 | **CI/CD Pipeline** | 🔴 Alto | Infraestructura | TEMPLATE_P4_CICD_AUDIT.md |
| 2 | **E2E Testing** | 🔴 Alto | Testing | TEMPLATE_P4_DEEP_ANALYSIS.md (extender) |
| 3 | **Load Testing** | 🔴 Alto | Performance | TEMPLATE_P4_PERFORMANCE_STRESS.md |
| 4 | **API Versioning** | 🔴 Alto | API | TEMPLATE_P4_API_AUDIT.md |
| 5 | **Database Migrations** | 🔴 Alto | Data | TEMPLATE_P4_DATA_MIGRATIONS.md |
| 6 | **License Compliance** | 🔴 Alto | Legal | TEMPLATE_P3_LEGAL_COMPLIANCE.md |
| 7 | **Data Privacy (PII/GDPR)** | 🔴 Alto | Seguridad | TEMPLATE_P4_DATA_PRIVACY.md |

---

### P1 - Alta Prioridad (Impacto Medio, Parcial)

| # | Dominio Faltante | Impacto | Categoría | Acción |
|---|------------------|---------|-----------|--------|
| 8 | **Accessibility (a11y)** | 🟡 Medio | UX/UI | TEMPLATE_P3_UX_A11Y_AUDIT.md |
| 9 | **Error Handling Strategy** | 🟡 Medio | Resiliencia | TEMPLATE_P4_DEEP_ANALYSIS.md (extender) |
| 10 | **API Documentation** | 🟡 Medio | Documentación | TEMPLATE_P3_API_DOCS_AUDIT.md |
| 11 | **Infrastructure as Code** | 🟡 Medio | DevOps | TEMPLATE_P4_INFRA_AUDIT.md (extender) |
| 12 | **Tracing Distribuido** | 🟡 Medio | Observabilidad | TEMPLATE_P4_OBSERVABILITY.md |
| 13 | **Refactoring Opportunities** | 🟡 Medio | Code Quality | TEMPLATE_REFACTORING.md (ya propuesto) |
| 14 | **Test Data Management** | 🟡 Medio | Testing | TEMPLATE_P3_TEST_DATA_MGMT.md |
| 15 | **Technical Debt Tracking** | 🟡 Medio | Arquitectura | TEMPLATE_P3_TECH_DEBT_AUDIT.md |

---

## 💡 RECOMENDACIONES

### OPCIÓN 1: Extender Templates Existentes (Rápido - 2 semanas)

**Prioridad:** Ampliar templates P4 actuales para cubrir gaps P0

**Plan:**

1. **TEMPLATE_P4_DEEP_ANALYSIS.md** (ampliar +600 palabras):
   - ✅ Agregar sección: E2E Testing
   - ✅ Agregar sección: Error Handling & Resiliencia
   - ✅ Agregar sección: API Design & Versioning
   - ✅ Agregar sección: Refactoring Opportunities
   - ✅ Agregar sección: Technical Debt Measurement

2. **TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md** (ampliar +400 palabras):
   - ✅ Agregar sección: CI/CD Pipeline Audit
   - ✅ Agregar sección: Infrastructure as Code (IaC)
   - ✅ Agregar sección: Deployment Strategy (Blue-Green, Canary)

3. **TEMPLATE_AUDITORIA.md** (ampliar +200 palabras):
   - ✅ Agregar sección: UX/UI Basic Review
   - ✅ Agregar sección: Documentation Status

**Resultado:** Cobertura 37% → **55%** (+18 puntos)

---

### OPCIÓN 2: Crear Templates Especializados (Completo - 6 semanas)

**Prioridad:** Nuevos templates para dominios críticos no cubiertos

**Plan:**

**Fase 1 - P0 (2 semanas):**
1. **TEMPLATE_P4_CICD_AUDIT.md** (800 palabras)
   - Pipeline stages (build, test, deploy)
   - Automated testing en CI
   - Security scanning (SAST, DAST)
   - Artifact management
   - Deployment rollback strategy

2. **TEMPLATE_P4_API_AUDIT.md** (700 palabras)
   - REST API design (endpoints, HTTP verbs, status codes)
   - API versioning strategy
   - OpenAPI/Swagger documentation
   - Rate limiting & throttling
   - Authentication & authorization (OAuth, JWT)
   - Webhooks strategy

3. **TEMPLATE_P4_DATA_PRIVACY.md** (600 palabras)
   - PII identification
   - GDPR compliance (right to delete, data portability)
   - Data encryption (at-rest, in-transit)
   - Data retention policies
   - Audit logs (who accessed what)

**Fase 2 - P1 (2 semanas):**
4. **TEMPLATE_P3_PERFORMANCE_STRESS.md** (500 palabras)
   - Load testing scenarios
   - Stress testing (max capacity)
   - Scalability limits
   - Bottleneck identification

5. **TEMPLATE_P3_UX_A11Y_AUDIT.md** (500 palabras)
   - WCAG 2.1 compliance
   - Keyboard navigation
   - Screen reader compatibility
   - Color contrast
   - Responsive design (mobile, tablet)

**Fase 3 - P1 (2 semanas):**
6. **TEMPLATE_P4_OBSERVABILITY.md** (700 palabras)
   - Distributed tracing (OpenTelemetry)
   - APM integration (New Relic, DataDog)
   - Error tracking (Sentry, Rollbar)
   - Metrics dashboards (Grafana)

7. **TEMPLATE_P3_TECH_DEBT_AUDIT.md** (400 palabras)
   - Technical debt identification
   - Code smells detection
   - Refactoring priority matrix
   - Debt cost estimation

**Resultado:** Cobertura 37% → **72%** (+35 puntos)

---

### OPCIÓN 3: Sistema de Templates Modular (Óptimo - 8 semanas)

**Prioridad:** Sistema completo con templates base + módulos especializados

**Arquitectura:**

```
04_templates/
├── base/
│   ├── TEMPLATE_P4_DEEP_ANALYSIS.md (base existente)
│   ├── TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md (base existente)
│   └── TEMPLATE_AUDITORIA.md (base existente)
│
├── modules/
│   ├── MODULE_CICD.md (200 palabras)
│   ├── MODULE_API_DESIGN.md (150 palabras)
│   ├── MODULE_DATA_PRIVACY.md (180 palabras)
│   ├── MODULE_LOAD_TESTING.md (120 palabras)
│   ├── MODULE_A11Y.md (150 palabras)
│   ├── MODULE_OBSERVABILITY.md (200 palabras)
│   ├── MODULE_TECH_DEBT.md (100 palabras)
│   ├── MODULE_ERROR_HANDLING.md (120 palabras)
│   ├── MODULE_MIGRATIONS.md (150 palabras)
│   └── MODULE_LICENSES.md (100 palabras)
│
└── composite/
    ├── TEMPLATE_P4_FULL_AUDIT.md (base + todos los módulos)
    ├── TEMPLATE_P4_SECURITY_COMPLETE.md (base + módulos seguridad)
    └── TEMPLATE_P4_DEVOPS_COMPLETE.md (infra + CI/CD + observability)
```

**Ventajas:**
- ✅ Máxima flexibilidad (combinar módulos según necesidad)
- ✅ Evita duplicación (módulos reutilizables)
- ✅ Escalable (agregar módulos sin modificar base)
- ✅ Mantenimiento fácil (actualizar módulo independiente)

**Resultado:** Cobertura 37% → **85%** (+48 puntos)

---

## 🎯 RECOMENDACIÓN FINAL

### Para VB: **OPCIÓN 1 (Extender Templates Existentes)**

**Justificación:**
1. **Rápido:** 2 semanas vs 6-8 semanas
2. **ROI inmediato:** +18 puntos cobertura con esfuerzo mínimo
3. **No breaking:** No invalida templates actuales
4. **Evolutivo:** Base para Opción 2/3 después

**Plan Ejecución:**

**Semana 1:**
- [ ] Extender TEMPLATE_P4_DEEP_ANALYSIS.md (+600 palabras)
  - E2E Testing (150 palabras)
  - Error Handling & Resiliencia (150 palabras)
  - API Design & Versioning (120 palabras)
  - Refactoring Opportunities (100 palabras)
  - Technical Debt Measurement (80 palabras)

**Semana 2:**
- [ ] Extender TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md (+400 palabras)
  - CI/CD Pipeline Audit (200 palabras)
  - Infrastructure as Code (120 palabras)
  - Deployment Strategy (80 palabras)

- [ ] Extender TEMPLATE_AUDITORIA.md (+200 palabras)
  - UX/UI Basic Review (120 palabras)
  - Documentation Status (80 palabras)

**Resultado Final:**
- TEMPLATE_P4_DEEP_ANALYSIS.md: 1500 → **2100 palabras**
- TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md: 1200 → **1600 palabras**
- TEMPLATE_AUDITORIA.md: 500 → **700 palabras**
- **Cobertura total: 55%** (vs 37% actual)

---

## 📋 PRÓXIMOS PASOS

1. **Revisar este análisis** con el equipo
2. **Seleccionar opción** (1, 2 o 3)
3. **Priorizar dominios** (P0 primero)
4. **Asignar trabajo** (templates a extender/crear)
5. **Tracking progreso** (dashboard métricas)

---

**Versión:** 1.0.0
**Fecha:** 2025-11-12
**Mantenedor:** Pedro Troncoso (@pwills85)
**Status:** 🔍 ANÁLISIS COMPLETO - ESPERANDO APROBACIÓN
