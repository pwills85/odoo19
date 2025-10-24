# 📝 CHANGELOG

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

---

## [Unreleased]

### Planeado
- Tests Sprint E (Boletas de Honorarios)
- Automatización recepción BHE desde Portal MiSII
- Parser XML boletas de honorarios
- Generación certificado retención PDF
- Fast-Track Migration Plan (3 brechas P0)
- Circuit breaker para servicios externos
- Disaster recovery automático

---

## [0.10.0] - 2025-10-23

### 🎉 Highlights
- **Sprint C+D completado:** Boletas de Honorarios (Recepción) + Tasas Retención IUE
- **Migración Odoo 11 Ready:** Soporte datos históricos desde 2018
- **75% funcionalidad DTE alcanzada** (70% → 75%)

### ✨ Added

#### Sprint C Base - Modelos Python
- **Modelo `retencion_iue_tasa`** (402 líneas)
  - Tasas históricas de retención IUE 2018-2025 (10% → 14.5%)
  - Búsqueda automática de tasa vigente por fecha
  - Cálculo automático de retención
  - Wizard para crear tasas históricas Chile
  - Constraint: No solapamiento de períodos de vigencia

- **Modelo `boleta_honorarios`** (432 líneas)
  - Registro de BHE recibidas de profesionales independientes
  - Cálculo automático retención según tasa histórica vigente
  - Workflow: draft → validated → accounted → paid
  - Integración con facturas de proveedor (account.move)
  - Generación certificado de retención
  - Tracking completo con mail.thread + mail.activity.mixin
  - Smart buttons para navegación

#### Sprint D Complete - UI/UX
- **Data inicial:** `retencion_iue_tasa_data.xml` (7 tasas históricas)
- **Vistas Tasas:** Tree + Form + Search con color coding
- **Vistas Boletas:** Tree + Form + Search con workflow buttons
- **Seguridad:** 4 reglas ACL (user + manager)
- **Menús:** 2 nuevos menús integrados
  - DTE Chile > Operaciones > Boletas de Honorarios
  - DTE Chile > Configuración > Tasas de Retención IUE

### 🔧 Changed
- **Manifest actualizado:** 23 archivos registrados (data: 3, views: 16)
- **Descripción módulo:** Agregadas funcionalidades BHE + tasas históricas
- **Security:** Extendido ir.model.access.csv con 4 nuevas reglas

### 📚 Documentation
- `docs/GAP_CLOSURE_SPRINT_C_BASE.md` - 10KB (Modelos Python)
- `docs/GAP_CLOSURE_SPRINT_D_COMPLETE.md` - 12KB (UI/UX completa)
- README.md actualizado con Sprint C+D
- .claude/project/01_overview.md actualizado

### ✅ Validation
- 100% sintaxis XML válida (4 archivos)
- 100% sintaxis Python válida
- 0 errores críticos
- 0 warnings bloqueantes

### 🎯 Progress
- **DTE Module:** 70% → 75% (+5%)
- **Sprint C Base:** 70% funcionalidad (infraestructura)
- **Sprint D Complete:** 100% funcionalidad (UI/UX)
- **Total archivos:** 6 nuevos/modificados
- **Total líneas código:** ~850 líneas (Python + XML)

---

## [0.9.0] - 2025-10-23

### 🎉 Highlights
- **Reorganización completa de documentación** (87% menos archivos en raíz)
- **Sprint 3 completado:** Refactoring analytic accounts
- **Integración proyectos + IA** operativa al 100%

### ✨ Added

#### Documentación
- `START_HERE.md` - Punto de entrada claro para nuevos desarrolladores
- `TEAM_ONBOARDING.md` - Guía completa de onboarding (15 min)
- `QUICK_START.md` - Setup rápido del stack (5 min)
- `AI_AGENT_INSTRUCTIONS.md` - Instrucciones completas para agentes IA
- `CONTRIBUTING.md` - Guía para contribuir al proyecto
- `CHANGELOG.md` - Este archivo
- `docs/README.md` - Índice maestro de toda la documentación
- Estructura organizada en `/docs/` con 13 subdirectorios

#### Features
- **AI Service:** Sugerencia inteligente de proyectos con Claude 3.5 Sonnet
- **AI Service:** Análisis semántico de órdenes de compra
- **AI Service:** Monitoreo automático del portal SII
- **DTE Service:** Webhook asíncrono para actualización de estados
- **Odoo:** Integración automática proyecto + orden de compra
- **Odoo:** Dashboard de warnings y validaciones

#### Testing
- 60+ tests unitarios en DTE Service
- 80% code coverage alcanzado
- Tests de integración para AI Service
- Mocks completos para SII, Redis, RabbitMQ

### 🔧 Changed

#### Arquitectura
- Refactorización de analytic accounts para mejor integración
- Optimización de consultas a Claude API (reducción 40% latencia)
- Mejora en manejo de errores SII (59 códigos mapeados)

#### Performance
- p95 latency: 800ms → 450ms (44% mejora)
- Cache hit rate: 65% → 82%
- Throughput: +35% en generación DTEs

### 🐛 Fixed
- Corrección de warnings en módulo l10n_cl_dte
- Fix timeout en cliente SOAP SII
- Corrección validación RUT con dígito verificador K
- Fix race condition en webhook DTE
- Corrección encoding ISO-8859-1 en XMLs

### 📚 Documentation
- Reorganización de 70+ archivos .md en estructura `/docs/`
- Documentación de patrones de código
- Guías de troubleshooting
- Documentación de APIs (Swagger)

### 🔒 Security
- Implementación OAuth2 para webhooks
- Validación HMAC en callbacks
- Rate limiting en endpoints públicos
- Sanitización de inputs en todos los endpoints

---

## [0.8.0] - 2025-10-22

### ✨ Added

#### Sprint 2: Integración Proyectos + IA
- Integración completa entre purchase.order y project.project
- Cliente Claude API para análisis semántico
- Sistema de sugerencias inteligentes (confidence score)
- Training con datos históricos

#### DTE Service
- Generador DTE 34 (Liquidación Honorarios)
- Polling automático de estados SII (cada 15 min)
- Retry logic con exponential backoff
- Health checks en todos los endpoints

### 🔧 Changed
- Migración de Ollama local a Claude 3.5 Sonnet (cloud)
- Optimización de generadores XML (30% más rápido)
- Mejora en validaciones pre-envío SII

### 🐛 Fixed
- Fix error en firma digital con certificados SHA-256
- Corrección timezone Chile (UTC-3)
- Fix memory leak en polling SII

---

## [0.7.0] - 2025-10-15

### ✨ Added

#### Sprint 1: Testing + Security
- Suite completa de tests (pytest)
- Code coverage reporting (80%+)
- Security audit completo
- RBAC implementation en Odoo

#### DTE Service
- Generadores DTE 33, 61, 56, 52
- Cliente SOAP SII (Maullin sandbox)
- Firma digital XMLDSig
- Validación XSD schemas

### 🔧 Changed
- Refactorización de generadores DTE (Factory Pattern)
- Implementación de Singleton para cliente SII
- Logging estructurado con structlog

---

## [0.6.0] - 2025-10-08

### ✨ Added

#### Arquitectura Base
- Docker Compose stack completo
- PostgreSQL 15 con locale chileno
- Redis 7 para caching
- RabbitMQ 3.12 para message queue
- Odoo 19 CE base instalado

#### Módulos Odoo
- l10n_cl_dte (base) - Facturación electrónica
- Modelos base: account.move, res.partner, res.company
- Views básicas de configuración

#### Microservicios
- DTE Service (FastAPI) - Estructura base
- AI Service (FastAPI) - Estructura base
- Health checks
- Swagger documentation

### 📚 Documentation
- README.md inicial
- Documentación de arquitectura
- Guías de instalación

---

## [0.5.0] - 2025-10-01

### ✨ Added
- Análisis completo de Odoo 18 módulos chilenos
- Identificación de gaps Odoo 19
- Plan de implementación 8 semanas
- Roadmap completo del proyecto

### 📚 Documentation
- Análisis comparativo Odoo 18 vs 19
- Documentación de brechas identificadas
- Estrategias de implementación

---

## [0.1.0] - 2025-09-15

### ✨ Added
- Inicio del proyecto
- Definición de alcance
- Stack tecnológico seleccionado
- Equipo conformado

---

## Tipos de Cambios

- `Added` - Para nuevas funcionalidades
- `Changed` - Para cambios en funcionalidades existentes
- `Deprecated` - Para funcionalidades que serán removidas
- `Removed` - Para funcionalidades removidas
- `Fixed` - Para corrección de bugs
- `Security` - Para cambios relacionados con seguridad

---

## Versionado

Usamos [Semantic Versioning](https://semver.org/lang/es/):

- **MAJOR** (X.0.0): Cambios incompatibles en la API
- **MINOR** (0.X.0): Nueva funcionalidad compatible con versiones anteriores
- **PATCH** (0.0.X): Corrección de bugs compatible con versiones anteriores

---

**Mantenido por:** Ing. Pedro Troncoso Willz  
**Empresa:** EERGYGROUP  
**Última actualización:** 2025-10-23
