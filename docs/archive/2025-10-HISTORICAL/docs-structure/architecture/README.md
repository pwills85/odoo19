# 🏗️ ARCHITECTURE - Arquitectura y Diseño

Este directorio contiene documentación de arquitectura técnica, diagramas y decisiones de diseño.

---

## 📚 Documentos Disponibles

### Arquitectura General
- **`REPORTE_ARQUITECTURA_GRAFICO_PROFESIONAL.md`** - Arquitectura completa con diagramas
- **`INTEGRATION_PATTERNS_API_EXAMPLES.md`** - Patrones de integración y ejemplos
- **`INTEGRACION_CLASE_MUNDIAL_ANALITICA_COMPRAS_IA.md`** - Integración proyectos + IA

### Architecture Decision Records (ADR)
- **`ADR/`** - Directorio para decisiones arquitectónicas documentadas

---

## 🎯 Arquitectura Three-Tier

```
┌─────────────────────────────────────────────────────────┐
│  TIER 1: PRESENTACIÓN                                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Odoo 19 CE (Puerto 8169)                         │  │
│  │  • UI/UX (Web Browser)                            │  │
│  │  • Business Logic                                 │  │
│  │  • ORM (Models, Views, Controllers)               │  │
│  │  • Módulos: l10n_cl_dte, l10n_cl_hr_payroll      │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         ↓ REST API
┌─────────────────────────────────────────────────────────┐
│  TIER 2: MICROSERVICIOS                                 │
│  ┌─────────────────────┐  ┌─────────────────────────┐  │
│  │  DTE Service        │  │  AI Service             │  │
│  │  (Puerto 8001)      │  │  (Puerto 8002)          │  │
│  │                     │  │                         │  │
│  │  • Generadores XML  │  │  • Claude 3.5 Sonnet   │  │
│  │  • Firma Digital    │  │  • Análisis Semántico  │  │
│  │  • Cliente SOAP SII │  │  • Monitoreo SII       │  │
│  │  • Validación XSD   │  │  • Sugerencias IA      │  │
│  │  • Polling Estados  │  │  • Training Histórico  │  │
│  └─────────────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  TIER 3: DATOS Y MENSAJERÍA                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │PostgreSQL│  │  Redis   │  │  RabbitMQ            │  │
│  │   15     │  │   7      │  │   3.12               │  │
│  │          │  │          │  │                      │  │
│  │• Data    │  │• Cache   │  │• Message Queue       │  │
│  │• Persist │  │• Session │  │• Async Processing    │  │
│  │• Locale  │  │• Temp    │  │• Event Bus           │  │
│  │  CL      │  │  Data    │  │• Webhooks            │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 🔑 Principios Arquitectónicos

### 1. Clean Architecture
- **Separación de responsabilidades**
  - Odoo: UI/UX + Business Logic
  - DTE Service: XML/Firma/SOAP
  - AI Service: IA/Analytics

### 2. Microservicios
- **Servicios independientes**
  - Deployable separadamente
  - Escalable horizontalmente
  - Fault isolation

### 3. API-First
- **REST APIs bien definidas**
  - Swagger documentation
  - Versionado de APIs
  - Rate limiting

### 4. Event-Driven
- **Comunicación asíncrona**
  - RabbitMQ para eventos
  - Webhooks para callbacks
  - Polling para estados SII

### 5. Security by Design
- **Seguridad en todas las capas**
  - OAuth2/OIDC
  - RBAC en Odoo
  - API Keys para microservicios
  - HTTPS en producción

---

## 📊 Patrones de Diseño Utilizados

### Creacionales
- **Factory Pattern** - Generadores DTE
- **Singleton Pattern** - Cliente SII, Cliente Claude
- **Builder Pattern** - Construcción de XMLs complejos

### Estructurales
- **Adapter Pattern** - Integración con APIs externas
- **Facade Pattern** - Simplificación de APIs complejas
- **Proxy Pattern** - Caching y rate limiting

### Comportamentales
- **Strategy Pattern** - Diferentes estrategias de validación
- **Observer Pattern** - Webhooks y eventos
- **Command Pattern** - Queue de comandos asíncronos

### Arquitectónicos
- **Repository Pattern** - Acceso a datos
- **Dependency Injection** - FastAPI
- **Circuit Breaker** - Protección servicios externos (planeado)

---

## 🔄 Flujos de Datos Principales

### Flujo 1: Emisión DTE
```
Usuario → Odoo → DTE Service → SII
                    ↓
                PostgreSQL
                    ↓
                RabbitMQ (polling)
                    ↓
                Webhook → Odoo
```

### Flujo 2: Sugerencia IA
```
Usuario → Odoo → AI Service → Claude API
                    ↓
                Redis (cache)
                    ↓
                Odoo (sugerencia)
```

### Flujo 3: Monitoreo SII
```
Cron → AI Service → SII Portal (scraping)
                    ↓
                Claude (análisis)
                    ↓
                Slack (notificación)
```

---

## 🛡️ Seguridad

### Capas de Seguridad

1. **Red**
   - Microservicios solo en red interna Docker
   - Solo Odoo expuesto (puerto 8169)
   - HTTPS en producción

2. **Autenticación**
   - OAuth2/OIDC para usuarios
   - API Keys para microservicios
   - JWT tokens para sesiones

3. **Autorización**
   - RBAC en Odoo (grupos y permisos)
   - Rate limiting en APIs
   - IP whitelisting (producción)

4. **Datos**
   - Certificados encriptados en DB
   - Secrets en variables de entorno
   - Logging sin datos sensibles

---

## 📈 Escalabilidad

### Horizontal Scaling
- **Odoo:** Múltiples workers
- **DTE Service:** Múltiples instancias
- **AI Service:** Múltiples instancias
- **PostgreSQL:** Read replicas
- **Redis:** Cluster mode

### Vertical Scaling
- **CPU:** Optimización de queries
- **Memory:** Caching agresivo
- **Disk:** SSD para PostgreSQL
- **Network:** CDN para assets

---

## 🔍 Monitoreo y Observabilidad

### Métricas
- **Performance:** p50, p95, p99 latency
- **Throughput:** Requests/segundo
- **Errors:** Error rate, tipos de errores
- **Resources:** CPU, Memory, Disk

### Logging
- **Structured logging** (structlog)
- **Log levels:** DEBUG, INFO, WARNING, ERROR
- **Correlation IDs** para tracing

### Alerting
- **Slack notifications** para errores críticos
- **Email alerts** para warnings
- **Dashboard** para visualización

---

## 🔗 Integraciones Externas

### SII (Servicio de Impuestos Internos)
- **Protocolo:** SOAP/XML
- **Ambiente:** Maullin (sandbox) / Palena (producción)
- **Certificación:** Requerida para producción

### Anthropic Claude
- **API:** REST
- **Modelo:** Claude 3.5 Sonnet
- **Rate limit:** Según plan contratado

### Otros
- **Slack:** Webhooks para notificaciones
- **Email:** SMTP para alertas
- **OneDrive:** Backup de documentos (opcional)

---

## 📝 ADR (Architecture Decision Records)

Las decisiones arquitectónicas importantes se documentan en `/ADR/`:

- Formato: `ADR-XXX-titulo-decision.md`
- Template: Contexto, Decisión, Consecuencias
- Versionado: Git

**Ejemplo:**
```
ADR-001-microservicios-vs-monolito.md
ADR-002-claude-vs-ollama.md
ADR-003-postgresql-vs-mysql.md
```

---

## 🔗 Enlaces Relacionados

- **Guías:** [../guides/](../guides/)
- **APIs:** [../api/](../api/)
- **Planning:** [../planning/](../planning/)
- **README Principal:** [../../README.md](../../README.md)

---

## 📚 Recursos Adicionales

### Documentación Externa
- [Odoo 19 Architecture](https://www.odoo.com/documentation/19.0/developer/reference/backend/architecture.html)
- [FastAPI Best Practices](https://fastapi.tiangolo.com/tutorial/)
- [Microservices Patterns](https://microservices.io/patterns/)
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

### Diagramas
- Usar [Mermaid](https://mermaid.js.org/) para diagramas en Markdown
- Usar [Draw.io](https://draw.io/) para diagramas complejos
- Exportar a PNG/SVG para documentación

---

**Última actualización:** 2025-10-23  
**Arquitecto Principal:** Ing. Pedro Troncoso Willz  
**Empresa:** EERGYGROUP
