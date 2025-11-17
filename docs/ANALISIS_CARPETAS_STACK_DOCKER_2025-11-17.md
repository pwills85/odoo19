# 📊 Análisis Carpetas Stack Docker - Estado Actual

**Fecha:** 2025-11-17  
**Scope:** Determinar estado (activo/descartado) de carpetas Docker  
**Carpetas analizadas:** `odoo-docker/`, `monitoring/`, `odoo-eergy-services/`

---

## 🎯 Resumen Ejecutivo

| Carpeta | Estado | Uso Docker Compose | Prioridad | Acción Recomendada |
|---------|--------|-------------------|-----------|-------------------|
| **odoo-docker/** | ✅ **ACTIVO** | Sí (`build: ./odoo-docker`) | 🔴 P0 CRÍTICO | **MANTENER** |
| **monitoring/** | ✅ **ACTIVO** | Sí (profile `monitoring`) | 🟡 P2 OPCIONAL | **MANTENER** |
| **odoo-eergy-services/** | ❌ **DESCARTADO** | No (comentado desde Oct 2024) | 🟢 P3 BAJO | **ARCHIVAR** |

---

## 📁 1. odoo-docker/ - ✅ ACTIVO (CRÍTICO)

### Estado
**✅ EN USO ACTIVO** - Carpeta esencial del proyecto

### Evidencia
```yaml
# docker-compose.yml:220-227
odoo:
  build:
    context: ./odoo-docker        # ✅ BUILD ACTIVO
    dockerfile: Dockerfile
    target: chile
    args:
      ODOO_VERSION: "19.0"
      ODOO_RELEASE: "20251021"
  image: pwills85/odoo19:chile-1.0.5  # ⭐ PUBLISHED (2025-11-15)
```

### Descripción
Imagen Docker multi-stage profesional de Odoo 19 CE con localización Chile completa.

**Stages:**
1. **base**: Odoo 19 oficial sin modificaciones
2. **chile**: Base + dependencias DTE/SII/nómina/reportes
3. **development**: Chile + herramientas testing/linting

**Tamaño:** 3.14 GB (stage chile)

### Estructura
```
odoo-docker/
├── Dockerfile                # Multi-stage (243 líneas)
├── .dockerignore
├── README.md                 # Documentación profesional
├── BUILD.md                  # Guía de build
├── CHANGELOG.md              # Historial versiones
├── base/                     # Stage 1: Base oficial
│   ├── entrypoint.sh
│   ├── wait-for-psql.py
│   └── odoo.conf
├── localization/             # Stage 2: Chile
│   └── chile/
│       ├── requirements.txt  # Python deps (lxml, zeep, xmlsec, etc.)
│       └── config/
│           └── odoo.conf     # Config Chile
└── scripts/                  # Build scripts
    └── build.sh
```

### Dependencias Python (Chile Stage)
```txt
# DTE (Facturación Electrónica)
lxml==5.3.0                   # XML generation (CVE-2024-45590 fixed)
xmlsec==1.3.13                # Digital signature
zeep==4.2.1                   # SII SOAP client
cryptography==46.0.3          # Certificates (CVE fixes)
pyOpenSSL==24.2.1             # SSL/TLS
pdf417==1.1.0                 # TED barcode
Pillow==11.0.0                # Images (CVE fixes)

# Development (stage development only)
pytest, pytest-cov, pytest-mock
black, flake8, pylint
ipython, ipdb
```

### Versionado
```
pwills85/odoo19:chile-1.0.5
              ↑    ↑   ↑ ↑ ↑
              │    │   │ │ └─ Hotfix (5)
              │    │   │ └─── Feature (0)
              │    │   └───── Minor (1)
              │    └─────── Major (0)
              └──────────── Odoo Version (19)
```

### Razón de Existencia
- ✅ Imagen base para servicio `odoo` en docker-compose
- ✅ Publicada en Docker Hub (pwills85/odoo19:chile-1.0.5)
- ✅ Contiene TODAS las dependencias Python para DTE/nómina/reportes
- ✅ Multi-stage permite imágenes optimizadas (base 1.8GB, chile 3.14GB, dev 3.5GB)

### ⚠️ Acción Recomendada
**MANTENER** - Carpeta crítica, NO eliminar ni archivar.

---

## 📁 2. monitoring/ - ✅ ACTIVO (OPCIONAL)

### Estado
**✅ OPERACIONAL** - Profile opcional para monitoreo

### Evidencia
```yaml
# docker-compose.yml:392-425
prometheus:
  image: prom/prometheus:latest
  container_name: odoo19_prometheus
  profiles: ["monitoring"]      # ✅ PROFILE ACTIVO (opcional)
  ports:
    - "9090:9090"
  volumes:
    - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    - ./monitoring/prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro

alertmanager:
  image: prom/alertmanager:latest
  container_name: odoo19_alertmanager
  profiles: ["monitoring"]      # ✅ PROFILE ACTIVO (opcional)
  ports:
    - "9093:9093"
  volumes:
    - ./monitoring/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
```

### Descripción
Stack de monitoreo y alerting para AI microservice y Redis HA.

**Componentes:**
- **Prometheus**: Scraping métricas (15s interval)
- **Alertmanager**: Routing alertas por severidad
- **13 Alert Rules**: 2 CRITICAL, 8 WARNING, 3 INFO

### Estructura
```
monitoring/
├── DEPLOYMENT_REPORT.md                 # 380 líneas - Reporte deployment
├── PROMETHEUS_ALERTING_GUIDE.md         # 1000+ líneas - Guía completa
├── validate.sh                          # Script validación config
├── prometheus/
│   ├── prometheus.yml                   # 180 líneas - Config scraping
│   └── alerts.yml                       # 350+ líneas - 13 alert rules
└── alertmanager/
    └── alertmanager.yml                 # 380 líneas - Routing & receivers
```

### Deployment (2025-11-09)
```
✅ Status: COMPLETE
✅ Execution Time: ~8 minutes
✅ Alert Rules: 13 configuradas
✅ Scrape Targets: 5 activos (ai-service, prometheus, alertmanager, redis, redis-sentinel)
✅ Prometheus: http://localhost:9090
✅ Alertmanager: http://localhost:9093
```

### Alert Rules Summary
**CRITICAL (2):**
1. **RedisDown**: Redis master unreachable >1 min
2. **AnthropicAPIDown**: Anthropic API errors >10 in 2 min

**WARNING (8):**
3. RedisReplicaDown, HighErrorRate, DailyCostExceeded, HighLatency
4. PluginLoadFailure, RedisSentinelDegraded, KnowledgeBaseEmpty, RedisHighMemoryUsage

**INFO (3):**
11. LowCacheHitRate, HighRequestRateDuringBusinessHours, AnthropicTokenUsageSpike

### Uso
```bash
# Activar monitoring stack
docker compose --profile monitoring up -d

# Desactivar
docker compose --profile monitoring down

# Ver logs
docker compose logs prometheus
docker compose logs alertmanager
```

### Razón de Existencia
- ✅ Monitoreo proactivo AI microservice (latencia, errores, costos)
- ✅ Alerting Redis HA (failover detection)
- ✅ Observabilidad producción (13 métricas críticas)
- ✅ Profile opcional (no afecta desarrollo si no se activa)

### ⚠️ Acción Recomendada
**MANTENER** - Carpeta operacional, útil para producción y debugging.

**Gaps Pendientes:**
- ⚠️ Slack webhooks no configurados (placeholders en config)
- ⚠️ SMTP credentials faltantes (email alerts)
- ⚠️ Redis/PostgreSQL exporters no deployados (scrape targets failing)

---

## 📁 3. odoo-eergy-services/ - ❌ DESCARTADO (MIGRADO A LIBS)

### Estado
**❌ ELIMINADO DEL STACK** - Comentado desde 2025-10-24

### Evidencia
```yaml
# docker-compose.yml:265-295
# ══════════════════════════════════════════════════════════
# DTE SERVICE - ELIMINADO (2025-10-24) ❌
# ══════════════════════════════════════════════════════════
# Migration Note: DTE microservice migrated to native Odoo library (libs/)

# odoo-eergy-services:                    # ❌ COMENTADO
#   build: ./odoo-eergy-services
#   container_name: odoo19_eergy_services
#   restart: unless-stopped
#   environment:
#     - API_KEY=${EERGY_SERVICES_API_KEY:-default_eergy_api_key}
#     - SII_ENVIRONMENT=${SII_ENVIRONMENT:-sandbox}
#   expose:
#     - "8001"
#   networks:
#     - stack_network

# To restore: Uncomment lines below and run `docker-compose up -d odoo-eergy-services`
```

### Historia de Migración

**Fecha:** 2025-10-24  
**Razón:** Simplificación arquitectura + mejor integración Odoo 19 CE

**Antes (6 servicios):**
```
db → Redis → RabbitMQ → Odoo → dte-service (FastAPI) → SII
                                    ↓
                              Ollama (LLM local)
```

**Después (4 servicios):**
```
db → Redis → Odoo (libs/ nativas) → SII
                 ↓
            ai-service (FastAPI + Claude)
```

**Cambios:**
- ❌ **RabbitMQ eliminado**: Async processing → `ir.cron` (DTE polling cada 15 min)
- ❌ **dte-service eliminado**: Microservicio FastAPI → `libs/` nativas Odoo
- ❌ **Ollama eliminado**: LLM local → Claude API (Anthropic)

### Migración DTE a Libs Nativas

**Nueva ubicación:** `addons/localization/l10n_cl_dte/libs/`

**Archivos migrados:**
```python
# Antes: odoo-eergy-services/ (FastAPI microservice)
# → POST http://dte-service:8001/generate
# → POST http://dte-service:8001/sign
# → POST http://dte-service:8001/send_to_sii

# Después: addons/localization/l10n_cl_dte/libs/
libs/
├── xml_generator.py              # XML generation (lxml)
├── xml_signer.py                 # Digital signature (xmlsec)
├── sii_soap_client.py            # SII SOAP client (zeep)
├── ted_generator.py              # TED barcode (pdf417)
├── xsd_validator.py              # XML schema validation
├── caf_handler.py                # CAF management
├── dte_52_generator.py           # Guía despacho
├── envio_dte_generator.py        # EnvioDTE wrapper
├── libro_guias_generator.py      # Libro guías
├── sii_authenticator.py          # SII authentication
└── exceptions.py                 # Custom exceptions
```

### Beneficios de Migración
- ✅ **~100ms más rápido** (no HTTP overhead)
- ✅ **Mejor seguridad** (certificados en DB, no HTTP transmission)
- ✅ **Máxima integración** Odoo 19 CE (ORM, @api, workflows)
- ✅ **Arquitectura simplificada** (4 servicios vs 6)
- ✅ **Direct Python calls** (no `requests.post`)
- ✅ **Uses Odoo ir.attachment** for XML storage
- ✅ **Uses ir.config_parameter** for configuration

### Nueva Arquitectura (account.move)
```python
# account.move hereda mixins DTE
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    # Direct Python calls a libs/
    def _generate_dte_xml(self):
        from ..libs.xml_generator import DTEXMLGenerator
        generator = DTEXMLGenerator()
        xml = generator.generate(self)
        return xml

    def _sign_dte_xml(self, xml):
        from ..libs.xml_signer import DTEXMLSigner
        signer = DTEXMLSigner()
        signed_xml = signer.sign(xml, self.company_id.l10n_cl_certificate_id)
        return signed_xml

    def _send_to_sii(self, signed_xml):
        from ..libs.sii_soap_client import SIISoapClient
        client = SIISoapClient()
        response = client.send_dte(signed_xml)
        return response
```

### Estructura Carpeta (Preservada)
```
odoo-eergy-services/
├── Dockerfile                # 38 líneas - FastAPI + lxml
├── main.py                   # 878 líneas - Aplicación principal
├── requirements.txt          # Python deps (FastAPI, lxml, zeep, pika)
├── config.py                 # Configuration
├── pytest.ini                # Testing config
│
├── auth/                     # Authentication
├── clients/                  # External clients (SII, RabbitMQ)
├── generators/               # XML generation
├── parsers/                  # XML parsing
├── receivers/                # RabbitMQ consumers
├── routes/                   # FastAPI endpoints
├── schemas/                  # Pydantic models
├── signers/                  # Digital signature
├── validators/               # XML validation
├── security/                 # Security utilities
├── contingency/              # Contingencia DTE
├── recovery/                 # Error recovery
├── resilience/               # Circuit breaker
├── scheduler/                # Async tasks
├── messaging/                # RabbitMQ integration
└── tests/                    # Unit tests
```

### ⚠️ Acción Recomendada
**ARCHIVAR** - Carpeta descartada del stack, código legacy.

**Opciones:**

**Opción 1: Archivar (RECOMENDADO)**
```bash
mkdir -p .archive/docker-services/
mv odoo-eergy-services/ .archive/docker-services/
git add -A
git commit -m "chore(archive): mover odoo-eergy-services a .archive - migrado a libs/ nativas (Oct 2024)"
```

**Opción 2: Eliminar (AGRESIVO)**
```bash
rm -rf odoo-eergy-services/
git add -A
git commit -m "chore(cleanup): eliminar odoo-eergy-services - migrado a libs/ nativas (Oct 2024)"
```

**Opción 3: Mantener (NO RECOMENDADO)**
- Mantener para referencia histórica
- Ocupa ~1.5 MB en disco
- Puede confundir a nuevos desarrolladores

**Recomendación:** **Opción 1 (Archivar)** - Preserva historia, limpia raíz.

---

## 📊 Comparación Stack Docker

### Antes (Oct 2024 - 6 servicios)
```
Stack:
  ✅ db (PostgreSQL 15)
  ✅ redis-master (Redis 7)
  ⚠️ redis-replica-1/2 (profiles: ha)
  ⚠️ redis-sentinel-1/2/3 (profiles: ha)
  ✅ odoo (Odoo 19 CE)
  ❌ dte-service (FastAPI) - ELIMINADO
  ❌ rabbitmq (RabbitMQ) - ELIMINADO
  ❌ ollama (LLM local) - ELIMINADO

Total: 9 servicios (6 core + 3 eliminados)
Imagen Odoo: eergygroup/odoo19:chile-1.0.3 (3.1 GB)
```

### Después (Nov 2025 - 5 servicios core)
```
Stack:
  ✅ db (PostgreSQL 15)
  ✅ redis-master (Redis 7)
  ⚠️ redis-replica-1/2 (profiles: ha)
  ⚠️ redis-sentinel-1/2/3 (profiles: ha)
  ✅ odoo (Odoo 19 CE + libs/ nativas)
  ✅ ai-service (FastAPI + Claude)
  ⚠️ prometheus (profiles: monitoring)
  ⚠️ alertmanager (profiles: monitoring)

Total: 5 servicios core + 5 opcionales (profiles)
Imagen Odoo: pwills85/odoo19:chile-1.0.5 (3.14 GB)
```

### Arquitectura Simplificada
```
ELIMINADO:
  - dte-service/ (FastAPI microservice) → libs/ nativas
  - rabbitmq/ (async queue) → ir.cron (Odoo scheduler)
  - ollama/ (LLM local) → Claude API (Anthropic)

AGREGADO:
  - ai-service/ (FastAPI + Claude) - NON-CRITICAL AI features
  - monitoring/ (Prometheus + Alertmanager) - Optional observability

MEJORADO:
  - odoo/ (libs/ nativas DTE) - 100ms más rápido, mejor integración
```

---

## 🎯 Conclusiones y Recomendaciones

### Estado Actual Carpetas Docker

| Carpeta | Estado | Justificación | Acción |
|---------|--------|--------------|--------|
| **odoo-docker/** | ✅ CRÍTICO | Build imagen Odoo 19 CE + Chile localization | **MANTENER** |
| **monitoring/** | ✅ OPERACIONAL | Prometheus + Alertmanager (profile opcional) | **MANTENER** |
| **odoo-eergy-services/** | ❌ DESCARTADO | Migrado a libs/ nativas (Oct 2024) | **ARCHIVAR** |

### Próximos Pasos

#### 1. Acción Inmediata (HOY)
```bash
# Archivar odoo-eergy-services/
mkdir -p .archive/docker-services/
mv odoo-eergy-services/ .archive/docker-services/
git add -A
git commit -m "chore(archive): mover odoo-eergy-services a .archive

Razón: Microservicio DTE migrado a libs/ nativas (2025-10-24)
- XML generation: libs/xml_generator.py
- Digital signature: libs/xml_signer.py
- SII SOAP client: libs/sii_soap_client.py

Beneficios migración:
- ~100ms más rápido (no HTTP overhead)
- Mejor seguridad (certs en DB)
- Máxima integración Odoo 19 CE

Arquitectura: 6 servicios → 4 servicios core
"
git push origin main
```

#### 2. Documentación (ESTA SEMANA)
```bash
# Actualizar README.md con arquitectura final
# Sección: "Stack Docker (Nov 2025)"
# - 5 servicios core (db, redis, odoo, ai-service, network)
# - 5 servicios opcionales (redis-replica 1/2, redis-sentinel 1/2/3, prometheus, alertmanager)
```

#### 3. Monitoring Config (PRÓXIMO MES)
```bash
# Completar configuración monitoring/ (gaps actuales)
# - Slack webhooks (alertmanager.yml)
# - SMTP credentials (alertmanager.yml)
# - Redis/PostgreSQL exporters (docker-compose.yml)
```

---

## 📚 Referencias

**Archivos Analizados:**
- `docker-compose.yml` (477 líneas)
- `odoo-docker/README.md`, `odoo-docker/Dockerfile`
- `monitoring/DEPLOYMENT_REPORT.md` (380 líneas)
- `odoo-eergy-services/main.py` (878 líneas)
- `addons/localization/l10n_cl_dte/libs/` (23 archivos)

**Documentación Relacionada:**
- `.claude/project/DOCKER_ENVIRONMENT.md` - Docker environment details
- `.github/agents/knowledge/deployment_environment.md` - Deployment guide
- `docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_DTE_DEEP.md` - DTE audit (migración libs/)

**Historial:**
- 2025-10-24: Migración DTE microservice → libs/ nativas
- 2025-11-09: Deployment monitoring stack (Prometheus + Alertmanager)
- 2025-11-15: Publicación imagen Docker Hub (pwills85/odoo19:chile-1.0.5)

---

**Generado:** 2025-11-17  
**Autor:** GitHub Copilot (Análisis Stack Docker)  
**Versión:** 1.0.0

