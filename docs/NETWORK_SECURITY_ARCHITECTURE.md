# 🔒 Arquitectura de Seguridad de Red

**Documento:** Network Security Architecture  
**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Criticidad:** ⭐⭐⭐ MÁXIMA

---

## 🎯 PRINCIPIO FUNDAMENTAL

### **SOLO ODOO DEBE SER ACCESIBLE DESDE EL EXTERIOR**

**Todos los microservicios internos (DTE Service, AI Service) DEBEN estar en red privada Docker.**

---

## 📊 CONFIGURACIÓN DE PUERTOS

### ✅ Configuración CORRECTA (Producción)

| Servicio | Puerto Interno | Exposición | Accesible Desde |
|----------|---------------|-----------|-----------------|
| **Traefik** | 80, 443, 8080 | `ports` público | Internet (80, 443), Localhost (8080) |
| **Odoo** | 8069 | `expose` + Traefik | Internet vía HTTPS (Traefik) |
| **DTE Service** | 8001 | `expose` SOLO | Red interna Docker |
| **AI Service** | 8002 | `expose` SOLO | Red interna Docker |
| **PostgreSQL** | 5432 | `expose` SOLO | Red interna Docker |
| **Redis** | 6379 | `expose` SOLO | Red interna Docker |
| **RabbitMQ** | 5672 | `expose` SOLO | Red interna Docker |
| **Ollama** | 11434 | `expose` SOLO | Red interna Docker |

---

## 🏗️ ARQUITECTURA DE RED

```
╔═══════════════════════════════════════════════════════════════╗
║                        INTERNET                               ║
║                    (Usuarios Públicos)                        ║
╚═══════════════════════════════════════════════════════════════╝
                           │
                           │ HTTPS (443)
                           │ HTTP (80) → redirect 443
                           │
                    ┌──────▼──────┐
                    │   TRAEFIK   │
                    │ Puerto 443  │ ✅ ÚNICO PUNTO PÚBLICO
                    │   (SSL/TLS) │
                    └──────┬──────┘
                           │
                           │ HTTP interno
                           │ (sin SSL, red privada)
                           │
╔═══════════════════════════▼═══════════════════════════════════╗
║             DOCKER NETWORK: stack_network                     ║
║                    (RED PRIVADA)                              ║
║                                                               ║
║  ┌──────────────┐                                            ║
║  │     ODOO     │  :8069                                     ║
║  │              │  ✅ Accesible vía Traefik                  ║
║  └──────┬───────┘  ❌ NO accesible directamente              ║
║         │                                                     ║
║         │ HTTP POST                                           ║
║         │                                                     ║
║         ├────────────────┐                                    ║
║         │                │                                    ║
║  ┌──────▼───────┐  ┌─────▼────────┐                         ║
║  │ DTE SERVICE  │  │  AI SERVICE  │                         ║
║  │   :8001      │  │   :8002      │                         ║
║  │ ❌ NO PÚBLICO │  │ ❌ NO PÚBLICO │                         ║
║  └──────┬───────┘  └──────┬───────┘                         ║
║         │                  │                                  ║
║         └────────┬─────────┘                                  ║
║                  │                                            ║
║         ┌────────▼────────┐                                  ║
║         │  PostgreSQL     │ :5432                            ║
║         │  Redis          │ :6379                            ║
║         │  RabbitMQ       │ :5672                            ║
║         │  Ollama         │ :11434                           ║
║         │ ❌ NO PÚBLICOS   │                                  ║
║         └─────────────────┘                                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
           │                    │
           │ HTTPS (salida)     │ HTTPS (salida)
           │                    │
    ┌──────▼──────┐      ┌──────▼──────┐
    │     SII     │      │  Anthropic  │
    │   Chile     │      │    API      │
    └─────────────┘      └─────────────┘
```

---

## 🔧 docker-compose.yml SEGURO

### Configuración Completa

```yaml
version: '3.8'

services:
  # ══════════════════════════════════════════════════════════
  # TRAEFIK - ÚNICO PUNTO DE ENTRADA PÚBLICO
  # ══════════════════════════════════════════════════════════
  traefik:
    image: traefik:v2.10
    container_name: traefik
    command:
      - "--api.dashboard=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"  # ⭐ CRÍTICO
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@eergygroup.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/acme.json"
    ports:
      - "80:80"                    # HTTP → HTTPS redirect
      - "443:443"                  # HTTPS ✅ PÚBLICO
      - "127.0.0.1:8080:8080"      # Dashboard (solo localhost)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/acme.json:/acme.json
    networks:
      - stack_network
    restart: unless-stopped

  # ══════════════════════════════════════════════════════════
  # ODOO - EXPUESTO VÍA TRAEFIK (NO DIRECTAMENTE)
  # ══════════════════════════════════════════════════════════
  odoo:
    image: eergygroup/odoo19:v1
    container_name: odoo
    # ❌ NO USAR: ports: - "8069:8069"
    expose:
      - "8069"  # ✅ Solo interno
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.odoo.rule=Host(`odoo.eergygroup.com`)"
      - "traefik.http.routers.odoo.entrypoints=websecure"
      - "traefik.http.routers.odoo.tls.certresolver=letsencrypt"
      - "traefik.http.services.odoo.loadbalancer.server.port=8069"
      # Rate limiting (opcional)
      - "traefik.http.middlewares.odoo-ratelimit.ratelimit.average=100"
      - "traefik.http.routers.odoo.middlewares=odoo-ratelimit"
    environment:
      - HOST=postgres
      - USER=odoo
      - PASSWORD=${POSTGRES_PASSWORD}
      - DB_NAME=odoo
    volumes:
      - odoo_data:/var/lib/odoo
      - ./addons:/mnt/extra-addons
    networks:
      - stack_network
    depends_on:
      - postgres
    restart: unless-stopped

  # ══════════════════════════════════════════════════════════
  # DTE SERVICE - SOLO RED INTERNA ⭐
  # ══════════════════════════════════════════════════════════
  dte-service:
    build: ./dte-service
    container_name: dte-service
    # ❌ NO ports: - NO EXPONER
    expose:
      - "8001"  # ✅ Solo interno
    environment:
      - ODOO_URL=http://odoo:8069
      - ODOO_API_KEY=${ODOO_DTE_API_KEY}
      - SII_ENVIRONMENT=${SII_ENVIRONMENT:-sandbox}
      - REDIS_URL=redis://redis:6379/0
      - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672//
      - LOG_LEVEL=INFO
    networks:
      - stack_network  # ✅ Red privada
    depends_on:
      - redis
      - rabbitmq
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ══════════════════════════════════════════════════════════
  # AI SERVICE - SOLO RED INTERNA ⭐
  # ══════════════════════════════════════════════════════════
  ai-service:
    build: ./ai-service
    container_name: ai-service
    # ❌ NO ports: - NO EXPONER
    expose:
      - "8002"  # ✅ Solo interno
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - ODOO_URL=http://odoo:8069
      - ODOO_API_KEY=${ODOO_AI_API_KEY}
      - OLLAMA_URL=http://ollama:11434
      - REDIS_URL=redis://redis:6379/1
      - LOG_LEVEL=INFO
    volumes:
      - ai_cache:/app/cache
      - ai_uploads:/app/uploads
    networks:
      - stack_network  # ✅ Red privada
    depends_on:
      - ollama
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8002/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ══════════════════════════════════════════════════════════
  # SERVICIOS DE DATOS - TODOS INTERNOS
  # ══════════════════════════════════════════════════════════
  postgres:
    image: postgres:15-alpine
    container_name: postgres
    expose:
      - "5432"
    environment:
      - POSTGRES_USER=odoo
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=odoo
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - stack_network
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: redis
    expose:
      - "6379"
    networks:
      - stack_network
    restart: unless-stopped

  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    container_name: rabbitmq
    expose:
      - "5672"   # AMQP
      - "15672"  # Management UI
    networks:
      - stack_network
    restart: unless-stopped

  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    expose:
      - "11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - stack_network
    restart: unless-stopped

networks:
  stack_network:
    driver: bridge
    internal: false  # ⭐ Permite salida a internet (SII, Anthropic)

volumes:
  odoo_data:
  postgres_data:
  ai_cache:
  ai_uploads:
  ollama_data:
```

---

## 🔒 CAPAS DE SEGURIDAD

### Capa 1: Firewall del Servidor

```bash
# Solo permitir puertos 80 y 443
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 22/tcp    # SSH (solo desde IPs confiables)
ufw enable
```

### Capa 2: Traefik (Reverse Proxy)

- ✅ SSL/TLS termination (Let's Encrypt)
- ✅ Rate limiting
- ✅ IP whitelisting (opcional)
- ✅ Headers de seguridad
- ✅ WAF básico

### Capa 3: Red Docker Privada

- ✅ Solo servicios en `stack_network` pueden comunicarse
- ✅ Puertos NO expuestos al host
- ✅ Comunicación HTTP interna (sin SSL, red privada)

### Capa 4: Autenticación API

- ✅ API Keys para Odoo ↔ DTE Service
- ✅ API Keys para Odoo ↔ AI Service
- ✅ Webhook keys para callbacks

---

## 🚨 RIESGOS SI SE EXPONEN PUERTOS

### DTE Service Expuesto (Puerto 8001)

**Riesgos:**
1. ❌ Firma digital sin autorización
2. ❌ Generación masiva de DTEs falsos
3. ❌ Consumo de cuota SII
4. ❌ Exposición de certificados digitales
5. ❌ DDoS attacks

**Costo potencial:** Alto (fraude, sanciones SII, pérdida de reputación)

### AI Service Expuesto (Puerto 8002)

**Riesgos:**
1. ❌ Uso no autorizado de API Anthropic (costos $$$)
2. ❌ Exposición de datos de facturación
3. ❌ Consumo de recursos Ollama
4. ❌ Acceso a embeddings (data leakage)
5. ❌ DDoS attacks

**Costo potencial:** Muy alto (costos API ilimitados, data breach)

---

## ✅ BENEFICIOS DE RED PRIVADA

### 1. Seguridad

- ✅ Servicios críticos protegidos
- ✅ Solo Odoo como punto de entrada (autenticado)
- ✅ Sin exposición de APIs internas

### 2. Control de Costos

- ✅ API Anthropic solo vía Odoo (controlado)
- ✅ Rate limiting centralizado en Traefik
- ✅ Sin uso no autorizado

### 3. Simplificación

- ✅ No requiere autenticación compleja en microservicios
- ✅ Comunicación HTTP simple en red privada
- ✅ Menos configuración de seguridad

### 4. Compliance

- ✅ Datos sensibles no expuestos
- ✅ Certificados digitales protegidos
- ✅ Auditoría centralizada en Odoo

---

## 🔧 TESTING Y DEBUGGING

### Desarrollo Local (MacBook M3)

```yaml
# docker-compose.dev.yml
services:
  dte-service:
    ports:
      - "127.0.0.1:8001:8001"  # ✅ Solo localhost para debugging
  
  ai-service:
    ports:
      - "127.0.0.1:8002:8002"  # ✅ Solo localhost para debugging
```

**Uso:**
```bash
# Desarrollo
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Acceso local para testing
curl http://localhost:8001/health
curl http://localhost:8002/health
```

### Producción

```yaml
# docker-compose.yml (SIN docker-compose.dev.yml)
services:
  dte-service:
    expose:
      - "8001"  # ✅ Solo interno, NO localhost
  
  ai-service:
    expose:
      - "8002"  # ✅ Solo interno, NO localhost
```

---

## 📋 CHECKLIST DE SEGURIDAD

### Antes de Deploy a Producción

- [ ] ❌ DTE Service NO tiene `ports:` en docker-compose.yml
- [ ] ❌ AI Service NO tiene `ports:` en docker-compose.yml
- [ ] ❌ PostgreSQL NO tiene `ports:` en docker-compose.yml
- [ ] ❌ Redis NO tiene `ports:` en docker-compose.yml
- [ ] ✅ Solo Traefik tiene `ports: 80, 443`
- [ ] ✅ Odoo solo accesible vía Traefik (HTTPS)
- [ ] ✅ Firewall del servidor configurado (solo 80, 443, 22)
- [ ] ✅ API Keys configuradas para comunicación interna
- [ ] ✅ SSL/TLS configurado en Traefik (Let's Encrypt)
- [ ] ✅ Rate limiting configurado en Traefik

---

## 🎯 DIAGRAMA DE COMUNICACIÓN

### Flujo Completo: Usuario → DTE → SII

```
[Usuario Internet]
        │
        │ HTTPS (443)
        ▼
    [Traefik]
        │ SSL termination
        │ HTTP interno
        ▼
      [Odoo]
        │ Valida factura
        │ HTTP POST
        ▼
   [DTE Service]  ← RED PRIVADA
        │ Genera XML
        │ Firma digital
        │ HTTPS (salida permitida)
        ▼
    [SII Chile]
```

### Flujo Completo: DTE → AI → Odoo

```
   [DTE Service]  ← RED PRIVADA
        │ Necesita validación IA
        │ HTTP POST
        ▼
   [AI Service]  ← RED PRIVADA
        │ Valida con LLM
        │ HTTP Response
        ▼
   [DTE Service]
        │ Callback HTTP POST
        ▼
      [Odoo]
        │ Actualiza estado
        ▼
  [Usuario vía Web]
```

---

## ⚠️ EXCEPCIONES Y CASOS ESPECIALES

### Grafana/Prometheus (Monitoring)

**Opción 1: Vía Traefik (RECOMENDADO)**
```yaml
grafana:
  expose:
    - "3000"
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.grafana.rule=Host(`grafana.eergygroup.com`)"
    - "traefik.http.routers.grafana.middlewares=admin-auth"
```

**Opción 2: Solo Localhost (ALTERNATIVA)**
```yaml
grafana:
  ports:
    - "127.0.0.1:3000:3000"  # Solo desde servidor
```

### RabbitMQ Management UI

**Solo para debugging (NO en producción):**
```yaml
rabbitmq:
  ports:
    - "127.0.0.1:15672:15672"  # Solo localhost
```

---

## 🔑 AUTENTICACIÓN ENTRE SERVICIOS

### Variables de Entorno (.env)

```bash
# API Keys para comunicación interna
ODOO_DTE_API_KEY=secret_key_dte_12345
ODOO_AI_API_KEY=secret_key_ai_67890
ODOO_WEBHOOK_KEY=secret_key_webhook_abcde

# API Keys externas
ANTHROPIC_API_KEY=sk-ant-api03-xxx
```

### Implementación en Odoo

```python
# tools/dte_api_client.py
class DTEApiClient(models.AbstractModel):
    _name = 'dte.api.client'
    
    def _get_headers(self):
        return {
            'Authorization': f'Bearer {os.getenv("ODOO_DTE_API_KEY")}',
            'Content-Type': 'application/json'
        }
    
    def generate_dte(self, move_id):
        response = requests.post(
            'http://dte-service:8001/api/dte/generate',
            json=data,
            headers=self._get_headers(),
            timeout=30
        )
        return response.json()
```

### Implementación en DTE Service

```python
# dte-service/middleware/auth.py
from fastapi import Security, HTTPException
from fastapi.security import HTTPBearer

security = HTTPBearer()

async def verify_api_key(credentials = Security(security)):
    if credentials.credentials != os.getenv('ODOO_DTE_API_KEY'):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return credentials

# main.py
@app.post("/api/dte/generate", dependencies=[Depends(verify_api_key)])
async def generate_dte(data: DTEData):
    # Solo accesible con API key válida
    pass
```

---

## 📊 RESUMEN EJECUTIVO

### Configuración Recomendada

| Aspecto | Configuración | Razón |
|---------|--------------|-------|
| **Traefik** | `ports: 80, 443` | Único punto público |
| **Odoo** | `expose: 8069` + Traefik labels | Acceso vía HTTPS |
| **DTE Service** | `expose: 8001` SOLO | Red privada |
| **AI Service** | `expose: 8002` SOLO | Red privada |
| **PostgreSQL** | `expose: 5432` SOLO | Red privada |
| **Redis** | `expose: 6379` SOLO | Red privada |
| **RabbitMQ** | `expose: 5672` SOLO | Red privada |

### Comunicación

```
PÚBLICO:  Internet → Traefik (443) → Odoo
PRIVADO:  Odoo → DTE Service (8001)
PRIVADO:  Odoo → AI Service (8002)
PÚBLICO:  DTE Service → SII (443)
PÚBLICO:  AI Service → Anthropic (443)
```

---

## ✅ CONCLUSIÓN

**RESPUESTA A LA PREGUNTA:**

Los puertos 8001 (DTE Service) y 8002 (AI Service) son **SOLO PARA LA RED INTERNA DEL STACK**.

**NO deben ser accesibles desde el exterior del servidor.**

**Configuración:**
- ✅ Usar `expose:` (NO `ports:`)
- ✅ Red privada Docker (`stack_network`)
- ✅ Solo Traefik expuesto al exterior
- ✅ Odoo accesible solo vía Traefik (HTTPS)

**Seguridad:**
- ✅ Máxima seguridad
- ✅ Control de costos
- ✅ Protección de datos sensibles
- ✅ Compliance OWASP

---

**Status:** ✅ Arquitectura de red segura definida  
**Próximo Paso:** Actualizar docker-compose.yml con configuración segura

