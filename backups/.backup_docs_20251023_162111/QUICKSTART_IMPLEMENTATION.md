# 🚀 Guía de Inicio Rápido - Implementación Completada

**Fecha:** 2025-10-21  
**Status:** ✅ MVP Implementado  
**Versión:** 1.0

---

## ✅ RESUMEN DE IMPLEMENTACIÓN

### Archivos Creados: 37 archivos (~3,500 líneas)

| Componente | Archivos | Líneas | Status |
|-----------|----------|--------|--------|
| **Módulo Odoo** | 22 | ~2,285 | ✅ |
| **DTE Microservice** | 7 | ~620 | ✅ |
| **AI Microservice** | 7 | ~570 | ✅ |
| **Docker Compose** | 1 | ~190 | ✅ |

---

## 🚀 INICIO RÁPIDO

### Paso 1: Configurar Variables de Entorno

```bash
# Crear archivo .env desde template
cat > .env << 'EOF'
# PostgreSQL
ODOO_DB_NAME=odoo
ODOO_DB_USER=odoo
ODOO_DB_PASSWORD=change_me_secure_password

# DTE Service
DTE_SERVICE_API_KEY=dte_api_key_123456789
SII_ENVIRONMENT=sandbox

# AI Service
AI_SERVICE_API_KEY=ai_api_key_987654321
ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY-HERE

# Timezone
TIMEZONE=America/Santiago
LOCALE=es_CL.UTF-8
EOF
```

### Paso 2: Construir Imágenes Docker

```bash
cd /Users/pedro/Documents/odoo19

# Construir todas las imágenes
docker-compose build

# Tiempo estimado: 10-15 minutos
```

### Paso 3: Iniciar Stack Completo

```bash
# Iniciar todos los servicios
docker-compose up -d

# Verificar que todos estén running
docker-compose ps
```

**Deberías ver 7 servicios:**
- ✅ db (postgres)
- ✅ redis
- ✅ rabbitmq
- ✅ odoo
- ✅ dte-service
- ✅ ollama
- ✅ ai-service

### Paso 4: Verificar Logs

```bash
# Ver logs de Odoo
docker-compose logs -f odoo

# Ver logs de DTE Service
docker-compose logs -f dte-service

# Ver logs de AI Service
docker-compose logs -f ai-service
```

### Paso 5: Acceder a Odoo

1. **Abrir navegador:** http://localhost:8069
2. **Crear base de datos:**
   - Database Name: `odoo`
   - Email: `admin@eergygroup.com`
   - Password: (tu contraseña)
   - Language: Spanish (CL) / Español (CL)
   - Country: Chile

### Paso 6: Instalar Módulo l10n_cl_dte

1. **Activar modo desarrollador:**
   - Settings → Activate Developer Mode

2. **Actualizar lista de aplicaciones:**
   - Apps → Update Apps List

3. **Instalar módulo:**
   - Apps → Buscar "Chilean" o "DTE"
   - Instalar "Chilean Localization - Electronic Invoicing (DTE)"

### Paso 7: Configurar Módulo DTE

1. **Ir a Configuración:**
   - Settings → Accounting → Facturación Electrónica Chile

2. **Configurar URLs de Microservicios:**
   - DTE Service URL: `http://dte-service:8001`
   - DTE API Key: (usar el configurado en .env)
   - AI Service URL: `http://ai-service:8002`
   - AI API Key: (usar el configurado en .env)
   - Ambiente SII: `Sandbox`

3. **Probar conexiones:**
   - Click en "Probar Conexión" para DTE Service
   - Click en "Probar Conexión" para AI Service

4. **Guardar configuración**

### Paso 8: Cargar Certificado Digital

1. **Ir a Certificados:**
   - Accounting → DTE Chile → Configuration → Certificados Digitales

2. **Crear nuevo certificado:**
   - Name: `Certificado Eergygroup 2025`
   - Upload .pfx file
   - Ingresar contraseña
   - Click "Validar Certificado"

3. **Verificar estado:** Debe quedar en estado "Válido"

### Paso 9: Configurar Diario de Ventas

1. **Ir a Diarios:**
   - Accounting → Configuration → Journals

2. **Abrir diario de ventas** (ej: "Customer Invoices")

3. **Configurar DTE:**
   - Marcar "Es Diario DTE"
   - Tipo de DTE: `Factura Electrónica (33)`
   - Folio Inicial: `1`
   - Folio Final: `1000`
   - Próximo Folio: `1`
   - Certificado Digital: Seleccionar el certificado creado

4. **Guardar**

### Paso 10: Emitir Primera Factura de Prueba

1. **Crear cliente:**
   - Contacts → Create
   - Name: `Cliente Prueba SII`
   - VAT: `12.345.678-5` (RUT válido de prueba)
   - Country: Chile
   - Save

2. **Crear factura:**
   - Accounting → Customers → Invoices → Create
   - Customer: Cliente Prueba SII
   - Add a line:
     - Product: (cualquier producto)
     - Quantity: 1
     - Unit Price: 10000
   - Save

3. **Confirmar factura:**
   - Click "Confirm"
   - Estado DTE debe cambiar a "Por Enviar"

4. **Enviar a SII:**
   - Click botón **"Enviar a SII"**
   - Sistema:
     - Valida datos
     - Llama DTE Service
     - Genera XML
     - Firma digitalmente
     - Envía a SII Sandbox
   - Ver resultado en página "DTE"

---

## ✅ VERIFICACIONES

### Health Checks

```bash
# Verificar DTE Service
curl http://localhost:8001/health

# Verificar AI Service
curl http://localhost:8002/health
```

**Nota:** Los servicios solo son accesibles desde dentro del stack Docker por seguridad.

Para probarlos desde el host, temporalmente puedes agregar en docker-compose.yml:

```yaml
dte-service:
  ports:
    - "127.0.0.1:8001:8001"  # Solo localhost
```

---

## 🔧 Troubleshooting

### Error: "DTE Service no disponible"

```bash
# Verificar servicio
docker-compose ps dte-service

# Ver logs
docker-compose logs dte-service

# Reiniciar
docker-compose restart dte-service
```

### Error: "AI Service no disponible"

```bash
# Verificar servicio
docker-compose ps ai-service

# Ver logs
docker-compose logs ai-service

# Verificar que ANTHROPIC_API_KEY esté configurada
docker-compose exec ai-service env | grep ANTHROPIC
```

### Error: "No se puede conectar a PostgreSQL"

```bash
# Verificar PostgreSQL
docker-compose ps db

# Ver logs
docker-compose logs db

# Reiniciar stack completo
docker-compose down
docker-compose up -d
```

---

## 📊 Arquitectura Implementada

```
┌─────────────────────────────────────────────────────────────┐
│                     DOCKER STACK                            │
│                   (stack_network)                           │
│                                                             │
│  ┌──────────┐      ┌────────────┐      ┌──────────┐      │
│  │   ODOO   │─────►│DTE Service │      │AI Service│      │
│  │  :8069   │◄─────│   :8001    │─────►│  :8002   │      │
│  └────┬─────┘      └──────┬─────┘      └────┬─────┘      │
│       │                   │                   │            │
│       └───────────────────┼───────────────────┘            │
│                           │                                │
│       ┌───────────────────▼────────────────┐              │
│       │ PostgreSQL / Redis / RabbitMQ      │              │
│       │ Ollama                              │              │
│       └─────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Próximos Desarrollos

### Fase 1.2: Completar DTEs

- ⏳ DTE 61 (Nota de Crédito)
- ⏳ DTE 56 (Nota de Débito)
- ⏳ DTE 52 (Guía de Despacho)
- ⏳ DTE 34 (Liquidación Honorarios)

### Fase 1.3: Implementar Funciones Completas AI

- ⏳ Validación inteligente real (con Claude)
- ⏳ Reconciliación con embeddings
- ⏳ Clasificación de documentos
- ⏳ Detección de anomalías

### Fase 1.4: Cola Asíncrona

- ⏳ Celery workers
- ⏳ RabbitMQ integration
- ⏳ Retry logic
- ⏳ Dead letter queue

---

**Status:** ✅ MVP Funcional Implementado  
**Próximo:** Testing y expansión de funcionalidades

