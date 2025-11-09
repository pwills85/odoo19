# 🚀 GUÍA DE ONBOARDING - Equipo Desarrollo Odoo 19 CE Chile

**Última actualización:** 2025-10-23  
**Tiempo de lectura:** 15 minutos  
**Objetivo:** Que cualquier desarrollador entienda el proyecto en < 30 minutos

---

## 📌 ¿QUÉ ES ESTE PROYECTO?

Suite **Odoo 19 Community Edition** mejorada para **localización chilena** con:

- ✅ **Facturación Electrónica SII** (DTEs 33, 34, 52, 56, 61)
- ✅ **Gestión de Nóminas** (HR Payroll Chile)
- ✅ **Microservicios** (DTE Service + AI Service)
- ✅ **Agentes de IA** (Claude 3.5 Sonnet para validación y monitoreo)

**Stack:** Odoo 19 CE + PostgreSQL 15 + Redis 7 + RabbitMQ 3.12 + FastAPI + Docker

---

## 🎯 ARQUITECTURA EN 60 SEGUNDOS

```
┌─────────────────────────────────────────────────────┐
│  USUARIO (Web Browser)                              │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  ODOO 19 CE (Puerto 8169)                           │
│  • UI/UX + Business Logic                           │
│  • Módulo: l10n_cl_dte + l10n_cl_hr_payroll        │
└─────────────────────────────────────────────────────┘
         ↓                    ↓                ↓
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ DTE Service  │   │ AI Service   │   │ PostgreSQL   │
│ (Puerto 8001)│   │ (Puerto 8002)│   │ (Puerto 5432)│
│ • XML/Firma  │   │ • Claude AI  │   │ • Data       │
│ • SOAP SII   │   │ • Monitoreo  │   │              │
└──────────────┘   └──────────────┘   └──────────────┘
         ↓                    ↓
┌──────────────┐   ┌──────────────┐
│ Redis        │   │ RabbitMQ     │
│ (Cache)      │   │ (Queue)      │
└──────────────┘   └──────────────┘
```

**Principio clave:** Separación de responsabilidades (Clean Architecture)

---

## 📂 ESTRUCTURA DEL PROYECTO

```
odoo19/
├── README.md                    ← Documentación principal (856 líneas)
├── TEAM_ONBOARDING.md          ← ESTE ARCHIVO (empieza aquí)
├── QUICK_START.md              ← Setup rápido (< 5 minutos)
│
├── docker-compose.yml          ← Stack completo (7 servicios)
├── .env                        ← Variables de entorno (API keys)
│
├── addons/
│   ├── localization/
│   │   ├── l10n_cl_dte/       ← MÓDULO PRINCIPAL DTE (80 archivos)
│   │   └── l10n_cl_hr_payroll/ ← Módulo Nóminas (48 archivos)
│   ├── custom/                 ← Módulos personalizados
│   └── third_party/            ← Módulos de terceros
│
├── dte-service/                ← Microservicio DTE (FastAPI)
│   ├── generators/             ← Generadores XML DTEs
│   ├── signers/                ← Firma digital XMLDSig
│   ├── clients/                ← Cliente SOAP SII
│   └── tests/                  ← 60+ tests (80% coverage)
│
├── ai-service/                 ← Microservicio IA (FastAPI)
│   ├── chat/                   ← Chat conversacional
│   ├── sii_monitor/            ← Monitoreo SII automático
│   ├── analytics/              ← Análisis proyectos
│   └── training/               ← Entrenamiento con históricos
│
├── docs/                       ← Documentación técnica
│   ├── architecture/           ← Diagramas y arquitectura
│   ├── api/                    ← Documentación APIs
│   └── guides/                 ← Guías de desarrollo
│
├── scripts/                    ← Scripts útiles
│   ├── build.sh                ← Build imágenes Docker
│   ├── start.sh                ← Iniciar stack
│   └── test.sh                 ← Ejecutar tests
│
└── config/                     ← Configuraciones
    ├── odoo.conf               ← Config Odoo
    └── rabbitmq/               ← Config RabbitMQ
```

---

## 🚀 SETUP RÁPIDO (5 MINUTOS)

### 1. **Prerrequisitos**
```bash
# Verificar instalaciones
docker --version        # Docker 24+
docker-compose --version # 2.20+
git --version           # 2.40+
```

### 2. **Clonar y Configurar**
```bash
cd /Users/pedro/Documents/odoo19

# Verificar .env existe (contiene API keys)
cat .env | grep ANTHROPIC_API_KEY

# Si no existe, copiar template
cp .env.example .env
# Editar y agregar tu ANTHROPIC_API_KEY
```

### 3. **Iniciar Stack**
```bash
# Iniciar todos los servicios
docker-compose up -d

# Verificar que todos estén "healthy"
docker-compose ps

# Ver logs en tiempo real
docker-compose logs -f odoo
```

### 4. **Acceder a Odoo**
```
URL: http://localhost:8169
Usuario: admin
Password: (configurar en primer acceso)
```

### 5. **Instalar Módulo DTE**
```
1. Apps → Update Apps List
2. Buscar: "Chilean" o "DTE"
3. Install: "Chilean Localization - Electronic Invoicing (DTE)"
```

---

## 🎓 CONCEPTOS CLAVE

### **1. DTEs (Documentos Tributarios Electrónicos)**
Documentos fiscales certificados por el SII (Servicio de Impuestos Internos de Chile):

| Código | Nombre | Uso |
|--------|--------|-----|
| DTE 33 | Factura Electrónica | Ventas B2B |
| DTE 61 | Nota de Crédito | Anulaciones/Devoluciones |
| DTE 56 | Nota de Débito | Cargos adicionales |
| DTE 52 | Guía de Despacho | Traslado mercancías |
| DTE 34 | Liquidación Honorarios | Pago a profesionales |

### **2. CAF (Código de Autorización de Folios)**
- Archivo XML descargado del SII
- Autoriza rangos de folios (ej: 1-100)
- Necesario para emitir DTEs
- Se incluye en cada DTE generado

### **3. Certificado Digital**
- Certificado PKCS#12 (.p12/.pfx) emitido por SII
- Usado para firmar digitalmente los DTEs
- Almacenado encriptado en Odoo

### **4. Microservicios**

**DTE Service (Puerto 8001):**
- Genera XML según esquemas SII
- Firma digitalmente (XMLDSig)
- Envía a SII vía SOAP
- Polling automático de estados

**AI Service (Puerto 8002):**
- Pre-validación con Claude 3.5 Sonnet
- Reconciliación semántica de facturas
- Monitoreo automático portal SII
- Sugerencias inteligentes de proyectos

---

## 👥 ROLES Y RESPONSABILIDADES

### **Backend Developer (Odoo)**
- **Foco:** Módulo `l10n_cl_dte` en `/addons/localization/`
- **Tecnologías:** Python 3.11, Odoo ORM, XML views
- **Tareas típicas:**
  - Extender modelos Odoo (account.move, purchase.order)
  - Crear vistas y wizards
  - Validaciones de negocio
  - Integración con microservicios

### **Backend Developer (Microservicios)**
- **Foco:** `dte-service/` y `ai-service/`
- **Tecnologías:** FastAPI, asyncio, SOAP, Redis
- **Tareas típicas:**
  - Endpoints REST API
  - Generadores XML DTEs
  - Cliente SOAP SII
  - Integración Claude API

### **DevOps/SysAdmin**
- **Foco:** `docker-compose.yml`, infraestructura
- **Tecnologías:** Docker, PostgreSQL, Redis, RabbitMQ
- **Tareas típicas:**
  - Deployment
  - Monitoring
  - Backups
  - Performance tuning

### **QA/Tester**
- **Foco:** `tests/` en cada servicio
- **Tecnologías:** pytest, unittest (Odoo)
- **Tareas típicas:**
  - Tests unitarios
  - Tests de integración
  - Validación SII compliance

---

## 🔧 FLUJOS DE TRABAJO COMUNES

### **Flujo 1: Emitir una Factura Electrónica (DTE 33)**

```
1. Usuario crea factura en Odoo (account.move)
2. Odoo valida datos localmente (RUT, montos, etc.)
3. Odoo llama a DTE Service → POST /api/dte/generate
4. DTE Service:
   a. Genera XML según esquema SII
   b. Incluye CAF en XML
   c. Firma digitalmente (XMLDSig)
   d. Envía a SII vía SOAP
5. SII responde con Track ID
6. DTE Service hace polling cada 15 min
7. Cuando SII acepta → Webhook a Odoo
8. Odoo actualiza estado DTE → "Aceptado"
9. Usuario puede descargar PDF con QR
```

### **Flujo 2: Monitoreo Automático SII**

```
1. AI Service ejecuta scraping cada 6 horas
2. Descarga HTML del portal SII
3. Claude analiza cambios normativos
4. Si detecta cambio crítico → Notificación Slack
5. Almacena en Redis (TTL 7 días)
```

### **Flujo 3: Sugerencia Inteligente de Proyecto**

```
1. Usuario crea orden de compra
2. Odoo llama AI Service → POST /api/ai/analytics/suggest_project
3. AI Service:
   a. Analiza descripción productos
   b. Busca histórico proveedor
   c. Claude hace matching semántico
   d. Retorna proyecto + confidence score
4. Si confidence ≥ 85% → Auto-asigna
5. Si 70-84% → Sugiere al usuario
6. Si < 70% → Usuario elige manual
```

---

## 📚 DOCUMENTACIÓN ADICIONAL

### **Para Empezar:**
1. ✅ `TEAM_ONBOARDING.md` (este archivo)
2. ✅ `QUICK_START.md` (setup rápido)
3. ✅ `README.md` (documentación completa)

### **Arquitectura:**
- `REPORTE_ARQUITECTURA_GRAFICO_PROFESIONAL.md` (1,200 líneas)
- `docs/architecture/` (diagramas detallados)

### **APIs:**
- DTE Service: http://localhost:8001/docs (Swagger)
- AI Service: http://localhost:8002/docs (Swagger)

### **Testing:**
- `dte-service/tests/README.md` (guía testing)
- `CLI_TESTING_EXPERT_PLAN.md` (plan testing completo)

### **Deployment:**
- `DESPLIEGUE_INTEGRACION_PROYECTOS.md`
- `docker-compose.yml` (configuración completa)

---

## 🐛 TROUBLESHOOTING COMÚN

### **Problema: Servicios no inician**
```bash
# Ver logs
docker-compose logs dte-service
docker-compose logs ai-service

# Rebuild si hay cambios
docker-compose build --no-cache
docker-compose up -d
```

### **Problema: Error "ANTHROPIC_API_KEY not found"**
```bash
# Verificar .env
cat .env | grep ANTHROPIC_API_KEY

# Debe tener formato: ANTHROPIC_API_KEY=sk-ant-api03-...
# Reiniciar servicios después de editar .env
docker-compose restart ai-service
```

### **Problema: Odoo no conecta con microservicios**
```bash
# Verificar red Docker
docker network inspect odoo19_stack_network

# Verificar que servicios estén en misma red
docker-compose ps

# Test conectividad desde Odoo
docker-compose exec odoo curl http://dte-service:8001/health
docker-compose exec odoo curl http://ai-service:8002/health
```

### **Problema: Tests fallan**
```bash
# Ejecutar tests con verbose
cd dte-service
pytest -v

# Ver coverage
pytest --cov=. --cov-report=term

# Ejecutar test específico
pytest tests/test_dte_generators.py::test_dte33_generation -v
```

---

## 📞 CONTACTO Y SOPORTE

**Desarrollador Principal:**  
Ing. Pedro Troncoso Willz  
Email: contacto@eergygroup.cl  
Empresa: EERGYGROUP

**Documentación:**  
- GitHub: (agregar URL del repo)
- Docs: `/docs/` en este proyecto

**Canales de Comunicación:**  
- Slack: (configurar canal equipo)
- Issues: (configurar issue tracker)

---

## ✅ CHECKLIST PRIMER DÍA

- [ ] Leer este documento completo
- [ ] Setup local exitoso (docker-compose up)
- [ ] Acceder a Odoo (http://localhost:8169)
- [ ] Instalar módulo l10n_cl_dte
- [ ] Explorar Swagger APIs (puertos 8001, 8002)
- [ ] Ejecutar tests: `cd dte-service && pytest`
- [ ] Leer README.md completo
- [ ] Revisar estructura `/addons/localization/l10n_cl_dte/`
- [ ] Entender flujo emisión DTE (diagrama arriba)
- [ ] Hacer primera modificación de prueba

---

## 🎯 PRÓXIMOS PASOS

**Semana 1:**
- Familiarizarse con codebase
- Ejecutar todos los tests
- Entender arquitectura microservicios

**Semana 2:**
- Implementar primera feature pequeña
- Code review con equipo
- Documentar aprendizajes

**Mes 1:**
- Dominar módulo l10n_cl_dte
- Contribuir a features P0/P1
- Participar en planning

---

**¡Bienvenido al equipo! 🚀**

Si tienes dudas, revisa primero la documentación en `/docs/` o pregunta al equipo.
