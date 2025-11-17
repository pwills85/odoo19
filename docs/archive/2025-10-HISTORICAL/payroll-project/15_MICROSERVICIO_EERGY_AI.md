# 🤖 MICROSERVICIO EERGY AI - Análisis Completo

**Versión:** 1.0.0  
**Status:** ✅ ENTERPRISE-GRADE (15.5/16)  
**Fecha:** 2025-10-22

---

## 🎯 ¿QUÉ ES EERGY AI?

Microservicio **FastAPI + Claude API (Anthropic)** que proporciona:

1. **Extracción automática indicadores** (Previred + SII)
2. **Portal empleados** (React SPA - Employee Self-Service)
3. **Validación inteligente** con IA
4. **Chat laboral** con Claude

---

## 📊 ARQUITECTURA COMPLETA

```
┌─────────────────────────────────────────────────────────┐
│ EERGY AI MICROSERVICE (FastAPI)                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. SCRAPING & EXTRACCIÓN ✅                            │
│    ├─ POST /api/v1/scraping/previred                   │
│    │  └─ 60 campos desde PDF/HTML                      │
│    ├─ GET /api/v1/scraping/previred/periods            │
│    │  └─ Lista períodos disponibles                    │
│    └─ POST /api/v1/scraping/sii/tax-brackets           │
│       └─ 32 campos tabla impuesto                      │
│                                                         │
│ 2. PORTAL EMPLEADOS ✅                                  │
│    ├─ POST /api/v1/auth/login                          │
│    ├─ GET /api/v1/employee/me                          │
│    ├─ GET /api/v1/employee/payslips                    │
│    ├─ GET /api/v1/employee/payslips/{id}               │
│    ├─ POST /api/v1/employee/payslips/{id}/pdf          │
│    └─ GET /api/v1/employee/statistics                  │
│                                                         │
│ 3. VALIDACIÓN IA ✅                                     │
│    └─ POST /api/v1/validation/contract                 │
│                                                         │
│ 4. CHAT LABORAL ✅                                      │
│    └─ POST /api/v1/chat/query                          │
│                                                         │
│ 5. AUDIT TRAIL ✅                                       │
│    └─ GET /api/v1/audit/trail                          │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ CLAUDE API (Anthropic)                                 │
│ ├─ claude-sonnet-4-5-20250929 (principal)             │
│ ├─ claude-3-haiku (económico)                         │
│ └─ claude-3-opus (complejo)                           │
└─────────────────────────────────────────────────────────┘
```

---

## ✨ CARACTERÍSTICAS ENTERPRISE

### **1. Observability**
- ✅ **Structured JSON Logging** (python-json-logger)
- ✅ **Correlation IDs** end-to-end (Odoo → Claude → Logs)
- ✅ **12 grupos Prometheus metrics**
- ✅ **Distributed Tracing** (OpenTelemetry + Jaeger)
- ✅ **Slack Alerting** con throttling

### **2. Seguridad**
- ✅ **Rate Limiting** (100 req/60s)
- ✅ **Security Headers** (OWASP 2023)
- ✅ **API Key** opcional
- ✅ **JWT Authentication** (portal empleados)
- ✅ **CORS** configurado

### **3. Compliance**
- ✅ **Audit Trail Blockchain** (SHA-256, 7 años)
- ✅ **Log Rotation** (10MB × 5 archivos)
- ✅ **Art. 54 Código del Trabajo**

### **4. Performance**
- ✅ **Redis Cache** (indicadores)
- ✅ **Circuit Breaker**
- ✅ **Retry Logic** con exponential backoff
- ✅ **SQL Direct** (portal empleados)

---

## 📋 ENDPOINTS PRINCIPALES

### **1. Scraping Previred**

```http
POST /api/v1/scraping/previred
Content-Type: application/json
X-Correlation-ID: test-abc123

{
  "fields_count": 60,
  "context": {
    "periodo": "2025-10"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "uf": 39383.07,
    "utm": 68647,
    "uta": 823764,
    "sueldo_minimo": 500000,
    "afp_tope_uf": 87.8,
    "salud_tope_uf": 0.0,
    "afc_tope_uf": 131.9,
    "exvida_pct": 0.9,
    "aporteafpe_pct": 0.1,
    // ... 51 campos más
  },
  "fields_extracted": 60,
  "metadata": {
    "source": "previred_pdf",
    "model_used": "claude-sonnet-4-5",
    "cost_usd": 0.025,
    "input_tokens": 15000,
    "output_tokens": 800
  }
}
```

---

### **2. Portal Empleados - Login**

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "rut": "12345678-9",
  "password": "secret123"
}
```

**Response:**
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

### **3. Portal Empleados - Mis Liquidaciones**

```http
GET /api/v1/employee/payslips?year=2025&state=done
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "payslips": [
    {
      "id": 123,
      "date_from": "2025-10-01",
      "date_to": "2025-10-31",
      "net_wage": 1500000,
      "basic_wage": 1200000,
      "state": "done",
      "sistema_calculo": "SOPA 2025"
    }
  ]
}
```

---

### **4. Tabla Impuesto SII**

```http
POST /api/v1/scraping/sii/tax-brackets?year=2025
```

**Response:**
```json
{
  "success": true,
  "data": {
    "imp_tramo_1_desde": 0,
    "imp_tramo_1_hasta": 935077.50,
    "imp_tramo_1_factor": 0.0,
    "imp_tramo_1_rebaja": 0,
    "imp_tramo_2_desde": 935077.51,
    "imp_tramo_2_hasta": 2077950.00,
    "imp_tramo_2_factor": 0.04,
    "imp_tramo_2_rebaja": 37403.10,
    // ... 24 campos más (8 tramos × 4 valores)
  },
  "fields_extracted": 32
}
```

---

## 💰 COSTOS

### **Por Extracción:**
- Previred PDF: **$0.025 USD** (60 campos)
- SII HTML: **$0.002 USD** (32 campos)

### **Anual:**
- **Total: ~$0.30 USD/año** (92 variables)
- **vs Manual**: $2,400/año → **Ahorro 99.99%**

---

## 🔧 COMPONENTES TÉCNICOS

### **Stack:**
```
FastAPI 0.104+
Python 3.11
Claude API (Anthropic)
Redis (cache)
PostgreSQL (Odoo DB - SQL Direct)
Prometheus (métricas)
Jaeger (tracing opcional)
```

### **Estructura:**
```
microservices/eergy-ai/
├── app/
│   ├── main.py                    # FastAPI app
│   ├── config.py                  # Settings
│   ├── routers/
│   │   ├── scraping.py            # Previred + SII
│   │   ├── employee_portal.py     # Portal empleados
│   │   ├── validation.py          # Validación IA
│   │   ├── chat.py                # Chat laboral
│   │   ├── auth.py                # Autenticación
│   │   └── audit.py               # Audit trail
│   ├── services/
│   │   ├── claude_client.py       # Cliente Claude API
│   │   ├── previred_fetcher.py    # Descarga PDF/HTML
│   │   ├── pdf_parser.py          # Parser PDF
│   │   ├── sii_scraper.py         # Scraper SII
│   │   └── db_session.py          # SQL Direct
│   ├── models/
│   │   └── odoo_hr.py             # SQLAlchemy models
│   ├── logging_config.py          # Structured logging
│   ├── metrics.py                 # Prometheus
│   ├── alerting.py                # Slack alerts
│   ├── audit_trail.py             # Blockchain audit
│   ├── rate_limiting.py           # Rate limiter
│   ├── security.py                # Security headers
│   ├── tracing.py                 # OpenTelemetry
│   └── cache.py                   # Redis cache
├── frontend/                      # React SPA (portal)
├── tests/                         # Pytest
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## 🎯 INTEGRACIÓN CON ODOO 19

### **Estrategia: REUTILIZAR TODO**

```python
# En Odoo 19: addons/localization/l10n_cl_hr_payroll/

# 1. Modelo hr.economic.indicators
@api.model
def fetch_from_ai_service(self, year, month):
    """
    Obtener indicadores desde EERGY AI
    """
    response = requests.post(
        f"{AI_SERVICE_URL}/api/v1/scraping/previred",
        json={"context": {"periodo": f"{year}-{month:02d}"}}
    )
    data = response.json()
    
    # Crear registro con 60 campos
    indicator = self.create({
        'period': date(year, month, 1),
        'uf': data['data']['uf'],
        'utm': data['data']['utm'],
        # ... 57 campos más
    })
    return indicator

# 2. Modelo hr.payslip
def action_compute_sheet(self):
    """
    Calcular liquidación usando Payroll-Service
    (EERGY AI puede extenderse para incluir cálculos)
    """
    # Preparar datos
    data = self._prepare_payroll_data()
    
    # Llamar servicio
    response = requests.post(
        f"{PAYROLL_SERVICE_URL}/api/payroll/calculate",
        json=data
    )
    
    # Aplicar resultados
    self._apply_results(response.json())

# 3. Validación IA (opcional)
def validate_with_ai(self):
    """
    Validar liquidación con Claude
    """
    response = requests.post(
        f"{AI_SERVICE_URL}/api/v1/validation/payslip",
        json=self._prepare_validation_data()
    )
    return response.json()
```

---

## 📋 PLAN DE ADAPTACIÓN

### **OPCIÓN A: Reutilizar EERGY AI Completo** ✅ RECOMENDADO

**Ventajas:**
- ✅ Microservicio ya existe (15.5/16 enterprise)
- ✅ 92 variables automáticas
- ✅ Portal empleados incluido
- ✅ Validación IA incluida
- ✅ Chat laboral incluido
- ✅ Solo agregar métodos en Odoo

**Adaptación:**
1. Copiar microservicio a stack Odoo 19
2. Actualizar conexión DB (Odoo 11 → Odoo 19)
3. Agregar métodos en modelos Odoo
4. Configurar docker-compose

**Tiempo:** 1 día

---

### **OPCIÓN B: Crear Payroll-Service Separado** ⚠️ NO RECOMENDADO

**Desventajas:**
- ❌ Duplicar funcionalidad
- ❌ Más código a mantener
- ❌ Perder portal empleados
- ❌ Perder validación IA

---

## ✅ DECISIÓN FINAL

**REUTILIZAR EERGY AI MICROSERVICE COMPLETO**

**Razones:**
1. Ya existe y funciona (enterprise-grade)
2. Incluye TODO lo que necesitamos:
   - Extracción indicadores (60 campos)
   - Portal empleados (SQL Direct)
   - Validación IA
   - Chat laboral
   - Audit trail
3. Solo agregar métodos en Odoo
4. Ahorro tiempo desarrollo: 4-6 semanas

**Arquitectura Odoo 19:**
```
ODOO 19 CE
└─ l10n_cl_hr_payroll
   ├─ Modelos (hr.contract, hr.payslip)
   ├─ Vistas XML
   └─ Métodos integración → EERGY AI

EERGY AI MICROSERVICE (Reutilizar)
├─ Scraping Previred/SII ✅
├─ Portal Empleados ✅
├─ Validación IA ✅
├─ Chat Laboral ✅
└─ Audit Trail ✅
```

**NO crear Payroll-Service separado**

---

## 📊 COMPARATIVA

| Aspecto | EERGY AI | Payroll-Service Nuevo |
|---------|----------|----------------------|
| **Extracción Previred** | ✅ 60 campos | ❌ A desarrollar |
| **Portal Empleados** | ✅ Completo | ❌ No incluido |
| **Validación IA** | ✅ Claude | ❌ A desarrollar |
| **Chat Laboral** | ✅ Claude | ❌ No incluido |
| **Audit Trail** | ✅ Blockchain | ❌ A desarrollar |
| **Enterprise Features** | ✅ 15.5/16 | ❌ Desde cero |
| **Tiempo desarrollo** | 1 día | 4-6 semanas |
| **Costo** | $0.30/año | Tiempo desarrollo |

**Ganador:** ✅ **EERGY AI**

---

## 🚀 PRÓXIMOS PASOS

1. ✅ Análisis completado
2. Copiar EERGY AI a stack Odoo 19
3. Actualizar conexión DB
4. Agregar métodos en modelos Odoo
5. Testing integración

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ ANÁLISIS COMPLETO
