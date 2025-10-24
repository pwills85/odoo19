# 🏗️ ARQUITECTURA TÉCNICA: Sistema Nóminas

**Proyecto:** l10n_cl_hr_payroll  
**Patrón:** Microservicios + IA (DTE-proven)

---

## 📊 ARQUITECTURA DE 4 CAPAS

```
┌─────────────────────────────────────────────────────────┐
│ CAPA 1: PRESENTACIÓN (Odoo UI)                         │
├─────────────────────────────────────────────────────────┤
│ • Views XML (form, tree, kanban)                       │
│ • Wizards (Previred, Finiquito)                        │
│ • Reportes QWeb (liquidación, finiquito)               │
│ • Assets (Chart.js, CSS)                               │
│                                                         │
│ Rescatado Odoo 11:                                     │
│ ✅ Design system CSS                                    │
│ ✅ Gráficos Chart.js                                    │
│ ✅ Reportes QWeb profesionales                          │
└─────────────────────────────────────────────────────────┘
                         ↓ HTTP/REST
┌─────────────────────────────────────────────────────────┐
│ CAPA 2: LÓGICA DE NEGOCIO (Odoo Models)               │
├─────────────────────────────────────────────────────────┤
│ • Models (_inherit hr.contract, hr.payslip)            │
│ • Business Logic (workflows, validaciones)             │
│ • Orquestación microservicios                          │
│ • Integración contable                                  │
│                                                         │
│ Patrón DTE (Odoo 18):                                  │
│ ✅ _inherit (EXTENDER, NO DUPLICAR)                     │
│ ✅ API Client (retry, circuit breaker)                  │
│ ✅ Async con RabbitMQ                                   │
│                                                         │
│ Rescatado Odoo 11:                                     │
│ ✅ 13 niveles herencia compute_sheet()                  │
│ ✅ Validaciones en cascada                              │
│ ✅ Snapshot indicadores (JSON)                          │
└─────────────────────────────────────────────────────────┘
                         ↓ HTTP/REST + RabbitMQ
┌─────────────────────────────────────────────────────────┐
│ CAPA 3: SERVICIOS (Microservicios)                     │
├─────────────────────────────────────────────────────────┤
│ PAYROLL-SERVICE (FastAPI - Python 3.11+)              │
│ ├─ Calculadoras                                         │
│ │  ├─ AFPCalculator                                     │
│ │  ├─ HealthCalculator                                  │
│ │  ├─ TaxCalculator                                     │
│ │  └─ GratificationCalculator                          │
│ ├─ Generadores                                          │
│ │  ├─ PreviredGenerator (105 campos)                   │
│ │  └─ SettlementCalculator (finiquito)                 │
│ └─ Validadores                                          │
│    ├─ LegalValidator                                    │
│    └─ MathematicalValidator                            │
│                                                         │
│ AI-SERVICE (Claude 3.5 Sonnet)                         │
│ ├─ Validación contratos                                 │
│ ├─ Detección anomalías                                  │
│ ├─ Optimización tributaria                             │
│ └─ Chat laboral (Knowledge Base)                       │
│                                                         │
│ Patrón DTE:                                            │
│ ✅ FastAPI async                                        │
│ ✅ Pydantic models                                      │
│ ✅ Structured logging                                   │
│ ✅ Circuit breaker                                      │
│ ✅ Retry logic                                          │
└─────────────────────────────────────────────────────────┘
                         ↓ SQL
┌─────────────────────────────────────────────────────────┐
│ CAPA 4: PERSISTENCIA (PostgreSQL 15+)                  │
├─────────────────────────────────────────────────────────┤
│ • Tablas Odoo (hr_contract, hr_payslip, etc.)         │
│ • Índices optimizados                                   │
│ • Constraints (unicidad, integridad)                   │
│ • Audit trail (7 años retención)                       │
│                                                         │
│ Rescatado Odoo 11:                                     │
│ ✅ Índices optimizados (performance)                    │
│ ✅ Constraints SQL (unicidad)                           │
│ ✅ Audit trail 7 años                                   │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 COMPONENTES PRINCIPALES

### **1. Módulo Odoo (l10n_cl_hr_payroll)**

**Estructura:**
```
l10n_cl_hr_payroll/
├── __manifest__.py
├── models/
│   ├── hr_contract_cl.py (_inherit hr.contract)
│   ├── hr_payslip_cl.py (crear hr.payslip)
│   ├── hr_settlement.py (finiquito)
│   ├── hr_afp.py, hr_isapre.py (maestros)
│   └── hr_economic_indicators.py
├── wizards/
│   ├── previred_export_wizard.py
│   └── settlement_wizard.py
├── tools/
│   ├── payroll_api_client.py
│   └── ai_api_client.py
├── views/
├── data/
├── security/
├── reports/
└── tests/ (80% coverage)
```

**Patrón DTE aplicado:**
- ✅ _inherit (no duplicar)
- ✅ API clients con retry
- ✅ Async con RabbitMQ
- ✅ Testing 80%

**Rescatado Odoo 11:**
- ✅ Estructura SOPA 2025
- ✅ Herencia en cascada
- ✅ Validaciones robustas

---

### **2. Payroll-Service (FastAPI)**

**Estructura:**
```
payroll-service/
├── main.py
├── config.py
├── calculators/
│   ├── afp_calculator.py
│   ├── health_calculator.py
│   ├── tax_calculator.py
│   └── gratification_calculator.py
├── generators/
│   ├── previred_generator.py
│   └── settlement_calculator.py
├── validators/
│   ├── legal_validator.py
│   └── mathematical_validator.py
├── models/
│   └── payroll_models.py (Pydantic)
└── tests/
```

**Features:**
- ✅ FastAPI async
- ✅ Pydantic validation
- ✅ Structured logging
- ✅ OpenAPI docs
- ✅ Testing 80%

---

### **3. AI-Service (Extensión)**

**Nuevos endpoints:**
```
POST /api/payroll/validate
POST /api/contract/analyze
POST /api/payroll/optimize
POST /api/chat/labor_query
```

**Rescatado Odoo 11:**
- ✅ Chat conversacional
- ✅ Knowledge base multi-módulo
- ✅ Validaciones inteligentes

---

## 🔄 FLUJO DE DATOS

### **Cálculo de Liquidación:**

```
1. Usuario → Odoo UI
   └─ Click "Calcular Liquidación"

2. Odoo → HrPayslipCL.action_compute_sheet()
   ├─ _prepare_payroll_data()
   │  └─ Extrae: employee, contract, period
   │
   ├─ HTTP POST → Payroll-Service
   │  └─ /api/payroll/calculate
   │     ├─ AFPCalculator.calculate()
   │     ├─ HealthCalculator.calculate()
   │     ├─ TaxCalculator.calculate()
   │     └─ GratificationCalculator.calculate()
   │
   ├─ HTTP POST → AI-Service (opcional)
   │  └─ /api/payroll/validate
   │     └─ Claude analiza y detecta anomalías
   │
   ├─ _apply_calculation_results()
   │  └─ Crea hr.payslip.line
   │
   └─ _save_indicators_snapshot()
      └─ Guarda JSON (Odoo 11 pattern)

3. Odoo → Usuario
   └─ Muestra liquidación + warnings IA
```

---

## 🛡️ PATRONES DE RESILIENCIA

### **1. Retry Logic (DTE pattern)**
```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def call_payroll_service(data):
    response = requests.post(url, json=data, timeout=30)
    response.raise_for_status()
    return response.json()
```

### **2. Circuit Breaker (DTE pattern)**
```python
from pybreaker import CircuitBreaker

payroll_breaker = CircuitBreaker(
    fail_max=5,
    timeout_duration=60
)

@payroll_breaker
def calculate_payslip(data):
    return call_payroll_service(data)
```

### **3. Graceful Degradation**
```python
try:
    result = calculate_payslip(data)
except CircuitBreakerError:
    # Fallback: cálculo básico local
    result = calculate_basic_payslip(data)
    logger.warning("Using fallback calculation")
```

---

## 📊 INTEGRACIÓN CON ODOO BASE

### **Aprovechamiento Odoo 19 CE:**

```python
# ✅ CORRECTO (patrón DTE)
class HrPayslipCL(models.Model):
    _inherit = 'hr.payslip'  # Extiende base
    
    # Solo campos Chile específicos
    previred_sent = fields.Boolean()
    indicators_snapshot = fields.Text()
    
    def action_compute_sheet(self):
        # Lógica custom
        # ...
        # Llama super() para workflow Odoo
        return super().action_compute_sheet()
```

**Módulos Odoo 19 CE usados:**
- ✅ `hr` (empleados)
- ✅ `hr_contract` (contratos)
- ✅ `hr_holidays` (vacaciones)
- ✅ `account` (contabilidad)
- ✅ `l10n_cl` (localización Chile)

---

## 🔐 SEGURIDAD

### **1. API Authentication**
```python
# Bearer token (como DTE)
headers = {
    'Authorization': f'Bearer {API_KEY}',
    'Content-Type': 'application/json'
}
```

### **2. Encriptación**
- ✅ HTTPS/TLS
- ✅ Secrets en .env
- ✅ API keys rotables

### **3. Audit Trail**
- ✅ Todos los cambios registrados
- ✅ Usuario, timestamp, IP
- ✅ Retención 7 años (Art. 54 CT)

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0
