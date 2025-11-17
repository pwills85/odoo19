# 🎯 ESTRATEGIA DE ADAPTACIÓN: Odoo 11 → Odoo 19

**Fecha:** 2025-10-22  
**Objetivo:** Adaptar sistema de nóminas desde Odoo 11 CE a Odoo 19 CE

---

## 📊 SITUACIÓN ACTUAL (Odoo 11 CE)

### **Sistema DUAL en Producción**

```
┌─────────────────────────────────────────────────────────┐
│ ODOO 11 CE (Ambiente Upgrade)                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. SISTEMA LEGACY (2018 - julio 2025)                 │
│    └─ Solo VISUALIZACIÓN de nóminas históricas        │
│    └─ Datos en BBDD PostgreSQL                        │
│    └─ NO genera nuevas liquidaciones                  │
│                                                         │
│ 2. SISTEMA SOPA 2025 (agosto 2025+)                   │
│    └─ GESTIÓN ACTIVA de nóminas                       │
│    └─ Genera liquidaciones nuevas                     │
│    └─ Reforma Previsional 2025                        │
│    └─ 38,852 LOC Python                               │
│                                                         │
│ 3. MICROSERVICIO PORTAL EMPLEADO                      │
│    └─ FastAPI (ya existe)                             │
│    └─ Consulta de liquidaciones                       │
│    └─ Descarga de documentos                          │
│    └─ Self-service                                     │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 OBJETIVO: Odoo 19 CE (Sistema Moderno)

### **Sistema ÚNICO con Microservicios**

```
┌─────────────────────────────────────────────────────────┐
│ ODOO 19 CE (l10n_cl_hr_payroll)                       │
├─────────────────────────────────────────────────────────┤
│ • Sistema ÚNICO (no dual)                              │
│ • Datos históricos MIGRADOS (2018-2025)               │
│ • Gestión activa desde agosto 2025                    │
│ • Arquitectura microservicios                         │
│ • ~5,500 LOC (vs 38,852)                              │
└──────────────┬──────────────────────────────────────────┘
               │
    ┌──────────┴──────────────────┐
    │                             │
┌───▼────────────┐    ┌──────────▼─────────┐
│ PAYROLL-       │    │ EMPLOYEE-          │
│ SERVICE        │    │ PORTAL             │
│ (nuevo)        │    │ (adaptar existente)│
├────────────────┤    ├────────────────────┤
│ • Cálculos     │    │ • Consultas        │
│ • Previred     │    │ • Descargas        │
│ • Finiquito    │    │ • Self-service     │
│ • Validaciones │    │ • Integración      │
└────────────────┘    │   Odoo 19          │
                      └────────────────────┘
           │
    ┌──────▼──────┐
    │ AI-SERVICE  │
    │ (extender)  │
    ├─────────────┤
    │ • Validación│
    │ • Chatbot   │
    │ • Analytics │
    └─────────────┘
```

---

## 🔄 ESTRATEGIA DE ADAPTACIÓN

### **FASE 1: Migración de Datos Históricos**

**Objetivo:** Traer datos Legacy (2018-julio 2025) a Odoo 19

```python
# Script: migrate_historical_data.py

# 1. Extraer de Odoo 11 (BBDD Legacy)
SELECT * FROM hr_payslip 
WHERE date_from >= '2018-01-01' 
  AND date_from < '2025-08-01';  # Pre-SOPA

# 2. Transformar
# - Mapear campos Odoo 11 → Odoo 19
# - Preservar snapshot de indicadores
# - Mantener audit trail

# 3. Cargar en Odoo 19
# - Insertar en hr_payslip (Odoo 19)
# - Marcar como "historical" (read-only)
# - Vincular con empleados/contratos
```

**Resultado:**
- ✅ Datos históricos visibles en Odoo 19
- ✅ Continuidad total (2018-presente)
- ✅ Un solo sistema

---

### **FASE 2: Adaptar Lógica SOPA 2025**

**De:** Odoo 11 (monolito)  
**A:** Payroll-Service (microservicio)

```python
# Odoo 11 (monolito - 38,852 LOC)
class HrPayslip(models.Model):
    def compute_sheet(self):
        # 13 niveles de herencia
        # Cálculos AFP, Salud, Impuesto
        # Previred, Finiquito
        # Todo en Odoo
        # ...

# Odoo 19 (microservicios - 5,500 LOC)
class HrPayslipCL(models.Model):
    _inherit = 'hr.payslip'
    
    def action_compute_sheet(self):
        # 1. Preparar datos
        data = self._prepare_payroll_data()
        
        # 2. Llamar Payroll-Service
        result = requests.post(
            f"{PAYROLL_SERVICE_URL}/api/payroll/calculate",
            json=data
        )
        
        # 3. Aplicar resultados
        self._apply_results(result.json())
        
        return super().action_compute_sheet()
```

**Extracción de Lógica:**

| Componente Odoo 11 | Destino Odoo 19 | Acción |
|--------------------|-----------------|--------|
| `hr_payslip_sopa_basic.py` | Payroll-Service | Extraer algoritmos |
| `hr_payslip_afp_sopa.py` | AFPCalculator | Copiar lógica |
| `hr_payslip_salud_sopa.py` | HealthCalculator | Copiar lógica |
| `hr_payslip_impuesto_sopa.py` | TaxCalculator | Copiar lógica |
| `wizard_export_csv_previred.py` | PreviredGenerator | Adaptar |
| `hr_settlement.py` | SettlementCalculator | Adaptar |

---

### **FASE 3: Adaptar Portal Empleado**

**Microservicio Existente:** `/microservices/employee-portal/`

**Cambios Necesarios:**

```python
# Antes (Odoo 11)
@app.get("/api/payslips/{employee_id}")
async def get_payslips(employee_id: int):
    # Conecta a Odoo 11
    odoo11 = xmlrpc.client.ServerProxy('http://odoo11:8069')
    payslips = odoo11.execute_kw(
        db, uid, password,
        'hr.payslip', 'search_read',
        [[('employee_id', '=', employee_id)]]
    )
    return payslips

# Después (Odoo 19)
@app.get("/api/payslips/{employee_id}")
async def get_payslips(employee_id: int):
    # Conecta a Odoo 19
    odoo19 = xmlrpc.client.ServerProxy('http://odoo19:8069')
    
    # Trae TODOS los datos (históricos + nuevos)
    payslips = odoo19.execute_kw(
        db, uid, password,
        'hr.payslip', 'search_read',
        [[('employee_id', '=', employee_id)]],
        {'order': 'date_from desc'}
    )
    return payslips
```

**Ventaja:** Portal ve TODO el historial (2018-presente) desde un solo origen

---

### **FASE 4: Integración AI-Service**

**Extender AI-Service existente** con capacidades de nóminas:

```python
# ai-service/payroll/
├── contract_validator.py      # Nuevo
├── anomaly_detector.py         # Nuevo
├── tax_optimizer.py            # Nuevo
└── labor_chatbot.py            # Nuevo

# Endpoints nuevos
POST /api/payroll/validate
POST /api/contract/analyze
POST /api/payroll/optimize
POST /api/chat/labor_query
```

---

## 📋 PLAN DE MIGRACIÓN DETALLADO

### **Sprint 0: Preparación (1 semana)**

**Objetivo:** Preparar ambientes y datos

```bash
# 1. Backup completo Odoo 11
pg_dump odoo11_db > odoo11_backup_$(date +%Y%m%d).sql

# 2. Análisis de datos
python scripts/analyze_legacy_data.py

# 3. Mapeo de campos
python scripts/map_fields_odoo11_to_19.py

# 4. Validación integridad
python scripts/validate_data_integrity.py
```

**Entregables:**
- ✅ Backup seguro
- ✅ Análisis de datos completo
- ✅ Mapeo de campos documentado
- ✅ Plan de migración validado

---

### **Sprint 1-4: Implementación Core (4 semanas)**

**Según plan:** `03_IMPLEMENTATION_PHASES.md`

- Módulo Odoo 19 base
- Payroll-Service con calculadoras
- Integración Odoo ↔ Payroll-Service

---

### **Sprint 5: Migración de Datos (1 semana)**

**Objetivo:** Migrar datos históricos 2018-julio 2025

```python
# migration/migrate_historical_payslips.py

class HistoricalDataMigrator:
    def migrate_payslips(self):
        # 1. Extraer de Odoo 11
        legacy_payslips = self.extract_from_odoo11(
            date_from='2018-01-01',
            date_to='2025-07-31'
        )
        
        # 2. Transformar
        transformed = self.transform_to_odoo19(legacy_payslips)
        
        # 3. Cargar en Odoo 19
        self.load_to_odoo19(transformed)
        
        # 4. Validar
        self.validate_migration()
```

**Datos a migrar:**
- ✅ ~42,000 liquidaciones (2018-julio 2025)
- ✅ ~420,000 líneas de liquidación
- ✅ ~168,000 inputs
- ✅ Contratos históricos
- ✅ Indicadores económicos

---

### **Sprint 6: Adaptación Portal (1 semana)**

**Objetivo:** Adaptar Employee-Portal a Odoo 19

```python
# Cambios en employee-portal/

# 1. Actualizar conexión
ODOO_URL = "http://odoo19:8069"  # Era odoo11:8069

# 2. Actualizar queries
# - Mismo modelo (hr.payslip)
# - Mismos campos (compatibilidad)
# - Ahora incluye históricos

# 3. Testing
# - Verificar acceso a datos históricos
# - Verificar acceso a datos nuevos
# - Verificar descarga PDFs
```

---

### **Sprint 7-10: Compliance + IA (4 semanas)**

**Según plan:** `03_IMPLEMENTATION_PHASES.md`

- Previred + Finiquito
- Audit Trail
- Validación IA
- Optimización

---

## 🎯 RESULTADO FINAL

### **Sistema Unificado Odoo 19**

```
┌─────────────────────────────────────────────────────────┐
│ ODOO 19 CE - SISTEMA ÚNICO                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ DATOS HISTÓRICOS (2018-julio 2025)                    │
│ └─ Migrados desde Odoo 11                             │
│ └─ Read-only, visualización                           │
│ └─ Continuidad total                                  │
│                                                         │
│ DATOS NUEVOS (agosto 2025+)                           │
│ └─ Generados en Odoo 19                               │
│ └─ Sistema SOPA 2025                                  │
│ └─ Microservicios                                     │
│                                                         │
│ PORTAL EMPLEADO                                        │
│ └─ Ve TODO el historial                               │
│ └─ Self-service completo                              │
│ └─ Integración única                                  │
└─────────────────────────────────────────────────────────┘
```

---

## ✅ VENTAJAS DE ESTA ESTRATEGIA

### **1. Continuidad Total**
- ✅ Empleado ve historial completo (2018-presente)
- ✅ Sin sistemas paralelos
- ✅ Una sola fuente de verdad

### **2. Arquitectura Moderna**
- ✅ Microservicios (escalable)
- ✅ IA integrada
- ✅ Testing 80%
- ✅ Performance optimizado

### **3. Aprovechamiento de Trabajo**
- ✅ Lógica SOPA 2025 rescatada
- ✅ Portal empleado adaptado (no reescrito)
- ✅ Validaciones probadas
- ✅ Conocimiento preservado

### **4. Reducción de Complejidad**
- ✅ 38,852 LOC → 5,500 LOC (85% reducción)
- ✅ Sistema dual → Sistema único
- ✅ Monolito → Microservicios

---

## 📊 COMPARATIVA

| Aspecto | Odoo 11 (Actual) | Odoo 19 (Objetivo) |
|---------|------------------|---------------------|
| **Arquitectura** | Monolito + Portal | Microservicios + Portal |
| **Sistemas** | Dual (Legacy + SOPA) | Único (unificado) |
| **LOC** | 38,852 | 5,500 |
| **Datos** | Separados | Unificados |
| **Portal** | Conecta Odoo 11 | Conecta Odoo 19 |
| **IA** | Básica | Avanzada (Claude) |
| **Testing** | Básico | 80% coverage |
| **Mantenibilidad** | Baja | Alta |

---

## 🎯 PRÓXIMOS PASOS

1. **Aprobar estrategia** ✅ Este documento
2. **Iniciar Sprint 0** (preparación)
3. **Ejecutar migración** (Sprint 5)
4. **Adaptar portal** (Sprint 6)
5. **Go-live** (Semana 11)

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ ESTRATEGIA DEFINIDA
