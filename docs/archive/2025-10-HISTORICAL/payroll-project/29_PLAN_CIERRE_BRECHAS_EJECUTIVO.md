# 🎯 PLAN CIERRE DE BRECHAS - Sistema Nóminas Chile Odoo 19 CE

**Fecha:** 2025-10-23 03:00 UTC  
**Módulo:** l10n_cl_hr_payroll  
**Stack:** Odoo 19 CE + Payroll-Service + AI-Service  
**Referencia:** SOPA 2025 (Odoo 11 CE)  
**Ruta Odoo 11:** `/Users/pedro/Documents/oficina_server1/produccion/prod_odoo-11_eergygroup_backup/addons/l10n_cl_hr`

---

## 📊 ESTADO ACTUAL

### Progreso General
```
MÓDULO ODOO (Core):              85% ████████████████▓▓▓
MICROSERVICIOS:                   0% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
AI INTEGRATION:                   0% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
─────────────────────────────────────────────────────────
TOTAL PROYECTO:                  73% ██████████████▓▓▓▓▓▓
```

### Código Actual
- **Líneas totales:** 5,235 líneas (Python + XML)
- **Modelos:** 14 archivos Python
- **Vistas:** 9 archivos XML
- **Datos:** 3 archivos XML (categorías SOPA)

### Análisis vs SOPA 2025 (Odoo 11)

| Componente | Odoo 11 SOPA | Odoo 19 Actual | Estado | Gap |
|------------|--------------|----------------|--------|-----|
| **Ficha Trabajador** | hr.employee + campos CL | hr.employee base | ✅ 95% | Completar campos Chile |
| **Contrato** | hr.contract + 25 campos | hr.contract + 20 campos | ✅ 90% | APV, gratificación |
| **Input SOPA** | hr.payslip.input | hr.payslip.input | ✅ 95% | Validaciones |
| **Estructura Salarial** | 22 categorías SOPA | 22 categorías SOPA | ✅ 100% | ✅ Completo |
| **Categorías Salariales** | 8 raíz + 14 sub | 8 raíz + 14 sub | ✅ 100% | ✅ Completo |
| **Totalizadores** | 4 totales SOPA | 4 totales SOPA | ✅ 100% | ✅ Completo |
| **Reglas Salariales** | 45 reglas | 30 reglas | ⚠️ 85% | 15 reglas faltantes |
| **Generación Nóminas** | Pipeline 9 pasos | Pipeline 9 pasos | ✅ 95% | Optimizar |
| **Reportes Nóminas** | 5 reportes PDF | 1 reporte básico | ❌ 20% | 4 reportes |
| **Previred** | Archivo 105 campos | ❌ No existe | ❌ 0% | Completo |
| **Libro Remuneraciones** | Excel + PDF | ❌ No existe | ❌ 0% | Completo |
| **Finiquito** | Modelo completo | ❌ No existe | ❌ 0% | Completo |
| **Payroll-Service** | N/A (monolítico) | ❌ No existe | ❌ 0% | Completo |
| **AI Integration** | N/A | ❌ No existe | ❌ 0% | Completo |

---

## 🔥 BRECHAS CRÍTICAS (PRIORIDAD ALTA)

### 1. Reglas Salariales Críticas (85% → 100%)

#### **Faltantes vs SOPA 2025:**

**A. Gratificación Legal (Art. 50 CT)** ❌
```python
# Odoo 11: hr_payslip_gratificacion.py
# Cálculo: 25% utilidades anuales, tope 4.75 IMM
# Método: Mensualización proporcional
# Odoo 19: NO EXISTE
```

**B. Asignación Familiar (DFL 150)** ❌
```python
# Odoo 11: hr_payslip_asignacion_familiar.py
# Tramos por ingreso: $434,162, $634,691, $988,204
# Montos: $13,193 / $8,120 / $2,563
# Odoo 19: NO EXISTE
```

**C. Aportes Empleador Reforma 2025** ❌
```python
# Odoo 11: hr_payslip_aportes_empleador.py
# 1. Seguro Invalidez y Sobrevivencia (SIS): 1.53%
# 2. Seguro Cesantía: 2.4% (indefinido) / 3.0% (plazo fijo)
# 3. CCAF: 0.6% (sobre imponible)
# Odoo 19: NO EXISTE
```

**D. Impuesto Único Tramo Exento** ⚠️
```python
# Odoo 11: 7 tramos, incluye exento hasta 13.5 UTM
# Odoo 19: 7 tramos, FALTA validar tramo exento
# Gap: Revisar umbral exento
```

### 2. Reportes Legales (20% → 100%)

#### **Requeridos por Ley:**

**A. Liquidación Individual PDF** ❌
- Formato DT (Dirección del Trabajo)
- Secciones: Haberes, Descuentos Legales, Otros Descuentos
- Total Líquido a pagar
- Firma empleador + trabajador

**B. Libro de Remuneraciones (Excel)** ❌
- Art. 62 Código del Trabajo
- Columnas: RUT, Nombre, Período, Haberes, Descuentos
- Totales por empresa
- Formato Excel exportable

**C. Previred (TXT 105 campos)** ❌
- Formato oficial Previred
- 105 campos obligatorios
- Validación archivo antes envío
- Certificado F30-1

**D. Certificado F30-1 (PDF)** ❌
- Certificado cotizaciones pagadas
- Requerido por Previred
- Formato oficial

**E. Resumen Contable** ❌
- Asientos contables automáticos
- Integración con account.move
- Cuentas por pagar empleados

### 3. Finiquito (0% → 100%)

#### **Componentes Faltantes:**

**A. Modelo hr.settlement** ❌
```python
# Campos:
# - employee_id, contract_id
# - date_from, date_to, termination_date
# - termination_reason (Art. 159, 160, 161, 168 CT)
# - vacation_days, vacation_amount
# - indemnity_years, indemnity_notice
# - total_settlement
```

**B. Cálculos Legales** ❌
- Sueldo proporcional
- Vacaciones proporcionales (1.25 días/mes)
- Indemnización años servicio (30 días × años, tope 11 años, 90 UF/mes)
- Indemnización aviso previo (30 días)
- Indemnización Art. 163 bis (6-11 meses según antigüedad)

**C. Reporte PDF Legal** ❌
- Formato DT
- Desglose completo
- Firma trabajador + empleador

---

## 🏗️ ARQUITECTURA STACK COMPLETO

### Flujo: Ficha Trabajador → Reporte Legal

```
┌─────────────────────────────────────────────────────────────────┐
│                        CAPA ODOO 19 CE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. FICHA TRABAJADOR (hr.employee - Base Odoo) ✅ 95%           │
│     ├─> RUT (l10n_cl)                                           │
│     ├─> Nombre, Fecha nacimiento                                │
│     ├─> Dirección, Comuna                                       │
│     ├─> AFP, ISAPRE, APV                                        │
│     └─> Cargas familiares                                       │
│                                                                   │
│  2. CONTRATO TRABAJADOR (hr.contract_cl) ✅ 90%                 │
│     ├─> Sueldo base (wage)                                      │
│     ├─> Fecha inicio/fin                                        │
│     ├─> Tipo jornada (completa/parcial)                         │
│     ├─> AFP, ISAPRE, APV ✅                                      │
│     ├─> Colación, Movilización ✅                                │
│     ├─> Cargas familiares ✅                                     │
│     ├─> Gratificación mensual ❌ FALTANTE                       │
│     └─> Tipo contrato (indefinido/plazo fijo) ❌ FALTANTE      │
│                                                                   │
│  3. INPUT SOPA (hr.payslip.input) ✅ 95%                        │
│     ├─> Horas extras (HEX50, HEX100, HEXDE) ✅                  │
│     ├─> Bonos imponibles ✅                                      │
│     ├─> Bonos NO imponibles ✅                                   │
│     ├─> Descuentos varios ✅                                     │
│     └─> Validaciones avanzadas ❌ MEJORAR                       │
│                                                                   │
│  4. ESTRUCTURA SALARIAL (hr.payroll.structure) ✅ 100%          │
│     └─> 22 categorías SOPA 2025 ✅                              │
│                                                                   │
│  5. CATEGORÍAS SALARIALES (hr.salary.rule.category) ✅ 100%     │
│     ├─> 8 raíz ✅                                                │
│     ├─> 5 sub haberes ✅                                         │
│     ├─> 3 sub descuentos ✅                                      │
│     └─> 6 SOPA específicas ✅                                    │
│                                                                   │
│  6. TOTALIZADORES SALARIALES ✅ 100%                             │
│     ├─> total_haberes ✅                                         │
│     ├─> total_imponible (AFP/Salud) ✅                           │
│     ├─> total_tributable (Impuesto) ✅                           │
│     └─> total_gratificacion_base ✅                              │
│                                                                   │
│  7. REGLAS SALARIALES (hr.salary.rule) ⚠️ 85%                   │
│     ├─> Sueldo Base ✅                                           │
│     ├─> Horas Extras ✅                                          │
│     ├─> Bonos ✅                                                 │
│     ├─> AFP ✅                                                   │
│     ├─> Salud (FONASA/ISAPRE) ✅                                │
│     ├─> AFC ✅                                                   │
│     ├─> Impuesto Único ✅                                        │
│     ├─> Gratificación Legal ❌ FALTANTE                         │
│     ├─> Asignación Familiar ❌ FALTANTE                         │
│     └─> Aportes Empleador ❌ FALTANTE                           │
│                                                                   │
│  8. GENERACIÓN DE NÓMINAS (hr.payslip) ✅ 95%                   │
│     ├─> Pipeline 9 pasos ✅                                      │
│     │   1. Validar contrato                                     │
│     │   2. Obtener inputs                                       │
│     │   3. Calcular haberes                                     │
│     │   4. Calcular imponible                                   │
│     │   5. Calcular descuentos                                  │
│     │   6. Calcular impuesto                                    │
│     │   7. Calcular líquido                                     │
│     │   8. Generar líneas                                       │
│     │   9. Validar totales                                      │
│     └─> Workflow: borrador → validar → confirmar → pagar ✅     │
│                                                                   │
│  9. REPORTES DE NÓMINAS ❌ 20%                                   │
│     ├─> Liquidación Individual PDF ❌                           │
│     ├─> Reporte básico Odoo ✅ (limitado)                       │
│     └─> Exportación Excel ❌                                    │
│                                                                   │
│  10. REPORTES PREVIRED ❌ 0%                                     │
│     ├─> Archivo TXT 105 campos ❌                               │
│     ├─> Certificado F30-1 PDF ❌                                │
│     └─> Validador formato ❌                                    │
│                                                                   │
│  11. LIBRO DE REMUNERACIONES ❌ 0%                               │
│     ├─> Excel mensual ❌                                        │
│     ├─> PDF firmado ❌                                          │
│     └─> Totales empresa ❌                                      │
│                                                                   │
│  12. FINIQUITO ❌ 0%                                             │
│     ├─> Modelo hr.settlement ❌                                 │
│     ├─> Cálculos legales ❌                                     │
│     └─> Reporte PDF ❌                                          │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    PAYROLL-SERVICE (FastAPI)                     │
│                        Puerto 8003 - Python                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  CÁLCULOS COMPLEJOS ❌ 0%                                        │
│     ├─> Gratificación Legal (Art. 50 CT)                        │
│     ├─> Finiquito (indemnizaciones)                             │
│     ├─> Horas extras jornada parcial                            │
│     └─> Optimización tributaria APV                             │
│                                                                   │
│  GENERACIÓN ARCHIVOS LEGALES ❌ 0%                               │
│     ├─> Previred TXT                                            │
│     ├─> Libro Remuneraciones Excel                              │
│     ├─> Certificados PDF                                        │
│     └─> Validadores formato                                     │
│                                                                   │
│  SCRAPER PREVIRED ❌ 0%                                          │
│     ├─> Tasas AFP actualización automática                      │
│     ├─> Valores UF, UTM, IPC                                    │
│     └─> Alertas cambios normativos                              │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     AI-SERVICE (Claude 3.5)                      │
│                        Puerto 8002 - Python                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  VALIDACIÓN CONTRATOS ❌ 0%                                      │
│     ├─> Detectar inconsistencias                                │
│     ├─> Sugerir correcciones                                    │
│     └─> Validar compliance legal                                │
│                                                                   │
│  OPTIMIZACIÓN TRIBUTARIA ❌ 0%                                   │
│     ├─> Análisis APV óptimo                                     │
│     ├─> Simulaciones sueldo líquido                             │
│     └─> Recomendaciones empleado                                │
│                                                                   │
│  CHAT LABORAL IA ❌ 0%                                           │
│     ├─> Consultas Código del Trabajo                            │
│     ├─> Cálculo manual finiquitos                               │
│     └─> Explicaciones liquidación                               │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 PLAN DE CIERRE DETALLADO

### **FASE 1: COMPLETAR MÓDULO ODOO (37h)**

#### Sprint 4.1: Reglas Salariales Críticas (16h)

**Objetivo:** Implementar 3 reglas faltantes

**Día 1 (8h): Gratificación Legal**
```python
# Archivo: models/hr_salary_rule_gratificacion.py
# Método: calculate_gratificacion()
# - Obtener utilidades anuales empresa
# - Calcular 25% / número trabajadores
# - Aplicar tope 4.75 IMM
# - Mensualizar (dividir / 12)
# Test: tests/test_gratificacion.py (6 casos)
```

**Día 2 (4h): Asignación Familiar**
```python
# Archivo: models/hr_salary_rule_asignacion_familiar.py
# Método: calculate_asignacion_familiar()
# - Obtener ingreso imponible mes anterior
# - Determinar tramo (3 tramos)
# - Calcular monto por carga (simple/maternal)
# Test: tests/test_asignacion_familiar.py (5 casos)
```

**Día 3 (4h): Aportes Empleador**
```python
# Archivo: models/hr_salary_rule_aportes_empleador.py
# 3 Reglas:
# 1. SIS: 1.53% imponible
# 2. Seguro Cesantía: 2.4% o 3.0%
# 3. CCAF: 0.6% imponible
# Test: tests/test_aportes_empleador.py (4 casos)
```

**Entregable:**
- 3 archivos Python (350 líneas)
- 3 archivos tests (180 líneas)
- Data XML con 15 reglas nuevas

---

#### Sprint 4.2: Ficha Trabajador + Contrato (8h)

**Día 4 (4h): Completar hr.employee**
```python
# Archivo: models/hr_employee_cl.py
# Campos faltantes:
# - pension_situation (pensionado/jubilado)
# - disability_type (discapacidad, si aplica)
# - nationality (nacionalidad)
# Vista: views/hr_employee_views.xml
```

**Día 5 (4h): Completar hr.contract_cl**
```python
# Archivo: models/hr_contract_cl.py
# Campos faltantes:
# - contract_type (indefinido/plazo_fijo/honorarios)
# - gratification_type (mensual/anual/mixta)
# - gratification_amount (monto fijo mensual)
# - overtime_allowed (permite horas extras)
# Vista: views/hr_contract_views.xml
```

---

#### Sprint 4.3: Lotes Nómina + Validaciones (8h)

**Día 6 (4h): Completar hr.payslip.run**
```python
# Archivo: models/hr_payslip_run.py
# Métodos faltantes:
# - validate_batch() # Validar todas liquidaciones
# - generate_summary() # Reporte consolidado
# - export_accounting() # Asientos contables
```

**Día 7 (4h): Validaciones avanzadas**
```python
# Archivo: models/hr_payslip_validations.py
# Validaciones:
# - Topes AFP (87.8 UF)
# - Topes AFC (120.2 UF)
# - Impuesto negativo = 0
# - Total líquido >= 0
# - Imponible <= tope
```

---

#### Sprint 4.4: Testing + Docs (5h)

**Día 8 (5h): Tests integración + Docs**
```bash
# Tests:
# - test_payslip_full_flow.py (workflow completo)
# - test_batch_processing.py (lotes masivos)
# - test_validations.py (casos borde)

# Docs:
# - USER_GUIDE.md (guía usuario)
# - DEVELOPER_GUIDE.md (guía técnica)
```

**Entregable Fase 1:**
- Módulo Odoo al 100%
- 22 reglas salariales completas
- 80% cobertura tests
- Documentación completa

---

### **FASE 2: REPORTES LEGALES (52h)**

#### Sprint 5.1: Liquidación Individual PDF (12h)

**Día 9-10 (12h): Reporte PDF formato DT**
```python
# Archivo: reports/report_payslip_individual.py
# Método: _get_report_values()
# 
# Secciones:
# 1. Encabezado (empresa, trabajador, período)
# 2. Haberes (base + variables)
# 3. Descuentos Previsionales (AFP, Salud, AFC)
# 4. Descuentos Tributarios (Impuesto Único)
# 5. Otros Descuentos
# 6. Total Líquido
# 7. Firmas

# Template: reports/report_payslip_individual.xml
# Librería: wkhtmltopdf (ya disponible en Odoo)
```

---

#### Sprint 5.2: Libro de Remuneraciones (16h)

**Día 11-13 (16h): Excel + PDF mensual**
```python
# Archivo: reports/report_payroll_book.py
# Método: generate_payroll_book()
# 
# Excel:
# - Columnas: RUT, Nombre, Período, Días, Haberes, Descuentos, Líquido
# - Totales por columna
# - Formato contable (moneda CLP)
# Librería: xlsxwriter

# PDF:
# - Misma data en formato PDF
# - Firma empleador
# Template: reports/report_payroll_book.xml
```

---

#### Sprint 5.3: Resumen Contable (8h)

**Día 14 (8h): Asientos contables automáticos**
```python
# Archivo: models/hr_payslip_accounting.py
# Método: generate_accounting_entries()
# 
# Asientos:
# 1. Cargo Gastos RRHH
# 2. Abono Cuentas por Pagar Empleados
# 3. Abono Provisiones AFP/Salud/AFC
# 4. Abono Retenciones Impuesto
# 
# Integración: account.move (Odoo CE)
```

**Entregable Fase 2:**
- 3 reportes funcionales
- Integración contable
- Exportación Excel/PDF

---

### **FASE 3: PREVIRED + FINIQUITO (64h)**

#### Sprint 6.1: Previred TXT 105 campos (24h)

**Día 15-17 (24h): Generador archivo oficial**
```python
# Archivo: reports/previred_generator.py
# Método: generate_previred_file()
# 
# Formato: TXT ancho fijo
# Líneas:
# 1. Encabezado empresa
# 2. Detalle empleados (105 campos c/u)
# 3. Totales
# 
# Campos críticos:
# - RUT empleado
# - Período cotización
# - Días trabajados
# - Remuneración imponible AFP
# - Remuneración imponible Salud
# - Cotización AFP
# - Cotización Salud
# - Seguro Cesantía
# - SIS, CCAF, etc.
# 
# Validador: previred_validator.py
# - Checksum
# - Formato campos
# - Totales cuadrados
```

---

#### Sprint 6.2: Finiquito Base (16h)

**Día 18-19 (16h): Modelo + cálculos básicos**
```python
# Archivo: models/hr_settlement.py
# Clase: HrSettlement
# 
# Campos:
# - employee_id, contract_id
# - termination_date, termination_reason
# - vacation_days, vacation_amount
# - days_worked_month, proportional_salary
# - total_settlement
# 
# Métodos:
# - calculate_proportional_salary()
# - calculate_proportional_vacation()
# - calculate_total()
# 
# Vista: views/hr_settlement_views.xml
# Wizard: wizards/hr_settlement_wizard.py
```

---

#### Sprint 6.3: Certificado F30-1 (8h)

**Día 20 (8h): Certificado PDF Previred**
```python
# Archivo: reports/report_previred_certificate.py
# Template: reports/report_previred_certificate.xml
# 
# Contenido:
# - Datos empleador
# - Período cotización
# - Detalle cotizaciones AFP/Salud/AFC
# - Totales pagados
# - Firma digital (opcional)
```

---

#### Sprint 6.4: Libro Remuneraciones Alternativo (16h)

**Día 21-22 (16h): Formato DT alternativo**
```python
# Archivo: reports/report_payroll_book_dt.py
# Template: Formato oficial DT
# 
# Diferencia vs anterior:
# - Estructura oficial DT
# - Más columnas legales
# - Formato auditable
```

**Entregable Fase 3:**
- Previred TXT completo
- Finiquito base funcional
- Certificados F30-1

---

### **FASE 4: PAYROLL-SERVICE (40h)**

#### Sprint 7.1: Setup FastAPI (8h)

**Día 23 (8h): Estructura microservicio**
```python
# Estructura:
payroll-service/
├── main.py                 # FastAPI app
├── routers/
│   ├── gratification.py   # /api/v1/gratification
│   ├── settlement.py      # /api/v1/settlement
│   ├── previred.py        # /api/v1/previred
│   └── scraper.py         # /api/v1/scraper
├── services/
│   ├── gratification_calculator.py
│   ├── settlement_calculator.py
│   ├── previred_generator.py
│   └── previred_scraper.py
├── models/
│   └── schemas.py
├── tests/
│   └── test_*.py
├── requirements.txt
└── Dockerfile

# Docker Compose:
# - Puerto 8003
# - Conexión Redis
# - Logs estructurados
```

---

#### Sprint 7.2: Endpoint Gratificación (8h)

**Día 24 (8h): Cálculo Art. 50 CT**
```python
# Archivo: services/gratification_calculator.py
# Endpoint: POST /api/v1/gratification/calculate
# 
# Input:
# {
#   "company_profit": 100000000,  # Utilidades año
#   "num_employees": 50,
#   "employee_salary": 800000,
#   "months_worked": 12
# }
# 
# Output:
# {
#   "monthly_gratification": 33333,
#   "annual_gratification": 400000,
#   "cap_applied": false,
#   "imm_value": 539454
# }
```

---

#### Sprint 7.3: Endpoint Finiquito (8h)

**Día 25 (8h): Cálculos indemnizaciones**
```python
# Archivo: services/settlement_calculator.py
# Endpoint: POST /api/v1/settlement/calculate
# 
# Input:
# {
#   "employee_id": 123,
#   "contract_start": "2020-01-01",
#   "termination_date": "2025-10-23",
#   "termination_reason": "art_161",  # Despido
#   "last_salary": 1200000,
#   "vacation_days": 10
# }
# 
# Output:
# {
#   "proportional_salary": 400000,
#   "proportional_vacation": 200000,
#   "indemnity_years": 7200000,  # 30 días × 6 años
#   "indemnity_notice": 1200000,
#   "total_settlement": 9000000
# }
```

---

#### Sprint 7.4: Scraper Previred (8h)

**Día 26 (8h): Actualización automática**
```python
# Archivo: services/previred_scraper.py
# Endpoint: POST /api/v1/scraper/run
# 
# Scraping:
# 1. Tasas AFP (10 fondos)
# 2. UF, UTM, UTA, IPC
# 3. Tramos Asignación Familiar
# 4. Tramos Impuesto Único
# 
# Storage: Redis (cache 7 días)
# Notificaciones: Slack (cambios detectados)
```

---

#### Sprint 7.5: Testing + CI/CD (8h)

**Día 27 (8h): Tests + Deployment**
```bash
# Tests:
pytest tests/ --cov=. --cov-report=html

# CI/CD GitHub Actions:
# - Lint (flake8, black)
# - Tests (pytest)
# - Build Docker image
# - Deploy staging

# Métricas:
# - 80% cobertura tests
# - p95 latency < 500ms
# - 0 vulnerabilidades críticas
```

**Entregable Fase 4:**
- Payroll-Service operacional
- 4 endpoints funcionales
- CI/CD configurado

---

### **FASE 5: FINIQUITO COMPLETO (32h)**

#### Sprint 8.1: Indemnizaciones Avanzadas (16h)

**Día 28-29 (16h): Cálculos complejos**
```python
# Archivo: models/hr_settlement_advanced.py
# 
# 1. Indemnización años servicio (Art. 163)
#    - 30 días × años trabajados
#    - Tope: 11 años
#    - Tope mensual: 90 UF
# 
# 2. Indemnización aviso previo (Art. 162)
#    - 30 días sueldo
#    - Si despido sin aviso
# 
# 3. Indemnización Art. 163 bis (Reforma 2017)
#    - 6-11 meses según antigüedad
#    - Solo contratos > 1 año
#    - Tope: 150 UF
# 
# 4. Feriado proporcional
#    - 1.25 días/mes trabajado
#    - Valorización: sueldo diario
# 
# 5. Sueldo proporcional mes despido
#    - Días trabajados / 30 × sueldo
```

---

#### Sprint 8.2: Reporte PDF Finiquito (8h)

**Día 30 (8h): Documento legal**
```python
# Archivo: reports/report_settlement.py
# Template: reports/report_settlement.xml
# 
# Secciones:
# 1. Encabezado (empresa, trabajador)
# 2. Datos contrato (fecha inicio/fin, causal)
# 3. Detalle liquidación:
#    - Sueldo proporcional
#    - Vacaciones proporcionales
#    - Indemnizaciones (desglosadas)
# 4. Total a pagar
# 5. Firmas (trabajador + empleador + testigos)
# 6. Anexos (cálculos detallados)
```

---

#### Sprint 8.3: Wizard Finiquito (8h)

**Día 31 (8h): Asistente generación**
```python
# Archivo: wizards/hr_settlement_wizard.py
# 
# Pasos wizard:
# 1. Seleccionar empleado
# 2. Fecha término + causal
# 3. Validar días trabajados
# 4. Calcular montos automático
# 5. Revisar + ajustar manual
# 6. Generar PDF
# 7. Registrar en contabilidad
```

**Entregable Fase 5:**
- Finiquito 100% funcional
- Reporte PDF legal
- Wizard user-friendly

---

### **FASE 6: AI INTEGRATION (24h)**

#### Sprint 9.1: Validación Contratos IA (8h)

**Día 32 (8h): Extensión AI-Service**
```python
# Archivo: ai-service/payroll/contract_validator.py
# Endpoint: POST /api/ai/validate-contract
# 
# Validaciones IA:
# 1. Detectar campos inconsistentes
#    - Sueldo < mínimo legal
#    - Jornada > 45h semanales
#    - AFP/ISAPRE faltante
# 
# 2. Sugerir correcciones
#    - "Sueldo debe ser >= $500.000"
#    - "Debe especificar AFP"
# 
# 3. Compliance legal
#    - Art. 41 CT (colación + movilización)
#    - Art. 42 CT (jornada)
#    - Reforma 2025
```

---

#### Sprint 9.2: Optimización Tributaria (8h)

**Día 33 (8h): Recomendaciones APV**
```python
# Archivo: ai-service/payroll/tax_optimizer.py
# Endpoint: POST /api/ai/optimize-tax
# 
# Input:
# {
#   "salary": 2000000,
#   "apv_current": 100000,
#   "tax_current": 180000
# }
# 
# Output:
# {
#   "recommendation": "Aumentar APV a $150.000",
#   "tax_savings": 45000,
#   "net_gain": 5000,
#   "explanation": "Al aumentar APV a $150k..."
# }
```

---

#### Sprint 9.3: Chat Laboral IA (8h)

**Día 34 (8h): Asistente conversacional**
```python
# Archivo: ai-service/payroll/chat_assistant.py
# Endpoint: POST /api/ai/chat
# 
# Casos uso:
# 1. "¿Cuánto es mi finiquito si renuncio hoy?"
#    → Cálculo automático
# 
# 2. "¿Por qué me descuentan AFP?"
#    → Explicación Art. 17 DL 3500
# 
# 3. "¿Cómo calcular horas extras?"
#    → Fórmula + ejemplo
# 
# Base conocimiento:
# - Código del Trabajo
# - DL 3500 (AFP)
# - DFL 150 (Asignación Familiar)
# - Ley 16.744 (Accidentes)
```

**Entregable Fase 6:**
- 3 funcionalidades IA operacionales
- Integración con Odoo
- Documentación API

---

## 📊 RESUMEN EJECUTIVO

### Horas Totales: 197h (5 semanas)

| Fase | Objetivo | Horas | Días | Prioridad |
|------|----------|-------|------|-----------|
| **1** | Completar Módulo Odoo | 37h | 5 días | 🔴 CRÍTICA |
| **2** | Reportes Legales | 52h | 7 días | 🔴 CRÍTICA |
| **3** | Previred + Finiquito | 64h | 8 días | 🔴 CRÍTICA |
| **4** | Payroll-Service | 40h | 5 días | 🟡 ALTA |
| **5** | Finiquito Completo | 32h | 4 días | 🟡 ALTA |
| **6** | AI Integration | 24h | 3 días | 🟢 MEDIA |

### Inversión Estimada

```
Desarrollador Senior Python/Odoo: $60/hora
Total: 197h × $60 = $11,820 USD

Desglose:
- Fase 1-3 (Críticas): $9,180 USD
- Fase 4-5 (Altas):    $4,320 USD
- Fase 6 (Media):      $1,440 USD
```

### Entregables Finales

✅ **Módulo Odoo 19 CE 100% funcional**
- 14 modelos Python
- 22 reglas salariales
- 9 vistas XML
- 80% cobertura tests

✅ **Payroll-Service (FastAPI)**
- 4 endpoints operacionales
- Scraper automático Previred
- CI/CD GitHub Actions

✅ **Reportes Legales Completos**
- Liquidación Individual PDF
- Libro Remuneraciones Excel/PDF
- Previred TXT 105 campos
- Certificado F30-1
- Resumen Contable

✅ **Finiquito Sistema Completo**
- Cálculos legales automáticos
- Reporte PDF formato DT
- Wizard user-friendly

✅ **AI Integration**
- Validación contratos
- Optimización tributaria
- Chat laboral IA

---

## 🎯 MÉTRICAS DE ÉXITO

### Funcionales
- ✅ 100% reglas salariales SOPA 2025
- ✅ 5 reportes legales operacionales
- ✅ Previred 105 campos completo
- ✅ Finiquito con todas indemnizaciones
- ✅ Integración contable automática

### Técnicas
- ✅ 80% cobertura tests
- ✅ p95 latency < 2s
- ✅ 0 errores críticos
- ✅ Código documentado 100%
- ✅ CI/CD automatizado

### Compliance
- ✅ Código del Trabajo vigente
- ✅ Reforma Previsional 2025
- ✅ Formato Previred oficial
- ✅ DT (Dirección del Trabajo) compliance
- ✅ Audit trail 7 años

---

## 🚀 SIGUIENTE PASO

**ARRANCAR FASE 1 - Sprint 4.1: Reglas Salariales Críticas**

¿Proceder con implementación Gratificación Legal?

```bash
# Comando para iniciar:
cd /Users/pedro/Documents/odoo19
# Crear archivos necesarios Sprint 4.1
```

---

**Preparado por:** Claude (Anthropic)  
**Fecha:** 2025-10-23 03:00 UTC  
**Versión:** 1.0
