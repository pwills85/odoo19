# 🎯 SEPARACIÓN DE RESPONSABILIDADES: ¿Qué va dónde?

**Fecha:** 2025-10-22  
**Objetivo:** Definir claramente qué funciones van en cada componente

---

## 📊 PRINCIPIO: APROVECHAR ODOO 19 CE AL MÁXIMO

### **Regla de Oro**

```
SI ODOO 19 CE LO HACE BIEN → USAR ODOO
SI ES CÁLCULO COMPLEJO → MICROSERVICIO
SI ES IA/ML → AI-SERVICE
SI ES PORTAL PÚBLICO → MICROSERVICIO SEPARADO
```

---

## 🏗️ ARQUITECTURA DETALLADA

### **1. ODOO 19 CE BASE (Suite Incluida)**

**Módulos que YA TENEMOS en Odoo 19 CE:**

```python
# ✅ INCLUIDOS EN ODOO 19 CE (GRATIS)
'hr'                    # Gestión de empleados
'hr_contract'           # Contratos de trabajo
'hr_holidays'           # Vacaciones y ausencias
'hr_attendance'         # Control de asistencia
'hr_expense'            # Gastos
'hr_recruitment'        # Reclutamiento
'account'               # Contabilidad
'l10n_cl'               # Localización Chile
'portal'                # Portal web para usuarios externos
'website'               # Website builder
```

**¿Qué USAMOS de Odoo base?**

| Función | Módulo Odoo | Uso |
|---------|-------------|-----|
| **Gestión empleados** | `hr` | ✅ USAR 100% |
| **Contratos** | `hr_contract` | ✅ EXTENDER (agregar campos Chile) |
| **Vacaciones** | `hr_holidays` | ✅ USAR 100% |
| **Asistencia** | `hr_attendance` | ✅ USAR 100% |
| **Portal empleado básico** | `portal` | ✅ USAR como base |
| **Contabilidad** | `account` | ✅ INTEGRAR liquidaciones |
| **Localización Chile** | `l10n_cl` | ✅ USAR (RUT, plan contable) |

---

### **2. NUESTRO MÓDULO ODOO (l10n_cl_hr_payroll)**

**Responsabilidad:** UI, Workflow, Orquestación

```python
# addons/localization/l10n_cl_hr_payroll/

# ✅ LO QUE VA EN NUESTRO MÓDULO ODOO:

1. MODELOS (Extender Odoo base)
   ├─ hr_contract_cl.py (_inherit hr.contract)
   │  └─ Agregar: AFP, ISAPRE, cargas, gratificación
   │
   ├─ hr_payslip_cl.py (crear hr.payslip)
   │  └─ Liquidaciones de sueldo
   │  └─ Orquestación con Payroll-Service
   │
   ├─ hr_settlement.py (nuevo)
   │  └─ Finiquitos
   │
   └─ hr_economic_indicators.py (nuevo)
      └─ UF, UTM, UTA mensuales

2. VISTAS (UI en Odoo)
   ├─ Formularios de contratos
   ├─ Formularios de liquidaciones
   ├─ Listas, kanban, calendarios
   └─ Dashboards (Chart.js)

3. WIZARDS (Asistentes)
   ├─ Exportar Previred
   ├─ Generar finiquito
   └─ Proceso masivo de nóminas

4. REPORTES (QWeb)
   ├─ Liquidación de sueldo (PDF)
   ├─ Finiquito (PDF)
   └─ Libro de remuneraciones

5. WORKFLOWS
   ├─ Aprobación de liquidaciones
   ├─ Firma de finiquitos
   └─ Estados (draft → done)

6. INTEGRACIÓN CONTABLE
   ├─ Asientos contables automáticos
   └─ Integración con account.move
```

**❌ LO QUE NO VA EN ODOO:**
- ❌ Cálculos complejos (van en Payroll-Service)
- ❌ Lógica de IA (va en AI-Service)
- ❌ Portal público (va en microservicio)

---

### **3. EERGY AI MICROSERVICE (Reutilizar existente)** ✅

**Responsabilidad:** Extracción Indicadores, Portal Empleados, Validación IA

```python
# EERGY AI Microservice (FastAPI + Claude API)
# Ubicación: microservices/eergy-ai/

# ✅ YA IMPLEMENTADO Y FUNCIONANDO:

1. EXTRACCIÓN INDICADORES (Scraping + IA)
   ├─ PreviredFetcher
   │  └─ Descarga PDF/HTML automático
   │  └─ Múltiples patrones URL
   │  └─ Retry con exponential backoff
   │
   ├─ PDFParser + Claude API
   │  └─ Extrae 60 campos desde PDF
   │  └─ Validación inteligente
   │  └─ Costo: $0.025/extracción
   │
   └─ SIIScraper + Claude API
      └─ Extrae 32 campos tabla impuesto
      └─ Costo: $0.002/extracción

2. PORTAL EMPLEADOS (SQL Direct)
   ├─ Autenticación JWT (httpOnly cookies)
   ├─ Ver liquidaciones históricas
   ├─ Descargar PDFs
   ├─ Estadísticas lifetime (6 KPIs)
   └─ Performance: 8ms (100x más rápido que XML-RPC)

3. VALIDACIÓN IA (Claude API)
   ├─ Validar contratos vs Código del Trabajo
   ├─ Detectar anomalías en liquidaciones
   ├─ Optimización tributaria
   └─ Chat laboral (consultas)

4. ENTERPRISE FEATURES
   ├─ Structured JSON Logging
   ├─ Correlation IDs end-to-end
   ├─ 12 grupos Prometheus metrics
   ├─ Audit Trail Blockchain (7 años)
   ├─ Rate Limiting (100 req/60s)
   └─ Slack Alerting

# API REST
POST /api/v1/scraping/previred           # 60 campos Previred
GET  /api/v1/scraping/previred/periods   # Períodos disponibles
POST /api/v1/scraping/sii/tax-brackets   # 32 campos SII
GET  /api/v1/employee/payslips           # Portal empleados
POST /api/v1/validation/contract         # Validación IA
POST /api/v1/chat/query                  # Chat laboral
```

**Ventajas de reutilizar:**
- ✅ Ya existe (15.5/16 enterprise-grade)
- ✅ 92 variables automáticas
- ✅ Portal empleados incluido
- ✅ Validación IA incluida
- ✅ Solo 1 día adaptación vs 4-6 semanas desarrollo
- ✅ Costo anual: $0.30 USD

---

### **4. AI-SERVICE (Claude - Microservicio)**

**Responsabilidad:** Inteligencia Artificial, Validaciones avanzadas

```python
# ai-service/payroll/ (extensión del AI-Service existente)

# ✅ LO QUE VA EN AI-SERVICE:

1. VALIDACIÓN INTELIGENTE
   ├─ Validar contratos vs Código del Trabajo
   │  └─ Detectar cláusulas ilegales
   │  └─ Sugerir correcciones
   │
   ├─ Detectar anomalías en liquidaciones
   │  └─ Salarios fuera de rango
   │  └─ Descuentos excesivos
   │  └─ Errores de cálculo
   │
   └─ Validar coherencia datos
      └─ Contratos vs liquidaciones
      └─ Histórico del empleado

2. OPTIMIZACIÓN TRIBUTARIA
   ├─ Sugerir APV óptimo
   ├─ Optimizar seguros deducibles
   └─ Maximizar líquido legal

3. CHATBOT LABORAL
   ├─ Responder consultas empleados
   │  └─ "¿Cuántas vacaciones tengo?"
   │  └─ "¿Cómo se calcula mi impuesto?"
   │
   ├─ Knowledge Base Código del Trabajo
   └─ Respuestas contextuales

4. ANALYTICS PREDICTIVO
   ├─ Predecir rotación
   ├─ Análisis de equity
   └─ Sugerencias de ajustes salariales

# API REST
POST /api/payroll/validate         # Validar liquidación
POST /api/contract/analyze         # Analizar contrato
POST /api/payroll/optimize         # Optimizar tributación
POST /api/chat/labor_query         # Chat laboral
```

**¿Por qué en AI-Service?**
- ✅ Requiere Claude (LLM)
- ✅ Procesamiento ML
- ✅ No bloquea Odoo
- ✅ Escalable independiente

---

### **5. PORTAL EMPLEADO (¿Dónde va?)**

**OPCIÓN A: Usar Portal de Odoo 19 CE** ✅ RECOMENDADO

```python
# ✅ APROVECHAR MÓDULO 'portal' DE ODOO 19 CE

# Odoo ya incluye:
- Autenticación de usuarios externos
- Permisos por registro
- UI responsive
- Multi-idioma
- Seguridad probada

# Nosotros agregamos:
# addons/localization/l10n_cl_hr_payroll/controllers/portal.py

from odoo.addons.portal.controllers.portal import CustomerPortal

class EmployeePortal(CustomerPortal):
    
    @route('/my/payslips', auth='user', website=True)
    def portal_my_payslips(self):
        """Lista de liquidaciones del empleado"""
        employee = request.env.user.employee_id
        payslips = request.env['hr.payslip'].search([
            ('employee_id', '=', employee.id)
        ], order='date_from desc')
        
        return request.render('l10n_cl_hr_payroll.portal_my_payslips', {
            'payslips': payslips
        })
    
    @route('/my/payslips/<int:payslip_id>/pdf', auth='user')
    def portal_payslip_pdf(self, payslip_id):
        """Descargar PDF de liquidación"""
        payslip = request.env['hr.payslip'].browse(payslip_id)
        
        # Verificar que es del empleado
        if payslip.employee_id != request.env.user.employee_id:
            raise Forbidden()
        
        pdf = request.env.ref('l10n_cl_hr_payroll.report_payslip').render_qweb_pdf([payslip_id])[0]
        
        return request.make_response(
            pdf,
            headers=[
                ('Content-Type', 'application/pdf'),
                ('Content-Disposition', f'attachment; filename=liquidacion_{payslip.number}.pdf')
            ]
        )
```

**Funciones del Portal (en Odoo):**
- ✅ Ver liquidaciones históricas
- ✅ Descargar PDFs
- ✅ Ver contratos
- ✅ Ver vacaciones
- ✅ Solicitar certificados
- ✅ Chat con IA (iframe a AI-Service)

**Ventajas:**
- ✅ Usa autenticación de Odoo
- ✅ Permisos nativos
- ✅ UI consistente
- ✅ Sin microservicio adicional
- ✅ Mantenimiento simplificado

---

**OPCIÓN B: Microservicio Separado** (Solo si necesario)

```python
# employee-portal/ (FastAPI)

# ⚠️ SOLO SI:
- Portal debe ser 100% independiente de Odoo
- Requiere autenticación externa (OAuth, SAML)
- Necesita UI completamente custom
- Debe escalar independiente

# Funciones:
- Autenticación propia
- Consulta a Odoo vía API
- UI React/Vue separada
- Deploy independiente
```

**❌ Desventajas:**
- Duplicar autenticación
- Duplicar permisos
- Más complejidad
- Más mantenimiento

---

## 🎯 DECISIÓN RECOMENDADA

### **ARQUITECTURA ÓPTIMA**

```
┌─────────────────────────────────────────────────────────┐
│ ODOO 19 CE (l10n_cl_hr_payroll)                       │
├─────────────────────────────────────────────────────────┤
│ ✅ Gestión empleados (hr base)                         │
│ ✅ Contratos extendidos (hr_contract + campos Chile)   │
│ ✅ Liquidaciones (hr.payslip nuevo)                    │
│ ✅ UI completa (vistas, wizards, reportes)            │
│ ✅ Workflows (aprobaciones, estados)                   │
│ ✅ Integración contable (account.move)                │
│ ✅ PORTAL EMPLEADO (portal base + extensión)          │
│    └─ Ver liquidaciones                               │
│    └─ Descargar PDFs                                  │
│    └─ Ver vacaciones                                  │
│    └─ Solicitar certificados                          │
└──────────────┬──────────────────────────────────────────┘
               │ HTTP/REST
    ┌──────────┴──────────┐
    │                     │
┌───▼────────────┐   ┌───▼────────────┐
│ PAYROLL-       │   │ AI-SERVICE     │
│ SERVICE        │   │ (Claude)       │
├────────────────┤   ├────────────────┤
│ ✅ Cálculos    │   │ ✅ Validación  │
│   AFP/Salud    │   │   contratos    │
│   Impuesto     │   │ ✅ Detección   │
│   Gratificación│   │   anomalías    │
│ ✅ Previred    │   │ ✅ Optimización│
│   105 campos   │   │   tributaria   │
│ ✅ Finiquito   │   │ ✅ Chatbot     │
│   Cálculo      │   │   laboral      │
└────────────────┘   └────────────────┘
```

---

## 📋 TABLA RESUMEN

| Función | Odoo 19 CE | Nuestro Módulo | Payroll-Service | AI-Service | Portal Separado |
|---------|------------|----------------|-----------------|------------|-----------------|
| **Gestión empleados** | ✅ | - | - | - | - |
| **Contratos base** | ✅ | - | - | - | - |
| **Contratos Chile** | - | ✅ Extender | - | - | - |
| **Vacaciones** | ✅ | - | - | - | - |
| **Asistencia** | ✅ | - | - | - | - |
| **UI liquidaciones** | - | ✅ | - | - | - |
| **Workflows** | - | ✅ | - | - | - |
| **Reportes PDF** | - | ✅ QWeb | - | - | - |
| **Cálculos AFP** | - | - | ✅ | - | - |
| **Cálculos Impuesto** | - | - | ✅ | - | - |
| **Previred** | - | - | ✅ | - | - |
| **Finiquito** | - | - | ✅ | - | - |
| **Validación IA** | - | - | - | ✅ | - |
| **Chatbot** | - | - | - | ✅ | - |
| **Optimización** | - | - | - | ✅ | - |
| **Portal empleado** | ✅ Base | ✅ Extender | - | - | ❌ No necesario |
| **Autenticación** | ✅ | - | - | - | - |
| **Contabilidad** | ✅ | ✅ Integrar | - | - | - |

---

## ✅ VENTAJAS DE ESTA ARQUITECTURA

### **1. Máximo Aprovechamiento Odoo 19 CE**
- ✅ Usa `hr`, `hr_contract`, `hr_holidays` (gratis)
- ✅ Usa `portal` (gratis, probado, seguro)
- ✅ Usa `account` (integración contable)
- ✅ Usa `l10n_cl` (RUT, plan contable)

### **2. Separación Clara**
- ✅ Odoo: UI, Workflow, Persistencia
- ✅ Payroll-Service: Cálculos, Archivos
- ✅ AI-Service: IA, Validaciones avanzadas

### **3. Simplicidad**
- ✅ Portal en Odoo (no microservicio adicional)
- ✅ Autenticación única
- ✅ Permisos nativos
- ✅ Menos código a mantener

### **4. Escalabilidad**
- ✅ Microservicios escalan independiente
- ✅ Odoo maneja UI y persistencia
- ✅ Cálculos no bloquean Odoo

---

## 🎯 RECOMENDACIÓN FINAL

**Portal Empleado:** ✅ **USAR PORTAL DE ODOO 19 CE**

**Razones:**
1. Ya está incluido (gratis)
2. Autenticación probada
3. Permisos nativos
4. UI consistente
5. Menos complejidad
6. Menos mantenimiento

**Microservicio separado:** ❌ **NO NECESARIO**

Solo considerar si:
- Portal debe ser 100% público (sin login Odoo)
- Requiere OAuth externo
- UI completamente diferente

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ RESPONSABILIDADES DEFINIDAS
