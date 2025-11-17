# 🏢 DOMINIO DE NEGOCIO: Nóminas Chile

**Proyecto:** l10n_cl_hr_payroll  
**Análisis:** Domain-Driven Design

---

## 📊 SUBDOMINIOS IDENTIFICADOS

### **CORE DOMAIN (Crítico para el negocio)**

#### 1. Cálculo de Nóminas
**Responsabilidad:** Calcular liquidaciones mensuales según normativa Chile

**Componentes:**
- **AFP** (10 fondos, comisiones 10.49%-11.54%)
  - Capital, Cuprum, Habitat, Modelo, PlanVital, Provida, Uno
  - Tope imponible: 83.1 UF
  - Ajuste por edad (55+ años)
  
- **Salud** (FONASA 7% / ISAPRE variable)
  - FONASA: 7% fijo sobre imponible
  - ISAPRE: Plan en UF, excedente como haber
  
- **Impuesto Único** (7 tramos progresivos 2025)
  - UTA 2025: $726,000
  - Tramos: 0%, 4%, 8%, 13.5%, 23%, 30.4%, 35%
  - Rebaja por cargas: $14,364/carga
  - Zona extrema: 50% rebaja
  
- **Gratificación Legal**
  - 25% utilidades / N° trabajadores
  - Tope: 4.75 IMM ($2,375,000)
  - Modalidad: Anual o mensual (1/12)
  
- **Reforma Previsional 2025**
  - Aporte empleador: 0.5% (2025) → 6% (2035)
  - Destino: 50% cuenta individual + 50% FAPP
  - Fecha corte: 1 agosto 2025

**Rescatado de Odoo 11:**
- ✅ Sistema SOPA 2025 (dual Legacy/SOPA)
- ✅ Snapshot de indicadores (JSON)
- ✅ 13 niveles de herencia en compute_sheet()
- ✅ Validaciones matemáticas robustas

---

#### 2. Previred
**Responsabilidad:** Generar archivo mensual obligatorio

**Componentes:**
- Archivo 105 campos (formato fijo o separado)
- Certificado F30-1 (cumplimiento)
- Validación formato
- Multas: 0.75-1.5 UF por trabajador

**Datos incluidos:**
- Empleador (RUT, razón social)
- Trabajador (RUT, AFP, salud)
- Remuneraciones (imponible, no imponible)
- Cotizaciones (AFP, salud, cesantía, ATEP)
- Aporte empleador (Reforma 2025)

**Rescatado de Odoo 11:**
- ✅ Generador Previred completo
- ✅ Validación formato
- ✅ Wizard de exportación

---

#### 3. Finiquito
**Responsabilidad:** Calcular liquidación final

**Componentes:**
1. Sueldo proporcional (días trabajados)
2. Vacaciones proporcionales (1.25 días/mes)
3. Indemnización años servicio (tope 11 años)
4. Indemnización aviso previo (1 mes)
5. Gratificación proporcional

**Cálculo años servicio:**
```python
años_completos = (fecha_termino - fecha_inicio).days // 365
meses_adicionales = ((fecha_termino - fecha_inicio).days % 365) // 30
if meses_adicionales >= 6:
    años_completos += 1
indemnización = min(años_completos, 11) * última_remuneración
```

**Rescatado de Odoo 11:**
- ✅ Calculadora finiquito completa
- ✅ Wizard de generación
- ✅ Reporte PDF legal

---

### **SUPPORTING DOMAIN (Importante)**

#### 4. Contratos
**Responsabilidad:** Gestionar datos laborales

**Campos Chile específicos:**
- AFP, ISAPRE, APV
- Cotizaciones en UF
- Colación, movilización (Art. 41 CT)
- Cargas familiares (3 tipos)
- Gratificación (tipo)
- Centro de costo
- Jornada semanal (44h default)
- Zona extrema

**Rescatado de Odoo 11:**
- ✅ 30+ campos específicos Chile
- ✅ Validaciones robustas
- ✅ Integración con estadísticas

---

#### 5. Indicadores Económicos
**Responsabilidad:** Mantener valores históricos

**Datos mensuales (2018-2025):**
- UF, UTM, UTA
- Sueldo mínimo
- Topes imponibles (AFP, IPS, AFC)
- Asignaciones familiares (3 tramos)
- Tramos impuesto único (7 tramos)

**Rescatado de Odoo 11:**
- ✅ 84 meses de datos históricos
- ✅ Snapshot en liquidaciones (JSON)
- ✅ Scraper automático Previred

---

#### 6. Maestros
**Responsabilidad:** Catálogos base

**Entidades:**
- AFPs (10 registros)
- ISAPREs (15 registros)
- APVs (8 registros)
- CCAFs (5 registros)
- Mutuales (3 registros)
- Centros de costo (20 registros)

---

### **GENERIC DOMAIN (Genérico)**

#### 7. Audit Trail
**Responsabilidad:** Trazabilidad legal (Art. 54 CT)

**Datos:**
- Acción (create, compute, validate, etc.)
- Usuario, timestamp, IP
- Valores antes/después (JSON)
- Retención 7 años

**Rescatado de Odoo 11:**
- ✅ Modelo hr.payroll.audit.trail
- ✅ Hooks automáticos
- ✅ Compliance Art. 54 CT

---

#### 8. Reportes
**Responsabilidad:** Generación de documentos

**Tipos:**
- Liquidación de sueldo (PDF)
- Finiquito (PDF legal)
- Libro de Remuneraciones
- Certificado F30-1
- Estadísticas empleado

**Rescatado de Odoo 11:**
- ✅ Reportes QWeb profesionales
- ✅ Design system CSS
- ✅ Gráficos Chart.js

---

## 🎯 FEATURES CLAVE DE ODOO 11 A RESCATAR

### **1. Sistema SOPA 2025**
- Dual Legacy/SOPA (fecha corte: 1 agosto 2025)
- Snapshot de indicadores (JSON)
- Categorías salariales optimizadas

### **2. Arquitectura Robusta**
- 13 niveles de herencia en compute_sheet()
- Validaciones en cascada
- Error handling enterprise

### **3. Analytics Enterprise**
- NumPy/Pandas optimizations
- Equity analysis
- Contract statistics
- Employee lifetime profile

### **4. AI Integration**
- Chat conversacional (microservicio)
- Knowledge base multi-módulo
- Validaciones inteligentes

### **5. Previred Completo**
- Generador 105 campos
- Wizard exportación
- Validación formato

### **6. Audit Trail**
- Compliance Art. 54 CT
- Retención 7 años
- Trazabilidad completa

---

## 📋 FEATURES DE ODOO 18 A CONSIDERAR

### **De l10n_cl_fe (DTE):**
- ✅ Patrón de herencia (_inherit)
- ✅ Integración con l10n_latam
- ✅ Microservicios (DTE-Service)
- ✅ Modo contingencia robusto
- ✅ Circuit breaker + Retry
- ✅ Testing 80%

### **Aplicar a Payroll:**
- Mismo patrón de herencia
- Misma arquitectura microservicios
- Mismo nivel de testing
- Misma robustez

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0
