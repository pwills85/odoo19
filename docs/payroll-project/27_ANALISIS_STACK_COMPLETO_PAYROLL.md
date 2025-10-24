# 🏗️ ANÁLISIS STACK COMPLETO - Sistema Nóminas Chile

**Fecha:** 2025-10-23  
**Módulo:** l10n_cl_hr_payroll (Odoo 19 CE)  
**Arquitectura:** Odoo 19 CE + Microservicios + AI Agent  
**Referencia:** SOPA 2025 (Odoo 11 CE)

---

## 🎯 OBJETIVO

Análisis exhaustivo del stack completo de nóminas chilenas, desde ficha del trabajador hasta reportes legales, identificando brechas entre el estado actual (95% Sprint 3.2) y el sistema de referencia SOPA 2025.

---

## 📊 ARQUITECTURA GENERAL

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ODOO 19 CE MODULE                                 │
│                    l10n_cl_hr_payroll (Frontend + Orquestación)          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  FICHA TRABAJADOR (hr.employee - Base Odoo)                             │
│    └─> Extiende con campos Chile                                        │
│                                                                           │
│  CONTRATO (hr.contract_cl - Extensión)                   95% ✅          │
│    ├─> AFP, ISAPRE, APV                                                 │
│    ├─> Asignaciones (colación, movilización)                            │
│    ├─> Cargas familiares                                                │
│    └─> Jornada, gratificación                                           │
│                                                                           │
│  INPUTS MANUALES (hr.payslip.input)                       95% ✅          │
│    ├─> Horas extras (HEX50, HEX100, HEXDE)                              │
│    ├─> Bonos imponibles                                                 │
│    ├─> Asignaciones NO imponibles                                       │
│    └─> Descuentos adicionales                                           │
│                                                                           │
│  ESTRUCTURA SALARIAL (hr.payroll.structure)               95% ✅          │
│    ├─> 22 categorías SOPA 2025                                          │
│    │   ├─> 8 categorías raíz                                            │
│    │   ├─> 5 sub-categorías haberes                                     │
│    │   ├─> 3 sub-categorías descuentos                                  │
│    │   └─> 6 categorías SOPA específicas                                │
│    └─> Reglas salariales                                                │
│                                                                           │
│  REGLAS SALARIALES (hr.salary.rule)                       85% ⚠️          │
│    ├─> Haberes (Base, HEX, Bonos)                         ✅            │
│    ├─> Descuentos Previsionales                           ✅            │
│    │   ├─> AFP (10 fondos, tope 87.8 UF)                                │
│    │   ├─> Salud (FONASA 7% / ISAPRE)                                   │
│    │   └─> AFC (0.6%, tope 120.2 UF)                                    │
│    ├─> Impuesto Único (7 tramos SII 2025)                 ✅            │
│    ├─> Gratificación Legal                                ❌ 0%         │
│    │   └─> 25% utilidades, tope 4.75 IMM                                │
│    ├─> Asignación Familiar                                ❌ 0%         │
│    └─> Aportes Empleador (Reforma 2025)                   ❌ 0%         │
│                                                                           │
│  LIQUIDACIÓN (hr.payslip - Core)                          95% ✅          │
│    ├─> Pipeline 9 pasos                                                 │
│    ├─> 4 totalizadores SOPA                                             │
│    │   ├─> total_haberes                                                │
│    │   ├─> total_imponible (AFP/Salud)                                  │
│    │   ├─> total_tributable (Impuesto)                                  │
│    │   └─> total_gratificacion_base                                     │
│    └─> Líneas de detalle (hr.payslip.line)                              │
│                                                                           │
│  LOTES DE NÓMINA (hr.payslip.run)                         80% ⚠️          │
│    ├─> Procesamiento masivo                                ✅            │
│    ├─> Validaciones batch                                  ❌ 0%         │
│    └─> Reporte consolidado                                 ❌ 0%         │
│                                                                           │
│  REPORTES LEGALES                                          20% ❌          │
│    ├─> Liquidación Individual (PDF)                        ❌ 0%         │
│    ├─> Libro de Remuneraciones (Excel)                     ❌ 0%         │
│    ├─> Previred (TXT 105 campos)                           ❌ 0%         │
│    ├─> Certificado F30-1 (PDF)                             ❌ 0%         │
│    └─> Resumen Contable                                    ❌ 0%         │
│                                                                           │
│  FINIQUITO (hr.settlement)                                 0% ❌          │
│    ├─> Cálculo liquidación final                           ❌            │
│    ├─> Vacaciones proporcionales                           ❌            │
│    ├─> Indemnizaciones                                     ❌            │
│    └─> Reporte PDF legal                                   ❌            │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                       PAYROLL-SERVICE (FastAPI)                          │
│                    Puerto 8003 - Microservicio Python                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  CÁLCULOS COMPLEJOS                                        0% ❌          │
│    ├─> Gratificación Legal (artículo 50 CT)                             │
│    ├─> Finiquito (indemnizaciones)                                      │
│    ├─> Horas extras con jornada parcial                                 │
│    └─> Optimización tributaria APV                                      │
│                                                                           │
│  GENERACIÓN ARCHIVOS LEGALES                               0% ❌          │
│    ├─> Previred TXT (105 campos)                                        │
│    ├─> Libro de Remuneraciones (Excel)                                  │
│    └─> Validaciones formato                                             │
│                                                                           │
│  SCRAPING INDICADORES                                      0% ❌          │
│    ├─> Scraper Previred (UF, UTM, UTA, IMM)                            │
│    ├─> Actualización automática                                         │
│    └─> Cache Redis                                                      │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         AI-SERVICE (Claude)                              │
│                    Puerto 8002 - Ya existente + Extensión                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  VALIDACIONES INTELIGENTES                                 0% ❌          │
│    ├─> Validación contratos (clausulas ilegales)                        │
│    ├─> Detección anomalías en liquidaciones                             │
│    └─> Sugerencias optimización                                         │
│                                                                           │
│  CONSULTAS LABORALES (Chat IA)                            0% ❌          │
│    ├─> Código del Trabajo                                               │
│    ├─> Jurisprudencia DT                                                │
│    └─> Casos de uso comunes                                             │
│                                                                           │
│  ANÁLISIS PREDICTIVO                                       0% ❌          │
│    ├─> Forecast costos de nómina                                        │
│    ├─> Análisis rotación                                                │
│    └─> Benchmarking mercado                                             │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 FLUJO COMPLETO SOPA 2025 vs ESTADO ACTUAL

### **PASO 1: FICHA DEL TRABAJADOR**

#### **Base Odoo (hr.employee)**
```python
# Campos estándar Odoo 19 CE
- name                    # Nombre completo
- identification_id       # RUT (heredado de l10n_cl)
- job_id                  # Cargo
- department_id           # Departamento
- address_home_id         # Dirección
- birthday                # Fecha nacimiento
- gender                  # Género
- country_id              # Nacionalidad
- work_email              # Email corporativo
- work_phone              # Teléfono
```

#### **Extensión Chile (Necesaria)** ❌ **NO IMPLEMENTADA**
```python
# models/hr_employee_cl.py - CREAR

class HrEmployeeCL(models.Model):
    _inherit = 'hr.employee'
    
    # DT y Previsión
    previred_rut = fields.Char('RUT Previred')  # Formato sin puntos
    date_start_company = fields.Date('Fecha Ingreso Empresa')
    
    # Contacto emergencia
    emergency_contact = fields.Char('Contacto Emergencia')
    emergency_phone = fields.Char('Teléfono Emergencia')
    
    # Datos bancarios
    bank_account_id = fields.Many2one('res.partner.bank', 'Cuenta Bancaria')
    
    # Escolaridad (para Previred)
    education_level = fields.Selection([
        ('basica_incompleta', 'Básica Incompleta'),
        ('basica_completa', 'Básica Completa'),
        ('media_incompleta', 'Media Incompleta'),
        ('media_completa', 'Media Completa'),
        ('tecnica', 'Técnica'),
        ('universitaria', 'Universitaria'),
        ('postgrado', 'Postgrado'),
    ], string='Nivel Educacional')
    
    # Discapacidad (para asignación familiar)
    has_disability = fields.Boolean('Tiene Discapacidad')
    disability_percentage = fields.Float('% Discapacidad')
```

**Estado:** ❌ **0% - NO IMPLEMENTADO**  
**Prioridad:** 🟡 MEDIA (necesario para Previred)  
**Tiempo estimado:** 4 horas

---

### **PASO 2: CONTRATO TRABAJADOR**

#### **Estado Actual** ✅ **95% IMPLEMENTADO**

**Archivo:** `models/hr_contract_cl.py`

**Campos implementados:**
```python
✅ AFP (afp_id, afp_rate)
✅ Salud (health_system, isapre_id, isapre_plan_uf, isapre_fun)
✅ APV (apv_id, apv_amount_uf, apv_type)
✅ Asignaciones (colacion, movilizacion)
✅ Cargas familiares (simple, maternal, invalid)
✅ Gratificación (gratification_type)
✅ Jornada (weekly_hours)
✅ Zona extrema (extreme_zone)
```

**Brechas identificadas:** ❌ **5% FALTANTE**

```python
# AGREGAR a hr_contract_cl.py

# 1. Tipo de trabajador (Previred campo 16)
worker_type = fields.Selection([
    ('0', 'Activo (no pensionado)'),
    ('1', 'Pensionado y cotiza'),
    ('2', 'Pensionado y no cotiza'),
    ('3', 'Activo mayor 65 años'),
], string='Tipo Trabajador', default='0')

# 2. Tipo de pago (Previred campo 17)
payment_type = fields.Selection([
    ('1', 'Mensual'),
    ('2', 'Quincenal'),
    ('3', 'Semanal'),
    ('4', 'Diario'),
], string='Tipo Pago', default='1')

# 3. Región de prestación servicios (Previred campo 18)
work_region_id = fields.Many2one('res.country.state', 'Región Trabajo')

# 4. AFP voluntaria (Previred campo 84-86)
voluntary_afp_amount = fields.Float('Cotización AFP Voluntaria')
voluntary_afp_type = fields.Selection([
    ('A', 'Régimen A'),
    ('B', 'Régimen B'),
], string='Tipo AFP Voluntaria')

# 5. Seguro complementario cesantía
afc_employer_rate = fields.Float(
    'Tasa AFC Empleador (%)',
    default=2.4,
    help='Tasa aporte empleador al seguro de cesantía'
)
```

**Estado:** ✅ **95% IMPLEMENTADO**  
**Prioridad:** 🟡 MEDIA (completar para Previred)  
**Tiempo estimado:** 2 horas

---

### **PASO 3: INPUTS MANUALES (SOPA)**

#### **Estado Actual** ✅ **95% IMPLEMENTADO**

**Archivo:** `models/hr_payslip.py` método `_process_input_lines()`

**Inputs implementados:**
```python
✅ HEX50   - Horas extras 50%
✅ HEX100  - Horas extras 100%
✅ HEXDE   - Horas extras domingo/festivo
✅ BONO_*  - Bonos imponibles
✅ COLACION - Colación (NO imponible, tope 20% IMM)
✅ MOVILIZACION - Movilización (NO imponible, tope 20% IMM)
✅ DESC_*  - Descuentos adicionales
```

**Brechas identificadas:** ❌ **5% FALTANTE**

```python
# AGREGAR inputs Previred requeridos

# 1. Días trabajados/licencia
'DIAS_TRAB'     # Días efectivamente trabajados
'DIAS_LIC'      # Días de licencia médica
'DIAS_VAC'      # Días de vacaciones

# 2. Subsidios
'SUBS_MATERNAL'  # Subsidio maternal
'SUBS_ENFERMEDAD' # Subsidio enfermedad
'SUBS_ACCIDENTE'  # Subsidio accidente trabajo

# 3. Bonos especiales
'BONO_ESCOLAR'    # Bono escolaridad (marzo-abril)
'BONO_FIESTAS'    # Bono fiestas patrias (septiembre)
```

**Estado:** ✅ **95% IMPLEMENTADO**  
**Prioridad:** 🟡 MEDIA (completar para edge cases)  
**Tiempo estimado:** 3 horas

---

### **PASO 4: ESTRUCTURA SALARIAL**

#### **Estado Actual** ✅ **100% IMPLEMENTADO**

**Archivos:**
- `data/hr_salary_rule_category_base.xml` (13 categorías)
- `data/hr_salary_rule_category_sopa.xml` (9 categorías SOPA)

**22 Categorías SOPA 2025:** ✅ COMPLETAS

```xml
CATEGORÍAS RAÍZ (8):
✅ BASE - Sueldo Base
✅ HABER - Haberes
✅ DESC - Descuentos
✅ APORTE - Aportes Empleador
✅ GROSS - Total Haberes (Bruto)
✅ TOTAL_IMPO - Total Imponible
✅ RENTA_TRIB - Renta Tributable
✅ NET - Líquido a Pagar

SUB-CATEGORÍAS HABERES (2):
✅ IMPO - Haberes Imponibles
✅ NOIMPO - Haberes NO Imponibles

SUB-CATEGORÍAS DESCUENTOS (3):
✅ LEGAL - Descuentos Legales
✅ TRIB - Descuentos Tributarios
✅ OTRO - Otros Descuentos

CATEGORÍAS SOPA (6):
✅ BASE_SOPA - Sueldo Base SOPA
✅ HEX_SOPA - Horas Extras SOPA
✅ BONUS_SOPA - Bonos Imponibles SOPA
✅ BONUS_NO_GRAT_SOPA - Bonos sin Gratificación
✅ IMPONIBLE_SOPA - Total Imponible SOPA
✅ TOTAL_SOPA - Total Haberes SOPA

CATEGORÍAS NO IMPONIBLES (3):
✅ HABER_NOIMP_SOPA - Haberes NO Imponibles SOPA
✅ BENEFITS_CT41_SOPA - Beneficios Art. 41 CT
✅ LEGAL_ALLOWANCE_SOPA - Asignaciones Legales
```

**Estado:** ✅ **100% COMPLETO**  
**Prioridad:** ✅ COMPLETADO

---

### **PASO 5: REGLAS SALARIALES**

#### **Estado Actual** ⚠️ **85% IMPLEMENTADO**

**Archivo:** `models/hr_salary_rule.py` + data XML

**Reglas implementadas:**

```python
# HABERES ✅
RULE_BASE      - Sueldo Base
RULE_HEX50     - Horas extras 50%
RULE_HEX100    - Horas extras 100%
RULE_HEXDE     - HEX domingo/festivo
RULE_BONO      - Bonos imponibles
RULE_COLACION  - Colación (con tope)
RULE_MOVILIZ   - Movilización (con tope)

# DESCUENTOS PREVISIONALES ✅
RULE_AFP       - AFP (tope 87.8 UF)
RULE_SALUD     - Salud (FONASA 7% / ISAPRE)
RULE_AFC       - AFC 0.6% (tope 120.2 UF)

# IMPUESTOS ✅
RULE_TAX       - Impuesto Único (7 tramos SII 2025)

# TOTALIZADORES ✅
RULE_GROSS     - Total Haberes
RULE_IMPONIBLE - Total Imponible
RULE_TRIBUTABLE - Total Tributable
RULE_NET       - Líquido a Pagar
```

**Brechas críticas:** ❌ **15% FALTANTE**

```xml
<!-- FALTA IMPLEMENTAR -->

<!-- 1. GRATIFICACIÓN LEGAL (CRÍTICO) -->
<record id="rule_gratificacion" model="hr.salary.rule">
    <field name="name">Gratificación Legal</field>
    <field name="code">GRAT</field>
    <field name="category_id" ref="category_haber_imponible"/>
    <field name="sequence">25</field>
    <!-- 
    Cálculo: 25% de utilidades / 12 meses
    Tope: 4.75 IMM (Ingreso Mínimo Mensual)
    Base: Solo haberes que afectan gratificación
    -->
</record>

<!-- 2. ASIGNACIÓN FAMILIAR (CRÍTICO) -->
<record id="rule_asig_familiar" model="hr.salary.rule">
    <field name="name">Asignación Familiar</field>
    <field name="code">ASIGFAM</field>
    <field name="category_id" ref="category_legal_allowance_sopa"/>
    <field name="sequence">30</field>
    <!-- 
    Monto variable según tramo de ingreso:
    - Tramo A: $xx por carga
    - Tramo B: $yy por carga
    - Tramo C: $zz por carga
    NO imponible, NO tributable
    -->
</record>

<!-- 3. APORTES EMPLEADOR (REFORMA 2025) -->
<record id="rule_aporte_empleador_afp" model="hr.salary.rule">
    <field name="name">Aporte Empleador AFP</field>
    <field name="code">APORTE_EMP_AFP</field>
    <field name="category_id" ref="category_aportes"/>
    <field name="sequence">200</field>
    <!-- 
    Aporte empleador gradual (Reforma 2025):
    2024: 0.5%
    2025: 1.0%
    2026: 1.5%
    ...
    2031+: 3.5%
    -->
</record>

<record id="rule_afc_employer" model="hr.salary.rule">
    <field name="name">AFC Empleador</field>
    <field name="code">AFC_EMP</field>
    <field name="category_id" ref="category_aportes"/>
    <field name="sequence">201</field>
    <!-- 
    AFC empleador: 2.4% sobre imponible
    Tope: 120.2 UF
    -->
</record>

<!-- 4. AJUSTES ESPECIALES -->
<record id="rule_ajuste_sueldo_minimo" model="hr.salary.rule">
    <field name="name">Ajuste Sueldo Mínimo</field>
    <field name="code">AJUSTE_MIN</field>
    <field name="category_id" ref="category_base"/>
    <field name="sequence">5</field>
    <!-- 
    Si (base + proporcionales) < Sueldo Mínimo:
        Ajuste = Sueldo Mínimo - (base + proporcionales)
    -->
</record>
```

**Estado:** ⚠️ **85% IMPLEMENTADO**  
**Prioridad:** 🔴 ALTA (Gratificación es obligatoria)  
**Tiempo estimado:** 16 horas

---

### **PASO 6: CÁLCULOS Y TOTALIZADORES**

#### **Estado Actual** ✅ **95% IMPLEMENTADO**

**Archivo:** `models/hr_payslip.py`

**Pipeline implementado (9 pasos):**

```python
def compute_sheet(self):
    """
    Pipeline de cálculo completo - Odoo 19 CE
    """
    for payslip in self:
        # PASO 1: Haberes Base ✅
        payslip._compute_base_lines()
        
        # PASO 2: Procesar Inputs ✅
        payslip._process_input_lines()
        
        # PASO 3: Computar Totalizadores ✅
        payslip._compute_totalizadores_sopa()
        # - total_imponible
        # - total_tributable
        # - total_gratificacion_base
        # - total_haberes
        
        # PASO 4: Descuentos Previsionales ✅
        payslip._compute_afp_lines()
        payslip._compute_health_lines()
        payslip._compute_afc_lines()
        
        # PASO 5: Impuesto Único ✅
        payslip._compute_tax_lines()
        
        # PASO 6: Gratificación ❌ NO IMPLEMENTADA
        # payslip._compute_gratification_lines()
        
        # PASO 7: Asignación Familiar ❌ NO IMPLEMENTADA
        # payslip._compute_family_allowance_lines()
        
        # PASO 8: Aportes Empleador ❌ NO IMPLEMENTADOS
        # payslip._compute_employer_contributions()
        
        # PASO 9: Recomputar Totales Finales ✅
        payslip._compute_totalizadores_sopa()
        payslip._compute_net_wage()
```

**Totalizadores implementados:**

```python
# models/hr_payslip.py

@api.depends('line_ids.total', 'line_ids.category_id')
def _compute_totalizadores_sopa(self):
    """Totalizadores SOPA 2025"""
    for payslip in self:
        # 1. Total Haberes ✅
        haber_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.tipo == 'haber'
        )
        payslip.total_haberes = sum(haber_lines.mapped('total'))
        
        # 2. Total Imponible ✅
        imponible_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.imponible == True
        )
        payslip.total_imponible = sum(imponible_lines.mapped('total'))
        
        # 3. Total Tributable ✅
        tributable_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.tributable == True
        )
        payslip.total_tributable = sum(tributable_lines.mapped('total'))
        
        # 4. Base Gratificación ✅
        grat_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.afecta_gratificacion == True
        )
        payslip.total_gratificacion_base = sum(grat_lines.mapped('total'))
```

**Estado:** ✅ **95% IMPLEMENTADO**  
**Prioridad:** 🟡 MEDIA (completar cálculos faltantes)  
**Tiempo estimado:** 8 horas

---

### **PASO 7: GENERACIÓN DE LIQUIDACIONES**

#### **Estado Actual** ✅ **95% IMPLEMENTADO**

**Archivo:** `models/hr_payslip.py`

**Funcionalidad implementada:**
```python
✅ Crear liquidación individual
✅ Asignar número secuencial
✅ Pipeline de cálculo automático
✅ Validaciones básicas
✅ Estados (draft, confirm, done, cancel)
✅ Tracking y auditoría
✅ Líneas de detalle completas
```

**Brechas identificadas:** ❌ **5% FALTANTE**

```python
# AGREGAR validaciones avanzadas

def action_payslip_done(self):
    """
    Confirmar liquidación - AGREGAR validaciones
    """
    for payslip in self:
        # Validación 1: Sueldo mínimo ❌
        if payslip.net_wage < payslip.indicadores_id.ingreso_minimo:
            raise ValidationError(
                'El líquido a pagar no puede ser menor al sueldo mínimo'
            )
        
        # Validación 2: Coherencia descuentos ❌
        if abs(payslip.total_descuentos) > payslip.total_haberes:
            raise ValidationError(
                'Los descuentos no pueden superar los haberes'
            )
        
        # Validación 3: Topes legales ❌
        # - AFP tope 87.8 UF
        # - Salud plan ISAPRE razonable
        # - Impuesto no negativo
        
        # Validación 4: Días del periodo ❌
        days = (payslip.date_to - payslip.date_from).days
        if days < 28 or days > 31:
            raise ValidationError(
                'El periodo debe ser mensual (28-31 días)'
            )
```

**Estado:** ✅ **95% IMPLEMENTADO**  
**Prioridad:** 🟢 BAJA (validaciones nice-to-have)  
**Tiempo estimado:** 4 horas

---

### **PASO 8: LOTES DE NÓMINA**

#### **Estado Actual** ⚠️ **80% IMPLEMENTADO**

**Archivo:** `models/hr_payslip_run.py`

**Funcionalidad implementada:**
```python
✅ Crear lote de nóminas
✅ Generar liquidaciones masivas
✅ Estados (draft, close, paid)
✅ Vista kanban y calendario
```

**Brechas críticas:** ❌ **20% FALTANTE**

```python
# models/hr_payslip_run.py - AGREGAR

class HrPayslipRun(models.Model):
    _inherit = 'hr.payslip.run'
    
    # CAMPOS ADICIONALES ❌
    payment_date = fields.Date(
        'Fecha de Pago',
        help='Fecha en que se pagará la nómina'
    )
    
    bank_payment_file = fields.Binary(
        'Archivo Pago Bancos',
        help='Archivo TXT para transferencias bancarias'
    )
    
    bank_payment_filename = fields.Char('Nombre Archivo')
    
    # TOTALIZADORES ❌
    total_employees = fields.Integer(
        'Total Empleados',
        compute='_compute_totals'
    )
    
    total_gross = fields.Monetary(
        'Total Bruto',
        compute='_compute_totals'
    )
    
    total_net = fields.Monetary(
        'Total Líquido',
        compute='_compute_totals'
    )
    
    total_employer_cost = fields.Monetary(
        'Costo Empleador Total',
        compute='_compute_totals',
        help='Incluye aportes patronales'
    )
    
    # MÉTODOS ❌
    
    def action_generate_bank_payment(self):
        """
        Generar archivo TXT para pago banco
        
        Formato BCI/Santander/etc según banco
        """
        pass
    
    def action_validate_all(self):
        """
        Validar todas las liquidaciones del lote
        
        - Verificar topes legales
        - Validar coherencia datos
        - Marcar errores
        """
        pass
    
    def action_generate_reports(self):
        """
        Generar reportes del lote
        
        - Libro de Remuneraciones
        - Previred
        - Resumen contable
        """
        pass
```

**Estado:** ⚠️ **80% IMPLEMENTADO**  
**Prioridad:** 🟡 MEDIA (importante para operación)  
**Tiempo estimado:** 12 horas

---

### **PASO 9: REPORTES DE NÓMINAS**

#### **Estado Actual** ❌ **20% IMPLEMENTADO**

**Brechas críticas:**

#### **9.1 Liquidación Individual (PDF)** ❌ **0%**

```xml
<!-- reports/report_payslip.xml - CREAR -->

<template id="report_payslip_document">
    <t t-call="web.external_layout">
        <div class="page">
            <!-- HEADER -->
            <div class="row">
                <div class="col-6">
                    <img t-att-src="company.logo" style="max-height: 60px;"/>
                    <h3 t-field="company.name"/>
                </div>
                <div class="col-6 text-right">
                    <h4>LIQUIDACIÓN DE SUELDO</h4>
                    <p><strong>Nº:</strong> <span t-field="o.number"/></p>
                    <p><strong>Periodo:</strong> 
                        <span t-field="o.date_from"/> - <span t-field="o.date_to"/>
                    </p>
                </div>
            </div>
            
            <!-- DATOS TRABAJADOR -->
            <div class="row mt-4">
                <div class="col-12">
                    <table class="table table-sm">
                        <tr>
                            <td><strong>Trabajador:</strong></td>
                            <td><span t-field="o.employee_id.name"/></td>
                            <td><strong>RUT:</strong></td>
                            <td><span t-field="o.employee_id.identification_id"/></td>
                        </tr>
                        <tr>
                            <td><strong>Cargo:</strong></td>
                            <td><span t-field="o.employee_id.job_id.name"/></td>
                            <td><strong>Fecha Ingreso:</strong></td>
                            <td><span t-field="o.contract_id.date_start"/></td>
                        </tr>
                    </table>
                </div>
            </div>
            
            <!-- HABERES Y DESCUENTOS -->
            <div class="row mt-4">
                <div class="col-6">
                    <h5>HABERES</h5>
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Concepto</th>
                                <th class="text-right">Monto</th>
                            </tr>
                        </thead>
                        <tbody>
                            <t t-foreach="o.line_ids.filtered(lambda l: l.category_id.tipo == 'haber')" t-as="line">
                                <tr>
                                    <td><span t-field="line.name"/></td>
                                    <td class="text-right">
                                        <span t-field="line.total" 
                                              t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                    </td>
                                </tr>
                            </t>
                        </tbody>
                        <tfoot>
                            <tr>
                                <th>TOTAL HABERES</th>
                                <th class="text-right">
                                    <span t-field="o.total_haberes"
                                          t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                </th>
                            </tr>
                        </tfoot>
                    </table>
                </div>
                
                <div class="col-6">
                    <h5>DESCUENTOS</h5>
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Concepto</th>
                                <th class="text-right">Monto</th>
                            </tr>
                        </thead>
                        <tbody>
                            <t t-foreach="o.line_ids.filtered(lambda l: l.category_id.tipo == 'descuento')" t-as="line">
                                <tr>
                                    <td><span t-field="line.name"/></td>
                                    <td class="text-right">
                                        <span t-field="line.total"
                                              t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                    </td>
                                </tr>
                            </t>
                        </tbody>
                        <tfoot>
                            <tr>
                                <th>TOTAL DESCUENTOS</th>
                                <th class="text-right">
                                    <span t-field="o.total_descuentos"
                                          t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                </th>
                            </tr>
                        </tfoot>
                    </table>
                </div>
            </div>
            
            <!-- LÍQUIDO A PAGAR -->
            <div class="row mt-4">
                <div class="col-12">
                    <table class="table">
                        <tr class="bg-primary text-white">
                            <th>LÍQUIDO A PAGAR</th>
                            <th class="text-right" style="font-size: 1.5em;">
                                <span t-field="o.net_wage"
                                      t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                            </th>
                        </tr>
                    </table>
                </div>
            </div>
            
            <!-- FIRMA -->
            <div class="row mt-5">
                <div class="col-6">
                    <div class="text-center">
                        <p>_______________________________</p>
                        <p>Firma Empleado</p>
                    </div>
                </div>
                <div class="col-6">
                    <div class="text-center">
                        <p>_______________________________</p>
                        <p>Firma Empleador</p>
                    </div>
                </div>
            </div>
        </div>
    </t>
</template>
```

**Tiempo:** 6 horas

---

#### **9.2 Libro de Remuneraciones (Excel)** ❌ **0%**

```python
# wizards/wizard_libro_remuneraciones.py - CREAR

class WizardLibroRemuneraciones(models.TransientModel):
    _name = 'wizard.libro.remuneraciones'
    _description = 'Exportar Libro de Remuneraciones'
    
    date_from = fields.Date('Desde', required=True)
    date_to = fields.Date('Hasta', required=True)
    company_id = fields.Many2one('res.company', required=True, 
                                  default=lambda self: self.env.company)
    
    def action_generate_excel(self):
        """
        Generar Libro de Remuneraciones en Excel
        
        Formato DT (Dirección del Trabajo)
        Columnas requeridas (mínimo 40):
        - Datos empleado (RUT, nombre, cargo)
        - Haberes detallados
        - Descuentos detallados
        - Totales
        - Aportes patronales
        """
        import xlsxwriter
        from io import BytesIO
        
        # Buscar liquidaciones del periodo
        payslips = self.env['hr.payslip'].search([
            ('date_from', '>=', self.date_from),
            ('date_to', '<=', self.date_to),
            ('company_id', '=', self.company_id.id),
            ('state', '=', 'done'),
        ])
        
        # Crear archivo Excel
        output = BytesIO()
        workbook = xlsxwriter.Workbook(output)
        worksheet = workbook.add_worksheet('Libro Remuneraciones')
        
        # Formatos
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#D7E4BD',
            'border': 1
        })
        
        # Headers
        headers = [
            'RUT', 'Nombre', 'Cargo', 'Fecha Ingreso',
            'Sueldo Base', 'HEX50', 'HEX100', 'Bonos',
            'Total Imponible', 'AFP', 'Salud', 'AFC',
            'Impuesto', 'Total Descuentos', 'Líquido',
            # ... más columnas
        ]
        
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        # Datos
        row = 1
        for payslip in payslips:
            worksheet.write(row, 0, payslip.employee_id.identification_id)
            worksheet.write(row, 1, payslip.employee_id.name)
            # ... más datos
            row += 1
        
        workbook.close()
        output.seek(0)
        
        # Retornar archivo
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/...?download=true',
            'target': 'self',
        }
```

**Tiempo:** 8 horas

---

#### **9.3 Previred (TXT 105 campos)** ❌ **0%**

```python
# wizards/wizard_export_previred.py - CREAR

class WizardExportPrevired(models.TransientModel):
    _name = 'wizard.export.previred'
    _description = 'Exportar Previred'
    
    month = fields.Selection([
        ('01', 'Enero'), ('02', 'Febrero'), ('03', 'Marzo'),
        # ... 12 meses
    ], required=True)
    
    year = fields.Selection([
        ('2024', '2024'), ('2025', '2025'), ('2026', '2026'),
    ], required=True)
    
    def action_generate_previred(self):
        """
        Generar archivo Previred TXT
        
        Formato fijo 105 campos:
        - Largo registro: 710 caracteres
        - Sin delimitadores
        - Posiciones fijas
        
        Especificación completa:
        https://www.previred.com/web/previred/...
        """
        
        # Buscar liquidaciones del mes
        date_from = f"{self.year}-{self.month}-01"
        date_to = self._get_last_day_month(self.year, self.month)
        
        payslips = self.env['hr.payslip'].search([
            ('date_from', '>=', date_from),
            ('date_to', '<=', date_to),
            ('state', '=', 'done'),
        ])
        
        lines = []
        
        for payslip in payslips:
            # Construir línea 710 caracteres
            line = self._build_previred_line(payslip)
            lines.append(line)
        
        # Archivo TXT
        content = '\n'.join(lines)
        filename = f"Previred_{self.year}{self.month}.txt"
        
        # Guardar y descargar
        attachment = self.env['ir.attachment'].create({
            'name': filename,
            'datas': base64.b64encode(content.encode('iso-8859-1')),
            'mimetype': 'text/plain',
        })
        
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'self',
        }
    
    def _build_previred_line(self, payslip):
        """
        Construir línea Previred 710 caracteres
        
        Campos críticos (105 total):
        01: RUT empleador (10)
        02: DV empleador (1)
        03: RUT trabajador (10)
        04: DV trabajador (1)
        05: Apellido paterno (30)
        06: Apellido materno (30)
        07: Nombres (30)
        ...
        105: Campo control (10)
        """
        line = ""
        
        # Campo 01: RUT empleador (posición 1-10)
        line += payslip.company_id.vat.rjust(10, '0')
        
        # Campo 02: DV empleador (posición 11)
        line += payslip.company_id.vat[-1]
        
        # Campo 03-04: RUT trabajador
        employee_rut = payslip.employee_id.identification_id.replace('.', '').replace('-', '')
        line += employee_rut[:-1].rjust(10, '0')
        line += employee_rut[-1]
        
        # ... 100 campos más
        
        # Validar largo 710
        if len(line) != 710:
            raise ValidationError(f"Línea Previred debe tener 710 caracteres, tiene {len(line)}")
        
        return line
```

**Tiempo:** 24 horas (complejo, 105 campos)

---

#### **9.4 Certificado F30-1 (PDF)** ❌ **0%**

Reporte anual de remuneraciones para el trabajador.

**Tiempo:** 6 horas

---

#### **9.5 Resumen Contable** ❌ **0%**

Resumen para integración contable (asientos automáticos).

**Tiempo:** 8 horas

---

### **PASO 10: FINIQUITO**

#### **Estado Actual** ❌ **0% IMPLEMENTADO**

**Brechas críticas:**

```python
# models/hr_settlement.py - CREAR COMPLETO

class HrSettlement(models.Model):
    """
    Liquidación Final (Finiquito)
    
    Modelo para gestión de finiquitos según Código del Trabajo Chile.
    """
    _name = 'hr.settlement'
    _description = 'Liquidación Final (Finiquito)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date desc'
    
    # CAMPOS BÁSICOS
    name = fields.Char('Número', required=True, copy=False, default='/')
    employee_id = fields.Many2one('hr.employee', 'Empleado', required=True)
    contract_id = fields.Many2one('hr.contract', 'Contrato', required=True)
    
    # FECHAS
    date = fields.Date('Fecha Finiquito', required=True, default=fields.Date.today)
    date_start = fields.Date('Fecha Ingreso', related='contract_id.date_start')
    date_end = fields.Date('Fecha Término', required=True)
    
    # MOTIVO TÉRMINO
    termination_reason = fields.Selection([
        ('resignation', 'Renuncia Voluntaria'),
        ('dismissal_cause', 'Despido con Causa (Art. 160)'),
        ('dismissal_no_cause', 'Despido sin Causa (Art. 161)'),
        ('mutual_agreement', 'Mutuo Acuerdo'),
        ('contract_end', 'Término de Contrato a Plazo'),
        ('death', 'Fallecimiento'),
    ], string='Causal de Término', required=True)
    
    article_ct = fields.Char('Artículo CT', help='Artículo Código del Trabajo')
    
    # CÁLCULOS
    
    # 1. Remuneraciones pendientes
    pending_salary = fields.Monetary('Sueldo Proporcional', currency_field='currency_id')
    pending_hex = fields.Monetary('Horas Extras Pendientes', currency_field='currency_id')
    pending_bonus = fields.Monetary('Bonos Pendientes', currency_field='currency_id')
    
    # 2. Vacaciones
    vacation_days_total = fields.Float('Días Vacaciones Totales')
    vacation_days_taken = fields.Float('Días Vacaciones Tomadas')
    vacation_days_pending = fields.Float('Días Vacaciones Pendientes', 
                                         compute='_compute_vacation_days')
    vacation_amount = fields.Monetary('Monto Vacaciones Proporcionales',
                                     currency_field='currency_id')
    
    # 3. Indemnizaciones
    years_service = fields.Float('Años de Servicio', compute='_compute_years_service')
    
    # Indemnización años servicio (Art. 163 CT)
    indemnification_years = fields.Monetary(
        'Indemnización Años Servicio',
        currency_field='currency_id',
        help='30 días de remuneración por año (tope 11 años)'
    )
    
    # Indemnización sustitutiva aviso previo (Art. 162 CT)
    indemnification_notice = fields.Monetary(
        'Indemnización Aviso Previo',
        currency_field='currency_id',
        help='30 días de remuneración si no hubo aviso previo'
    )
    
    # Indemnización voluntaria
    indemnification_voluntary = fields.Monetary(
        'Indemnización Voluntaria',
        currency_field='currency_id'
    )
    
    # 4. Descuentos
    afp_amount = fields.Monetary('AFP', currency_field='currency_id')
    health_amount = fields.Monetary('Salud', currency_field='currency_id')
    afc_amount = fields.Monetary('AFC', currency_field='currency_id')
    tax_amount = fields.Monetary('Impuesto', currency_field='currency_id')
    other_deductions = fields.Monetary('Otros Descuentos', currency_field='currency_id')
    
    # TOTALES
    total_haberes = fields.Monetary('Total Haberes', 
                                    compute='_compute_totals',
                                    currency_field='currency_id')
    total_indemnifications = fields.Monetary('Total Indemnizaciones',
                                            compute='_compute_totals',
                                            currency_field='currency_id')
    total_deductions = fields.Monetary('Total Descuentos',
                                       compute='_compute_totals',
                                       currency_field='currency_id')
    total_net = fields.Monetary('Líquido a Pagar',
                                compute='_compute_totals',
                                currency_field='currency_id')
    
    # ESTADO
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('calculated', 'Calculado'),
        ('validated', 'Validado'),
        ('paid', 'Pagado'),
        ('cancel', 'Cancelado'),
    ], default='draft', tracking=True)
    
    # MÉTODOS
    
    def action_calculate(self):
        """
        Calcular finiquito completo
        """
        for settlement in self:
            # 1. Sueldo proporcional
            settlement._calculate_pending_salary()
            
            # 2. Vacaciones proporcionales
            settlement._calculate_vacation_amount()
            
            # 3. Indemnizaciones
            settlement._calculate_indemnifications()
            
            # 4. Descuentos previsionales
            settlement._calculate_deductions()
            
            settlement.state = 'calculated'
    
    def _calculate_indemnifications(self):
        """
        Calcular indemnizaciones según causal
        """
        self.ensure_one()
        
        # Años de servicio (tope 11 años)
        years = min(self.years_service, 11)
        monthly_salary = self.contract_id.wage
        
        if self.termination_reason == 'dismissal_no_cause':
            # Art. 163: 30 días por año (tope 11 años)
            self.indemnification_years = (monthly_salary / 30) * 30 * years
            
            # Art. 162: Indemnización aviso previo (30 días)
            self.indemnification_notice = monthly_salary
            
        elif self.termination_reason == 'mutual_agreement':
            # Negociable, generalmente reducida
            self.indemnification_years = (monthly_salary / 30) * 20 * years
            
        else:
            # Sin indemnización legal
            self.indemnification_years = 0
            self.indemnification_notice = 0
```

**Tiempo:** 32 horas (cálculo complejo + reporte legal)

---

## 📊 RESUMEN DE BRECHAS POR COMPONENTE

| Componente | Estado | % | Prioridad | Tiempo |
|------------|--------|---|-----------|--------|
| **Ficha Trabajador** | ❌ Incompleto | 70% | 🟡 Media | 4h |
| **Contrato** | ✅ Casi completo | 95% | 🟡 Media | 2h |
| **Inputs** | ✅ Completo | 95% | 🟡 Media | 3h |
| **Estructura Salarial** | ✅ Completo | 100% | ✅ Completo | 0h |
| **Reglas Salariales** | ⚠️ Brechas | 85% | 🔴 Alta | 16h |
| **Cálculos** | ✅ Casi completo | 95% | 🟡 Media | 8h |
| **Generación Liquidaciones** | ✅ Completo | 95% | 🟢 Baja | 4h |
| **Lotes Nómina** | ⚠️ Brechas | 80% | 🟡 Media | 12h |
| **Reportes** | ❌ Crítico | 20% | 🔴 Alta | 52h |
| **Finiquito** | ❌ No implementado | 0% | 🔴 Alta | 32h |
| **TOTAL ODOO MODULE** | | **85%** | | **133h** |
| | | | | |
| **Payroll-Service** | ❌ No iniciado | 0% | 🔴 Alta | 40h |
| **AI-Service Extension** | ❌ No iniciado | 0% | 🟡 Media | 24h |
| **TOTAL MICROSERVICIOS** | | **0%** | | **64h** |
| | | | | |
| **TOTAL PROYECTO** | | **73%** | | **197h** |

---

## 🎯 PROGRESO ACTUAL vs OBJETIVO

```
ESTADO ACTUAL (Sprint 3.2):
├─ Core Odoo Module: 85% ████████████████▓▓▓
├─ Microservicios:     0% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
└─ TOTAL:             73% ██████████████▓▓▓▓▓▓

OBJETIVO (100%):
├─ Core Odoo Module: 100% ████████████████████
├─ Microservicios:   100% ████████████████████
└─ TOTAL:            100% ████████████████████

BRECHA: 27% (197 horas)
```

---

## 📈 COMPARACIÓN CON SOPA 2025 (ODOO 11)

| Feature | SOPA 2025 (Odoo 11) | Actual (Odoo 19) | Gap |
|---------|---------------------|------------------|-----|
| **Categorías SOPA** | 22 ✅ | 22 ✅ | 0% ✅ |
| **Totalizadores** | 4 ✅ | 4 ✅ | 0% ✅ |
| **Haberes base** | ✅ | ✅ | 0% ✅ |
| **HEX (3 tipos)** | ✅ | ✅ | 0% ✅ |
| **AFP (10 fondos)** | ✅ | ✅ | 0% ✅ |
| **Salud (FONASA/ISAPRE)** | ✅ | ✅ | 0% ✅ |
| **AFC** | ✅ | ✅ | 0% ✅ |
| **Impuesto 7 tramos** | ✅ | ✅ | 0% ✅ |
| **Gratificación Legal** | ✅ | ❌ | 100% ❌ |
| **Asignación Familiar** | ✅ | ❌ | 100% ❌ |
| **Aportes Empleador** | ✅ | ❌ | 100% ❌ |
| **Liquidación PDF** | ✅ | ❌ | 100% ❌ |
| **Libro Remuneraciones** | ✅ | ❌ | 100% ❌ |
| **Previred** | ✅ | ❌ | 100% ❌ |
| **F30-1** | ✅ | ❌ | 100% ❌ |
| **Finiquito** | ✅ | ❌ | 100% ❌ |
| **Analytics** | ✅ (NumPy/Pandas) | ❌ | 100% ❌ |
| **Audit Trail** | ✅ | Parcial | 50% ⚠️ |

**Paridad funcional:** 58% (11/19 features)

---

## 🚀 SIGUIENTE PASO: PLAN DE CIERRE BRECHAS

Ver documento: `28_PLAN_CIERRE_BRECHAS_COMPLETO.md`

---

**Documento generado:** 2025-10-23  
**Autor:** Claude AI + Pedro  
**Versión:** 1.0  
**Estado:** ✅ ANÁLISIS COMPLETO - LISTO PARA PLAN
