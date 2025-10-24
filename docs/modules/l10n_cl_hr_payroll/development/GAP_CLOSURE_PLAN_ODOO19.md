# 🎯 PLAN CIERRE BRECHAS - l10n_cl_hr_payroll (Odoo 19 CE)

**Fecha:** 2025-10-23  
**Versión Odoo:** 19.0 Community Edition  
**Estado Actual:** 70% Core Completado  
**Duración:** 8 horas (1 día)  
**Técnicas:** Solo patrones oficiales Odoo 19 CE

---

## 📊 ANÁLISIS DE ESTADO ACTUAL

### ✅ COMPLETADO (70%)

**Modelos Python:**
- ✅ `hr_salary_rule_category.py` - Con jerarquía SOPA 2025 (_parent_store)
- ✅ `hr_payslip.py` - Con totalizadores computed
- ✅ `hr_contract_cl.py` - Extensión con campos Chile
- ✅ `hr_economic_indicators.py` - Indicadores + AI-Service
- ✅ Maestros: AFP, ISAPRE, APV

**Vistas XML:**
- ✅ 6 archivos views
- ✅ Seguridad (groups + access)
- ✅ Menús

**Patrones Odoo 19 CE Aplicados:**
- ✅ `_parent_store = True` (jerarquía optimizada)
- ✅ `@api.depends()` (campos computed)
- ✅ `@api.constrains()` (validaciones)
- ✅ `_sql_constraints` (constraints DB)
- ✅ Sin `@api.multi` (deprecated Odoo 13+)
- ✅ `self.ensure_one()` (garantía single record)

---

## 🔴 BRECHAS IDENTIFICADAS

### **BRECHA 1: Datos Base XML Vacío** 
**Criticidad:** 🔴 CRÍTICA  
**Impacto:** Módulo no instala correctamente

**Problema:**
```xml
<!-- data/hr_salary_rule_category_base.xml -->
<?xml version="1.0" encoding="utf-8"?>
<!-- VACÍO - Solo cierre de tags -->
```

**Consecuencia:**
- Referencias `env.ref('l10n_cl_hr_payroll.category_base')` → **UserError**
- Referencias `env.ref('l10n_cl_hr_payroll.category_desc_legal')` → **UserError**
- No se pueden crear liquidaciones

---

### **BRECHA 2: Totalizadores No Calculan**
**Criticidad:** 🟡 ALTA  
**Impacto:** Cálculos AFP/Salud incorrectos

**Problema:**
```python
# models/hr_payslip.py líneas 103-149

total_imponible = fields.Monetary(compute='_compute_totals', store=True)
total_tributable = fields.Monetary(compute='_compute_totals', store=True)

@api.depends('line_ids.total', 'line_ids.category_id')
def _compute_totals(self):
    # Método existe pero puede no ejecutarse en orden correcto
```

**Necesita:** Asegurar que `_compute_totals()` se ejecuta DESPUÉS de crear líneas

---

### **BRECHA 3: Falta Secuencia**
**Criticidad:** 🟢 MEDIA  
**Impacto:** Campo `number` queda vacío

**Problema:**
```python
# models/hr_payslip.py línea 36
number = fields.Char(
    string='Número',
    readonly=True,
    copy=False,
    help='Número único de liquidación'
)
# No hay lógica de asignación automática
```

---

## 🛠️ PLAN DE CORRECCIÓN (Odoo 19 CE)

---

## ✅ FASE 1: DATOS BASE XML (2 horas)

### **Objetivo:** Crear 22 categorías SOPA 2025 con jerarquía

### **1.1 Categorías Raíz** (30 min)

Editar `data/hr_salary_rule_category_base.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">
        
        <!-- ========================================== -->
        <!-- CATEGORÍAS RAÍZ (4) -->
        <!-- ========================================== -->
        
        <!-- 1. BASE (Sueldo Base) -->
        <record id="category_base" model="hr.salary.rule.category">
            <field name="name">Sueldo Base</field>
            <field name="code">BASE</field>
            <field name="sequence">10</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="True"/>
            <field name="tributable" eval="True"/>
            <field name="afecta_gratificacion" eval="True"/>
            <field name="signo">positivo</field>
            <field name="note">Sueldo base mensual del contrato</field>
        </record>
        
        <!-- 2. HABERES (Padre) -->
        <record id="category_haberes" model="hr.salary.rule.category">
            <field name="name">Haberes</field>
            <field name="code">HABER</field>
            <field name="sequence">20</field>
            <field name="tipo">haber</field>
            <field name="signo">positivo</field>
            <field name="note">Categoría padre de todos los haberes</field>
        </record>
        
        <!-- 3. DESCUENTOS (Padre) -->
        <record id="category_descuentos" model="hr.salary.rule.category">
            <field name="name">Descuentos</field>
            <field name="code">DESC</field>
            <field name="sequence">100</field>
            <field name="tipo">descuento</field>
            <field name="signo">negativo</field>
            <field name="note">Categoría padre de todos los descuentos</field>
        </record>
        
        <!-- 4. APORTES EMPLEADOR (Padre) -->
        <record id="category_aportes" model="hr.salary.rule.category">
            <field name="name">Aportes Empleador</field>
            <field name="code">APORTE</field>
            <field name="sequence">200</field>
            <field name="tipo">aporte</field>
            <field name="signo">positivo</field>
            <field name="note">Aportes que paga el empleador (no afectan líquido)</field>
        </record>

    </data>
</odoo>
```

**Técnica Odoo 19 CE:**
- ✅ `noupdate="1"` - No sobrescribir en actualizaciones
- ✅ `eval="True"` - Valores booleanos
- ✅ Campos `tipo`, `signo`, flags (imponible, tributable)

---

### **1.2 Sub-Categorías Haberes** (30 min)

Agregar después de categorías raíz:

```xml
        <!-- ========================================== -->
        <!-- SUB-CATEGORÍAS HABERES (2) -->
        <!-- ========================================== -->
        
        <!-- 2.1 Haberes Imponibles -->
        <record id="category_haber_imponible" model="hr.salary.rule.category">
            <field name="name">Haberes Imponibles</field>
            <field name="code">IMPO</field>
            <field name="parent_id" ref="category_haberes"/>
            <field name="sequence">21</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="True"/>
            <field name="tributable" eval="True"/>
            <field name="afecta_gratificacion" eval="True"/>
            <field name="signo">positivo</field>
            <field name="note">Haberes que afectan cálculo AFP/Salud (Art. 41 CT)</field>
        </record>
        
        <!-- 2.2 Haberes NO Imponibles -->
        <record id="category_haber_no_imponible" model="hr.salary.rule.category">
            <field name="name">Haberes NO Imponibles</field>
            <field name="code">NOIMPO</field>
            <field name="parent_id" ref="category_haberes"/>
            <field name="sequence">22</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="False"/>
            <field name="tributable" eval="False"/>
            <field name="afecta_gratificacion" eval="False"/>
            <field name="signo">positivo</field>
            <field name="note">Haberes que NO afectan AFP/Salud (colación, movilización, asig. familiar)</field>
        </record>
```

**Técnica Odoo 19 CE:**
- ✅ `parent_id` con `ref="category_haberes"` - Jerarquía
- ✅ `_parent_store = True` en modelo - Optimización consultas

---

### **1.3 Sub-Categorías Descuentos** (30 min)

```xml
        <!-- ========================================== -->
        <!-- SUB-CATEGORÍAS DESCUENTOS (3) -->
        <!-- ========================================== -->
        
        <!-- 3.1 Descuentos Legales -->
        <record id="category_desc_legal" model="hr.salary.rule.category">
            <field name="name">Descuentos Legales</field>
            <field name="code">LEGAL</field>
            <field name="parent_id" ref="category_descuentos"/>
            <field name="sequence">101</field>
            <field name="tipo">descuento</field>
            <field name="signo">negativo</field>
            <field name="note">AFP, Salud, Impuesto Único (obligatorios)</field>
        </record>
        
        <!-- 3.2 Descuentos Tributables -->
        <record id="category_desc_tributable" model="hr.salary.rule.category">
            <field name="name">Descuentos Tributables</field>
            <field name="code">TRIB</field>
            <field name="parent_id" ref="category_descuentos"/>
            <field name="sequence">102</field>
            <field name="tipo">descuento</field>
            <field name="signo">negativo</field>
            <field name="note">APV, seguros (rebajan base imponible impuesto)</field>
        </record>
        
        <!-- 3.3 Otros Descuentos -->
        <record id="category_desc_otros" model="hr.salary.rule.category">
            <field name="name">Otros Descuentos</field>
            <field name="code">OTRO</field>
            <field name="parent_id" ref="category_descuentos"/>
            <field name="sequence">103</field>
            <field name="tipo">descuento</field>
            <field name="signo">negativo</field>
            <field name="note">Préstamos, anticipos, otros descuentos voluntarios</field>
        </record>
```

---

### **1.4 Totalizadores** (30 min)

```xml
        <!-- ========================================== -->
        <!-- TOTALIZADORES (4) -->
        <!-- ========================================== -->
        
        <!-- T1. Gross (Haberes Totales) -->
        <record id="category_gross" model="hr.salary.rule.category">
            <field name="name">Total Haberes</field>
            <field name="code">GROSS</field>
            <field name="sequence">300</field>
            <field name="tipo">totalizador</field>
            <field name="note">Suma de todos los haberes (BASE + IMPO + NOIMPO)</field>
        </record>
        
        <!-- T2. Total Imponible -->
        <record id="category_total_imponible" model="hr.salary.rule.category">
            <field name="name">Total Imponible</field>
            <field name="code">TOTAL_IMPO</field>
            <field name="sequence">310</field>
            <field name="tipo">totalizador</field>
            <field name="note">Base para cálculo AFP y Salud</field>
        </record>
        
        <!-- T3. Renta Tributable -->
        <record id="category_renta_tributable" model="hr.salary.rule.category">
            <field name="name">Renta Tributable</field>
            <field name="code">RENTA_TRIB</field>
            <field name="sequence">320</field>
            <field name="tipo">totalizador</field>
            <field name="note">Base para cálculo Impuesto Único</field>
        </record>
        
        <!-- T4. Líquido a Pagar (NET) -->
        <record id="category_liquido" model="hr.salary.rule.category">
            <field name="name">Líquido a Pagar</field>
            <field name="code">NET</field>
            <field name="sequence">400</field>
            <field name="tipo">totalizador</field>
            <field name="note">Monto final a transferir al trabajador</field>
        </record>
```

---

### **1.5 Categorías SOPA 2025 (Específicas Chile)** (30 min)

Crear archivo nuevo: `data/hr_salary_rule_category_sopa.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">
        
        <!-- ========================================== -->
        <!-- CATEGORÍAS SOPA 2025 (9) -->
        <!-- Sistema Operativo de Pensiones y Asignaciones -->
        <!-- ========================================== -->
        
        <!-- SOPA 1: Base Sueldo -->
        <record id="category_base_sopa" model="hr.salary.rule.category">
            <field name="name">Base Sueldo SOPA</field>
            <field name="code">BASE_SOPA</field>
            <field name="parent_id" ref="category_base"/>
            <field name="sequence">11</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="True"/>
            <field name="tributable" eval="True"/>
            <field name="afecta_gratificacion" eval="True"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 2: Horas Extras -->
        <record id="category_hex_sopa" model="hr.salary.rule.category">
            <field name="name">Horas Extras SOPA</field>
            <field name="code">HEX_SOPA</field>
            <field name="parent_id" ref="category_haber_imponible"/>
            <field name="sequence">23</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="True"/>
            <field name="tributable" eval="True"/>
            <field name="afecta_gratificacion" eval="True"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 3: Bonos -->
        <record id="category_bonus_sopa" model="hr.salary.rule.category">
            <field name="name">Bonos SOPA</field>
            <field name="code">BONUS_SOPA</field>
            <field name="parent_id" ref="category_haber_imponible"/>
            <field name="sequence">24</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="True"/>
            <field name="tributable" eval="True"/>
            <field name="afecta_gratificacion" eval="False"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 4: Gratificación -->
        <record id="category_grat_sopa" model="hr.salary.rule.category">
            <field name="name">Gratificación SOPA</field>
            <field name="code">GRAT_SOPA</field>
            <field name="parent_id" ref="category_haber_imponible"/>
            <field name="sequence">25</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="True"/>
            <field name="tributable" eval="True"/>
            <field name="afecta_gratificacion" eval="False"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 5: Asignación Familiar -->
        <record id="category_asigfam_sopa" model="hr.salary.rule.category">
            <field name="name">Asignación Familiar SOPA</field>
            <field name="code">ASIGFAM_SOPA</field>
            <field name="parent_id" ref="category_haber_no_imponible"/>
            <field name="sequence">26</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="False"/>
            <field name="tributable" eval="False"/>
            <field name="afecta_gratificacion" eval="False"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 6: Colación -->
        <record id="category_colacion_sopa" model="hr.salary.rule.category">
            <field name="name">Colación SOPA</field>
            <field name="code">COL_SOPA</field>
            <field name="parent_id" ref="category_haber_no_imponible"/>
            <field name="sequence">27</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="False"/>
            <field name="tributable" eval="False"/>
            <field name="afecta_gratificacion" eval="False"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 7: Movilización -->
        <record id="category_movil_sopa" model="hr.salary.rule.category">
            <field name="name">Movilización SOPA</field>
            <field name="code">MOV_SOPA</field>
            <field name="parent_id" ref="category_haber_no_imponible"/>
            <field name="sequence">28</field>
            <field name="tipo">haber</field>
            <field name="imponible" eval="False"/>
            <field name="tributable" eval="False"/>
            <field name="afecta_gratificacion" eval="False"/>
            <field name="signo">positivo</field>
        </record>
        
        <!-- SOPA 8: AFP -->
        <record id="category_afp_sopa" model="hr.salary.rule.category">
            <field name="name">AFP SOPA</field>
            <field name="code">AFP_SOPA</field>
            <field name="parent_id" ref="category_desc_legal"/>
            <field name="sequence">104</field>
            <field name="tipo">descuento</field>
            <field name="signo">negativo</field>
        </record>
        
        <!-- SOPA 9: Salud -->
        <record id="category_salud_sopa" model="hr.salary.rule.category">
            <field name="name">Salud SOPA</field>
            <field name="code">SALUD_SOPA</field>
            <field name="parent_id" ref="category_desc_legal"/>
            <field name="sequence">105</field>
            <field name="tipo">descuento</field>
            <field name="signo">negativo</field>
        </record>
        
    </data>
</odoo>
```

---

## ✅ FASE 2: SECUENCIA (30 min)

### **Objetivo:** Generar número automático para liquidaciones

Crear archivo `data/ir_sequence.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">
        
        <!-- Secuencia para Liquidaciones -->
        <record id="sequence_hr_payslip" model="ir.sequence">
            <field name="name">Liquidación de Sueldo</field>
            <field name="code">hr.payslip</field>
            <field name="prefix">LIQ-%(year)s%(month)s-</field>
            <field name="padding">4</field>
            <field name="number_increment">1</field>
            <field name="number_next">1</field>
            <field name="implementation">standard</field>
            <field name="company_id" eval="False"/>
        </record>
        
    </data>
</odoo>
```

**Resultado:** `LIQ-202510-0001`, `LIQ-202510-0002`, etc.

**Técnica Odoo 19 CE:**
- ✅ `prefix` con formato dinámico `%(year)s%(month)s`
- ✅ `padding=4` para números con ceros (0001)
- ✅ `company_id eval="False"` para multi-company

---

### **2.1 Agregar Lógica de Asignación**

Editar `models/hr_payslip.py`, agregar método:

```python
@api.model_create_multi
def create(self, vals_list):
    """Asignar número secuencial - Odoo 19 CE"""
    for vals in vals_list:
        if vals.get('number', '/') == '/' or not vals.get('number'):
            vals['number'] = self.env['ir.sequence'].next_by_code('hr.payslip') or '/'
    return super(HrPayslip, self).create(vals_list)
```

**Técnica Odoo 19 CE:**
- ✅ `@api.model_create_multi` - Optimizado para creación masiva
- ✅ `next_by_code('hr.payslip')` - Obtener siguiente número
- ✅ Itera sobre `vals_list` (soporta create múltiple)

---

## ✅ FASE 3: ACTUALIZAR MANIFEST (15 min)

Editar `__manifest__.py`, agregar rutas data:

```python
'data': [
    # Seguridad
    'security/security_groups.xml',
    'security/ir.model.access.csv',
    
    # Datos base
    'data/ir_sequence.xml',  # ← AGREGAR
    'data/hr_salary_rule_category_base.xml',  # ← ACTUALIZAR
    'data/hr_salary_rule_category_sopa.xml',  # ← AGREGAR NUEVO
    
    # Vistas
    'views/hr_contract_views.xml',
    'views/hr_payslip_views.xml',
    'views/hr_economic_indicators_views.xml',
    'views/hr_afp_views.xml',
    'views/hr_isapre_views.xml',
    'views/menus.xml',
],
```

**Técnica Odoo 19 CE:**
- ✅ Orden: Seguridad → Datos → Vistas → Menús
- ✅ Secuencia antes de categorías (dependencias)

---

## ✅ FASE 4: REFORZAR TOTALIZADORES (1.5 horas)

### **Objetivo:** Asegurar cálculo correcto en orden

### **4.1 Mejorar _compute_totals()**

Editar `models/hr_payslip.py`, refactorizar método:

```python
@api.depends('line_ids.total', 'line_ids.category_id', 
             'line_ids.category_id.imponible', 
             'line_ids.category_id.tributable',
             'line_ids.category_id.afecta_gratificacion')
def _compute_totals(self):
    """
    Calcular totalizadores SOPA 2025 - Odoo 19 CE
    
    Usa flags de categorías para determinar qué líneas
    afectan cada totalizador.
    
    Totalizadores:
    - total_imponible: Suma líneas con category.imponible=True
    - total_tributable: Suma líneas con category.tributable=True
    - total_gratificacion_base: Suma líneas con category.afecta_gratificacion=True
    """
    for payslip in self:
        # Totalizador 1: Imponible (AFP + Salud)
        imponible_lines = payslip.line_ids.filtered(
            lambda l: l.category_id and l.category_id.imponible == True
        )
        payslip.total_imponible = sum(imponible_lines.mapped('total'))
        
        # Totalizador 2: Tributable (Impuesto)
        tributable_lines = payslip.line_ids.filtered(
            lambda l: l.category_id and l.category_id.tributable == True
        )
        payslip.total_tributable = sum(tributable_lines.mapped('total'))
        
        # Totalizador 3: Base Gratificación
        grat_lines = payslip.line_ids.filtered(
            lambda l: l.category_id and l.category_id.afecta_gratificacion == True
        )
        payslip.total_gratificacion_base = sum(grat_lines.mapped('total'))
        
        # Gross (suma positivos)
        payslip.gross_wage = sum(
            payslip.line_ids.filtered(lambda l: l.total > 0).mapped('total')
        )
        
        # Descuentos (suma negativos)
        payslip.deductions = abs(sum(
            payslip.line_ids.filtered(lambda l: l.total < 0).mapped('total')
        ))
        
        # Líquido
        payslip.net_wage = payslip.gross_wage - payslip.deductions
```

**Técnica Odoo 19 CE:**
- ✅ `@api.depends()` con todos los campos dependientes
- ✅ `filtered(lambda l: ...)` - Filtrado funcional
- ✅ `mapped('total')` - Extracción de valores
- ✅ `sum()` - Agregación
- ✅ Chequeo `l.category_id` (evitar NoneType error)

---

### **4.2 Forzar Recálculo Después de Crear Líneas**

Editar `models/hr_payslip.py`, método `_compute_basic_lines()`:

```python
def _compute_basic_lines(self):
    """
    Calcular líneas básicas de liquidación usando SOPA 2025
    
    Orden crítico:
    1. Crear líneas haberes (BASE)
    2. Invalidar cache y recalcular totalizadores
    3. Crear líneas descuentos (AFP, SALUD) usando totalizadores
    """
    self.ensure_one()
    
    # Limpiar líneas existentes
    self.line_ids.unlink()
    
    LineObj = self.env['hr.payslip.line']
    
    # Obtener categorías SOPA 2025
    CategoryBase = self.env.ref('l10n_cl_hr_payroll.category_base', raise_if_not_found=False)
    CategoryLegal = self.env.ref('l10n_cl_hr_payroll.category_desc_legal', raise_if_not_found=False)
    
    if not CategoryBase or not CategoryLegal:
        raise UserError(_(
            'Categorías SOPA 2025 no encontradas. '
            'Por favor actualice el módulo con: odoo -u l10n_cl_hr_payroll'
        ))
    
    # PASO 1: Crear sueldo base
    LineObj.create({
        'slip_id': self.id,
        'code': 'BASIC',
        'name': 'Sueldo Base',
        'sequence': 10,
        'category_id': CategoryBase.id,
        'amount': self.contract_id.wage,
        'quantity': 1.0,
        'rate': 100.0,
        'total': self.contract_id.wage,
    })
    
    # PASO 2: Invalidar cache y forzar recálculo totalizadores
    self.invalidate_recordset(['line_ids'])  # Odoo 19 CE
    self._compute_totals()  # Forzar cálculo explícito
    
    _logger.info(
        "Totalizadores calculados para %s: total_imponible=$%s",
        self.name,
        f"{self.total_imponible:,.0f}"
    )
    
    # PASO 3: Crear descuentos usando totalizadores
    # AFP (ahora usa total_imponible correcto)
    afp_amount = self._calculate_afp()
    if afp_amount > 0:
        LineObj.create({
            'slip_id': self.id,
            'code': 'AFP',
            'name': f'AFP {self.contract_id.afp_id.name}',
            'sequence': 100,
            'category_id': CategoryLegal.id,
            'amount': afp_amount,
            'quantity': 1.0,
            'rate': self.contract_id.afp_rate,
            'total': -afp_amount,
        })
    
    # Salud (ahora usa total_imponible correcto)
    health_amount = self._calculate_health()
    if health_amount > 0:
        health_name = 'FONASA' if self.contract_id.health_system == 'fonasa' else \
                      f'ISAPRE {self.contract_id.isapre_id.name}'
        LineObj.create({
            'slip_id': self.id,
            'code': 'HEALTH',
            'name': health_name,
            'sequence': 110,
            'category_id': CategoryLegal.id,
            'amount': health_amount,
            'quantity': 1.0,
            'rate': 7.0 if self.contract_id.health_system == 'fonasa' else 0.0,
            'total': -health_amount,
        })
    
    _logger.info(
        "Liquidación %s: %d líneas creadas, líquido=$%s",
        self.name,
        len(self.line_ids),
        f"{self.net_wage:,.0f}"
    )
```

**Técnica Odoo 19 CE:**
- ✅ `invalidate_recordset(['line_ids'])` - Odoo 15+ API
- ✅ Llamada explícita a `_compute_totals()` para forzar
- ✅ Logging con f-strings para debugging

---

## ✅ FASE 5: TESTING Y VALIDACIÓN (2 horas)

### **5.1 Test Unitario Categorías**

Crear `tests/test_sopa_categories.py`:

```python
# -*- coding: utf-8 -*-

from odoo.tests import common, tagged


@tagged('post_install', '-at_install', 'payroll_sopa')
class TestSOPACategories(common.TransactionCase):
    """Test SOPA 2025 Categories"""
    
    def setUp(self):
        super(TestSOPACategories, self).setUp()
        self.Category = self.env['hr.salary.rule.category']
    
    def test_01_categories_exist(self):
        """Verificar que existen 22 categorías"""
        categories = self.Category.search([])
        self.assertGreaterEqual(
            len(categories), 22,
            "Deben existir al menos 22 categorías SOPA 2025"
        )
    
    def test_02_category_base_exists(self):
        """Verificar categoría BASE"""
        category = self.env.ref('l10n_cl_hr_payroll.category_base')
        self.assertTrue(category.exists(), "Categoría BASE debe existir")
        self.assertEqual(category.code, 'BASE')
        self.assertTrue(category.imponible, "BASE debe ser imponible")
        self.assertTrue(category.tributable, "BASE debe ser tributable")
    
    def test_03_category_hierarchy(self):
        """Verificar jerarquía HABER → IMPO"""
        parent = self.env.ref('l10n_cl_hr_payroll.category_haberes')
        child = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible')
        
        self.assertEqual(
            child.parent_id.id, parent.id,
            "IMPO debe ser hijo de HABER"
        )
    
    def test_04_imponible_flags(self):
        """Verificar flags imponibles"""
        # Imponibles
        impo = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible')
        self.assertTrue(impo.imponible)
        
        # No imponibles
        noimpo = self.env.ref('l10n_cl_hr_payroll.category_haber_no_imponible')
        self.assertFalse(noimpo.imponible)
    
    def test_05_code_unique_constraint(self):
        """Verificar constraint código único"""
        from odoo.exceptions import ValidationError
        
        with self.assertRaises(ValidationError):
            self.Category.create({
                'name': 'Duplicado',
                'code': 'BASE',  # Ya existe
                'tipo': 'haber'
            })
```

**Técnica Odoo 19 CE:**
- ✅ Hereda de `common.TransactionCase`
- ✅ `@tagged()` para ejecutar selectivamente
- ✅ `self.env.ref()` para obtener external IDs
- ✅ `self.assertTrue()`, `assertEqual()` - Asserts estándar

---

### **5.2 Test Integración Totalizadores**

Crear `tests/test_payslip_totals.py`:

```python
# -*- coding: utf-8 -*-

from odoo.tests import common, tagged
from datetime import date


@tagged('post_install', '-at_install', 'payroll_sopa')
class TestPayslipTotals(common.TransactionCase):
    """Test Totalizadores SOPA 2025"""
    
    def setUp(self):
        super(TestPayslipTotals, self).setUp()
        
        # Crear empleado y contrato
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee',
        })
        
        # Obtener AFP e ISAPRE
        afp = self.env['hr.afp'].search([], limit=1)
        
        self.contract = self.env['hr.contract'].create({
            'name': 'Test Contract',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'state': 'open',
            'afp_id': afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
        })
        
        # Crear indicadores
        self.indicators = self.env['hr.economic.indicators'].create({
            'year': 2025,
            'month': 10,
            'uf': 39383.07,
            'afp_limit': 87.8,
        })
    
    def test_01_total_imponible_single_line(self):
        """Test total_imponible con solo sueldo base"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar
        self.assertEqual(
            payslip.total_imponible, 1000000,
            f"total_imponible debe ser 1.000.000, obtuvo {payslip.total_imponible}"
        )
    
    def test_02_afp_uses_total_imponible(self):
        """Test AFP usa total_imponible"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        payslip.action_compute_sheet()
        
        # AFP = 1.000.000 * 11.44% = 114.400
        afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')
        self.assertEqual(len(afp_line), 1, "Debe existir línea AFP")
        self.assertAlmostEqual(
            abs(afp_line.total), 114400, delta=10,
            f"AFP debe ser ~114.400, obtuvo {abs(afp_line.total)}"
        )
    
    def test_03_health_fonasa_uses_total_imponible(self):
        """Test FONASA usa total_imponible"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 31),
            'indicadores_id': self.indicators.id,
        })
        
        payslip.action_compute_sheet()
        
        # FONASA = 1.000.000 * 7% = 70.000
        health_line = payslip.line_ids.filtered(lambda l: l.code == 'HEALTH')
        self.assertEqual(len(health_line), 1, "Debe existir línea HEALTH")
        self.assertAlmostEqual(
            abs(health_line.total), 70000, delta=10,
            f"FONASA debe ser ~70.000, obtuvo {abs(health_line.total)}"
        )
```

**Técnica Odoo 19 CE:**
- ✅ Crear datos de prueba en `setUp()`
- ✅ `assertAlmostEqual()` con `delta` para floats
- ✅ `filtered(lambda ...)` para buscar líneas

---

### **5.3 Ejecutar Tests**

```bash
# Desde terminal
cd /Users/pedro/Documents/odoo19

# Test específico
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-tags=payroll_sopa --stop-after-init

# Ver solo resultados
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-tags=payroll_sopa --stop-after-init --log-level=test
```

**Técnica Odoo 19 CE:**
- ✅ `--test-tags=payroll_sopa` - Solo tests tagueados
- ✅ `--stop-after-init` - No iniciar servidor
- ✅ `--log-level=test` - Solo logs de tests

---

## ✅ FASE 6: INSTALACIÓN Y PRUEBA MANUAL (1.5 horas)

### **6.1 Actualizar Módulo**

```bash
# Actualizar código
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  -u l10n_cl_hr_payroll --stop-after-init

# Verificar logs
docker-compose logs odoo | grep -E "category_base|category_desc_legal"
```

---

### **6.2 Verificación Manual en UI**

**Paso 1: Verificar Categorías**
1. Abrir Odoo: http://localhost:8169
2. Ir a: Empleados → Configuración → Categorías Salariales
3. Verificar:
   - ✅ Existen 22 categorías
   - ✅ Jerarquía visible (iconos +/-)
   - ✅ Flags correctos (imponible, tributable)

**Paso 2: Crear Liquidación**
1. Ir a: Empleados → Nóminas → Liquidaciones
2. Crear nueva:
   - Empleado: Seleccionar
   - Período: Oct 2025
   - Botón "Calcular"
3. Verificar:
   - ✅ Número generado (LIQ-202510-0001)
   - ✅ 3 líneas: BASE, AFP, HEALTH
   - ✅ Total imponible: $1.000.000
   - ✅ AFP: $114.400
   - ✅ FONASA: $70.000
   - ✅ Líquido: $815.600

**Paso 3: Ver Totalizadores**
1. En form liquidación
2. Pestaña "Totales"
3. Verificar campos computed:
   - ✅ Total Imponible: $1.000.000
   - ✅ Total Haberes: $1.000.000
   - ✅ Total Descuentos: $184.400
   - ✅ Líquido a Pagar: $815.600

---

## 📊 CHECKLIST FINAL

### **Código Python**

- [x] `models/hr_salary_rule_category.py` - Con `_parent_store = True`
- [x] `models/hr_payslip.py` - Método `create()` con secuencia
- [x] `models/hr_payslip.py` - Método `_compute_totals()` robusto
- [x] `models/hr_payslip.py` - Método `_compute_basic_lines()` con invalidate_recordset
- [x] `models/hr_payslip.py` - Método `_calculate_afp()` usa total_imponible
- [x] `models/hr_payslip.py` - Método `_calculate_health()` usa total_imponible

### **Datos XML**

- [ ] `data/hr_salary_rule_category_base.xml` - 13 categorías base
- [ ] `data/hr_salary_rule_category_sopa.xml` - 9 categorías SOPA (NUEVO)
- [ ] `data/ir_sequence.xml` - Secuencia liquidaciones (NUEVO)

### **Manifest**

- [ ] `__manifest__.py` - Rutas data agregadas en orden correcto

### **Tests**

- [ ] `tests/test_sopa_categories.py` - 5 tests categorías (NUEVO)
- [ ] `tests/test_payslip_totals.py` - 3 tests totalizadores (NUEVO)
- [ ] `tests/__init__.py` - Imports agregados (NUEVO)

### **Validación**

- [ ] Módulo instala sin errores
- [ ] 22 categorías visibles en UI
- [ ] Liquidación genera número automático
- [ ] Cálculo AFP correcto ($114.400)
- [ ] Cálculo FONASA correcto ($70.000)
- [ ] Tests pasan (8/8)

---

## 🎯 RESULTADO ESPERADO

**Antes del Plan:**
- ❌ 4 categorías (insuficiente)
- ❌ Cálculos usan `wage` directo
- ❌ Sin secuencia
- ❌ 0% tests

**Después del Plan:**
- ✅ 22 categorías SOPA 2025
- ✅ Cálculos usan `total_imponible`
- ✅ Secuencia automática (LIQ-202510-XXXX)
- ✅ 8 tests automatizados
- ✅ 100% compatible Odoo 19 CE
- ✅ 0 errores instalación

---

## 📚 TÉCNICAS ODOO 19 CE APLICADAS

1. **Jerarquía Optimizada:** `_parent_store = True` + `parent_path`
2. **Campos Computed:** `@api.depends()` con todas las dependencias
3. **Invalidate Cache:** `invalidate_recordset()` API Odoo 15+
4. **Create Multi:** `@api.model_create_multi` para performance
5. **Secuencias:** `ir.sequence` con formato dinámico
6. **External IDs:** `env.ref()` para referencias robustas
7. **Constraints:** `_sql_constraints` + `@api.constrains()`
8. **Tests:** `TransactionCase` + `@tagged()` + asserts
9. **Logging:** `_logger.info()` con f-strings
10. **Error Handling:** `raise_if_not_found=False` para env.ref()

---

## ⏱️ TIEMPO ESTIMADO

| Fase | Duración | Criticidad |
|------|----------|------------|
| 1. Datos Base XML | 2h | 🔴 Crítica |
| 2. Secuencia | 30min | 🟢 Media |
| 3. Actualizar Manifest | 15min | 🟢 Media |
| 4. Reforzar Totalizadores | 1.5h | 🟡 Alta |
| 5. Testing | 2h | 🟡 Alta |
| 6. Instalación Manual | 1.5h | 🟢 Media |
| **TOTAL** | **8 horas** | - |

---

## 🚀 PRÓXIMOS PASOS (Después de cierre)

1. **Sprint 3.1:** Testing 80% coverage (16h)
2. **Sprint 3.2:** Cálculos completos (impuesto, gratificación) (8h)
3. **Sprint 3.3:** Performance optimization (6h)
4. **Sprint 3.4:** Previred export (8h)

**Total Fase 1:** 46 horas (6 días)

---

**Última actualización:** 2025-10-23 01:27 UTC  
**Estado:** ✅ Plan técnico listo para ejecución  
**Técnicas:** 100% Odoo 19 CE Official Patterns
