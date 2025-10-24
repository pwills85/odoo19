# 🏛️ ESTRUCTURA SALARIAL CHILE - Análisis Crítico

**Fecha:** 2025-10-22  
**Criticidad:** 🔴 ALTA - Gap crítico identificado  
**Impacto:** Legal + Operacional

---

## ⚠️ PROBLEMA IDENTIFICADO

### **Estado Actual: INSUFICIENTE**

**Categorías actuales** (4):
```python
- Haberes (BASIC)
- Descuentos Legales (DED)
- Otros Descuentos (OTHER_DED)
- Líquido (NET)
```

**Problema:** NO distingue entre:
- ❌ Imponible vs No Imponible
- ❌ Tributable vs No Tributable
- ❌ Afecta Gratificación vs No Afecta

**Consecuencia:** Cálculos incorrectos → Multas DT/SII

---

## 📋 ESTRUCTURA LEGAL CHILENA

### **Según Código del Trabajo + Dirección del Trabajo**

#### **1. HABERES IMPONIBLES**
**Definición:** Afectan cálculo AFP y Salud

```
✅ Imponibles:
- Sueldo base
- Sobresueldo (horas extra)
- Comisiones
- Bonos de producción
- Gratificación legal
- Participación (si pactada)
- Aguinaldos (si habituales)

❌ NO Imponibles:
- Asignación familiar (Art. 1 Ley 18.020)
- Colación (Art. 41 CT, tope 20% IMM)
- Movilización (Art. 41 CT, tope 20% IMM)
- Asignación pérdida caja
- Asignación desgaste herramientas
- Viáticos (comprobados)
- Indemnizaciones legales
```

#### **2. HABERES TRIBUTABLES**
**Definición:** Afectan cálculo Impuesto Único

```
✅ Tributables:
- Sueldo base
- Sobresueldo
- Comisiones
- Bonos
- Gratificación
- Participación

❌ NO Tributables:
- Asignación familiar
- Indemnizaciones legales
- Asignaciones Art. 41 CT (dentro de topes)
```

#### **3. BASES DE CÁLCULO**

```python
# Base AFP
base_afp = sum(haberes_imponibles)
if base_afp > (87.8 * UF):
    base_afp = 87.8 * UF  # Tope

# Base Salud
base_salud = sum(haberes_imponibles)  # Sin tope

# Base Impuesto
base_impuesto = sum(haberes_tributables) - afp - salud - apv
```

---

## 🔴 RIESGOS ACTUALES

### **LEGALES**

| Riesgo | Multa | Probabilidad |
|--------|-------|--------------|
| AFP mal calculado | 2-40 UTM | Alta |
| Impuesto incorrecto | 50%-300% diferencia | Alta |
| Previred rechazado | Bloqueo pago cotizaciones | Media |
| Auditoría DT Art. 54 | Hasta 60 UTM | Media |

**Costo potencial:** $5M - $20M CLP

### **OPERACIONALES**

- Liquidaciones incorrectas
- Reclamos empleados
- Re-cálculos manuales
- Pérdida confianza sistema
- Tiempo RRHH en correcciones

### **TÉCNICOS**

- Imposible agregar conceptos correctamente
- Lógica hardcoded
- No escalable
- Testing complejo
- Deuda técnica alta

---

## ✅ SOLUCIÓN PROPUESTA

### **Estructura Correcta de Categorías**

```python
# models/hr_salary_rule_category.py - EXTENDER

class HrSalaryRuleCategory(models.Model):
    _name = 'hr.salary.rule.category'
    _description = 'Categoría de Concepto'
    _order = 'sequence, id'
    
    name = fields.Char('Nombre', required=True, translate=True)
    code = fields.Char('Código', required=True)
    sequence = fields.Integer('Secuencia', default=10)
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS NUEVOS - CRÍTICOS PARA CHILE
    # ═══════════════════════════════════════════════════════════
    
    tipo = fields.Selection([
        ('haber', 'Haber'),
        ('descuento', 'Descuento'),
        ('totalizador', 'Totalizador')
    ], string='Tipo', required=True, default='haber')
    
    imponible = fields.Boolean(
        string='Imponible AFP/Salud',
        default=False,
        help='Si True, afecta cálculo AFP y Salud'
    )
    
    tributable = fields.Boolean(
        string='Tributable Impuesto',
        default=False,
        help='Si True, afecta cálculo Impuesto Único'
    )
    
    afecta_gratificacion = fields.Boolean(
        string='Afecta Gratificación',
        default=False,
        help='Si True, se considera para cálculo gratificación'
    )
    
    signo = fields.Selection([
        ('positivo', 'Positivo (+)'),
        ('negativo', 'Negativo (-)')
    ], string='Signo', default='positivo')
    
    note = fields.Text('Descripción')
```

### **Categorías Requeridas** (10)

```xml
<!-- data/hr_salary_rule_category.xml -->

<!-- HABERES IMPONIBLES -->
<record id="category_haber_imponible" model="hr.salary.rule.category">
    <field name="name">Haberes Imponibles</field>
    <field name="code">HAB_IMP</field>
    <field name="sequence">10</field>
    <field name="tipo">haber</field>
    <field name="imponible">True</field>
    <field name="tributable">True</field>
    <field name="afecta_gratificacion">True</field>
    <field name="signo">positivo</field>
</record>

<!-- HABERES NO IMPONIBLES -->
<record id="category_haber_no_imponible" model="hr.salary.rule.category">
    <field name="name">Haberes No Imponibles</field>
    <field name="code">HAB_NO_IMP</field>
    <field name="sequence">20</field>
    <field name="tipo">haber</field>
    <field name="imponible">False</field>
    <field name="tributable">False</field>
    <field name="afecta_gratificacion">False</field>
    <field name="signo">positivo</field>
</record>

<!-- HABERES TRIBUTABLES NO IMPONIBLES -->
<record id="category_haber_trib_no_imp" model="hr.salary.rule.category">
    <field name="name">Haberes Tributables No Imponibles</field>
    <field name="code">HAB_TRIB_NO_IMP</field>
    <field name="sequence">30</field>
    <field name="tipo">haber</field>
    <field name="imponible">False</field>
    <field name="tributable">True</field>
    <field name="afecta_gratificacion">False</field>
    <field name="signo">positivo</field>
</record>

<!-- DESCUENTOS LEGALES -->
<record id="category_descuento_legal" model="hr.salary.rule.category">
    <field name="name">Descuentos Legales</field>
    <field name="code">DESC_LEGAL</field>
    <field name="sequence">100</field>
    <field name="tipo">descuento</field>
    <field name="imponible">False</field>
    <field name="tributable">False</field>
    <field name="signo">negativo</field>
</record>

<!-- DESCUENTOS VOLUNTARIOS -->
<record id="category_descuento_voluntario" model="hr.salary.rule.category">
    <field name="name">Descuentos Voluntarios</field>
    <field name="code">DESC_VOL</field>
    <field name="sequence">110</field>
    <field name="tipo">descuento</field>
    <field name="imponible">False</field>
    <field name="tributable">False</field>
    <field name="signo">negativo</field>
</record>

<!-- TOTALIZADORES -->
<record id="category_total_haberes" model="hr.salary.rule.category">
    <field name="name">Total Haberes</field>
    <field name="code">TOTAL_HAB</field>
    <field name="sequence">200</field>
    <field name="tipo">totalizador</field>
</record>

<record id="category_total_imponible" model="hr.salary.rule.category">
    <field name="name">Total Imponible</field>
    <field name="code">TOTAL_IMP</field>
    <field name="sequence">210</field>
    <field name="tipo">totalizador</field>
</record>

<record id="category_total_tributable" model="hr.salary.rule.category">
    <field name="name">Total Tributable</field>
    <field name="code">TOTAL_TRIB</field>
    <field name="sequence">220</field>
    <field name="tipo">totalizador</field>
</record>

<record id="category_total_descuentos" model="hr.salary.rule.category">
    <field name="name">Total Descuentos</field>
    <field name="code">TOTAL_DESC</field>
    <field name="sequence">300</field>
    <field name="tipo">totalizador</field>
</record>

<record id="category_liquido" model="hr.salary.rule.category">
    <field name="name">Líquido a Pagar</field>
    <field name="code">LIQUIDO</field>
    <field name="sequence">400</field>
    <field name="tipo">totalizador</field>
</record>
```

---

## 🔧 REFACTORIZACIÓN CÁLCULOS

### **Agregar Computed Fields en hr.payslip**

```python
# models/hr_payslip.py - AGREGAR

class HrPayslip(models.Model):
    _inherit = 'hr.payslip'
    
    # ═══════════════════════════════════════════════════════════
    # TOTALIZADORES (Computed)
    # ═══════════════════════════════════════════════════════════
    
    total_haberes = fields.Monetary(
        string='Total Haberes',
        compute='_compute_totalizadores',
        store=True,
        currency_field='currency_id'
    )
    
    total_imponible = fields.Monetary(
        string='Total Imponible',
        compute='_compute_totalizadores',
        store=True,
        currency_field='currency_id',
        help='Base para AFP y Salud'
    )
    
    total_tributable = fields.Monetary(
        string='Total Tributable',
        compute='_compute_totalizadores',
        store=True,
        currency_field='currency_id',
        help='Base para Impuesto Único'
    )
    
    total_descuentos_legales = fields.Monetary(
        string='Total Descuentos Legales',
        compute='_compute_totalizadores',
        store=True,
        currency_field='currency_id'
    )
    
    total_descuentos_voluntarios = fields.Monetary(
        string='Total Descuentos Voluntarios',
        compute='_compute_totalizadores',
        store=True,
        currency_field='currency_id'
    )
    
    @api.depends('line_ids.total', 'line_ids.category_id')
    def _compute_totalizadores(self):
        """Calcular totalizadores según categorías"""
        for payslip in self:
            # Total Haberes
            haber_lines = payslip.line_ids.filtered(
                lambda l: l.category_id.tipo == 'haber'
            )
            payslip.total_haberes = sum(haber_lines.mapped('total'))
            
            # Total Imponible
            imponible_lines = payslip.line_ids.filtered(
                lambda l: l.category_id.imponible == True
            )
            payslip.total_imponible = sum(imponible_lines.mapped('total'))
            
            # Total Tributable
            tributable_lines = payslip.line_ids.filtered(
                lambda l: l.category_id.tributable == True
            )
            payslip.total_tributable = sum(tributable_lines.mapped('total'))
            
            # Descuentos Legales
            desc_legal_lines = payslip.line_ids.filtered(
                lambda l: l.category_id.code == 'DESC_LEGAL'
            )
            payslip.total_descuentos_legales = abs(sum(desc_legal_lines.mapped('total')))
            
            # Descuentos Voluntarios
            desc_vol_lines = payslip.line_ids.filtered(
                lambda l: l.category_id.code == 'DESC_VOL'
            )
            payslip.total_descuentos_voluntarios = abs(sum(desc_vol_lines.mapped('total')))
    
    
    def _calculate_afp(self):
        """Calcular AFP usando total_imponible"""
        self.ensure_one()
        
        # Base: Total Imponible
        base_afp = self.total_imponible
        
        # Aplicar tope 87.8 UF
        afp_limit_clp = self.indicadores_id.uf * self.indicadores_id.afp_limit
        if base_afp > afp_limit_clp:
            base_afp = afp_limit_clp
        
        # Calcular AFP
        afp_rate = self.contract_id.afp_rate / 100
        afp_amount = base_afp * afp_rate
        
        return afp_amount
    
    
    def _calculate_tax(self):
        """Calcular Impuesto usando total_tributable"""
        self.ensure_one()
        
        # Base: Total Tributable - Descuentos Legales
        base_impuesto = self.total_tributable - self.total_descuentos_legales
        
        # Rebaja cargas familiares
        # ... (código existente)
        
        # Calcular impuesto
        # ... (código existente)
```

---

## 📊 IMPACTO EN PLAN

### **Nuevo Sprint: ESTRUCTURA SALARIAL**

**Ubicación:** ANTES de Sprint 3.2 (Cálculos)  
**Duración:** 8 horas (1 día)  
**Criticidad:** 🔴 BLOQUEANTE

**Tareas:**
1. Extender modelo hr_salary_rule_category (1h)
2. Crear 10 categorías correctas (1h)
3. Migrar categorías existentes (1h)
4. Agregar totalizadores en hr_payslip (2h)
5. Refactorizar cálculos (2h)
6. Testing (1h)

**Entregable:**
- ✅ Estructura legal completa
- ✅ 10 categorías configuradas
- ✅ Totalizadores funcionando
- ✅ Cálculos usando bases correctas

---

## ⚠️ PLAN ACTUALIZADO

### **FASE 1: CRÍTICO** (46 horas - 6 días)

**NUEVO:**
- **SPRINT 3.0: ESTRUCTURA SALARIAL** (8h - 1 día) 🔴 NUEVO

**Existentes:**
- SPRINT 3.1: TESTING (16h - 2 días)
- SPRINT 3.2: CÁLCULOS (8h - 1 día)
- SPRINT 3.3: PERFORMANCE (6h - 1 día)
- SPRINT 3.4: PREVIRED (8h - 1 día)

**Total Fase 1:** 46 horas (6 días)

---

## ✅ RECOMENDACIÓN

**ACCIÓN INMEDIATA:**

1. ✅ Implementar Sprint 3.0 (Estructura Salarial)
2. ✅ Validar con experto legal/contable
3. ✅ Continuar con Sprint 3.1 (Testing)

**Sin estructura correcta, TODO lo demás será incorrecto.**

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** 🔴 CRÍTICO - Requiere acción inmediata
