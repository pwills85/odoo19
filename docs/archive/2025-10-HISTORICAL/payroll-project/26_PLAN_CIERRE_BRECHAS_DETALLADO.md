# 🛠️ PLAN ROBUSTO DE CIERRE DE BRECHAS - Sprint 3.0

**Fecha:** 2025-10-22  
**Duración:** 45 minutos  
**Criticidad:** 🔴 ALTA - Bloquea testing

---

## 🔍 BRECHAS CONFIRMADAS

### **🔴 CRÍTICAS (Bloquean ejecución)**

#### **1. Referencias a categorías inexistentes**

**Ubicación:** `models/hr_payslip.py`

```python
# Línea 441
CategoryLegal = self.env.ref('l10n_cl_hr_payroll.category_desc_legal')
# ↑ NO EXISTE en XML → UserError

# Línea 532
'category_id': self.env.ref('l10n_cl_hr_payroll.category_deduction').id
# ↑ NO EXISTE en XML → Error
```

**Impacto:** Código falla inmediatamente en runtime

---

#### **2. Variables no definidas en _calculate_health()**

**Ubicación:** `models/hr_payslip.py` líneas 527-537

```python
def _calculate_health(self):
    # ...
    LineObj.create({  # ← LineObj NO DEFINIDO → NameError
        'amount': wage,  # ← wage NO DEFINIDO → NameError
    })
```

**Impacto:** NameError en runtime

---

#### **3. Código duplicado/muerto en _calculate_health()**

**Problema:** Líneas 527-537 crean líneas dentro de un método que solo debe calcular

```python
def _calculate_health(self):
    """Calcular salud"""
    if self.contract_id.health_system == 'fonasa':
        health_amount = self.contract_id.wage * 0.07
    elif self.contract_id.health_system == 'isapre':
        # ... cálculo ...
        
        # ↓ ESTO NO DEBE ESTAR AQUÍ
        LineObj.create({  # Código duplicado
            'slip_id': self.id,
            # ...
        })
    
    # ↓ NUNCA SE EJECUTA (código muerto)
    _logger.info(...)
```

**Impacto:** Lógica incorrecta + código muerto

---

### **🟡 ALTAS (Cálculos incorrectos)**

#### **4. Cálculos no usan total_imponible**

**Ubicación:** `models/hr_payslip.py`

```python
# Línea 506 - _calculate_afp()
imponible_afp = min(self.contract_id.wage, afp_limit_clp)
# ↑ INCORRECTO: Usa solo sueldo base

# Línea 514 - _calculate_health() FONASA
health_amount = self.contract_id.wage * 0.07
# ↑ INCORRECTO: Usa solo sueldo base

# Línea 518 - _calculate_health() ISAPRE
legal_7pct = self.contract_id.wage * 0.07
# ↑ INCORRECTO: Usa solo sueldo base
```

**Impacto Legislación Chilena:**
- Si empleado tiene bonos imponibles, NO se consideran
- AFP se calcula solo sobre sueldo base (INCORRECTO)
- Salud se calcula solo sobre sueldo base (INCORRECTO)
- Incumple Art. 41 Código del Trabajo

**Ejemplo:**
```
Sueldo base: $1,000,000
Bono producción: $500,000 (imponible)
Total imponible: $1,500,000

ACTUAL (incorrecto):
AFP = $1,000,000 * 11.44% = $114,400

CORRECTO:
AFP = $1,500,000 * 11.44% = $171,600

Diferencia: $57,200 (33% menos) ← ILEGAL
```

---

### **🟢 MEDIAS (Incompletitud)**

#### **5. XML incompleto**

**Actual:** 4 categorías  
**Requerido:** 9 categorías

**Faltantes:**
- `category_haber_no_imponible` (NOIMPO)
- `category_descuentos` (DESC)
- `category_desc_legal` (LEGAL) ← Referenciada en código
- `category_renta_tributable` (RENTA_TRIB)
- `category_liquido` (NET)

---

## 🛠️ PLAN DE CORRECCIÓN

### **FASE 1: Completar XML** (15 minutos)

**Archivo:** `data/hr_salary_rule_category_base.xml`

**Acción:** Agregar 5 categorías faltantes

```xml
<!-- Agregar después de category_haber_imponible -->

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
</record>

<record id="category_descuentos" model="hr.salary.rule.category">
    <field name="name">Descuentos</field>
    <field name="code">DESC</field>
    <field name="sequence">100</field>
    <field name="tipo">descuento</field>
    <field name="signo">negativo</field>
</record>

<record id="category_desc_legal" model="hr.salary.rule.category">
    <field name="name">Descuentos Legales</field>
    <field name="code">LEGAL</field>
    <field name="parent_id" ref="category_descuentos"/>
    <field name="sequence">101</field>
    <field name="tipo">descuento</field>
    <field name="signo">negativo</field>
</record>

<record id="category_renta_tributable" model="hr.salary.rule.category">
    <field name="name">Renta Tributable</field>
    <field name="code">RENTA_TRIB</field>
    <field name="sequence">320</field>
    <field name="tipo">totalizador</field>
</record>

<record id="category_liquido" model="hr.salary.rule.category">
    <field name="name">Líquido a Pagar</field>
    <field name="code">NET</field>
    <field name="sequence">400</field>
    <field name="tipo">totalizador</field>
</record>
```

---

### **FASE 2: Limpiar _calculate_health()** (10 minutos)

**Archivo:** `models/hr_payslip.py` líneas 510-543

**Acción:** Eliminar código duplicado y simplificar

```python
def _calculate_health(self):
    """
    Calcular salud usando total_imponible
    
    Retorna monto a descontar según sistema de salud.
    """
    if self.contract_id.health_system == 'fonasa':
        # FONASA 7% fijo sobre total imponible
        health_amount = self.total_imponible * 0.07
        
    elif self.contract_id.health_system == 'isapre':
        # ISAPRE: plan en UF vs 7% legal
        plan_clp = self.contract_id.isapre_plan_uf * self.indicadores_id.uf
        legal_7pct = self.total_imponible * 0.07
        
        # Se paga el mayor entre plan y 7% legal
        health_amount = max(plan_clp, legal_7pct)
    else:
        health_amount = 0.0
    
    return health_amount
```

**Cambios:**
1. ✅ Usa `total_imponible` en lugar de `wage`
2. ✅ Elimina código duplicado (líneas 527-537)
3. ✅ Retorna solo el monto
4. ✅ Simplifica lógica ISAPRE (max en lugar de if)

---

### **FASE 3: Corregir _calculate_afp()** (5 minutos)

**Archivo:** `models/hr_payslip.py` líneas 503-508

**Acción:** Usar total_imponible

```python
def _calculate_afp(self):
    """
    Calcular AFP usando total_imponible
    
    Aplica tope de 87.8 UF según legislación chilena.
    """
    # Tope AFP: 87.8 UF (actualizado 2025)
    afp_limit_clp = self.indicadores_id.uf * self.indicadores_id.afp_limit
    
    # Base imponible con tope
    imponible_afp = min(self.total_imponible, afp_limit_clp)
    
    # Calcular AFP
    afp_amount = imponible_afp * (self.contract_id.afp_rate / 100)
    
    return afp_amount
```

**Cambios:**
1. ✅ Usa `total_imponible` en lugar de `contract_id.wage`
2. ✅ Documentación mejorada
3. ✅ Cumple legislación chilena

---

### **FASE 4: Eliminar referencia a category_deduction** (5 minutos)

**Archivo:** `models/hr_payslip.py` línea 532

**Problema:** Referencia a categoría que no existe

**Acción:** Esta línea está en código muerto que se eliminará en Fase 2

---

### **FASE 5: Verificación** (10 minutos)

#### **5.1 Sintaxis Python**
```bash
python3 -m py_compile models/hr_payslip.py
python3 -m py_compile models/hr_salary_rule_category.py
```

#### **5.2 Verificar XML**
```bash
xmllint --noout data/hr_salary_rule_category_base.xml
```

#### **5.3 Contar categorías**
```bash
grep -c "<record id=\"category_" data/hr_salary_rule_category_base.xml
# Debe retornar: 9
```

#### **5.4 Verificar referencias**
```bash
grep -n "category_" models/hr_payslip.py | grep "\.ref("
# Verificar que todas existen en XML
```

---

## ✅ CHECKLIST DE CORRECCIONES

### **XML**
- [ ] category_haber_no_imponible agregada
- [ ] category_descuentos agregada
- [ ] category_desc_legal agregada
- [ ] category_renta_tributable agregada
- [ ] category_liquido agregada
- [ ] Total: 9 categorías

### **Código Python**
- [ ] _calculate_health() limpiado (sin código duplicado)
- [ ] _calculate_health() usa total_imponible
- [ ] _calculate_afp() usa total_imponible
- [ ] Sin referencias a categorías inexistentes
- [ ] Sin variables no definidas

### **Verificación**
- [ ] Sintaxis Python válida
- [ ] XML válido
- [ ] 9 categorías en XML
- [ ] Todas las referencias existen

---

## 📊 IMPACTO DE CORRECCIONES

### **Antes (Incorrecto)**
```python
# AFP sobre sueldo base solamente
Sueldo: $1,000,000
Bono: $500,000 (imponible)
AFP = $1,000,000 * 11.44% = $114,400 ❌
```

### **Después (Correcto)**
```python
# AFP sobre total imponible
Sueldo: $1,000,000
Bono: $500,000 (imponible)
Total Imponible: $1,500,000
AFP = $1,500,000 * 11.44% = $171,600 ✅
```

**Diferencia:** $57,200 (33% más) - CUMPLE LEGISLACIÓN

---

## 🎯 RESULTADO ESPERADO

**Antes:** 80/100 (Aprobado con correcciones)  
**Después:** 95/100 (Excelente)

**Tiempo:** 45 minutos  
**Riesgo:** BAJO (correcciones quirúrgicas)

---

## 🚀 PRÓXIMOS PASOS

1. ✅ Aplicar correcciones (45 min)
2. ✅ Commit: "fix(payroll): Corregir brechas Sprint 3.0"
3. ✅ Testing básico
4. ✅ Proceder a Sprint 3.1

---

**Plan generado:** 2025-10-22  
**Estado:** ✅ LISTO PARA EJECUCIÓN  
**Aprobado:** SÍ
