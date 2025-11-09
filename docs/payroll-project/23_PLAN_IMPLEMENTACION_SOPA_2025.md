# 🚀 PLAN IMPLEMENTACIÓN SOPA 2025 → Odoo 19 CE

**Duración:** 8 horas (1 día)  
**Estrategia:** Incremental con validación continua  
**Riesgo:** BAJO

---

## 📋 FASES

| # | Fase | Duración | Riesgo |
|---|------|----------|--------|
| 0 | Preparación | 30min | Ninguno |
| 1 | Estructura | 3h | Bajo |
| 2 | Totalizadores | 2h | Bajo |
| 3 | Cálculos | 2h | Medio |
| 4 | Testing | 30min | Bajo |

---

## 🔧 FASE 0: PREPARACIÓN (30min)

### Backup + Branch

```bash
cd /Users/pedro/Documents/odoo19

# Backup
cp -r addons/localization/l10n_cl_hr_payroll \
      addons/localization/l10n_cl_hr_payroll.backup_$(date +%Y%m%d)

# Branch Git
git checkout -b feature/sopa-2025

echo "✅ Preparación completa"
```

---

## 🏗️ FASE 1: ESTRUCTURA (3h)

### 1.1 Extender Modelo (1h)

Editar `models/hr_salary_rule_category.py` - Agregar:
- `parent_id` (Many2one)
- `child_ids` (One2many)
- `tipo` (Selection)
- `imponible` (Boolean)
- `tributable` (Boolean)
- `afecta_gratificacion` (Boolean)

### 1.2 Crear Categorías Base (1h)

Crear `data/hr_salary_rule_category_base.xml` con 13 categorías:
- BASE, HABER, DESC, APORTE (raíz)
- GROSS, TOTAL_IMPO, RENTA_TRIB, NET (totalizadores)
- IMPO, NOIMPO (sub-haberes)
- LEGAL, TRIB, OTRO (sub-descuentos)

### 1.3 Crear Categorías SOPA (1h)

Crear `data/hr_salary_rule_category_sopa.xml` con 9 categorías:
- BASE_SOPA, HEX_SOPA, BONUS_SOPA, etc.

---

## 📊 FASE 2: TOTALIZADORES (2h)

### 2.1 Agregar Computed Fields

Editar `models/hr_payslip.py` - Agregar:

```python
total_imponible = fields.Monetary(compute='_compute_totalizadores')
total_tributable = fields.Monetary(compute='_compute_totalizadores')
total_gratificacion_base = fields.Monetary(compute='_compute_totalizadores')

@api.depends('line_ids.total', 'line_ids.category_id')
def _compute_totalizadores(self):
    for payslip in self:
        imponible_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.imponible == True
        )
        payslip.total_imponible = sum(imponible_lines.mapped('total'))
        # ... resto
```

---

## 🔢 FASE 3: CÁLCULOS (2h)

### 3.1 Refactorizar _calculate_afp()

```python
def _calculate_afp(self):
    # Antes: base_afp = self.contract_id.wage
    # Ahora: base_afp = self.total_imponible
    
    base_afp = self.total_imponible
    # ... resto igual
```

### 3.2 Refactorizar _calculate_tax()

```python
def _calculate_tax(self):
    # Usar total_tributable
    base_impuesto = self.total_tributable
    # ... resto
```

---

## ✅ FASE 4: TESTING (30min)

```python
# tests/test_sopa_migration.py

def test_totalizadores(self):
    payslip = self._create_payslip()
    self.assertGreater(payslip.total_imponible, 0)

def test_category_hierarchy(self):
    child = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible')
    self.assertTrue(child.parent_id)
```

---

## 📦 ARCHIVOS A CREAR/MODIFICAR

**Crear:**
1. `data/hr_salary_rule_category_base.xml`
2. `data/hr_salary_rule_category_sopa.xml`
3. `tests/test_sopa_migration.py`

**Modificar:**
1. `models/hr_salary_rule_category.py`
2. `models/hr_payslip.py`
3. `__manifest__.py`

---

## ✅ CHECKLIST

- [ ] Fase 0: Backup + Branch
- [ ] Fase 1.1: Modelo extendido
- [ ] Fase 1.2: Categorías base
- [ ] Fase 1.3: Categorías SOPA
- [ ] Fase 2: Totalizadores
- [ ] Fase 3: Cálculos refactorizados
- [ ] Fase 4: Tests pasando
- [ ] Commit final

---

**Siguiente paso:** Ejecutar Fase 0
