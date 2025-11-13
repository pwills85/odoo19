# ✅ Checklist Validaciones Odoo 19 CE - OBLIGATORIO

**Versión:** 1.0.0  
**Fecha creación:** 2025-11-12  
**Propósito:** Prevenir deprecaciones P0/P1/P2 en código generado  
**Uso:** TODOS los prompts auditoría/desarrollo/cierre DEBEN referenciar este documento

---

## 🎯 Objetivo

Este checklist garantiza que **todo código generado/modificado** cumple con estándares Odoo 19 CE, evitando breaking changes y problemas de producción.

**Integración en prompts:**
```markdown
## ✅ Validaciones Odoo 19 CE

**Ver checklist completo:** `docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md`
**Guía deprecaciones:** `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md`

[Aplicar validaciones P0 + P1 según tipo de cambio]
```

---

## 🔴 VALIDACIONES P0 - BREAKING CHANGES (Deadline: 2025-03-01)

### P0-01: QWeb Templates - `t-esc` → `t-out` ✅

**Status global:** 85/87 fixed (97.7% compliance)

#### ✅ Validación Pre-Commit

```bash
# Detectar uso deprecated en XML templates
grep -rn "t-esc" addons/localization/*/views/*.xml \
  addons/localization/*/reports/*.xml \
  --color=always

# Esperado: 0 matches (excepto backups)
```

#### 📋 Transformación Automática

```xml
<!-- ❌ EVITAR (breaking en Odoo 19) -->
<span t-esc="widget.name"/>
<div t-esc="record.description"/>
<p t-esc="o.partner_id.name"/>

<!-- ✅ USAR (Odoo 19 compliant) -->
<span t-out="widget.name"/>
<div t-out="record.description"/>
<p t-out="o.partner_id.name"/>
```

#### 🔧 Script Corrección

```bash
# Ejecutar migración automática (con backup)
python3 scripts/odoo19_migration/2_migrate_safe.py \
  --pattern qweb \
  --target addons/localization/l10n_cl_*/views/ \
  --dry-run

# Aplicar cambios si dry-run OK
python3 scripts/odoo19_migration/2_migrate_safe.py \
  --pattern qweb \
  --target addons/localization/l10n_cl_*/views/
```

---

### P0-02: HTTP Controllers - `type='json'` → `type='jsonrpc'` ✅

**Status global:** 26/26 routes fixed (100% compliance)

#### ✅ Validación Pre-Commit

```bash
# Detectar type='json' deprecated
grep -rn "type='json'" addons/localization/*/controllers/*.py \
  --color=always

# Esperado: 0 matches
```

#### 📋 Transformación Obligatoria

```python
# ❌ EVITAR (breaking en Odoo 19)
@http.route('/api/dte/validate', type='json', auth='user')
def validate_dte(self, folio):
    return {'status': 'ok'}

# ✅ USAR (Odoo 19 compliant)
@http.route('/api/dte/validate', type='jsonrpc', auth='user', csrf=False)
def validate_dte(self, folio):
    return {'status': 'ok'}
```

**⚠️ IMPORTANTE:** SIEMPRE agregar `csrf=False` a rutas `jsonrpc`

#### 🔧 Script Corrección

```bash
# Ejecutar migración automática
python3 scripts/odoo19_migration/2_migrate_safe.py \
  --pattern http_route \
  --target addons/localization/l10n_cl_*/controllers/ \
  --dry-run
```

---

### P0-03: XML Views - `attrs=` → Python Expressions ⚠️

**Status global:** 0/24 fixed (PENDIENTE MANUAL - deadline 2025-03-01)

#### ✅ Validación Pre-Commit

```bash
# Detectar attrs= en XML views
grep -rn "attrs=" addons/localization/*/views/*.xml \
  addons/localization/*/wizards/*views.xml \
  --color=always | grep -v ".backup"

# Esperado: 0 matches (actualmente 24 en 6 archivos)
```

#### 📋 Transformaciones Manuales Requeridas

**Operadores básicos:**
```python
# Boolean
[('field', '=', True)]              → field == True  o  field
[('field', '!=', False)]            → field != False  o  field
[('field', '=', False)]             → field == False  o  not field

# Comparación
[('state', '=', 'draft')]           → state == 'draft'
[('state', '!=', 'done')]           → state != 'done'
[('amount', '>', 0)]                → amount > 0
[('amount', '<=', 1000)]            → amount <= 1000

# Pertenencia
[('type', 'in', ('invoice', 'bill'))]    → type in ('invoice', 'bill')
[('state', 'not in', ['draft', 'cancel'])] → state not in ['draft', 'cancel']
```

**Lógica AND/OR:**
```python
# AND (coma implícita)
[('a', '=', True), ('b', '=', True)]     → a and b

# OR (prefijo '|')
['|', ('a', '=', True), ('b', '=', True)] → a or b

# OR múltiple
['|', '|', ('x', '=', 1), ('y', '=', 2), ('z', '=', 3)] → x == 1 or y == 2 or z == 3

# NOT (prefijo '!')
['!', ('state', '=', 'done')]            → state != 'done'

# Combinaciones complejas
['|', ('a', '=', True), '&', ('b', '=', True), ('c', '!=', False)]
→ a or (b and c)
```

**Casos especiales:**
```python
# parent_id en contexto de vista
[('parent_id', '=', parent.id)]     → parent_id == parent.id
[('parent_id', 'in', parent_ids)]   → parent_id in parent_ids

# Acceso a campos relacionados
[('partner_id.country_id', '=', country)]  → partner_id.country_id == country
```

#### 🗂️ Archivos Pendientes (6 files, 24 occurrences)

**Alta prioridad (9+ occurrences):**
1. `l10n_cl_financial_reports/views/l10n_cl_f29_views.xml` (9)

**Media prioridad (3-5 occurrences):**
2. `l10n_cl_hr_payroll/wizards/previred_validation_wizard_views.xml` (5)
3. `l10n_cl_financial_reports/wizards/financial_dashboard_add_widget_wizard_view.xml` (3)

**Baja prioridad (1-2 occurrences):**
4. `l10n_cl_financial_reports/wizards/l10n_cl_f22_config_wizard_views.xml` (1)
5. `l10n_cl_financial_reports/views/financial_dashboard_layout_views.xml` (2)
6. `l10n_cl_financial_reports/views/res_config_settings_views.xml` (4)

**⚠️ ACCIÓN REQUERIDA:** Migración manual antes de 2025-03-01 (4-6h estimadas)

---

### P0-04: ORM - `_sql_constraints` → `models.Constraint` ⚠️

**Status global:** 0/3 constraints fixed (PENDIENTE MANUAL - deadline 2025-03-01)

#### ✅ Validación Pre-Commit

```bash
# Detectar _sql_constraints
grep -rn "_sql_constraints = \[" addons/localization/*/models/*.py \
  --color=always

# Esperado: 0 matches (actualmente 3 en 2 archivos)
```

#### 📋 Transformación Manual

```python
# ❌ EVITAR (breaking en Odoo 19)
class FinancialDashboard(models.Model):
    _name = 'financial.dashboard'
    
    _sql_constraints = [
        ('name_uniq', 'unique (name)', 'Name must be unique!'),
        ('user_template_unique', 'unique (user_id, template_id)', 
         'User can only have one template!'),
    ]

# ✅ USAR (Odoo 19 compliant)
class FinancialDashboard(models.Model):
    _name = 'financial.dashboard'
    
    _sql_constraints = []  # Vaciar o eliminar completamente
    
    # Constraints como atributos de clase
    name_uniq = models.Constraint(
        'unique (name)',
        'Name must be unique!'
    )
    
    user_template_unique = models.Constraint(
        'unique (user_id, template_id)',
        'User can only have one template!'
    )
```

#### 🗂️ Archivos Pendientes (2 files, 3 constraints)

1. **`l10n_cl_financial_reports/models/financial_dashboard_template.py`** (2 constraints)
   - `name_uniq`: unique (name)
   - `user_template_unique`: unique (user_id, template_id)

2. **`l10n_cl_financial_reports/models/financial_dashboard_layout.py`** (1 constraint)
   - `user_widget_unique`: unique(user_id, widget_identifier)

**⚠️ ACCIÓN REQUERIDA:** Refactorizar antes de 2025-03-01 (30-45 min estimadas)

---

### P0-05: Dashboard Views - `<dashboard>` → `<kanban>` ⚠️

**Status global:** 0/2 dashboards fixed (PENDIENTE MANUAL - l10n_cl_dte)

#### ✅ Validación Pre-Commit

```bash
# Detectar tag <dashboard> deprecated
grep -rn "<dashboard" addons/localization/*/views/*.xml \
  --color=always | grep -v ".backup"

# Esperado: 0 matches (actualmente 2 en l10n_cl_dte)
```

#### 📋 Transformación Manual

```xml
<!-- ❌ EVITAR (breaking en Odoo 19) -->
<record id="view_dte_dashboard" model="ir.ui.view">
    <field name="name">DTE Dashboard</field>
    <field name="model">account.move</field>
    <field name="arch" type="xml">
        <dashboard>
            <widget name="dte_stats"/>
        </dashboard>
    </field>
</record>

<!-- ✅ USAR (Odoo 19 compliant) -->
<record id="view_dte_dashboard" model="ir.ui.view">
    <field name="name">DTE Dashboard</field>
    <field name="model">account.move</field>
    <field name="arch" type="xml">
        <kanban class="o_kanban_dashboard">
            <field name="id"/>
            <templates>
                <t t-name="kanban-box">
                    <div class="oe_kanban_global_click">
                        <div class="o_kanban_card_header">
                            <div class="o_kanban_card_header_title">
                                <div class="o_primary">DTE Dashboard</div>
                            </div>
                        </div>
                        <div class="container o_kanban_card_content">
                            <!-- Widgets aquí -->
                            <div class="row">
                                <div class="col-12">
                                    <widget name="dte_stats"/>
                                </div>
                            </div>
                        </div>
                    </div>
                </t>
            </templates>
        </kanban>
    </field>
</record>
```

#### 🗂️ Archivos Pendientes (2 dashboards, ~740 líneas)

1. `addons/localization/l10n_cl_dte/views/account_move_views.xml`
   - Dashboard DTE principal (400 líneas estimadas)
   - Dashboard estadísticas SII (340 líneas estimadas)

**⚠️ ACCIÓN REQUERIDA:** Conversión antes de 2025-03-01 (10-12h estimadas)

---

## 🟡 VALIDACIONES P1 - HIGH PRIORITY (Deadline: 2025-06-01)

### P1-01: Database Access - `self._cr` → `self.env.cr` ✅

**Status global:** 119/132 fixed (90.2% compliance, 13 en tests pendientes)

#### ✅ Validación Pre-Commit

```bash
# Detectar self._cr (excepto en tests/comments)
grep -rn "self\._cr" addons/localization/*/models/*.py \
  addons/localization/*/wizards/*.py \
  addons/localization/*/controllers/*.py \
  --color=always | grep -v "# TODO" | grep -v "tests/"

# Esperado: 0 matches en código producción
```

#### 📋 Transformación Automática

```python
# ❌ EVITAR (thread-unsafe, no multi-company)
self._cr.execute("SELECT id, name FROM res_partner")
self._cr.commit()
self._cr.rollback()

# ✅ USAR (Odoo 19 compliant)
self.env.cr.execute("SELECT id, name FROM res_partner")
self.env.cr.commit()
self.env.cr.rollback()
```

**Razón:**
- `self.env.cr` es thread-safe
- Respeta contexto multi-company
- Aplica security rules correctamente

#### 🔧 Script Corrección

```bash
# Ejecutar migración automática (con backup)
python3 scripts/odoo19_migration/2_migrate_safe.py \
  --pattern database_cursor \
  --target addons/localization/l10n_cl_*/models/ \
  --dry-run
```

---

### P1-02: View Methods - `fields_view_get()` → `get_view()`

**Status global:** 0/1 fixed (PENDIENTE - 1 archivo)

#### ✅ Validación Pre-Commit

```bash
# Detectar fields_view_get()
grep -rn "def fields_view_get" addons/localization/*/models/*.py \
  --color=always

# Esperado: 0 matches
```

#### 📋 Transformación Manual

```python
# ❌ EVITAR (deprecated en Odoo 19)
@api.model
def fields_view_get(self, view_id=None, view_type='form', 
                    toolbar=False, submenu=False):
    result = super().fields_view_get(view_id, view_type, toolbar, submenu)
    # Modificar result['arch']
    return result

# ✅ USAR (Odoo 19 compliant)
@api.model
def get_view(self, view_id=None, view_type='form', **options):
    result = super().get_view(view_id, view_type, **options)
    # Modificar result['arch']
    return result
```

#### 🗂️ Archivos Pendientes (1 file)

1. `l10n_cl_financial_reports/models/mixins/dynamic_states_mixin.py`

**⚠️ ACCIÓN REQUERIDA:** Refactorizar antes de 2025-06-01 (15-30 min estimadas)

---

### P1-03: Decorators - `@api.depends` Comportamiento Acumulativo

**Status global:** 184 occurrences (AUDIT ONLY - no breaking automático)

#### ⚠️ Validación Conceptual

**Cambio de comportamiento en Odoo 19:**
- `@api.depends` es ahora **acumulativo** en herencia
- Si heredas un método con `@api.depends`, las dependencias se SUMAN automáticamente

```python
# Clase base (en core Odoo o módulo padre)
class AccountMove(models.Model):
    _name = 'account.move'
    
    @api.depends('line_ids.debit', 'line_ids.credit')
    def _compute_amount_total(self):
        for move in self:
            move.amount_total = sum(move.line_ids.mapped('debit'))

# Clase heredada (tu módulo)
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    
    # ⚠️ CUIDADO: Ahora depende de line_ids.debit + line_ids.credit + l10n_cl_dte_exempt_amount
    @api.depends('l10n_cl_dte_exempt_amount')
    def _compute_amount_total(self):
        super()._compute_amount_total()
        # Agregar lógica adicional DTE
        for move in self:
            if move.l10n_cl_dte_type_id:
                move.amount_total += move.l10n_cl_dte_exempt_amount
```

#### 📋 Patrón Recomendado

**Opción A: No redeclarar `@api.depends` si no hay nuevas dependencias**
```python
# ✅ Si solo extiendes lógica sin agregar campos
def _compute_amount_total(self):
    super()._compute_amount_total()
    # Lógica adicional usando campos ya dependientes
```

**Opción B: Declarar SOLO nuevas dependencias**
```python
# ✅ Si agregas dependencia nueva
@api.depends('l10n_cl_dte_exempt_amount')  # Solo la nueva
def _compute_amount_total(self):
    super()._compute_amount_total()
    # Lógica adicional
```

**Opción C: Redeclarar TODAS las dependencias (explícito)**
```python
# ✅ Si quieres ser explícito (verbose pero claro)
@api.depends('line_ids.debit', 'line_ids.credit', 'l10n_cl_dte_exempt_amount')
def _compute_amount_total(self):
    super()._compute_amount_total()
    # Lógica adicional
```

#### 🔧 Acción Manual

**NO requiere cambios inmediatos**, pero revisar:
- Métodos heredados con `@api.depends`
- Verificar que no hay recálculos duplicados
- Documentar dependencias acumulativas en docstrings

---

## 🟢 VALIDACIONES P2 - BEST PRACTICES

### P2-01: Internationalization - Usar `_lt()` para Lazy Translations

**Status global:** 659 occurrences (AUDIT ONLY - mejora opcional)

#### 📋 Patrón Recomendado

```python
# ⚠️ NO IDEAL (traduce inmediatamente al cargar módulo)
from odoo import _

class MyModel(models.Model):
    _name = 'my.model'
    
    def action_validate(self):
        raise UserError(_("Error message"))  # Traduce AHORA

# ✅ MEJOR (lazy translation - traduce cuando se usa)
from odoo.tools.translate import _lt

class MyModel(models.Model):
    _name = 'my.model'
    
    ERROR_MESSAGE = _lt("Error message")  # Traduce CUANDO se evalúa
    
    def action_validate(self):
        raise UserError(self.ERROR_MESSAGE)
```

#### 🎯 Cuándo Usar `_lt()`

**Obligatorio:**
- Mensajes en atributos de clase
- Strings en `default` de campos
- Selection values

**Recomendado:**
- Mensajes de error en métodos computados
- Strings generados dinámicamente
- Logs con contexto traducible

**Innecesario:**
- Labels de campos (`string=_("Field")` está OK)
- Help texts (`help=_("Help text")` está OK)
- Mensajes dentro de métodos que se ejecutan on-demand

---

## 🚀 SCRIPTS Y HERRAMIENTAS

### Auditoría Completa Automática

```bash
# Ejecutar auditoría de todas las deprecaciones
python3 scripts/odoo19_migration/1_audit_deprecations.py

# Ver reporte detallado
cat audit_report.md

# Validar estado actual
python3 scripts/odoo19_migration/3_validate_changes.py
```

### Migración Automática (Patrones P0 + P1 automáticos)

```bash
# DRY RUN (simular cambios sin aplicar)
python3 scripts/odoo19_migration/2_migrate_safe.py \
  --pattern all \
  --target addons/localization/ \
  --dry-run

# APLICAR cambios (con backup automático)
python3 scripts/odoo19_migration/2_migrate_safe.py \
  --pattern all \
  --target addons/localization/

# Revertir si hay problemas
git stash pop  # Restaura backup automático
```

### Validación Pre-Commit (Git Hook)

```bash
# Instalar git hook validación Odoo 19
cp scripts/odoo19_migration/git-hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit

# Hook validará automáticamente:
# - NO usar t-esc en XML
# - NO usar type='json' en routes
# - NO usar self._cr en Python
# - Advertirá sobre attrs= y _sql_constraints
```

---

## 📊 COMPLIANCE DASHBOARD (Estado Actual)

| Prioridad | Patrón | Total | Fixed | Pending | Rate | Deadline |
|-----------|--------|-------|-------|---------|------|----------|
| **P0** | `t-esc` | 87 | 85 | 2 backups | 97.7% | 2025-03-01 |
| **P0** | `type='json'` | 26 | 26 | 0 | 100% | 2025-03-01 |
| **P0** | `attrs=` | 24 | 0 | 24 MANUAL | 0% | 2025-03-01 |
| **P0** | `_sql_constraints` | 3 | 0 | 3 MANUAL | 0% | 2025-03-01 |
| **P0** | `<dashboard>` | 2 | 0 | 2 MANUAL | 0% | 2025-03-01 |
| **P1** | `self._cr` | 132 | 119 | 13 tests | 90.2% | 2025-06-01 |
| **P1** | `fields_view_get()` | 1 | 0 | 1 MANUAL | 0% | 2025-06-01 |
| **P1** | `@api.depends` | 184 | N/A | AUDIT | - | 2025-06-01 |
| **P2** | `_lt()` usage | 659 | N/A | AUDIT | - | - |

**Compliance Global:**
- **P0:** 80.4% (111/138 automáticas, 27 manuales pendientes)
- **P1:** 8.8% (119/1,324 auditorías completadas)
- **P2:** 0% (659 auditorías pendientes)

**Próximo deadline crítico:** 2025-03-01 (109 días restantes) - **29 deprecaciones P0 manuales pendientes**

---

## 🔗 REFERENCIAS

### Documentación Interna

- **Guía completa deprecaciones:** `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md`
- **Sistema migración:** `scripts/odoo19_migration/README.md`
- **Config deprecaciones:** `scripts/odoo19_migration/config/deprecations.yaml`
- **Informe final:** `CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md`
- **Resumen trabajo:** `RESUMEN_TRABAJO_MIGRACION_ODOO19.md`

### Documentación Externa

- **Odoo 19 Release Notes:** https://www.odoo.com/odoo-19
- **Odoo 19 API Changes:** https://www.odoo.com/documentation/19.0/developer/reference/backend/upgrade.html
- **Odoo 19 ORM Guide:** https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html

---

## ✅ CHECKLIST RESUMEN (Copy-Paste Ready)

**Para usar en prompts de desarrollo/auditoría:**

```markdown
## ✅ Validaciones Odoo 19 CE Obligatorias

**Checklist completo:** `docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md`

### P0 - BREAKING CHANGES (Deadline: 2025-03-01)
- [ ] ✅ NO usar `t-esc` en templates XML (usar `t-out`)
- [ ] ✅ NO usar `type='json'` en routes (usar `type='jsonrpc'` + `csrf=False`)
- [ ] ⚠️ NO usar `attrs=` en XML views (usar expresiones Python directas)
- [ ] ⚠️ NO usar `_sql_constraints` (usar `models.Constraint`)
- [ ] ⚠️ NO usar `<dashboard>` (convertir a `<kanban class="o_kanban_dashboard">`)

### P1 - HIGH PRIORITY (Deadline: 2025-06-01)
- [ ] ✅ NO usar `self._cr` (usar `self.env.cr`)
- [ ] ⚠️ NO usar `fields_view_get()` (usar `get_view()`)
- [ ] 📋 Revisar `@api.depends` en herencias (comportamiento acumulativo)

### Comandos Validación
```bash
# Auditoría completa
python3 scripts/odoo19_migration/1_audit_deprecations.py

# Validar código específico
grep -rn "t-esc\|type='json'\|attrs=\|self\._cr" addons/localization/MODULE_NAME/
```
```

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-12  
**Mantenedor:** Pedro Troncoso Willz (@pwills85)  
**Compliance:** 80.4% P0 | 8.8% P1 | 0% P2
