# ⚠️ ODOO 19 CE DEPRECATIONS - GUÍA CRÍTICA

**Última actualización:** 2025-11-11  
**Status:** Sistema migrado - 137 automáticas aplicadas | 27 manuales pendientes  
**Compliance:** 80.4% P0 cerradas

---

## 🚨 USO OBLIGATORIO PARA AGENTES AI

**ESTA INFORMACIÓN ES CRÍTICA - ERRAR AQUÍ CAUSA PROBLEMAS EN PRODUCCIÓN**

Todos los agentes AI que trabajen en este proyecto **DEBEN** validar su código contra estas deprecaciones antes de cualquier commit.

---

## 🔴 P0: BREAKING CHANGES (Deadline: 2025-03-01)

### 1. QWeb Templates: `t-esc` → `t-out` ✅ MIGRADO

**Status:** ✅ 85 occurrences fixed (2025-11-11)

```xml
<!-- ❌ DEPRECATED (will break in Odoo 19) -->
<span t-esc="widget.name"/>
<div t-esc="record.description"/>

<!-- ✅ CORRECTO (Odoo 19) -->
<span t-out="widget.name"/>
<div t-out="record.description"/>
```

**Razón:** Mejor seguridad XSS y consistencia con estándares modernos

**Archivos ya migrados:** 18 XML templates en `l10n_cl_financial_reports`, `l10n_cl_dte`

---

### 2. HTTP Controllers: `type='json'` → `type='jsonrpc'` ✅ MIGRADO

**Status:** ✅ 26 routes fixed (2025-11-11)

```python
# ❌ DEPRECATED (will be removed)
@http.route('/api/endpoint', type='json', auth='user')
def get_data(self):
    return {'data': []}

# ✅ CORRECTO (Odoo 19)
@http.route('/api/endpoint', type='jsonrpc', auth='user', csrf=False)
def get_data(self):
    return {'data': []}
```

**Razón:** `type='json'` será removido completamente en Odoo 19

**IMPORTANTE:** 
- SIEMPRE agregar `csrf=False` a rutas `jsonrpc`
- No usar `type='json'` en NINGÚN controlador nuevo

**Archivos ya migrados:**
- `l10n_cl_financial_reports/controllers/*.py` (5 archivos, 26 rutas)

---

### 3. XML Views: `attrs=` → Python Expressions ⚠️ PENDIENTE MANUAL

**Status:** ⚠️ 24 occurrences PENDING (6 files)

```xml
<!-- ❌ DEPRECATED (breaking change) -->
<field name="campo" attrs="{'invisible': [('state', '!=', 'draft')]}"/>
<button name="action" attrs="{'readonly': [('active', '=', False)]}"/>

<!-- ✅ CORRECTO (Odoo 19) -->
<field name="campo" invisible="state != 'draft'"/>
<button name="action" readonly="not active"/>
```

**Transformaciones comunes:**
```python
# Operadores
[('field', '=', 'value')]   → field == 'value'
[('field', '!=', 'value')]  → field != 'value'
[('field', 'in', (a,b))]    → field in (a, b)
[('field', 'not in', [a])]  → field not in [a]

# Lógica
[('a', '=', True), ('b', '!=', False)]  → a and b  # AND implícito
['|', ('a', '=', True), ('b', '=', True)]  → a or b
['!', ('state', '=', 'done')]  → state != 'done'
```

**Archivos pendientes:**
1. `l10n_cl_hr_payroll/wizards/previred_validation_wizard_views.xml` (5)
2. `l10n_cl_financial_reports/wizards/l10n_cl_f22_config_wizard_views.xml` (1)
3. `l10n_cl_financial_reports/wizards/financial_dashboard_add_widget_wizard_view.xml` (3)
4. `l10n_cl_financial_reports/views/financial_dashboard_layout_views.xml` (2)
5. `l10n_cl_financial_reports/views/l10n_cl_f29_views.xml` (9)
6. `l10n_cl_financial_reports/views/res_config_settings_views.xml` (4)

**⚠️ ACCIÓN REQUERIDA:** Migrar manualmente antes de 2025-03-01

---

### 4. ORM: `_sql_constraints` → `models.Constraint` ⚠️ PENDIENTE MANUAL

**Status:** ⚠️ 3 constraints PENDING (2 files)

```python
# ❌ DEPRECATED (will break)
class MyModel(models.Model):
    _sql_constraints = [
        ('name_uniq', 'unique (name)', 'Name must be unique!'),
    ]

# ✅ CORRECTO (Odoo 19)
class MyModel(models.Model):
    _sql_constraints = []  # Vaciar o eliminar
    
    name_uniq = models.Constraint(
        'unique (name)',
        'Name must be unique!'
    )
```

**Archivos pendientes:**
1. `l10n_cl_financial_reports/models/financial_dashboard_template.py` (2 constraints)
   - `name_uniq`: unique (name)
   - `user_template_unique`: unique (user_id, template_id)
2. `l10n_cl_financial_reports/models/financial_dashboard_layout.py` (1 constraint)
   - `user_widget_unique`: unique(user_id, widget_identifier)

**⚠️ ACCIÓN REQUERIDA:** Refactorizar antes de 2025-03-01

---

## 🟡 P1: HIGH PRIORITY (Deadline: 2025-06-01)

### 5. Database Access: `self._cr` → `self.env.cr` ✅ MIGRADO

**Status:** ✅ 119 occurrences fixed (2025-11-11)

```python
# ❌ DEPRECATED (thread-unsafe, no multi-company)
self._cr.execute("SELECT * FROM table")
self._cr.commit()

# ✅ CORRECTO (Odoo 19)
self.env.cr.execute("SELECT * FROM table")
self.env.cr.commit()
```

**Razón:**
- `self.env.cr` es thread-safe
- Respeta contexto multi-company
- Aplica security rules correctamente

**Archivos ya migrados:** 26 files en todos los módulos

---

### 6. View Methods: `fields_view_get()` → `get_view()`

**Status:** ⚠️ 1 occurrence (wizards)

```python
# ❌ DEPRECATED
@api.model
def fields_view_get(self, view_id=None, view_type='form', 
                    toolbar=False, submenu=False):
    result = super().fields_view_get(view_id, view_type, toolbar, submenu)
    # modificar result
    return result

# ✅ CORRECTO (Odoo 19)
@api.model
def get_view(self, view_id=None, view_type='form', **options):
    result = super().get_view(view_id, view_type, **options)
    # modificar result
    return result
```

**Archivo:** `l10n_cl_financial_reports/models/mixins/dynamic_states_mixin.py`

---

### 7. Decorators: `@api.depends` - Comportamiento Acumulativo

**Status:** 📋 184 occurrences (AUDIT ONLY - no breaking)

**Cambio de comportamiento en Odoo 19:**
- `@api.depends` es ahora **acumulativo** en herencia
- Si heredas un método con `@api.depends`, las dependencias se SUMAN

```python
# Clase base
class Base(models.Model):
    @api.depends('field_a')
    def _compute_total(self):
        pass

# Clase heredada
class Child(Base):
    @api.depends('field_b')  # CUIDADO: Ahora tiene field_a + field_b
    def _compute_total(self):
        super()._compute_total()
```

**Acción:** Revisar métodos heredados para evitar recálculos duplicados o faltantes

---

## 🟢 P2: BEST PRACTICES

### 8. Internationalization: Usar `_lt()` para Lazy Translations

**Status:** 📋 659 occurrences (AUDIT ONLY)

```python
# ⚠️ NO IDEAL (traduce inmediatamente)
raise UserError(_("Error message"))

# ✅ MEJOR (lazy translation)
from odoo.tools.translate import _lt

raise UserError(_lt("Error message"))
```

**Cuándo usar `_lt()`:**
- Mensajes en atributos de clase
- Strings en campos computados
- Mensajes de error generados dinámicamente

---

## 📊 ESTADO DEL PROYECTO

### Compliance Dashboard

| Prioridad | Total | Fixed | Pending | Rate |
|-----------|-------|-------|---------|------|
| **P0** | 138 | 111 | 27 manual | 80.4% |
| **P1** | 294 | 26 | 268 audit | 8.8% |
| **P2** | 659 | 0 | 659 audit | 0% |

### Archivos Críticos Pendientes

**P0 Manual (Deadline: 2025-03-01):**
- 6 XML files con `attrs=` (24 occurrences)
- 2 Python files con `_sql_constraints` (3 constraints)

**Estimado:** 4-6 horas de trabajo manual

---

## 🛠️ HERRAMIENTAS DISPONIBLES

### Scripts de Migración

```bash
# Auditar código actual
python3 scripts/odoo19_migration/1_audit_deprecations.py

# Ver hallazgos
less audit_report.md

# Migrar automáticamente (con dry-run)
python3 scripts/odoo19_migration/2_migrate_safe.py --dry-run

# Validar cambios
python3 scripts/odoo19_migration/3_validate_changes.py
```

### Documentación

- **Config completa:** `/scripts/odoo19_migration/config/deprecations.yaml`
- **README técnico:** `/scripts/odoo19_migration/README.md`
- **Informe final:** `/CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md`
- **Resumen trabajo:** `/RESUMEN_TRABAJO_MIGRACION_ODOO19.md`

---

## ✅ CHECKLIST PARA NUEVOS DESARROLLOS

Antes de commitear código nuevo en Odoo 19:

- [ ] ✅ NO usar `t-esc` en templates (usar `t-out`)
- [ ] ✅ NO usar `type='json'` en routes (usar `type='jsonrpc'` + `csrf=False`)
- [ ] ✅ NO usar `attrs=` en XML views (usar expresiones Python directas)
- [ ] ✅ NO usar `_sql_constraints` (usar `models.Constraint`)
- [ ] ✅ NO usar `self._cr` (usar `self.env.cr`)
- [ ] ✅ NO usar `fields_view_get()` (usar `get_view()`)
- [ ] ⚠️ Revisar `@api.depends` en herencias (comportamiento acumulativo)
- [ ] 🟢 Considerar `_lt()` para traducciones lazy

---

## 🚨 RECORDATORIO CRÍTICO

**ESTAS DEPRECACIONES SON BREAKING CHANGES**

Ignorarlas causará:
- ❌ Errores en producción
- ❌ Funcionalidad rota
- ❌ Incompatibilidad con Odoo 19
- ❌ Problemas de seguridad (CSRF, XSS)
- ❌ Issues de threading y multi-company

**Validar SIEMPRE contra esta guía antes de commitear.**

---

**Última migración:** 2025-11-11  
**Commits:** f5dc0c31 (P0), 76198a16 (P1)  
**Mantenedor:** Pedro Troncoso Willz (@pwills85)

