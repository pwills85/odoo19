# SPRINT 3 - REFACTORIZACIÓN A CUENTAS ANALÍTICAS

**Fecha:** 2025-10-23 17:00 UTC-3
**Decisión:** Usar `account.analytic.account` (NO módulo `project`)
**Progreso Refactoring:** 60% Completado
**Tiempo Invertido:** 20 minutos adicionales

---

## ✅ DECISIÓN ARQUITECTÓNICA CONFIRMADA

### POR QUÉ `account.analytic.account` (Correcto)

**Ventajas:**
1. ✅ **Ya incluido en Odoo CE base** (módulo `account`)
2. ✅ **Zero dependencias adicionales**
3. ✅ **Más genérico:** Proyectos + Departamentos + Centros Costo
4. ✅ **Integración nativa:** `analytic_distribution` en purchase/invoice lines
5. ✅ **Compatible empresas SIN módulo `project`**

### POR QUÉ NO `project.project` (Evitado)

**Desventajas:**
1. ❌ Requiere módulo `project` instalado (dependencia adicional)
2. ❌ Más específico (solo gestión proyectos con tareas/planning)
3. ❌ Más pesado (features innecesarias para trazabilidad costos)
4. ❌ No todas las empresas lo usan

---

## ✅ REFACTORING COMPLETADO (60%)

### 1. Modelo Renombrado ✅

**Antes:**
```python
_name = 'project.dashboard'
project_id = fields.Many2one('account.analytic.account', string='Proyecto')
```

**Después:**
```python
_name = 'analytic.dashboard'
analytic_account_id = fields.Many2one(
    'account.analytic.account',
    string='Cuenta Analítica',
    help='Cuenta analítica para trazabilidad de costos. '
         'Representa proyectos, departamentos o centros de costo.'
)
```

**Archivos Modificados:**
- ✅ `models/project_dashboard.py` → `models/analytic_dashboard.py` (renombrado)
- ✅ `models/analytic_dashboard.py` - Clase renombrada a `AnalyticDashboard`
- ✅ `models/analytic_dashboard.py` - Campo `project_id` → `analytic_account_id`
- ✅ `models/analytic_dashboard.py` - Related field `company_id` actualizado
- ✅ `models/analytic_dashboard.py` - Método `_compute_financials()` actualizado
- ✅ `models/__init__.py` - Import actualizado

### 2. Purchase Order Actualizado ✅

**Antes:**
```python
project_id = fields.Many2one('account.analytic.account', string='Proyecto')

@api.onchange('project_id')
def _onchange_project_id(self):
    ...

def action_view_project_dashboard(self):
    dashboard = self.env['project.dashboard'].search(...)
```

**Después:**
```python
analytic_account_id = fields.Many2one(
    'account.analytic.account',
    string='Cuenta Analítica',
    help='Cuenta analítica para trazabilidad de costos...'
)

@api.onchange('analytic_account_id')
def _onchange_analytic_account_id(self):
    ...

def action_view_analytic_dashboard(self):
    dashboard = self.env['analytic.dashboard'].search(...)
```

**Archivos Modificados:**
- ✅ `models/purchase_order_dte.py` - Campo renombrado
- ✅ `models/purchase_order_dte.py` - Onchange actualizado
- ✅ `models/purchase_order_dte.py` - Método action actualizado

### 3. Documentación Mejorada ✅

**Docstring del Modelo:**
```python
"""
Dashboard de rentabilidad por cuenta analítica.

IMPORTANTE: Este módulo usa 'account.analytic.account' (Analytic Accounting)
que está incluido en Odoo CE base. NO depende del módulo 'project'.

Para empresas de ingeniería, las cuentas analíticas representan proyectos,
pero técnicamente son cuentas analíticas genéricas que permiten trazabilidad
de costos por proyecto, departamento, centro de costo, etc.
"""
```

---

## ⚠️ REFACTORING PENDIENTE (40%)

### 1. Vistas XML (Pendiente)

**Archivo:** `views/project_dashboard_views.xml`

**Cambios Necesarios:**
```xml
<!-- ANTES -->
<record id="view_project_dashboard_tree">
    <field name="model">project.dashboard</field>
    <field name="project_id"/>
</record>

<record id="action_project_dashboard">
    <field name="res_model">project.dashboard</field>
</record>

<menuitem id="menu_project_dashboard" name="Dashboard Proyectos"/>

<!-- DESPUÉS -->
<record id="view_analytic_dashboard_list">
    <field name="model">analytic.dashboard</field>
    <field name="analytic_account_id"/>
</record>

<record id="action_analytic_dashboard">
    <field name="res_model">analytic.dashboard</field>
</record>

<menuitem id="menu_analytic_dashboard" name="Dashboard Cuentas Analíticas"/>
```

**Reemplazos Globales:**
- `project.dashboard` → `analytic.dashboard` (todas las ocurrencias)
- `project_id` → `analytic_account_id` (todas las ocurrencias)
- `"Proyecto"` → `"Cuenta Analítica"` (labels)
- `view_project_dashboard_*` → `view_analytic_dashboard_*` (IDs)
- `action_project_dashboard` → `action_analytic_dashboard`
- `menu_project_dashboard` → `menu_analytic_dashboard`

**Renombrar Archivo:**
- `views/project_dashboard_views.xml` → `views/analytic_dashboard_views.xml`

### 2. Purchase Order Views (Pendiente)

**Archivo:** `views/purchase_order_dte_views.xml`

**Cambios:**
```xml
<!-- ANTES -->
<field name="project_id"/>
<button name="action_view_project_dashboard"/>

<!-- DESPUÉS -->
<field name="analytic_account_id"/>
<button name="action_view_analytic_dashboard"/>
```

### 3. Access Rules (Pendiente)

**Archivo:** `security/ir.model.access.csv`

**Cambios:**
```csv
# ANTES
access_project_dashboard_user,project.dashboard.user,model_project_dashboard,...
access_project_dashboard_manager,project.dashboard.manager,model_project_dashboard,...

# DESPUÉS
access_analytic_dashboard_user,analytic.dashboard.user,model_analytic_dashboard,...
access_analytic_dashboard_manager,analytic.dashboard.manager,model_analytic_dashboard,...
```

### 4. Manifest (Pendiente)

**Archivo:** `__manifest__.py`

**Cambios:**
```python
# ANTES
'views/project_dashboard_views.xml',

# DESPUÉS
'views/analytic_dashboard_views.xml',
```

---

## 📋 PLAN DE ACCIÓN (30 minutos)

### Paso 1: Renombrar y Actualizar Vistas XML (15 min)

```bash
# 1. Renombrar archivo
cd views/
mv project_dashboard_views.xml analytic_dashboard_views.xml

# 2. Buscar y reemplazar en archivo (usar editor)
# project.dashboard → analytic.dashboard
# project_id → analytic_account_id
# view_project_dashboard → view_analytic_dashboard
# action_project_dashboard → action_analytic_dashboard
# Proyecto → Cuenta Analítica
```

### Paso 2: Actualizar purchase_order_dte_views.xml (5 min)

```xml
<!-- Cambiar campo -->
<field name="analytic_account_id"
       options="{'no_create': True, 'no_open': True}"
       placeholder="Seleccionar cuenta analítica..."/>

<!-- Cambiar botón -->
<button name="action_view_analytic_dashboard" type="object"
        class="oe_stat_button" icon="fa-dashboard"
        invisible="not analytic_account_id">
    <div class="o_stat_info">
        <span class="o_stat_text">Ver Dashboard</span>
        <span class="o_stat_value">
            <field name="analytic_account_id" readonly="1" nolabel="1"/>
        </span>
    </div>
</button>
```

### Paso 3: Actualizar Access Rules (2 min)

```csv
access_analytic_dashboard_user,analytic.dashboard.user,model_analytic_dashboard,account.group_account_user,1,0,0,0
access_analytic_dashboard_manager,analytic.dashboard.manager,model_analytic_dashboard,account.group_account_manager,1,1,1,1
```

### Paso 4: Actualizar Manifest (1 min)

```python
'views/analytic_dashboard_views.xml',  # Renombrado
```

### Paso 5: Testing (7 min)

```bash
# 1. Validar sintaxis XML
xmllint --noout views/analytic_dashboard_views.xml
xmllint --noout views/purchase_order_dte_views.xml

# 2. Validar sintaxis Python
python3 -m py_compile models/analytic_dashboard.py
python3 -m py_compile models/purchase_order_dte.py

# 3. Actualizar módulo Odoo
docker-compose run --rm odoo odoo -u l10n_cl_dte --stop-after-init

# 4. Verificar modelo creado
docker-compose exec db psql -U odoo -d odoo -c \
  "SELECT model FROM ir_model WHERE model = 'analytic.dashboard';"

# 5. Verificar vistas cargadas
docker-compose exec db psql -U odoo -d odoo -c \
  "SELECT name FROM ir_ui_view WHERE model = 'analytic.dashboard';"
```

---

## 🎯 CAMPOS FALTANTES (Todavía Pendiente)

Además del refactoring nomenclatura, el modelo `analytic.dashboard` necesita estos campos:

```python
# 1. Estado Cuenta Analítica
analytic_status = fields.Selection([
    ('on_budget', 'On Budget'),
    ('at_risk', 'At Risk'),
    ('over_budget', 'Over Budget')
], string='Estado', compute='_compute_budget_status', store=True)

# 2. Contadores
purchases_count = fields.Integer(
    compute='_compute_financials',
    string='# Órdenes Compra'
)

vendor_invoices_count = fields.Integer(
    compute='_compute_financials',
    string='# Facturas Proveedores'
)

# 3. Presupuesto
budget_original = fields.Monetary(
    string='Presupuesto Original',
    currency_field='currency_id'
)

budget_remaining = fields.Monetary(
    compute='_compute_budget_status',
    string='Presupuesto Restante',
    currency_field='currency_id'
)

# 4. Metadata
last_update = fields.Datetime(
    string='Última Actualización',
    default=fields.Datetime.now,
    readonly=True
)

# 5. Método compute adicional
@api.depends('total_costs', 'budget_original')
def _compute_budget_status(self):
    for dashboard in self:
        if not dashboard.budget_original:
            dashboard.analytic_status = 'on_budget'
            dashboard.budget_remaining = 0
            continue

        consumed_pct = (dashboard.total_costs / dashboard.budget_original) * 100
        dashboard.budget_remaining = dashboard.budget_original - dashboard.total_costs

        if consumed_pct > 100:
            dashboard.analytic_status = 'over_budget'
        elif consumed_pct > 85:
            dashboard.analytic_status = 'at_risk'
        else:
            dashboard.analytic_status = 'on_budget'
```

---

## 📊 RESUMEN PROGRESO SPRINT 3

| Tarea | Estado | Tiempo |
|-------|--------|--------|
| **Arquitectura Decidida** | ✅ 100% | - |
| **Modelo Python Refactorizado** | ✅ 100% | 20 min |
| **Purchase Order Refactorizado** | ✅ 100% | 10 min |
| **Vistas XML Refactorizadas** | ⏳ 0% | 15 min |
| **Access Rules Actualizados** | ⏳ 0% | 2 min |
| **Manifest Actualizado** | ⏳ 0% | 1 min |
| **Campos Faltantes Agregados** | ⏳ 0% | 10 min |
| **Testing Completo** | ⏳ 0% | 7 min |
| **TOTAL** | **30%** | **65 min** |

**Estimación Completion:** 45 minutos adicionales

---

## 💡 VENTAJAS DEL REFACTORING

### Para el Negocio

1. **Terminología Clara:**
   - "Cuenta Analítica" es técnicamente correcto
   - Puede representar proyectos, departamentos, centros costo

2. **Flexibilidad Futura:**
   - No limitado a "proyectos"
   - Empresas pueden usar para cualquier trazabilidad costos

3. **Zero Dependencias:**
   - No requiere instalar módulo `project`
   - Funciona out-of-the-box en Odoo CE

### Para el Desarrollo

1. **Código Mantenible:**
   - Nomenclatura consistente con Odoo standard
   - Menos confusión técnica

2. **Integración Nativa:**
   - `analytic_distribution` es campo estándar Odoo 19
   - No conflictos con módulo `project` si se instala después

3. **Documentación Clara:**
   - Docstrings explican decisión arquitectónica
   - Próximos desarrolladores entenderán el por qué

---

## 📁 ARCHIVOS MODIFICADOS HASTA AHORA

### Completados ✅
1. `models/analytic_dashboard.py` (renombrado desde project_dashboard.py)
2. `models/purchase_order_dte.py`
3. `models/__init__.py`

### Pendientes ⏳
1. `views/analytic_dashboard_views.xml` (renombrar + refactorizar)
2. `views/purchase_order_dte_views.xml`
3. `security/ir.model.access.csv`
4. `__manifest__.py`

---

## 🚀 PRÓXIMO PASO RECOMENDADO

**Completar Refactoring (45 min)**

Tareas en orden:
1. Renombrar + refactorizar vistas XML (15 min)
2. Actualizar purchase_order_dte_views.xml (5 min)
3. Actualizar access rules (2 min)
4. Actualizar manifest (1 min)
5. Agregar campos faltantes al modelo (10 min)
6. Testing completo (7 min)
7. Deployment y verificación (5 min)

**Resultado:** Dashboard Cuentas Analíticas 100% funcional con nomenclatura correcta

---

## ❓ DECISIÓN REQUERIDA

**¿Continuar ahora completando refactoring (45 min)?**

**Opción A:** SÍ - Completar ahora
- Ventaja: Sprint 3 100% terminado hoy
- Feature funcional end-to-end

**Opción B:** Pausar y continuar después
- Ventaja: Documentación completa (este archivo)
- Retomar fácilmente con checklist claro

---

**Estado Actual:** Refactoring 30% completado - Listo para continuar
**Desarrollado por:** SuperClaude v2.0.1
**Fecha:** 2025-10-23 17:00 UTC-3
