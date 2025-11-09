# MEJORES PRÁCTICAS ODOO 19 CE
## Ejemplos de Código Correcto vs Incorrecto

**Basado en:** Auditoría l10n_cl_dte
**Fecha:** 2025-11-06

---

## 1. HERENCIAS DE MODELOS

### ❌ INCORRECTO (encontrado en account_move_dte.py)

```python
class AccountMoveDTE(models.Model):
    _name = 'account.move'       # ❌ NO hacer esto
    _inherit = 'account.move'    # ❌ Duplicación
```

**Problema:**
- Duplica la definición del modelo
- Puede causar conflictos de registro
- Odoo puede intentar crear un nuevo modelo en lugar de extender

**Impacto:**
- Error: `Model 'account.move' already exists`
- Herencias múltiples de otros módulos se rompen
- Upgrade de módulo puede fallar

---

### ✅ CORRECTO (patrón estándar Odoo)

```python
class AccountMoveDTE(models.Model):
    """Extension of account.move for Chilean DTE"""
    _inherit = 'account.move'    # ✓ SOLO _inherit para extensiones
```

**Cuándo usar _name:**
```python
# Caso 1: Modelo completamente nuevo
class MyCustomModel(models.Model):
    _name = 'my.custom.model'    # ✓ Modelo nuevo
    _description = 'My Custom Model'

# Caso 2: Modelo nuevo que hereda de otro (pero con _name diferente)
class MyInheritedModel(models.Model):
    _name = 'my.inherited.model'      # ✓ Nombre diferente
    _inherit = 'res.partner'          # ✓ Hereda funcionalidad
    _description = 'Extended Partner'
```

**Regla de oro:**
- Si `_name == _inherit` → eliminar `_name`
- Si `_name != _inherit` → mantener ambos (delegated inheritance)

---

## 2. API DECORATORS

### ❌ INCORRECTO (deprecated en Odoo 13+)

```python
# Decoradores deprecated
@api.one                          # ❌ Deprecated en Odoo 13
def my_method(self):
    pass

@api.multi                        # ❌ Deprecated en Odoo 13
def another_method(self):
    pass

@api.cr                           # ❌ Deprecated
def yet_another(self):
    pass
```

---

### ✅ CORRECTO (Odoo 19 modernos)

```python
from odoo import models, fields, api

class MyModel(models.Model):
    _inherit = 'account.move'

    # Método de instancia (aplica a recordset)
    def my_method(self):
        """Por defecto opera en recordset (self puede ser múltiples records)"""
        for record in self:
            # Procesar cada record
            record.name = "Updated"

    # Método de clase (no requiere instancia)
    @api.model
    def create_invoices_batch(self, vals_list):
        """Método que NO opera sobre self (self es el modelo)"""
        return self.create(vals_list)

    # Campo computado con dependencias
    total_amount = fields.Float(
        compute='_compute_total_amount',
        store=True,  # ✓ Almacenar para búsquedas
    )

    @api.depends('line_ids.price_subtotal')  # ✓ Dependencias explícitas
    def _compute_total_amount(self):
        """Recalcula cuando line_ids.price_subtotal cambia"""
        for record in self:
            record.total_amount = sum(record.line_ids.mapped('price_subtotal'))

    # Validación con constraint
    @api.constrains('amount', 'state')
    def _check_amount(self):
        """Valida cuando amount o state cambian"""
        for record in self:
            if record.state == 'posted' and record.amount <= 0:
                raise ValidationError("Amount must be positive for posted invoices")

    # Onchange en UI
    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        """Se ejecuta en UI cuando partner_id cambia (antes de guardar)"""
        if self.partner_id:
            self.payment_term_id = self.partner_id.property_payment_term_id
```

---

## 3. CAMPOS COMPUTADOS

### ❌ INCORRECTO (sin store explícito)

```python
# Issue MEDIUM encontrado en múltiples archivos
dtes_count = fields.Integer(
    compute='_compute_dtes_count',
    # ❌ Falta store=True/False explícito
)

@api.depends()  # ❌ @api.depends vacío sin justificación
def _compute_dtes_count(self):
    for record in self:
        record.dtes_count = len(record.dte_ids)
```

**Problemas:**
- No se puede buscar por este campo (no searchable)
- No se puede ordenar en vistas (no sortable)
- Se recalcula cada vez (pérdida de performance)

---

### ✅ CORRECTO (Opción 1: Almacenar)

```python
# Para campos que deben ser searchable/sortable
dtes_count = fields.Integer(
    compute='_compute_dtes_count',
    store=True,  # ✓ Almacenar en DB
    help="Number of DTEs for this invoice"
)

@api.depends('dte_ids')  # ✓ Dependencia explícita
def _compute_dtes_count(self):
    """Recalcula automáticamente cuando dte_ids cambia"""
    for record in self:
        record.dtes_count = len(record.dte_ids)
```

**Ventajas:**
- Searchable: `self.search([('dtes_count', '>', 5)])`
- Sortable: `<field name="dtes_count"/>` en tree view
- Performance: No recalcula en cada acceso

---

### ✅ CORRECTO (Opción 2: No almacenar)

```python
# Para campos que cambian frecuentemente o son caros de calcular
dte_xml_filename = fields.Char(
    compute='_compute_dte_xml_filename',
    store=False,  # ✓ Explícito: NO almacenar
    help="Dynamic filename based on current timestamp"
)

def _compute_dte_xml_filename(self):
    """Genera nombre dinámico (no depende de campos rastreables)"""
    for record in self:
        timestamp = fields.Datetime.now().strftime('%Y%m%d_%H%M%S')
        record.dte_xml_filename = f"DTE_{record.dte_folio}_{timestamp}.xml"
```

**Cuándo NO almacenar:**
- Valores que incluyen timestamp actual
- Cálculos muy complejos/costosos
- Datos que cambian con cada acceso
- Dependencias no rastreables (búsquedas en otros modelos)

---

### ✅ CORRECTO (Opción 3: Inverse relation counter)

```python
# Para contadores de relaciones inversas
partner_count = fields.Integer(
    compute='_compute_partner_count',
    store=False,  # ✓ No almacenar (búsqueda dinámica)
)

@api.depends()  # ✓ Vacío justificado: inverse relation
def _compute_partner_count(self):
    """
    Cuenta partners que apuntan a este registro.

    NOTE: @api.depends() vacío porque es inverse relation.
    El campo se calcula consultando otro modelo (res.partner).
    No depende de campos de este modelo.
    """
    for record in self:
        record.partner_count = self.env['res.partner'].search_count([
            ('l10n_cl_comuna_id', '=', record.id)
        ])
```

**Justificación:**
- Es una búsqueda en otro modelo (inverse relation)
- No depende de campos del mismo modelo
- Documentar claramente con comentario

---

## 4. ACLS (ACCESS CONTROL LISTS)

### ❌ INCORRECTO (modelo sin ACL)

```python
# Modelo definido en Python
class MyCustomModel(models.Model):
    _name = 'my.custom.model'
    _description = 'My Custom Model'

    name = fields.Char()

# ❌ NO hay entrada en security/ir.model.access.csv
```

**Problema:**
- Usuario puede ver error: "Access Denied"
- O peor: Acceso no controlado (si no hay security)

---

### ✅ CORRECTO (ACL completo)

```python
# 1. Modelo en Python
class MyCustomModel(models.Model):
    _name = 'my.custom.model'
    _description = 'My Custom Model'
```

```csv
# 2. Entrada en security/ir.model.access.csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_my_custom_model_user,my.custom.model.user,model_my_custom_model,base.group_user,1,0,0,0
access_my_custom_model_manager,my.custom.model.manager,model_my_custom_model,account.group_account_manager,1,1,1,1
```

**Explicación:**
- Línea 1: Usuarios normales (base.group_user) pueden LEER (1,0,0,0)
- Línea 2: Managers contables pueden TODO (1,1,1,1)

**Permisos:**
- `perm_read`: Lectura
- `perm_write`: Escritura
- `perm_create`: Creación
- `perm_unlink`: Eliminación

---

### ✅ PATRÓN COMÚN: 3 niveles de acceso

```csv
# Nivel 1: Usuario normal (solo lectura)
access_model_user,model.user,model_model,base.group_user,1,0,0,0

# Nivel 2: Usuario contable (lectura + escritura + creación)
access_model_account_user,model.account.user,model_model,account.group_account_user,1,1,1,0

# Nivel 3: Manager (todo)
access_model_manager,model.manager,model_model,account.group_account_manager,1,1,1,1
```

---

## 5. VISTAS XML (Odoo 19)

### ❌ INCORRECTO (deprecated tags)

```xml
<!-- Odoo 11-18 style -->
<record id="view_invoice_tree" model="ir.ui.view">
    <field name="name">account.move.tree</field>
    <field name="model">account.move</field>
    <field name="arch" type="xml">
        <tree string="Invoices">  <!-- ❌ <tree> deprecated en Odoo 19 -->
            <field name="name"/>
            <field name="partner_id"/>
        </tree>
    </field>
</record>
```

---

### ✅ CORRECTO (Odoo 19 style)

```xml
<!-- Odoo 19 recommended -->
<record id="view_invoice_list" model="ir.ui.view">
    <field name="name">account.move.list</field>
    <field name="model">account.move</field>
    <field name="arch" type="xml">
        <list string="Invoices">  <!-- ✓ <list> en Odoo 19 -->
            <field name="name"/>
            <field name="partner_id"/>

            <!-- Decorations con expresiones Python -->
            <field name="state"
                   decoration-success="state == 'posted'"
                   decoration-danger="state == 'cancel'"/>
        </list>
    </field>
</record>
```

---

### ✅ CORRECTO (Atributos dinámicos Odoo 19)

```xml
<!-- Antiguo (Odoo 11-18) -->
<field name="name" attrs="{'invisible': [('state', '=', 'draft')]}"/>

<!-- Odoo 19 (recomendado) -->
<field name="name" invisible="state == 'draft'"/>

<!-- Múltiples condiciones -->
<field name="amount"
       invisible="state == 'draft' or partner_id == False"
       readonly="state == 'posted'"
       required="state == 'posted'"/>
```

**Ventajas Odoo 19:**
- Sintaxis más simple (Python expressions)
- Más legible
- Mejor performance

---

## 6. HERENCIA DE VISTAS

### ✅ CORRECTO (XPath patterns)

```xml
<!-- Agregar campo después de otro -->
<record id="view_invoice_form_inherit" model="ir.ui.view">
    <field name="name">account.move.form.inherit</field>
    <field name="model">account.move</field>
    <field name="inherit_id" ref="account.view_move_form"/>
    <field name="arch" type="xml">

        <!-- Después de un campo -->
        <xpath expr="//field[@name='partner_id']" position="after">
            <field name="dte_status"/>
        </xpath>

        <!-- Dentro de un group -->
        <xpath expr="//group[@name='header_left']" position="inside">
            <field name="dte_folio"/>
        </xpath>

        <!-- Reemplazar un campo -->
        <xpath expr="//field[@name='invoice_date']" position="replace">
            <field name="invoice_date" required="1"/>
        </xpath>

        <!-- Agregar atributos a campo existente -->
        <xpath expr="//field[@name='amount_total']" position="attributes">
            <attribute name="readonly">1</attribute>
        </xpath>

    </field>
</record>
```

**Positions disponibles:**
- `after`: Después del elemento
- `before`: Antes del elemento
- `inside`: Dentro del elemento (al final)
- `replace`: Reemplazar el elemento
- `attributes`: Modificar atributos del elemento

---

## 7. ÍNDICES DE BASE DE DATOS

### ❌ INCORRECTO (sin índices en campos consultados)

```python
class AccountMove(models.Model):
    _inherit = 'account.move'

    dte_folio = fields.Char()  # ❌ Sin index, pero se consulta frecuentemente
```

**Problema:**
```python
# Esta búsqueda será LENTA sin índice
invoices = self.env['account.move'].search([
    ('dte_folio', '=', '12345')
])
```

---

### ✅ CORRECTO (índices en campos consultados)

```python
class AccountMove(models.Model):
    _inherit = 'account.move'

    # Campos que se usan en búsquedas → index=True
    dte_folio = fields.Char(
        index=True,  # ✓ Índice para búsquedas rápidas
        help='DTE Folio from SII'
    )

    dte_status = fields.Selection([
        ('draft', 'Draft'),
        ('sent', 'Sent'),
        ('accepted', 'Accepted'),
    ], index=True)  # ✓ Índice para filtros frecuentes

    dte_track_id = fields.Char(
        index=True,  # ✓ Índice para consultas SII
    )
```

**Cuándo usar index=True:**
- Campos usados en `search([('field', '=', value)])`
- Campos usados en filtros de vistas
- Campos de referencia externa (IDs de otros sistemas)
- Campos de estado (si se filtran frecuentemente)

**Cuándo NO usar:**
- Campos de texto largo (Text, Html)
- Campos poco consultados
- Campos que cambian muy frecuentemente

---

## 8. VALIDACIONES

### ✅ CORRECTO (SQL Constraints)

```python
class AccountMove(models.Model):
    _inherit = 'account.move'

    _sql_constraints = [
        # Folio único por empresa
        ('dte_folio_company_uniq',
         'UNIQUE(dte_folio, company_id)',
         'DTE Folio must be unique per company!'),

        # Track ID único
        ('dte_track_id_uniq',
         'UNIQUE(dte_track_id)',
         'DTE Track ID must be unique!'),
    ]
```

**Ventajas:**
- Garantía a nivel de base de datos
- Muy rápido (DB enforcement)
- No se puede violar ni con SQL directo

---

### ✅ CORRECTO (Python Constraints)

```python
from odoo import api, models, fields, _
from odoo.exceptions import ValidationError

class AccountMove(models.Model):
    _inherit = 'account.move'

    @api.constrains('dte_folio', 'company_id')
    def _check_dte_folio_format(self):
        """Validar formato del folio DTE"""
        for record in self:
            if record.dte_folio:
                # Solo dígitos
                if not record.dte_folio.isdigit():
                    raise ValidationError(
                        _('DTE Folio must contain only digits.')
                    )

                # Rango válido
                folio_int = int(record.dte_folio)
                if not (1 <= folio_int <= 99999999):
                    raise ValidationError(
                        _('DTE Folio must be between 1 and 99999999.')
                    )
```

**Cuándo usar Python constraints:**
- Validaciones complejas (múltiples campos)
- Validaciones que requieren lógica
- Validaciones que consultan otros modelos
- Validaciones con mensajes dinámicos

---

## 9. SEGURIDAD MULTI-COMPANY

### ✅ CORRECTO (Record Rules)

```xml
<!-- security/multi_company_rules.xml -->
<odoo>
    <data noupdate="1">

        <!-- Usuarios solo ven registros de su empresa -->
        <record id="dte_caf_company_rule" model="ir.rule">
            <field name="name">DTE CAF: multi-company</field>
            <field name="model_id" ref="model_dte_caf"/>
            <field name="domain_force">
                ['|', ('company_id', '=', False),
                      ('company_id', 'in', company_ids)]
            </field>
            <field name="global" eval="True"/>
        </record>

    </data>
</odoo>
```

**Domain explained:**
- `('company_id', '=', False)`: Registros sin empresa (compartidos)
- `('company_id', 'in', company_ids)`: Registros de empresas del usuario
- `|`: OR lógico

---

## 10. PERFORMANCE TIPS

### ❌ INCORRECTO (N+1 queries)

```python
# ❌ MAL: Loop que ejecuta query en cada iteración
def process_invoices(self):
    for invoice in self:
        partner = invoice.partner_id  # Query por cada invoice
        print(partner.name)
```

---

### ✅ CORRECTO (Prefetch + Batch)

```python
# ✓ BIEN: Prefetch automático de Odoo
def process_invoices(self):
    # Force prefetch
    self.mapped('partner_id')

    for invoice in self:
        partner = invoice.partner_id  # Sin query (cached)
        print(partner.name)

# ✓ MEJOR: Batch operation
def process_invoices(self):
    # Una sola operación para todos
    self.write({'state': 'processed'})

    # En lugar de:
    # for invoice in self:
    #     invoice.state = 'processed'  # ❌ Query por cada uno
```

---

## RESUMEN DE REGLAS

### Herencias
- `_inherit` solo → extensión
- `_name + _inherit` diferentes → delegated inheritance
- `_name = _inherit` → ERROR, eliminar _name

### API Decorators
- `@api.model` → método de clase
- `@api.depends('field1', 'field2')` → computed fields
- `@api.constrains('field1')` → validaciones
- `@api.onchange('field1')` → cambios en UI

### Campos Computados
- `store=True` → si debe ser searchable/sortable
- `store=False` → si cambia dinámicamente
- `@api.depends()` vacío → justificar con comentario (inverse relation)

### ACLs
- TODO modelo custom debe tener ACL
- Mínimo 2 niveles: user (read) + manager (all)
- Verificar con `python3 scripts/validate_odoo19_standards.py`

### Vistas XML
- Usar `<list>` en lugar de `<tree>`
- Usar atributos dinámicos: `invisible="expr"` en lugar de `attrs`
- XPath positions: `after`, `before`, `inside`, `replace`, `attributes`

### Performance
- `index=True` en campos consultados
- Evitar N+1 queries (usar prefetch)
- Batch operations siempre que sea posible

---

**Referencias:**
- Documentación Odoo 19: https://www.odoo.com/documentation/19.0/
- ORM API: https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html

**Última actualización:** 2025-11-06

