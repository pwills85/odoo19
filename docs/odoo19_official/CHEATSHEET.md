# 🚀 Odoo 19 CE Cheatsheet - Desarrollo Rápido

**Versión:** 19.0  
**Para:** Módulo l10n_cl_dte  
**Fecha:** 2025-10-21

---

## 📋 TABLA DE CONTENIDOS

1. [Modelos](#modelos)
2. [Campos](#campos)
3. [Vistas XML](#vistas-xml)
4. [Seguridad](#seguridad)
5. [Métodos Comunes](#métodos-comunes)
6. [Decorators](#decorators)
7. [Queries ORM](#queries-orm)
8. [Reportes](#reportes)

---

## 🏗️ MODELOS

### Crear Modelo Nuevo

```python
from odoo import models, fields, api

class DTECertificate(models.Model):
    _name = 'dte.certificate'
    _description = 'Certificado Digital DTE'
    _order = 'name desc'
    
    name = fields.Char(string='Nombre', required=True)
    active = fields.Boolean(default=True)
    company_id = fields.Many2one('res.company', required=True, default=lambda self: self.env.company)
```

### Extender Modelo Existente (Herencia)

```python
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    
    # Campos nuevos
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
    ], default='draft')
    
    dte_folio = fields.Char('Folio DTE')
    dte_timestamp = fields.Datetime('Timestamp DTE')
    
    # Método nuevo
    def action_send_to_sii(self):
        for record in self:
            # Lógica de envío
            pass
```

### Herencia por Delegación (_inherits)

```python
class DTEDocument(models.Model):
    _name = 'dte.document'
    _inherits = {'account.move': 'move_id'}
    
    move_id = fields.Many2one('account.move', required=True, ondelete='cascade')
    xml_content = fields.Text('XML DTE')
```

---

## 📝 CAMPOS

### Campos Básicos

```python
# Texto
name = fields.Char('Nombre', size=128, required=True)
description = fields.Text('Descripción')

# Números
amount = fields.Float('Monto', digits=(16, 2))
quantity = fields.Integer('Cantidad')
percentage = fields.Float('Porcentaje', digits=(5, 2))

# Booleano
active = fields.Boolean('Activo', default=True)
is_dte = fields.Boolean('Es DTE')

# Fecha/Hora
date = fields.Date('Fecha', default=fields.Date.today)
datetime = fields.Datetime('Fecha y Hora', default=fields.Datetime.now)

# Selección
state = fields.Selection([
    ('draft', 'Borrador'),
    ('confirmed', 'Confirmado'),
    ('done', 'Finalizado'),
], default='draft', string='Estado')

# Binario
cert_file = fields.Binary('Certificado', encrypted=True)
pdf_file = fields.Binary('PDF Factura')

# Monetario
total = fields.Monetary('Total', currency_field='currency_id')
currency_id = fields.Many2one('res.currency', default=lambda self: self.env.company.currency_id)
```

### Campos Relacionales

```python
# Many2one (muchos a uno)
partner_id = fields.Many2one('res.partner', string='Cliente', required=True)
company_id = fields.Many2one('res.company', default=lambda self: self.env.company)

# One2many (uno a muchos)
line_ids = fields.One2many('dte.line', 'dte_id', string='Líneas')

# Many2many (muchos a muchos)
tag_ids = fields.Many2many('dte.tag', string='Etiquetas')

# Related (campo relacionado)
partner_vat = fields.Char(related='partner_id.vat', string='RUT Cliente', store=True)

# Computed (campo calculado)
total_amount = fields.Float(compute='_compute_total', store=True)
```

### Campos Computados

```python
total = fields.Float(compute='_compute_total', store=True)

@api.depends('line_ids.amount')
def _compute_total(self):
    for record in self:
        record.total = sum(record.line_ids.mapped('amount'))
```

### Campos con Dominio

```python
partner_id = fields.Many2one(
    'res.partner',
    string='Cliente',
    domain="[('customer_rank', '>', 0), ('country_id.code', '=', 'CL')]"
)
```

---

## 🎨 VISTAS XML

### Vista Form (Formulario)

```xml
<record id="view_dte_certificate_form" model="ir.ui.view">
    <field name="name">dte.certificate.form</field>
    <field name="model">dte.certificate</field>
    <field name="arch" type="xml">
        <form>
            <header>
                <button name="action_validate" string="Validar" type="object" class="btn-primary"/>
                <field name="state" widget="statusbar" statusbar_visible="draft,confirmed,done"/>
            </header>
            <sheet>
                <div class="oe_title">
                    <h1>
                        <field name="name" placeholder="Nombre del Certificado"/>
                    </h1>
                </div>
                <group>
                    <group>
                        <field name="company_id"/>
                        <field name="cert_rut"/>
                    </group>
                    <group>
                        <field name="validity_from"/>
                        <field name="validity_to"/>
                    </group>
                </group>
                <notebook>
                    <page string="Detalles">
                        <field name="description"/>
                    </page>
                    <page string="Archivo">
                        <field name="cert_file" filename="cert_filename"/>
                    </page>
                </notebook>
            </sheet>
            <div class="oe_chatter">
                <field name="message_follower_ids"/>
                <field name="message_ids"/>
            </div>
        </form>
    </field>
</record>
```

### Vista Tree (Lista)

```xml
<record id="view_dte_certificate_tree" model="ir.ui.view">
    <field name="name">dte.certificate.tree</field>
    <field name="model">dte.certificate</field>
    <field name="arch" type="xml">
        <tree>
            <field name="name"/>
            <field name="company_id"/>
            <field name="validity_from"/>
            <field name="validity_to"/>
            <field name="state" decoration-success="state == 'active'" decoration-danger="state == 'expired'"/>
        </tree>
    </field>
</record>
```

### Vista Search (Búsqueda y Filtros)

```xml
<record id="view_dte_certificate_search" model="ir.ui.view">
    <field name="name">dte.certificate.search</field>
    <field name="model">dte.certificate</field>
    <field name="arch" type="xml">
        <search>
            <field name="name"/>
            <field name="company_id"/>
            <filter string="Activos" name="active" domain="[('state', '=', 'active')]"/>
            <filter string="Expirados" name="expired" domain="[('state', '=', 'expired')]"/>
            <group expand="0" string="Agrupar por">
                <filter string="Empresa" name="group_company" context="{'group_by': 'company_id'}"/>
            </group>
        </search>
    </field>
</record>
```

### Action (Acción de Ventana)

```xml
<record id="action_dte_certificate" model="ir.actions.act_window">
    <field name="name">Certificados DTE</field>
    <field name="res_model">dte.certificate</field>
    <field name="view_mode">tree,form</field>
    <field name="context">{'search_default_active': 1}</field>
    <field name="help" type="html">
        <p class="o_view_nocontent_smiling_face">
            Crear primer certificado digital
        </p>
    </field>
</record>
```

### Menu Item

```xml
<menuitem
    id="menu_dte_certificate"
    name="Certificados"
    parent="account.menu_finance_configuration"
    action="action_dte_certificate"
    sequence="10"/>
```

---

## 🔐 SEGURIDAD

### ir.model.access.csv

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_dte_certificate_user,dte.certificate.user,model_dte_certificate,account.group_account_user,1,1,1,0
access_dte_certificate_manager,dte.certificate.manager,model_dte_certificate,account.group_account_manager,1,1,1,1
```

### Record Rules (rules.xml)

```xml
<record id="dte_certificate_company_rule" model="ir.rule">
    <field name="name">DTE Certificate: multi-company</field>
    <field name="model_id" ref="model_dte_certificate"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
</record>
```

---

## ⚙️ MÉTODOS COMUNES

### CRUD Básico

```python
# Create
partner = self.env['res.partner'].create({
    'name': 'Juan Pérez',
    'vat': '12345678-9',
    'country_id': self.env.ref('base.cl').id
})

# Read/Search
partners = self.env['res.partner'].search([('country_id.code', '=', 'CL')])
partner = self.env['res.partner'].browse(partner_id)

# Update
partner.write({'name': 'Juan Pérez S.A.'})

# Delete
partner.unlink()
```

### Métodos de Búsqueda

```python
# search() - búsqueda con dominio
records = self.env['account.move'].search([('state', '=', 'posted')])

# search_count() - contar registros
count = self.env['account.move'].search_count([('state', '=', 'posted')])

# filtered() - filtrar recordset
invoices = moves.filtered(lambda m: m.move_type == 'out_invoice')

# mapped() - mapear campo
amounts = moves.mapped('amount_total')

# sorted() - ordenar
sorted_moves = moves.sorted(key=lambda m: m.date, reverse=True)
```

### Validaciones

```python
from odoo.exceptions import ValidationError, UserError

@api.constrains('vat')
def _check_vat(self):
    for record in self:
        if not self._validate_rut(record.vat):
            raise ValidationError('RUT inválido')

def action_validate(self):
    if not self.line_ids:
        raise UserError('Debe agregar al menos una línea')
```

---

## 🎯 DECORATORS

### @api.depends (Computados)

```python
@api.depends('line_ids.amount')
def _compute_total(self):
    for record in self:
        record.total = sum(record.line_ids.mapped('amount'))
```

### @api.onchange (Cambios en UI)

```python
@api.onchange('partner_id')
def _onchange_partner_id(self):
    if self.partner_id:
        self.payment_term_id = self.partner_id.property_payment_term_id
```

### @api.constrains (Validaciones)

```python
@api.constrains('date_from', 'date_to')
def _check_dates(self):
    for record in self:
        if record.date_from > record.date_to:
            raise ValidationError('Fecha desde debe ser menor que fecha hasta')
```

### @api.model (Métodos de Clase)

```python
@api.model
def _get_default_currency(self):
    return self.env.company.currency_id
```

### @api.model_create_multi (Create Optimizado)

```python
@api.model_create_multi
def create(self, vals_list):
    for vals in vals_list:
        # Pre-procesamiento
        vals['name'] = vals.get('name', '').upper()
    return super().create(vals_list)
```

---

## 🔍 QUERIES ORM

### Dominios Básicos

```python
# Igual
[('state', '=', 'draft')]

# Diferente
[('state', '!=', 'cancel')]

# Mayor/Menor
[('amount', '>', 1000)]
[('date', '<=', '2025-12-31')]

# En lista
[('state', 'in', ['draft', 'confirmed'])]

# No en lista
[('state', 'not in', ['cancel', 'done'])]

# Like
[('name', 'like', '%factura%')]
[('name', 'ilike', '%factura%')]  # Case insensitive

# Relacional
[('partner_id.country_id.code', '=', 'CL')]
```

### Dominios Compuestos

```python
# AND (por defecto)
[('state', '=', 'posted'), ('amount', '>', 1000)]

# OR
['|', ('state', '=', 'draft'), ('state', '=', 'posted')]

# NOT
['!', ('state', '=', 'cancel')]

# Combinado
[
    '&',
        ('state', '=', 'posted'),
        '|',
            ('partner_id.country_id.code', '=', 'CL'),
            ('partner_id.vat', '!=', False)
]
```

---

## 📄 REPORTES

### Reporte QWeb (XML)

```xml
<record id="report_dte_invoice" model="ir.actions.report">
    <field name="name">Factura DTE</field>
    <field name="model">account.move</field>
    <field name="report_type">qweb-pdf</field>
    <field name="report_name">l10n_cl_dte.report_invoice_dte</field>
    <field name="print_report_name">'Factura - %s' % (object.name)</field>
</record>

<template id="report_invoice_dte">
    <t t-call="web.html_container">
        <t t-foreach="docs" t-as="o">
            <t t-call="web.external_layout">
                <div class="page">
                    <h2>Factura Electrónica</h2>
                    <div class="row">
                        <div class="col-6">
                            <strong>Cliente:</strong>
                            <div t-field="o.partner_id" 
                                 t-options='{"widget": "contact", "fields": ["address", "name"], "no_marker": True}'/>
                        </div>
                        <div class="col-6">
                            <strong>Folio:</strong> <span t-field="o.dte_folio"/>
                            <br/>
                            <strong>Fecha:</strong> <span t-field="o.invoice_date"/>
                        </div>
                    </div>
                    
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Descripción</th>
                                <th class="text-right">Cantidad</th>
                                <th class="text-right">Precio</th>
                                <th class="text-right">Subtotal</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr t-foreach="o.invoice_line_ids" t-as="line">
                                <td><span t-field="line.name"/></td>
                                <td class="text-right"><span t-field="line.quantity"/></td>
                                <td class="text-right"><span t-field="line.price_unit"/></td>
                                <td class="text-right"><span t-field="line.price_subtotal"/></td>
                            </tr>
                        </tbody>
                    </table>
                    
                    <div class="row">
                        <div class="col-6">
                            <!-- QR Code -->
                            <img t-if="o.dte_qr" t-att-src="'data:image/png;base64,%s' % o.dte_qr"/>
                        </div>
                        <div class="col-6">
                            <table class="table table-sm">
                                <tr>
                                    <td>Subtotal:</td>
                                    <td class="text-right"><span t-field="o.amount_untaxed"/></td>
                                </tr>
                                <tr>
                                    <td>IVA:</td>
                                    <td class="text-right"><span t-field="o.amount_tax"/></td>
                                </tr>
                                <tr class="border-black">
                                    <td><strong>Total:</strong></td>
                                    <td class="text-right"><strong><span t-field="o.amount_total"/></strong></td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
            </t>
        </t>
    </t>
</template>
```

---

## 🔧 MÉTODOS ÚTILES

### Contexto y Entorno

```python
# Obtener empresa actual
company = self.env.company

# Obtener usuario actual
user = self.env.user

# Ejecutar con contexto modificado
records.with_context(lang='es_CL').action_send()

# Ejecutar como otro usuario (sudo)
records.sudo().write({'state': 'confirmed'})

# Ejecutar sin activar onchanges
records.with_context(tracking_disable=True).write(vals)
```

### Manejo de Recordsets

```python
# Verificar si está vacío
if not records:
    pass

# Primer/último elemento
first = records[0]
last = records[-1]

# Unión
all_records = records1 | records2

# Intersección
common = records1 & records2

# Diferencia
diff = records1 - records2

# Verificar si está en recordset
if record in records:
    pass
```

### Transacciones

```python
# Commit manual (usar con cuidado)
self.env.cr.commit()

# Rollback manual
self.env.cr.rollback()
```

---

## 📚 REFERENCIAS RÁPIDAS

### Imports Comunes

```python
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError, AccessError
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)
```

### Logging

```python
_logger.debug('Debug message: %s', variable)
_logger.info('Info message')
_logger.warning('Warning message')
_logger.error('Error message')
```

### Traducción

```python
from odoo import _

# En Python
raise UserError(_('Error message'))

# En XML
<field name="name">Certificados DTE</field>
```

---

## ✅ CHECKLIST DE DESARROLLO

- [ ] Crear modelo en `models/*.py`
- [ ] Agregar campos necesarios
- [ ] Implementar métodos de negocio
- [ ] Crear vistas XML en `views/*.xml`
- [ ] Configurar seguridad en `security/ir.model.access.csv`
- [ ] Agregar record rules si necesario
- [ ] Crear menús en `views/menus.xml`
- [ ] Implementar tests en `tests/test_*.py`
- [ ] Agregar datos demo en `data/demo_*.xml`
- [ ] Actualizar `__manifest__.py` con todos los archivos
- [ ] Probar en Odoo
- [ ] Revisar logs de errores

---

**Última Actualización:** 2025-10-21  
**Versión Odoo:** 19.0  
**Para más detalles:** Ver [INDEX.md](INDEX.md)

