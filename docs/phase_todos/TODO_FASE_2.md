# 📋 TODO Fase 2 - Módulo Instalable

**Objetivo:** Hacer que el módulo se pueda instalar en Odoo sin errores  
**Duración Estimada:** 2-3 horas  
**Archivos a Crear:** 12 archivos (~850 líneas)  
**Complejidad:** MEDIA

---

## 🎯 META DE ESTA FASE

Al finalizar, podrás:
- ✅ Instalar módulo `l10n_cl_dte` en Odoo
- ✅ Ver menús y navegar UI
- ✅ Crear certificados, CAFs, etc (UI visible)
- ⚠️ Botones no envían a SII aún (esperado, Fase 3)

---

## 📋 LISTA DE TAREAS

### Tarea 1: Actualizar Security (15 min)

**Archivo:** `security/ir.model.access.csv`

**Acción:** Agregar permisos para nuevos modelos

**Código a agregar:**
```csv
access_dte_caf_user,dte.caf.user,model_dte_caf,account.group_account_user,1,0,0,0
access_dte_caf_manager,dte.caf.manager,model_dte_caf,account.group_account_manager,1,1,1,1
access_retencion_iue_user,retencion.iue.user,model_retencion_iue,account.group_account_user,1,0,0,0
access_retencion_iue_manager,retencion.iue.manager,model_retencion_iue,account.group_account_manager,1,1,1,1
```

**Referencia:** Ver archivo actual con 4 líneas, agregar 4 más

---

### Tarea 2: Vista dte_caf_views.xml (30 min)

**Archivo:** `views/dte_caf_views.xml`

**Contenido:**
- Form view: name, dte_type, folio_desde, folio_hasta, caf_file, state
- Tree view: lista de CAFs con decoración por estado
- Search view: filtros por tipo DTE, estado
- Action window
- Agregar a menus.xml

**Template base:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <record id="view_dte_caf_form" model="ir.ui.view">
        <field name="name">dte.caf.form</field>
        <field name="model">dte.caf</field>
        <field name="arch" type="xml">
            <form>
                <header>
                    <button name="action_validate" string="Validar CAF" .../>
                    <field name="state" widget="statusbar"/>
                </header>
                <sheet>
                    <!-- Similar a dte_certificate_views.xml -->
                </sheet>
            </form>
        </field>
    </record>
    
    <!-- Tree, Search, Action -->
</odoo>
```

**Referencia:** Copiar estructura de `dte_certificate_views.xml` y adaptar

**Líneas:** ~80

---

### Tarea 3: Vista purchase_order_dte_views.xml (25 min)

**Archivo:** `views/purchase_order_dte_views.xml`

**Contenido:**
- Extender purchase.order form (herencia con xpath)
- Agregar página "Liquidación Honorarios"
- Campos: es_liquidacion_honorarios, profesional_rut, retencion_iue, montos
- Botón "Generar DTE 34"

**Template base:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <record id="view_purchase_order_form_dte" model="ir.ui.view">
        <field name="name">purchase.order.form.dte</field>
        <field name="model">purchase.order</field>
        <field name="inherit_id" ref="purchase.purchase_order_form"/>
        <field name="arch" type="xml">
            
            <xpath expr="//notebook" position="inside">
                <page string="Liquidación Honorarios" 
                      attrs="{'invisible': [('es_liquidacion_honorarios', '=', False)]}">
                    <group>
                        <field name="es_liquidacion_honorarios"/>
                        <field name="profesional_rut"/>
                        <!-- ... más campos -->
                    </group>
                </page>
            </xpath>
            
        </field>
    </record>
</odoo>
```

**Referencia:** Ver `account_move_dte_views.xml` para patrón de herencia xpath

**Líneas:** ~90

---

### Tarea 4: Vista stock_picking_dte_views.xml (20 min)

**Archivo:** `views/stock_picking_dte_views.xml`

**Contenido:**
- Extender stock.picking form
- Checkbox "genera_dte_52"
- Campos DTE 52: estado, folio, tipo_traslado
- Botón "Generar Guía Electrónica"

**Referencia:** Usar patrón similar a purchase_order_dte_views.xml

**Líneas:** ~80

---

### Tarea 5: Vista retencion_iue_views.xml (20 min)

**Archivo:** `views/retencion_iue_views.xml`

**Contenido:**
- Form view: profesional, período, montos, purchase_orders
- Tree view: lista de retenciones
- Search view: filtros por período, profesional
- Action

**Referencia:** Similar a `dte_communication_views.xml`

**Líneas:** ~70

---

### Tarea 6: Vista account_journal_dte_views.xml (15 min)

**Archivo:** `views/account_journal_dte_views.xml`

**Contenido:**
- Extender account.journal form
- Pestaña "DTE"
- Campos: is_dte_journal, dte_type, folios, certificado

**Líneas:** ~60

---

### Tarea 7-10: Wizards Views (Stubs) (40 min total)

**Archivos (4):**
1. `wizard/upload_certificate_views.xml` (~40)
2. `wizard/send_dte_batch_views.xml` (~50)
3. `wizard/generate_consumo_folios_views.xml` (~40)
4. `wizard/generate_libro_views.xml` (~40)

**Template genérico:**
```xml
<record id="view_wizard_name_form" model="ir.ui.view">
    <field name="name">wizard.name.form</field>
    <field name="model">wizard.name</field>
    <field name="arch" type="xml">
        <form>
            <group>
                <field name="field1"/>
            </group>
            <footer>
                <button name="action_process" string="Procesar" type="object" class="btn-primary"/>
                <button string="Cancelar" special="cancel"/>
            </footer>
        </form>
    </field>
</record>
```

**Total:** ~170 líneas

---

### Tarea 11-12: Reports (Stubs) (30 min total)

**Archivos (2):**
1. `reports/dte_invoice_report.xml` (~80)
2. `reports/dte_receipt_report.xml` (~60)

**Template base:**
```xml
<odoo>
    <record id="report_dte_invoice" model="ir.actions.report">
        <field name="name">Factura DTE</field>
        <field name="model">account.move</field>
        <field name="report_type">qweb-pdf</field>
        <field name="report_name">l10n_cl_dte.report_invoice_dte</field>
    </record>
    
    <template id="report_invoice_dte">
        <t t-call="web.html_container">
            <t t-foreach="docs" t-as="o">
                <!-- Template básico -->
                <div class="page">
                    <h2>Factura Electrónica</h2>
                    <!-- Más contenido -->
                </div>
            </t>
        </t>
    </template>
</odoo>
```

**Total:** ~140 líneas

---

### Tarea 13: Wizards Python (Stubs) (30 min)

**Archivos (4):**
1. `wizard/upload_certificate.py`
2. `wizard/send_dte_batch.py`
3. `wizard/generate_consumo_folios.py`
4. `wizard/generate_libro.py`

**Template genérico:**
```python
# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError

class WizardName(models.TransientModel):
    _name = 'wizard.name'
    _description = 'Descripción'
    
    field1 = fields.Char('Campo 1')
    
    def action_process(self):
        # TODO: Implementar en fase posterior
        raise UserError(_('Pendiente de implementación'))
```

**Total:** ~260 líneas

---

### Tarea 14: Data File (10 min)

**Archivo:** `data/sii_activity_codes.xml`

**Contenido:**
```xml
<odoo>
    <data noupdate="1">
        <!-- Códigos de actividad económica SII -->
        <!-- Por ahora vacío o con 5-10 códigos básicos -->
    </data>
</odoo>
```

**Líneas:** ~50

---

### Tarea 15: Actualizar menus.xml (5 min)

**Archivo:** `views/menus.xml`

**Acción:** Agregar menús para:
- CAF
- Retenciones IUE
- Purchase Orders DTE
- Stock Pickings DTE

**Líneas:** +20

---

## ✅ CHECKLIST DE FINALIZACIÓN FASE 2

Al completar todas las tareas, verificar:

- [ ] Archivo `security/ir.model.access.csv` tiene 8 líneas
- [ ] Todos los archivos en `__manifest__.py` existen
- [ ] No hay errores de sintaxis en XML
- [ ] No hay errores de sintaxis en Python
- [ ] Módulo aparece en lista de Apps
- [ ] Módulo se puede instalar sin errores
- [ ] Menús DTE visibles
- [ ] Forms abren sin errores (aunque botones no funcionen)

---

## 🚀 COMANDOS DE VERIFICACIÓN

```bash
# 1. Verificar archivos existen
ls -la addons/localization/l10n_cl_dte/views/*.xml
ls -la addons/localization/l10n_cl_dte/wizard/*.xml

# 2. Verificar sintaxis Python
python3 -m py_compile addons/localization/l10n_cl_dte/**/*.py

# 3. Iniciar Odoo
docker-compose up -d odoo

# 4. Ver logs
docker-compose logs -f odoo

# 5. Acceder
http://localhost:8169

# 6. Instalar módulo
Apps → Update Apps List → Search "Chilean" → Install
```

---

## 📁 ARCHIVOS A CREAR (Lista Exacta)

```
1.  security/ir.model.access.csv (actualizar)
2.  views/dte_caf_views.xml
3.  views/account_journal_dte_views.xml
4.  views/purchase_order_dte_views.xml
5.  views/stock_picking_dte_views.xml
6.  views/retencion_iue_views.xml
7.  wizard/upload_certificate_views.xml
8.  wizard/send_dte_batch_views.xml
9.  wizard/generate_consumo_folios_views.xml
10. wizard/generate_libro_views.xml
11. reports/dte_invoice_report.xml
12. reports/dte_receipt_report.xml
13. wizard/upload_certificate.py
14. wizard/send_dte_batch.py
15. wizard/generate_consumo_folios.py
16. wizard/generate_libro.py
17. data/sii_activity_codes.xml
18. views/menus.xml (actualizar)
```

**Total:** 17 archivos (1 actualización + 16 nuevos)

---

## 🎯 RESULTADO ESPERADO FASE 2

**Al finalizar:**
- ✅ Módulo `l10n_cl_dte` instalable en Odoo
- ✅ Menús visibles y navegables
- ✅ Forms funcionan (abren sin errores)
- ✅ Wizards abren (aunque no procesen)
- ⚠️ Botones "Enviar a SII" aún no funcionales (Fase 3)

**Porcentaje completado:** 75% (de 54% → 75%)

---

**Próximo documento:** Iniciar Fase 2 o pausar según decisión

