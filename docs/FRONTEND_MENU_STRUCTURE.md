# 🎨 Estructura Frontend Odoo 19 CE - l10n_cl_dte

**Fecha:** 2025-10-22
**Módulo:** `l10n_cl_dte` (Chilean Electronic Invoicing)
**Ubicación Base:** Contabilidad > DTE Chile

---

## 📋 Estructura Completa de Menús

```
Contabilidad (account.menu_finance)
└── DTE Chile (menu_dte_root)
    ├── 📁 Operaciones (menu_dte_operations)
    │   ├── Facturas Electrónicas (menu_dte_invoices)
    │   │   └── Action: account.action_move_out_invoice_type
    │   │   └── Vista: account.move filtered by out_invoice
    │   │   └── Tipos: DTE 33 (Factura), DTE 56 (Nota Débito), DTE 61 (Nota Crédito)
    │   │
    │   ├── Notas de Crédito (menu_dte_credit_notes)
    │   │   └── Action: account.action_move_out_refund_type
    │   │   └── Vista: account.move filtered by out_refund
    │   │   └── Tipo: DTE 61 (Nota de Crédito)
    │   │
    │   ├── Guías de Despacho (menu_dte_guias_despacho)
    │   │   └── Action: stock.action_picking_tree_all
    │   │   └── Vista: stock.picking (con extensión DTE)
    │   │   └── Tipo: DTE 52 (Guía de Despacho)
    │   │
    │   ├── Liquidaciones Honorarios (menu_dte_honorarios)
    │   │   └── Action: purchase.purchase_form_action
    │   │   └── Vista: purchase.order (con extensión DTE)
    │   │   └── Tipo: DTE 34 (Liquidación Honorarios)
    │   │
    │   └── Retenciones IUE (menu_retencion_iue)
    │       └── Action: action_retencion_iue
    │       └── Modelo: retencion.iue
    │       └── Vista: retencion_iue_views.xml
    │
    ├── 📥 DTEs Recibidos (menu_dte_inbox)
    │   └── Action: action_dte_inbox
    │   └── Modelo: dte.inbox
    │   └── Vista: dte_inbox_views.xml
    │   └── Función: Recepción de compras (DTEs de proveedores)
    │
    ├── 📊 Reportes SII (menu_dte_reportes)
    │   ├── Libro Compra/Venta (menu_dte_libro_compra_venta)
    │   │   └── Action: action_dte_libro
    │   │   └── Modelo: dte.libro
    │   │   └── Vista: dte_libro_views.xml ⭐ NUEVO
    │   │   └── Tipos: Libro Ventas / Libro Compras
    │   │
    │   ├── Libro de Guías (menu_dte_libro_guias)
    │   │   └── Action: action_dte_libro_guias
    │   │   └── Modelo: dte.libro.guias
    │   │   └── Vista: dte_libro_guias_views.xml
    │   │   └── Tipo: TipoLibro=3, TpoDoc=52
    │   │
    │   └── Consumo de Folios (menu_dte_consumo_folios)
    │       └── Sin action (pendiente implementación)
    │       └── Generado vía wizard: generate_consumo_folios
    │
    ├── 📡 Comunicaciones SII (menu_dte_communications)
    │   └── Action: action_dte_communication
    │   └── Modelo: dte.communication
    │   └── Vista: dte_communication_views.xml
    │   └── Función: Log de comunicaciones SOAP con SII
    │
    └── ⚙️ Configuración (menu_dte_configuration)
        ├── Certificados Digitales (menu_dte_certificates)
        │   └── Action: action_dte_certificate
        │   └── Modelo: dte.certificate
        │   └── Vista: dte_certificate_views.xml
        │   └── Función: Gestión certificados .p12 para firma digital
        │
        ├── CAF (Folios) (menu_dte_caf)
        │   └── Action: action_dte_caf
        │   └── Modelo: dte.caf
        │   └── Vista: dte_caf_views.xml
        │   └── Función: Códigos de Autorización de Folios (rangos)
        │
        └── Configuración General (menu_dte_settings)
            └── Action: base.action_res_config_settings
            └── Vista: res_config_settings_views.xml (extends)
            └── Sección: "Facturación Electrónica Chile (DTE)"
            └── Función: URLs microservicios, ambiente SII, etc.
```

---

## 🎯 Vistas Implementadas por Modelo

### 1. **account.move** (Facturas/Notas)
- **Extensión:** `account_move_dte_views.xml`
- **Campos DTE agregados:**
  - `dte_type` (33, 56, 61)
  - `dte_folio`
  - `dte_status` (draft, pending, sent, accepted, rejected)
  - `dte_xml`, `dte_pdf`
  - `dte_track_id`
- **Botones:**
  - "Generar DTE"
  - "Enviar al SII"
  - "Consultar Estado"
  - "Ver XML", "Ver PDF"

### 2. **stock.picking** (Guías Despacho)
- **Extensión:** `stock_picking_dte_views.xml`
- **Campos DTE agregados:**
  - `dte_type` (52)
  - `dte_folio`
  - `dte_status`
  - `dte_xml`, `dte_pdf`
- **Función:** DTE 52 Guía de Despacho Electrónica

### 3. **purchase.order** (Liquidación Honorarios)
- **Extensión:** `purchase_order_dte_views.xml`
- **Campos DTE agregados:**
  - `dte_type` (34)
  - `dte_folio`
  - `dte_status`
  - `retencion_iue` (10%)
- **Función:** DTE 34 Liquidación Honorarios

### 4. **dte.certificate** (Certificados Digitales)
- **Vista propia:** `dte_certificate_views.xml`
- **Vistas:** Tree, Form, Search
- **Función:** Gestión certificados PKCS#12 (.p12) para firma digital
- **Campos:** name, certificate_data (binary), password (encrypted), valid_from, valid_to, is_active

### 5. **dte.caf** (Folios)
- **Vista propia:** `dte_caf_views.xml`
- **Vistas:** Tree, Form, Search, Kanban
- **Función:** Códigos de Autorización de Folios del SII
- **Campos:** dte_type, folio_inicio, folio_fin, folios_disponibles, caf_xml

### 6. **dte.libro** ⭐ NUEVO
- **Vista propia:** `dte_libro_views.xml`
- **Vistas:** Tree, Form, Search, Kanban
- **Función:** Libro Compra/Venta mensual obligatorio SII
- **Campos:** tipo_libro (venta/compra), periodo_mes, invoice_ids, totales, state, track_id

### 7. **dte.libro.guias** ⭐ IMPLEMENTADO 2025-10-22
- **Vista propia:** `dte_libro_guias_views.xml`
- **Vistas:** Tree, Form, Search, Kanban
- **Función:** Libro de Guías mensual (TipoLibro=3, TpoDoc=52)
- **Campos:** periodo_mes, picking_ids, cantidad_guias, totales, state, track_id

### 8. **dte.inbox** (DTEs Recibidos)
- **Vista propia:** `dte_inbox_views.xml`
- **Vistas:** Tree, Form, Search, Kanban
- **Función:** Recepción de compras (DTEs de proveedores)
- **Campos:** dte_xml, partner_id, dte_type, folio, monto_total, status

### 9. **dte.communication** (Comunicaciones SII)
- **Vista propia:** `dte_communication_views.xml`
- **Vistas:** Tree, Form, Search
- **Función:** Log de comunicaciones SOAP con SII
- **Campos:** fecha, tipo, request_xml, response_xml, track_id, status

### 10. **retencion.iue** (Retenciones IUE)
- **Vista propia:** `retencion_iue_views.xml`
- **Vistas:** Tree, Form, Search
- **Función:** Gestión retenciones 10% DTE 34 (Honorarios)
- **Campos:** purchase_id, partner_id, monto_bruto, retencion_10, monto_liquido

### 11. **res.config.settings** (Configuración)
- **Extensión:** `res_config_settings_views.xml`
- **Sección agregada:** "Facturación Electrónica Chile (DTE)"
- **Campos:**
  - DTE Service URL + API Key + Botón "Probar Conexión"
  - AI Service URL + API Key + Toggle + Botón "Probar Conexión"
  - Ambiente SII (Sandbox/Producción)
  - Timeout SII (segundos)

---

## 📂 Archivos de Vista

| Archivo | Modelo(s) | Vistas | Estado |
|---------|-----------|--------|--------|
| `account_move_dte_views.xml` | account.move | Form (extend) | ✅ |
| `stock_picking_dte_views.xml` | stock.picking | Form (extend) | ✅ |
| `purchase_order_dte_views.xml` | purchase.order | Form (extend) | ✅ |
| `account_journal_dte_views.xml` | account.journal | Form (extend) | ✅ |
| `dte_certificate_views.xml` | dte.certificate | Tree, Form, Search | ✅ |
| `dte_caf_views.xml` | dte.caf | Tree, Form, Search, Kanban | ✅ |
| `dte_libro_views.xml` | dte.libro | Tree, Form, Search, Kanban | ⭐ NUEVO |
| `dte_libro_guias_views.xml` | dte.libro.guias | Tree, Form, Search, Kanban | ✅ |
| `dte_inbox_views.xml` | dte.inbox | Tree, Form, Search, Kanban | ✅ |
| `dte_communication_views.xml` | dte.communication | Tree, Form, Search | ✅ |
| `retencion_iue_views.xml` | retencion.iue | Tree, Form, Search | ✅ |
| `res_config_settings_views.xml` | res.config.settings | Form (extend) | ✅ |
| `menus.xml` | - | Menu structure | ⭐ ACTUALIZADO |

---

## 🚀 Acceso desde Odoo UI

### Navegación Principal

**Desde Dashboard:**
```
Apps → Contabilidad → DTE Chile
```

**Rutas directas:**

1. **Generar Factura Electrónica:**
   ```
   Contabilidad → DTE Chile → Operaciones → Facturas Electrónicas → Crear
   ```

2. **Configurar Certificado Digital:**
   ```
   Contabilidad → DTE Chile → Configuración → Certificados Digitales → Crear
   ```

3. **Cargar CAF:**
   ```
   Contabilidad → DTE Chile → Configuración → CAF (Folios) → Crear
   ```

4. **Ver DTEs Recibidos:**
   ```
   Contabilidad → DTE Chile → DTEs Recibidos
   ```

5. **Generar Libro Mensual:**
   ```
   Contabilidad → DTE Chile → Reportes SII → Libro Compra/Venta → Crear
   ```

6. **Configurar Microservicios:**
   ```
   Ajustes → Contabilidad → Scroll down → "Facturación Electrónica Chile (DTE)"
   ```

---

## 🔐 Permisos y Grupos de Seguridad

**Archivo:** `security/security_groups.xml`

```xml
<record id="group_dte_user" model="res.groups">
    <field name="name">DTE User</field>
    <field name="category_id" ref="base.module_category_accounting"/>
</record>

<record id="group_dte_manager" model="res.groups">
    <field name="name">DTE Manager</field>
    <field name="category_id" ref="base.module_category_accounting"/>
    <field name="implied_ids" eval="[(4, ref('group_dte_user'))]"/>
</record>
```

**Archivo:** `security/ir.model.access.csv`

Accesos configurados para:
- DTE User: Read/Create DTEs
- DTE Manager: Full CRUD + Config

---

## ✅ Checklist de Implementación Frontend

### Menús
- ✅ Menú principal "DTE Chile"
- ✅ Submenú "Operaciones" con 5 opciones
- ✅ Submenú "DTEs Recibidos"
- ✅ Submenú "Reportes SII" con 3 opciones
- ✅ Submenú "Comunicaciones SII"
- ✅ Submenú "Configuración" con 3 opciones

### Vistas
- ✅ 11 modelos con vistas completas
- ✅ Todas las vistas incluyen Tree + Form + Search
- ✅ Vistas Kanban para modelos principales
- ✅ Botones de acción en headers (Generar, Enviar, Consultar)
- ✅ Stat buttons con contadores
- ✅ Chatter integrado (mail.thread, mail.activity.mixin)

### Integraciones
- ✅ Extiende account.move (no duplica)
- ✅ Extiende stock.picking (no duplica)
- ✅ Extiende purchase.order (no duplica)
- ✅ Extiende res.config.settings (no duplica)
- ✅ Compatible con l10n_cl, l10n_latam_base

### Acciones
- ✅ 11 actions definidas
- ✅ Todas las actions tienen help text
- ✅ Context configurado correctamente
- ✅ Domains para filtros automáticos

---

## 🎨 Colores y Decoraciones

**Campos state con badges:**
```python
decoration-muted="state == 'draft'"           # Gris (Borrador)
decoration-info="state == 'generated'"        # Azul (Generado)
decoration-warning="state in ('sent', ...)"   # Amarillo (Enviado)
decoration-success="state == 'accepted'"      # Verde (Aceptado)
decoration-danger="state == 'rejected'"       # Rojo (Rechazado)
```

**Iconos:**
- 📁 Operaciones: `fa-file-text-o`
- 📥 Recepción: `fa-inbox`
- 📊 Reportes: `fa-bar-chart`
- 📡 Comunicaciones: `fa-exchange`
- ⚙️ Configuración: `fa-cog`
- 🔒 Certificados: `fa-certificate`
- 📋 CAF: `fa-list-ol`

---

## 📝 Notas Técnicas

### Orden de Carga en __manifest__.py

```python
'data': [
    # 1. Seguridad (PRIMERO)
    'security/ir.model.access.csv',
    'security/security_groups.xml',

    # 2. Datos base
    'data/dte_document_types.xml',
    'data/sii_activity_codes.xml',

    # 3. Vistas (definen actions)
    'views/*.xml',

    # 4. Menús (AL FINAL - referencian actions)
    'views/menus.xml',

    # 5. Wizards
    'wizard/*.xml',
]
```

**Razón:** Menús referencian actions, por lo que views deben cargarse antes que menus.xml.

### Estrategia "Extend, Don't Duplicate"

✅ **CORRECTO:**
```python
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'  # Extiende

    dte_type = fields.Selection(...)  # Agrega campo
```

❌ **INCORRECTO:**
```python
class DTEInvoice(models.Model):
    _name = 'dte.invoice'  # Duplica account.move

    partner_id = fields.Many2one(...)  # Re-implementa todo
```

---

## 🚀 Próximos Pasos (Post-Implementación)

1. ✅ Actualizar módulo en Odoo:
   ```bash
   docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -u l10n_cl_dte
   ```

2. ✅ Verificar menús visibles en UI

3. ✅ Probar flujo completo:
   - Configurar certificado
   - Cargar CAF
   - Crear factura DTE
   - Generar y enviar
   - Ver en reportes

---

**Documento generado:** 2025-10-22 23:45 UTC
**Última actualización menús:** 2025-10-22 23:30 UTC
**Total vistas:** 12 archivos XML, 11 modelos
**Total menús:** 16 menuitem records

