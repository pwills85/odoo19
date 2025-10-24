# 📋 INVENTARIO COMPLETO DE COMPONENTES DESHABILITADOS

**Fecha:** 2025-10-22
**Proyecto:** l10n_cl_dte - Odoo 19 CE
**Objetivo:** Identificar todos los componentes deshabilitados para planificar su implementación correcta usando técnicas de Odoo 19 CE

---

## 📊 RESUMEN EJECUTIVO

| Categoría | Total | Activables | Requiere Trabajo | Bloqueo |
|-----------|-------|------------|------------------|---------|
| **Wizards** | 6 | 1 | 4 | 1 |
| **Reportes** | 2 | 0 | 2 | 0 |
| **Botones en Vistas** | 9 | 0 | 9 | 0 |
| **Campos en Vistas** | 6 | 0 | 6 | 0 |
| **Menús** | 1 | 0 | 1 | 0 |
| **Actions** | 1 | 0 | 1 | 0 |
| **TOTAL** | **25** | **1** | **23** | **1** |

**Leyenda:**
- **Activables:** Pueden activarse inmediatamente sin cambios
- **Requiere Trabajo:** Necesitan implementación de métodos/modelos
- **Bloqueo:** Bloqueados por dependencias externas no disponibles

---

## 1️⃣ WIZARDS (6 ARCHIVOS)

### ✅ 1.1. dte_generate_wizard (70% Completado)

**Estado:** 🟡 **EN PROGRESO - ETAPA 2**

**Archivo:** `wizards/dte_generate_wizard.py` + `wizards/dte_generate_wizard_views.xml`

**Cambios Aplicados:**
- ✅ Campo `dte_type` → `dte_code` corregido (3 ubicaciones)
- ✅ Herencia `dte.service.integration` eliminada
- ✅ Métodos compute simplificados
- ✅ Action principal convertido a stub
- ✅ Activado en `__init__.py`
- ✅ Activado en `__manifest__.py` línea 102

**Problema Actual:**
```
TypeError: Model 'dte.generate.wizard' inherits from non-existing model 'dte.service.integration'.
```

**Análisis:**
El wizard aún falla al cargar incluso después de eliminar la herencia. Posibles causas:
1. Dependencias adicionales no identificadas en el código del wizard
2. Views XML pueden tener referencias a métodos no implementados
3. Caché de Odoo no limpiado correctamente

**Opciones para Resolver:**

**Opción A: Simplificar Aún Más (RECOMENDADO)** ⭐
- Crear wizard minimal con solo campos básicos
- Stub completo sin lógica de negocio
- Validar que abre correctamente
- Implementación real en ETAPA 4
- **Tiempo:** 1-2 horas
- **Riesgo:** Bajo

**Opción B: Crear Mixin Faltante**
- Implementar `dte.service.integration` básico
- Stubs de métodos necesarios
- Más trabajo pero wizard más completo
- **Tiempo:** 4-6 horas
- **Riesgo:** Medio

**Opción C: Desactivar Temporalmente**
- Revertir cambios
- Mantener wizard desactivado
- Pasar a ETAPA 3 (reportes)
- **Tiempo:** 30 minutos
- **Riesgo:** Ninguno (status quo)

**Recomendación:** Opción A

**Prioridad:** 🔴 **CRÍTICA** (bloqueando ETAPA 2)

---

### ❌ 1.2. ai_chat_wizard

**Estado:** 🔴 **BLOQUEADO**

**Archivos:**
- `wizards/ai_chat_wizard.py`
- `wizards/ai_chat_wizard_views.xml`

**Desactivación:**
- Comentado en `wizards/__init__.py` línea 4
- Comentado en `__manifest__.py` línea 103

**Razón:**
```python
# from . import ai_chat_wizard  # ⭐ DESACTIVADO: depende de ai_chat_integration
```

**Dependencia Bloqueante:**
El wizard depende de un modelo `ai.chat.integration` que NO existe en el código actual. Posiblemente era una integración planificada que nunca se implementó.

**Análisis Adicional Necesario:**
1. Leer `ai_chat_wizard.py` para entender dependencias completas
2. Verificar si `ai-service` (microservicio FastAPI) puede suplir la funcionalidad
3. Decidir si implementar el modelo faltante o rediseñar el wizard

**Opciones:**

**Opción A: Crear Modelo Faltante**
- Implementar `models/ai_chat_integration.py`
- Conectar con microservicio ai-service existente
- **Tiempo:** 8-12 horas
- **Riesgo:** Alto (requiere arquitectura nueva)

**Opción B: Descartar Wizard**
- Eliminar archivos del módulo
- Funcionalidad no crítica para DTE
- **Tiempo:** 30 minutos
- **Riesgo:** Ninguno

**Opción C: Rediseñar como Transient Simple**
- Wizard autocontenido sin modelo base
- Llamadas directas a ai-service
- **Tiempo:** 6-8 horas
- **Riesgo:** Medio

**Recomendación:** Opción B (descartar) o posponer para FASE AVANZADA

**Prioridad:** 🟢 **BAJA** (funcionalidad opcional)

---

### ❌ 1.3. upload_certificate_wizard

**Estado:** 🔴 **NO EXISTE**

**Desactivación:** `__manifest__.py` línea 105

```python
# 'wizard/upload_certificate_views.xml',  # ⭐ FASE 2
```

**Verificación:**
```bash
$ ls -la /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/wizard/
ls: /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/wizard/: No such file or directory
```

**Análisis:**
El archivo NO EXISTE en el sistema de archivos. La referencia en `__manifest__.py` es incorrecta (note que usa `wizard/` en singular, pero la carpeta real es `wizards/` en plural).

**Funcionalidad Esperada:**
Wizard para subir certificados digitales PKCS#12 (.pfx/.p12) del SII.

**Implementación Requerida:**

**Paso 1: Crear Modelo Transient**
```python
# wizards/upload_certificate_wizard.py
class UploadCertificateWizard(models.TransientModel):
    _name = 'upload.certificate.wizard'
    _description = 'Upload Digital Certificate'

    certificate_file = fields.Binary(required=True)
    password = fields.Char(required=True)
    name = fields.Char(required=True)
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)
```

**Paso 2: Método de Procesamiento**
```python
def action_upload(self):
    # 1. Validate PKCS#12 format
    # 2. Extract certificate info
    # 3. Create dte.certificate record
    # 4. Store encrypted in database
```

**Paso 3: View XML**
```xml
<form>
    <group>
        <field name="name"/>
        <field name="certificate_file" filename="certificate_file_name"/>
        <field name="password" password="True"/>
    </group>
    <footer>
        <button name="action_upload" type="object" string="Upload"/>
        <button special="cancel" string="Cancel"/>
    </footer>
</form>
```

**Tiempo Estimado:** 4-6 horas
**Prioridad:** 🟡 **MEDIA** (útil pero no crítico - existe formulario manual)

---

### ❌ 1.4. send_dte_batch_wizard

**Estado:** 🔴 **NO EXISTE**

**Desactivación:** `__manifest__.py` línea 106

```python
# 'wizard/send_dte_batch_views.xml',  # ⭐ FASE 2
```

**Funcionalidad Esperada:**
Wizard para enviar múltiples DTEs al SII en lote (batch processing).

**Implementación Requerida:**

**Modelo:**
```python
class SendDTEBatchWizard(models.TransientModel):
    _name = 'send.dte.batch.wizard'
    _description = 'Send DTEs in Batch'

    invoice_ids = fields.Many2many('account.move', default=lambda self: self.env.context.get('active_ids'))
    environment = fields.Selection([('sandbox', 'Maullin'), ('production', 'Palena')])
    certificate_id = fields.Many2one('dte.certificate', required=True)
```

**Método:**
```python
def action_send_batch(self):
    # 1. Validate all invoices
    # 2. Queue to RabbitMQ
    # 3. Return progress notification
```

**Integración:**
- Action en tree view de facturas (selección múltiple)
- Usa RabbitMQ para procesamiento asíncrono

**Tiempo Estimado:** 6-8 horas
**Prioridad:** 🟡 **MEDIA** (mejora UX pero existe envío individual)

---

### ❌ 1.5. generate_consumo_folios_wizard

**Estado:** 🔴 **NO EXISTE**

**Desactivación:** `__manifest__.py` línea 107

```python
# 'wizard/generate_consumo_folios_views.xml',  # ⭐ FASE 2
```

**Funcionalidad Esperada:**
Wizard para generar reporte de "Consumo de Folios" mensual obligatorio al SII.

**Contexto SII:**
Según normativa chilena, las empresas deben reportar mensualmente al SII:
- Folios utilizados de cada tipo de DTE
- Folios anulados
- Rango de folios consumidos

**Implementación Requerida:**

**Modelo:**
```python
class GenerateConsumoFoliosWizard(models.TransientModel):
    _name = 'generate.consumo.folios.wizard'
    _description = 'Generate Folio Consumption Report'

    periodo_mes = fields.Date(required=True, default=fields.Date.context_today)
    dte_type = fields.Selection([('33', 'Factura'), ('52', 'Guía'), ...])
    company_id = fields.Many2one('res.company')
```

**Lógica:**
1. Consultar todas las facturas del mes con folios asignados
2. Agrupar por tipo de DTE
3. Generar XML según schema SII `ConsumoFolios_v10.xsd`
4. Firmar digitalmente
5. Enviar vía SOAP
6. Crear registro en `dte.consumo.folios` (modelo a crear)

**Tiempo Estimado:** 10-12 horas (incluye modelo + XML generator)
**Prioridad:** 🔴 **ALTA** (reporte obligatorio SII)

---

### ❌ 1.6. generate_libro_wizard

**Estado:** 🔴 **NO EXISTE**

**Desactivación:** `__manifest__.py` línea 108

```python
# 'wizard/generate_libro_views.xml',  # ⭐ FASE 2
```

**Funcionalidad Esperada:**
Wizard para generar Libro de Compra/Venta mensual.

**Contexto:**
El modelo `dte.libro` ya existe y está activo. El wizard facilitaría:
- Selección automática de facturas del período
- Pre-validación antes de generación
- Configuración de parámetros de envío

**Implementación Requerida:**

**Modelo:**
```python
class GenerateLibroWizard(models.TransientModel):
    _name = 'generate.libro.wizard'
    _description = 'Generate Purchase/Sales Book'

    tipo_libro = fields.Selection([('compra', 'Purchase'), ('venta', 'Sales')])
    periodo_mes = fields.Date(required=True)
    tipo_envio = fields.Selection([('total', 'Total'), ('rectifica', 'Rectificación')])
```

**Tiempo Estimado:** 4-6 horas
**Prioridad:** 🟡 **MEDIA** (modelo principal ya existe, wizard es UX)

---

## 2️⃣ REPORTES (2 ARCHIVOS)

### ❌ 2.1. dte_invoice_report.xml

**Estado:** 🔴 **DESACTIVADO - FASE 3**

**Desactivación:** `__manifest__.py` línea 112

```python
# 'reports/dte_invoice_report.xml',  # ⭐ FASE 3
```

**Funcionalidad Esperada:**
Reporte PDF imprimible de factura electrónica (DTE 33) con:
- Timbre Electrónico (TED)
- Código QR
- Formato cedible (según normativa SII)
- Logo empresa
- Detalle de impuestos

**Implementación Requerida:**

**Paso 1: QWeb Template**
```xml
<template id="report_invoice_dte_document">
    <t t-call="web.external_layout">
        <!-- Header: Logo + Datos Emisor -->
        <!-- TED (Timbre) -->
        <!-- QR Code -->
        <!-- Detalle Productos -->
        <!-- Totales -->
        <!-- Footer: Datos Receptor -->
    </t>
</template>
```

**Paso 2: Report Definition**
```xml
<report id="action_report_invoice_dte"
        string="Factura Electrónica"
        model="account.move"
        report_type="qweb-pdf"
        file="l10n_cl_dte.report_invoice_dte_document"
        name="l10n_cl_dte.report_invoice_dte_document"/>
```

**Paso 3: Generación de TED y QR**
Métodos en `models/account_move_dte.py`:
```python
def _generate_ted_barcode(self):
    """Generate electronic timestamp (TED) barcode"""
    # DD XML + Digital signature

def _generate_qr_code(self):
    """Generate QR code with invoice validation URL"""
    # https://www.sii.cl/servicios/factura/electr/docs/...
```

**Tiempo Estimado:** 12-16 horas (incluye diseño visual + TED + QR)
**Prioridad:** 🔴 **ALTA** (documento legal obligatorio)

---

### ❌ 2.2. dte_receipt_report.xml

**Estado:** 🔴 **DESACTIVADO - FASE 3**

**Desactivación:** `__manifest__.py` línea 113

```python
# 'reports/dte_receipt_report.xml',  # ⭐ FASE 3
```

**Funcionalidad Esperada:**
Reporte PDF de "Acuse de Recibo" de DTE recibido (compras).

**Contexto SII:**
Cuando una empresa recibe un DTE de un proveedor, debe:
1. Validar el DTE
2. Aceptar o rechazar
3. Enviar "Acuse de Recibo" al SII
4. Opcionalmente, generar reporte impreso

**Implementación Requerida:**

**QWeb Template:**
```xml
<template id="report_dte_receipt_document">
    <!-- Datos del DTE recibido -->
    <!-- Estado de aceptación/rechazo -->
    <!-- Observaciones -->
    <!-- Firma receptor -->
</template>
```

**Tiempo Estimado:** 8-10 horas
**Prioridad:** 🟡 **MEDIA** (útil pero no crítico - acuse se envía vía XML)

---

## 3️⃣ BOTONES EN VISTAS (9 BOTONES)

### 3.1. dte_libro_views.xml (4 botones)

**Ubicación:** `views/dte_libro_views.xml` líneas 16-25

**Botones Desactivados:**

#### 🔴 3.1.1. action_generate_libro

```xml
<!-- DESACTIVADO línea 17 -->
<button name="action_generate_libro" string="Generar Libro" type="object"
        class="oe_highlight" invisible="state != 'draft'"/>
```

**Método Faltante:** `models/dte_libro.py` → `action_generate_libro()`

**Funcionalidad:**
Generar XML del Libro de Compra/Venta según schema SII.

**Implementación:**
```python
def action_generate_libro(self):
    """Generate Purchase/Sales Book XML"""
    self.ensure_one()

    # 1. Validate invoices
    if not self.move_ids:
        raise UserError(_('No invoices selected'))

    # 2. Generate XML (EnvioLibro)
    xml = self._generate_libro_xml()

    # 3. Sign with certificate
    signed_xml = self._sign_xml(xml)

    # 4. Store
    self.write({
        'xml_file': base64.b64encode(signed_xml),
        'xml_file_name': f'libro_{self.tipo_libro}_{self.periodo_mes}.xml',
        'state': 'generated',
    })
```

**Tiempo:** 8-10 horas
**Prioridad:** 🔴 **ALTA** (funcionalidad core)

---

#### 🔴 3.1.2. action_send_libro

```xml
<!-- DESACTIVADO línea 19 -->
<button name="action_send_libro" string="Enviar al SII" type="object"
        class="oe_highlight" invisible="state != 'generated'"/>
```

**Método Faltante:** `models/dte_libro.py` → `action_send_libro()`

**Funcionalidad:**
Enviar Libro generado al SII vía SOAP.

**Implementación:**
```python
def action_send_libro(self):
    """Send book to SII"""
    self.ensure_one()

    # 1. Validate XML exists
    if not self.xml_file:
        raise UserError(_('Generate book first'))

    # 2. Call DTE Service
    response = requests.post(
        'http://dte-service:8001/api/v1/send_libro',
        json={'xml_b64': self.xml_file.decode()},
        headers={'Authorization': f'Bearer {api_key}'}
    )

    # 3. Process response
    if response['success']:
        self.write({
            'track_id': response['track_id'],
            'state': 'sent',
        })
```

**Tiempo:** 4-6 horas
**Prioridad:** 🔴 **ALTA**

---

#### 🔴 3.1.3. action_consultar_estado

```xml
<!-- DESACTIVADO línea 21 -->
<button name="action_consultar_estado" string="Consultar Estado" type="object"
        invisible="state not in ('sent', 'processing')"/>
```

**Método Faltante:** `models/dte_libro.py` → `action_consultar_estado()`

**Funcionalidad:**
Consultar estado del Libro en SII usando track_id.

**Implementación:**
```python
def action_consultar_estado(self):
    """Check book status in SII"""
    for record in self:
        if not record.track_id:
            continue

        # Call SII GetEstadoLibro
        response = requests.post(
            'http://dte-service:8001/api/v1/get_libro_status',
            json={'track_id': record.track_id}
        )

        record.write({
            'state': response['state'],  # accepted/rejected
            'sii_response': response['message'],
        })
```

**Tiempo:** 4 horas
**Prioridad:** 🟡 **MEDIA**

---

#### 🔴 3.1.4. action_set_draft

```xml
<!-- DESACTIVADO línea 23 -->
<button name="action_set_draft" string="Volver a Borrador" type="object"
        invisible="state == 'draft'"/>
```

**Método Faltante:** `models/dte_libro.py` → `action_set_draft()`

**Funcionalidad:**
Resetear libro a borrador para modificar.

**Implementación:**
```python
def action_set_draft(self):
    """Reset to draft"""
    self.write({'state': 'draft'})
```

**Tiempo:** 30 minutos
**Prioridad:** 🟢 **BAJA** (funcionalidad simple)

---

### 3.2. dte_libro_views.xml - Button Box (1 botón)

#### 🔴 3.2.1. action_view_invoices

**Ubicación:** `views/dte_libro_views.xml` líneas 32-38

```xml
<!-- DESACTIVADO línea 33 -->
<button name="action_view_invoices" type="object"
        class="oe_stat_button" icon="fa-file-text-o">
    <field name="cantidad_documentos" widget="statinfo"
           string="Documentos"/>
</button>
```

**Método Faltante:** `models/dte_libro.py` → `action_view_invoices()`

**Funcionalidad:**
Smart button para abrir vista de facturas incluidas en el libro.

**Implementación:**
```python
def action_view_invoices(self):
    """Open invoices in this book"""
    self.ensure_one()
    return {
        'name': _('Invoices in Book'),
        'type': 'ir.actions.act_window',
        'res_model': 'account.move',
        'view_mode': 'tree,form',
        'domain': [('id', 'in', self.move_ids.ids)],
    }
```

**Tiempo:** 1 hora
**Prioridad:** 🟢 **BAJA** (UX improvement)

---

### 3.3. dte_libro_guias_views.xml (0 botones)

**Nota:** Los botones en este archivo SÍ están activos:
- `action_agregar_guias` (línea 14)
- `action_generar_y_enviar` (línea 21)
- `action_consultar_estado_sii` (línea 28)

**Verificación Necesaria:**
Confirmar que estos 3 métodos están implementados en `models/dte_libro_guias.py`.

---

### 3.4. account_move_dte_views.xml (3 botones)

#### 🟢 3.4.1. Professional Wizard Button (PARCIALMENTE ACTIVO)

**Ubicación:** `views/account_move_dte_views.xml` línea 12

```xml
<!-- ⭐ DESACTIVADO: Botón Professional Wizard (requiere wizard views desactivado en manifest) -->
```

**Estado:**
El botón está comentado en XML pero el wizard existe y está en proceso de activación (ETAPA 2 70% completada).

**Código del Botón (comentado):**
```xml
<button name="%(action_dte_generate_wizard)d" string="Generar DTE" type="action"
        class="oe_highlight"
        invisible="state != 'posted' or not dte_code"/>
```

**Acción:**
Una vez resuelto el problema del wizard en ETAPA 2, descomentar este botón.

**Tiempo:** 5 minutos (solo descomentar)
**Prioridad:** 🔴 **CRÍTICA** (depende de ETAPA 2)

---

#### 🟢 3.4.2. action_send_to_sii (ACTIVO)

**Ubicación:** línea 15

```xml
<button name="action_send_to_sii" string="Enviar a SII" type="object"
        class="btn-secondary"
        invisible="dte_status not in ('draft', 'to_send', 'rejected') or state != 'posted'"/>
```

**Estado:** ✅ **ACTIVO** (método ya implementado en `models/account_move_dte.py`)

---

#### 🟢 3.4.3. action_send_dte_async (ACTIVO)

**Ubicación:** línea 20

```xml
<button name="action_send_dte_async" string="Enviar DTE (Async)" type="object"
        class="oe_highlight"
        icon="fa-paper-plane"
        invisible="state != 'posted' or not dte_code or dte_async_status in ('queued', 'processing')"/>
```

**Estado:** ✅ **ACTIVO** (método implementado - RabbitMQ integration)

---

## 4️⃣ CAMPOS EN VISTAS (6 CAMPOS)

### 4.1. dte_libro_views.xml (4 campos)

#### 🔴 4.1.1. tipo_envio

**Ubicación:** `views/dte_libro_views.xml` líneas 58-61

```xml
<!-- ⭐ DESACTIVADO: campo tipo_envio no existe en modelo -->
<field name="tipo_envio" readonly="state != 'draft'"/>
```

**Problema:**
Campo NO existe en modelo `dte.libro`.

**Funcionalidad Esperada:**
Tipo de envío del libro:
- `total`: Envío total (primera vez en el mes)
- `rectifica`: Rectificación (corrige envío anterior)
- `complementa`: Complementa (agrega facturas olvidadas)

**Implementación Requerida:**

**En modelo (`models/dte_libro.py`):**
```python
tipo_envio = fields.Selection([
    ('total', 'Total'),
    ('rectifica', 'Rectificación'),
    ('complementa', 'Complementa'),
], string='Tipo Envío', default='total', required=True)
```

**Tiempo:** 30 minutos
**Prioridad:** 🟡 **MEDIA** (útil para reportes SII)

---

#### 🔴 4.1.2. sii_status

**Ubicación:** línea 93

```xml
<!-- DESACTIVADO: campo no existe -->
<field name="sii_status" readonly="1"/>
```

**Problema:**
Campo NO existe en modelo.

**Funcionalidad:**
Estado devuelto por SII después de consultar con track_id.

**Implementación:**
```python
sii_status = fields.Selection([
    ('pending', 'Pendiente'),
    ('processing', 'Procesando'),
    ('accepted', 'Aceptado'),
    ('rejected', 'Rechazado'),
    ('reparo', 'Reparo'),
], string='SII Status', readonly=True)
```

**Tiempo:** 30 minutos
**Prioridad:** 🟡 **MEDIA**

---

#### 🔴 4.1.3. fecha_envio

**Ubicación:** línea 94

```xml
<field name="fecha_envio" readonly="1"/>
```

**Problema:**
Campo NO existe.

**Implementación:**
```python
fecha_envio = fields.Datetime('Fecha Envío SII', readonly=True)
```

**Tiempo:** 15 minutos
**Prioridad:** 🟢 **BAJA**

---

#### 🔴 4.1.4. fecha_aceptacion

**Ubicación:** línea 95

```xml
<field name="fecha_aceptacion" readonly="1"/>
```

**Problema:**
Campo NO existe.

**Implementación:**
```python
fecha_aceptacion = fields.Datetime('Fecha Aceptación SII', readonly=True)
```

**Tiempo:** 15 minutos
**Prioridad:** 🟢 **BAJA**

---

### 4.2. dte_libro_guias_views.xml (1 campo)

#### 🔴 4.2.1. sale_id (en stock.picking)

**Ubicación:** `views/dte_libro_guias_views.xml` línea 86

```xml
<!-- ⭐ DESACTIVADO: sale_id no existe en stock.picking CE -->
```

**Problema:**
El campo `sale_id` (relación con venta) NO existe en **Odoo Community Edition**.

Solo existe en **Odoo Enterprise** con el módulo `sale_stock`.

**Análisis:**
- CE: `stock.picking` no tiene relación directa con `sale.order`
- EE: `sale.order` → `sale_id` many2one

**Opciones:**

**Opción A: No Agregar (Recomendado)**
Mantener comentado. No es información crítica para Libro de Guías.

**Opción B: Crear Campo Computed**
```python
# En l10n_cl_dte/models/stock_picking_dte.py
sale_id = fields.Many2one('sale.order', compute='_compute_sale_id', store=False)

def _compute_sale_id(self):
    for picking in self:
        # Buscar venta relacionada via stock.move → sale.order.line
        sale = self.env['sale.order'].search([
            ('picking_ids', 'in', picking.id)
        ], limit=1)
        picking.sale_id = sale
```

**Tiempo:** 2-3 horas (Opción B)
**Prioridad:** 🟢 **BAJA** (no crítico)
**Recomendación:** Opción A (mantener desactivado)

---

### 4.3. dte_libro_views.xml (1 campo comentado)

#### ⚠️ 4.3.1. sii_response

**Ubicación:** líneas 100-102

```xml
<!-- ⭐ DESACTIVADO: campo sii_response no existe -->
<field name="sii_response" readonly="1" widget="text"/>
```

**Problema:**
Campo NO existe en modelo.

**Funcionalidad:**
Mensaje de respuesta del SII (XML parseado).

**Implementación:**
```python
sii_response = fields.Text('Respuesta SII', readonly=True)
```

**Tiempo:** 15 minutos
**Prioridad:** 🟢 **BAJA**

---

## 5️⃣ MENÚS (1 MENÚ)

### 🔴 5.1. Configuración General

**Ubicación:** `views/menus.xml` líneas 145-152

```xml
<!-- ⭐ TEMPORALMENTE DESACTIVADO: base.action_res_config_settings no existe en Odoo 19 -->
<menuitem
    id="menu_dte_settings"
    name="Configuración General"
    parent="menu_dte_configuration"
    action="base.action_res_config_settings"
    sequence="100"/>
```

**Problema:**
En Odoo 19, el action `base.action_res_config_settings` cambió. Ahora se debe especificar el modelo de configuración correcto.

**Solución:**

**Paso 1: Crear Modelo de Configuración**
```python
# models/res_config_settings.py
from odoo import models, fields

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # DTE Service Config
    dte_service_url = fields.Char(
        string='DTE Service URL',
        config_parameter='l10n_cl_dte.service_url',
        default='http://dte-service:8001'
    )

    dte_service_api_key = fields.Char(
        string='DTE Service API Key',
        config_parameter='l10n_cl_dte.api_key'
    )

    # SII Config
    sii_environment = fields.Selection([
        ('sandbox', 'Maullin (Sandbox)'),
        ('production', 'Palena (Production)')
    ], string='SII Environment',
       config_parameter='l10n_cl_dte.sii_environment',
       default='sandbox')
```

**Paso 2: Crear Vista**
```xml
<!-- views/res_config_settings_views.xml (ya existe) -->
<record id="res_config_settings_view_form" model="ir.ui.view">
    <field name="name">res.config.settings.view.form.inherit.dte</field>
    <field name="model">res.config.settings</field>
    <field name="inherit_id" ref="base.res_config_settings_view_form"/>
    <field name="arch" type="xml">
        <xpath expr="//div[hasclass('settings')]" position="inside">
            <div class="app_settings_block" data_key="l10n_cl_dte">
                <h2>DTE Chile Configuration</h2>
                <div class="row mt16 o_settings_container">
                    <div class="col-12 col-lg-6 o_setting_box">
                        <div class="o_setting_left_pane"/>
                        <div class="o_setting_right_pane">
                            <label for="dte_service_url"/>
                            <field name="dte_service_url"/>
                        </div>
                    </div>
                </div>
            </div>
        </xpath>
    </field>
</record>
```

**Paso 3: Crear Action Correcto**
```xml
<record id="action_dte_settings" model="ir.actions.act_window">
    <field name="name">DTE Configuration</field>
    <field name="res_model">res.config.settings</field>
    <field name="view_mode">form</field>
    <field name="target">inline</field>
    <field name="context">{'module': 'l10n_cl_dte'}</field>
</record>
```

**Paso 4: Actualizar Menú**
```xml
<menuitem
    id="menu_dte_settings"
    name="Configuración General"
    parent="menu_dte_configuration"
    action="action_dte_settings"  <!-- CAMBIO AQUÍ -->
    sequence="100"/>
```

**Tiempo:** 3-4 horas
**Prioridad:** 🟡 **MEDIA** (configuración accesible vía Settings generales, pero menú directo es UX)

---

## 6️⃣ ACTIONS (1 ACTION)

### 🔴 6.1. action_view_libro_guias_pickings

**Ubicación:** `views/dte_libro_guias_views.xml` líneas 230-238

```xml
<!-- ⭐ DESACTIVADO: Action no usado (botón comentado en formulario) -->
<record id="action_view_libro_guias_pickings" model="ir.actions.act_window">
    <field name="name">Guías del Libro</field>
    <field name="res_model">stock.picking</field>
    <field name="view_mode">tree,form</field>
    <field name="domain">[('id', 'in', active_id)]</field>
    <field name="context">{'default_picking_type_code': 'outgoing'}</field>
</record>
```

**Problema:**
Action definido pero no se usa en ningún lugar (botón en formulario está comentado).

**Análisis:**
Posiblemente era un smart button que fue reemplazado por el campo `picking_ids` directamente en el formulario.

**Opciones:**

**Opción A: Eliminar**
Action no usado, eliminar del XML.

**Opción B: Crear Smart Button**
Agregar botón en button_box de `dte_libro_guias` form view.

**Recomendación:** Opción A (eliminar)

**Tiempo:** 5 minutos
**Prioridad:** 🟢 **BAJA** (limpieza de código)

---

## 7️⃣ TREE VIEW INHERITANCE (1 VISTA)

### 🔴 7.1. view_move_tree_dte

**Ubicación:** `views/account_move_dte_views.xml` líneas 171-192

```xml
<!-- ⭐ TEMPORALMENTE DESACTIVADO: account.view_invoice_tree cambió en Odoo 19 -->
<record id="view_move_tree_dte" model="ir.ui.view">
    <field name="name">account.move.tree.dte</field>
    <field name="model">account.move</field>
    <field name="inherit_id" ref="account.view_invoice_tree"/>
    ...
</record>
```

**Problema:**
En Odoo 19, la vista tree de facturas cambió:
- Odoo 18: `account.view_invoice_tree`
- Odoo 19: Vista rediseñada con nuevo ID

**Solución:**

**Paso 1: Identificar Vista Correcta en Odoo 19**
```bash
docker-compose exec db psql -U odoo -d odoo -c \
  "SELECT id, name, model FROM ir_ui_view WHERE model='account.move' AND type='tree' LIMIT 5;"
```

**Paso 2: Actualizar inherit_id**
```xml
<field name="inherit_id" ref="account.view_move_tree"/>  <!-- NUEVO ID Odoo 19 -->
```

**Paso 3: Verificar XPath**
Confirmar que el xpath `//field[@name='state']` existe en la nueva vista.

**Tiempo:** 2-3 horas (incluye investigación de cambios en Odoo 19)
**Prioridad:** 🟡 **MEDIA** (mejorar UX en list view)

---

## 📋 PLAN DE RE-ACTIVACIÓN POR ETAPAS

### ETAPA 2: RESTAURAR WIZARD ✅ (EN PROGRESO - 70%)

**Objetivo:** Activar `dte_generate_wizard` funcionalmente

**Tareas Pendientes:**
1. ✅ Corregir campos `dte_type` → `dte_code` (COMPLETADO)
2. ✅ Eliminar herencia inexistente (COMPLETADO)
3. ✅ Simplificar métodos compute (COMPLETADO)
4. ⏳ **Resolver error de carga del wizard** (EN PROGRESO)
   - Opción A: Simplificar aún más (1-2h)
   - Opción B: Crear mixin (4-6h)
   - Opción C: Desactivar temporalmente (30min)
5. ⏳ Descomentar botón Professional Wizard (5min)

**Tiempo Restante:** 1-6 horas (según opción elegida)

---

### ETAPA 3: RESTAURAR REPORTES (PENDIENTE)

**Objetivo:** Activar reportes PDF de DTEs

**Tareas:**
1. 🔴 Implementar `dte_invoice_report.xml` (12-16h)
   - QWeb template
   - Generación TED
   - Generación QR Code
   - Formato cedible SII
2. 🔴 Implementar `dte_receipt_report.xml` (8-10h)
   - Template acuse recibo
   - Datos validación

**Tiempo Estimado:** 20-26 horas
**Prioridad:** 🔴 **ALTA** (documentos legales obligatorios)

---

### ETAPA 4: IMPLEMENTAR MÉTODOS LIBRO (PENDIENTE)

**Objetivo:** Activar funcionalidad completa de Libro Compra/Venta

**Tareas:**
1. 🔴 `action_generate_libro` (8-10h)
2. 🔴 `action_send_libro` (4-6h)
3. 🔴 `action_consultar_estado` (4h)
4. 🟢 `action_set_draft` (30min)
5. 🟢 `action_view_invoices` (1h)

**Tiempo Estimado:** 17-21.5 horas
**Prioridad:** 🔴 **ALTA** (reporte mensual obligatorio SII)

---

### ETAPA 5: CREAR WIZARDS FALTANTES (PENDIENTE)

**Objetivo:** Implementar wizards de FASE 2

**Tareas:**
1. 🟡 `upload_certificate_wizard` (4-6h)
2. 🟡 `send_dte_batch_wizard` (6-8h)
3. 🔴 `generate_consumo_folios_wizard` (10-12h)
4. 🟡 `generate_libro_wizard` (4-6h)

**Tiempo Estimado:** 24-32 horas
**Prioridad:** 🟡 **MEDIA-ALTA** (mejoras UX importantes)

---

### ETAPA 6: AGREGAR CAMPOS FALTANTES (PENDIENTE)

**Objetivo:** Completar modelos con campos missing

**Tareas:**
1. 🟡 `dte_libro.tipo_envio` (30min)
2. 🟡 `dte_libro.sii_status` (30min)
3. 🟢 `dte_libro.fecha_envio` (15min)
4. 🟢 `dte_libro.fecha_aceptacion` (15min)
5. 🟢 `dte_libro.sii_response` (15min)

**Tiempo Estimado:** 1.75 horas
**Prioridad:** 🟢 **BAJA** (campos auxiliares no críticos)

---

### ETAPA 7: CORREGIR HERENCIAS DE VISTAS (PENDIENTE)

**Objetivo:** Adaptar vistas heredadas a Odoo 19

**Tareas:**
1. 🟡 `view_move_tree_dte` - Actualizar inherit_id (2-3h)
2. 🟡 Verificar métodos en `dte_libro_guias` (2h)

**Tiempo Estimado:** 4-5 horas
**Prioridad:** 🟡 **MEDIA** (UX improvements)

---

### ETAPA 8: CONFIGURACIÓN Y LIMPIEZA (PENDIENTE)

**Objetivo:** Menús configuración y limpieza código

**Tareas:**
1. 🟡 Crear `action_dte_settings` correcto (3-4h)
2. 🟢 Eliminar `action_view_libro_guias_pickings` (5min)
3. 🟢 Decisión sobre `ai_chat_wizard` (eliminar o rediseñar)

**Tiempo Estimado:** 3-8 horas
**Prioridad:** 🟢 **BAJA**

---

## 📊 RESUMEN DE TIEMPOS

| Etapa | Tiempo Mínimo | Tiempo Máximo | Prioridad |
|-------|---------------|---------------|-----------|
| **ETAPA 2** (Wizard) | 1h | 6h | 🔴 CRÍTICA |
| **ETAPA 3** (Reportes) | 20h | 26h | 🔴 ALTA |
| **ETAPA 4** (Libro Métodos) | 17h | 21.5h | 🔴 ALTA |
| **ETAPA 5** (Wizards Faltantes) | 24h | 32h | 🟡 MEDIA-ALTA |
| **ETAPA 6** (Campos) | 1.75h | 1.75h | 🟢 BAJA |
| **ETAPA 7** (Vistas) | 4h | 5h | 🟡 MEDIA |
| **ETAPA 8** (Config) | 3h | 8h | 🟢 BAJA |
| **TOTAL** | **70.75h** | **100.25h** | |

**Estimación Total:** 9-13 días de trabajo (8h/día)

---

## 🎯 RECOMENDACIONES ESTRATÉGICAS

### Prioridad Inmediata (Sprint 1 - 3-4 días)

1. ✅ **Completar ETAPA 2** (Wizard)
   - Opción A recomendada: Simplificar wizard
   - Validar que abre correctamente
   - Implementación real en ETAPA posterior

2. 🔴 **Iniciar ETAPA 3** (Reportes)
   - `dte_invoice_report.xml` es documento legal obligatorio
   - Requiere TED + QR Code (funcionalidad core)

### Prioridad Alta (Sprint 2 - 4-5 días)

3. 🔴 **Completar ETAPA 4** (Libro Métodos)
   - Reporte mensual obligatorio SII
   - 5 métodos a implementar

4. 🔴 **Wizard Consumo Folios** (de ETAPA 5)
   - Reporte mensual obligatorio
   - Priorizar sobre otros wizards

### Prioridad Media (Sprint 3 - 3-4 días)

5. 🟡 **Completar ETAPA 5** (resto de Wizards)
   - Mejoras UX importantes
   - No bloqueantes para funcionalidad core

6. 🟡 **ETAPA 7** (Vistas)
   - Mejoras UX en list views

### Prioridad Baja (Sprint 4 - 1 día)

7. 🟢 **ETAPA 6** (Campos auxiliares)
8. 🟢 **ETAPA 8** (Configuración y limpieza)

---

## 🚨 DECISIONES REQUERIDAS

### 1. ai_chat_wizard
**Pregunta:** ¿Implementar o eliminar?
- **Eliminar:** 30 minutos, libera código
- **Implementar:** 8-12 horas, funcionalidad opcional

**Recomendación:** Eliminar (funcionalidad no crítica para DTE)

### 2. sale_id en stock.picking
**Pregunta:** ¿Agregar computed field o dejar desactivado?
- **Dejar:** Sin trabajo adicional
- **Agregar:** 2-3 horas, mejora mínima

**Recomendación:** Dejar desactivado (no crítico, solo existe en EE)

### 3. Wizard Simplification (ETAPA 2)
**Pregunta:** ¿Qué opción seguir?
- **A:** Simplificar (1-2h, bajo riesgo)
- **B:** Crear mixin (4-6h, medio riesgo)
- **C:** Desactivar (30min, sin progreso)

**Recomendación:** Opción A

---

## ✅ CRITERIOS DE ÉXITO

### Módulo al 100% Funcional:

1. ✅ **15 modelos** activos y funcionales
2. ✅ **13 vistas** activas (estado actual)
3. 🔄 **2 wizards** activos y funcionales (1/2 actual)
4. 🔴 **2 reportes** PDF implementados (0/2 actual)
5. 🔴 **21 métodos** de acción implementados (12/21 actual)
6. ✅ **Sin campos faltantes** en vistas
7. ✅ **Sin botones desactivados** por métodos faltantes
8. ✅ **Todas las herencias de vistas** correctas para Odoo 19

**Estado Actual:** 57% completado
**Meta:** 100% completado en 70-100 horas de trabajo

---

**FIN DEL INVENTARIO COMPLETO**

---

**Documento Generado:** 2025-10-22 22:45 UTC
**Metodología:** Análisis incremental con validación en staging
**Próxima Acción:** Resolver ETAPA 2 (wizard) según Opción A recomendada
