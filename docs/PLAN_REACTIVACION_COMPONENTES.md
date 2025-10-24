# 🎯 PLAN DETALLADO DE REACTIVACIÓN DE COMPONENTES

**Fecha:** 2025-10-22
**Proyecto:** l10n_cl_dte - Migración Odoo 19 CE
**Objetivo:** Plan paso a paso para reactivar 25 componentes deshabilitados
**Metodología:** Incremental con validación en staging después de cada cambio

---

## 📋 ÍNDICE RÁPIDO

- [ETAPA 2: Completar Wizard (70% → 100%)](#etapa-2)
- [ETAPA 3: Reportes PDF](#etapa-3)
- [ETAPA 4: Métodos Libro Compra/Venta](#etapa-4)
- [ETAPA 5: Wizards Faltantes](#etapa-5)
- [ETAPA 6: Campos Auxiliares](#etapa-6)
- [ETAPA 7: Herencias de Vistas](#etapa-7)
- [ETAPA 8: Configuración y Limpieza](#etapa-8)

---

<a name="etapa-2"></a>
## 🔴 ETAPA 2: COMPLETAR WIZARD - 70% → 100%

**Estado Actual:** 🟡 EN PROGRESO
**Tiempo Estimado:** 1-2 horas
**Prioridad:** 🔴 **CRÍTICA** (bloqueando progreso)

### Contexto

El wizard `dte_generate_wizard` ha sido parcialmente corregido:
- ✅ Campo `dte_type` → `dte_code` corregido
- ✅ Herencia `dte.service.integration` eliminada
- ✅ Métodos compute simplificados
- ✅ Activado en `__init__.py` y `__manifest__.py`

**Problema Actual:**
```
TypeError: Model 'dte.generate.wizard' inherits from non-existing model 'dte.service.integration'.
```

El error persiste incluso después de eliminar la herencia, sugiriendo dependencias adicionales no identificadas.

---

### 📝 OPCIÓN A: SIMPLIFICAR WIZARD (RECOMENDADA) ⭐

**Objetivo:** Crear wizard minimal funcional, implementación completa en ETAPA posterior

#### Paso 1: Crear Backup Pre-Cambio (5 min)

```bash
cd /Users/pedro/Documents/odoo19
./scripts/backup_odoo.sh odoo_staging
```

**Verificar:**
```bash
ls -lh backups/ | tail -1
```

---

#### Paso 2: Crear Versión Minimal del Wizard (30 min)

**Archivo:** `wizards/dte_generate_wizard.py`

**Reemplazar por versión minimal:**

```python
# -*- coding: utf-8 -*-
"""
DTE Generate Wizard - MINIMAL VERSION (ETAPA 2)
==============================================

Wizard simplificado para ETAPA 2.
Solo valida que el wizard abre correctamente.
Implementación completa se realizará en ETAPA 4.
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError

class DTEGenerateWizard(models.TransientModel):
    _name = 'dte.generate.wizard'
    _description = 'Generate DTE Wizard (Minimal)'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    move_id = fields.Many2one(
        'account.move',
        string='Invoice',
        required=True,
        readonly=True,
        default=lambda self: self.env.context.get('active_id')
    )

    dte_code = fields.Selection(
        related='move_id.dte_code',
        string='DTE Type',
        readonly=True
    )

    certificate_id = fields.Many2one(
        'dte.certificate',
        string='Digital Certificate',
        required=True,
        domain="[('company_id', '=', company_id), ('active', '=', True)]"
    )

    caf_id = fields.Many2one(
        'dte.caf',
        string='CAF (Folio Authorization)',
        required=True,
        domain="[('company_id', '=', company_id), ('dte_code', '=', dte_code), ('state', '=', 'active')]"
    )

    environment = fields.Selection([
        ('sandbox', 'Sandbox (Maullin)'),
        ('production', 'Production (Palena)'),
    ], string='SII Environment', default='sandbox', required=True)

    company_id = fields.Many2one(
        related='move_id.company_id',
        store=True
    )

    status_message = fields.Text(
        string='Status',
        readonly=True,
        default='✅ ETAPA 2: Wizard minimal funcional.\n'
                'La generación real de DTEs se implementará en ETAPA 4.'
    )

    # ═══════════════════════════════════════════════════════════
    # ONCHANGE METHODS
    # ═══════════════════════════════════════════════════════════

    @api.onchange('certificate_id')
    def _onchange_certificate(self):
        """Auto-fill CAF when certificate changes."""
        if self.certificate_id and self.dte_code:
            caf = self.env['dte.caf'].search([
                ('company_id', '=', self.company_id.id),
                ('dte_code', '=', self.dte_code),
                ('state', '=', 'active'),
                ('available_folios', '>', 0),
            ], limit=1)

            self.caf_id = caf if caf else False

    # ═══════════════════════════════════════════════════════════
    # VALIDATIONS
    # ═══════════════════════════════════════════════════════════

    def _validate_pre_generation(self):
        """Pre-flight checks - MINIMAL VERSION"""
        self.ensure_one()

        # 1. Invoice validations
        if self.move_id.state != 'posted':
            raise UserError(_('Invoice must be posted'))

        # 2. Company validations
        if not self.company_id.vat:
            raise UserError(_('Company RUT is not configured'))

        # 3. Partner validations
        if not self.move_id.partner_id.vat:
            raise UserError(_('Customer RUT is required'))

        # 4. Certificate validations
        if not self.certificate_id:
            raise UserError(_('Digital certificate is required'))

        # 5. CAF validations
        if not self.caf_id:
            raise UserError(_('CAF (Folio Authorization) is required'))

        return True

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_generate_dte(self):
        """
        ETAPA 2: STUB IMPLEMENTATION

        Valida que el wizard abre y funciona correctamente.
        Solo registra la configuración seleccionada.
        NO genera DTE real (implementación en ETAPA 4).
        """
        self.ensure_one()

        # Validaciones básicas
        self._validate_pre_generation()

        # Registrar configuración en factura
        self.move_id.write({
            'dte_certificate_id': self.certificate_id.id,
            'dte_caf_id': self.caf_id.id,
            'dte_environment': self.environment,
        })

        # Log en chatter
        self.move_id.message_post(
            body=_(
                '✅ <strong>DTE Wizard Configurado (ETAPA 2)</strong><br/>'
                'Certificado: %s<br/>'
                'CAF: %s<br/>'
                'Ambiente: %s<br/>'
                '<em>Generación real de DTEs se implementará en ETAPA 4.</em>'
            ) % (
                self.certificate_id.name,
                self.caf_id.name,
                self.environment
            )
        )

        # Notificación usuario
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('✅ Wizard Activado Exitosamente'),
                'message': _(
                    'ETAPA 2 Completada: Wizard funciona correctamente.\n\n'
                    'Configuración guardada:\n'
                    '• Certificado: %s\n'
                    '• Ambiente: %s\n\n'
                    'La generación de DTEs se implementará en ETAPA 4.'
                ) % (self.certificate_id.name, self.environment),
                'type': 'success',
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            }
        }

    def action_cancel(self):
        """Cancel wizard."""
        return {'type': 'ir.actions.act_window_close'}
```

**Cambios Clave:**
1. ✅ Eliminados todos los campos computed (service_health, contingency)
2. ✅ Eliminados métodos helper complejos
3. ✅ Solo campos básicos esenciales
4. ✅ Validaciones mínimas
5. ✅ Action stub que solo guarda configuración
6. ✅ Mensajes claros indicando que es versión minimal

---

#### Paso 3: Actualizar Vista del Wizard (15 min)

**Archivo:** `wizards/dte_generate_wizard_views.xml`

**Simplificar form view (reemplazar contenido):**

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- ══════════════════════════════════════════════════════════════════
         DTE GENERATE WIZARD - MINIMAL VERSION (ETAPA 2)
         ══════════════════════════════════════════════════════════════════ -->

    <!-- Form View -->
    <record id="view_dte_generate_wizard_form" model="ir.ui.view">
        <field name="name">dte.generate.wizard.form</field>
        <field name="model">dte.generate.wizard</field>
        <field name="arch" type="xml">
            <form string="Generate DTE">
                <div class="alert alert-info" role="alert">
                    <strong>ℹ️ ETAPA 2 - Wizard Minimal</strong><br/>
                    Este es un wizard simplificado para validar funcionalidad básica.<br/>
                    La generación real de DTEs se implementará en ETAPA 4.
                </div>

                <group>
                    <group string="Invoice Information">
                        <field name="move_id" readonly="1"/>
                        <field name="dte_code" readonly="1"/>
                        <field name="company_id" readonly="1"/>
                    </group>

                    <group string="DTE Configuration">
                        <field name="certificate_id"
                               options="{'no_create': True, 'no_open': True}"/>
                        <field name="caf_id"
                               options="{'no_create': True, 'no_open': True}"/>
                        <field name="environment" widget="radio"/>
                    </group>
                </group>

                <group>
                    <field name="status_message" readonly="1"
                           class="text-muted"/>
                </group>

                <footer>
                    <button name="action_generate_dte"
                            string="Configure DTE"
                            type="object"
                            class="btn-primary"/>
                    <button name="action_cancel"
                            string="Cancel"
                            type="object"
                            class="btn-secondary"/>
                </footer>
            </form>
        </field>
    </record>

    <!-- Action Window -->
    <record id="action_dte_generate_wizard" model="ir.actions.act_window">
        <field name="name">Generate DTE</field>
        <field name="res_model">dte.generate.wizard</field>
        <field name="view_mode">form</field>
        <field name="target">new</field>
        <field name="binding_model_id" ref="account.model_account_move"/>
        <field name="binding_view_types">form</field>
    </record>

</odoo>
```

**Cambios Clave:**
1. ✅ Vista ultra-simplificada
2. ✅ Mensaje claro sobre ETAPA 2
3. ✅ Solo campos esenciales
4. ✅ Sin campos computed problemáticos

---

#### Paso 4: Actualizar Staging (10 min)

```bash
# 1. Reiniciar contenedor para limpiar caché
docker-compose restart odoo

# 2. Esperar que Odoo inicie (30 segundos)
sleep 30

# 3. Actualizar módulo en staging
docker-compose exec odoo odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo_staging \
  -u l10n_cl_dte \
  --stop-after-init \
  --log-level=info \
  2>&1 | tee logs/update_wizard_minimal_staging.log
```

**Verificar Salida:**
```bash
# Buscar errores
grep -i "error\|exception\|failed" logs/update_wizard_minimal_staging.log

# Si NO hay errores, buscar éxito
grep -i "successfully\|module.*updated" logs/update_wizard_minimal_staging.log
```

---

#### Paso 5: Validar en Staging (10 min)

```bash
# 1. Iniciar Odoo en staging (modo manual para testing)
docker-compose exec odoo odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo_staging \
  --log-level=debug &

# 2. Esperar inicio
sleep 15

# 3. Verificar wizard está registrado
docker-compose exec -T db psql -U odoo -d odoo_staging -c \
  "SELECT name, model FROM ir_ui_view WHERE model='dte.generate.wizard';"

# 4. Verificar action
docker-compose exec -T db psql -U odoo -d odoo_staging -c \
  "SELECT name, res_model FROM ir_actions_act_window WHERE res_model='dte.generate.wizard';"
```

**Resultado Esperado:**
```
 name                              | model
-----------------------------------+--------------------------
 dte.generate.wizard.form          | dte.generate.wizard

 name          | res_model
---------------+----------------------
 Generate DTE  | dte.generate.wizard
```

---

#### Paso 6: Activar Botón en Vista de Factura (5 min)

**Archivo:** `views/account_move_dte_views.xml`

**Descomentar botón (líneas 11-16):**

```xml
<!-- ANTES (comentado): -->
<!-- ⭐ DESACTIVADO: Botón Professional Wizard (requiere wizard views desactivado en manifest) -->

<!-- DESPUÉS (activo): -->
<!-- Botón Professional Wizard -->
<button name="%(action_dte_generate_wizard)d"
        string="Generar DTE"
        type="action"
        class="oe_highlight"
        invisible="state != 'posted' or not dte_code"/>
```

---

#### Paso 7: Actualizar Módulo Completo en Staging (10 min)

```bash
# 1. Backup antes de cambio final
./scripts/backup_odoo.sh odoo_staging

# 2. Actualizar módulo
docker-compose exec odoo odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo_staging \
  -u l10n_cl_dte \
  --stop-after-init \
  2>&1 | tee logs/update_wizard_final_staging.log

# 3. Verificar éxito
grep -i "successfully\|module.*updated" logs/update_wizard_final_staging.log
```

---

#### Paso 8: Test Manual en Odoo UI (10 min)

1. **Acceder a staging:**
   ```
   http://localhost:8169
   Usuario: admin
   DB: odoo_staging
   ```

2. **Navegar a factura:**
   - Contabilidad → Clientes → Facturas
   - Abrir cualquier factura en estado "Posted"

3. **Abrir wizard:**
   - Click botón "Generar DTE"
   - Wizard debe abrirse sin errores

4. **Completar formulario:**
   - Seleccionar certificado (debe haber al menos 1)
   - Seleccionar CAF (debe filtrarse automáticamente)
   - Seleccionar ambiente (sandbox)

5. **Ejecutar acción:**
   - Click "Configure DTE"
   - Debe mostrar notificación de éxito
   - Revisar chatter de factura (debe tener mensaje)

**Resultado Esperado:**
- ✅ Wizard abre sin errores
- ✅ Campos se llenan correctamente
- ✅ Onchange de certificate funciona
- ✅ Action se ejecuta sin errores
- ✅ Notificación de éxito aparece
- ✅ Mensaje en chatter registrado

---

#### Paso 9: Aplicar a Producción (10 min)

**SOLO SI ETAPA 8 FUE EXITOSA**

```bash
# 1. Backup producción
./scripts/backup_odoo.sh odoo

# 2. Actualizar módulo en producción
docker-compose exec odoo odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -u l10n_cl_dte \
  --stop-after-init \
  2>&1 | tee logs/update_wizard_production.log

# 3. Validar
./scripts/validate_installation.sh odoo

# 4. Verificar tests (debe pasar 8/8)
grep "PASS" logs/validate_installation.log | wc -l
```

---

#### Paso 10: Documentar Éxito (5 min)

Actualizar `docs/PROGRESO_ETAPAS_1_2.md`:

```markdown
## 🔧 ETAPA 2: RESTAURAR WIZARD - 100% COMPLETADA ✅

### Objetivo Cumplido

Activar `dte_generate_wizard` funcionalmente con versión minimal.

### Trabajo Realizado

#### Versión Minimal Implementada ✅
- Wizard simplificado con solo campos esenciales
- Eliminados todos los métodos computed problemáticos
- Action stub funcional que valida y guarda configuración
- Vista XML ultra-simplificada
- Mensajes claros indicando que es versión ETAPA 2

#### Validación Completa ✅
- Wizard abre sin errores
- Campos relacionados funcionan correctamente
- Onchange de certificate funciona
- Action se ejecuta sin errores
- Notificaciones y mensajes en chatter correctos
- Botón activado en vista de facturas

### Resultado

**Estado:** 🟢 **100% COMPLETADO**
**Tiempo Real:** 1.5 horas
**Wizard Funcional:** SÍ ✅
**Implementación Completa:** Pospuesto para ETAPA 4

### Archivos Modificados
- `wizards/dte_generate_wizard.py` (versión minimal - 150 líneas)
- `wizards/dte_generate_wizard_views.xml` (simplificado - 60 líneas)
- `views/account_move_dte_views.xml` (botón activado - línea 11-16)

### Próximos Pasos
- ETAPA 3: Implementar reportes PDF
- ETAPA 4: Implementar generación real de DTEs en wizard
```

---

### ✅ CRITERIOS DE ÉXITO ETAPA 2

| Criterio | Estado |
|----------|--------|
| Wizard abre sin errores | ⏳ Pendiente validación |
| Campos relacionados funcionan | ⏳ Pendiente validación |
| Onchange certificate funciona | ⏳ Pendiente validación |
| Action se ejecuta | ⏳ Pendiente validación |
| Notificación aparece | ⏳ Pendiente validación |
| Mensaje en chatter | ⏳ Pendiente validación |
| Botón visible en facturas | ⏳ Pendiente validación |
| Tests 8/8 pasan | ⏳ Pendiente validación |

---

### 🚨 TROUBLESHOOTING ETAPA 2

#### Error: "Field does not exist"
```
Solución:
1. Verificar herencia de vista: inherit_id correcto
2. Revisar que campo existe en modelo
3. Limpiar caché: docker-compose restart odoo
```

#### Error: "Action not found"
```
Solución:
1. Verificar action está en .xml
2. Confirmar .xml está en __manifest__.py data
3. Actualizar lista de actions: Settings → Technical → Actions → Windows
```

#### Wizard no aparece en menú Action
```
Solución:
1. Verificar binding_model_id en action
2. Confirmar binding_view_types='form'
3. Refrescar navegador (Ctrl+F5)
```

---

<a name="etapa-3"></a>
## 🔴 ETAPA 3: REPORTES PDF

**Estado:** 🔴 PENDIENTE
**Tiempo Estimado:** 20-26 horas
**Prioridad:** 🔴 **ALTA** (documentos legales obligatorios)

### Objetivo

Implementar 2 reportes PDF:
1. `dte_invoice_report.xml` - Factura Electrónica con TED y QR
2. `dte_receipt_report.xml` - Acuse de Recibo

---

### 📄 3.1. DTE Invoice Report (16 horas)

#### Paso 1: Implementar Generación de TED (4 horas)

**TED (Timbre Electrónico Digital):** Código de barras PDF417 con datos del DTE firmados digitalmente.

**Archivo:** `models/account_move_dte.py`

**Agregar método:**

```python
def _generate_ted(self):
    """
    Generate TED (Timbre Electrónico Digital) for invoice.

    TED Structure:
    <TED version="1.0">
      <DD>
        <RE>76123456-7</RE>  <!-- Emisor RUT -->
        <TD>33</TD>           <!-- DTE Type -->
        <F>12345</F>          <!-- Folio -->
        <FE>2025-10-22</FE>   <!-- Emission Date -->
        <RR>12345678-9</RR>   <!-- Receptor RUT -->
        <RSR>Cliente SA</RSR> <!-- Receptor Name -->
        <MNT>119000</MNT>     <!-- Total Amount -->
        <IT1>Producto 1</IT1> <!-- First Item -->
        <CAF>...</CAF>        <!-- CAF XML -->
        <TSTED>2025-10-22T10:30:00</TSTED>
      </DD>
      <FRMT algoritmo="SHA1withRSA">
        [Digital Signature]
      </FRMT>
    </TED>
    """
    self.ensure_one()

    if not self.dte_folio:
        raise UserError(_('DTE Folio is required to generate TED'))

    # 1. Build DD (Document Data) XML
    dd_xml = etree.Element('DD')

    etree.SubElement(dd_xml, 'RE').text = self.company_id.vat
    etree.SubElement(dd_xml, 'TD').text = self.dte_code
    etree.SubElement(dd_xml, 'F').text = str(self.dte_folio)
    etree.SubElement(dd_xml, 'FE').text = self.invoice_date.strftime('%Y-%m-%d')
    etree.SubElement(dd_xml, 'RR').text = self.partner_id.vat
    etree.SubElement(dd_xml, 'RSR').text = self.partner_id.name[:40]
    etree.SubElement(dd_xml, 'MNT').text = str(int(self.amount_total))

    # First invoice line (item 1)
    if self.invoice_line_ids:
        etree.SubElement(dd_xml, 'IT1').text = self.invoice_line_ids[0].name[:40]

    # CAF XML
    if self.dte_caf_id and self.dte_caf_id.caf_file:
        caf_xml = base64.b64decode(self.dte_caf_id.caf_file)
        etree.SubElement(dd_xml, 'CAF').text = caf_xml.decode()

    etree.SubElement(dd_xml, 'TSTED').text = fields.Datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    # 2. Canonicalize DD
    dd_str = etree.tostring(dd_xml, method='c14n')

    # 3. Sign DD with certificate
    if not self.dte_certificate_id:
        raise UserError(_('Digital certificate required to generate TED'))

    signature = self.dte_certificate_id._sign_data(dd_str)

    # 4. Build final TED XML
    ted_xml = etree.Element('TED', version='1.0')
    ted_xml.append(dd_xml)

    frmt = etree.SubElement(ted_xml, 'FRMT', algoritmo='SHA1withRSA')
    frmt.text = base64.b64encode(signature).decode()

    # 5. Generate PDF417 barcode
    ted_str = etree.tostring(ted_xml, encoding='unicode')
    barcode_image = self._generate_pdf417(ted_str)

    # 6. Store in record
    self.write({
        'dte_ted_xml': ted_str,
        'dte_ted_barcode': barcode_image,
    })

    return ted_str
```

**Agregar campos al modelo:**

```python
dte_ted_xml = fields.Text('TED XML', readonly=True)
dte_ted_barcode = fields.Binary('TED Barcode', readonly=True)
```

---

#### Paso 2: Implementar Generación de QR Code (2 horas)

**Archivo:** `models/account_move_dte.py`

```python
def _generate_qr_code(self):
    """
    Generate QR code for DTE validation.

    QR Format (SII standard):
    URL: https://www.sii.cl/servicios/factura/electronica/docs/validate.html
    ?emisor=[RUT]&tipo=[TD]&folio=[FOLIO]&fecha=[FECHA]&monto=[MONTO]&firma=[FIRMA]
    """
    self.ensure_one()

    if not self.dte_folio:
        raise UserError(_('DTE Folio required for QR code'))

    # Build validation URL
    base_url = 'https://www.sii.cl/servicios/factura/electronica/docs/validate.html'

    params = {
        'emisor': self.company_id.vat.replace('-', ''),
        'tipo': self.dte_code,
        'folio': self.dte_folio,
        'fecha': self.invoice_date.strftime('%d-%m-%Y'),
        'monto': int(self.amount_total),
        'firma': self._get_signature_digest()[:10],  # First 10 chars
    }

    url = f"{base_url}?{'&'.join(f'{k}={v}' for k, v in params.items())}"

    # Generate QR code image
    import qrcode
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    import io
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_image = base64.b64encode(buffer.getvalue())

    self.dte_qr_image = qr_image
    return qr_image

def _get_signature_digest(self):
    """Extract signature digest from DTE XML"""
    if not self.dte_xml:
        return ''

    try:
        root = etree.fromstring(self.dte_xml.encode())
        signature = root.find('.//{http://www.w3.org/2000/09/xmldsig#}SignatureValue')
        if signature is not None:
            return signature.text[:10]
    except:
        pass

    return ''
```

**Agregar dependencia en `__manifest__.py`:**

```python
'external_dependencies': {
    'python': [
        'lxml',
        'qrcode',  # NUEVO
        'pillow',  # NUEVO (requerido por qrcode)
        ...
    ],
}
```

---

#### Paso 3: Crear QWeb Template (6 horas)

**Archivo:** `reports/dte_invoice_report.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- ══════════════════════════════════════════════════════════════════
         REPORTE FACTURA ELECTRÓNICA - DTE 33
         Formato cedible según normativa SII
         ══════════════════════════════════════════════════════════════════ -->

    <!-- Main Template -->
    <template id="report_invoice_dte_document">
        <t t-call="web.external_layout">
            <t t-set="o" t-value="o.with_context(lang=o.partner_id.lang)"/>

            <div class="page">
                <!-- ═══════════════════════════════════════════════════ -->
                <!-- HEADER: Logo + Cuadro Folio -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row">
                    <div class="col-6">
                        <!-- Logo Empresa -->
                        <img t-if="o.company_id.logo"
                             t-att-src="image_data_uri(o.company_id.logo)"
                             style="max-height: 80px;"
                             alt="Company Logo"/>

                        <!-- Datos Emisor -->
                        <div style="margin-top: 10px;">
                            <strong t-field="o.company_id.name"/><br/>
                            <span t-field="o.company_id.street"/><br/>
                            <span t-if="o.company_id.street2" t-field="o.company_id.street2"/><br/>
                            <span t-field="o.company_id.city"/>,
                            <span t-field="o.company_id.country_id.name"/><br/>
                            <strong>RUT:</strong> <span t-field="o.company_id.vat"/>
                        </div>
                    </div>

                    <div class="col-6 text-end">
                        <!-- Cuadro Folio (recuadro rojo) -->
                        <div style="border: 2px solid red; padding: 15px; display: inline-block;">
                            <h3 style="color: red; margin: 0;">
                                R.U.T.: <span t-field="o.company_id.vat"/>
                            </h3>
                            <h2 style="margin: 5px 0;">
                                FACTURA ELECTRÓNICA
                            </h2>
                            <h3 style="margin: 5px 0;">
                                N° <span t-field="o.dte_folio"/>
                            </h3>
                            <p style="margin: 5px 0; font-size: 10px;">
                                S.I.I. - <span t-if="o.dte_environment == 'sandbox'">MAULLIN</span>
                                <span t-else="">PALENA</span>
                            </p>
                        </div>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- DATOS RECEPTOR -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row mt-4">
                    <div class="col-12">
                        <table class="table table-sm table-bordered">
                            <tr>
                                <td width="20%"><strong>Señor(es):</strong></td>
                                <td><span t-field="o.partner_id.name"/></td>
                            </tr>
                            <tr>
                                <td><strong>RUT:</strong></td>
                                <td><span t-field="o.partner_id.vat"/></td>
                            </tr>
                            <tr>
                                <td><strong>Dirección:</strong></td>
                                <td><span t-field="o.partner_id.street"/></td>
                            </tr>
                            <tr>
                                <td><strong>Comuna:</strong></td>
                                <td><span t-field="o.partner_id.city"/></td>
                            </tr>
                            <tr>
                                <td><strong>Fecha Emisión:</strong></td>
                                <td><span t-field="o.invoice_date" t-options='{"widget": "date"}'/></td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- DETALLE PRODUCTOS -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row mt-4">
                    <div class="col-12">
                        <table class="table table-sm">
                            <thead>
                                <tr style="background-color: #f0f0f0;">
                                    <th>Código</th>
                                    <th>Descripción</th>
                                    <th class="text-end">Cantidad</th>
                                    <th class="text-end">Precio Unit.</th>
                                    <th class="text-end">Total</th>
                                </tr>
                            </thead>
                            <tbody>
                                <t t-foreach="o.invoice_line_ids" t-as="line">
                                    <tr>
                                        <td><span t-field="line.product_id.default_code"/></td>
                                        <td><span t-field="line.name"/></td>
                                        <td class="text-end"><span t-field="line.quantity"/></td>
                                        <td class="text-end">
                                            <span t-field="line.price_unit"
                                                  t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                        </td>
                                        <td class="text-end">
                                            <span t-field="line.price_subtotal"
                                                  t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                        </td>
                                    </tr>
                                </t>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- TOTALES -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row">
                    <div class="col-7"></div>
                    <div class="col-5">
                        <table class="table table-sm">
                            <tr>
                                <td class="text-end"><strong>Neto:</strong></td>
                                <td class="text-end">
                                    <span t-field="o.amount_untaxed"
                                          t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                </td>
                            </tr>
                            <tr>
                                <td class="text-end"><strong>IVA 19%:</strong></td>
                                <td class="text-end">
                                    <span t-field="o.amount_tax"
                                          t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                </td>
                            </tr>
                            <tr style="background-color: #f0f0f0;">
                                <td class="text-end"><strong>TOTAL:</strong></td>
                                <td class="text-end">
                                    <strong>
                                        <span t-field="o.amount_total"
                                              t-options='{"widget": "monetary", "display_currency": o.currency_id}'/>
                                    </strong>
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- TED (TIMBRE ELECTRÓNICO) -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row mt-4" t-if="o.dte_ted_barcode">
                    <div class="col-12 text-center">
                        <h5>Timbre Electrónico S.I.I.</h5>
                        <img t-att-src="image_data_uri(o.dte_ted_barcode)"
                             style="max-width: 400px;"
                             alt="TED Barcode"/>
                        <p style="font-size: 8px; margin-top: 5px;">
                            Timbre Electrónico DTE - Res. <span t-field="o.dte_folio"/>
                        </p>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- QR CODE -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row mt-2" t-if="o.dte_qr_image">
                    <div class="col-12 text-center">
                        <p style="font-size: 10px; margin-bottom: 5px;">
                            Verifique este documento en www.sii.cl
                        </p>
                        <img t-att-src="image_data_uri(o.dte_qr_image)"
                             style="max-width: 150px;"
                             alt="QR Code"/>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- FOOTER: Información Legal -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div class="row mt-4">
                    <div class="col-12 text-center" style="font-size: 9px;">
                        <p>
                            ACUSE RECIBO ELECTRÓNICO AL: <span t-field="o.company_id.email"/><br/>
                            Timbre Electrónico Verificable en www.sii.cl
                        </p>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════ -->
                <!-- CEDIBLE (Copia adicional con texto "CEDIBLE") -->
                <!-- ═══════════════════════════════════════════════════ -->
                <div style="page-break-before: always;">
                    <div class="text-center" style="margin: 20px 0;">
                        <h2 style="border: 3px solid black; padding: 10px; display: inline-block;">
                            CEDIBLE
                        </h2>
                    </div>

                    <!-- Repetir todo el contenido anterior -->
                    <t t-call="l10n_cl_dte.report_invoice_dte_document_content"/>
                </div>

            </div>
        </t>
    </template>

    <!-- Report Definition -->
    <record id="action_report_invoice_dte" model="ir.actions.report">
        <field name="name">Factura Electrónica (DTE 33)</field>
        <field name="model">account.move</field>
        <field name="report_type">qweb-pdf</field>
        <field name="report_name">l10n_cl_dte.report_invoice_dte_document</field>
        <field name="report_file">l10n_cl_dte.report_invoice_dte_document</field>
        <field name="binding_model_id" ref="account.model_account_move"/>
        <field name="binding_type">report</field>
        <field name="paperformat_id" ref="base.paperformat_us"/>
    </record>

</odoo>
```

---

#### Paso 4: Activar en __manifest__.py (2 min)

**Archivo:** `__manifest__.py`

**Descomentar línea 112:**

```python
# ANTES:
# 'reports/dte_invoice_report.xml',  # ⭐ FASE 3

# DESPUÉS:
'reports/dte_invoice_report.xml',  # ✅ ACTIVADO ETAPA 3
```

---

#### Paso 5: Instalar Dependencias (30 min)

**Archivo:** `dte-service/requirements.txt`

```txt
# Agregar:
qrcode==7.4.2
pillow==10.1.0
pdf417gen==0.7.1  # Para generar PDF417 (TED barcode)
```

**Rebuild container:**

```bash
cd /Users/pedro/Documents/odoo19
docker-compose build odoo
docker-compose restart odoo
```

---

#### Paso 6: Testing en Staging (2 horas)

```bash
# 1. Backup
./scripts/backup_odoo.sh odoo_staging

# 2. Actualizar módulo
docker-compose exec odoo odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo_staging \
  -u l10n_cl_dte \
  --stop-after-init

# 3. Test manual:
# - Abrir factura en UI
# - Click "Imprimir → Factura Electrónica"
# - Verificar PDF se genera
# - Verificar TED barcode presente
# - Verificar QR code presente
# - Verificar formato cedible (2 páginas)
```

**Checklist de Validación:**
- [ ] PDF se genera sin errores
- [ ] TED barcode visible y legible
- [ ] QR code escaneable
- [ ] Datos emisor correctos
- [ ] Datos receptor correctos
- [ ] Detalle productos completo
- [ ] Totales correctos
- [ ] Copia cedible incluida

---

### 📄 3.2. DTE Receipt Report (10 horas)

**Similar al invoice report pero para acuse de recibo.**

**Pasos:**
1. Crear QWeb template (6 horas)
2. Activar en __manifest__.py (2 min)
3. Testing (2 horas)
4. Documentación (2 horas)

**Postponer detalles hasta completar 3.1**

---

### ✅ CRITERIOS DE ÉXITO ETAPA 3

| Criterio | Estado |
|----------|--------|
| TED generation implementado | 🔴 Pendiente |
| QR code generation implementado | 🔴 Pendiente |
| QWeb template completo | 🔴 Pendiente |
| PDF se genera correctamente | 🔴 Pendiente |
| TED barcode legible | 🔴 Pendiente |
| QR code escaneable | 🔴 Pendiente |
| Formato cedible (2 páginas) | 🔴 Pendiente |
| Reporte activado en __manifest__ | 🔴 Pendiente |

---

<a name="etapa-4"></a>
## 🔴 ETAPA 4: MÉTODOS LIBRO COMPRA/VENTA

**Estado:** 🔴 PENDIENTE
**Tiempo Estimado:** 17-21.5 horas
**Prioridad:** 🔴 **ALTA**

### Objetivo

Implementar 5 métodos en `models/dte_libro.py`:
1. `action_generate_libro` (8-10h)
2. `action_send_libro` (4-6h)
3. `action_consultar_estado` (4h)
4. `action_set_draft` (30min)
5. `action_view_invoices` (1h)

### Plan Detallado

#### Paso 1: Implementar action_generate_libro (10 horas)

**Funcionalidad:** Generar XML del Libro según schema SII `EnvioLibro_v10.xsd`

**Archivo:** `models/dte_libro.py`

```python
def action_generate_libro(self):
    """
    Generate Purchase/Sales Book XML (EnvioLibro)
    according to SII schema EnvioLibro_v10.xsd
    """
    self.ensure_one()

    # 1. Validations
    if not self.move_ids:
        raise UserError(_('No invoices selected for this book'))

    if not self.company_id.vat:
        raise UserError(_('Company RUT is required'))

    # 2. Call DTE Service to generate XML
    api_key = self.env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.api_key')

    response = requests.post(
        'http://dte-service:8001/api/v1/generate_libro',
        json={
            'tipo_libro': self.tipo_libro,
            'periodo': self.periodo_mes.strftime('%Y-%m'),
            'invoices': [self._prepare_invoice_data(inv) for inv in self.move_ids],
            'company_rut': self.company_id.vat,
        },
        headers={'Authorization': f'Bearer {api_key}'},
        timeout=60
    )

    if not response.ok:
        raise UserError(_('Error generating book: %s') % response.text)

    result = response.json()

    # 3. Store XML
    self.write({
        'xml_file': result['xml_b64'],
        'xml_filename': f'libro_{self.tipo_libro}_{self.periodo_mes.strftime("%Y%m")}.xml',
        'state': 'generated',
    })

    # 4. Log success
    self.message_post(
        body=_('Book generated successfully. Ready to send to SII.')
    )

    return True

def _prepare_invoice_data(self, invoice):
    """Prepare invoice data for libro generation"""
    return {
        'dte_code': invoice.dte_code,
        'folio': invoice.dte_folio,
        'date': invoice.invoice_date.strftime('%Y-%m-%d'),
        'partner_vat': invoice.partner_id.vat,
        'partner_name': invoice.partner_id.name,
        'amount_untaxed': invoice.amount_untaxed,
        'amount_tax': invoice.amount_tax,
        'amount_total': invoice.amount_total,
    }
```

**Testing:**
```bash
# Test generation
docker-compose exec -T db psql -U odoo -d odoo_staging <<EOF
SELECT action_generate_libro() FROM dte_libro WHERE id=1;
EOF
```

---

#### Paso 2-5: Implementar métodos restantes

**Similar pattern para cada método.**

**Detalles postponidos hasta completar ETAPA 2 y 3.**

---

<a name="etapa-5"></a>
## 🟡 ETAPA 5: WIZARDS FALTANTES

**Estado:** 🔴 PENDIENTE
**Tiempo Estimado:** 24-32 horas
**Prioridad:** 🟡 **MEDIA-ALTA**

### Objetivo

Crear 4 wizards:
1. `upload_certificate_wizard` (4-6h)
2. `send_dte_batch_wizard` (6-8h)
3. `generate_consumo_folios_wizard` (10-12h)
4. `generate_libro_wizard` (4-6h)

### Plan Resumido

**Detalles completos se desarrollarán después de completar ETAPAS 2-4.**

**Patrón general por wizard:**
1. Crear modelo TransientModel (1h)
2. Implementar método de acción (2-8h según complejidad)
3. Crear vista XML (1h)
4. Activar en __manifest__.py (2min)
5. Testing en staging (1h)
6. Documentación (30min)

---

<a name="etapa-6"></a>
## 🟢 ETAPA 6: CAMPOS AUXILIARES

**Estado:** 🔴 PENDIENTE
**Tiempo Estimado:** 1.75 horas
**Prioridad:** 🟢 **BAJA**

### Objetivo

Agregar 5 campos faltantes en modelo `dte.libro`:
1. `tipo_envio` (30min)
2. `sii_status` (30min)
3. `fecha_envio` (15min)
4. `fecha_aceptacion` (15min)
5. `sii_response` (15min)

### Plan

**Archivo:** `models/dte_libro.py`

```python
# Agregar campos:
tipo_envio = fields.Selection([
    ('total', 'Total'),
    ('rectifica', 'Rectificación'),
    ('complementa', 'Complementa'),
], string='Tipo Envío', default='total', required=True)

sii_status = fields.Selection([
    ('pending', 'Pendiente'),
    ('processing', 'Procesando'),
    ('accepted', 'Aceptado'),
    ('rejected', 'Rechazado'),
    ('reparo', 'Reparo'),
], string='SII Status', readonly=True)

fecha_envio = fields.Datetime('Fecha Envío SII', readonly=True)
fecha_aceptacion = fields.Datetime('Fecha Aceptación SII', readonly=True)
sii_response = fields.Text('Respuesta SII', readonly=True)
```

**Descomentar en vistas:**
- `views/dte_libro_views.xml` líneas 58-61, 93-102

**Testing:**
```bash
# Actualizar módulo
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo_staging -u l10n_cl_dte --stop-after-init

# Verificar campos en UI
# Contabilidad → DTE Chile → Reportes SII → Libro Compra/Venta
```

---

<a name="etapa-7"></a>
## 🟡 ETAPA 7: HERENCIAS DE VISTAS

**Estado:** 🔴 PENDIENTE
**Tiempo Estimado:** 4-5 horas
**Prioridad:** 🟡 **MEDIA**

### Objetivo

Corregir herencia de vista tree de facturas para Odoo 19.

### Paso 1: Identificar Vista Correcta (1 hora)

```bash
# Consultar vistas tree de account.move en Odoo 19
docker-compose exec -T db psql -U odoo -d odoo -c \
  "SELECT id, name, xml_id FROM ir_ui_view
   WHERE model='account.move' AND type='tree'
   ORDER BY id;"
```

**Resultado Esperado:**
```
 id  |       name              |          xml_id
-----+-------------------------+---------------------------
 123 | account.move.tree       | account.view_move_tree
 ...
```

---

### Paso 2: Actualizar inherit_id (30 min)

**Archivo:** `views/account_move_dte_views.xml`

**Descomentar y corregir líneas 171-192:**

```xml
<!-- ANTES (comentado): -->
<!-- ⭐ TEMPORALMENTE DESACTIVADO: account.view_invoice_tree cambió en Odoo 19 -->

<!-- DESPUÉS (activo): -->
<record id="view_move_tree_dte" model="ir.ui.view">
    <field name="name">account.move.tree.dte</field>
    <field name="model">account.move</field>
    <field name="inherit_id" ref="account.view_move_tree"/>  <!-- ACTUALIZADO -->
    <field name="arch" type="xml">
        <xpath expr="//field[@name='state']" position="after">
            <field name="dte_status" optional="show"
                   decoration-success="dte_status == 'accepted'"
                   decoration-warning="dte_status == 'to_send'"
                   decoration-danger="dte_status == 'rejected'"/>
            <field name="dte_async_status" optional="show"/>
            <field name="dte_folio" optional="show"/>
            <field name="dte_code" optional="hide"/>
        </xpath>
    </field>
</record>
```

---

### Paso 3: Testing (1 hora)

```bash
# 1. Backup
./scripts/backup_odoo.sh odoo_staging

# 2. Actualizar
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo_staging -u l10n_cl_dte --stop-after-init

# 3. Verificar en UI:
# Contabilidad → Clientes → Facturas
# Verificar columnas: dte_status, dte_folio visibles
```

---

### Paso 4: Verificar Métodos en dte_libro_guias (2 horas)

**Archivo:** `models/dte_libro_guias.py`

**Verificar existen estos 3 métodos:**
1. `action_agregar_guias`
2. `action_generar_y_enviar`
3. `action_consultar_estado_sii`

**Si NO existen, implementar stubs:**

```python
def action_agregar_guias(self):
    """Add shipping guides from period"""
    self.ensure_one()
    # TODO: Implement in later stage
    raise UserError(_('Function not implemented yet. Coming in FASE 4.'))

def action_generar_y_enviar(self):
    """Generate and send book to SII"""
    self.ensure_one()
    # TODO: Implement
    raise UserError(_('Function not implemented yet. Coming in FASE 4.'))

def action_consultar_estado_sii(self):
    """Check book status in SII"""
    self.ensure_one()
    # TODO: Implement
    raise UserError(_('Function not implemented yet. Coming in FASE 4.'))
```

---

<a name="etapa-8"></a>
## 🟢 ETAPA 8: CONFIGURACIÓN Y LIMPIEZA

**Estado:** 🔴 PENDIENTE
**Tiempo Estimado:** 3-8 horas
**Prioridad:** 🟢 **BAJA**

### Objetivo

1. Crear action correcto para menú Configuración (3-4h)
2. Eliminar action no usado (5min)
3. Decidir sobre ai_chat_wizard (eliminar o rediseñar)

### 8.1. Menú Configuración (4 horas)

**Ver detalles completos en INVENTARIO_COMPONENTES_DESHABILITADOS.md sección 5.1**

**Resumen:**
1. Crear `ResConfigSettings` inherit
2. Agregar campos configuración DTE
3. Crear vista XML
4. Crear action correcto
5. Actualizar menú

---

### 8.2. Eliminar Actions No Usados (5 min)

**Archivo:** `views/dte_libro_guias_views.xml`

**Eliminar líneas 230-238:**

```xml
<!-- ELIMINAR: -->
<!-- ⭐ DESACTIVADO: Action no usado (botón comentado en formulario) -->
<record id="action_view_libro_guias_pickings" model="ir.actions.act_window">
    ...
</record>
```

---

### 8.3. ai_chat_wizard Decision (30 min)

**Opción A: Eliminar (RECOMENDADO)**

```bash
# 1. Eliminar archivos
rm /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/wizards/ai_chat_wizard.py
rm /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/wizards/ai_chat_wizard_views.xml

# 2. Eliminar referencia en __manifest__.py (ya está comentada)
# Línea 103 - mantener comentada o eliminar completamente
```

**Opción B: Rediseñar**
- Tiempo: 8-12 horas
- No recomendado (funcionalidad no crítica)

---

## 📊 PROGRESO GENERAL

| ETAPA | Componentes | Tiempo Est. | Prioridad | Estado |
|-------|-------------|-------------|-----------|--------|
| ETAPA 2 | 1 wizard | 1-2h | 🔴 CRÍTICA | 🟡 70% |
| ETAPA 3 | 2 reportes | 20-26h | 🔴 ALTA | 🔴 0% |
| ETAPA 4 | 5 métodos | 17-21.5h | 🔴 ALTA | 🔴 0% |
| ETAPA 5 | 4 wizards | 24-32h | 🟡 MEDIA | 🔴 0% |
| ETAPA 6 | 5 campos | 1.75h | 🟢 BAJA | 🔴 0% |
| ETAPA 7 | 2 vistas | 4-5h | 🟡 MEDIA | 🔴 0% |
| ETAPA 8 | Limpieza | 3-8h | 🟢 BAJA | 🔴 0% |
| **TOTAL** | **25 items** | **71-96h** | | **4.6%** |

---

## 🚀 ORDEN DE EJECUCIÓN RECOMENDADO

### 🔥 Sprint 1 (Crítico - 3-4 días)
1. ✅ Completar ETAPA 2 (Wizard minimal)
2. 🔴 Iniciar ETAPA 3 (Reportes PDF - documento legal)

### 🔥 Sprint 2 (Alta Prioridad - 4-5 días)
3. 🔴 Completar ETAPA 3 (Reportes)
4. 🔴 Completar ETAPA 4 (Libro Métodos - reporte obligatorio)

### 🟡 Sprint 3 (Media Prioridad - 5-6 días)
5. 🟡 ETAPA 5 - Wizard Consumo Folios (obligatorio)
6. 🟡 ETAPA 5 - Resto wizards (UX improvements)
7. 🟡 ETAPA 7 (Vistas)

### 🟢 Sprint 4 (Baja Prioridad - 1 día)
8. 🟢 ETAPA 6 (Campos auxiliares)
9. 🟢 ETAPA 8 (Configuración y limpieza)

---

## ✅ CRITERIOS DE ÉXITO FINAL

### Módulo 100% Funcional:

- [x] **15 modelos** activos ✅
- [x] **13 vistas** activas ✅
- [ ] **2 wizards** funcionales (1/2 = 50%)
- [ ] **2 reportes** PDF (0/2 = 0%)
- [ ] **21 métodos** implementados (12/21 = 57%)
- [ ] **0 campos** faltantes en vistas
- [ ] **0 botones** desactivados
- [ ] **Herencias** correctas Odoo 19

**Progreso Actual:** ~57% → **Meta:** 100%

---

**DOCUMENTO GENERADO:** 2025-10-22 23:00 UTC
**METODOLOGÍA:** Incremental con validación en staging
**PRÓXIMA ACCIÓN:** Ejecutar ETAPA 2 - Opción A (Simplificar Wizard)

---

**FIN DEL PLAN DE REACTIVACIÓN**
