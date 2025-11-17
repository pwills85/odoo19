# ROUTING EMAIL → AI MICROSERVICE: COMPLETE FLOW

**Autor:** EERGYGROUP - Ing. Pedro Troncoso Willz
**Fecha:** 2025-10-25
**Sprint:** 4 - DTE Reception + AI Validation
**Propósito:** Documentar flujo completo de enrutamiento desde recepción email hasta procesamiento AI

---

## 📋 TABLA DE CONTENIDOS

1. [Pregunta del Usuario](#pregunta-del-usuario)
2. [Respuesta Ejecutiva](#respuesta-ejecutiva)
3. [Arquitectura Visual](#arquitectura-visual)
4. [Flujo Detallado (10 Pasos)](#flujo-detallado-10-pasos)
5. [Código Crítico](#código-crítico)
6. [Configuración Requerida](#configuración-requerida)
7. [Patrón de Herencia (Clave del Routing)](#patrón-de-herencia-clave-del-routing)
8. [Endpoints AI Service](#endpoints-ai-service)
9. [Diagrama de Secuencia](#diagrama-de-secuencia)
10. [Estado Actual vs. Estado Objetivo](#estado-actual-vs-estado-objetivo)

---

## ❓ PREGUNTA DEL USUARIO

> **"la pregunta es quien o como se enrutan los mensajes que llegan a nuestro sistema de recepcion de dtes para que microservicio IA lo procede??"**

**Contexto adicional:**
- Usuario revisó que Odoo 19 CE tiene infraestructura nativa de email (`fetchmail_server`, `ir_mail_server`)
- Se descartó crear campos IMAP personalizados (dte_imap_host, etc.)
- Se debe usar patrón nativo de Odoo para recepción de emails
- AI Service ya está implementado y funcionando (FastAPI en http://ai-service:8002)

---

## ✅ RESPUESTA EJECUTIVA

**El enrutamiento NO es automático al recibir el email.** El flujo es:

1. **Email llega → Odoo fetchmail crea registro dte.inbox** (automático, cada 5 min)
2. **Usuario presiona botón "Validate"** en la UI (manual)
3. **`action_validate()` llama a `self.validate_received_dte()`** (heredado de `dte.ai.client`)
4. **Mixin `dte.ai.client` hace request HTTP a AI Service** (`POST /api/ai/validate`)
5. **AI Service procesa y retorna resultados** (confianza, anomalías, recomendación)
6. **Resultados se guardan en campos del registro dte.inbox**

**Patrón clave:** **HERENCIA DE MIXIN**
```python
class DTEInbox(models.Model):
    _name = 'dte.inbox'
    _inherit = [
        'mail.thread',        # ← Recibe emails
        'dte.ai.client'       # ← Tiene métodos AI
    ]
```

---

## 🏗️ ARQUITECTURA VISUAL

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SII (Servicio Impuestos)                      │
│                                                                       │
│  dte@sii.cl envía email con XML adjunto a facturacion@eergygroup.cl │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 1. Email con DTE XML
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Gmail IMAP (imap.gmail.com:993)                    │
│                                                                       │
│  Buzón: facturacion@eergygroup.cl                                    │
│  Carpeta: INBOX                                                       │
│  Filtro: De dte@sii.cl                                               │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 2. Polling cada 5 minutos
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Odoo 19 CE - Scheduled Action (ir.cron)                 │
│                                                                       │
│  Nombre: "Mail: Fetchmail Service"                                   │
│  Modelo: fetchmail.server                                            │
│  Método: fetch_mail()                                                │
│  Intervalo: 5 minutos                                                │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 3. Descarga email + adjuntos XML
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Odoo 19 CE - fetchmail_server.fetch_mail()              │
│                                                                       │
│  1. Conecta a IMAP                                                   │
│  2. Descarga emails no leídos de dte@sii.cl                         │
│  3. Para cada email:                                                 │
│     - Extrae adjuntos XML                                            │
│     - Llama a dte.inbox.message_process()  ← AQUÍ ENTRA             │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 4. Crea registro dte.inbox
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│            Odoo 19 CE - dte.inbox.message_process()                  │
│                  (MÉTODO A IMPLEMENTAR - PENDIENTE)                  │
│                                                                       │
│  def message_process(self, msg_dict):                                │
│      # 1. Extraer adjuntos XML del email                             │
│      # 2. Parsear XML (extraer RUT, folio, montos)                  │
│      # 3. Crear registro dte.inbox con estado 'new'                 │
│      # 4. Retornar ID del registro creado                            │
│                                                                       │
│  Estado del registro: 'new' (esperando validación)                   │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 5. Registro visible en UI
                                │    (estado: 'new', botón "Validate")
                                │
                     ┌──────────┴──────────┐
                     │   USUARIO HUMANO    │
                     │                     │
                     │  Presiona botón     │
                     │  "Validate"         │
                     └──────────┬──────────┘
                                │
                                │ 6. Click en "Validate"
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│            Odoo 19 CE - dte.inbox.action_validate()                  │
│              (IMPLEMENTADO - dte_inbox.py:281-508)                   │
│                                                                       │
│  FASE 1: NATIVE VALIDATION (sin AI)                                  │
│    ✓ DTEStructureValidator (estructura XML, campos obligatorios)    │
│    ✓ TEDValidator (firma digital SII)                               │
│    ✓ RUT validation (Módulo 11)                                     │
│    ✓ Montos coherencia (neto + IVA = total)                         │
│                                                                       │
│  Si falla → STOP (estado: 'error')                                   │
│  Si pasa → Continúa a FASE 2                                         │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 7. Native validation PASSED
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│            Odoo 19 CE - dte.inbox.action_validate()                  │
│                          FASE 2: AI VALIDATION                        │
│                                                                       │
│  # Obtener historial del proveedor                                   │
│  vendor_history = self._get_vendor_history()                         │
│                                                                       │
│  # ← AQUÍ ESTÁ EL ROUTING A AI SERVICE                              │
│  ai_result = self.validate_received_dte(  # Heredado de mixin       │
│      dte_data=dte_data,                                              │
│      vendor_history=vendor_history                                   │
│  )                                                                    │
│                                                                       │
│  # Guardar resultados AI en registro                                 │
│  self.ai_validated = True                                            │
│  self.ai_confidence = ai_result['confidence']                        │
│  self.ai_recommendation = ai_result['recommendation']                │
│  self.ai_anomalies = ai_result['anomalies']                          │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 8. Llama método heredado
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│         Odoo 19 CE - dte.ai.client.validate_received_dte()          │
│              (MIXIN - dte_ai_client.py:357-447)                      │
│                                                                       │
│  def validate_received_dte(self, dte_data, vendor_history):         │
│      url, api_key, timeout = self._get_ai_service_config()          │
│                                                                       │
│      payload = {                                                     │
│          'dte_data': dte_data,                                       │
│          'history': vendor_history,                                  │
│          'company_id': self.env.company.id,                          │
│          'mode': 'reception'                                         │
│      }                                                                │
│                                                                       │
│      # ← HTTP REQUEST A AI SERVICE                                  │
│      response = requests.post(                                       │
│          f'{url}/api/ai/validate',                                   │
│          json=payload,                                               │
│          headers={'Authorization': f'Bearer {api_key}'},             │
│          timeout=timeout                                             │
│      )                                                                │
│                                                                       │
│      # Retornar resultado parseado                                   │
│      return {                                                         │
│          'valid': result['recommendation'] != 'reject',              │
│          'confidence': result['confidence'],                         │
│          'anomalies': result['errors'],                              │
│          'warnings': result['warnings'],                             │
│          'recommendation': 'accept' | 'review' | 'reject'            │
│      }                                                                │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 9. HTTP POST request
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│              AI SERVICE (FastAPI - Port 8002)                        │
│                  http://ai-service:8002/api/ai/validate              │
│                                                                       │
│  Recibe:                                                             │
│  {                                                                    │
│    "dte_data": {                                                     │
│      "tipo_dte": 33,                                                 │
│      "folio": 12345,                                                 │
│      "monto_total": 1190000,                                         │
│      "rut_emisor": "76123456-7",                                     │
│      ...                                                              │
│    },                                                                 │
│    "history": [...],  # Historial proveedor                          │
│    "mode": "reception"                                               │
│  }                                                                    │
│                                                                       │
│  Procesa con Claude 3.5 Sonnet:                                      │
│  ✓ Análisis semántico de descripciones                              │
│  ✓ Detección anomalías vs historial                                  │
│  ✓ Validación coherencia montos                                      │
│  ✓ Detección patrones sospechosos                                    │
│                                                                       │
│  Retorna:                                                             │
│  {                                                                    │
│    "recommendation": "accept" | "review" | "reject",                 │
│    "confidence": 85.5,  # 0-100                                      │
│    "errors": [],        # Anomalías graves                           │
│    "warnings": [...]    # Anomalías menores                          │
│  }                                                                    │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                │ 10. Resultado AI retorna a Odoo
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│            Odoo 19 CE - dte.inbox (registro actualizado)             │
│                                                                       │
│  Campos actualizados:                                                │
│  - state: 'validated' | 'matched' | 'error'                          │
│  - ai_validated: True                                                │
│  - ai_confidence: 85.5                                               │
│  - ai_recommendation: 'accept'                                       │
│  - ai_anomalies: '' (ninguna anomalía detectada)                     │
│  - processed_date: 2025-10-25 14:30:00                              │
│                                                                       │
│  Usuario ve notificación:                                            │
│  ✅ DTE Validated Successfully                                       │
│  Native validation: ✅ PASSED                                        │
│  TED validation: ✅ PASSED                                           │
│  AI confidence: 85.5% (accept)                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 FLUJO DETALLADO (10 PASOS)

### **PASO 1: Email DTE llega a Gmail**
- **Actor:** SII (Servicio de Impuestos Internos)
- **Remitente:** `dte@sii.cl`
- **Destinatario:** `facturacion@eergygroup.cl` (configurado en empresa)
- **Contenido:**
  - Asunto: `Notificación DTE Folio 12345`
  - Adjunto: `DTE_33_12345.xml` (documento tributario electrónico)
- **Ubicación:** Gmail IMAP server (`imap.gmail.com:993`)

**Código SII (ejemplo XML adjunto):**
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
  <Documento ID="F33T12345">
    <Encabezado>
      <IdDoc>
        <TipoDTE>33</TipoDTE>
        <Folio>12345</Folio>
        <FchEmis>2025-10-25</FchEmis>
      </IdDoc>
      <Emisor>
        <RUTEmisor>76123456-7</RUTEmisor>
        <RznSoc>PROVEEDOR SPA</RznSoc>
      </Emisor>
      <Totales>
        <MntNeto>1000000</MntNeto>
        <MntIVA>190000</MntIVA>
        <MntTotal>1190000</MntTotal>
      </Totales>
    </Encabezado>
    <TED>...</TED>
  </Documento>
</DTE>
```

---

### **PASO 2: Odoo Scheduled Action ejecuta fetchmail**
- **Frecuencia:** Cada 5 minutos (configurable)
- **Modelo:** `ir.cron`
- **Registro:** `"Mail: Fetchmail Service"` (nativo de Odoo)
- **Método ejecutado:** `fetchmail.server.fetch_mail()`

**Configuración cron (SQL):**
```sql
SELECT
    name,
    active,
    interval_number,
    interval_type,
    model_id,
    code
FROM ir_cron
WHERE name = 'Mail: Fetchmail Service';

-- Resultado:
-- name: Mail: Fetchmail Service
-- active: true
-- interval_number: 5
-- interval_type: minutes
-- code: model.fetch_mail()
```

---

### **PASO 3: fetchmail_server descarga emails**
- **Tabla:** `fetchmail_server` (configurado en Settings → Technical → Incoming Mail Servers)
- **Conexión:**
  - `server_type`: `imap`
  - `server`: `imap.gmail.com`
  - `port`: `993`
  - `is_ssl`: `True`
  - `user`: `facturacion@eergygroup.cl`
  - `password`: `<app-specific-password>` (OAuth2 o contraseña aplicación)

**Filtro IMAP:**
```python
# Filtro configurado en fetchmail_server
# Solo descarga emails de dte@sii.cl
search_criteria = [
    'UNSEEN',  # Solo no leídos
    'FROM "dte@sii.cl"'  # Solo del SII
]
```

**Lógica Odoo nativa (pseudocódigo):**
```python
# odoo/addons/fetchmail/models/fetchmail.py (NATIVO)
def fetch_mail(self):
    for server in self:
        imap = server.connect()

        # Buscar emails según criterios
        emails = imap.search(criteria)

        for email_id in emails:
            # Descargar email completo
            msg = imap.fetch(email_id, '(RFC822)')

            # Parsear mensaje
            msg_dict = {
                'subject': msg['subject'],
                'from': msg['from'],
                'date': msg['date'],
                'body': msg['body'],
                'attachments': [...]  # XML adjunto aquí
            }

            # ← LLAMADA AL MODELO CONFIGURADO
            # En nuestro caso: dte.inbox
            self.object_id.message_process(msg_dict)

            # Marcar como leído
            imap.store(email_id, '+FLAGS', '\\Seen')
```

---

### **PASO 4: message_process() crea registro dte.inbox**
- **Método:** `dte.inbox.message_process(msg_dict)`
- **Estado:** **PENDIENTE DE IMPLEMENTACIÓN** ⚠️
- **Archivo:** `/addons/localization/l10n_cl_dte/models/dte_inbox.py`

**Implementación requerida:**
```python
# dte_inbox.py (A IMPLEMENTAR)

@api.model
def message_process(self, msg_dict, custom_values=None):
    """
    Procesa email entrante desde fetchmail_server.

    Llamado automáticamente por fetchmail cuando llega email de dte@sii.cl.

    Args:
        msg_dict (dict): Diccionario con datos del email
            - subject: str
            - from: str
            - date: datetime
            - body: str (HTML o texto)
            - attachments: list of tuples (nombre, contenido_base64)

        custom_values (dict, optional): Valores adicionales

    Returns:
        int: ID del registro dte.inbox creado
    """
    _logger.info(f"📧 Processing incoming DTE email: {msg_dict.get('subject')}")

    # 1. Extraer adjuntos XML
    xml_attachments = []
    for name, content_base64 in msg_dict.get('attachments', []):
        if name.lower().endswith('.xml'):
            # Decodificar base64
            import base64
            xml_string = base64.b64decode(content_base64).decode('utf-8')
            xml_attachments.append({
                'filename': name,
                'content': xml_string
            })

    if not xml_attachments:
        _logger.warning("No XML attachments found in email")
        return False

    # 2. Parsear primer XML (normalmente solo hay uno)
    xml_data = xml_attachments[0]

    try:
        # Usar parser nativo (ya existe en libs/xml_parser.py)
        from odoo.addons.l10n_cl_dte.libs.xml_parser import DTEParser

        parsed = DTEParser.parse(xml_data['content'])

        # 3. Buscar proveedor por RUT
        partner = self.env['res.partner'].search([
            ('vat', '=', parsed['rut_emisor'])
        ], limit=1)

        # 4. Crear registro dte.inbox
        vals = {
            'name': f"DTE {parsed['tipo_dte']}-{parsed['folio']}",
            'dte_type': str(parsed['tipo_dte']),
            'folio': parsed['folio'],
            'fecha_emision': parsed['fecha_emision'],
            'emisor_rut': parsed['rut_emisor'],
            'emisor_name': parsed['razon_social_emisor'],
            'monto_total': parsed['monto_total'],
            'monto_neto': parsed['monto_neto'],
            'monto_iva': parsed['monto_iva'],
            'monto_exento': parsed.get('monto_exento', 0),
            'partner_id': partner.id if partner else False,
            'raw_xml': xml_data['content'],
            'parsed_data': json.dumps(parsed),
            'state': 'new',  # ← Estado inicial
            'received_date': fields.Datetime.now(),
            'reception_method': 'imap',  # vs 'api' o 'manual'
        }

        # Si custom_values tiene valores, mergear
        if custom_values:
            vals.update(custom_values)

        # Crear registro
        inbox_record = self.create(vals)

        # Post mensaje en chatter
        inbox_record.message_post(
            body=_('DTE received via email from %s') % msg_dict.get('from'),
            subject=msg_dict.get('subject')
        )

        _logger.info(
            f"✅ DTE inbox record created: ID={inbox_record.id}, "
            f"Folio={inbox_record.folio}, Partner={partner.name if partner else 'Unknown'}"
        )

        return inbox_record.id

    except Exception as e:
        _logger.error(f"Error processing DTE email: {e}", exc_info=True)

        # Crear registro en estado 'error' para no perder el email
        error_record = self.create({
            'name': f"Error: {msg_dict.get('subject', 'Sin asunto')}",
            'state': 'error',
            'validation_errors': str(e),
            'raw_xml': xml_data['content'] if xml_attachments else False,
            'received_date': fields.Datetime.now()
        })

        return error_record.id
```

---

### **PASO 5: Usuario ve registro en UI (estado 'new')**
- **Vista:** Tree view de `dte.inbox`
- **Ubicación:** Facturación → Recepción DTEs → Bandeja de Entrada
- **Estado visible:** `new` (badge naranja)
- **Botón disponible:** `"Validate"` (botón primario azul)

**Vista XML (dte_inbox_views.xml):**
```xml
<record id="view_dte_inbox_tree" model="ir.ui.view">
    <field name="name">dte.inbox.tree</field>
    <field name="model">dte.inbox</field>
    <field name="arch" type="xml">
        <list string="DTEs Recibidos">
            <field name="name"/>
            <field name="folio"/>
            <field name="emisor_name"/>
            <field name="monto_total" sum="Total"/>
            <field name="fecha_emision"/>
            <field name="state"
                   decoration-warning="state == 'new'"
                   decoration-success="state in ('validated', 'matched')"
                   decoration-danger="state == 'error'"
                   widget="badge"/>
        </list>
    </field>
</record>
```

---

### **PASO 6: Usuario presiona "Validate"**
- **Acción:** Click en botón `"Validate"` en form view
- **Método llamado:** `dte.inbox.action_validate()` (línea 281)
- **Ubicación:** `/addons/localization/l10n_cl_dte/models/dte_inbox.py`

**Botón XML:**
```xml
<button name="action_validate"
        type="object"
        string="Validate"
        class="btn-primary"
        invisible="state != 'new'"/>
```

---

### **PASO 7: FASE 1 - Native Validation (sin AI)**
- **Método:** `action_validate()` líneas 305-374
- **Validadores:**
  1. `DTEStructureValidator` (estructura XML, campos obligatorios)
  2. `TEDValidator` (firma digital SII - Timbre Electrónico)
  3. RUT validation (Módulo 11 checksum)
  4. Montos coherencia (neto + IVA = total)

**Código (dte_inbox.py:324-366):**
```python
# 1.1. Structure validation
structure_result = DTEStructureValidator.validate_dte(
    dte_data=dte_data,
    xml_string=self.raw_xml
)

if not structure_result['valid']:
    errors.extend(structure_result['errors'])
    _logger.warning(f"❌ Native structure validation FAILED: {len(errors)} errors")
else:
    _logger.info("✅ Native structure validation PASSED")

# 1.2. TED validation
if self.raw_xml:
    ted_result = TEDValidator.validate_ted(
        xml_string=self.raw_xml,
        dte_data=dte_data
    )

    if ted_result['valid']:
        self.ted_validated = True
        _logger.info("✅ TED validation PASSED")
    else:
        errors.extend(ted_result['errors'])

# Update native validation flag
self.native_validation_passed = len(errors) == 0

# Si falla validación nativa → STOP
if not self.native_validation_passed:
    self.validation_errors = '\n'.join(errors)
    self.state = 'error'
    self.processed_date = fields.Datetime.now()

    raise UserError(
        _('Native validation failed:\n\n%s') % '\n'.join(errors)
    )
```

**Si falla fase 1 → STOP, no se llama a AI Service (ahorro de costos)**

---

### **PASO 8: FASE 2 - AI Validation (semántica y anomalías)**
- **Método:** `action_validate()` líneas 376-415
- **Clave:** Llama a `self.validate_received_dte()` que está **heredado de mixin**

**Código (dte_inbox.py:380-414):**
```python
try:
    # Get vendor history for anomaly detection
    vendor_history = self._get_vendor_history()

    # AI validation (usa método heredado de dte.ai.client)
    # ← ESTE ES EL ROUTING A AI SERVICE
    ai_result = self.validate_received_dte(
        dte_data=dte_data,
        vendor_history=vendor_history
    )

    # Save AI results
    self.ai_validated = True
    self.ai_confidence = ai_result.get('confidence', 0)
    self.ai_recommendation = ai_result.get('recommendation', 'review')

    ai_anomalies = ai_result.get('anomalies', [])
    ai_warnings = ai_result.get('warnings', [])

    if ai_anomalies:
        self.ai_anomalies = '\n'.join(ai_anomalies)
        warnings.extend(ai_anomalies)

    warnings.extend(ai_warnings)

    _logger.info(
        f"✅ AI validation completed: confidence={self.ai_confidence:.1f}%, "
        f"recommendation={self.ai_recommendation}"
    )

except Exception as e:
    _logger.warning(f"AI validation failed (non-blocking): {e}")
    # AI validation failure is non-blocking
    self.ai_validated = False
    self.ai_recommendation = 'review'
    warnings.append(f"AI validation unavailable: {str(e)[:50]}")
```

**Importante:** AI validation es **non-blocking**. Si falla, el DTE igual se procesa.

---

### **PASO 9: Mixin dte.ai.client hace HTTP request**
- **Archivo:** `/addons/localization/l10n_cl_dte/models/dte_ai_client.py`
- **Método:** `validate_received_dte()` líneas 357-447
- **Endpoint:** `POST http://ai-service:8002/api/ai/validate`

**Código completo (dte_ai_client.py:357-447):**
```python
@api.model
def validate_received_dte(self, dte_data, vendor_history=None):
    """
    Validación AI de DTE recibido (detección anomalías semánticas).

    SPRINT 4 FEATURE: Usa AI para detectar anomalías en DTEs recibidos.

    Detecta:
    - Montos inusualmente altos/bajos para este proveedor
    - Descripciones sospechosas
    - Fechas incoherentes
    - Patrones anómalos vs historial

    Args:
        dte_data (dict): Datos del DTE recibido
        vendor_history (list, optional): Historial DTEs del proveedor

    Returns:
        dict: {
            'valid': bool,
            'confidence': float (0-100),
            'anomalies': list of str,
            'warnings': list of str,
            'recommendation': str ('accept', 'review', 'reject')
        }
    """
    url, api_key, timeout = self._get_ai_service_config()

    if not api_key:
        # Fallback graceful: aceptar sin AI
        return {
            'valid': True,
            'confidence': 0,
            'anomalies': [],
            'warnings': ['AI Service no configurado - validación manual requerida'],
            'recommendation': 'review'
        }

    try:
        payload = {
            'dte_data': dte_data,
            'history': vendor_history or [],
            'company_id': self.env.company.id,
            'mode': 'reception'  # Indicar que es DTE recibido (no emitido)
        }

        # ← HTTP REQUEST A AI SERVICE
        response = requests.post(
            f'{url}/api/ai/validate',  # Reusar endpoint validate
            json=payload,
            headers={'Authorization': f'Bearer {api_key}'},
            timeout=timeout
        )

        if response.status_code == 200:
            result = response.json()

            # Mapear respuesta a formato recepción
            recommendation_map = {
                'send': 'accept',      # Si es válido para enviar, es válido para recibir
                'review': 'review',
                'reject': 'reject'
            }

            return {
                'valid': result.get('recommendation') != 'reject',
                'confidence': result.get('confidence', 0),
                'anomalies': result.get('errors', []),
                'warnings': result.get('warnings', []),
                'recommendation': recommendation_map.get(
                    result.get('recommendation'),
                    'review'
                )
            }
        else:
            # Fallback graceful
            return {
                'valid': True,
                'confidence': 0,
                'anomalies': [],
                'warnings': [f'AI Service error: {response.status_code}'],
                'recommendation': 'review'
            }

    except Exception as e:
        _logger.error("AI received DTE validation error: %s", str(e))
        return {
            'valid': True,
            'confidence': 0,
            'anomalies': [],
            'warnings': [f'AI error: {str(e)[:50]}'],
            'recommendation': 'review'
        }
```

**Payload enviado:**
```json
{
  "dte_data": {
    "tipo_dte": "33",
    "folio": "12345",
    "fecha_emision": "2025-10-25",
    "rut_emisor": "76123456-7",
    "razon_social_emisor": "PROVEEDOR SPA",
    "monto_total": 1190000.0,
    "monto_neto": 1000000.0,
    "monto_iva": 190000.0,
    "monto_exento": 0.0
  },
  "history": [
    {
      "fecha_emision": "2025-09-15",
      "monto_total": 1150000.0,
      "tipo_dte": "33"
    },
    {
      "fecha_emision": "2025-08-10",
      "monto_total": 980000.0,
      "tipo_dte": "33"
    }
  ],
  "company_id": 1,
  "mode": "reception"
}
```

---

### **PASO 10: AI Service procesa con Claude 3.5 Sonnet**
- **Service:** FastAPI corriendo en Docker container `ai-service`
- **Puerto:** 8002
- **Endpoint:** `POST /api/ai/validate`
- **Modelo:** Claude 3.5 Sonnet (vía Anthropic API)
- **Ubicación código:** `/ai-service/app/routes/ai_analytics.py`

**Análisis AI (pseudocódigo):**
```python
# ai-service/app/routes/ai_analytics.py

@router.post("/api/ai/validate")
async def validate_dte(request: DTEValidationRequest):
    """
    Valida DTE usando Claude 3.5 Sonnet.

    Análisis:
    1. Coherencia semántica de descripciones
    2. Anomalías de montos vs historial proveedor
    3. Fechas incoherentes (fines de semana, festivos)
    4. Patrones sospechosos (redondeos exactos, duplicados)
    """

    # 1. Preparar contexto para Claude
    context = f"""
    Eres experto en validación de facturas electrónicas chilenas.

    DTE recibido:
    - Tipo: {request.dte_data.tipo_dte} (33 = Factura Electrónica)
    - Folio: {request.dte_data.folio}
    - Emisor: {request.dte_data.razon_social_emisor} ({request.dte_data.rut_emisor})
    - Fecha: {request.dte_data.fecha_emision}
    - Monto Total: ${request.dte_data.monto_total:,.0f}
    - Monto Neto: ${request.dte_data.monto_neto:,.0f}
    - IVA: ${request.dte_data.monto_iva:,.0f}

    Historial del proveedor (últimos 3 meses):
    {json.dumps(request.history, indent=2)}

    Analiza:
    1. ¿El monto es coherente con el historial del proveedor?
    2. ¿La fecha es sospechosa (fin de semana, festivo)?
    3. ¿Los montos tienen patrones anómalos?
    4. ¿Hay duplicados de folio?

    Retorna JSON:
    {{
      "recommendation": "accept" | "review" | "reject",
      "confidence": 0-100,
      "errors": ["anomalías graves"],
      "warnings": ["anomalías menores"]
    }}
    """

    # 2. Llamar a Claude API
    response = await anthropic_client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        temperature=0.0,  # Determinístico
        messages=[{
            "role": "user",
            "content": context
        }]
    )

    # 3. Parsear respuesta
    result = json.loads(response.content[0].text)

    # 4. Validación adicional estadística
    if len(request.history) >= 3:
        # Calcular z-score del monto
        amounts = [h.monto_total for h in request.history]
        avg = statistics.mean(amounts)
        stdev = statistics.stdev(amounts)

        current_amount = request.dte_data.monto_total
        z_score = abs((current_amount - avg) / stdev)

        if z_score > 3:  # Muy anómalo
            result['warnings'].append(
                f"Monto {z_score:.1f} desviaciones estándar del promedio"
            )
            result['confidence'] = min(result['confidence'], 70)

    # 5. Retornar
    return result
```

**Respuesta AI Service:**
```json
{
  "recommendation": "accept",
  "confidence": 85.5,
  "errors": [],
  "warnings": [
    "Monto 3.2% superior al promedio del proveedor"
  ]
}
```

---

## 💻 CÓDIGO CRÍTICO

### **1. Herencia de dte.inbox (CLAVE)**

**Archivo:** `/addons/localization/l10n_cl_dte/models/dte_inbox.py:29-37`

```python
class DTEInbox(models.Model):
    """
    Bandeja de entrada para DTEs recibidos.

    Hereda de:
    - mail.thread: Para recibir emails vía fetchmail
    - mail.activity.mixin: Para tareas y recordatorios
    - dte.ai.client: Para integración con AI Service ← CLAVE DEL ROUTING
    """
    _name = 'dte.inbox'
    _description = 'Received DTEs Inbox'
    _order = 'received_date desc'
    _inherit = [
        'mail.thread',           # ← Habilita message_process()
        'mail.activity.mixin',
        'dte.ai.client'          # ← Provee validate_received_dte()
    ]
```

**Sin esta herencia, NO funcionaría el routing a AI Service.**

---

### **2. Configuración AI Service (ir.config_parameter)**

**Tabla:** `ir_config_parameter`

```sql
-- Insertar configuración AI Service
INSERT INTO ir_config_parameter (key, value) VALUES
('dte.ai_service_url', 'http://ai-service:8002'),
('dte.ai_service_api_key', 'eergygroup-ai-key-2025'),
('dte.ai_service_timeout', '10');

-- Verificar
SELECT key, value FROM ir_config_parameter WHERE key LIKE 'dte.ai%';
```

**Método getter (dte_ai_client.py:33-52):**
```python
@api.model
def _get_ai_service_config(self):
    """
    Obtiene configuración de AI Service desde parámetros del sistema.

    Returns:
        tuple: (url, api_key, timeout)
    """
    ICP = self.env['ir.config_parameter'].sudo()

    url = ICP.get_param(
        'dte.ai_service_url',
        default='http://ai-service:8002'
    )

    api_key = ICP.get_param('dte.ai_service_api_key', default='')

    timeout = int(ICP.get_param('dte.ai_service_timeout', default='10'))

    return url, api_key, timeout
```

---

### **3. Configuración fetchmail_server**

**Tabla:** `fetchmail_server`

```sql
-- Crear servidor IMAP para recepción DTEs
INSERT INTO fetchmail_server (
    name,
    server_type,
    is_ssl,
    server,
    port,
    user,
    password,
    object_id,  -- res.model.id de 'dte.inbox'
    state,
    priority
) VALUES (
    'DTE SII Reception',
    'imap',
    true,
    'imap.gmail.com',
    993,
    'facturacion@eergygroup.cl',
    '<app-specific-password>',
    (SELECT id FROM ir_model WHERE model = 'dte.inbox'),
    'done',
    5
);
```

**Interfaz UI:** Settings → Technical → Incoming Mail Servers → Create

---

### **4. Método message_process() a implementar**

**Archivo:** `/addons/localization/l10n_cl_dte/models/dte_inbox.py` (AGREGAR)

```python
@api.model
def message_process(self, msg_dict, custom_values=None):
    """
    Procesa email entrante desde fetchmail_server.

    IMPLEMENTACIÓN REQUERIDA para completar routing.

    Ver documentación completa en PASO 4 arriba.
    """
    # Ver código completo en sección PASO 4
    pass  # TODO: Implementar
```

---

## ⚙️ CONFIGURACIÓN REQUERIDA

### **A. Configurar fetchmail_server (UI)**

1. **Ir a:** Settings → Technical → Email → Incoming Mail Servers
2. **Click:** Create
3. **Completar:**
   - **Name:** `DTE SII Reception`
   - **Server Type:** IMAP Server
   - **SSL/TLS:** ✅ Yes
   - **Server:** `imap.gmail.com`
   - **Port:** `993`
   - **Username:** `facturacion@eergygroup.cl`
   - **Password:** `<contraseña-aplicación-gmail>`
   - **Create a New Record:**
     - **Model:** `dte.inbox`
   - **Actions to Perform on Incoming Mails:**
     - ☑ Keep original email
     - ☐ Delete original email
     - ☐ Mark as read
4. **Filtro (Advanced):**
   - **From Filter:** `dte@sii.cl`
5. **Click:** Test & Confirm
6. **Click:** Fetch Now (para probar manualmente)

**Resultado:** Emails de `dte@sii.cl` serán descargados y procesados automáticamente cada 5 minutos.

---

### **B. Configurar AI Service (ir.config_parameter)**

**Opción 1: SQL directo**
```sql
INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date) VALUES
('dte.ai_service_url', 'http://ai-service:8002', 2, NOW(), 2, NOW()),
('dte.ai_service_api_key', 'eergygroup-ai-key-2025', 2, NOW(), 2, NOW()),
('dte.ai_service_timeout', '10', 2, NOW(), 2, NOW());
```

**Opción 2: Python shell**
```python
# Desde Odoo shell (docker-compose exec odoo odoo shell -d TEST)
ICP = env['ir.config_parameter'].sudo()

ICP.set_param('dte.ai_service_url', 'http://ai-service:8002')
ICP.set_param('dte.ai_service_api_key', 'eergygroup-ai-key-2025')
ICP.set_param('dte.ai_service_timeout', '10')

# Verificar
print(ICP.get_param('dte.ai_service_url'))
# Output: http://ai-service:8002
```

**Opción 3: UI (Developer mode)**
```
Settings → Technical → Parameters → System Parameters → Create

Key: dte.ai_service_url
Value: http://ai-service:8002

Key: dte.ai_service_api_key
Value: eergygroup-ai-key-2025

Key: dte.ai_service_timeout
Value: 10
```

---

### **C. Verificar Scheduled Action (ir.cron)**

```sql
-- Verificar que cron de fetchmail esté activo
SELECT
    id,
    name,
    active,
    interval_number,
    interval_type,
    nextcall,
    numbercall,
    priority
FROM ir_cron
WHERE name LIKE '%Fetchmail%';

-- Si no existe o está inactivo:
UPDATE ir_cron SET active = true WHERE name = 'Mail: Fetchmail Service';
```

**UI:** Settings → Technical → Automation → Scheduled Actions → Mail: Fetchmail Service

---

## 🔗 PATRÓN DE HERENCIA (CLAVE DEL ROUTING)

### **¿Por qué funciona el routing?**

**Python Multiple Inheritance (MRO - Method Resolution Order):**

```python
class DTEInbox(models.Model):
    _inherit = ['mail.thread', 'mail.activity.mixin', 'dte.ai.client']

    def action_validate(self):
        # Llama a método que NO está definido en DTEInbox
        ai_result = self.validate_received_dte(...)
        #               ^^^^^^^^^^^^^^^^^^^^^^
        #               ¿Dónde está este método?
```

**Respuesta:** En `dte.ai.client` (mixin heredado)

**MRO (Method Resolution Order):**
```python
# Python busca métodos en este orden:
DTEInbox.__mro__
# Output:
(
    <class 'odoo.addons.l10n_cl_dte.models.dte_inbox.DTEInbox'>,  # 1. Clase actual
    <class 'odoo.addons.l10n_cl_dte.models.dte_ai_client.DTEAIClient'>,  # 2. Mixin AI
    <class 'odoo.addons.mail.models.mail_thread.MailThread'>,  # 3. Mail thread
    <class 'odoo.addons.mail.models.mail_activity_mixin.MailActivityMixin'>,  # 4. Activity
    <class 'odoo.models.BaseModel'>,  # 5. Base Odoo
    ...
)
```

**Cuando se llama `self.validate_received_dte()`, Python:**
1. Busca en `DTEInbox` → ❌ No está
2. Busca en `DTEAIClient` → ✅ ENCONTRADO (línea 357)
3. Ejecuta método de mixin
4. Mixin hace HTTP request a AI Service

**Ventajas de este patrón:**
- ✅ **Separación de responsabilidades:** `dte.inbox` maneja lógica de negocio, `dte.ai.client` maneja integración AI
- ✅ **Reusabilidad:** Otros modelos pueden heredar `dte.ai.client` (ej: `account.move` para facturas emitidas)
- ✅ **Testeable:** Se puede mockear `validate_received_dte()` en tests
- ✅ **Mantenible:** Cambios en AI Service solo afectan mixin, no toda la aplicación

---

## 🌐 ENDPOINTS AI SERVICE

### **1. Validación DTE (recepción y emisión)**

**Endpoint:** `POST /api/ai/validate`

**Request:**
```json
{
  "dte_data": {
    "tipo_dte": "33",
    "folio": "12345",
    "fecha_emision": "2025-10-25",
    "rut_emisor": "76123456-7",
    "razon_social_emisor": "PROVEEDOR SPA",
    "monto_total": 1190000.0,
    "monto_neto": 1000000.0,
    "monto_iva": 190000.0
  },
  "history": [],
  "company_id": 1,
  "mode": "reception"
}
```

**Response:**
```json
{
  "recommendation": "accept",
  "confidence": 85.5,
  "errors": [],
  "warnings": ["Monto superior al promedio"]
}
```

---

### **2. PO Matching**

**Endpoint:** `POST /api/ai/reception/match_po`

**Request:**
```json
{
  "dte_data": {
    "partner_id": 123,
    "partner_vat": "76123456-7",
    "total_amount": 1190000.0,
    "date": "2025-10-25",
    "lines": [...]
  },
  "pending_pos": [
    {
      "id": 45,
      "name": "PO00123",
      "partner_name": "PROVEEDOR SPA",
      "amount_total": 1200000.0,
      "lines": [...]
    }
  ],
  "company_id": 1
}
```

**Response:**
```json
{
  "matched_po_id": 45,
  "confidence": 92.3,
  "reasoning": "Proveedor coincide, monto dentro de tolerancia 1%, fecha coherente",
  "line_matches": [
    {"dte_line": 0, "po_line": 0, "confidence": 95.0}
  ]
}
```

---

### **3. Sugerencia de Proyecto (analítica)**

**Endpoint:** `POST /api/ai/analytics/suggest_project`

**Request:**
```json
{
  "partner_id": 123,
  "partner_vat": "76123456-7",
  "partner_name": "PROVEEDOR SPA",
  "invoice_lines": [
    {
      "description": "Materiales eléctricos obra Santiago Centro",
      "quantity": 100,
      "price_unit": 10000.0
    }
  ],
  "company_id": 1,
  "available_projects": [
    {"id": 10, "name": "Proyecto Santiago Centro", "code": "SC2025"},
    {"id": 11, "name": "Proyecto Expansión Norte", "code": "EN2025"}
  ]
}
```

**Response:**
```json
{
  "project_id": 10,
  "project_name": "Proyecto Santiago Centro",
  "confidence": 88.7,
  "reasoning": "Descripción menciona explícitamente 'obra Santiago Centro', coincide con proyecto SC2025"
}
```

---

## 📊 DIAGRAMA DE SECUENCIA

```
┌─────┐  ┌─────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  ┌────────┐
│ SII │  │Gmail│  │  Odoo    │  │ dte.     │  │  Mixin  │  │   AI   │
│     │  │IMAP │  │fetchmail │  │ inbox    │  │ai.client│  │Service │
└──┬──┘  └──┬──┘  └────┬─────┘  └────┬─────┘  └────┬────┘  └───┬────┘
   │        │          │             │             │           │
   │ 1. Send email     │             │             │           │
   │  (DTE XML)        │             │             │           │
   ├────────>│         │             │             │           │
   │        │          │             │             │           │
   │        │  2. Poll IMAP          │             │           │
   │        │  (every 5 min)         │             │           │
   │        │<─────────┤             │             │           │
   │        │          │             │             │           │
   │        │  3. Download email     │             │           │
   │        ├─────────>│             │             │           │
   │        │          │             │             │           │
   │        │          │ 4. message_process()      │           │
   │        │          ├────────────>│             │           │
   │        │          │             │             │           │
   │        │          │  5. Create record         │           │
   │        │          │  (state='new')            │           │
   │        │          │<────────────┤             │           │
   │        │          │             │             │           │
   │        │          │             │ [WAIT FOR USER VALIDATION]
   │        │          │             │             │           │
   │        │          │             │ 6. action_validate()    │
   │        │          │             │<──USER                  │
   │        │          │             │             │           │
   │        │          │             │ 7. Native validation    │
   │        │          │             │ (Structure, TED, RUT)   │
   │        │          │             │             │           │
   │        │          │             │ 8. validate_received_dte()
   │        │          │             ├────────────>│           │
   │        │          │             │             │           │
   │        │          │             │             │ 9. POST   │
   │        │          │             │             ├──────────>│
   │        │          │             │             │ /api/ai/  │
   │        │          │             │             │ validate  │
   │        │          │             │             │           │
   │        │          │             │             │ 10. AI    │
   │        │          │             │             │ analysis  │
   │        │          │             │             │ (Claude)  │
   │        │          │             │             │           │
   │        │          │             │             │ 11. Result│
   │        │          │             │             │<──────────┤
   │        │          │             │ 12. Return  │           │
   │        │          │             │<────────────┤           │
   │        │          │             │             │           │
   │        │          │             │ 13. Update record       │
   │        │          │             │ (ai_validated=True)     │
   │        │          │             │             │           │
   │        │          │             │ 14. Notify user         │
   │        │          │             ├──────>USER             │
   │        │          │             │ "DTE validated"         │
```

---

## 🎯 ESTADO ACTUAL vs. ESTADO OBJETIVO

### **Estado Actual (❌ INCOMPLETO)**

| Componente | Estado | Completitud | Blocker |
|------------|--------|-------------|---------|
| `fetchmail_server` configurado | ❌ No | 0% | Falta config UI |
| `message_process()` implementado | ❌ No | 0% | Método no existe |
| `dte.ai.client` mixin | ✅ Sí | 100% | - |
| `action_validate()` | ✅ Sí | 100% | - |
| AI Service `/api/ai/validate` | ✅ Sí | 100% | - |
| AI Service `/api/ai/reception/match_po` | ✅ Sí | 100% | - |
| Configuración `ir.config_parameter` | ❌ No | 0% | Falta insertar keys |
| Tests de integración | ❌ No | 0% | Falta implementar |

**BLOCKERS CRÍTICOS:**
1. ⛔ `message_process()` no implementado → Emails NO se procesan automáticamente
2. ⛔ `fetchmail_server` no configurado → Emails NO se descargan
3. ⛔ `ir.config_parameter` no configurado → AI Service NO se puede conectar

---

### **Estado Objetivo (✅ COMPLETO)**

| Componente | Estado | Acción Requerida |
|------------|--------|------------------|
| `fetchmail_server` configurado | ✅ Sí | Configurar en UI (Settings → Incoming Mail Servers) |
| `message_process()` implementado | ✅ Sí | Agregar método a `dte_inbox.py` (ver código PASO 4) |
| `ir.config_parameter` | ✅ Sí | Insertar 3 keys (url, api_key, timeout) |
| Tests de integración | ✅ Sí | Crear `tests/test_dte_inbox_reception.py` |

**Flujo completo funcionando:**
1. Email llega a Gmail cada vez que SII envía DTE
2. Odoo descarga automáticamente cada 5 minutos
3. `message_process()` crea registro `dte.inbox` en estado `new`
4. Usuario valida en UI
5. AI Service analiza y retorna resultados
6. Registro se actualiza con confianza AI y recomendación

---

## ✅ PRÓXIMOS PASOS (IMPLEMENTACIÓN)

### **Paso 1: Implementar `message_process()`**
```bash
# Editar archivo
vi /addons/localization/l10n_cl_dte/models/dte_inbox.py

# Agregar método (ver código completo en PASO 4)
```

### **Paso 2: Configurar `ir.config_parameter`**
```sql
-- Conectar a base de datos
docker-compose exec db psql -U odoo -d TEST

-- Insertar configuración AI
INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date) VALUES
('dte.ai_service_url', 'http://ai-service:8002', 2, NOW(), 2, NOW()),
('dte.ai_service_api_key', 'eergygroup-ai-key-2025', 2, NOW(), 2, NOW()),
('dte.ai_service_timeout', '10', 2, NOW(), 2, NOW());

-- Verificar
SELECT key, value FROM ir_config_parameter WHERE key LIKE 'dte.ai%';
```

### **Paso 3: Configurar `fetchmail_server` (UI)**
```
1. Odoo UI → Settings → Activate Developer Mode
2. Settings → Technical → Email → Incoming Mail Servers
3. Create:
   - Name: DTE SII Reception
   - Server Type: IMAP Server
   - SSL/TLS: Yes
   - Server: imap.gmail.com
   - Port: 993
   - Username: facturacion@eergygroup.cl
   - Password: <app-password>
   - Model: dte.inbox
   - From Filter: dte@sii.cl
4. Test & Confirm
5. Fetch Now (manual test)
```

### **Paso 4: Reiniciar Odoo**
```bash
docker-compose restart odoo

# Verificar logs
docker-compose logs -f odoo | grep -i "fetchmail\|dte.inbox"
```

### **Paso 5: Test End-to-End**
```bash
# 1. Enviar email de prueba simulando SII
# (desde otra cuenta Gmail a facturacion@eergygroup.cl con XML adjunto)

# 2. Esperar 5 minutos o forzar fetch manual
# UI: Incoming Mail Servers → DTE SII Reception → Fetch Now

# 3. Verificar registro creado
# UI: Facturación → Recepción DTEs → Bandeja de Entrada
# Debería aparecer registro nuevo en estado 'new'

# 4. Validar manualmente
# Click en registro → Validate

# 5. Verificar logs AI
docker-compose logs -f ai-service | grep "validate"

# 6. Verificar resultado en UI
# Campos deberían tener valores:
# - ai_validated: True
# - ai_confidence: 85.5
# - ai_recommendation: accept
```

---

## 📌 CONCLUSIONES

### **Respuesta a pregunta del usuario:**

> **"la pregunta es quien o como se enrutan los mensajes que llegan a nuestro sistema de recepcion de dtes para que microservicio IA lo procede??"**

**Respuesta completa:**

1. **NO hay enrutamiento automático email → AI.** La AI se invoca DESPUÉS de validación nativa.

2. **Flujo de enrutamiento:**
   ```
   Email (SII)
     → Gmail IMAP
     → Odoo fetchmail (automático cada 5 min)
     → message_process() crea registro (automático)
     → Usuario presiona "Validate" (MANUAL)
     → action_validate() ejecuta validación nativa (automático)
     → Si pasa nativa → llama validate_received_dte() (automático)
     → Mixin hace HTTP request a AI Service (automático)
     → AI Service procesa con Claude (automático)
     → Resultados vuelven a Odoo (automático)
   ```

3. **Patrón clave:** **Herencia de mixin `dte.ai.client`**
   - `dte.inbox` hereda de `dte.ai.client`
   - Herencia provee método `validate_received_dte()`
   - Método hace HTTP request a AI Service
   - Usa configuración de `ir.config_parameter`

4. **Componentes que falta implementar:**
   - ⛔ `message_process()` en `dte.inbox`
   - ⛔ Configurar `fetchmail_server` en UI
   - ⛔ Insertar `ir.config_parameter` (AI Service URL + API key)

5. **Una vez implementado:**
   - ✅ DTEs llegarán automáticamente a bandeja de entrada
   - ✅ Usuario validará manualmente (botón "Validate")
   - ✅ AI se invocará automáticamente durante validación
   - ✅ Resultados AI se guardarán en registro

---

**Documento creado:** 2025-10-25
**Autor:** EERGYGROUP - Ing. Pedro Troncoso Willz
**Sprint:** 4 - DTE Reception + AI Validation
**Referencias:**
- `CORRECCION_ARQUITECTURA_EMAIL_DTE_ODOO_NATIVO.md`
- `EXPLICACION_DETALLADA_FASE1_IMAP.md`
- `ANALISIS_ARQUITECTURA_RECEPCION_DTES.md`
- `/addons/localization/l10n_cl_dte/models/dte_inbox.py`
- `/addons/localization/l10n_cl_dte/models/dte_ai_client.py`
