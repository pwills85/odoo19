# 🔄 CORRECCIÓN ARQUITECTURA: Email DTE con Odoo Nativo

**Fecha:** 2025-10-25
**Criticidad:** 🔴 **ALTA - Corrección de enfoque arquitectónico**
**Problema Detectado:** Estábamos reinventando la rueda (creando campos IMAP custom)
**Solución:** Usar infraestructura nativa de Odoo 19 CE

---

## ⚠️ ADVERTENCIA: MI ERROR ANTERIOR

En el análisis previo (`EXPLICACION_DETALLADA_FASE1_IMAP.md`) propuse crear campos custom:

```python
# ❌ ENFOQUE INCORRECTO (reinventando la rueda)
dte_imap_host = fields.Char(...)
dte_imap_port = fields.Integer(...)
dte_imap_user = fields.Char(...)
dte_imap_password = fields.Char(...)
dte_imap_ssl = fields.Boolean(...)
```

**Problema:** Odoo 19 CE **YA TIENE** un sistema completo de email (fetchmail_server + ir_mail_server)

**Pregunta del Usuario (correcta):**
> "Entiendo que la suite base de Odoo tiene configuración de servidores de correo... ¿No deberíamos usar eso?"

**Respuesta:** ✅ **SÍ, ABSOLUTAMENTE. Tienes toda la razón.**

---

## 📚 FLUJO CORRECTO SEGÚN SII (Chile)

### **Emisión de DTEs (Ventas)**

```
1. EMPRESA genera factura en Odoo
   ↓
2. Odoo FIRMA DTE con certificado digital
   ↓
3. Odoo ENVÍA DTE al SII para validación
   POST https://palena.sii.cl/DTEWS/...
   ↓
4. SII VALIDA y retorna Track ID
   ↓
5. Odoo POLLING al SII (hasta tener resultado)
   GET /QueryEstDte (cada X minutos)
   ↓
6. SII responde: "ACEPTADO"
   ↓
7. Odoo ENVÍA EMAIL al cliente con DTE
   To: cliente@empresa.cl
   Attach: DTE_33_1234.xml
   Subject: "Factura Electrónica 33-1234"
   ↓
8. Cliente RECIBE email
   ↓
9. Cliente ACEPTA/RECHAZA DTE (8 días plazo)
   (Puede ser automático o manual)
   ↓
10. Cliente ENVÍA respuesta comercial al SII
    (Opcional: también por email al emisor)
```

### **Recepción de DTEs (Compras)**

```
1. PROVEEDOR emite DTE en su sistema
   ↓
2. PROVEEDOR envía al SII (igual que arriba)
   ↓
3. SII VALIDA y NOTIFICA a nuestra empresa:

   ┌─────────────────────────────────────┐
   │ From: dte@sii.cl                    │
   │ To: facturacion@eergygroup.cl       │
   │ Subject: DTE Recibido               │
   │ Attach: DTE_33_1234.xml             │
   └─────────────────────────────────────┘

   ↓
4. Email llega a buzón Gmail/Outlook
   ↓
5. Odoo DESCARGA email automáticamente (IMAP)
   ↓
6. Odoo PARSEA XML del DTE
   ↓
7. Odoo VALIDA estructura y montos
   ↓
8. Odoo CREA factura borrador en sistema
   ↓
9. Usuario REVISA y ACEPTA/RECHAZA
   ↓
10. Odoo ENVÍA respuesta comercial al SII
    POST /EnvioRecepcion (SOAP)
    ↓
11. SII NOTIFICA al proveedor
```

---

## 🏗️ ARQUITECTURA CORRECTA: Odoo 19 CE Nativo

### **Infraestructura Nativa de Odoo**

Odoo 19 CE tiene **2 sistemas de email separados:**

#### **1. ENVÍO (SMTP) - ir_mail_server**

**Tabla:** `ir_mail_server`

**Campos clave:**
```sql
name                 VARCHAR   "Gmail EERGYGROUP"
smtp_host            VARCHAR   "smtp.gmail.com"
smtp_port            INTEGER   587 o 465
smtp_user            VARCHAR   "facturacion@eergygroup.cl"
smtp_pass            VARCHAR   "app_password"
smtp_encryption      VARCHAR   "starttls" o "ssl"
smtp_authentication  VARCHAR   "login"
active               BOOLEAN   TRUE
```

**Uso:**
```python
# Al enviar DTE por email (después de validación SII)
template = env.ref('l10n_cl_dte.email_template_dte_invoice')
template.send_mail(invoice_id, force_send=True)

# Odoo usa automáticamente ir_mail_server configurado
```

**Configuración UI:**
```
Settings → Technical → Emails: Outgoing Mail Servers

[+] Create:
  Name: Gmail EERGYGROUP
  SMTP Server: smtp.gmail.com
  SMTP Port: 587
  Connection Security: TLS (STARTTLS)
  Username: facturacion@eergygroup.cl
  Password: [App Password de Gmail]
  [✓] Active

  [Test Connection] [Save]
```

---

#### **2. RECEPCIÓN (IMAP/POP) - fetchmail_server**

**Tabla:** `fetchmail_server`

**Campos clave:**
```sql
name                 VARCHAR   "DTE Inbox - EERGYGROUP"
server_type          VARCHAR   "imap"
server               VARCHAR   "imap.gmail.com"
port                 INTEGER   993
user                 VARCHAR   "facturacion@eergygroup.cl"
password             VARCHAR   "app_password"
is_ssl               BOOLEAN   TRUE
object_id            INTEGER   → ir.model('dte.inbox')
active               BOOLEAN   TRUE
state                VARCHAR   "draft" / "done"
```

**Uso:**
```python
# Odoo ejecuta automáticamente cada 5 minutos (scheduled action)
# No necesitas código custom, solo configurar el fetchmail_server
```

**Configuración UI:**
```
Settings → Technical → Emails: Incoming Mail Servers

[+] Create:
  Name: DTE Inbox - EERGYGROUP
  Server Type: IMAP Server
  Server Name: imap.gmail.com
  Port: 993
  SSL/TLS: [✓] Enabled
  Username: facturacion@eergygroup.cl
  Password: [App Password de Gmail]

  Create a New Record:
    Model: DTE Inbox (dte.inbox)

  [Fetch Now] [Save]
```

---

### **Scheduled Action (Cron Job) - Nativo de Odoo**

**Ubicación:** Settings → Technical → Automation → Scheduled Actions

**Scheduled Action:** `Mail: Fetchmail Service`

```
Name: Mail: Fetchmail Service
Model: fetchmail.server
Function: _fetch_mails()
Interval Number: 5
Interval Unit: Minutes
Active: ✓
```

**Comportamiento:**
- Se ejecuta cada 5 minutos automáticamente
- Recorre todos los `fetchmail_server` activos
- Descarga emails no leídos
- Procesa cada email según el `object_id` configurado
- Llama a `message_process()` del modelo destino

---

## 🔧 IMPLEMENTACIÓN CORRECTA

### **PASO 1: Hacer que dte.inbox herede mail.thread**

**Archivo:** `models/dte_inbox.py`

**Cambio actual (línea 29-33):**
```python
class DTEInbox(models.Model):
    _name = 'dte.inbox'
    _description = 'Received DTEs Inbox'
    _order = 'received_date desc'
    _inherit = [
        'mail.thread',           # ✅ YA EXISTE
        'mail.activity.mixin',   # ✅ YA EXISTE
        'dte.ai.client'
    ]
```

✅ **Ya está correcto** - El modelo YA hereda `mail.thread`

---

### **PASO 2: Implementar message_process() para procesar emails**

**Archivo:** `models/dte_inbox.py`

**Agregar método:**

```python
@api.model
def message_process(self, model, message_dict, save_original=False,
                    strip_attachments=False, thread_id=None):
    """
    Procesar emails entrantes con DTEs del SII.

    Este método es llamado automáticamente por fetchmail_server
    cuando llega un email al buzón configurado.

    Args:
        model: 'dte.inbox' (nuestro modelo)
        message_dict: Dict con datos del email
        save_original: Guardar email original
        strip_attachments: Quitar adjuntos
        thread_id: ID del registro existente (para respuestas)

    Returns:
        ID del registro dte.inbox creado
    """
    _logger.info(f"📧 Processing incoming DTE email from fetchmail")

    # 1. Extraer datos del email
    subject = message_dict.get('subject', '')
    from_email = message_dict.get('from', '')
    attachments = message_dict.get('attachments', [])

    _logger.info(f"   From: {from_email}")
    _logger.info(f"   Subject: {subject}")
    _logger.info(f"   Attachments: {len(attachments)}")

    # 2. Validar que sea del SII
    if 'dte@sii.cl' not in from_email.lower():
        _logger.warning(f"   ⚠️ Email NOT from SII, ignoring")
        return False

    # 3. Procesar cada adjunto XML
    for attachment in attachments:
        filename = attachment.get('fname', '')
        content = attachment.get('content', b'')

        # Solo procesar archivos XML
        if not filename.lower().endswith('.xml'):
            continue

        try:
            # Decodificar contenido
            if isinstance(content, bytes):
                xml_content = content.decode('utf-8')
            else:
                xml_content = content

            # Parsear DTE usando eergy-services
            dte_data = self._parse_dte_from_email(xml_content)

            if dte_data:
                # Crear registro dte.inbox
                record = self._create_inbox_record(dte_data)
                _logger.info(f"   ✅ Created DTE inbox record: {record.name}")

                # Retornar ID del primer registro creado
                return record.id

        except Exception as e:
            _logger.error(f"   ❌ Error processing attachment {filename}: {e}")
            continue

    return False


def _parse_dte_from_email(self, xml_content):
    """
    Parsear DTE XML usando servicio eergy-services.

    Args:
        xml_content: XML del DTE (string)

    Returns:
        Dict con datos parseados del DTE
    """
    try:
        # Llamar a eergy-services para parsear
        dte_service_url = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_url',
            'http://odoo-eergy-services:8001'
        )

        response = requests.post(
            f"{dte_service_url}/api/v1/reception/parse_dte",
            json={'xml_content': xml_content},
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return result.get('data')

        return None

    except Exception as e:
        _logger.error(f"DTE parsing failed: {e}")
        return None
```

---

### **PASO 3: Eliminar cron_check_inbox() custom**

**Archivo:** `models/dte_inbox.py`

**Líneas 776-826 (método `cron_check_inbox()`):**

```python
# ❌ ELIMINAR ESTE MÉTODO COMPLETO
# Ya no es necesario porque fetchmail_server lo hace automáticamente

# @api.model
# def cron_check_inbox(self):
#     """... código custom de polling IMAP ..."""
#     pass
```

**Razón:**
- fetchmail_server hace polling automático cada 5 minutos
- No necesitamos código custom
- Más robusto y mantenible

---

### **PASO 4: NO crear campos IMAP en res.company**

**Archivo:** `models/res_company_dte.py`

**❌ NO AGREGAR:**
```python
# NO CREAR ESTOS CAMPOS (estaban propuestos en análisis anterior)
# dte_imap_host = ...
# dte_imap_port = ...
# dte_imap_user = ...
# dte_imap_password = ...
# dte_imap_ssl = ...
```

**✅ USAR:** Configuración nativa de Odoo en `fetchmail_server`

---

## 📋 CONFIGURACIÓN PASO A PASO

### **A. Configurar Servidor de ENVÍO (SMTP)**

**Navegación:**
```
Settings → General Settings → Discuss → Custom Email Servers
→ Outgoing Mail Servers
→ [Create]
```

**Formulario:**
```
┌────────────────────────────────────────────────┐
│ Outgoing Mail Server                           │
├────────────────────────────────────────────────┤
│ Description:        Gmail EERGYGROUP           │
│                                                │
│ SMTP Server:        smtp.gmail.com             │
│ SMTP Port:          587                        │
│ Connection Security: TLS (STARTTLS)            │
│ Username:           facturacion@eergygroup.cl  │
│ Password:           [••••••••••••••]           │
│                                                │
│ Priority:           10                         │
│ [✓] Active                                    │
│                                                │
│ [Test Connection] → Should show "Success"      │
│ [Save]                                         │
└────────────────────────────────────────────────┘
```

**Validación:**
```bash
# En Odoo shell
>>> server = env['ir.mail_server'].search([], limit=1)
>>> server.test_smtp_connection()
# Esperado: True
```

---

### **B. Configurar Servidor de RECEPCIÓN (IMAP)**

**Navegación:**
```
Settings → Technical → Emails: Incoming Mail Servers
→ [Create]
```

**Formulario:**
```
┌────────────────────────────────────────────────┐
│ Incoming Mail Server                           │
├────────────────────────────────────────────────┤
│ Name:               DTE Inbox EERGYGROUP       │
│                                                │
│ Server Type:        IMAP Server                │
│ Server Name:        imap.gmail.com             │
│ Port:               993                        │
│ [✓] SSL/TLS                                   │
│                                                │
│ Username:           facturacion@eergygroup.cl  │
│ Password:           [••••••••••••••]           │
│                                                │
│ Allowed Senders:    dte@sii.cl                 │
│                                                │
│ Create a New Record:                           │
│   Model: DTE Inbox (dte.inbox)                 │
│   [Search More...]                             │
│                                                │
│ Actions to Perform on Incoming Mails:          │
│   [✓] Keep Original                           │
│   [ ] Keep Attachments                         │
│                                                │
│ Last Fetch Date:    2025-10-25 10:00:00       │
│                                                │
│ [✓] Active                                    │
│                                                │
│ [Fetch Now] → Should fetch emails immediately  │
│ [Save]                                         │
└────────────────────────────────────────────────┘
```

**Opciones Avanzadas:**
```python
# script field (dejar vacío para comportamiento por defecto)
# O custom si necesitas filtrado adicional:

# Ejemplo: Solo emails con adjuntos XML
if message.get_content_type() == 'multipart/mixed':
    for part in message.walk():
        if part.get_filename() and part.get_filename().endswith('.xml'):
            return True
return False
```

---

### **C. Verificar Scheduled Action**

**Navegación:**
```
Settings → Technical → Automation → Scheduled Actions
→ Buscar: "Mail: Fetchmail Service"
```

**Verificar configuración:**
```
┌────────────────────────────────────────────────┐
│ Scheduled Action: Mail: Fetchmail Service      │
├────────────────────────────────────────────────┤
│ Model:              fetchmail.server           │
│ Execute every:      5 Minutes                  │
│ Number of Calls:    -1 (unlimited)             │
│ Next Execution:     2025-10-25 10:05:00       │
│                                                │
│ [✓] Active                                    │
│                                                │
│ [Run Manually] [Save]                          │
└────────────────────────────────────────────────┘
```

**⚠️ IMPORTANTE:** Este scheduled action viene pre-configurado en Odoo. NO modificar.

---

## 🔄 FLUJO COMPLETO (Arquitectura Correcta)

```
┌─────────────────────────────────────────────────────────────────────┐
│ RECEPCIÓN AUTOMÁTICA DE DTES (Odoo Nativo)                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ 1. PROVEEDOR emite DTE → SII valida                                │
│                                                                     │
│ 2. SII envía email:                                                 │
│    From: dte@sii.cl                                                 │
│    To: facturacion@eergygroup.cl                                    │
│    Attach: DTE_33_1234.xml                                          │
│    ↓                                                                │
│ 3. Email llega a Gmail                                              │
│    ↓                                                                │
│ 4. SCHEDULED ACTION (cada 5 min):                                   │
│    "Mail: Fetchmail Service"                                        │
│    ├─> Busca fetchmail_server activos                              │
│    ├─> Conecta a imap.gmail.com:993                                │
│    ├─> Login: facturacion@eergygroup.cl                            │
│    ├─> Busca emails no leídos                                      │
│    └─> Para cada email:                                            │
│        ├─> Verifica sender: dte@sii.cl ✓                           │
│        ├─> Extrae adjuntos XML                                     │
│        └─> Llama: dte.inbox.message_process()                      │
│            ↓                                                        │
│ 5. message_process():                                               │
│    ├─> Parsea XML (llama a eergy-services)                         │
│    ├─> Extrae: folio, RUT, monto, fecha                            │
│    ├─> Valida estructura                                           │
│    ├─> Crea registro dte.inbox                                     │
│    └─> Marca email como leído                                      │
│    ↓                                                                │
│ 6. REGISTRO CREADO:                                                 │
│    dte.inbox:                                                       │
│    - DTE 33 - 1234                                                  │
│    - PROVEEDOR SPA                                                  │
│    - $150,000                                                       │
│    - State: New                                                     │
│    ↓                                                                │
│ 7. USUARIO REVISA en UI:                                            │
│    DTE → Bandeja de Entrada                                         │
│    ↓                                                                │
│ 8. USUARIO ACEPTA/RECHAZA:                                          │
│    [Validar] → action_validate()                                    │
│    [Crear Factura] → action_create_invoice()                        │
│    ↓                                                                │
│ 9. RESPUESTA AL SII:                                                │
│    POST /EnvioRecepcion (SOAP)                                      │
│    ↓                                                                │
│ 10. SII NOTIFICA al proveedor                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✅ VENTAJAS DEL ENFOQUE NATIVO

| Aspecto | Custom IMAP | Odoo Nativo | Ganancia |
|---------|-------------|-------------|----------|
| **Configuración** | Código Python | UI intuitiva | ✅ Más fácil |
| **Mantenimiento** | Custom code | Odoo estándar | ✅ Menos bugs |
| **Monitoreo** | Logs custom | UI built-in | ✅ Mejor visibilidad |
| **Testing** | Script manual | Botón "Fetch Now" | ✅ Más rápido |
| **Scheduled Action** | Crear desde cero | Pre-configurado | ✅ Cero config |
| **Multi-empresa** | Código complejo | Soporte nativo | ✅ Automático |
| **Seguridad** | Custom encryption | Odoo security | ✅ Más robusto |
| **Upgrades** | Migrar código | Compatible | ✅ Futuro-proof |

---

## 📝 CHECKLIST DE MIGRACIÓN

### **Cambios a Realizar**

- [ ] **Implementar `message_process()` en dte.inbox**
- [ ] **Implementar `_parse_dte_from_email()` helper**
- [ ] **Eliminar método `cron_check_inbox()` custom** (líneas 776-826)
- [ ] **NO crear campos IMAP en res.company**
- [ ] **Configurar ir_mail_server (SMTP) en UI**
- [ ] **Configurar fetchmail_server (IMAP) en UI**
- [ ] **Verificar scheduled action activo**
- [ ] **Probar con email de prueba**
- [ ] **Documentar configuración para usuario**

---

## 🎯 CONCLUSIÓN

### **Corrección del Enfoque:**

❌ **ANTES (Incorrecto):**
```
Crear campos IMAP custom en res.company
→ Código custom de polling
→ Reinventar la rueda
```

✅ **AHORA (Correcto):**
```
Usar fetchmail_server nativo de Odoo
→ Implementar message_process()
→ Seguir estándares de Odoo
```

### **Respuesta a tu Pregunta:**

> "¿No deberíamos usar el sistema de correo de Odoo?"

✅ **SÍ, ABSOLUTAMENTE**

Tu instinto fue correcto. Odoo 19 CE tiene:
1. **ir_mail_server** para ENVÍO (SMTP)
2. **fetchmail_server** para RECEPCIÓN (IMAP)
3. **Scheduled Action** automático cada 5 min
4. **mail.thread** infrastructure para procesamiento

**NO necesitamos** crear campos IMAP custom ni cron jobs custom.

---

**Firma Digital:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CORRECCIÓN DE ARQUITECTURA COMPLETADA
 EJECUTADO POR: Claude Code AI (Sonnet 4.5)
 FECHA: 2025-10-25
 AGRADECIMIENTO: Usuario por cuestionar el enfoque incorrecto
 RESULTADO: ✅ Arquitectura corregida siguiendo estándares Odoo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
