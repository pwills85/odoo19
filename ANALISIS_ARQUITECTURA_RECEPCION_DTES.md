# 🔍 ANÁLISIS DE ARQUITECTURA: Recepción de DTEs

**Fecha:** 2025-10-25
**Objetivo:** Entender arquitectura actual de recepción de DTEs y sus implicaciones para migración
**Analista:** Claude Code AI (Senior Solution Architect)
**Criticidad:** 🔴 **ALTA - Afecta decisión sobre campo dte_email en partners**

---

## 📊 RESUMEN EJECUTIVO

```
┌─────────────────────────────────────────────────────────────────────┐
│ ARQUITECTURA DE RECEPCIÓN DE DTES - ESTADO ACTUAL                  │
├─────────────────────────────────────────────────────────────────────┤
│ Método Principal:  IMAP Email Polling (cron job cada 1 hora)       │
│ Método Secundario: Descarga directa desde SII                      │
│ Método Terciario:  Upload manual de XML                            │
│                                                                     │
│ Componentes Involucrados:                                          │
│   ✅ Odoo (Cron Job + Model dte.inbox)                            │
│   ✅ odoo-eergy-services (IMAP Client + Parsers)                  │
│   ⚠️  ai-service (Validación semántica - opcional)                │
│                                                                     │
│ PROBLEMA CRÍTICO DETECTADO:                                        │
│   ❌ Campos IMAP NO EXISTEN en res.company                        │
│   ❌ Cron job FALLARÁ al intentar acceder a campos inexistentes   │
│                                                                     │
│ DECISIÓN REQUERIDA:                                                 │
│   ¿Campo dte_email en partners ES NECESARIO?                       │
│   Respuesta: ⚠️ SÍ, pero CON MATICES (ver análisis abajo)        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ ARQUITECTURA ACTUAL (DIAGRAMA)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RECEPCIÓN DE DTES                                   │
│                                                                             │
│  ┌──────────────┐                                                           │
│  │   SII        │                                                           │
│  │   (dte@...)  │                                                           │
│  └──────┬───────┘                                                           │
│         │ Envía DTE XML por email                                           │
│         ▼                                                                    │
│  ┌──────────────────────────────┐                                           │
│  │ BUZÓN EMAIL EMPRESA          │  ← ⚠️ CONFIGURACIÓN CRÍTICA               │
│  │ (Gmail/IMAP configurado)     │     dte_imap_host                         │
│  │                              │     dte_imap_port                         │
│  │ To: facturacion@empresa.cl   │     dte_imap_user ← ⚠️ NO EXISTE EN BD   │
│  │ From: dte@sii.cl             │     dte_imap_password ← ⚠️ NO EXISTE     │
│  │ Attach: DTE_33_1234.xml      │     dte_imap_ssl                          │
│  └──────┬───────────────────────┘                                           │
│         │                                                                    │
│         │ Polling cada 1 hora (Cron Job)                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────┐                                           │
│  │ ODOO - Cron Job              │                                           │
│  │ dte.inbox.cron_check_inbox() │                                           │
│  │                              │                                           │
│  │ 1. Lee config IMAP de company│                                           │
│  │ 2. Llama a eergy-services    │                                           │
│  │ 3. Recibe DTEs parseados     │                                           │
│  │ 4. Crea registros dte.inbox  │                                           │
│  └──────┬───────────────────────┘                                           │
│         │ POST /api/v1/reception/check_inbox                                │
│         ▼                                                                    │
│  ┌──────────────────────────────┐                                           │
│  │ ODOO-EERGY-SERVICES (FastAPI)│                                           │
│  │                              │                                           │
│  │ IMAPClient:                  │                                           │
│  │ 1. Conecta a IMAP            │                                           │
│  │ 2. Busca emails de dte@sii.cl│                                           │
│  │ 3. Descarga XMLs adjuntos    │                                           │
│  │ 4. Parsea XML → JSON         │                                           │
│  │ 5. Valida estructura         │                                           │
│  │ 6. Retorna DTEs válidos      │                                           │
│  └──────┬───────────────────────┘                                           │
│         │ JSON Response con DTEs                                            │
│         ▼                                                                    │
│  ┌──────────────────────────────┐                                           │
│  │ ODOO - dte.inbox             │                                           │
│  │                              │                                           │
│  │ Para cada DTE recibido:      │                                           │
│  │ 1. Busca proveedor por RUT   │                                           │
│  │ 2. Crea registro nuevo       │                                           │
│  │ 3. Valida (Native + AI)      │                                           │
│  │ 4. Match con PO (AI)         │                                           │
│  │ 5. Crea factura draft        │                                           │
│  └──────────────────────────────┘                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔑 FLUJO DETALLADO

### **FASE 1: Configuración IMAP (res.company)**

**Ubicación:** Odoo → Configuración → Empresas → Mi Empresa

**Campos Requeridos (❌ FALTAN - DEBEN CREARSE):**

```python
# En res_company_dte.py - CAMPOS FALTANTES

dte_imap_host = fields.Char(
    string='IMAP Host',
    default='imap.gmail.com',
    help='Servidor IMAP para recepción de DTEs.\\n\\n'
         'Ejemplos:\\n'
         '  • Gmail: imap.gmail.com\\n'
         '  • Outlook: outlook.office365.com\\n'
         '  • Yahoo: imap.mail.yahoo.com\\n'
         '  • Otro: servidor.empresa.cl'
)

dte_imap_port = fields.Integer(
    string='IMAP Port',
    default=993,
    help='Puerto IMAP.\\n\\n'
         '  • 993: IMAP con SSL (recomendado)\\n'
         '  • 143: IMAP sin SSL'
)

dte_imap_user = fields.Char(
    string='IMAP User',
    help='Usuario (email) para autenticación IMAP.\\n\\n'
         'Ejemplo: facturacion@empresa.cl\\n\\n'
         '⚠️ IMPORTANTE:\\n'
         'Este es el buzón donde SII envía los DTEs recibidos.\\n'
         'Debe ser el email registrado en el SII como email de intercambio.'
)

dte_imap_password = fields.Char(
    string='IMAP Password',
    help='Contraseña o App Password para autenticación IMAP.\\n\\n'
         '📌 GMAIL: Requiere "App Password" (no contraseña normal)\\n'
         '   1. Activar 2FA en cuenta Google\\n'
         '   2. Generar App Password en seguridad\\n'
         '   3. Usar ese password aquí\\n\\n'
         '📌 OUTLOOK: Puede usar contraseña normal\\n\\n'
         '⚠️ SEGURIDAD: Se almacena encriptado en BD'
)

dte_imap_ssl = fields.Boolean(
    string='Use SSL',
    default=True,
    help='Usar conexión SSL/TLS segura.\\n\\n'
         'Recomendado: SIEMPRE activado para seguridad.'
)
```

**Estado Actual:**
- ❌ **Campos NO EXISTEN en res.company**
- ⚠️ **Cron job referencia estos campos (líneas 789-793 de dte_inbox.py)**
- 🔴 **BLOQUEANTE: Cron job fallará con AttributeError**

**Acción Requerida:**
✅ **CREAR campos IMAP en res_company_dte.py (PRIORIDAD P0)**

---

### **FASE 2: Cron Job de Polling (cada 1 hora)**

**Ubicación:** `models/dte_inbox.py:776-826`

**Función:** `cron_check_inbox()`

**Lógica:**

```python
@api.model
def cron_check_inbox(self):
    """
    Cron job to check email inbox for new DTEs.
    Runs every 1 hour.
    """
    # 1. Lee configuración IMAP de la empresa
    company = self.env.company

    imap_config = {
        'host': company.dte_imap_host or 'imap.gmail.com',  # ❌ Campo NO existe
        'port': company.dte_imap_port or 993,               # ❌ Campo NO existe
        'user': company.dte_imap_user,                      # ❌ Campo NO existe
        'password': company.dte_imap_password,              # ❌ Campo NO existe
        'use_ssl': company.dte_imap_ssl,                    # ❌ Campo NO existe
        'sender_filter': 'dte@sii.cl',                      # ✅ Hardcoded OK
        'unread_only': True,                                # ✅ Hardcoded OK
    }

    # 2. Valida credenciales
    if not imap_config['user'] or not imap_config['password']:
        _logger.warning("IMAP credentials not configured")
        return

    # 3. Llama al servicio eergy-services
    dte_service_url = 'http://odoo-eergy-services:8001'

    response = requests.post(
        f"{dte_service_url}/api/v1/reception/check_inbox",
        json=imap_config,
        params={'company_rut': company.vat},
        timeout=120
    )

    # 4. Procesa respuesta
    if response.status_code == 200:
        result = response.json()

        # Crea registros dte.inbox
        for dte_data in result.get('dtes', []):
            self._create_inbox_record(dte_data)
```

**Estado:**
- ✅ Lógica correcta
- ❌ **Campos IMAP faltantes bloquean ejecución**
- ✅ Llamada a eergy-services OK

---

### **FASE 3: Servicio eergy-services (IMAP Client)**

**Ubicación:** `odoo-eergy-services/routes/reception.py:71-191`

**Endpoint:** `POST /api/v1/reception/check_inbox`

**Input:**
```json
{
  "host": "imap.gmail.com",
  "port": 993,
  "user": "facturacion@empresa.cl",
  "password": "app_password_here",
  "use_ssl": true,
  "sender_filter": "dte@sii.cl",
  "unread_only": true
}
```

**Proceso:**

1. **Conecta a IMAP** (línea 94-106)
   ```python
   client = IMAPClient(
       host=config.host,
       port=config.port,
       user=config.user,
       password=config.password,
       use_ssl=config.use_ssl
   )

   if not client.connect():
       raise HTTPException(503, "Failed to connect to email server")
   ```

2. **Busca emails de DTEs** (línea 109-113)
   ```python
   emails = client.fetch_dte_emails(
       sender_filter='dte@sii.cl',  # Solo emails del SII
       unread_only=True,            # Solo no leídos
       limit=100                     # Máximo 100 por vez
   )
   ```

3. **Procesa cada email** (línea 125-169)
   - Parsea XML DTE
   - Valida estructura
   - Valida reglas de negocio
   - Marca email como leído

4. **Retorna DTEs válidos** (línea 176-181)
   ```json
   {
     "success": true,
     "dtes": [
       {
         "dte_type": "33",
         "folio": "1234",
         "emisor_rut": "76489218-6",
         "emisor_name": "PROVEEDOR SPA",
         "monto_total": 150000,
         "raw_xml": "<?xml...",
         "email_id": "12345",
         "received_from": "dte@sii.cl",
         "received_date": "2025-10-25T10:00:00"
       }
     ],
     "count": 1,
     "errors": []
   }
   ```

**Estado:**
- ✅ Servicio funcional
- ✅ IMAP Client implementado (`clients/imap_client.py`)
- ✅ Parser implementado (`parsers/dte_parser.py`)
- ✅ Validadores implementados

---

### **FASE 4: Creación de Registros dte.inbox**

**Ubicación:** `models/dte_inbox.py:827-868`

**Función:** `_create_inbox_record(dte_data)`

**Lógica:**

```python
def _create_inbox_record(self, dte_data):
    # 1. Verifica si ya existe (evita duplicados)
    existing = self.search([
        ('emisor_rut', '=', dte_data.get('emisor', {}).get('rut')),
        ('dte_type', '=', dte_data.get('dte_type')),
        ('folio', '=', dte_data.get('folio')),
    ], limit=1)

    if existing:
        return existing

    # 2. Crea nuevo registro
    vals = {
        'folio': dte_data.get('folio'),
        'dte_type': dte_data.get('dte_type'),
        'emisor_rut': emisor.get('rut'),
        'emisor_name': emisor.get('razon_social'),
        'emisor_email': emisor.get('email'),  # ← ⚠️ Email del EMISOR (proveedor)
        'fecha_emision': dte_data.get('fecha_emision'),
        'monto_total': totales.get('total', 0),
        'raw_xml': dte_data.get('raw_xml'),
        'parsed_data': json.dumps(dte_data),
        'received_via': 'email',
        'state': 'new',
    }

    record = self.create(vals)
    return record
```

**Observación Crítica:**
- ✅ Campo `emisor_email` se extrae del XML DTE (email del proveedor)
- ⚠️ **NO se usa campo `dte_email` del partner**
- ⚠️ Email del XML puede estar desactualizado o incorrecto

---

## 🤔 ANÁLISIS: ¿Se Necesita Campo dte_email en Partners?

### **Situación Actual**

```
┌─────────────────────────────────────────────────────────────────────┐
│ FLUJO DE EMAIL EN RECEPCIÓN DE DTES                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ 1. SII envía DTE por email a:                                      │
│    To: facturacion@EMPRESA_RECEPTORA.cl ← Email IMAP configurado   │
│                                                                     │
│ 2. Email contiene XML DTE que incluye:                             │
│    <Emisor>                                                         │
│      <RUTEmisor>76489218-6</RUTEmisor>                             │
│      <RznSoc>PROVEEDOR SPA</RznSoc>                                │
│      <CorreoEmisor>contacto@proveedor.cl</CorreoEmisor>             │
│    </Emisor>                                                        │
│                                                                     │
│ 3. Odoo extrae email del XML y lo guarda en:                       │
│    dte.inbox.emisor_email = "contacto@proveedor.cl"                │
│                                                                     │
│ 4. ¿Se usa res.partner.dte_email?                                  │
│    ❌ NO - Se usa el email del XML                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### **Escenarios de Uso de dte_email en Partner**

#### **Escenario A: Recepción de DTEs**
**¿Se usa dte_email del partner?**
- ❌ **NO** - El email viene en el XML del DTE
- ✅ **SÍ (indirecto)** - Para validar/actualizar datos del proveedor

**Flujo:**
```
1. DTE llega con emisor_email = "contacto@proveedor.cl"
2. Odoo busca partner por RUT
3. Si partner.dte_email != emisor_email del XML:
   → ⚠️ ALERTA: Email desactualizado
   → Opción: Actualizar partner.dte_email automáticamente
```

#### **Escenario B: Envío de Respuestas Comerciales**
**¿Se usa dte_email del partner?**
- ✅ **SÍ** - Cuando enviamos respuesta (Aceptar/Rechazar/Reclamar DTE)

**Flujo:**
```
1. Usuario acepta/rechaza DTE en dte.inbox
2. Sistema envía email al proveedor
3. ¿A qué email enviar?
   → Opción 1: partner.dte_email (si existe)
   → Opción 2: dte_inbox.emisor_email (del XML)
   → Opción 3: partner.email (email general)
```

**Código Actual:**
- ⚠️ **NO IMPLEMENTADO** - Respuesta comercial se envía al SII vía SOAP, NO por email
- ℹ️ SII notifica al emisor, no nosotros directamente

#### **Escenario C: Notificaciones Proactivas**
**¿Se usa dte_email del partner?**
- ✅ **SÍ** - Para enviar notificaciones fuera del flujo SII

**Ejemplos:**
```
1. "Tu DTE fue recibido y validado"
2. "Problema con tu DTE - requiere corrección"
3. "Pago programado para tu DTE"
4. "Solicitud de aclaración de DTE"
```

**Código Actual:**
- ⚠️ **NO IMPLEMENTADO** - No hay notificaciones proactivas por email

---

## 💡 RECOMENDACIÓN ESTRATÉGICA

### **Decisión: Campo dte_email en Partners**

```
┌─────────────────────────────────────────────────────────────────────┐
│ VEREDICTO: ✅ SÍ CREAR, pero con PRIORIDAD MEDIA (P1, no P0)       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ RAZÓN:                                                              │
│                                                                     │
│ ✅ NECESARIO para:                                                 │
│   1. Mantener email actualizado del proveedor                      │
│   2. Enviar notificaciones futuras (roadmap)                       │
│   3. Validar discrepancias con XML                                 │
│   4. Buena práctica de maestro de datos                            │
│                                                                     │
│ ❌ NO BLOQUEANTE para:                                             │
│   1. Recepción actual de DTEs (usa email del XML)                  │
│   2. Migración de contactos (puede quedar NULL inicialmente)       │
│   3. Funcionalidad core del módulo                                 │
│                                                                     │
│ 🎯 ESTRATEGIA RECOMENDADA:                                         │
│                                                                     │
│ FASE 1 (Ahora - P0 BLOQUEANTE):                                    │
│   ✅ Crear campos IMAP en res.company                             │
│   ✅ Configurar buzón IMAP empresa                                │
│   ✅ Probar recepción de DTEs                                     │
│                                                                     │
│ FASE 2 (Después - P1 IMPORTANTE):                                  │
│   ✅ Crear campo dte_email en res.partner                         │
│   ✅ Migrar contactos (dte_email puede quedar NULL)               │
│   ✅ Poblar dte_email desde datos Odoo 11 (si existen)            │
│                                                                     │
│ FASE 3 (Futuro - P2 MEJORA):                                       │
│   ✅ Implementar sincronización automática XML → Partner          │
│   ✅ Alertas de discrepancia de datos                             │
│   ✅ Notificaciones proactivas por email                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📋 PLAN DE ACCIÓN INMEDIATO

### **PASO 1: Crear Campos IMAP (BLOQUEANTE - P0)**

**Archivo:** `addons/localization/l10n_cl_dte/models/res_company_dte.py`

**Agregar después de línea 43:**

```python
# ═══════════════════════════════════════════════════════════
# CONFIGURACIÓN IMAP PARA RECEPCIÓN DE DTES
# ═══════════════════════════════════════════════════════════

dte_imap_host = fields.Char(
    string='IMAP Host',
    default='imap.gmail.com',
    help='Servidor IMAP para recepción de DTEs.\\n\\n'
         'Ejemplos:\\n'
         '  • Gmail: imap.gmail.com\\n'
         '  • Outlook: outlook.office365.com\\n'
         '  • Otro: servidor.empresa.cl'
)

dte_imap_port = fields.Integer(
    string='IMAP Port',
    default=993,
    help='Puerto IMAP (993 para SSL, 143 sin SSL).'
)

dte_imap_user = fields.Char(
    string='IMAP User (Email)',
    help='Email del buzón para recepción de DTEs.\\n\\n'
         '⚠️ IMPORTANTE:\\n'
         'Este debe ser el email registrado en el SII\\n'
         'como email de intercambio de la empresa.\\n\\n'
         'Ejemplo: facturacion@empresa.cl'
)

dte_imap_password = fields.Char(
    string='IMAP Password',
    help='Contraseña o App Password para IMAP.\\n\\n'
         '📌 GMAIL: Requiere "App Password"\\n'
         '   1. Activar 2FA\\n'
         '   2. Generar App Password\\n'
         '   3. Usar ese password aquí'
)

dte_imap_ssl = fields.Boolean(
    string='Use SSL',
    default=True,
    help='Usar conexión SSL/TLS segura (recomendado).'
)
```

**Tiempo Estimado:** 5 minutos

---

### **PASO 2: Agregar Campos a Vista (Opcional - UX)**

**Archivo:** `addons/localization/l10n_cl_dte/views/res_company_views.xml`

**Agregar sección IMAP:**

```xml
<xpath expr="//group[@name='chile_tax']" position="after">
    <group string="Configuración Email - Recepción DTEs" name="chile_imap" colspan="2">

        <div colspan="2" class="alert alert-info" role="alert">
            <strong>ℹ️ Recepción Automática de DTEs por Email</strong>
            <p class="mb-0 mt-2 small">
                Configure el buzón de email donde el SII envía los DTEs recibidos.
                El sistema revisará este buzón cada hora para descargar automáticamente
                las facturas recibidas de proveedores.
            </p>
        </div>

        <field name="dte_imap_host" placeholder="imap.gmail.com"/>
        <field name="dte_imap_port"/>
        <field name="dte_imap_user" placeholder="facturacion@empresa.cl"/>
        <field name="dte_imap_password" password="True"/>
        <field name="dte_imap_ssl"/>
    </group>
</xpath>
```

**Tiempo Estimado:** 5 minutos

---

### **PASO 3: Actualizar Módulo y Probar**

```bash
# 1. Actualizar módulo
docker exec odoo19_app odoo -d TEST -u l10n_cl_dte --stop-after-init

# 2. Reiniciar Odoo
docker-compose restart odoo

# 3. Configurar IMAP en UI
# Odoo → Configuración → Empresas → Mi Empresa → Configuración Email

# 4. Probar cron job manualmente
# En Odoo shell o código:
# env['dte.inbox'].cron_check_inbox()
```

---

### **PASO 4 (POSTERIOR): Campo dte_email en Partners**

**Cuando:** Después de tener IMAP funcionando

**Archivo:** `addons/localization/l10n_cl_dte/models/res_partner_dte.py`

**Agregar campo:**

```python
dte_email = fields.Char(
    string='Email DTE',
    help='Email específico para envío/recepción de DTEs.\\n\\n'
         'Si está vacío, se usa el email general del contacto.'
)
```

**Migración:** Campo puede quedar NULL, se llenará progresivamente desde XMLs recibidos.

---

## 🎯 CONCLUSIÓN

### **Respuesta a Tu Pregunta:**

> "Lo del correo de intercambio es muy importante, por lo tanto tiene otra dimensión de análisis, esto es el funcionamiento mismo de la recepción de DTEs."

**RESPUESTA:**

✅ **CORRECTO** - El email de intercambio es **CRÍTICO**, pero hay **2 niveles:**

1. **Email de la EMPRESA (Buzón IMAP)** → 🔴 **P0 BLOQUEANTE**
   - Es donde SII envía TODOS los DTEs recibidos
   - Se configura en `res.company` (campos dte_imap_*)
   - **FALTA CREAR ESTOS CAMPOS AHORA**

2. **Email del PARTNER (Proveedor)** → 🟡 **P1 IMPORTANTE**
   - Es para notificaciones y validación de datos
   - Se configura en `res.partner` (campo dte_email)
   - **PUEDE CREARSE DESPUÉS** (no bloqueante)

**DELEGACIÓN DE RECEPCIÓN:**

```
┌───────────────────────────────────────────────────────┐
│ ¿QUIÉN RECIBE LOS DTES?                               │
├───────────────────────────────────────────────────────┤
│ 1. odoo-eergy-services (IMAPClient)                  │
│    → Descarga emails del buzón                       │
│    → Parsea XMLs                                      │
│    → Valida estructura                               │
│                                                       │
│ 2. Odoo (dte.inbox model)                            │
│    → Cron job coordinator                            │
│    → Creación de registros                           │
│    → Validación AI                                   │
│    → Matching PO                                     │
│    → Creación facturas                               │
│                                                       │
│ ⚠️ PROBLEMA ACTUAL:                                  │
│    Campos IMAP NO EXISTEN en res.company             │
│    → Cron job NO puede ejecutarse                   │
│    → Recepción automática NO funciona               │
└───────────────────────────────────────────────────────┘
```

**ACCIÓN INMEDIATA:**

✅ **Crear campos IMAP en res.company AHORA (P0)**
✅ **Dejar campo dte_email en partners para DESPUÉS (P1)**
✅ **Continuar con migración de contactos** (sin bloqueo)

---

**Firma Digital:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ANÁLISIS DE ARQUITECTURA DE RECEPCIÓN COMPLETADO
 EJECUTADO POR: Claude Code AI (Sonnet 4.5)
 ESPECIALIDAD: Senior Solution Architect
 EMPRESA: EERGYGROUP
 FECHA: 2025-10-25
 RESULTADO: ✅ ARQUITECTURA ANALIZADA - PLAN DE ACCIÓN DEFINIDO
 BLOQUEANTES IDENTIFICADOS: 1 (Campos IMAP faltantes)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
