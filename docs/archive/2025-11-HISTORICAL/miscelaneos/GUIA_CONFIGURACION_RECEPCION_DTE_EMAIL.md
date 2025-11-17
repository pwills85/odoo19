# GUÍA DE CONFIGURACIÓN: RECEPCIÓN DTE VÍA EMAIL

**Autor:** EERGYGROUP - Ing. Pedro Troncoso Willz
**Fecha:** 2025-10-25
**Sprint:** 4 - DTE Reception + AI Validation
**Propósito:** Guía paso a paso para configurar recepción automática de DTEs vía email

---

## 📋 ÍNDICE

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Prerequisitos](#prerequisitos)
3. [Paso 1: Configurar Gmail App Password](#paso-1-configurar-gmail-app-password)
4. [Paso 2: Configurar AI Service](#paso-2-configurar-ai-service)
5. [Paso 3: Configurar Incoming Mail Server (fetchmail)](#paso-3-configurar-incoming-mail-server-fetchmail)
6. [Paso 4: Configurar Outgoing Mail Server (SMTP)](#paso-4-configurar-outgoing-mail-server-smtp)
7. [Paso 5: Verificar Scheduled Action](#paso-5-verificar-scheduled-action)
8. [Paso 6: Probar Recepción](#paso-6-probar-recepción)
9. [Troubleshooting](#troubleshooting)
10. [Monitoreo](#monitoreo)

---

## 🎯 RESUMEN EJECUTIVO

Esta guía configura el sistema para:

✅ **Recibir DTEs automáticamente** desde SII vía email (IMAP)
✅ **Parsear XML** y crear registros `dte.inbox` en estado `new`
✅ **Validar con AI** cuando usuario presiona "Validate"
✅ **Matching automático** con Purchase Orders usando AI

**Flujo completo:**
```
SII envía email → Gmail → Odoo fetchmail (cada 5 min)
→ message_process() crea dte.inbox → Usuario valida
→ AI Service analiza → Resultados guardados
```

**Tiempo estimado:** 20-30 minutos

---

## ✅ PREREQUISITOS

Antes de comenzar, verificar:

- [ ] Cuenta Gmail activa: `facturacion@eergygroup.cl`
- [ ] Acceso a consola de Odoo (Developer mode activado)
- [ ] Docker containers corriendo:
  - `odoo` (Puerto 8069)
  - `ai-service` (Puerto 8002)
  - `db` (PostgreSQL)
- [ ] Módulo `l10n_cl_dte` instalado y actualizado
- [ ] Credenciales de administrador Odoo

**Verificar servicios:**
```bash
docker-compose ps

# Debe mostrar:
# odoo          running   0.0.0.0:8069->8069/tcp
# ai-service    running   0.0.0.0:8002->8002/tcp
# db            running   5432/tcp
```

---

## 📧 PASO 1: CONFIGURAR GMAIL APP PASSWORD

Google requiere App Passwords para aplicaciones de terceros que acceden vía IMAP.

### **1.1. Habilitar 2-Step Verification**

1. Ir a: https://myaccount.google.com/security
2. Login con `facturacion@eergygroup.cl`
3. Buscar sección **"2-Step Verification"**
4. Si no está habilitada:
   - Click **"Get started"**
   - Seguir wizard (agregar teléfono, etc.)
   - Confirmar activación

### **1.2. Crear App Password**

1. Ir a: https://myaccount.google.com/apppasswords
2. Login con `facturacion@eergygroup.cl`
3. **Select app:** Other (Custom name)
4. **Enter name:** `Odoo DTE Reception`
5. Click **Generate**
6. **COPIAR** el password de 16 caracteres (ej: `abcd efgh ijkl mnop`)
   - ⚠️ **IMPORTANTE:** Guardar en lugar seguro, solo se muestra una vez
7. Click **Done**

**Ejemplo de App Password:**
```
App: Odoo DTE Reception
Password: abcd efgh ijkl mnop
```

**Guardar para Paso 3.**

---

## 🤖 PASO 2: CONFIGURAR AI SERVICE

Configurar parámetros del sistema para conexión con AI Service.

### **2.1. Acceder a System Parameters**

1. Odoo UI → **Settings**
2. Activar **Developer Mode**:
   - Settings → Developer Tools → Activate the developer mode
3. Ir a: **Settings → Technical → Parameters → System Parameters**

### **2.2. Crear parámetros AI Service**

Click **Create** y agregar estos 3 parámetros:

**Parámetro 1:**
```
Key: dte.ai_service_url
Value: http://ai-service:8002
```

**Parámetro 2:**
```
Key: dte.ai_service_api_key
Value: eergygroup-ai-key-2025
```

**Parámetro 3:**
```
Key: dte.ai_service_timeout
Value: 10
```

### **2.3. Verificar con SQL (Opcional)**

```bash
# Conectar a DB
docker-compose exec db psql -U odoo -d TEST

# Query
SELECT key, value FROM ir_config_parameter WHERE key LIKE 'dte.ai%';

# Resultado esperado:
#          key             |         value
# -------------------------+------------------------
#  dte.ai_service_url      | http://ai-service:8002
#  dte.ai_service_api_key  | eergygroup-ai-key-2025
#  dte.ai_service_timeout  | 10
```

### **2.4. Probar conexión AI Service**

```bash
# Desde terminal
curl -X POST http://localhost:8002/api/ai/validate \
  -H "Authorization: Bearer eergygroup-ai-key-2025" \
  -H "Content-Type: application/json" \
  -d '{
    "dte_data": {
      "tipo_dte": "33",
      "folio": "12345",
      "monto_total": 1190000
    },
    "history": [],
    "mode": "reception"
  }'

# Respuesta esperada:
# {
#   "recommendation": "accept",
#   "confidence": 85.5,
#   "errors": [],
#   "warnings": []
# }
```

---

## 📥 PASO 3: CONFIGURAR INCOMING MAIL SERVER (FETCHMAIL)

Configurar servidor IMAP para descargar emails de SII.

### **3.1. Acceder a Incoming Mail Servers**

1. Odoo UI → **Settings**
2. **Technical → Email → Incoming Mail Servers**
3. Click **Create**

### **3.2. Completar formulario**

**General Information:**
```
Name: DTE SII Reception
Server Type: IMAP Server
```

**Server & Login:**
```
SSL/TLS: ✅ Checked
Server: imap.gmail.com
Port: 993
Username: facturacion@eergygroup.cl
Password: <App Password del Paso 1.2>
```

**Actions to Perform on Incoming Mails:**
```
☐ Keep Original (unchecked - marcar como leído después)
☐ Permanent Delete (unchecked)
☐ Mark as Read (checked - marcar como leído)
```

**Create a New Record:**
```
Model: dte.inbox
```

**Advanced (opcional):**
```
From Filter: dte@sii.cl
Folder: INBOX
```

### **3.3. Test & Confirm**

1. Click **Test & Confirm** button
2. Debería mostrar: "Connection test succeeded!"
3. Click **Save**

### **3.4. Fetch Manual (Test)**

1. Con el registro guardado, click **Fetch Now**
2. Verificar logs:

```bash
docker-compose logs -f odoo | grep -i "fetchmail\|dte.inbox"

# Logs esperados:
# INFO odoo.addons.fetchmail.models.fetchmail: Fetching mail from imap.gmail.com...
# INFO odoo.addons.l10n_cl_dte.models.dte_inbox: 📧 Processing incoming DTE email: Notificación DTE...
# INFO odoo.addons.l10n_cl_dte.models.dte_inbox: ✅ DTE inbox record created: ID=15, Type=33, Folio=12345...
```

---

## 📤 PASO 4: CONFIGURAR OUTGOING MAIL SERVER (SMTP)

Configurar servidor SMTP para enviar DTEs a clientes.

### **4.1. Acceder a Outgoing Mail Servers**

1. Odoo UI → **Settings**
2. **Technical → Email → Outgoing Mail Servers**
3. Click **Create**

### **4.2. Completar formulario**

**General Information:**
```
Description: Gmail SMTP - Facturación
Priority: 10
```

**Connection:**
```
SMTP Server: smtp.gmail.com
SMTP Port: 587
Connection Security: TLS (STARTTLS)
Username: facturacion@eergygroup.cl
Password: <App Password del Paso 1.2>
```

**Advanced:**
```
FROM Filtering: facturacion@eergygroup.cl
```

### **4.3. Test Connection**

1. Click **Test Connection** button
2. Debería mostrar: "Connection Test Succeeded!"
3. Click **Save**

### **4.4. Configurar como servidor por defecto**

**Opción A: UI**
```
Settings → General Settings → Email
→ Use a specific SMTP server: Gmail SMTP - Facturación
→ Save
```

**Opción B: SQL**
```sql
-- Marcar como default
UPDATE ir_mail_server SET sequence = 1 WHERE name = 'Gmail SMTP - Facturación';
```

---

## ⏰ PASO 5: VERIFICAR SCHEDULED ACTION

Verificar que cron job de fetchmail esté activo.

### **5.1. Acceder a Scheduled Actions**

1. Odoo UI → **Settings**
2. **Technical → Automation → Scheduled Actions**
3. Buscar: **"Mail: Fetchmail Service"**

### **5.2. Verificar configuración**

```
Name: Mail: Fetchmail Service
Model: fetchmail.server
Function: fetch_mail()
Interval Number: 5
Interval Type: Minutes
Active: ✅ Checked
Next Execution Date: (debe estar en el futuro)
```

### **5.3. Ejecutar manualmente (Test)**

1. Con el registro seleccionado
2. Click **Run Manually**
3. Verificar logs (igual que Paso 3.4)

### **5.4. Verificar con SQL (Opcional)**

```sql
SELECT
    id,
    name,
    active,
    interval_number,
    interval_type,
    nextcall,
    numbercall
FROM ir_cron
WHERE name = 'Mail: Fetchmail Service';

-- Resultado esperado:
--  id |          name           | active | interval_number | interval_type |      nextcall       | numbercall
-- ----+-------------------------+--------+-----------------+---------------+---------------------+------------
--   7 | Mail: Fetchmail Service | t      |               5 | minutes       | 2025-10-25 15:30:00 |        123
```

---

## 🧪 PASO 6: PROBAR RECEPCIÓN

Probar flujo completo end-to-end.

### **6.1. Enviar email de prueba**

**Opción A: Simular SII (desde otra cuenta Gmail)**

1. Login con cuenta personal en Gmail
2. Compose nuevo email:
   ```
   To: facturacion@eergygroup.cl
   Subject: Notificación DTE Folio 99999 (TEST)
   Body: Este es un DTE de prueba
   ```
3. **Adjuntar XML de prueba** (crear archivo `DTE_33_99999.xml`):

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
  <Documento ID="F33T99999">
    <Encabezado>
      <IdDoc>
        <TipoDTE>33</TipoDTE>
        <Folio>99999</Folio>
        <FchEmis>2025-10-25</FchEmis>
      </IdDoc>
      <Emisor>
        <RUTEmisor>76123456-7</RUTEmisor>
        <RznSoc>PROVEEDOR TEST SPA</RznSoc>
        <GiroEmis>Venta de materiales</GiroEmis>
        <DirOrigen>Av. Test 123</DirOrigen>
        <CmnaOrigen>Santiago</CmnaOrigen>
      </Emisor>
      <Receptor>
        <RUTRecep>76456789-K</RUTRecep>
        <RznSocRecep>EERGYGROUP SPA</RznSocRecep>
      </Receptor>
      <Totales>
        <MntNeto>1000000</MntNeto>
        <IVA>190000</IVA>
        <MntTotal>1190000</MntTotal>
        <MntExe>0</MntExe>
      </Totales>
    </Encabezado>
    <Detalle>
      <NroLinDet>1</NroLinDet>
      <NmbItem>Producto Test</NmbItem>
      <DscItem>Descripción del producto</DscItem>
      <QtyItem>10</QtyItem>
      <PrcItem>100000</PrcItem>
      <MontoItem>1000000</MontoItem>
    </Detalle>
  </Documento>
</DTE>
```

4. Click **Send**

### **6.2. Verificar recepción (Automático - 5 minutos)**

**Esperar 5 minutos** para que cron job ejecute, O forzar manualmente:

```
Settings → Technical → Email → Incoming Mail Servers
→ DTE SII Reception → Fetch Now
```

### **6.3. Verificar registro creado**

1. Ir a: **Facturación → Recepción DTEs → Bandeja de Entrada**
   (Si no existe el menú, crear acceso manual)

2. Buscar registro:
   ```
   Name: DTE 33 - 99999
   State: new (badge naranja)
   Supplier: PROVEEDOR TEST SPA (o sin partner si RUT no existe)
   Amount: $1,190,000
   ```

### **6.4. Validar con AI**

1. Abrir registro DTE
2. Click botón **"Validate"** (azul)
3. Verificar logs AI:

```bash
docker-compose logs -f ai-service | grep "validate"

# Log esperado:
# INFO: POST /api/ai/validate - 200 OK
```

4. Verificar resultados en UI:
   ```
   State: validated (badge verde)
   AI Validated: ✅ Yes
   AI Confidence: 85.5%
   AI Recommendation: accept
   ```

### **6.5. Verificar chatter**

En la parte inferior del formulario, verificar mensajes:

```
📧 DTE received via email
From: test@gmail.com
Subject: Notificación DTE Folio 99999 (TEST)
Attachment: DTE_33_99999.xml
Supplier: PROVEEDOR TEST SPA
```

---

## 🔧 TROUBLESHOOTING

### **Problema 1: "Connection test failed" en fetchmail**

**Síntomas:**
```
Connection test failed!
Please double check the configuration.
```

**Soluciones:**

1. **Verificar App Password:**
   - NO usar password normal de Gmail
   - Debe ser App Password de 16 caracteres (sin espacios)
   - Recrear si es necesario (Paso 1.2)

2. **Verificar 2-Step Verification:**
   - Debe estar ACTIVA en cuenta Gmail
   - https://myaccount.google.com/security

3. **Verificar IMAP habilitado:**
   - Gmail → Settings → Forwarding and POP/IMAP
   - IMAP access: Enable IMAP
   - Save Changes

4. **Verificar firewall:**
   ```bash
   # Test IMAP connection
   telnet imap.gmail.com 993
   # Debe conectar (Ctrl+C para salir)
   ```

---

### **Problema 2: No se crean registros dte.inbox**

**Síntomas:**
- fetchmail ejecuta sin errores
- Pero no aparecen registros en Bandeja de Entrada

**Soluciones:**

1. **Verificar logs:**
   ```bash
   docker-compose logs -f odoo | grep -i "dte.inbox\|error"
   ```

2. **Verificar filtro From:**
   - Settings → Technical → Incoming Mail Servers → DTE SII Reception
   - From Filter debe ser: `dte@sii.cl` (o vacío para recibir todos)

3. **Verificar adjunto XML:**
   - Email debe tener archivo `.xml` adjunto
   - Revisar logs: "No XML attachments found"

4. **Verificar modelo:**
   - Incoming Mail Server → Create a New Record
   - Model debe ser: `dte.inbox` (NO `mail.message`)

---

### **Problema 3: Error "AI Service no configurado"**

**Síntomas:**
```
AI confidence: 0%
AI recommendation: review
Warnings: AI Service no configurado - validación manual requerida
```

**Soluciones:**

1. **Verificar parámetros sistema:**
   ```sql
   SELECT key, value FROM ir_config_parameter WHERE key LIKE 'dte.ai%';
   ```

2. **Verificar AI Service corriendo:**
   ```bash
   docker-compose ps ai-service
   # Debe mostrar: Up

   curl http://localhost:8002/health
   # Debe retornar: {"status": "healthy"}
   ```

3. **Verificar API key:**
   - Debe coincidir en `ir_config_parameter` y en AI Service
   - Por defecto: `eergygroup-ai-key-2025`

4. **Reiniciar AI Service:**
   ```bash
   docker-compose restart ai-service
   docker-compose logs -f ai-service
   ```

---

### **Problema 4: XML parsing failed**

**Síntomas:**
```
State: error
Validation Errors: XML parsing failed: ...
```

**Soluciones:**

1. **Verificar encoding XML:**
   - Debe ser ISO-8859-1 (encoding chileno)
   - Primera línea: `<?xml version="1.0" encoding="ISO-8859-1"?>`

2. **Verificar estructura XML:**
   - Debe tener nodos: `//IdDoc/TipoDTE`, `//IdDoc/Folio`, `//Totales/MntTotal`
   - Validar contra schema SII

3. **Ver raw_xml:**
   - Abrir registro error en Developer mode
   - Campo `raw_xml` muestra XML completo
   - Buscar caracteres especiales o encoding issues

---

## 📊 MONITOREO

### **Dashboard de recepción DTEs**

**Queries útiles:**

```sql
-- DTEs recibidos hoy
SELECT
    COUNT(*) as total,
    state,
    received_via
FROM dte_inbox
WHERE DATE(received_date) = CURRENT_DATE
GROUP BY state, received_via;

-- DTEs pendientes validación
SELECT
    COUNT(*) as pendientes
FROM dte_inbox
WHERE state = 'new';

-- Proveedores top (últimos 30 días)
SELECT
    partner_id,
    COUNT(*) as dte_count,
    SUM(monto_total) as total_amount
FROM dte_inbox
WHERE received_date >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY partner_id
ORDER BY dte_count DESC
LIMIT 10;

-- Performance AI (últimos 7 días)
SELECT
    DATE(received_date) as dia,
    COUNT(*) as total,
    COUNT(CASE WHEN ai_validated THEN 1 END) as validados_ai,
    AVG(ai_confidence) as confianza_promedio
FROM dte_inbox
WHERE received_date >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(received_date)
ORDER BY dia DESC;
```

### **Logs a monitorear**

```bash
# Logs fetchmail
docker-compose logs -f odoo | grep -i fetchmail

# Logs DTE processing
docker-compose logs -f odoo | grep -i "dte.inbox"

# Logs AI Service
docker-compose logs -f ai-service | grep -E "validate|match_po"

# Errores generales
docker-compose logs -f | grep -i error
```

### **Alertas recomendadas**

1. **DTEs en estado 'error' > 5:**
   - Indica problemas parsing o validación
   - Revisar logs inmediatamente

2. **AI Service timeout > 10s:**
   - Revisar performance Claude API
   - Considerar aumentar timeout

3. **DTEs sin partner > 20%:**
   - Indica RUTs faltantes en base de datos
   - Ejecutar importación de contactos

---

## ✅ CHECKLIST FINAL

Una vez completados todos los pasos:

- [ ] Gmail App Password creado y guardado
- [ ] AI Service parámetros configurados (3 keys)
- [ ] AI Service responde a test curl
- [ ] Incoming Mail Server creado y test exitoso
- [ ] Outgoing Mail Server creado y test exitoso
- [ ] Scheduled Action "Mail: Fetchmail Service" activo
- [ ] Email de prueba enviado y recibido
- [ ] Registro `dte.inbox` creado en estado 'new'
- [ ] Validación manual ejecutada
- [ ] AI Service procesó y retornó resultados
- [ ] Estado final: 'validated' con AI confidence > 0%
- [ ] Chatter muestra mensaje de recepción

**Si todos los items están ✅, la configuración está completa.**

---

## 📚 REFERENCIAS

- [ROUTING_EMAIL_TO_AI_MICROSERVICE_COMPLETE_FLOW.md](ROUTING_EMAIL_TO_AI_MICROSERVICE_COMPLETE_FLOW.md) - Arquitectura completa
- [CORRECCION_ARQUITECTURA_EMAIL_DTE_ODOO_NATIVO.md](CORRECCION_ARQUITECTURA_EMAIL_DTE_ODOO_NATIVO.md) - Corrección arquitectura
- [Odoo Fetchmail Documentation](https://www.odoo.com/documentation/19.0/developer/reference/backend/mail.html)
- [Gmail App Passwords](https://support.google.com/accounts/answer/185833)
- [SII DTE Format](https://www.sii.cl/factura_electronica/formato_dte.htm)

---

**Documento creado:** 2025-10-25
**Última actualización:** 2025-10-25
**Autor:** EERGYGROUP - Ing. Pedro Troncoso Willz
**Sprint:** 4 - DTE Reception + AI Validation
**Versión:** 1.0
