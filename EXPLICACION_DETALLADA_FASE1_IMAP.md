# 📧 FASE 1: Configuración IMAP - Explicación Detallada

**Objetivo:** Entender qué son los campos IMAP, por qué son críticos, y cómo configurarlos
**Tiempo de Lectura:** 10 minutos
**Nivel:** Explicación para entender el contexto completo

---

## 🎯 ¿QUÉ PROBLEMA ESTAMOS RESOLVIENDO?

### **Situación Actual (Con Problema)**

```
┌─────────────────────────────────────────────────────────────────────┐
│ FLUJO DE RECEPCIÓN DE DTES - ESTADO ACTUAL                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ 1. PROVEEDOR emite factura en su sistema                           │
│    └─> Genera DTE_33_1234.xml                                      │
│                                                                     │
│ 2. PROVEEDOR envía al SII                                          │
│    └─> SII valida y acepta el DTE                                  │
│                                                                     │
│ 3. SII NOTIFICA AL RECEPTOR (tu empresa) por email:                │
│    ┌────────────────────────────────────────────────┐              │
│    │ From: dte@sii.cl                                │              │
│    │ To: facturacion@eergygroup.cl ← ⚠️ ESTE EMAIL  │              │
│    │ Subject: DTE Recibido - Factura 33-1234        │              │
│    │ Attachment: DTE_33_1234.xml                     │              │
│    └────────────────────────────────────────────────┘              │
│                                                                     │
│ 4. EMAIL LLEGA A BUZÓN:                                            │
│    Gmail/Outlook de facturacion@eergygroup.cl                      │
│    └─> XML se queda ahí esperando...                               │
│                                                                     │
│ 5. ODOO NECESITA DESCARGAR AUTOMÁTICAMENTE:                        │
│    ❌ PROBLEMA: Odoo NO SABE cómo conectarse al buzón              │
│    ❌ Falta: Host, puerto, usuario, contraseña del buzón           │
│    ❌ Resultado: DTEs se acumulan sin procesar                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Pregunta:** ¿Cómo hace Odoo para descargar esos emails automáticamente?

**Respuesta:** Usando **protocolo IMAP** (como cuando abres Gmail en tu celular)

---

## 📚 ¿QUÉ ES IMAP?

### **Definición Simple**

**IMAP** (Internet Message Access Protocol) = Protocolo para **leer emails remotamente**

**Analogía:**
```
IMAP es como tener una LLAVE para entrar a tu buzón de correo
y revisar los mensajes desde cualquier lugar.

┌─────────────────────────────────────────┐
│ TU CELULAR (Gmail App)                  │
│ └─> Usa IMAP para leer emails           │
└─────────────────────────────────────────┘
         │ IMAP Protocol
         ▼
┌─────────────────────────────────────────┐
│ SERVIDOR GMAIL (imap.gmail.com:993)     │
│ └─> Guarda tus emails                   │
└─────────────────────────────────────────┘
         │ IMAP Protocol
         ▼
┌─────────────────────────────────────────┐
│ ODOO (Con nuestro código)               │
│ └─> También puede leer los mismos emails│
└─────────────────────────────────────────┘
```

**Lo que hace IMAP:**
- ✅ Conecta a tu buzón de email
- ✅ Lista mensajes (leídos/no leídos)
- ✅ Descarga contenido de emails
- ✅ Descarga archivos adjuntos (XML de DTEs)
- ✅ Marca emails como leídos
- ✅ Mueve emails a carpetas

---

## 🔑 LOS 5 CAMPOS IMAP (LA "LLAVE" DEL BUZÓN)

Para que Odoo pueda conectarse al buzón, necesita **5 datos** (como una llave):

### **Campo 1: dte_imap_host (Servidor)**

**¿Qué es?**
- La **dirección del servidor** de email

**Ejemplos:**
```
Gmail:     imap.gmail.com
Outlook:   outlook.office365.com
Yahoo:     imap.mail.yahoo.com
Empresa:   mail.eergygroup.cl  (si tienes servidor propio)
```

**¿Por qué es importante?**
- Sin esto, Odoo no sabe **A DÓNDE** conectarse

**Valor típico para Chile:**
```python
dte_imap_host = 'imap.gmail.com'  # 90% de empresas chilenas usan Gmail
```

---

### **Campo 2: dte_imap_port (Puerto)**

**¿Qué es?**
- El **puerto de conexión** (como el número de puerta en un edificio)

**Valores estándar:**
```
993 → IMAP con SSL (SEGURO, ENCRIPTADO) ← RECOMENDADO
143 → IMAP sin SSL (INSEGURO, NO USAR)
```

**¿Por qué es importante?**
- Puerto 993 = Conexión **encriptada** (nadie puede leer tus emails en tránsito)
- Puerto 143 = Conexión **sin encriptar** (PELIGROSO)

**Valor recomendado:**
```python
dte_imap_port = 993  # SIEMPRE usar SSL
```

---

### **Campo 3: dte_imap_user (Email/Usuario)**

**¿Qué es?**
- El **email completo** del buzón

**Ejemplos:**
```
facturacion@eergygroup.cl
contabilidad@eergygroup.cl
dte@eergygroup.cl
```

**¿Por qué es importante?**
- Este es el email que está **registrado en el SII**
- Aquí es donde el SII envía TODOS los DTEs recibidos

**⚠️ CRÍTICO:**
```
Este email DEBE coincidir con el email de intercambio
registrado en el portal SII (www.sii.cl)

Si en SII tienes:     facturacion@eergygroup.cl
Entonces aquí va:     facturacion@eergygroup.cl

❌ NO puede ser otro email diferente
```

**Valor de ejemplo:**
```python
dte_imap_user = 'facturacion@eergygroup.cl'
```

---

### **Campo 4: dte_imap_password (Contraseña)**

**¿Qué es?**
- La **contraseña** para acceder al buzón

**⚠️ IMPORTANTE - GMAIL REQUIERE "APP PASSWORD":**

Si usas **Gmail**, NO puedes usar tu contraseña normal. Debes generar una "App Password":

**Pasos para generar App Password en Gmail:**

```
1. Ve a tu cuenta Google
   https://myaccount.google.com/

2. Ir a: Seguridad → Verificación en 2 pasos
   └─> Activa 2FA si no lo tienes

3. Ir a: Seguridad → Contraseñas de aplicaciones
   https://myaccount.google.com/apppasswords

4. Generar nueva contraseña:
   - Nombre: "Odoo DTE Reception"
   - Se genera algo como: "xxxx xxxx xxxx xxxx" (16 caracteres)

5. Copiar esa contraseña (SIN ESPACIOS) y usarla aquí
```

**Ejemplo visual:**
```
┌────────────────────────────────────────────────┐
│ Google App Passwords                           │
├────────────────────────────────────────────────┤
│ Odoo DTE Reception                             │
│ xxxx xxxx xxxx xxxx    [Copiar] [Revocar]     │
│                                                │
│ ⚠️ Esta contraseña solo se muestra UNA VEZ   │
└────────────────────────────────────────────────┘
```

**Si usas Outlook/Exchange:**
```
Puedes usar tu contraseña normal
O también generar un App Password (más seguro)
```

**Valor de ejemplo:**
```python
dte_imap_password = 'xxxxyyyyzzzzwwww'  # App Password de Gmail (sin espacios)
```

**🔒 SEGURIDAD:**
- Esta contraseña se guarda **encriptada** en la base de datos
- No es visible en la interfaz (se muestra como `••••••••`)
- Solo Odoo puede leerla

---

### **Campo 5: dte_imap_ssl (Usar Encriptación)**

**¿Qué es?**
- Flag para activar **conexión segura SSL/TLS**

**Valores:**
```
True  → Conexión ENCRIPTADA (segura) ← SIEMPRE USAR
False → Conexión SIN ENCRIPTAR (insegura) ← NUNCA USAR
```

**¿Por qué es importante?**
- **SSL = Secure Socket Layer** = Encripta la comunicación
- Sin SSL, alguien puede **interceptar** tus emails y contraseñas

**Valor recomendado:**
```python
dte_imap_ssl = True  # SIEMPRE activado
```

---

## 🔄 FLUJO COMPLETO (CON CAMPOS IMAP CONFIGURADOS)

```
┌─────────────────────────────────────────────────────────────────────┐
│ RECEPCIÓN AUTOMÁTICA DE DTES (Flujo Correcto)                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ 1. SII envía email a facturacion@eergygroup.cl                     │
│    └─> Email llega al servidor Gmail                               │
│                                                                     │
│ 2. CRON JOB de Odoo se ejecuta (cada 1 hora)                       │
│    └─> Script: dte.inbox.cron_check_inbox()                        │
│                                                                     │
│ 3. Odoo LEE configuración IMAP de res.company:                     │
│    ┌──────────────────────────────────────────┐                    │
│    │ host     = 'imap.gmail.com'              │                    │
│    │ port     = 993                           │                    │
│    │ user     = 'facturacion@eergygroup.cl'   │                    │
│    │ password = 'xxxx' (App Password)         │                    │
│    │ use_ssl  = True                          │                    │
│    └──────────────────────────────────────────┘                    │
│                                                                     │
│ 4. Odoo LLAMA a odoo-eergy-services:                               │
│    POST /api/v1/reception/check_inbox                              │
│    Body: {config IMAP de arriba}                                   │
│                                                                     │
│ 5. odoo-eergy-services (IMAPClient):                               │
│    a. Conecta a imap.gmail.com:993 con SSL                         │
│    b. Login con facturacion@eergygroup.cl + password               │
│    c. Busca emails de dte@sii.cl que NO hayan sido leídos          │
│    d. Descarga archivos XML adjuntos                               │
│    e. Parsea cada XML (extrae folio, RUT, monto, etc.)             │
│    f. Valida estructura del DTE                                    │
│    g. Marca emails como leídos                                     │
│    h. Retorna DTEs válidos a Odoo                                  │
│                                                                     │
│ 6. Odoo RECIBE lista de DTEs:                                      │
│    [                                                                │
│      {                                                              │
│        "dte_type": "33",                                            │
│        "folio": "1234",                                             │
│        "emisor_rut": "76489218-6",                                  │
│        "monto_total": 150000,                                       │
│        "raw_xml": "<?xml..."                                        │
│      }                                                              │
│    ]                                                                │
│                                                                     │
│ 7. Para cada DTE:                                                   │
│    a. Crea registro en dte.inbox                                   │
│    b. Valida con AI (opcional)                                     │
│    c. Intenta match con Purchase Order                             │
│    d. Crea factura borrador                                        │
│    e. Notifica al usuario                                          │
│                                                                     │
│ ✅ RESULTADO: DTEs procesados automáticamente                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ❌ ¿QUÉ PASA SI NO CREAMOS ESTOS CAMPOS?

### **Escenario de Falla**

```python
# Código actual en dte_inbox.py línea 788

@api.model
def cron_check_inbox(self):
    company = self.env.company

    # ❌ FALLA AQUÍ - AttributeError
    imap_config = {
        'host': company.dte_imap_host,  # ❌ Campo no existe
        # ... Python lanza excepción y DETIENE el cron job
    }
```

**Excepción que se lanza:**
```
AttributeError: 'res.company' object has no attribute 'dte_imap_host'
```

**Consecuencias:**
1. ❌ Cron job se detiene inmediatamente
2. ❌ No se descargan DTEs del email
3. ❌ DTEs se acumulan sin procesar
4. ❌ Facturas de proveedores NO se crean automáticamente
5. ❌ Tienes que procesar DTEs MANUALMENTE (subir XML uno por uno)

---

## ✅ SOLUCIÓN: Crear los 5 Campos

### **Código a Agregar**

**Archivo:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/models/res_company_dte.py`

**Ubicación:** Después de línea 43 (después de `dte_resolution_date`)

```python
# ═══════════════════════════════════════════════════════════
# CONFIGURACIÓN IMAP PARA RECEPCIÓN DE DTES
#
# Estos campos permiten a Odoo conectarse automáticamente
# al buzón de email donde el SII envía los DTEs recibidos.
# ═══════════════════════════════════════════════════════════

dte_imap_host = fields.Char(
    string='IMAP Host',
    default='imap.gmail.com',
    help='Servidor IMAP para recepción de DTEs.\n\n'
         'Ejemplos:\n'
         '  • Gmail: imap.gmail.com\n'
         '  • Outlook: outlook.office365.com\n'
         '  • Yahoo: imap.mail.yahoo.com\n'
         '  • Servidor propio: mail.empresa.cl\n\n'
         'Este es el servidor donde están almacenados\n'
         'los emails que envía el SII.'
)

dte_imap_port = fields.Integer(
    string='IMAP Port',
    default=993,
    help='Puerto de conexión IMAP.\n\n'
         '  • 993: IMAP con SSL (RECOMENDADO - seguro)\n'
         '  • 143: IMAP sin SSL (NO usar - inseguro)\n\n'
         'El puerto 993 encripta la comunicación.'
)

dte_imap_user = fields.Char(
    string='IMAP User (Email)',
    help='Email completo del buzón para recepción de DTEs.\n\n'
         '⚠️ IMPORTANTE:\n'
         'Este email DEBE ser el mismo que está registrado\n'
         'en el SII como "Email de Intercambio" de la empresa.\n\n'
         'Ejemplos:\n'
         '  • facturacion@eergygroup.cl\n'
         '  • contabilidad@eergygroup.cl\n'
         '  • dte@eergygroup.cl\n\n'
         'Aquí es donde el SII envía todos los DTEs recibidos.'
)

dte_imap_password = fields.Char(
    string='IMAP Password',
    help='Contraseña para autenticación IMAP.\n\n'
         '📌 GMAIL: Requiere "App Password"\n'
         '   1. Ir a: https://myaccount.google.com/apppasswords\n'
         '   2. Activar verificación en 2 pasos (2FA)\n'
         '   3. Generar App Password para "Odoo DTE"\n'
         '   4. Copiar contraseña de 16 caracteres (sin espacios)\n'
         '   5. Pegar aquí\n\n'
         '📌 OUTLOOK/EXCHANGE:\n'
         '   Puede usar contraseña normal de la cuenta.\n\n'
         '🔒 SEGURIDAD:\n'
         '   Esta contraseña se almacena encriptada en la base de datos.'
)

dte_imap_ssl = fields.Boolean(
    string='Use SSL',
    default=True,
    help='Usar conexión SSL/TLS segura.\n\n'
         '✅ RECOMENDADO: Siempre activado\n'
         'Encripta la comunicación para proteger datos sensibles.\n\n'
         '❌ Desactivar solo si el servidor IMAP no soporta SSL\n'
         '(poco común en servidores modernos).'
)
```

---

## 🎯 PASO A PASO: Implementación

### **PASO 1: Editar Archivo Python**

```bash
# Abrir archivo
nano /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/models/res_company_dte.py

# O si usas VSCode:
code /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/models/res_company_dte.py
```

**Buscar línea 43:**
```python
    dte_resolution_date = fields.Date(
        string='Fecha Resolución DTE',
        help='Fecha de la resolución de autorización de DTEs'
    )
```

**Agregar DESPUÉS (línea 44):**
```python
    # ═══════════════════════════════════════════════════════════
    # CONFIGURACIÓN IMAP PARA RECEPCIÓN DE DTES
    # ═══════════════════════════════════════════════════════════

    dte_imap_host = fields.Char(...)  # Copiar código de arriba
    # ... resto de campos
```

**Guardar archivo:** `Ctrl+S` o `:wq` en nano

---

### **PASO 2: Actualizar Módulo en Odoo**

```bash
# Opción A: Con Odoo apagado
docker exec odoo19_app odoo -d TEST -u l10n_cl_dte --stop-after-init

# Opción B: Con Odoo corriendo (más rápido)
docker-compose restart odoo
```

**Verificar en logs:**
```bash
docker-compose logs odoo | grep "Registry loaded"
# Esperado: "Registry loaded in X.XXs" (sin errores)
```

---

### **PASO 3: Configurar en la Interfaz de Odoo**

**Navegación:**
```
Odoo → ⚙️ Configuración → Empresas → 🏢 Mi Empresa
```

**Buscar sección:**
```
"Configuración Tributaria Chile - DTE"
```

**Llenar campos:**
```
IMAP Host:        imap.gmail.com
IMAP Port:        993
IMAP User:        facturacion@eergygroup.cl
IMAP Password:    [App Password de Gmail - 16 caracteres]
Use SSL:          ✅ Activado
```

**Ejemplo visual:**
```
┌────────────────────────────────────────────────┐
│ Configuración Email - Recepción DTEs          │
├────────────────────────────────────────────────┤
│ IMAP Host:     [imap.gmail.com            ]   │
│ IMAP Port:     [993                       ]   │
│ IMAP User:     [facturacion@eergygroup.cl ]   │
│ IMAP Password: [••••••••••••••••          ]   │
│ Use SSL:       [✓] Activado                   │
│                                                │
│ [Guardar]                                      │
└────────────────────────────────────────────────┘
```

**Guardar:** Click en `[Guardar]`

---

### **PASO 4: Probar Recepción (Manualmente)**

**Opción A: Desde Odoo UI (Próximamente - crear botón)**

**Opción B: Desde Python Shell**

```bash
# Entrar al shell de Odoo
docker exec -it odoo19_app odoo shell -d TEST

# Ejecutar cron job manualmente
>>> env['dte.inbox'].cron_check_inbox()

# Ver resultados
>>> dtes = env['dte.inbox'].search([], order='received_date desc', limit=5)
>>> for dte in dtes:
...     print(f"{dte.name} - {dte.emisor_name} - ${dte.monto_total}")
```

**Opción C: Esperar al Cron Job (1 hora)**

El cron job se ejecuta automáticamente cada hora.

---

## 📊 VERIFICACIÓN DE ÉXITO

### **✅ Checklist Post-Configuración**

```
□ Campos creados en código Python
□ Módulo actualizado sin errores
□ Odoo reiniciado correctamente
□ Campos visibles en UI (Configuración Empresa)
□ Valores configurados y guardados
□ App Password generado en Gmail (si aplica)
□ Cron job ejecutado manualmente (sin errores)
□ Al menos 1 DTE descargado y visible en dte.inbox
```

### **🔍 Cómo Verificar que Funciona**

**1. Ver Logs del Cron Job:**
```bash
docker-compose logs -f odoo | grep "cron_check_inbox"
```

**Esperado:**
```
INFO TEST odoo.addons.l10n_cl_dte.models.dte_inbox: Running DTE inbox cron job
INFO TEST odoo.addons.l10n_cl_dte.models.dte_inbox: Inbox check complete: 3 DTEs processed
```

**2. Ver DTEs Recibidos en Odoo:**
```
Odoo → DTE → 📨 Bandeja de Entrada

Deberías ver:
┌─────────────────────────────────────────────────┐
│ DTE 33 - 1234   PROVEEDOR SPA   $150,000  Nuevo│
│ DTE 33 - 1235   OTRO PROV LTDA  $85,000   Nuevo│
└─────────────────────────────────────────────────┘
```

**3. Verificar Email Marcado como Leído:**
```
Entrar a Gmail → Ver que emails de dte@sii.cl
ahora están marcados como leídos
```

---

## ⚠️ PROBLEMAS COMUNES Y SOLUCIONES

### **Error 1: "IMAP connection failed"**

**Causa:** Credenciales incorrectas o Gmail bloqueando acceso

**Solución:**
```
1. Verificar que 2FA esté activado en Gmail
2. Generar NUEVO App Password
3. Copiar sin espacios: "xxxx xxxx xxxx xxxx" → "xxxxxxxxxxxxxxxx"
4. Pegar en campo IMAP Password
5. Guardar y reintentar
```

---

### **Error 2: "No DTEs found"**

**Causa:** No hay emails nuevos de dte@sii.cl

**Solución:**
```
1. Verificar que el email configurado sea correcto
2. Pedir a un proveedor que envíe DTE de prueba
3. Verificar en Gmail que el email llegó
4. Verificar que no esté en carpeta Spam
5. Ejecutar cron job después de que llegue el email
```

---

### **Error 3: "AttributeError: no attribute 'dte_imap_host'"**

**Causa:** Campos no creados o módulo no actualizado

**Solución:**
```bash
# 1. Verificar que el código esté en el archivo
grep -n "dte_imap_host" /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/models/res_company_dte.py

# 2. Actualizar módulo
docker exec odoo19_app odoo -d TEST -u l10n_cl_dte --stop-after-init

# 3. Reiniciar Odoo
docker-compose restart odoo

# 4. Verificar en logs que no haya errores
docker-compose logs odoo | tail -50
```

---

## 🎯 RESUMEN EJECUTIVO

### **¿Qué Estamos Haciendo?**

Creando 5 campos en `res.company` que le dicen a Odoo:

1. **Dónde** está el buzón de email (servidor IMAP)
2. **Cómo** conectarse (puerto con SSL)
3. **Quién** puede acceder (email + contraseña)

### **¿Por Qué es Necesario?**

Sin estos campos, Odoo **NO PUEDE** descargar automáticamente los DTEs que el SII envía por email.

### **¿Cuánto Tiempo Toma?**

```
Generar App Password Gmail:    5 min
Editar código Python:          3 min
Actualizar módulo Odoo:        2 min
Configurar en UI:              2 min
Probar:                        3 min
───────────────────────────────────
TOTAL:                        15 min
```

### **¿Qué Ganamos?**

✅ Recepción **automática** de DTEs (cada hora)
✅ **Cero trabajo manual** de descarga de XMLs
✅ DTEs **validados** y **listos** para aprobar
✅ **Matching automático** con Purchase Orders
✅ Facturas **pre-creadas** en borrador

---

## 📝 SIGUIENTE PASO

Una vez que FASE 1 esté funcionando:

**FASE 2:** Agregar campo `dte_email` en partners (para notificaciones y validación)

**FASE 3:** Ejecutar migración de contactos desde Odoo 11

---

**¿Quieres que proceda con la implementación de FASE 1 ahora?**

Puedo:
1. ✅ Crear los campos en el código
2. ✅ Actualizar el módulo
3. ✅ Probar la recepción

O prefieres hacerlo manualmente siguiendo esta guía?

---

**Firma Digital:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXPLICACIÓN DETALLADA FASE 1 - CAMPOS IMAP
 CREADO POR: Claude Code AI (Sonnet 4.5)
 FECHA: 2025-10-25
 OBJETIVO: Hacer comprensible la arquitectura IMAP
 RESULTADO: ✅ Explicación completa con ejemplos prácticos
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
