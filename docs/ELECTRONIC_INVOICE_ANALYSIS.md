# 📋 Análisis Profundo: Facturación Electrónica en Chile

## Objetivo
Determinar todas las librerías, dependencias y requisitos técnicos necesarios para implementar un módulo robusto de facturación electrónica (DTE) en Odoo 19 CE, con máxima integración a la suite base.

**Fecha:** 2025-10-21  
**Versión Odoo:** 19.0 Community Edition  
**Localización:** Chile (SII - Servicio de Impuestos Internos)

---

## 🔍 PARTE 1: CONTEXTO REGULATORIO CHILENO

### 1.1 Marco Normativo

| Aspecto | Descripción |
|--------|------------|
| **Regulador** | SII (Servicio de Impuestos Internos de Chile) |
| **Formato** | DTE - Documento Tributario Electrónico |
| **Estándar** | XML según norma SII |
| **Firma** | Certificado digital clase 2 o 3 (PKI) |
| **Obligatoriedad** | Desde 2014 para empresas tributarias |
| **Validación** | Online con servidores SII en tiempo real |

### 1.2 Documentos Tributarios Electrónicos (DTE)

**Tipos principales implementar:**
- **Factura (33):** Venta de bienes/servicios
- **Boleta (39):** Comprobante pago consumidor final
- **Factura Electrónica de Compra (46):** Comprobante comprador
- **Notas de Crédito (61):** Devoluciones/descuentos
- **Notas de Débito (56):** Cargos adicionales
- **Guía de Despacho (52):** Movimiento físico de mercancía

**Campos obligatorios en DTE:**
```xml
<DTE>
  <Documento>
    <Encabezado>
      <!-- Datos del documento: folio, fecha, etc -->
    </Encabezado>
    <Detalle>
      <!-- Ítems: descripción, cantidad, precio -->
    </Detalle>
    <Referencia>
      <!-- Referencias a otros DTE -->
    </Referencia>
    <Timbre>
      <!-- Sello de validación SII -->
    </Timbre>
    <Firma>
      <!-- Firma digital del emisor -->
    </Firma>
  </Documento>
</DTE>
```

---

## 🔧 PARTE 2: ANÁLISIS TÉCNICO DETALLADO

### 2.1 Cadena de Procesamientos

```
1. GENERACIÓN DTE
   ├─ Datos de factura desde Odoo
   ├─ Validación de datos según SII
   ├─ Generación XML según norma
   └─ Firma digital del documento

2. ENVÍO A SII
   ├─ Autenticación con certificado
   ├─ Upload del XML firmado
   ├─ Recepción de timbre/sellado
   └─ Almacenamiento de constancia

3. RECEPCIÓN DE COMPRAS (del proveedor)
   ├─ Descarga del DTE del proveedor
   ├─ Validación de firma
   ├─ Validación de datos
   └─ Registro en contabilidad

4. CONSULTA DE ESTADO
   ├─ Verificación de acuse de recibo
   ├─ Verificación de rechazo
   └─ Obtención de constancia
```

### 2.2 Flujo de Datos Odoo ↔ SII

```
Odoo Database
    ↓
Factura (modelo account.move)
    ↓
Procesador DTE
    ├─ Lectura de datos
    ├─ Validación
    ├─ Generación XML
    └─ Firma con certificado
    ↓
XML Firmado
    ↓
Cliente SOAP/HTTP
    ├─ Autenticación al SII
    ├─ Upload documento
    └─ Recepción de Timbre
    ↓
SII Servers
    ├─ Validación
    ├─ Asignación de folio
    └─ Generación de Timbre
    ↓
DTE Sellado
    ↓
Odoo (registro de constancia)
```

---

## 📦 PARTE 3: LIBRERÍAS NECESARIAS POR FUNCIONALIDAD

### 3.1 GRUPO 1: Procesamiento de Certificados Digitales PKI

**Descripción:** Lectura, validación y uso de certificados X.509 para firma digital.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **pyOpenSSL** | Interfaz Python para OpenSSL | ✅ CRÍTICA | Lectura de certificados .pfx/.pem, manejo de claves privadas |
| **cryptography** | Primitivas criptográficas modernas | ✅ CRÍTICA | Firma digital PKCS#1 RSA, verificación de certificados |
| **python-pkcs1** | Implementación PKCS#1 | ✅ RECOMENDADA | Firma PKCS#1 v1.5 compatible con SII |
| **asn1crypto** | Parsing de ASN.1 (formato certificados) | ✅ RECOMENDADA | Extracción de datos de certificados X.509 |

**Instalación:**
```bash
apt-get install -y \
  libssl-dev \
  libffi-dev \
  python3-dev

pip install \
  pyOpenSSL>=21.0.0 \
  cryptography>=3.4.8 \
  python-pkcs1>=0.0.1 \
  asn1crypto>=1.5.1
```

### 3.2 GRUPO 2: Generación y Procesamiento XML

**Descripción:** Creación, validación y transformación de documentos XML según normas SII.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **lxml** | Parser y generador XML (C speedups) | ✅ CRÍTICA | Generación eficiente de XML, validación contra XSD |
| **xmlsec** | Firma digital de XML (xmldsig) | ✅ CRÍTICA | Firma digital de documentos XML según W3C |
| **defusedxml** | Protección contra ataques XXE | ✅ CRÍTICA | Prevención de inyecciones XML maliciosas |
| **requests-xml** | Parser XML para respuestas SII | ⚠️ OPCIONAL | Alternativa a lxml para parsing simple |

**Instalación:**
```bash
apt-get install -y \
  libxml2-dev \
  libxslt1-dev \
  libxmlsec1-dev \
  libxmlsec1-openssl

pip install \
  lxml>=4.9.0 \
  xmlsec>=1.1.25 \
  defusedxml>=0.0.1
```

### 3.3 GRUPO 3: Protocolo SOAP y Comunicación HTTP

**Descripción:** Comunicación con servicios web del SII usando SOAP.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **requests** | Cliente HTTP moderno | ✅ CRÍTICA | Comunicación HTTPS con servidor SII |
| **zeep** | Cliente SOAP 1.1/1.2 (recomendado) | ✅ CRÍTICA | Comunicación con web services SII (boleta, dte) |
| **suds-py3** | Cliente SOAP alternativo (legacy) | ⚠️ OPCIONAL | Compatibilidad con sistemas antiguos SII |
| **urllib3** | Pool de conexiones HTTP | ✅ RECOMENDADA | Connection pooling, timeouts, reintentos |
| **requests-toolbelt** | Extensiones a requests | ⚠️ OPCIONAL | Multipart uploads, streaming |

**Instalación:**
```bash
pip install \
  requests>=2.28.0 \
  zeep>=4.2.0 \
  urllib3>=1.26.0
```

### 3.4 GRUPO 4: Códigos de Barras y Códigos 2D

**Descripción:** Generación de códigos QR para TimbreXML en facturas.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **pybarcode** (barcode) | Códigos de barras 1D | ⚠️ OPCIONAL | Código de barras simple en facturas |
| **qrcode** | Generación de códigos QR | ✅ CRÍTICA | QR con TimbreXML en facturas (obligatorio SII) |
| **pillow** | Procesamiento de imágenes (requiere qrcode) | ✅ CRÍTICA | Renderización de QR a PNG/JPEG |
| **pyzbar** | Lectura de códigos 2D | ⚠️ OPCIONAL | Validación de QR en recepción de compras |

**Instalación:**
```bash
apt-get install -y \
  libzbar0 \
  libzbar-dev \
  libjpeg-dev \
  zlib1g-dev

pip install \
  qrcode>=7.3.0 \
  pillow>=9.0.0 \
  pyzbar>=0.1.8 \
  python-barcode>=0.13.1
```

### 3.5 GRUPO 5: Validación de Datos

**Descripción:** Validación de RUTs, datos fiscales y campos obligatorios.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **python-rut** | Validación y formatos de RUT chileno | ✅ CRÍTICA | Validación de RUT emisor/receptor |
| **phonenumbers** | Validación de números telefónicos | ⚠️ RECOMENDADA | Validación de contactos (normalizados) |
| **email-validator** | Validación de emails | ✅ RECOMENDADA | Validación de correos para envíos SII |
| **marshmallow** | Validación y serialización de datos | ⚠️ OPCIONAL | Schema validation alternativa |

**Instalación:**
```bash
pip install \
  python-rut>=0.1.0 \
  python-phonenumbers>=8.12.0 \
  email-validator>=1.1.5
```

### 3.6 GRUPO 6: Generación de PDFs

**Descripción:** Generación de representación visual de facturas con QR y firma.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **reportlab** | Generador PDF puro Python | ✅ RECOMENDADA | PDFs con QR, código de barras, formatos complejos |
| **PyPDF2** | Manipulación de PDFs | ⚠️ OPCIONAL | Merge/split de PDFs, metadatos |
| **fpdf2** | Alternativa simplificada a reportlab | ⚠️ OPCIONAL | PDFs simples, más rápido que reportlab |
| **weasyprint** | HTML → PDF (requiere ghostscript) | ✅ RECOMENDADA | PDFs desde templates HTML5/CSS3 |

**Instalación:**
```bash
apt-get install -y ghostscript  # Ya instalado en Dockerfile

pip install \
  reportlab>=3.6.0 \
  PyPDF2>=3.0.0 \
  weasyprint>=54.0 \
  fpdf2>=2.7.0
```

### 3.7 GRUPO 7: Almacenamiento y Caché

**Descripción:** Almacenamiento de certificados, caché de sesiones SII.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **redis** | Cliente Redis (caché distribuido) | ⚠️ RECOMENDADA | Caché de sesiones SII, folios temporales |
| **python-memcached** | Cliente Memcached | ⚠️ OPCIONAL | Caché alternativa a Redis |
| **keyring** | Almacenamiento seguro de contraseñas | ⚠️ RECOMENDADA | Almacenamiento seguro de contraseña certificado |
| **cryptography** | Ya incluida en Grupo 1 | ✅ INCLUIDA | Encriptación de datos sensibles en BD |

**Instalación:**
```bash
pip install \
  redis>=4.3.0 \
  keyring>=23.5.0
```

### 3.8 GRUPO 8: Logging, Auditoría y Debugging

**Descripción:** Registro detallado de operaciones para auditoría y troubleshooting.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **python-json-logger** | Logging en formato JSON | ⚠️ RECOMENDADA | Logs estructurados para análisis |
| **pythonjsonlogger** | Alternativa a json-logger | ⚠️ OPCIONAL | JSON logging para ELK/Splunk |
| **sentry-sdk** | Monitoreo de errores en producción | ⚠️ RECOMENDADA | Alertas en tiempo real de errores |
| **structlog** | Logging estructurado avanzado | ⚠️ OPCIONAL | Contexto completo en logs |

**Instalación:**
```bash
pip install \
  python-json-logger>=2.0.4 \
  sentry-sdk>=1.9.0 \
  structlog>=22.1.0
```

### 3.9 GRUPO 9: Testing y Validación

**Descripción:** Herramientas para testing del módulo DTE.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **pytest** | Framework de testing | ✅ RECOMENDADA | Tests unitarios del módulo |
| **pytest-mock** | Mocking para pytest | ✅ RECOMENDADA | Mock de respuestas SII |
| **responses** | Mock HTTP responses | ✅ RECOMENDADA | Simulación de servidor SII |
| **freezegun** | Mock de datetime | ⚠️ OPCIONAL | Testing de sellos de tiempo |

**Instalación:**
```bash
pip install \
  pytest>=7.0.0 \
  pytest-mock>=3.10.0 \
  responses>=0.20.0 \
  freezegun>=1.2.0
```

### 3.10 GRUPO 10: Parseo y Transformación de Datos

**Descripción:** Conversión de datos entre formatos.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **python-dateutil** | Parseo flexible de fechas | ✅ RECOMENDADA | Parseo de fechas desde XML SII |
| **pytz** | Manejo de zonas horarias | ✅ RECOMENDADA | Conversión a zona horaria Chile (CLT/CLST) |
| **simplejson** | JSON mejorado | ⚠️ OPCIONAL | Serialización JSON con decimales exactos |
| **arrow** | Datetime alternativo | ⚠️ OPCIONAL | Manejo de timestamps |

**Instalación:**
```bash
pip install \
  python-dateutil>=2.8.2 \
  pytz>=2022.1 \
  arrow>=1.2.0
```

### 3.11 GRUPO 11: Encriptación y Tokenización

**Descripción:** Encriptación de datos sensibles en Odoo.

| Librería | Propósito | Estado | Razón |
|----------|----------|--------|--------|
| **pycryptodome** | Suite criptográfica alternativa | ✅ RECOMENDADA | AES, DES, etc. para datos sensibles |
| **bcrypt** | Hash de contraseñas | ⚠️ OPCIONAL | Almacenamiento seguro de pins |
| **secretstorage** | Integración con GNOME Keyring | ⚠️ OPCIONAL | Almacenamiento en SO (Linux) |

**Instalación:**
```bash
pip install \
  pycryptodome>=3.15.0 \
  bcrypt>=4.0.0
```

---

## 📊 PARTE 4: DEPENDENCIAS DEL SISTEMA OPERATIVO

### 4.1 Librerías del Sistema Requeridas

```bash
# Librerías de desarrollo y compilación
apt-get install -y \
  build-essential \
  libssl-dev \
  libffi-dev \
  libxml2-dev \
  libxslt1-dev \
  libxmlsec1-dev \
  libxmlsec1-openssl \
  zlib1g-dev \
  libjpeg-dev

# Herramientas SSL/TLS
apt-get install -y \
  openssl \
  ca-certificates

# Herramientas de código de barras (ya instaladas)
apt-get install -y \
  libzbar0 \
  libzbar-dev

# Herramientas PDF avanzadas (ya instaladas)
apt-get install -y \
  ghostscript \
  wkhtmltopdf

# Herramientas de compresión
apt-get install -y \
  xz-utils \
  gzip \
  bzip2
```

### 4.2 Dependencias de Seguridad

```bash
# Para certificados y criptografía
apt-get install -y \
  libssl-dev \
  libcrypto++-dev

# Para base de datos de certificados del sistema
apt-get install -y \
  ca-certificates
```

---

## 🎯 PARTE 5: ARQUITECTURA DEL MÓDULO ODOO

### 5.1 Estructura de Carpetas del Módulo

```
l10n_cl_dte/
├── __init__.py
├── __manifest__.py
│
├── models/
│   ├── __init__.py
│   ├── account_move.py              # Extensión de facturas
│   ├── account_move_line.py         # Extensión de líneas
│   ├── dte_folio.py                 # Control de folios
│   ├── dte_certificate.py           # Gestión certificados
│   ├── dte_document.py              # Documentos DTE
│   ├── dte_send_response.py         # Respuestas del SII
│   └── dte_communication.py         # Comunicación con SII
│
├── views/
│   ├── account_move_view.xml        # UI para facturas
│   ├── dte_certificate_view.xml     # UI certificados
│   ├── dte_folio_view.xml           # UI folios
│   └── dte_settings_view.xml        # Configuración
│
├── reports/
│   ├── dte_pdf_report.py            # Generador PDF
│   ├── dte_receipt_report.py        # Comprobante pago
│   └── templates/
│       ├── dte_invoice.html         # Template factura
│       └── dte_receipt.html         # Template recibo
│
├── controllers/
│   ├── __init__.py
│   └── dte_webhook.py               # Webhooks del SII
│
├── tools/
│   ├── __init__.py
│   ├── dte_generator.py             # Generación XML DTE
│   ├── dte_signer.py                # Firma digital
│   ├── dte_validator.py             # Validación datos
│   ├── dte_sender.py                # Envío a SII
│   ├── dte_receiver.py              # Recepción de compras
│   ├── certificate_manager.py       # Gestión de certs
│   ├── folio_manager.py             # Control de folios
│   └── exceptions.py                # Excepciones personalizadas
│
├── tests/
│   ├── __init__.py
│   ├── test_dte_generator.py
│   ├── test_dte_signer.py
│   ├── test_dte_validator.py
│   ├── test_dte_sender.py
│   └── fixtures/
│       ├── sample_certificate.pfx
│       ├── sample_dte.xml
│       └── sample_responses/
│
├── static/
│   ├── css/
│   │   └── dte_styles.css
│   └── js/
│       └── dte_actions.js
│
├── wizard/
│   ├── __init__.py
│   ├── upload_certificate.py        # Wizard carga certificado
│   └── regenerate_folios.py         # Wizard regenerar folios
│
├── security/
│   ├── ir.model.access.csv          # Permisos acceso
│   └── rules.xml                    # Reglas de seguridad
│
├── i18n/
│   └── es_CL.po                     # Traducciones español Chile
│
└── README.md
```

### 5.2 Flujo de Integración con Odoo Core

```
account.move (Factura)
    ↓
Validación Odoo Core
    ├─ Impuestos
    ├─ Contacto
    └─ Empresa
    ↓
Extensión l10n_cl_dte
    ├─ Validación específica Chile
    ├─ Generación XML DTE
    ├─ Firma digital
    └─ Envío a SII
    ↓
account.journal (Diario)
    ├─ Configuración folio
    ├─ Rango de folios
    └─ Certificado digital
    ↓
account.tax (Impuestos)
    ├─ Códigos SII
    ├─ Porcentajes
    └─ Tipos DTE
```

---

## 📋 PARTE 6: TABLA CONSOLIDADA - LIBRERÍAS DEFINITIVAS

### 6.1 Librerías Python - Resumen Ejecutivo

| Categoría | Librería | Versión | Criticidad | Razón |
|-----------|----------|---------|-----------|-------|
| **Firma Digital** | pyOpenSSL | >=21.0.0 | ✅ CRÍTICA | Certificados PKI |
| | cryptography | >=3.4.8 | ✅ CRÍTICA | RSA/PKCS#1 |
| | asn1crypto | >=1.5.1 | ✅ CRÍTICA | Parseo X.509 |
| **XML** | lxml | >=4.9.0 | ✅ CRÍTICA | Generación/parseo XML |
| | xmlsec | >=1.1.25 | ✅ CRÍTICA | Firma XML |
| | defusedxml | >=0.0.1 | ✅ CRÍTICA | Seguridad XXE |
| **SOAP/HTTP** | zeep | >=4.2.0 | ✅ CRÍTICA | Comunicación SII |
| | requests | >=2.28.0 | ✅ CRÍTICA | Cliente HTTP |
| | urllib3 | >=1.26.0 | ✅ RECOMENDADA | Connection pooling |
| **Códigos QR** | qrcode | >=7.3.0 | ✅ CRÍTICA | QR TimbreXML |
| | pillow | >=9.0.0 | ✅ CRÍTICA | Renderización imágenes |
| **Validación** | python-rut | >=0.1.0 | ✅ CRÍTICA | RUT chileno |
| | python-phonenumbers | >=8.12.0 | ⚠️ RECOMENDADA | Teléfonos |
| | email-validator | >=1.1.5 | ✅ RECOMENDADA | Emails |
| **PDFs** | reportlab | >=3.6.0 | ✅ RECOMENDADA | Facturas QR |
| | weasyprint | >=54.0 | ✅ RECOMENDADA | HTML5→PDF |
| **Fecha/Hora** | python-dateutil | >=2.8.2 | ✅ RECOMENDADA | Parseo fechas |
| | pytz | >=2022.1 | ✅ RECOMENDADA | Zonas horarias |
| **Encriptación** | pycryptodome | >=3.15.0 | ✅ RECOMENDADA | Datos sensibles |
| | keyring | >=23.5.0 | ⚠️ RECOMENDADA | Almacenamiento seguro |
| **Testing** | pytest | >=7.0.0 | ✅ RECOMENDADA | Tests unitarios |
| | pytest-mock | >=3.10.0 | ✅ RECOMENDADA | Mocking |
| | responses | >=0.20.0 | ✅ RECOMENDADA | Mock HTTP |

### 6.2 Librerías del Sistema - Resumen

```bash
## CRÍTICAS
libssl-dev              (OpenSSL development)
libxml2-dev             (XML development)
libxslt1-dev            (XSLT development)
libxmlsec1-dev          (XML security)
libxmlsec1-openssl      (XML security - OpenSSL backend)

## RECOMENDADAS
libffi-dev              (Foreign Function Interface)
libjpeg-dev             (Imagen JPEG)
zlib1g-dev              (Compresión)
libzbar-dev             (Código de barras)

## SISTEMA OPERATIVO
ghostscript             (PDF rendering - YA INSTALADO)
ca-certificates         (Certificados SSL)
openssl                 (OpenSSL CLI tools)
```

---

## 🚀 PARTE 7: ACTUALIZACIÓN DEL DOCKERFILE

### 7.1 Librerías del Sistema a Agregar

**Actualmente instaladas:**
```dockerfile
# FASE 4: PERSONALIZACIÓN PARA CHILE
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ghostscript \              # ✓ YA PRESENTE
        libgeos-dev \              # ✓ YA PRESENTE
        libgeoip-dev \             # ✓ YA PRESENTE
        libxslt1-dev \             # ✓ YA PRESENTE
        libxml2-dev \              # ✓ YA PRESENTE
        libzbar0 \                 # ✓ YA PRESENTE
        libzbar-dev && \           # ✓ YA PRESENTE
    rm -rf /var/lib/apt/lists/*
```

**NUEVAS LIBRERÍAS PARA AGREGAR:**
```dockerfile
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Ya están: ghostscript, libgeos-dev, libgeoip-dev, libxslt1-dev, libxml2-dev, libzbar0, libzbar-dev
        
        # NUEVAS - Firma digital y PKI
        libssl-dev \               # OpenSSL development
        libffi-dev \               # Foreign Function Interface
        libxmlsec1-dev \           # XML security development
        libxmlsec1-openssl \       # XML security - OpenSSL backend
        
        # NUEVAS - Imágenes y código de barras
        libjpeg-dev \              # JPEG support
        zlib1g-dev \               # Compression library
        
        # NUEVAS - Certificados SSL
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*
```

### 7.2 Paquetes Python a Agregar

**requirements_dte.txt (archivo nuevo):**
```
# Firma Digital y Certificados PKI
pyOpenSSL>=21.0.0
cryptography>=3.4.8
python-pkcs1>=0.0.1
asn1crypto>=1.5.1

# Procesamiento XML
lxml>=4.9.0
xmlsec>=1.1.25
defusedxml>=0.0.1

# SOAP y Comunicación HTTP
requests>=2.28.0
zeep>=4.2.0
urllib3>=1.26.0

# Códigos QR
qrcode>=7.3.0
pillow>=9.0.0
pyzbar>=0.1.8
python-barcode>=0.13.1

# Validación de Datos Chile
python-rut>=0.1.0
python-phonenumbers>=8.12.0
email-validator>=1.1.5

# Generación de PDFs
reportlab>=3.6.0
PyPDF2>=3.0.0
weasyprint>=54.0
fpdf2>=2.7.0

# Fecha/Hora
python-dateutil>=2.8.2
pytz>=2022.1
arrow>=1.2.0

# Encriptación y Almacenamiento Seguro
pycryptodome>=3.15.0
bcrypt>=4.0.0
keyring>=23.5.0

# Logging y Monitoreo
python-json-logger>=2.0.4
sentry-sdk>=1.9.0
structlog>=22.1.0

# Testing
pytest>=7.0.0
pytest-mock>=3.10.0
responses>=0.20.0
freezegun>=1.2.0
```

---

## 💡 PARTE 8: INTEGRACIÓN CON MÓDULOS ODOO BASE

### 8.1 Módulos Odoo a Integrar

| Módulo | Integración | Propósito |
|--------|------------|----------|
| **account** | Extensión core | Facturas, asientos contables |
| **account_invoice** (v19) | Extensión | Validaciones facturación |
| **tax** | Extensión | Códigos impuestos SII |
| **partner** | Extensión | RUT validación, contactos |
| **company** | Configuración | Datos empresa, certificado |
| **journal** | Configuración | Folios, rango de numeración |
| **stock** | Integración | Guías de despacho (DTE 52) |
| **purchase** | Integración | Recepción de compras |
| **sale** | Integración | Facturas de venta |
| **report** | Extensión | Reportes DTE |
| **web** | Extensión | UI controllers |

### 8.2 Modelos a Extender

```python
# models/account_move.py
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
        ('voided', 'Anulado'),
    ])
    dte_folio = fields.Char('Folio DTE')
    dte_timestamp = fields.Datetime('Timestamp DTE')
    dte_track_id = fields.Char('Track ID SII')
    dte_response_xml = fields.Text('Respuesta XML SII')

# models/account_journal.py
class AccountJournal(models.Model):
    _inherit = 'account.journal'
    
    dte_folio_start = fields.Integer('Folio Inicial')
    dte_folio_end = fields.Integer('Folio Final')
    dte_folio_current = fields.Integer('Próximo Folio')
    dte_certificate_id = fields.Many2one('dte.certificate')
    dte_document_type = fields.Selection([...])

# models/partner.py (empresa)
class ResCompany(models.Model):
    _inherit = 'res.company'
    
    sii_taxpayer_type = fields.Selection([
        ('1', 'Aporte'),
        ('2', 'Simplificado'),
        ('', 'No Afecto'),
    ])
    dte_email_address = fields.Char('Email notificaciones')
```

### 8.3 Campos Específicos Odoo 19

**Para account.move:**
```python
# Extensión de campos core
dte_status
dte_folio
dte_timestamp
dte_track_id
dte_reference_ids (Many2many a otros DTEs)
dte_attachment_ids (Attachments XML/PDF)

# Métodos nuevos
def action_send_to_sii()
def action_download_dte()
def action_void_dte()
def get_dte_xml()
def get_dte_pdf()
def get_sii_status()
```

---

## 🔒 PARTE 9: CONFIGURACIÓN DE SEGURIDAD

### 9.1 Almacenamiento de Certificados

```python
# Opción 1: Encriptado en BD (RECOMENDADO)
class DTECertificate(models.Model):
    _name = 'dte.certificate'
    
    cert_file = fields.Binary('Certificado .pfx', encrypted=True)
    cert_password = fields.Char('Contraseña', encrypted=True)
    cert_validity_from = fields.Date('Válido desde')
    cert_validity_to = fields.Date('Válido hasta')
    cert_rut = fields.Char('RUT Certificado')

# Opción 2: Sistema de archivos (alternativa)
/var/lib/odoo/dte_certificates/
├── empresa1_cert.pfx (con permisos 600)
├── empresa2_cert.pfx
└── .htaccess (denegar acceso web)

# Opción 3: Keyring del SO (avanzado)
from keyring import get_password, set_password
password = get_password("odoo_dte", "empresa1")
```

### 9.2 Validación y Auditoría

```python
# Logging detallado
import structlog
logger = structlog.get_logger()

logger.info("dte_send_attempt", 
    folio=folio,
    rut_emisor=rut_emisor,
    monto=monto,
    timestamp=datetime.now()
)

# Auditoría en BD
class DTEAuditLog(models.Model):
    _name = 'dte.audit.log'
    
    action = fields.Char('Acción')
    user_id = fields.Many2one('res.users')
    document_id = fields.Char('ID Documento')
    status = fields.Selection([
        ('success', 'Éxito'),
        ('failure', 'Error'),
        ('pending', 'Pendiente'),
    ])
    error_message = fields.Text()
    timestamp = fields.Datetime('Timestamp', default=fields.Datetime.now)
```

---

## 📦 PARTE 10: PLAN DE IMPLEMENTACIÓN

### 10.1 Fases

**FASE 1: Infraestructura (1-2 semanas)**
- [ ] Actualizar Dockerfile con nuevas librerías
- [ ] Crear modelos base (Certificate, AuditLog)
- [ ] Configurar almacenamiento seguro de certificados

**FASE 2: Generación DTE (2-3 semanas)**
- [ ] Implementar DTEGenerator
- [ ] Validación de datos según SII
- [ ] Generación XML con estructura correcta

**FASE 3: Firma Digital (1-2 semanas)**
- [ ] Implementar DTESigner
- [ ] Lectura de certificados .pfx
- [ ] Firma PKCS#1 RSA

**FASE 4: Comunicación SII (2-3 semanas)**
- [ ] Implementar DTESender (SOAP/Zeep)
- [ ] Autenticación con certificado
- [ ] Manejo de respuestas

**FASE 5: Recepción de Compras (1-2 semanas)**
- [ ] Implementar DTEReceiver
- [ ] Descarga automática desde SII
- [ ] Procesamiento en Odoo

**FASE 6: Reportes y UI (1-2 semanas)**
- [ ] Generador de PDFs
- [ ] Vistas en Odoo
- [ ] Acciones masivas

**FASE 7: Testing (2-3 semanas)**
- [ ] Tests unitarios
- [ ] Tests de integración
- [ ] Pruebas con ambiente SII de pruebas

---

## 📚 REFERENCIAS

### Documentación Oficial
- [SII - Facturación Electrónica](https://www.sii.cl)
- [Biblioteca Tributaria SII](https://www.sii.cl/servicios/servicios-electronicos.html)
- [Documentación Odoo 19](https://www.odoo.com/documentation/19.0/)

### Librerías Clave
- [pyOpenSSL](https://www.pyopenssl.org/)
- [cryptography](https://cryptography.io/)
- [lxml](https://lxml.de/)
- [xmlsec](https://github.com/mehcode/python-xmlsec)
- [zeep](https://github.com/mvantellingen/python-zeep)
- [qrcode](https://github.com/lincolnloop/python-qrcode)

---

## 🎯 CONCLUSIÓN

Para una implementación robusta de facturación electrónica en Odoo 19 CE para Chile, se requieren:

**Librerías Críticas (11):** pyOpenSSL, cryptography, lxml, xmlsec, defusedxml, zeep, requests, qrcode, pillow, python-rut, email-validator

**Librerías Recomendadas (10+):** asn1crypto, urllib3, reportlab, weasyprint, python-dateutil, pytz, pycryptodome, pytest, pytest-mock, responses

**Librerías del Sistema:** libssl-dev, libxml2-dev, libxslt1-dev, libxmlsec1-dev, libffi-dev, libjpeg-dev, zlib1g-dev

Total: **30+ dependencias** cuidadosamente seleccionadas para máxima integración con Odoo 19 CE base.
