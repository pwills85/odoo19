# Análisis de Patrón de Delegación: Odoo ↔ DTE Microservice

**Documento:** Delegation Pattern Analysis
**Versión:** 1.0
**Fecha:** 2025-10-22
**Propósito:** Definir WHO DOES WHAT en el stack de 3 capas

---

## 🎯 Executive Summary

Este análisis documenta el **patrón de delegación establecido** entre Odoo Module y DTE Microservice, identificando:

1. ✅ **Separación clara de responsabilidades** (Business vs Technical)
2. ✅ **API contracts bien definidos** (REST + JSON)
3. ✅ **Patrones de integración consistentes** (Factory, Mixin, Singleton)
4. ✅ **Best practices identificadas** para nuevas features

**Conclusión:** La arquitectura actual es **sólida y extensible**. Nuevas features (Libro Guías, Eventos, IECV) deben seguir los mismos patrones.

---

## 📋 Tabla de Contenidos

1. [Principios Arquitectónicos](#principios-arquitectónicos)
2. [Matriz de Responsabilidades](#matriz-de-responsabilidades)
3. [Flujos de Integración Existentes](#flujos-de-integración-existentes)
4. [API Contracts](#api-contracts)
5. [Patrones de Código Identificados](#patrones-de-código-identificados)
6. [Recomendaciones para Nuevas Features](#recomendaciones-para-nuevas-features)

---

## 🏗️ Principios Arquitectónicos

### 1. **Single Responsibility Principle** ✅

Cada capa hace SOLO lo que está en su dominio de expertise:

```
┌─────────────────────────────────────────────────────────────┐
│ ODOO MODULE (Python/PostgreSQL)                             │
│ • Business Logic                                            │
│ • Data Persistence                                          │
│ • UI/UX                                                     │
│ • Workflow Management                                       │
│ • Local Validations                                         │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ REST API (JSON)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ DTE MICROSERVICE (FastAPI/Redis/RabbitMQ)                   │
│ • XML Generation                                            │
│ • Digital Signature                                         │
│ • SII SOAP Communication                                    │
│ • XSD Validation                                            │
│ • Queue Management                                          │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ SOAP (XML)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ SII (Servicio de Impuestos Internos)                        │
│ • DTE Reception                                             │
│ • DTE Validation                                            │
│ • Response Generation                                       │
└─────────────────────────────────────────────────────────────┘
```

### 2. **Extend, Don't Duplicate** ✅

El módulo Odoo **extiende** modelos existentes en lugar de crear nuevos:

```python
# ✅ CORRECTO: Extender modelo existente
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'  # Extend Odoo's invoice model

    dte_status = fields.Selection(...)
    dte_folio = fields.Char(...)
    dte_xml = fields.Text(...)
```

**Beneficios:**
- Reutiliza validaciones de Odoo
- Hereda workflows existentes
- Aprovecha UI/UX nativa
- Facilita migración entre versiones

### 3. **Integration via Mixin Pattern** ✅

La integración con microservicios se hace mediante un **Abstract Model reutilizable**:

```python
# ✅ CORRECTO: Mixin para integración
class DTEServiceIntegration(models.AbstractModel):
    _name = 'dte.service.integration'
    _description = 'DTE Service Integration Layer'

    @api.model
    def generate_and_send_dte(self, dte_data, certificate_data, environment='sandbox'):
        """Llamada única y reutilizable a DTE Service"""
        # ...
```

**Uso:**
```python
class AccountMoveDTE(models.Model):
    _inherit = ['account.move', 'dte.service.integration']

    def action_send_dte(self):
        result = self.generate_and_send_dte(data, cert, 'sandbox')
```

### 4. **No Duplication of Expertise** ✅

- **XML Generation:** SOLO en DTE Service (lxml expertise)
- **Digital Signature:** SOLO en DTE Service (cryptography expertise)
- **SOAP Communication:** SOLO en DTE Service (SII protocol expertise)
- **Business Rules:** SOLO en Odoo (domain knowledge)

---

## 📊 Matriz de Responsabilidades

### Caso 1: Emisión de DTE (Factura, Boleta, etc.)

| Tarea | Odoo Module | DTE Service | Justificación |
|-------|-------------|-------------|---------------|
| **Capturar datos usuario** | ✅ | ❌ | Form views, wizards en Odoo |
| **Validar RUT (módulo 11)** | ✅ | ❌ | Validación local, lógica de negocio |
| **Validar montos/totales** | ✅ | ❌ | Computed fields de Odoo |
| **Validar líneas de factura** | ✅ | ❌ | Business rules en Odoo |
| **Obtener folio siguiente** | ✅ | ❌ | Odoo maneja CAF ranges |
| **Preparar datos para DTE** | ✅ | ❌ | Data transformation en Odoo |
| **Generar XML DTE** | ❌ | ✅ | Technical expertise: lxml |
| **Incluir CAF en XML** | ❌ | ✅ | Technical expertise: XML structure |
| **Generar TED (timbre)** | ❌ | ✅ | Technical expertise: hash + QR |
| **Validar contra XSD** | ❌ | ✅ | Technical expertise: schema validation |
| **Firmar digitalmente (XMLDsig)** | ❌ | ✅ | Technical expertise: cryptography |
| **Enviar a SII (SOAP)** | ❌ | ✅ | Technical expertise: SOAP protocol |
| **Guardar resultado** | ✅ | ❌ | Data persistence en PostgreSQL |
| **Actualizar estado workflow** | ✅ | ❌ | Business workflow |
| **Crear log auditoría** | ✅ | ❌ | mail.thread, chatter |
| **Notificar usuario** | ✅ | ❌ | UI notifications |

**Patrón identificado:**
- **Odoo:** Orquestación, datos, workflow, UI
- **DTE Service:** Operaciones técnicas intensivas (CPU/I/O)

### Caso 2: Consumo de Folios

| Tarea | Odoo Module | DTE Service | Justificación |
|-------|-------------|-------------|---------------|
| **Definir período (mes/año)** | ✅ | ❌ | Input del usuario |
| **Seleccionar tipo DTE** | ✅ | ❌ | Input del usuario |
| **Consultar facturas del período** | ✅ | ❌ | PostgreSQL query (Odoo ORM) |
| **Calcular rango folios** | ✅ | ❌ | Lógica de negocio (min/max) |
| **Preparar datos para XML** | ✅ | ❌ | Data transformation |
| **Generar XML consumo** | ❌ | ✅ | Technical expertise: XML generation |
| **Firmar XML** | ❌ | ✅ | Technical expertise: digital signature |
| **Enviar a SII** | ❌ | ✅ | Technical expertise: SOAP |
| **Guardar constancia** | ✅ | ❌ | Data persistence |
| **Actualizar estado** | ✅ | ❌ | Business workflow |

**Archivos involucrados:**

**Odoo Side:**
```
addons/localization/l10n_cl_dte/
├── models/dte_consumo_folios.py         # Business model
│   ├── action_calcular_folios()         # Query facturas, calc range
│   └── action_generar_y_enviar()        # Llama DTE Service
├── wizard/generate_consumo_folios.py    # Wizard UI
└── tools/dte_api_client.py              # HTTP client
```

**DTE Service Side:**
```
dte-service/
├── generators/consumo_generator.py      # XML generation
│   └── generate(consumo_data) -> XML
└── main.py
    └── POST /api/consumo/generate       # Endpoint
```

### Caso 3: Libro de Compra/Venta

| Tarea | Odoo Module | DTE Service | Justificación |
|-------|-------------|-------------|---------------|
| **Definir período** | ✅ | ❌ | Input del usuario |
| **Definir tipo (compra/venta)** | ✅ | ❌ | Input del usuario |
| **Consultar account.move** | ✅ | ❌ | PostgreSQL query (Odoo ORM) |
| **Filtrar por estado DTE** | ✅ | ❌ | Lógica de negocio |
| **Calcular totales** | ✅ | ❌ | Computed fields Odoo |
| **Preparar estructura datos** | ✅ | ❌ | Data transformation |
| **Generar XML libro** | ❌ | ✅ | Technical expertise: XML generation |
| **Firmar XML** | ❌ | ✅ | Technical expertise: digital signature |
| **Enviar a SII** | ❌ | ✅ | Technical expertise: SOAP |
| **Guardar constancia** | ✅ | ❌ | Data persistence |

**Archivos involucrados:**

**Odoo Side:**
```
addons/localization/l10n_cl_dte/
└── models/dte_libro.py                  # Business model
    ├── action_agregar_documentos()      # Query + filter DTEs
    ├── _compute_totales()               # Calculate aggregates
    └── action_generar_y_enviar()        # Llama DTE Service
```

**DTE Service Side:**
```
dte-service/
└── generators/libro_generator.py        # XML generation
    ├── _add_caratula()                  # Header SII
    ├── _add_resumen()                   # Totals
    └── _add_detalle_documento()         # Each DTE detail
```

---

## 🔄 Flujos de Integración Existentes

### Flujo 1: Emisión DTE 33 (Factura Electrónica)

```
┌─────────────────────────────────────────────────────────────┐
│ PASO 1: Usuario crea/confirma factura en Odoo              │
│         Form view → Botón "Enviar DTE"                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 2: Odoo - Validaciones Locales                        │
│         account_move_dte.py::_validate_dte_data()           │
│         • RUT cliente válido (módulo 11)                    │
│         • RUT empresa válido                                │
│         • Líneas de factura presentes                       │
│         • Montos > 0                                        │
│         • Certificado digital válido                        │
│         • Diario con CAF configurado                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 3: Odoo - Preparar Datos                              │
│         account_move_dte.py::_prepare_dte_data()            │
│         • Obtener folio siguiente del CAF                   │
│         • Extraer datos emisor (company_id)                 │
│         • Extraer datos receptor (partner_id)               │
│         • Extraer líneas (invoice_line_ids)                 │
│         • Calcular totales                                  │
│         • Obtener certificado del diario                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 4: Odoo - Llamar DTE Service                          │
│         POST http://dte-service:8001/api/dte/generate       │
│         Headers: Authorization: Bearer {api_key}            │
│         Body: {                                             │
│           dte_type: "33",                                   │
│           invoice_data: {...},                              │
│           certificate: {...},                               │
│           environment: "sandbox"                            │
│         }                                                   │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP POST (JSON)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 5: DTE Service - Factory Pattern                      │
│         main.py::_get_generator(dte_type='33')              │
│         Returns: DTEGenerator33 instance                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 6: DTE Service - Generar XML                          │
│         dte_generator_33.py::generate(invoice_data)         │
│         • _add_encabezado() - IdDoc, Emisor, Receptor       │
│         • _add_detalle() - Líneas de factura                │
│         • _add_descuentos_recargos() - Si aplica            │
│         Returns: XML DTE (sin firmar)                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 7: DTE Service - Incluir CAF                          │
│         caf_handler.py::include_caf_in_dte()                │
│         • Valida rango folio en CAF                         │
│         • Inserta CAF en XML                                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 8: DTE Service - Generar TED (Timbre)                 │
│         ted_generator.py::generate_ted()                    │
│         • Calcula hash SHA-1                                │
│         • Firma hash con clave privada                      │
│         • Genera QR code                                    │
│         Returns: TED XML + QR image (base64)                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 9: DTE Service - Validaciones                         │
│         • xsd_validator.py - Valida contra DTE_v10.xsd      │
│         • dte_structure_validator.py - Norma SII            │
│         • ted_validator.py - Validar TED                    │
│         Si falla: Return HTTP 400 con detalles              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 10: DTE Service - Firma Digital                       │
│         xmldsig_signer.py::sign_xml()                       │
│         • Load certificado PKCS#12                          │
│         • Firma con RSA-SHA1                                │
│         • Canonicalización C14N                             │
│         Returns: XML firmado                                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 11: DTE Service - Enviar a SII                        │
│         sii_soap_client.py::send_dte()                      │
│         • SOAP call a Maullin/Palena                        │
│         • Retry logic (3 intentos)                          │
│         • Timeout 60s                                       │
│         Returns: track_id, estado, errores                  │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP Response (JSON)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 12: Odoo - Procesar Resultado                         │
│         account_move_dte.py::_process_dte_result()          │
│         • Actualizar dte_folio                              │
│         • Actualizar dte_status = 'sent'                    │
│         • Guardar dte_xml (base64)                          │
│         • Guardar dte_track_id                              │
│         • Guardar dte_response_xml                          │
│         • Crear log en dte.communication                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 13: Odoo - Notificar Usuario                          │
│         • Display notification (success/error)              │
│         • Log en chatter (mail.thread)                      │
│         • Actualizar UI (form view refresh)                 │
└─────────────────────────────────────────────────────────────┘
```

**Tiempo típico:** 2-5 segundos (incluyendo SOAP call a SII)

### Flujo 2: Consumo de Folios (Mensual)

```
┌─────────────────────────────────────────────────────────────┐
│ PASO 1: Usuario abre wizard "Consumo de Folios"            │
│         • Selecciona período (mes/año)                      │
│         • Selecciona tipo DTE (33, 34, 52, etc.)            │
│         • Opcionalmente: selecciona diario                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 2: Odoo - Calcular Folios Utilizados                  │
│         dte_consumo_folios.py::action_calcular_folios()     │
│         • Query account.move (facturas del período)         │
│         • Filtrar por dte_type, state='posted'              │
│         • Extraer dte_folio de cada factura                 │
│         • Calcular min/max (folio_inicio, folio_fin)        │
│         • Cantidad = folio_fin - folio_inicio + 1           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 3: Odoo - Preparar Datos para DTE Service             │
│         • rut_emisor (company_id.vat)                       │
│         • periodo (YYYY-MM)                                 │
│         • dte_type                                          │
│         • folio_inicio, folio_fin, cantidad                 │
│         • fecha_resolucion, nro_resolucion (CAF)            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 4: Odoo - Llamar DTE Service                          │
│         POST /api/consumo/generate-and-send                 │
│         Body: consumo_data                                  │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP POST (JSON)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 5: DTE Service - Generar XML Consumo                  │
│         consumo_generator.py::generate()                    │
│         • Carátula (RutEmisor, PeriodoTributario)           │
│         • Resumen (TipoDocumento, FoliosEmitidos)           │
│         • RangoUtilizados (Inicial, Final)                  │
│         Returns: XML consumo folios                         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 6: DTE Service - Firmar y Enviar                      │
│         • Firma digital (xmldsig_signer)                    │
│         • SOAP call a SII                                   │
│         Returns: track_id, estado                           │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP Response (JSON)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PASO 7: Odoo - Guardar Resultado                           │
│         • Actualizar state = 'sent'                         │
│         • Guardar xml_file, track_id                        │
│         • Crear log auditoría                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔌 API Contracts

### Contract 1: DTE Generation & Send

**Endpoint:** `POST /api/dte/generate-and-send`

**Request:**
```json
{
  "dte_type": "33",
  "invoice_data": {
    "folio": 12345,
    "fecha_emision": "2025-10-22",
    "emisor": {
      "rut": "76123456-7",
      "razon_social": "MI EMPRESA LTDA",
      "giro": "Servicios de Consultoría",
      "direccion": "Av. Principal 123",
      "ciudad": "Santiago",
      "comuna": "Las Condes"
    },
    "receptor": {
      "rut": "12345678-9",
      "razon_social": "CLIENTE S.A.",
      "giro": "Comercio al por Mayor",
      "direccion": "Calle Secundaria 456",
      "ciudad": "Santiago",
      "comuna": "Providencia"
    },
    "totales": {
      "monto_neto": 100000,
      "monto_iva": 19000,
      "monto_total": 119000
    },
    "lineas": [
      {
        "numero_linea": 1,
        "nombre": "Servicio de Consultoría",
        "descripcion": "Consultoría técnica mes octubre",
        "cantidad": 1,
        "unidad": "SERV",
        "precio_unitario": 100000,
        "descuento_pct": 0,
        "subtotal": 100000
      }
    ],
    "caf_xml": "<CAF>...</CAF>",
    "caf_folio_desde": 12000,
    "caf_folio_hasta": 13000,
    "timestamp": "2025-10-22T10:30:00"
  },
  "certificate": {
    "cert_file": "504B030414...",  // Hex-encoded PKCS#12
    "password": "mi_password_123"
  },
  "environment": "sandbox"  // o "production"
}
```

**Response Success (200):**
```json
{
  "success": true,
  "folio": "12345",
  "track_id": "987654321",
  "xml_b64": "PD94bWwgdmVy...",  // Base64-encoded XML firmado
  "qr_image_b64": "iVBORw0KGgo...",  // Base64-encoded QR PNG
  "response_xml": "<RECEPCIONDTE>...</RECEPCIONDTE>",
  "error_message": null
}
```

**Response Error (400):**
```json
{
  "detail": {
    "error": "DTE no cumple con validaciones SII",
    "validations": {
      "xsd": {
        "valid": false,
        "errors": ["Element 'Folio': Missing required element"]
      },
      "structure": {
        "valid": true,
        "errors": [],
        "warnings": []
      },
      "ted": {
        "valid": true,
        "errors": [],
        "warnings": []
      }
    }
  }
}
```

**Response Error (503):**
```json
{
  "detail": "DTE Service temporarily unavailable"
}
```

### Contract 2: DTE Status Query

**Endpoint:** `GET /api/dte/status/{track_id}`

**Response (200):**
```json
{
  "track_id": "987654321",
  "estado": "accepted",
  "glosa": "DTE Aceptado",
  "fecha_recepcion": "2025-10-22T10:35:00",
  "errores": []
}
```

### Contract 3: Consumo Folios Generation

**Endpoint:** `POST /api/consumo/generate-and-send`

**Request:**
```json
{
  "rut_emisor": "76123456-7",
  "periodo": "2025-10",
  "dte_type": "33",
  "folio_inicio": 12000,
  "folio_fin": 12345,
  "cantidad": 346,
  "monto_neto": 34600000,
  "monto_iva": 6574000,
  "monto_total": 41174000,
  "anulados": 5,
  "fecha_resolucion": "2014-08-22",
  "nro_resolucion": 80,
  "certificate": {...},
  "environment": "sandbox"
}
```

**Response (200):**
```json
{
  "success": true,
  "track_id": "123456789",
  "xml_b64": "PD94bWwgdmVy...",
  "estado": "sent"
}
```

### Contract 4: Libro Generation

**Endpoint:** `POST /api/libro/generate-and-send`

**Request:**
```json
{
  "tipo": "venta",  // o "compra"
  "rut_emisor": "76123456-7",
  "periodo": "2025-10",
  "documentos": [
    {
      "tipo_dte": "33",
      "folio": 12345,
      "fecha": "2025-10-15",
      "rut_contraparte": "12345678-9",
      "razon_social": "CLIENTE S.A.",
      "monto_neto": 100000,
      "monto_iva": 19000,
      "monto_total": 119000
    },
    // ... más documentos
  ],
  "totales": {
    "monto_neto": 34600000,
    "monto_iva": 6574000,
    "monto_total": 41174000
  },
  "fecha_resolucion": "2014-08-22",
  "nro_resolucion": 80,
  "certificate": {...},
  "environment": "sandbox"
}
```

**Response (200):**
```json
{
  "success": true,
  "track_id": "555666777",
  "xml_b64": "PD94bWwgdmVy...",
  "estado": "sent"
}
```

---

## 🎨 Patrones de Código Identificados

### Patrón 1: Model Extension (Odoo)

**Ubicación:** `addons/localization/l10n_cl_dte/models/`

**Propósito:** Extender modelos Odoo existentes sin duplicar

**Ejemplo:**
```python
# account_move_dte.py
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'  # ✅ EXTEND existing model

    # DTE-specific fields
    dte_status = fields.Selection([...])
    dte_folio = fields.Char(...)
    dte_xml = fields.Text(...)

    # DTE-specific methods
    def action_send_dte(self):
        """Send invoice to SII as DTE"""
        self._validate_dte_data()
        result = self._call_dte_service()
        self._process_dte_result(result)
```

**Best Practices:**
- ✅ Use `_inherit` (not `_name`)
- ✅ Prefix DTE fields with `dte_` (avoid name conflicts)
- ✅ Keep business logic (validation, workflow)
- ✅ Delegate technical operations to microservice

### Patrón 2: Mixin for Integration (Odoo)

**Ubicación:** `addons/localization/l10n_cl_dte/models/dte_service_integration.py`

**Propósito:** Reutilizar código de integración en múltiples modelos

**Ejemplo:**
```python
# dte_service_integration.py
class DTEServiceIntegration(models.AbstractModel):
    _name = 'dte.service.integration'
    _description = 'DTE Service Integration Layer'

    @api.model
    def generate_and_send_dte(self, dte_data, certificate_data, environment='sandbox'):
        """Single integration point with DTE Service"""
        try:
            base_url = self._get_dte_service_url()
            headers = self._get_request_headers()

            response = requests.post(
                f"{base_url}/api/dte/generate-and-send",
                json=payload,
                headers=headers,
                timeout=60
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise UserError(...)
        except requests.exceptions.Timeout:
            raise UserError(...)
```

**Usage:**
```python
# account_move_dte.py
class AccountMoveDTE(models.Model):
    _inherit = ['account.move', 'dte.service.integration']  # ✅ Use mixin

    def _call_dte_service(self):
        data = self._prepare_dte_data()
        return self.generate_and_send_dte(data, cert, 'sandbox')
```

**Best Practices:**
- ✅ Abstract Model (`_name` without create/read/write)
- ✅ Single responsibility (only API communication)
- ✅ Error handling with user-friendly messages
- ✅ Configuration via `ir.config_parameter`
- ✅ Comprehensive logging

### Patrón 3: Factory Pattern (DTE Service)

**Ubicación:** `dte-service/main.py`

**Propósito:** Seleccionar generador correcto según tipo DTE

**Ejemplo:**
```python
# main.py
def _get_generator(dte_type: str):
    """Factory pattern for DTE generators"""
    generators = {
        '33': DTEGenerator33,
        '34': DTEGenerator34,
        '52': DTEGenerator52,
        '56': DTEGenerator56,
        '61': DTEGenerator61,
    }

    generator_class = generators.get(dte_type)
    if generator_class is None:
        raise ValueError(f"Tipo DTE no soportado: {dte_type}")

    return generator_class()

@app.post("/api/dte/generate-and-send")
async def generate_and_send_dte(data: DTEData):
    generator = _get_generator(data.dte_type)  # ✅ Factory
    dte_xml = generator.generate(data.invoice_data)
    # ...
```

**Best Practices:**
- ✅ Centralized generator selection
- ✅ Easy to add new DTE types (just add to dict)
- ✅ Runtime type selection
- ✅ Clear error messages

### Patrón 4: Generator Classes (DTE Service)

**Ubicación:** `dte-service/generators/`

**Propósito:** Encapsular lógica de generación XML por tipo DTE

**Ejemplo:**
```python
# dte_generator_33.py
class DTEGenerator33:
    """Generator for DTE Type 33 (Electronic Invoice)"""

    def __init__(self):
        self.dte_type = '33'

    def generate(self, invoice_data: dict) -> str:
        """Generate XML DTE 33 according to SII spec"""
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{invoice_data['folio']}")

        self._add_encabezado(documento, invoice_data)
        self._add_detalle(documento, invoice_data)
        self._add_descuentos_recargos(documento, invoice_data)

        return etree.tostring(dte, pretty_print=True, encoding='ISO-8859-1').decode('ISO-8859-1')

    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Add header section"""
        # ...

    def _add_detalle(self, documento: etree.Element, data: dict):
        """Add detail lines"""
        # ...
```

**Best Practices:**
- ✅ One class per DTE type
- ✅ Private methods for sections (`_add_*`)
- ✅ Clear method signatures (input/output)
- ✅ Consistent structure across generators
- ✅ ISO-8859-1 encoding (SII requirement)

### Patrón 5: Data Transformation (Odoo → DTE Service)

**Ubicación:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

**Propósito:** Transformar datos Odoo a formato esperado por DTE Service

**Ejemplo:**
```python
# account_move_dte.py
def _prepare_dte_data(self):
    """Transform Odoo data to DTE Service format"""
    self.ensure_one()

    certificate = self.journal_id.dte_certificate_id
    cert_data = certificate.get_certificate_data()

    return {
        'dte_type': self.dte_code,
        'invoice_data': {
            'folio': self.journal_id._get_next_folio(),
            'fecha_emision': fields.Date.to_string(self.invoice_date),
            'emisor': {
                'rut': self.company_id.vat,
                'razon_social': self.company_id.name,
                'giro': self.company_id.l10n_cl_activity_description,
                'direccion': self._format_address(self.company_id),
                'ciudad': self.company_id.city,
                'comuna': self.company_id.state_id.name,
            },
            'receptor': {
                'rut': self.partner_id.vat,
                'razon_social': self.partner_id.name,
                # ...
            },
            'totales': {
                'monto_neto': self.amount_untaxed,
                'monto_iva': self.amount_tax,
                'monto_total': self.amount_total,
            },
            'lineas': self._prepare_invoice_lines(),
        },
        'certificate': {
            'cert_file': cert_data['cert_file'].hex(),
            'password': cert_data['password']
        },
        'environment': self._get_sii_environment(),
    }
```

**Best Practices:**
- ✅ Clear input/output contract
- ✅ Extract all needed data in one place
- ✅ Handle missing/optional fields gracefully
- ✅ Format conversion (Date → string, binary → hex)
- ✅ Business logic stays in Odoo (folio selection, etc.)

### Patrón 6: HTTP Client (Odoo)

**Ubicación:** `addons/localization/l10n_cl_dte/tools/dte_api_client.py`

**Propósito:** Centralizar comunicación HTTP con microservicios

**Ejemplo:**
```python
# dte_api_client.py
class DTEApiClient:
    """HTTP Client for DTE Microservice"""

    def __init__(self, env):
        self.env = env
        self.base_url = self._get_dte_service_url()
        self.api_key = self._get_api_key()
        self.timeout = 60

    def generate_and_send_dte(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate, sign and send DTE to SII"""
        try:
            response = requests.post(
                f'{self.base_url}/api/dte/generate-and-send',
                json=data,
                headers=self._get_headers(),
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            raise Exception('Timeout al comunicar con DTE Service')
        except requests.exceptions.RequestException as e:
            raise Exception(f'Error de comunicación: {str(e)}')
```

**Best Practices:**
- ✅ Centralized configuration (URL, API key, timeout)
- ✅ Consistent error handling
- ✅ Logging of requests/responses
- ✅ Timeout management
- ✅ Reusable across models

---

## 📋 Recomendaciones para Nuevas Features

### Feature 1: Libro de Guías de Despacho

**Tipo:** Reporte mensual SII (similar a Libro Compra/Venta)

**Delegación Recomendada:**

| Tarea | Responsable | Implementación |
|-------|-------------|----------------|
| **Modelo datos** | Odoo | Crear `dte.libro.guias` (similar a `dte.libro`) |
| **UI (wizard)** | Odoo | Form view con período, filtros |
| **Query stock.picking** | Odoo | ORM query: DTEs tipo 52 del período |
| **Calcular totales** | Odoo | Computed fields (cantidad_guias, etc.) |
| **Preparar datos** | Odoo | Method `_prepare_libro_guias_data()` |
| **Generar XML libro** | DTE Service | Nuevo: `LibroGuiasGenerator` |
| **Firmar XML** | DTE Service | Reutilizar `XMLDsigSigner` |
| **Enviar a SII** | DTE Service | Reutilizar `SIISoapClient` |
| **Guardar resultado** | Odoo | Actualizar state, xml_file, track_id |

**Archivos a crear/modificar:**

**Odoo:**
```
addons/localization/l10n_cl_dte/
├── models/
│   └── dte_libro_guias.py           # NUEVO: Business model
├── views/
│   └── dte_libro_guias_views.xml    # NUEVO: Tree, form views
└── security/
    └── ir.model.access.csv           # MODIFICAR: Add access rules
```

**DTE Service:**
```
dte-service/
├── generators/
│   └── libro_guias_generator.py     # NUEVO: XML generation
└── main.py                           # MODIFICAR: Add endpoint
    └── POST /api/libro/guias/generate-and-send
```

**Patrón a seguir:**
```python
# Odoo: dte_libro_guias.py
class DTELibroGuias(models.Model):
    _name = 'dte.libro.guias'
    _inherit = ['mail.thread', 'dte.service.integration']  # ✅ Mixin

    def action_agregar_documentos(self):
        """Query stock.picking con dte_type='52'"""
        domain = [
            ('invoice_date', '>=', self.periodo_inicio),
            ('invoice_date', '<=', self.periodo_fin),
            ('dte_type', '=', '52'),
            ('state', '=', 'done'),
            ('dte_status', '=', 'accepted'),
        ]
        guias = self.env['stock.picking'].search(domain)
        self.write({'picking_ids': [(6, 0, guias.ids)]})

    def action_generar_y_enviar(self):
        """Generate libro and send to SII"""
        data = self._prepare_libro_guias_data()
        result = self.generate_libro_guias(data, cert, 'sandbox')  # Call DTE Service
        self._process_result(result)

# DTE Service: libro_guias_generator.py
class LibroGuiasGenerator:
    """Generator for Libro de Guías de Despacho"""

    def generate(self, libro_data: dict) -> str:
        """Generate XML according to SII spec"""
        libro = etree.Element('LibroGuia')
        env_libro = etree.SubElement(libro, 'EnvioLibro', ID="LibroG")

        self._add_caratula(env_libro, libro_data)
        self._add_resumen(env_libro, libro_data)

        for guia in libro_data.get('guias', []):
            self._add_detalle_guia(env_libro, guia)

        return etree.tostring(libro, pretty_print=True, encoding='ISO-8859-1').decode('ISO-8859-1')
```

### Feature 2: Eventos Comerciales (Aceptación/Rechazo DTEs Recibidos)

**Tipo:** Comunicación bidireccional con SII (responder DTEs de proveedores)

**Delegación Recomendada:**

| Tarea | Responsable | Implementación |
|-------|-------------|----------------|
| **UI (botones Aceptar/Rechazar)** | Odoo | Buttons en form view de facturas recibidas |
| **Capturar motivo rechazo** | Odoo | Wizard con campo Text |
| **Preparar datos evento** | Odoo | Method `_prepare_evento_data()` |
| **Generar XML evento** | DTE Service | Nuevo: `EventoComercialGenerator` |
| **Firmar XML** | DTE Service | Reutilizar `XMLDsigSigner` |
| **Enviar a SII** | DTE Service | Reutilizar `SIISoapClient` (método RecepcionEvento) |
| **Actualizar estado factura** | Odoo | state = 'accepted' / 'rejected' |

**Archivos a crear/modificar:**

**Odoo:**
```
addons/localization/l10n_cl_dte/
├── models/
│   └── account_move_dte.py          # MODIFICAR: Add evento fields
├── wizards/
│   └── evento_comercial_wizard.py   # NUEVO: Capture motivo
└── views/
    └── account_move_dte_views.xml    # MODIFICAR: Add buttons
```

**DTE Service:**
```
dte-service/
├── generators/
│   └── evento_comercial_generator.py  # NUEVO: XML generation
└── clients/
    └── sii_soap_client.py            # MODIFICAR: Add send_evento()
```

**Patrón a seguir:**
```python
# Odoo: account_move_dte.py
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    evento_comercial = fields.Selection([
        ('pending', 'Pendiente Respuesta'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
        ('claimed', 'Reclamado'),
    ])
    evento_motivo = fields.Text('Motivo Evento')

    def action_aceptar_dte_recibido(self):
        """Accept received DTE"""
        data = self._prepare_evento_data('ACD')  # Aceptación Contenido DTE
        result = self.send_evento_comercial(data, cert, 'sandbox')
        self.write({'evento_comercial': 'accepted'})

    def action_rechazar_dte_recibido(self):
        """Reject received DTE with wizard"""
        return {
            'type': 'ir.actions.act_window',
            'name': 'Rechazar DTE',
            'res_model': 'evento.comercial.wizard',
            'view_mode': 'form',
            'target': 'new',
        }

# DTE Service: evento_comercial_generator.py
class EventoComercialGenerator:
    """Generator for Eventos Comerciales (commercial responses)"""

    EVENTOS = {
        'ACD': 'Aceptación Contenido DTE',
        'RCD': 'Reclamo Contenido DTE',
        'ERM': 'No Recibido por el Receptor',
        'RFP': 'Reclamo por Falta Parcial de Mercaderías',
        'RFT': 'Reclamo por Falta Total de Mercaderías',
    }

    def generate(self, evento_data: dict) -> str:
        """Generate evento XML"""
        evento = etree.Element('RespuestaEnvioDTE', version="1.0")
        resultado = etree.SubElement(evento, 'Resultado', ID="Ev")

        caratula = etree.SubElement(resultado, 'Caratula')
        etree.SubElement(caratula, 'RutResponde').text = evento_data['rut_receptor']
        etree.SubElement(caratula, 'RutRecibe').text = evento_data['rut_emisor']

        doc_evento = etree.SubElement(resultado, 'DocumentoEvento')
        etree.SubElement(doc_evento, 'TipoDoc').text = evento_data['tipo_dte']
        etree.SubElement(doc_evento, 'Folio').text = str(evento_data['folio'])
        etree.SubElement(doc_evento, 'FchEmis').text = evento_data['fecha_emision']
        etree.SubElement(doc_evento, 'RUTEmisor').text = evento_data['rut_emisor']
        etree.SubElement(doc_evento, 'CodEvento').text = evento_data['codigo_evento']  # ACD, RCD, etc.

        if evento_data.get('descripcion_evento'):
            etree.SubElement(doc_evento, 'DescEvento').text = evento_data['descripcion_evento']

        return etree.tostring(evento, pretty_print=True, encoding='ISO-8859-1').decode('ISO-8859-1')
```

### Feature 3: IECV (Información Electrónica de Compra/Venta)

**Tipo:** Reporte detallado mensual (reemplaza RCV tradicional)

**Delegación Recomendada:**

| Tarea | Responsable | Implementación |
|-------|-------------|----------------|
| **Query facturas período** | Odoo | ORM query con filtros complejos |
| **Calcular totales por tipo** | Odoo | Group by dte_type, tax_id |
| **Preparar estructura IECV** | Odoo | Method `_prepare_iecv_data()` |
| **Generar XML IECV** | DTE Service | Nuevo: `IECVGenerator` |
| **Firmar XML** | DTE Service | Reutilizar `XMLDsigSigner` |
| **Enviar a SII** | DTE Service | Reutilizar `SIISoapClient` |
| **Guardar resultado** | Odoo | Actualizar state, xml_file |

**Archivos a crear/modificar:**

**Odoo:**
```
addons/localization/l10n_cl_dte/
├── models/
│   └── dte_iecv.py                   # NUEVO: Business model
├── wizards/
│   └── generate_iecv_wizard.py       # NUEVO: Wizard selección período
└── views/
    └── dte_iecv_views.xml            # NUEVO: Tree, form views
```

**DTE Service:**
```
dte-service/
├── generators/
│   └── iecv_generator.py             # NUEVO: XML generation
└── main.py                           # MODIFICAR: Add endpoint
    └── POST /api/iecv/generate-and-send
```

**Patrón a seguir:**
```python
# Odoo: dte_iecv.py
class DTEIECV(models.Model):
    _name = 'dte.iecv'
    _inherit = ['mail.thread', 'dte.service.integration']

    def action_calcular_iecv(self):
        """Calculate IECV data from account.move"""
        # Query ventas
        ventas = self.env['account.move'].search([
            ('invoice_date', '>=', self.periodo_inicio),
            ('invoice_date', '<=', self.periodo_fin),
            ('move_type', 'in', ['out_invoice', 'out_refund']),
            ('state', '=', 'posted'),
        ])

        # Query compras
        compras = self.env['account.move'].search([
            ('invoice_date', '>=', self.periodo_inicio),
            ('invoice_date', '<=', self.periodo_fin),
            ('move_type', 'in', ['in_invoice', 'in_refund']),
            ('state', '=', 'posted'),
        ])

        # Group and aggregate
        self._compute_resumen_ventas(ventas)
        self._compute_resumen_compras(compras)

    def action_generar_y_enviar(self):
        """Generate IECV and send to SII"""
        data = self._prepare_iecv_data()
        result = self.generate_iecv(data, cert, 'sandbox')
        self._process_result(result)

# DTE Service: iecv_generator.py
class IECVGenerator:
    """Generator for IECV (Información Electrónica Compra/Venta)"""

    def generate(self, iecv_data: dict) -> str:
        """Generate XML according to SII IECV spec"""
        iecv = etree.Element('LibroCompraVenta', version="1.0")
        envio = etree.SubElement(iecv, 'EnvioLibro', ID="IECV")

        self._add_caratula(envio, iecv_data)

        # Resumen Ventas
        for resumen in iecv_data.get('resumenes_ventas', []):
            self._add_resumen_periodo(envio, resumen, tipo='venta')

        # Resumen Compras
        for resumen in iecv_data.get('resumenes_compras', []):
            self._add_resumen_periodo(envio, resumen, tipo='compra')

        # Detalle Ventas
        for dte in iecv_data.get('detalles_ventas', []):
            self._add_detalle_dte(envio, dte, tipo='venta')

        # Detalle Compras
        for dte in iecv_data.get('detalles_compras', []):
            self._add_detalle_dte(envio, dte, tipo='compra')

        return etree.tostring(iecv, pretty_print=True, encoding='ISO-8859-1').decode('ISO-8859-1')
```

---

## ✅ Best Practices Summary

### DO ✅

1. **Odoo Module:**
   - ✅ Extend existing models (`_inherit`)
   - ✅ Keep business logic and validations
   - ✅ Handle UI/UX (forms, wizards, notifications)
   - ✅ Manage data persistence (PostgreSQL)
   - ✅ Orchestrate workflows (states, transitions)
   - ✅ Use Odoo ORM for queries
   - ✅ Use mixin pattern for integration
   - ✅ Log user actions (mail.thread)

2. **DTE Service:**
   - ✅ Generate XML (lxml)
   - ✅ Validate against XSD
   - ✅ Digital signature (pyOpenSSL)
   - ✅ SOAP communication with SII
   - ✅ Handle retries and timeouts
   - ✅ Use factory pattern for generators
   - ✅ Return structured responses
   - ✅ Log technical operations (structlog)

3. **Integration:**
   - ✅ REST API (JSON)
   - ✅ Bearer token authentication
   - ✅ Clear error messages
   - ✅ Timeout management (60s for generation, 30s for queries)
   - ✅ Health check endpoints
   - ✅ Graceful degradation (AI Service optional)

### DON'T ❌

1. **Odoo Module:**
   - ❌ Don't generate XML directly
   - ❌ Don't implement SOAP clients
   - ❌ Don't duplicate Odoo functionality
   - ❌ Don't block on external services without timeout
   - ❌ Don't expose internal APIs to internet

2. **DTE Service:**
   - ❌ Don't handle business rules
   - ❌ Don't persist business data (use Redis for cache only)
   - ❌ Don't implement UI logic
   - ❌ Don't duplicate validation logic from Odoo

3. **Integration:**
   - ❌ Don't use synchronous calls without timeout
   - ❌ Don't expose sensitive data in logs
   - ❌ Don't skip error handling
   - ❌ Don't assume services are always available

---

## 📝 Checklist para Implementar Nueva Feature

Cuando implementes una nueva feature (Libro Guías, Eventos, IECV, etc.), sigue este checklist:

### [ ] 1. Análisis de Delegación

- [ ] ¿Qué hace el usuario? → **Odoo UI**
- [ ] ¿Qué datos se consultan? → **Odoo ORM**
- [ ] ¿Qué se calcula/agrega? → **Odoo Business Logic**
- [ ] ¿Qué XML se genera? → **DTE Service**
- [ ] ¿Qué se firma? → **DTE Service**
- [ ] ¿Qué se envía a SII? → **DTE Service**
- [ ] ¿Qué se guarda? → **Odoo Persistence**

### [ ] 2. Odoo Module

- [ ] Crear/extender modelo (`models/`)
- [ ] Definir campos necesarios
- [ ] Implementar computed fields
- [ ] Crear métodos de negocio (`action_*`)
- [ ] Implementar `_prepare_*_data()` para DTE Service
- [ ] Crear views (form, tree, search)
- [ ] Crear wizards si necesario
- [ ] Configurar security (ir.model.access.csv)
- [ ] Actualizar `__manifest__.py`

### [ ] 3. DTE Service

- [ ] Crear generator class (`generators/`)
- [ ] Implementar `generate()` method
- [ ] Implementar métodos privados (`_add_*`)
- [ ] Crear endpoint en `main.py`
- [ ] Definir Pydantic models (request/response)
- [ ] Agregar validaciones necesarias
- [ ] Reutilizar componentes existentes (signer, soap client)

### [ ] 4. Integration

- [ ] Definir API contract (request/response JSON)
- [ ] Implementar método en `dte_service_integration.py` (si reusable)
- [ ] O implementar en `dte_api_client.py` (si específico)
- [ ] Agregar error handling
- [ ] Configurar timeouts apropiados
- [ ] Agregar logging

### [ ] 5. Testing

- [ ] Tests unitarios Odoo (validaciones, computed fields)
- [ ] Tests DTE Service (XML generation, estructura)
- [ ] Tests integración (Odoo → DTE Service)
- [ ] Test manual en sandbox SII

### [ ] 6. Documentation

- [ ] Actualizar CLAUDE.md con nueva feature
- [ ] Documentar API contract
- [ ] Documentar flujo de integración
- [ ] Actualizar README si aplica

---

## 🎯 Conclusión

El patrón de delegación actual es **robusto, escalable y bien diseñado**:

1. ✅ **Separación clara:** Business (Odoo) vs Technical (DTE Service)
2. ✅ **Reutilización:** Mixins, factory pattern, shared components
3. ✅ **Extensibilidad:** Fácil agregar nuevos DTEs o reportes
4. ✅ **Mantenibilidad:** Código organizado, responsabilidades claras
5. ✅ **Testing:** Cada capa se puede testear independientemente

**Para nuevas features:** Sigue los patrones existentes documentados en este análisis.

---

**Archivo generado:** 2025-10-22
**Revisado por:** Claude Code
**Status:** ✅ Production Ready
