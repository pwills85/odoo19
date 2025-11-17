# Análisis Funcional de Modelos de Datos - l10n_cl_fe
## Fase 2.1: Auditoría Funcional Odoo 11 → Odoo 19

---

**Fecha:** 2025-11-09  
**Módulo Analizado:** `l10n_cl_fe` (Facturación Electrónica Chile)  
**Ruta:** `/addons/l10n_cl_fe/models/`  
**Objetivo:** Identificar know-how funcional a preservar en migración a Odoo 19  

---

## RESUMEN EJECUTIVO

### Estadísticas del Módulo
- **Total archivos Python:** 42 modelos
- **Tamaño total:** ~250KB de código
- **Modelos principales identificados:** 15 modelos críticos
- **Archivos CAF encontrados:** Sistema completo de gestión de folios
- **Integraciones detectadas:** SII, Email, Libros CV, Reclamos DTE

### Hallazgos Clave
1. **Sistema completo de Facturación Electrónica** con integración directa al SII
2. **Gestión de folios CAF** con control de rangos y vencimientos
3. **Libros de Compra/Venta** con envío automático al SII
4. **Sistema de Reclamos DTE** (ACD, RCD, ERM, etc.)
5. **Cola de envíos automáticos** con reintentos y persistencia
6. **Impuestos MEPCO** con actualización automática desde Diario Oficial
7. **Sincronización de Partners** con servidor remoto
8. **Validaciones comerciales** y recepción de mercaderías

---

## 1. MODELOS PRINCIPALES

### 1.1. account.invoice (87KB) - MODELO CRÍTICO

**Archivo:** `account_invoice.py`

#### Campos Funcionales Principales

| Campo | Tipo | Propósito Funcional | Calculado/Almacenado |
|-------|------|---------------------|----------------------|
| `document_class_id` | Many2one(sii.document_class) | Tipo de documento tributario (33, 34, 39, 41, etc.) | Almacenado |
| `journal_document_class_id` | Many2one(account.journal.sii_document_class) | Clase de documento del diario para control de secuencias | Almacenado |
| `sii_batch_number` | Integer | Número de lote de envío al SII | Almacenado |
| `sii_barcode` | Char | Código de barras PDF417 para impresión en documento | Almacenado |
| `sii_barcode_img` | Binary | Imagen del código de barras | Calculado |
| `sii_xml_dte` | Text | XML del DTE firmado para envío | Almacenado |
| `sii_xml_request` | Many2one(sii.xml.envio) | Relación al XML de envío al SII | Almacenado |
| `sii_result` | Selection | Estado de aceptación del SII (Aceptado, Rechazado, Reparo, etc.) | Almacenado |
| `claim` | Selection | Estado del reclamo (ACD, RCD, ERM, RFP, RFT, PAG) | Almacenado |
| `claim_description` | Char | Descripción del reclamo o respuesta del SII | Almacenado |
| `referencias` | One2many(account.invoice.referencias) | Referencias a otros documentos (NC, ND) | Relación |
| `global_descuentos_recargos` | One2many(account.invoice.gdr) | Descuentos/recargos globales del documento | Relación |
| `forma_pago` | Selection | Forma de pago (1=Contado, 2=Crédito, 3=Sin Costo) | Almacenado |
| `ind_servicio` | Selection | Indicador de tipo de servicio (1-5) | Almacenado |
| `responsability_id` | Many2one(sii.responsability) | Tipo de contribuyente del receptor | Almacenado |
| `activity_description` | Many2one(sii.activity.description) | Giro del emisor | Almacenado |
| `acteco_ids` | Many2many(partner.activities) | Actividades económicas aplicables | Relación |

#### Relaciones Clave

```
account.invoice
  ├─> sii.xml.envio (envío al SII)
  ├─> sii.document_class (tipo documento)
  ├─> account.journal.sii_document_class (secuencia)
  ├─> account.invoice.referencias (referencias a otros docs)
  ├─> account.invoice.gdr (descuentos/recargos globales)
  ├─> sii.dte.claim (reclamos del documento)
  ├─> sii.responsability (tipo contribuyente)
  └─> partner.activities (actividades económicas)
```

#### Métodos de Negocio Críticos

1. **`do_dte_send_invoice()`**
   - **Propósito:** Enviar factura al SII
   - **Qué hace:** Crea el DTE, lo firma, genera el XML y lo encola para envío

2. **`_timbrar()`**
   - **Propósito:** Generar el timbre electrónico del documento
   - **Qué hace:** Crea el código de barras PDF417 con datos del documento

3. **`_validar_caf()`**
   - **Propósito:** Validar que existe folio CAF disponible
   - **Qué hace:** Verifica que hay un archivo CAF vigente con folios disponibles

4. **`_dte()`**
   - **Propósito:** Construir estructura del DTE
   - **Qué hace:** Genera el diccionario completo del documento según formato SII

5. **`ask_for_dte_status()`**
   - **Propósito:** Consultar estado del documento en SII
   - **Qué hace:** Consulta el track_id en SII y actualiza el estado

6. **`set_dte_claim()` / `get_dte_claim()`**
   - **Propósito:** Enviar/consultar reclamos de DTE
   - **Qué hace:** Gestiona los reclamos (ACD, RCD, ERM, etc.) ante el SII

7. **`send_exchange()`**
   - **Propósito:** Enviar intercambio de documentos
   - **Qué hace:** Envía el XML del documento al partner vía email

8. **`_totales()`, `_encabezado()`, `_receptor()`, `_emisor()`**
   - **Propósito:** Construir secciones del DTE
   - **Qué hace:** Genera cada sección del XML según especificación SII

9. **`compute_invoice_totals()`**
   - **Propósito:** Calcular totales considerando descuentos/recargos globales
   - **Qué hace:** Recalcula montos aplicando descuentos y recargos globales

10. **`_invoice_lines()`**
    - **Propósito:** Generar líneas de detalle del DTE
    - **Qué hace:** Formatea las líneas de productos/servicios según formato SII

---

### 1.2. account.invoice.referencias

**Archivo:** `account_invoice.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `origen` | Char | Folio del documento original |
| `sii_referencia_TpoDocRef` | Many2one(sii.document_class) | Tipo de documento referenciado |
| `sii_referencia_CodRef` | Selection | Código de referencia (1=Anula, 2=Corrige texto, 3=Corrige montos) |
| `motivo` | Char | Motivo de la referencia |
| `fecha_documento` | Date | Fecha del documento referenciado |
| `sequence` | Integer | Orden de la referencia |

**Propósito:** Permitir referencias a documentos previos (ej: NC que anula factura)

---

### 1.3. account.move.book (21KB) - LIBROS CV

**Archivo:** `libro.py`

#### Campos Funcionales Principales

| Campo | Tipo | Propósito Funcional | Calculado |
|-------|------|---------------------|-----------|
| `tipo_libro` | Selection | Tipo de libro (ESPECIAL, MENSUAL, RECTIFICA) | Almacenado |
| `tipo_operacion` | Selection | Operación (COMPRA, VENTA, BOLETA) | Almacenado |
| `tipo_envio` | Selection | Tipo de envío (AJUSTE, TOTAL, PARCIAL) | Almacenado |
| `periodo_tributario` | Char | Período (YYYY-MM) | Almacenado |
| `move_ids` | Many2many(account.move) | Facturas incluidas en el libro | Relación |
| `impuestos` | One2many(account.move.book.tax) | Resumen de impuestos | Relación |
| `boletas` | One2many(account.move.book.boletas) | Detalle de boletas | Relación |
| `total_afecto` | Monetary | Total afecto a IVA | Calculado, Almacenado |
| `total_exento` | Monetary | Total exento de IVA | Calculado, Almacenado |
| `total_iva` | Monetary | Total IVA | Calculado, Almacenado |
| `sii_xml_request` | Many2one(sii.xml.envio) | XML de envío al SII | Almacenado |
| `state` | Selection | Estado del libro (draft, Enviado, Aceptado, etc.) | Almacenado |

#### Métodos de Negocio

1. **`set_movimientos()`**
   - **Propósito:** Cargar automáticamente facturas del período
   - **Qué hace:** Busca todas las facturas del mes según tipo de operación

2. **`_validar()`**
   - **Propósito:** Validar libro antes de envío
   - **Qué hace:** Genera el XML del libro y lo valida contra el esquema SII

3. **`do_dte_send_book()`**
   - **Propósito:** Enviar libro al SII
   - **Qué hace:** Encola el libro para envío automático al SII

4. **`compute_taxes()`**
   - **Propósito:** Calcular resumen de impuestos
   - **Qué hace:** Agrupa y suma los impuestos de todas las facturas

**Funcionalidad Clave:** Este modelo permite cumplir con la obligación mensual de enviar los libros de compra/venta al SII.

---

### 1.4. account.move.consumo_folios (20KB)

**Archivo:** `consumo_folios.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional | Calculado |
|-------|------|---------------------|-----------|
| `fecha_inicio` | Date | Fecha del consumo | Almacenado |
| `fecha_final` | Date | Fecha final (normalmente = inicio) | Almacenado |
| `sec_envio` | Integer | Secuencia de envío (permite reenvíos) | Almacenado |
| `move_ids` | Many2many(account.move) | Boletas del día | Relación |
| `detalles` | One2many(account.move.consumo_folios.detalles) | Rangos de folios utilizados/anulados | Relación |
| `impuestos` | One2many(account.move.consumo_folios.impuestos) | Resumen de impuestos | Relación |
| `anulaciones` | One2many(account.move.consumo_folios.anulaciones) | Folios anulados | Relación |
| `total_neto` | Monetary | Total neto | Calculado, Almacenado |
| `total_iva` | Monetary | Total IVA | Calculado, Almacenado |
| `total_boletas` | Integer | Cantidad de boletas | Calculado, Almacenado |

#### Métodos de Negocio

1. **`set_data()`**
   - **Propósito:** Cargar automáticamente boletas del día
   - **Qué hace:** Busca todas las boletas emitidas en la fecha seleccionada

2. **`_resumenes()`**
   - **Propósito:** Generar resúmenes de consumo
   - **Qué hace:** Crea los rangos de folios utilizados y anulados

3. **`do_dte_send_consumo_folios()`**
   - **Propósito:** Enviar consumo al SII
   - **Qué hace:** Encola el consumo de folios para envío diario obligatorio

**Funcionalidad Clave:** Permite cumplir con la obligación DIARIA de informar al SII el consumo de folios de boletas.

---

### 1.5. res.partner (18KB)

**Archivo:** `res_partner.py`

#### Campos Funcionales Principales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `document_type_id` | Many2one(sii.document_type) | Tipo de documento (RUT, RUN, etc.) |
| `document_number` | Char | Número de documento (RUT formateado) |
| `responsability_id` | Many2one(sii.responsability) | Responsabilidad tributaria |
| `activity_description` | Many2one(sii.activity.description) | Giro del negocio |
| `acteco_ids` | Many2many(partner.activities) | Códigos de actividad económica |
| `dte_email` | Char | Email para recepción de DTE |
| `dte_email_id` | Many2one(res.partner) | Contacto principal DTE |
| `send_dte` | Boolean | Auto-enviar DTE a este partner |
| `es_mipyme` | Boolean | Usa sistema gratuito MiPyme SII |
| `sync` | Boolean | Sincronizado con servidor remoto |
| `last_sync_update` | Datetime | Última sincronización |

#### Métodos de Negocio

1. **`check_vat_cl()`**
   - **Propósito:** Validar RUT chileno
   - **Qué hace:** Valida el dígito verificador del RUT

2. **`onchange_document()`**
   - **Propósito:** Formatear y validar RUT al ingresarlo
   - **Qué hace:** Formatea xx.xxx.xxx-x y valida unicidad

3. **`fill_partner()`**
   - **Propósito:** Autocompletar datos del partner
   - **Qué hace:** Consulta servidor remoto para obtener datos del RUT

4. **`get_remote_user_data()` / `put_remote_user_data()`**
   - **Propósito:** Sincronizar datos con servidor remoto
   - **Qué hace:** Obtiene/envía información tributaria actualizada

**Funcionalidad Clave:** Validación de RUT y sincronización de datos tributarios con servidor centralizado.

---

### 1.6. account.tax (15KB) - IMPUESTOS Y MEPCO

**Archivo:** `account_tax.py`

#### Campos Funcionales (heredados/extendidos)

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `sii_code` | Integer | Código SII del impuesto |
| `sii_type` | Selection | Tipo SII (A=Adicional, R=Retención) |
| `retencion` | Float | Porcentaje de retención |
| `no_rec` | Boolean | Impuesto no recuperable |
| `mepco` | Selection | Tipo MEPCO (gasolina_93, gasolina_97, diesel, gas_licuado, gas_natural) |
| `uom_id` | Many2one(uom.uom) | Unidad de medida para impuestos específicos |

#### Métodos de Negocio Críticos

1. **`compute_all()`**
   - **Propósito:** Calcular todos los impuestos de una línea
   - **Qué hace:** Sobrescribe método estándar para soportar impuestos chilenos (retenciones, no recuperables, específicos)

2. **`_compute_amount_ret()`**
   - **Propósito:** Calcular monto de retención
   - **Qué hace:** Calcula el monto a retener según porcentaje configurado

3. **`verify_mepco()`**
   - **Propósito:** Actualizar valor MEPCO
   - **Qué hace:** Consulta Diario Oficial para obtener valor actualizado del impuesto específico a combustibles

4. **`_get_from_diario()` / `_get_from_sii()`**
   - **Propósito:** Obtener valores MEPCO desde fuentes oficiales
   - **Qué hace:** Scraping del Diario Oficial o página SII para obtener valores vigentes

**Funcionalidad Clave:** Gestión automática de impuestos específicos a combustibles con actualización desde fuentes oficiales.

---

### 1.7. mail.message.dte.document (13KB)

**Archivo:** `mail_message_dte_document.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `dte_id` | Many2one(mail.message.dte) | Email que contiene el DTE |
| `partner_id` | Many2one(res.partner) | Proveedor del documento |
| `new_partner` | Char | Datos de proveedor nuevo no registrado |
| `document_class_id` | Many2one(sii.document_class) | Tipo de documento |
| `number` | Char | Folio del documento |
| `date` | Date | Fecha de emisión |
| `amount` | Monetary | Monto total |
| `invoice_line_ids` | One2many | Líneas del documento recibido |
| `xml` | Text | XML del documento recibido |
| `state` | Selection | Estado (draft, accepted, rejected) |
| `invoice_id` | Many2one(account.invoice) | Factura creada a partir del DTE |
| `claim` | Selection | Estado del reclamo (ACD, RCD, ERM, etc.) |
| `claim_ids` | One2many(sii.dte.claim) | Historial de reclamos |

#### Métodos de Negocio

1. **`accept_document()`**
   - **Propósito:** Aceptar documento recibido
   - **Qué hace:** Crea la factura de proveedor y envía acuse de recibo

2. **`reject_document()`**
   - **Propósito:** Rechazar documento
   - **Qué hace:** Envía reclamo de rechazo al SII y al emisor

3. **`set_dte_claim()` / `get_dte_claim()`**
   - **Propósito:** Gestionar reclamos de documentos recibidos
   - **Qué hace:** Envía/consulta reclamos ante el SII

4. **`auto_accept_documents()`**
   - **Propósito:** Aceptación automática de documentos antiguos
   - **Qué hace:** Acepta documentos con más de 8 días sin reclamo (aceptación tácita)

**Funcionalidad Clave:** Gestión completa del ciclo de vida de documentos recibidos vía intercambio.

---

### 1.8. sii.dte.claim (12KB)

**Archivo:** `sii_dte_claim.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `document_id` | Many2one(mail.message.dte.document) | Documento de intercambio |
| `invoice_id` | Many2one(account.invoice) | Factura emitida/recibida |
| `claim` | Selection | Tipo de reclamo (ACD, RCD, ERM, RFP, RFT, PAG) |
| `estado_dte` | Selection | Estado de recepción (0=Ok, 1=Discrepancia, 2=Rechazado) |
| `claim_description` | Char | Descripción del reclamo |
| `date` | Datetime | Fecha del reclamo |
| `user_id` | Many2one(res.users) | Usuario que reclama |

#### Métodos de Negocio

1. **`send_claim()`**
   - **Propósito:** Enviar reclamo al SII
   - **Qué hace:** Registra el reclamo en el portal del SII

2. **`do_validar_comercial()`**
   - **Propósito:** Enviar validación comercial
   - **Qué hace:** Genera y envía XML de validación comercial al emisor

3. **`do_recep_mercaderia()`**
   - **Propósito:** Enviar recepción de mercaderías
   - **Qué hace:** Genera y envía XML de recepción de mercaderías

4. **`do_reject()`**
   - **Propósito:** Procesar rechazo comercial
   - **Qué hace:** Genera XML de rechazo y lo envía al emisor

**Funcionalidad Clave:** Gestión completa del sistema de reclamos y validaciones comerciales del SII.

---

### 1.9. sii.cola_envio (8KB)

**Archivo:** `sii_cola_envio.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `doc_ids` | Char | IDs de documentos a procesar (serializado) |
| `model` | Char | Modelo de los documentos |
| `tipo_trabajo` | Selection | Tipo (pasivo, envio, consulta, persistencia) |
| `user_id` | Many2one(res.users) | Usuario que encola |
| `company_id` | Many2one(res.company) | Compañía |
| `date_time` | Datetime | Fecha/hora programada de envío |
| `send_email` | Boolean | Auto-enviar email después |
| `n_atencion` | Char | Número de atención |
| `set_pruebas` | Boolean | Es envío de prueba |

#### Métodos de Negocio

1. **`_procesar_tipo_trabajo()`**
   - **Propósito:** Procesar trabajo encolado
   - **Qué hace:** Ejecuta la acción según tipo (envío, consulta, persistencia)

2. **`_cron_procesar_cola()`**
   - **Propósito:** Cron que procesa cola automáticamente
   - **Qué hace:** Ejecuta trabajos pendientes en lotes de 20

3. **`enviar_email()`**
   - **Propósito:** Enviar email al partner
   - **Qué hace:** Envía intercambio electrónico después de aceptación SII

**Funcionalidad Clave:** Sistema de cola asíncrona para envíos al SII con reintentos automáticos.

---

### 1.10. sii.firma (8KB)

**Archivo:** `sii_firma.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `name` | Char | Nombre del certificado |
| `file_content` | Binary | Archivo .p12 de la firma |
| `password` | Char | Contraseña del certificado |
| `emision_date` | Date | Fecha de emisión del certificado |
| `expire_date` | Date | Fecha de vencimiento |
| `state` | Selection | Estado (unverified, valid, expired) |
| `subject_serial_number` | Char | RUT del titular |
| `subject_common_name` | Char | Nombre del titular |
| `cert` | Text | Certificado en formato PEM |
| `priv_key` | Text | Clave privada en formato PEM |
| `user_ids` | Many2many(res.users) | Usuarios autorizados |
| `company_ids` | Many2many(res.company) | Empresas autorizadas |
| `priority` | Integer | Prioridad de uso |

#### Métodos de Negocio

1. **`action_process()`**
   - **Propósito:** Procesar certificado digital
   - **Qué hace:** Extrae datos del .p12 y los almacena en formato PEM

2. **`check_signature()`**
   - **Propósito:** Verificar vigencia del certificado
   - **Qué hace:** Actualiza estado según fecha de vencimiento

3. **`firmar()`**
   - **Propósito:** Firmar un string/documento
   - **Qué hace:** Firma digitalmente usando la clave privada

4. **`parametros_firma()`**
   - **Propósito:** Obtener parámetros para firma
   - **Qué hace:** Retorna diccionario con cert, priv_key y RUT

5. **`alerta_vencimiento()`**
   - **Propósito:** Alertar sobre vencimiento próximo
   - **Qué hace:** Notifica si faltan menos de 30 días para vencer

**Funcionalidad Clave:** Gestión completa de certificados digitales para firma electrónica de DTEs.

---

### 1.11. dte.caf (5KB)

**Archivo:** `caf.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional | Calculado |
|-------|------|---------------------|-----------|
| `filename` | Char | Nombre del archivo CAF | Almacenado |
| `caf_file` | Binary | Archivo XML del CAF | Almacenado |
| `caf_string` | Text | Contenido XML del CAF | Almacenado |
| `issued_date` | Date | Fecha de emisión | Calculado, Almacenado |
| `expiration_date` | Date | Fecha de vencimiento (6 meses para facturas) | Calculado, Almacenado |
| `sii_document_class` | Integer | Código del tipo de documento | Calculado, Almacenado |
| `start_nm` | Integer | Folio inicial | Calculado, Almacenado |
| `final_nm` | Integer | Folio final | Calculado, Almacenado |
| `status` | Selection | Estado (draft, in_use, spent) | Almacenado |
| `rut_n` | Char | RUT de la empresa | Calculado, Almacenado |
| `sequence_id` | Many2one(ir.sequence) | Secuencia asociada | Almacenado |
| `use_level` | Float | Porcentaje de uso | Calculado |

#### Métodos de Negocio

1. **`load_caf()`**
   - **Propósito:** Cargar y validar archivo CAF
   - **Qué hace:** Extrae datos del XML, valida RUT y tipo de documento

2. **`decode_caf()`**
   - **Propósito:** Decodificar XML del CAF
   - **Qué hace:** Parsea el XML para extraer información

3. **`_set_level()` / `_used_level()`**
   - **Propósito:** Calcular nivel de uso
   - **Qué hace:** Calcula porcentaje de folios utilizados

**Funcionalidad Clave:** Gestión de archivos CAF (Código de Autorización de Folios) necesarios para emitir documentos electrónicos.

---

### 1.12. sii.xml.envio (7KB)

**Archivo:** `sii_xml_envio.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `name` | Char | Nombre del envío |
| `xml_envio` | Text | XML completo a enviar al SII |
| `state` | Selection | Estado (draft, NoEnviado, Enviado, Aceptado, Rechazado) |
| `sii_send_ident` | Text | Track ID del SII |
| `sii_xml_response` | Text | Respuesta inicial del SII |
| `sii_receipt` | Text | Recibo de aceptación/rechazo |
| `invoice_ids` | One2many(account.invoice) | Facturas incluidas |
| `user_id` | Many2one(res.users) | Usuario que envía |
| `company_id` | Many2one(res.company) | Empresa |

#### Métodos de Negocio

1. **`send_xml()`**
   - **Propósito:** Enviar XML al SII
   - **Qué hace:** Envía el sobre electrónico al webservice del SII

2. **`get_send_status()`**
   - **Propósito:** Consultar estado del envío
   - **Qué hace:** Consulta con el track_id el estado de procesamiento

3. **`set_childs()`**
   - **Propósito:** Actualizar estado de documentos hijos
   - **Qué hace:** Propaga el estado a todas las facturas del envío

**Funcionalidad Clave:** Gestión de envíos al SII con seguimiento de estado.

---

### 1.13. account.journal.sii_document_class (2KB)

**Archivo:** `account_journal_sii_document_class.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `journal_id` | Many2one(account.journal) | Diario contable |
| `sii_document_class_id` | Many2one(sii.document_class) | Tipo de documento |
| `sequence_id` | Many2one(ir.sequence) | Secuencia de folios |
| `sequence` | Integer | Orden de presentación |
| `qty_available` | Integer | Folios disponibles |

**Propósito:** Relacionar diarios contables con tipos de documentos tributarios y sus secuencias de folios.

---

### 1.14. account.invoice.gdr (5KB) - Descuentos/Recargos Globales

**Archivo:** `global_descuento_recargo.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional | Calculado |
|-------|------|---------------------|-----------|
| `type` | Selection | Tipo (D=Descuento, R=Recargo) | Almacenado |
| `gdr_type` | Selection | Tipo de cálculo (amount, percent) | Almacenado |
| `valor` | Float | Valor del descuento/recargo | Almacenado |
| `gdr_detail` | Char | Razón del descuento/recargo | Almacenado |
| `aplicacion` | Selection | Aplicación (flete, seguro) | Almacenado |
| `impuesto` | Selection | Sobre qué se aplica (afectos, exentos, no_facturables) | Almacenado |
| `amount_untaxed_global_dr` | Float | Monto calculado | Calculado |
| `invoice_id` | Many2one(account.invoice) | Factura | Almacenado |

#### Métodos de Negocio

1. **`_untaxed_gdr()`**
   - **Propósito:** Calcular monto del descuento/recargo
   - **Qué hace:** Calcula el monto según porcentaje o monto fijo

2. **`get_agrupados()`**
   - **Propósito:** Agrupar descuentos/recargos
   - **Qué hace:** Suma descuentos y recargos por tipo

3. **`get_monto_aplicar()`**
   - **Propósito:** Obtener monto total a aplicar
   - **Qué hace:** Calcula el neto de descuentos menos recargos

**Funcionalidad Clave:** Gestión de descuentos/recargos globales según normativa SII (ej: descuento por pago anticipado, recargo por flete).

---

### 1.15. account.tax.mepco (1KB)

**Archivo:** `account_tax_mepco.py`

#### Campos Funcionales

| Campo | Tipo | Propósito Funcional |
|-------|------|---------------------|
| `type` | Selection | Tipo de combustible |
| `date` | Date | Fecha de vigencia |
| `amount` | Float | Monto en CLP |
| `factor` | Float | Factor en UTM |
| `sequence` | Integer | Secuencia |
| `company_id` | Many2one(res.company) | Empresa |

**Propósito:** Almacenar histórico de valores MEPCO (impuesto específico a combustibles).

---

## 2. DIAGRAMA DE RELACIONES ENTRE MODELOS

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FACTURACIÓN ELECTRÓNICA CHILE                     │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│   res.company        │
│  - dte_resolution    │──┐
│  - dte_service       │  │
│  - activity_desc     │  │
└──────────────────────┘  │
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ sii.firma    │  │ dte.caf      │  │ res.partner  │
│ - cert       │  │ - folios     │  │ - RUT        │
│ - priv_key   │  │ - vigencia   │  │ - giro       │
│ - expire     │  │ - uso %      │  │ - acteco     │
└──────────────┘  └──────────────┘  └──────────────┘
         │                │                │
         │                │                │
         └────────────────┼────────────────┘
                          │
                          ▼
         ┌────────────────────────────────┐
         │     account.invoice            │
         │  MODELO CENTRAL                │
         │  - document_class_id           │
         │  - sii_xml_dte                │
         │  - sii_barcode                │
         │  - referencias                 │
         │  - global_descuentos_recargos │
         │  - claim                       │
         └────────────────────────────────┘
                 │        │         │
        ┌────────┼────────┼─────────┼────────┐
        │        │        │         │        │
        ▼        ▼        ▼         ▼        ▼
┌─────────┐ ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│sii.xml. │ │invoice. │ │inv.  │ │sii.  │ │mail.msg. │
│envio    │ │referen. │ │gdr   │ │dte.  │ │dte.doc   │
│         │ │cias     │ │      │ │claim │ │          │
│-xml     │ │         │ │-desc │ │      │ │-xml      │
│-track_id│ │-origen  │ │-rec  │ │-ACD  │ │-partner  │
│-state   │ │-tipo    │ │      │ │-RCD  │ │-state    │
└─────────┘ └─────────┘ └──────┘ └──────┘ └──────────┘
     │                                            │
     │                                            │
     ▼                                            ▼
┌─────────────┐                          ┌──────────────┐
│sii.cola_    │                          │sii.respuesta_│
│envio        │                          │cliente       │
│             │                          │              │
│-tipo_trabajo│                          │-recep_envio  │
│-date_time   │                          │-recep_mercad │
│-send_email  │                          │              │
└─────────────┘                          └──────────────┘

         LIBROS Y CONSUMOS
         ─────────────────
┌────────────────────┐       ┌─────────────────────┐
│account.move.book   │       │account.move.        │
│                    │       │consumo_folios       │
│-tipo_operacion     │       │                     │
│-periodo_tributario │       │-fecha_inicio        │
│-move_ids           │       │-detalles (rangos)   │
│-impuestos          │       │-impuestos           │
│-boletas            │       │-anulaciones         │
└────────────────────┘       └─────────────────────┘
         │                            │
         │                            │
         └──────────┬─────────────────┘
                    ▼
            ┌──────────────┐
            │sii.xml.envio │
            │(compartido)  │
            └──────────────┘

         IMPUESTOS
         ─────────
┌────────────────────┐
│account.tax         │
│ - sii_code         │
│ - sii_type         │
│ - retencion        │
│ - no_rec           │
│ - mepco            │
└────────────────────┘
         │
         ▼
┌────────────────────┐
│account.tax.mepco   │
│ - type             │
│ - date             │
│ - amount           │
│ - factor (UTM)     │
└────────────────────┘
```

---

## 3. FLUJOS FUNCIONALES PRINCIPALES

### 3.1. Flujo de Emisión de DTE

```
1. Usuario crea factura
   ├─> Selecciona tipo de documento (document_class_id)
   ├─> Selecciona secuencia de folios (journal_document_class_id)
   └─> Ingresa líneas de productos/servicios

2. Usuario valida factura (invoice_validate)
   ├─> Valida existencia de CAF con folios disponibles
   ├─> Asigna folio siguiente
   ├─> Genera estructura del DTE (_dte)
   │   ├─> Encabezado (_encabezado)
   │   ├─> Emisor (_emisor)
   │   ├─> Receptor (_receptor)
   │   ├─> Totales (_totales)
   │   ├─> Líneas (_invoice_lines)
   │   └─> Descuentos/Recargos (_gdr)
   ├─> Genera timbre electrónico (_timbrar)
   │   └─> Crea código de barras PDF417
   └─> Almacena XML del DTE (sii_xml_dte)

3. Usuario envía al SII (do_dte_send_invoice)
   ├─> Obtiene firma digital del usuario
   ├─> Crea sobre electrónico (_crear_envio)
   ├─> Firma el sobre digitalmente
   ├─> Crea registro sii.xml.envio
   └─> Encola para envío (sii.cola_envio)

4. Cron procesa cola (_cron_procesar_cola)
   ├─> Envía XML al webservice SII (send_xml)
   ├─> Obtiene track_id
   ├─> Actualiza estado a 'Enviado'
   └─> Encola consulta de estado

5. Cron consulta estado
   ├─> Consulta con track_id (get_send_status)
   ├─> Obtiene respuesta del SII
   ├─> Actualiza estado (Aceptado/Rechazado/Reparo)
   └─> Si aceptado: envía email al partner
```

### 3.2. Flujo de Recepción de DTE

```
1. Email recibido con DTE adjunto
   ├─> Plugin de correo detecta XML
   ├─> Crea mail.message.dte
   └─> Crea mail.message.dte.document

2. Usuario revisa documento recibido
   ├─> Visualiza datos del XML
   ├─> Decide aceptar o rechazar
   └─> Puede asignar a factura existente

3. Usuario acepta documento (accept_document)
   ├─> Crea factura de proveedor desde XML
   ├─> Envía acuse de recibo al SII
   │   └─> Genera validación comercial
   ├─> Envía email al emisor
   └─> Actualiza estado a 'accepted'

4. Usuario puede enviar reclamo (set_dte_claim)
   ├─> Selecciona tipo de reclamo (ACD, RCD, ERM, etc.)
   ├─> Envía reclamo al SII
   └─> Envía notificación al emisor
```

### 3.3. Flujo de Libros de Compra/Venta

```
1. Fin de mes: Usuario crea libro
   ├─> Selecciona período tributario (YYYY-MM)
   ├─> Selecciona tipo (COMPRA/VENTA/BOLETA)
   └─> Libro autocarga facturas del mes (set_movimientos)

2. Sistema calcula totales
   ├─> Agrupa facturas por tipo de documento
   ├─> Suma totales afecto, exento, IVA
   ├─> Calcula resumen de impuestos (compute_taxes)
   └─> Genera detalles de boletas si aplica

3. Usuario valida libro (_validar)
   ├─> Genera XML del libro según formato SII
   ├─> Valida estructura XML
   └─> Almacena en sii.xml.envio

4. Usuario envía libro (do_dte_send_book)
   ├─> Encola libro para envío
   ├─> Cron envía al SII
   ├─> Consulta estado
   └─> Actualiza a Aceptado/Rechazado
```

### 3.4. Flujo de Consumo de Folios

```
1. Fin del día: Usuario crea consumo de folios
   ├─> Selecciona fecha (fecha_inicio)
   ├─> Sistema autocarga boletas del día (set_data)
   └─> Calcula secuencia de envío (sec_envio)

2. Sistema genera resúmenes (_resumenes)
   ├─> Detecta rangos de folios utilizados
   ├─> Detecta rangos de folios anulados
   ├─> Calcula totales por tipo de boleta
   └─> Agrupa impuestos

3. Usuario valida consumo (validar_consumo_folios)
   ├─> Genera XML de consumo de folios
   ├─> Anula consumos anteriores del mismo día
   └─> Cambia estado a 'NoEnviado'

4. Usuario envía consumo (do_dte_send_consumo_folios)
   ├─> Encola para envío
   ├─> Cron envía al SII
   └─> Actualiza estado según respuesta
```

### 3.5. Flujo de Actualización MEPCO

```
1. Cron diario ejecuta actualización MEPCO
   ├─> Para cada impuesto tipo MEPCO
   └─> Verifica valor vigente (verify_mepco)

2. Si no existe valor actual
   ├─> Consulta Diario Oficial (_list_from_diario)
   ├─> Scraping del PDF del diario
   ├─> Extrae valor en UTM
   ├─> Convierte UTM a CLP
   ├─> Crea registro account.tax.mepco
   └─> Actualiza amount del impuesto

3. Al facturar producto con MEPCO
   ├─> Obtiene valor vigente a la fecha
   ├─> Calcula impuesto = cantidad × mepco
   └─> Aplica a la línea
```

---

## 4. VALIDACIONES Y REGLAS DE NEGOCIO

### 4.1. Validaciones de Facturación

1. **Validación de RUT**
   - El RUT debe tener formato válido (xx.xxx.xxx-x)
   - El dígito verificador debe ser correcto
   - El RUT debe ser único por partner comercial

2. **Validación de Folios (CAF)**
   - Debe existir un CAF vigente para el tipo de documento
   - El CAF debe tener folios disponibles
   - El CAF no debe estar vencido (6 meses para facturas)
   - El RUT del CAF debe coincidir con el RUT de la empresa

3. **Validación de Documentos de Referencia**
   - Las NC deben referenciar un documento válido
   - El código de referencia debe ser apropiado (1=Anula, 2=Corrige texto, 3=Corrige montos)
   - El tipo de documento de referencia debe existir

4. **Validación de Totales**
   - Los descuentos globales no pueden ser mayores al neto
   - Los totales deben cuadrar con la suma de líneas
   - Los impuestos deben calcularse correctamente

### 4.2. Reglas de Negocio SII

1. **Plazos de Envío**
   - Facturas: hasta el mes siguiente
   - Boletas (consumo folios): máximo día siguiente
   - Libros CV: antes del día 10 del mes siguiente

2. **Reclamos de DTE**
   - Período de reclamo: 8 días desde recepción
   - Aceptación tácita: sin reclamo en 8 días
   - Tipos de reclamo válidos: ACD, RCD, ERM, RFP, RFT, PAG

3. **Tipos de Documento**
   - 33: Factura electrónica
   - 34: Factura exenta electrónica
   - 39: Boleta electrónica
   - 41: Boleta exenta electrónica
   - 52: Guía de despacho electrónica
   - 56: Nota de débito electrónica
   - 61: Nota de crédito electrónica

4. **Validaciones Comerciales**
   - 0: DTE Recibido Ok
   - 1: DTE Aceptado con Discrepancia
   - 2: DTE Rechazado

---

## 5. CAMPOS CALCULADOS Y DEPENDENCIAS

### 5.1. Campos Calculados Principales

#### account.invoice

| Campo Calculado | Dependencias | Propósito |
|-----------------|--------------|-----------|
| `sii_barcode_img` | `sii_barcode` | Genera imagen PNG del código de barras |
| `amount_untaxed` | `invoice_line_ids`, `global_descuentos_recargos` | Calcula neto con descuentos/recargos globales |
| `amount_tax` | `invoice_line_ids`, `tax_line_ids` | Suma total de impuestos |
| `amount_total` | `amount_untaxed`, `amount_tax` | Total del documento |

#### account.move.book

| Campo Calculado | Dependencias | Propósito |
|-----------------|--------------|-----------|
| `total_afecto` | `move_ids` | Suma montos afectos de todas las facturas |
| `total_exento` | `move_ids` | Suma montos exentos |
| `total_iva` | `move_ids` | Suma IVA de todas las facturas |
| `total_otros_imps` | `move_ids` | Suma otros impuestos |

#### account.move.consumo_folios

| Campo Calculado | Dependencias | Propósito |
|-----------------|--------------|-----------|
| `total_neto` | `impuestos` | Total neto de boletas |
| `total_iva` | `impuestos` | Total IVA |
| `total_boletas` | `detalles` | Cantidad de boletas emitidas |

#### dte.caf

| Campo Calculado | Dependencias | Propósito |
|-----------------|--------------|-----------|
| `use_level` | `sequence_id.number_next`, `start_nm`, `final_nm` | Porcentaje de folios utilizados |
| `start_nm` | `caf_file` | Folio inicial extraído del XML |
| `final_nm` | `caf_file` | Folio final extraído del XML |

### 5.2. Triggers y Onchanges Importantes

#### account.invoice

```python
@api.onchange('journal_id')
def _onchange_journal_id():
    # Actualiza tipos de documento disponibles
    # Carga valores por defecto de la compañía
```

```python
@api.onchange('partner_id')
def _onchange_partner_id():
    # Actualiza giro, responsabilidad tributaria
    # Carga email DTE del partner
```

```python
@api.onchange('global_descuentos_recargos')
def _onchange_descuentos():
    # Recalcula totales de factura
    # Actualiza taxes según nuevos montos
```

#### res.partner

```python
@api.onchange('document_number')
def onchange_document():
    # Valida formato de RUT
    # Verifica dígito verificador
    # Autocompleta datos desde servidor remoto
    # Valida unicidad del RUT
```

---

## 6. CONCLUSIONES Y KNOW-HOW A PRESERVAR

### 6.1. Know-How Crítico Funcional

#### 1. Generación de DTE según Especificación SII
- Estructura exacta del XML DTE
- Cálculo del timbre electrónico
- Generación del código de barras PDF417
- Formato de fechas, montos y campos según norma

#### 2. Gestión de Folios CAF
- Validación de vigencia de CAF
- Control de rangos de folios
- Asignación secuencial de folios
- Alertas de agotamiento y vencimiento

#### 3. Sistema de Reclamos DTE
- Códigos de reclamo (ACD, RCD, ERM, RFP, RFT, PAG)
- Plazos de reclamo (8 días)
- Aceptación tácita
- Flujo de validación comercial
- Recepción de mercaderías

#### 4. Libros de Compra/Venta
- Agrupación por período tributario
- Generación de resúmenes de impuestos
- Detalle de boletas
- Formato XML de libro CV

#### 5. Consumo de Folios Diario
- Detección automática de rangos utilizados/anulados
- Cálculo de totales por tipo de boleta
- Secuencia de envíos del mismo día

#### 6. Cola de Envíos Asíncrona
- Tipos de trabajo (envío, consulta, persistencia)
- Reintentos automáticos
- Programación de envíos
- Persistencia de intentos

#### 7. Impuestos Específicos MEPCO
- Actualización automática desde Diario Oficial
- Scraping de PDF del diario
- Conversión UTM a CLP
- Histórico de valores

#### 8. Descuentos/Recargos Globales
- Aplicación sobre afectos/exentos
- Cálculo por monto o porcentaje
- Tipos de aplicación (flete, seguro)
- Validaciones de límites

#### 9. Validación de RUT Chileno
- Algoritmo de validación de dígito verificador
- Formateo automático
- Verificación de unicidad

#### 10. Sincronización de Partners
- Integración con servidor remoto
- Autocarga de datos tributarios
- Sincronización bidireccional
- Detección de cambios

### 6.2. Funcionalidades Únicas del Sistema

1. **Intercambio Electrónico de DTEs**
   - Recepción de DTEs vía email
   - Procesamiento automático de XML
   - Creación de facturas desde XML recibido
   - Envío de acuses de recibo

2. **Sistema de Firmas Múltiples**
   - Gestión de múltiples certificados digitales
   - Asignación por usuario y empresa
   - Priorización de certificados
   - Alertas de vencimiento

3. **Integración con Servidor de Partners**
   - Base de datos centralizada de contribuyentes
   - Actualización automática de datos
   - Sincronización bidireccional
   - Logo y datos completos del partner

4. **Gestión de Boletas Electrónicas**
   - Consumo de folios diario automático
   - Agrupación por tipo de boleta
   - Cálculo de rangos utilizados/anulados
   - Resumen de impuestos por tipo

5. **Valores MEPCO Automáticos**
   - Scraping del Diario Oficial
   - Parsing de PDF del decreto
   - Conversión automática UTM-CLP
   - Actualización diaria vía cron

### 6.3. Configuraciones y Parámetros Críticos

#### res.company
- `dte_service_provider`: SII o SIICERT (producción/certificación)
- `dte_resolution_number`: Número de resolución SII
- `dte_resolution_date`: Fecha de resolución
- `dte_email_id`: Email para envío de DTEs

#### ir.config_parameter
- `partner.url_remote_partners`: URL servidor de partners
- `partner.token_remote_partners`: Token de autenticación
- `partner.sync_remote_partners`: Activar sincronización
- `account.auto_send_persistencia`: Horas de persistencia

#### Secuencias (ir.sequence)
- Una secuencia por cada tipo de documento y empresa
- Debe estar vinculada a un CAF
- Control de folios disponibles

---

## 7. RECOMENDACIONES PARA MIGRACIÓN A ODOO 19

### 7.1. Prioridades de Preservación

**ALTA PRIORIDAD:**
1. Estructura de generación de DTEs (métodos `_dte`, `_encabezado`, `_totales`, etc.)
2. Sistema de firma digital y timbraje
3. Gestión de folios CAF
4. Cola de envíos asíncrona
5. Sistema de reclamos DTE
6. Validación de RUT chileno

**MEDIA PRIORIDAD:**
7. Libros de compra/venta
8. Consumo de folios
9. Descuentos/recargos globales
10. Impuestos MEPCO

**BAJA PRIORIDAD:**
11. Sincronización de partners (evaluar si sigue siendo necesario)
12. Scraping de Diario Oficial (puede reemplazarse por API si existe)

### 7.2. Áreas de Modernización

1. **Reemplazar Scraping por APIs**
   - Evaluar si SII ofrece API para valores MEPCO
   - Considerar servicios de terceros para datos de contribuyentes

2. **Mejorar Cola de Envíos**
   - Evaluar uso de Odoo queue_job
   - Implementar mejor manejo de errores
   - Dashboard de monitoreo de envíos

3. **Optimizar Cálculo de Impuestos**
   - Revisar sobrescritura de `compute_all`
   - Evaluar uso de account_tax nativo de Odoo 19

4. **Modernizar UI/UX**
   - Wizards más intuitivos
   - Dashboards de estado de DTEs
   - Alertas proactivas

### 7.3. Dependencias Externas Críticas

**Bibliotecas Python:**
- `facturacion_electronica`: Librería core de FE (CRÍTICA)
- `pdf417gen`: Generación de código de barras
- `PyMuPDF (fitz)`: Parsing de PDFs del Diario Oficial
- `OpenSSL/crypto`: Manejo de certificados digitales
- `lxml`: Parsing y generación de XML
- `urllib3`: Comunicación con servicios web

**Servicios Externos:**
- Webservices SII (producción/certificación)
- Diario Oficial (para MEPCO)
- Servidor de partners (si se mantiene)

### 7.4. Riesgos Identificados

1. **Compatibilidad de Firma Digital**
   - Verificar compatibilidad de OpenSSL con Odoo 19
   - Probar certificados digitales en nuevo entorno

2. **Cambios en Especificación SII**
   - Verificar cambios en formato XML DTE
   - Revisar nuevos tipos de documento
   - Validar esquemas XSD vigentes

3. **Estructura de Impuestos**
   - Cambios en account.tax de Odoo 19
   - Compatibilidad con impuestos compuestos
   - Retenciones y no recuperables

4. **Migración de CAFs**
   - Preservar archivos CAF vigentes
   - Migrar folios utilizados
   - No perder control de secuencias

---

## 8. ANEXO: TIPOS DE DOCUMENTO SII

### Documentos Soportados (según código)

| Código | Descripción | Uso |
|--------|-------------|-----|
| 29 | Factura de Inicio | Migración de saldos |
| 30 | Factura | Papel (descontinuado) |
| 32 | Factura de Ventas y Servicios No Afectos o Exentos | Papel |
| 33 | Factura Electrónica | **PRINCIPAL - Facturas afectas** |
| 34 | Factura No Afecta o Exenta Electrónica | **Facturas exentas** |
| 35 | Boleta | Papel |
| 38 | Boleta Exenta | Papel |
| 39 | Boleta Electrónica | **PRINCIPAL - Boletas afectas** |
| 40 | Liquidación Factura | Compras a productores agrícolas |
| 41 | Boleta Exenta Electrónica | **Boletas exentas** |
| 43 | Liquidación-Factura Electrónica | Compras agrícolas |
| 45 | Factura de Compra | Compras a no contribuyentes |
| 46 | Factura de Compra Electrónica | Compras electrónicas |
| 48 | Comprobante de Pago Electrónico | Pagos |
| 52 | Guía de Despacho | Papel |
| 55 | Nota de Débito | Papel |
| 56 | Nota de Débito Electrónica | **Notas de débito** |
| 60 | Nota de Crédito | Papel |
| 61 | Nota de Crédito Electrónica | **PRINCIPAL - Notas de crédito** |
| 101-112 | Facturas de Exportación | Exportaciones |
| 175 | Nota de Crédito de Exportación Electrónica | NC Exportación |
| 180-185 | Facturas de Compra | Diversos |
| 500-501 | Documentos de Ajuste | Ajustes contables |
| 900-924 | Otros Documentos | Documentos especiales |

---

## 9. MÉTRICAS DEL ANÁLISIS

**Archivos Analizados:** 15 de 42 (modelos críticos)  
**Líneas de Código Revisadas:** ~2,500 líneas  
**Campos Documentados:** 150+ campos funcionales  
**Métodos de Negocio Identificados:** 80+ métodos  
**Relaciones Mapeadas:** 35+ relaciones entre modelos  
**Flujos Documentados:** 5 flujos principales  
**Dependencias Externas:** 6 bibliotecas críticas  

---

**FIN DEL ANÁLISIS**

Este análisis funcional será la base para la migración del módulo l10n_cl_fe de Odoo 11 a Odoo 19, preservando todo el know-how funcional crítico identificado.
