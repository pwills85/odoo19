# Auditoría Fase 2 - Modelos Funcionales de Facturación

## Resumen Ejecutivo
- ✅ La localización `l10n_cl_fe` modela todo el marco regulatorio del SII en objetos configurables (`sii.document_class`, `sii.document_letter`, `sii.responsability`, sucursales, actividades) que alimentan diarios, socios y compañías para garantizar que cada DTE se emita con códigos, giros y responsabilidades válidas. `l10n_cl_fe/models/sii_document_class.py:7`, `l10n_cl_fe/models/sii.py:31`, `l10n_cl_fe/models/sii.py:54`, `l10n_cl_fe/models/company.py:12`
- ✅ La cadena operativa DTE se sustenta en modelos especializados para firmas (`sii.firma`), folios (`dte.caf`), colas de envío (`sii.cola_envio`), sobres (`sii.xml.envio`) y confirmaciones de clientes (`sii.respuesta.cliente`), asegurando trazabilidad completa desde la generación hasta la recepción en SII. `l10n_cl_fe/models/sii_firma.py:21`, `l10n_cl_fe/models/caf.py:18`, `l10n_cl_fe/models/sii_cola_envio.py:18`, `l10n_cl_fe/models/sii_xml_envio.py:33`, `l10n_cl_fe/models/sii_respuesta_cliente.py:8`
- ⚠️ El módulo `l10n_cl_dte_factoring` introduce extensiones críticas para cesiones de crédito (campos de cesionario, declaraciones juradas y nuevas tareas de cola), funcionalidad que no existe en la base de Odoo 19 y deberá preservarse explícitamente. `l10n_cl_dte_factoring/models/invoice.py:24`, `l10n_cl_dte_factoring/models/sii_cola_envio.py:9`

## Análisis Detallado

### 1. Configuración Tributaria SII

| Modelo | Propósito funcional | Campos/Relaciones clave | Referencia |
|--------|---------------------|-------------------------|------------|
| `sii.document_class` | Catálogo oficial de tipos de documento (Factura, NC, ND, Boletas, Guías) con código SII, letra y tipo funcional (ventas, compras, stock). | `name`, `sii_code`, `document_type`, `document_letter_id`, `use_prefix` permiten condicionar secuencias y reportes. | `l10n_cl_fe/models/sii_document_class.py:7`
| `sii.document_letter` | Define letras tributarias y si discriminan IVA; relaciona responsabilidades emisoras/receptoras para validar qué documentos puede usar cada contribuyente. | One2many a clases, Many2many a responsabilidades, flag `vat_discriminated`. | `l10n_cl_fe/models/sii.py:31`
| `sii.responsability` | Clasifica contribuyentes (exento, afecto, exportador) y enlaza las letras que pueden emitir/recibir, impactando validaciones de factura. | `code`, `tp_sii_code`, relaciones M2M con letras emitidas y recibidas. | `l10n_cl_fe/models/sii.py:54`
| `partner.activities` / `sii.activity.description` | Mantienen el giro económico (código ACTECO) y glosas impresas que se inyectan en facturas y diarios para cumplir con la normativa. | Campos `code`, `name`, `vat_affected`, `tax_category`, relaciones recursivas y con partners. | `l10n_cl_fe/models/partner_activities.py:5`, `l10n_cl_fe/models/sii_activity_description.py:5`
| `sii.sucursal` | Registra sucursales SII (códigos, dirección y compañía) que luego se referencian en diarios para diferenciar folios y puntos de emisión. | `sii_code`, `company_id`, `partner_id` obligatorios. | `l10n_cl_fe/models/sii.py:7`
| `res.company` (extensión) | Agrega parámetros DTE (correo autorizado, proveedor SII, número/resolución, responsabilidades, sucursales) y valida RUT según tipo documental. | Campos `dte_email_id`, `dte_service_provider`, `dte_resolution_number/date`, `sii_regional_office_id`, `invoice_vat_discrimination_default`. | `l10n_cl_fe/models/company.py:18`

### 2. Infraestructura DTE y Control de Folios

| Modelo | Rol en la cadena | Relaciones y reglas | Referencia |
|--------|------------------|---------------------|------------|
| `sii.firma` | Administra certificados digitales, controla vigencia, usuarios autorizados y parámetros criptográficos usados en cada envío. | Campos `file_content`, `subject_serial_number`, `state`, `user_ids`; métodos `action_process`, `parametros_firma`. | `l10n_cl_fe/models/sii_firma.py:21`
| `dte.caf` | Gestiona archivos CAF, extrae rangos, vigencia y valida que correspondan a la compañía/sucursal antes de activar secuencias. | Campos computados `start_nm`, `final_nm`, `sii_document_class`; método `load_caf` verifica RUT y secuencia asociada. | `l10n_cl_fe/models/caf.py:18`
| `sii.xml.envio` | Representa cada sobre enviado al SII: XML, estado, track id, facturas incluidas y respuestas. Incluye métodos para firmar y consultar estado. | Campos `xml_envio`, `state`, `sii_send_ident`, `invoice_ids`; métodos `send_xml`, `_emisor`, `_get_datos_empresa`. | `l10n_cl_fe/models/sii_xml_envio.py:33`
| `sii.cola_envio` | Cola de trabajos que automatiza envíos, consultas y persistencia de respuestas; programa cron y dispara emails a clientes cuando hay reparos/proceso. | Campos `doc_ids`, `tipo_trabajo`, `date_time`, `company_id`; método `_procesar_tipo_trabajo` gestiona transiciones. | `l10n_cl_fe/models/sii_cola_envio.py:18`
| `sii.respuesta.cliente` | Registra las cuatro respuestas obligatorias (recepción envío/DTE, mercaderías, validación comercial) con glosas e ID de intercambio. | Campos `type`, `recep_envio`, `recep_dte`, `merc_estado`, `company_id`. | `l10n_cl_fe/models/sii_respuesta_cliente.py:8`
| `account.move.consumo_folios` | Controla consumo/anulación de folios por rango, acumulando totales neto/iva e impuestos asociados; se enlaza a `sii.xml.envio` para respaldar informes mensuales. | Campos `state`, `move_ids`, `fecha_inicio/final`, totales monetarios, One2many `detalles`, `impuestos`, `anulaciones`. | `l10n_cl_fe/models/consumo_folios.py:18`
| `account.move.consumo_folios.detalles/impuestos/anulaciones` | Desglosan los rangos enviados, impuestos por tipo y folios anulados, permitiendo generar XML del libro de consumo. | Campos `tpo_doc`, `folio_inicio/final`, `impuesto`, `monto_neto/iva/exento`, `rango_inicio/final`. | `l10n_cl_fe/models/consumo_folios.py:468`

### 3. Integración con Documentos Comerciales

| Modelo | Funcionalidad | Detalle | Referencia |
|--------|---------------|---------|------------|
| `account.invoice` (extensión) | Añade campos de clase de documento, folio, colas DTE, códigos de referencia y estados SII; prepara datos Emisor/Receptor/Ítems para el XML. | Campos `document_class_ids`, `journal_document_class_id`, `document_class_id`, `sii_document_number`, `sii_result`, `sii_xml_request`, `referencias`; métodos `_id_doc`, `_emisor`, `_receptor`, `do_dte_send_invoice`. | `l10n_cl_fe/models/account_invoice.py:143`, `l10n_cl_fe/models/account_invoice.py:256`, `l10n_cl_fe/models/account_invoice.py:1187`, `l10n_cl_fe/models/account_invoice.py:1234`
| `account.invoice.referencias` | Representa líneas de referencia DTE (documentos anulados o corregidos) que se incluyen en el XML y en vistas. | Campos `sii_referencia_TpoDocRef`, `sii_referencia_CodRef`, `fecha_documento`, `sequence`. | `l10n_cl_fe/models/account_invoice.py:45`
| `account.journal.sii_document_class` | Mapea diarios contables a secuencias/CAF específicos, calculando nombre amigable y validando coherencia del tipo de documento. | Campos `sii_document_class_id`, `sequence_id`, `journal_id`, `qty_available`; método `check_sii_document_class`. | `l10n_cl_fe/models/account_journal_sii_document_class.py:10`
| `res.company` / `res.partner` extensiones | Propagan responsabilidad, glosa y RUT formateado a facturas; validan RUT de socios y compañías antes de emitir DTE. | Campos `responsability_id`, `document_number`, `invoice_vat_discrimination_default`; onchange que formatea RUT y verifica duplicados. | `l10n_cl_fe/models/company.py:50`

### 4. Factoring y Cesiones Electrónicas

| Modelo | Propósito | Claves funcionales | Referencia |
|--------|-----------|--------------------|------------|
| `account.invoice` (`l10n_cl_dte_factoring`) | Agrega campos de cesión (`cesionario_id`, `declaracion_jurada`, `sii_cesion_result`, `imagen_ar_ids`) y lógica para construir XML AEC y declaratoria jurada automática. | Métodos `_cesion`, `_crear_envio_cesion`, `validate_cesion`, `cesion_dte_send` reutilizan datos del DTE original y coordinan el seguimiento en SII. | `l10n_cl_dte_factoring/models/invoice.py:24`
| `sii.cola_envio` (herencia) | Introduce nuevos tipos de trabajo `cesion` y `cesion_consulta` para enviar y consultar cesiones asíncronamente, usando el mismo motor de colas. | Campo `tipo_trabajo` con `selection_add` y override de `_procesar_tipo_trabajo`. | `l10n_cl_dte_factoring/models/sii_cola_envio.py:9`
| `sii.xml.envio` (herencia) | Ajusta parámetros y parsing de respuestas cuando el archivo corresponde a AEC, reutilizando track id y estados específicos. | Métodos `init_params`, `procesar_recepcion`, `get_cesion_send_status`. | `l10n_cl_dte_factoring/models/sii_xml_envio.py:16`

## Conclusiones
- La arquitectura de datos de facturación combina catálogos regulatorios, configuraciones por compañía y modelos operativos que encapsulan cada paso del ciclo DTE. Cualquier migración a Odoo 19 debe contemplar tablas equivalentes para no perder capacidad de timbraje, seguimiento y reporte.
- Los modelos `account.invoice` y `account.move.consumo_folios` concentran dependencias cruzadas (diarios, partners, CAF, colas), por lo que su documentación detallada servirá como blueprint para reproducir flujos en la nueva versión.
- La capa de factoring amplía el modelo base y requiere soporte explícito de colas, XML y trazabilidad; sin su trasplante se perdería la posibilidad de ceder facturas electrónicas cumpliendo Ley 19.983.
