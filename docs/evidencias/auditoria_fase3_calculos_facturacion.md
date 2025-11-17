# Auditoría Fase 3 - Cálculos y Lógica de Negocio (Facturación)

## Resumen Ejecutivo
- ✅ Los totales tributarios se calculan en capas: primero se validan montos netos/exentos a partir de líneas de impuestos (`_totales`), luego se generan estructuras específicas para moneda nacional u otra moneda (`_totales_normal`, `_totales_otra_moneda`) antes de integrarse al XML DTE. `l10n_cl_fe/models/account_invoice.py:1327`, `l10n_cl_fe/models/account_invoice.py:1355`, `l10n_cl_fe/models/account_invoice.py:1387`
- ✅ La generación del sobre DTE se basa en funciones que arman el encabezado (`_id_doc`, `_emisor`, `_receptor`), agrupan documentos y llaman a la librería `facturacion_electronica` para timbrar y enviar; los estados se monitorean mediante colas y consultas periódicas. `l10n_cl_fe/models/account_invoice.py:1234`, `l10n_cl_fe/models/account_invoice.py:1258`, `l10n_cl_fe/models/account_invoice.py:1290`, `l10n_cl_fe/models/account_invoice.py:1725`
- ✅ Los procesos de consumo de folios y exportación de libros derivan automáticamente resúmenes por tipo de documento, totales de boletas y folios anulados, asegurando cumplimiento con reportes SII. `l10n_cl_fe/models/consumo_folios.py:187`
- ⚠️ Las cesiones electrónicas agregan una segunda capa de cálculos (monto cedido, declaraciones juradas, seguimiento `sii_cesion_result`) que no está cubierta por los módulos base de Odoo 19. `l10n_cl_dte_factoring/models/invoice.py:56`

## Análisis Detallado

### 1. Impuestos, Descuentos y Totales

| Función / Modelo | Lógica funcional | Referencia |
|------------------|------------------|------------|
| `compute_invoice_totals` (`account.invoice`) | Ajusta líneas contables aplicando descuentos globales (`porcentaje_dr`) y normaliza diferencias entre moneda de la factura y moneda compañía antes de postear. | `l10n_cl_fe/models/account_invoice.py:399`
| `_totales` | Recorre impuestos para separar montos netos (códigos 14/15), bases especiales (código 17) y validar que documentos exentos no incluyan líneas afectas; retorna la tupla base para construir el bloque Totales. | `l10n_cl_fe/models/account_invoice.py:1387`
| `_totales_normal` / `_totales_otra_moneda` | Construyen el diccionario `Totales` con moneda, MntNeto, MntExe, IVA, tasa y MntTotal; cuando la moneda difiere se recalcula usando `currency_id.compute`. | `l10n_cl_fe/models/account_invoice.py:1327`, `l10n_cl_fe/models/account_invoice.py:1355`
| `account.move.consumo_folios.get_totales` | Suma IVA, exento y total de boletas solo para documentos 39/41, asegurando reporte mensual correcto hacia SII. | `l10n_cl_fe/models/consumo_folios.py:187`

### 2. Construcción del XML DTE

| Componentes | Descripción | Referencia |
|-------------|-------------|------------|
| `_id_doc`, `_emisor`, `_receptor` | Preparan el bloque Encabezado validando folio, fecha, tipo de servicio, giro emisor y datos del receptor (incluye giros, correos, direcciones y validaciones de RUT). | `l10n_cl_fe/models/account_invoice.py:1234`, `l10n_cl_fe/models/account_invoice.py:1258`, `l10n_cl_fe/models/account_invoice.py:1290`
| `_crear_envio` + `do_dte_send` | Agrupan facturas, generan el identificador de envío, invocan `fe.timbrar_y_enviar` y persisten resultado en `sii.xml.envio` (XML, track id, estado). | `l10n_cl_fe/models/account_invoice.py:1725`
| `do_dte_send_invoice` + `sii.cola_envio` | Marca cada factura como `EnCola`, limpia timbrajes rechazados y agenda un trabajo en `sii.cola_envio` que ejecutará envío o consulta según `tipo_trabajo`. | `l10n_cl_fe/models/account_invoice.py:1187`, `l10n_cl_fe/models/sii_cola_envio.py:18`
| `ask_for_dte_status` | Llama tanto a `sii.xml.envio.get_send_status` como a `consulta_estado_documento`, actualiza `sii_result` y dispara notificaciones vía bus para rechazos/anulaciones. | `l10n_cl_fe/models/account_invoice.py:1782`

### 3. Reportes y Consumo de Folios

| Procedimiento | Objetivo | Referencia |
|---------------|----------|------------|
| `_get_resumenes` (`account.move.consumo_folios`) | Recorre movimientos contables ligados, agrupa por código SII y construye estructura `Documento` con rangos utilizados/anulados antes de llamar al generador CF. | `l10n_cl_fe/models/consumo_folios.py:207`
| `_resumenes` onchange | Al detectar nuevos asientos o anulaciones, limpia tablas detalle e inserta nuevos rangos/impuestos calculados por `_get_resumenes`, garantizando consistencia. | `l10n_cl_fe/models/consumo_folios.py:236`

### 4. Cesiones Electrónicas (Factoring)

| Cálculo | Descripción | Referencia |
|---------|-------------|------------|
| `_id_dte`, `_monto_cesion`, `_cesion` | Toman datos del DTE original (folio, monto total, RUT emisor/receptor) y generan la estructura `Cesion` con monto cedido, último vencimiento y declaración jurada obligatoria. | `l10n_cl_dte_factoring/models/invoice.py:56`
| `_crear_envio_cesion` + `cesion_dte_send` | Generan parámetros de firma (`_get_datos_empresa`), construyen el XML AEC via `fe.timbrar_y_enviar_cesion` y crean/actualizan registros `sii.xml.envio` específicos. | `l10n_cl_dte_factoring/models/invoice.py:86`
| `sii.cola_envio` (herencia) | Añade tipos de trabajo `cesion` y `cesion_consulta`, invocando `cesion_dte_send` primero y luego `ask_for_cesion_dte_status` hasta obtener resultado final. | `l10n_cl_dte_factoring/models/sii_cola_envio.py:9`

## Conclusiones
- Los cálculos de totales están fuertemente ligados a códigos SII y al detalle de impuestos (%14, %15, %17); cualquier reimplementación debe respetar esta lógica para evitar rechazos del SII.
- La separación entre generación del XML y su envío/consulta (a través de `sii.cola_envio`) permite reintentos y persistencia controlada; replicar este pipeline en Odoo 19 es imprescindible para asegurar trazabilidad.
- Las funciones que calculan consumo de folios y generan resúmenes alimentan obligaciones periódicas; descuidarlas implicaría perder visibilidad de boletas y rangos anulados.
- El factoring añade cálculos adicionales (montos cedidos, declaración jurada) y depende de extensiones de cola/envío; migrar sin esta capa implicaría perder capacidad legal de ceder facturas electrónicas.
