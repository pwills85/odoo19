# Auditoría Fase 6 - Reportes y Exportaciones (Facturación)

## Resumen Ejecutivo
- ✅ La localización provee reportes impresos adaptados al SII, incluyendo plantillas de factura que reemplazan la numeración por la letra/documento oficial y botones para emitir copias “Cedible”, cumpliendo con los requisitos del mercado chileno. `l10n_cl_fe/views/account_invoice.xml:50`, `l10n_cl_fe/views/report_invoice.xml:4`
- ✅ Los libros electrónicos (compra/venta y consumo de folios) cuentan con formularios dedicados que gestionan validación, descarga de XML y envío al SII directamente desde la interfaz, eliminando dependencias externas. `l10n_cl_fe/views/libro_compra_venta.xml:30`, `l10n_cl_fe/views/consumo_folios.xml:44`
- ✅ Existen reportes específicos como Honorarios y Libro de Boletas que filtran diarios y documentos asociados, asegurando cobertura para todos los formatos tributarios (33/34, 41, etc.). `l10n_cl_fe/views/honorarios.xml:200`

## Análisis Detallado

### 1. Impresión de Facturas y Cedibles

| Reporte | Funcionalidad | Referencia |
|---------|---------------|------------|
| Botones “Imprimir Copia y Cedible / Imprimir Cedible” | Disponibles en la cabecera de la factura; invocan acciones de impresión personalizadas para entregar la versión legal exigida por el SII. | `l10n_cl_fe/views/account_invoice.xml:50`
| Plantilla `report_invoice_document` | Hereda el QWeb estándar para reemplazar el número por la letra/documento SII, garantizando que la impresión refleje la codificación oficial. | `l10n_cl_fe/views/report_invoice.xml:4`

### 2. Libros Electrónicos

| Reporte/Acción | Uso | Referencia |
|----------------|-----|------------|
| `account.move.book` (Libro Compra/Venta) | Vista árbol con estados (Borrador, Proceso, Rechazado) y formulario con botones `Validate`, `Download XML`, `Send XML`, `Ask for DTE`. Incluye pestañas para movimientos, boletas y XML enviado. | `l10n_cl_fe/views/libro_compra_venta.xml:16`, `l10n_cl_fe/views/libro_compra_venta.xml:30`
| Menú “Libros Cierre de Mes” | Ubicado en Contabilidad → Reportes financieros y apunta a `action_move_books`. | `l10n_cl_fe/views/libro_compra_venta.xml:136`
| `account.move.consumo_folios` | Similar estructura para reportar boletas (totales, detalle de rangos, anulaciones) con acciones de validación, descarga y envío. | `l10n_cl_fe/views/consumo_folios.xml:44`

### 3. Reportes Especiales

| Reporte | Descripción | Referencia |
|---------|-------------|------------|
| Honorarios | Acción `honorarios_tree2` filtra facturas de compras con diarios asociados a documentos honorarios; servidor `load_honorarios` arma dominio dinámico y menú específico en Cuentas por Pagar. | `l10n_cl_fe/views/honorarios.xml:200`
| Libro de Boletas / Honorarios (XML) | Formularios incluyen campos específicos (boletas, folios, totales) y reutilizan botones de envío SII, manteniendo el mismo patrón operativo que los libros de ventas. | `l10n_cl_fe/views/libro_honorarios.xml:86`
| Exportaciones XLSX | El módulo depende de `report_xlsx` (declarado en el manifiesto) para generar reportes como libros en Excel; los botones de descarga se ubican en los formularios de libros/consumo. | `l10n_cl_fe/__manifest__.py:41`

## Conclusiones
- Los reportes están completamente integrados al flujo SII (validar → descargar XML → enviar → consultar). Migrar a Odoo 19 exige replicar estos botones y acciones para mantener la cadena certificada.
- La personalización del reporte de factura (cedible) evita errores comunes en fiscalizaciones; sin este template, los documentos impresos no cumplirían formato legal.
- Los informes especiales (Honorarios, Boletas) garantizan trazabilidad de documentos menos frecuentes; deben preservarse para cubrir la totalidad del catálogo tributario chileno.
